#include "wia_com_worker.h"

#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <utility>

#ifdef _WIN32
#include <objbase.h>
#endif

namespace just_scanner {
namespace {

bool is_safe_issue_code(const std::string& code) noexcept {
    if (code.empty() || code.size() > 64U) return false;
    for (const unsigned char ch : code) {
        if ((ch < 'a' || ch > 'z') && ch != '_') return false;
    }
    return true;
}

WiaWorkerReply failure_reply(
    const WiaWorkerRequest& request,
    const char* issue_code) {
    WiaWorkerReply reply;
    reply.request_id = request.request_id;
    reply.operation = request.operation;
    reply.issue_code = issue_code;
    return reply;
}

void validate_request(const WiaWorkerRequest& request) {
    if (request.request_id == 0U) throw ScannerError("WIA worker request identifier is invalid");
    if (request.operation == WiaWorkerOperation::none) {
        throw ScannerError("WIA worker request operation is invalid");
    }
    if (request.opaque_device_id.size() > 64U) {
        throw ScannerError("WIA worker device selection is invalid");
    }
    if (request.operation == WiaWorkerOperation::refresh) {
        if (!request.opaque_device_id.empty() || request.discovery_generation != 0U || request.scan_request) {
            throw ScannerError("WIA refresh request contains unexpected fields");
        }
        return;
    }
    if (request.opaque_device_id.empty() || request.discovery_generation == 0U) {
        throw ScannerError("WIA worker device selection is missing");
    }
    if (request.operation == WiaWorkerOperation::connect && request.scan_request) {
        throw ScannerError("WIA connect request contains scan settings");
    }
    if (request.operation == WiaWorkerOperation::scan && !request.scan_request) {
        throw ScannerError("WIA scan request is missing settings");
    }
}

}  // namespace

bool WindowsMtaApartment::initialize() noexcept {
#ifdef _WIN32
    if (initialized_) return false;
    const HRESULT result = CoInitializeEx(nullptr, COINIT_MULTITHREADED | COINIT_DISABLE_OLE1DDE);
    initialized_ = SUCCEEDED(result);
    return initialized_;
#else
    return false;
#endif
}

void WindowsMtaApartment::uninitialize() noexcept {
#ifdef _WIN32
    if (initialized_) CoUninitialize();
#endif
    initialized_ = false;
}

struct WiaComWorker::Impl {
    struct PendingRequest {
        explicit PendingRequest(WiaWorkerRequest submitted) : request(std::move(submitted)) {}
        WiaWorkerRequest request;
        std::promise<WiaWorkerReply> promise;
    };

    Impl(std::shared_ptr<IWiaWorkerBackend> supplied_backend, std::unique_ptr<IComApartment> supplied_apartment)
        : backend(std::move(supplied_backend)), apartment(std::move(supplied_apartment)) {
        if (!backend || !apartment) throw ScannerError("WIA worker dependencies are missing");
    }

    ~Impl() { shutdown(); }

    void start() {
        std::unique_lock lock(mutex);
        if (thread.joinable() || started) throw ScannerError("WIA COM worker is already started");
        stopping = false;
        accepting = false;
        startup_done = false;
        startup_succeeded = false;
        cancel_requested.store(false);
        thread = std::thread([this] { run(); });
        startup_cv.wait(lock, [this] { return startup_done; });
        if (!startup_succeeded) {
            lock.unlock();
            if (thread.joinable()) thread.join();
            throw ScannerError("WIA COM worker initialization failed");
        }
        started = true;
        accepting = true;
    }

    std::future<WiaWorkerReply> submit(WiaWorkerRequest request) {
        validate_request(request);
        auto pending = std::make_shared<PendingRequest>(std::move(request));
        auto future = pending->promise.get_future();
        {
            std::lock_guard lock(mutex);
            if (!started || !accepting || stopping) throw ScannerError("WIA COM worker is not accepting requests");
            if (queue.size() >= 64U) throw ScannerError("WIA COM worker request queue is full");
            queue.push_back(std::move(pending));
        }
        work_cv.notify_one();
        return future;
    }

    void request_cancel() {
        std::lock_guard lock(mutex);
        if (!active) throw ScannerError("WIA COM worker has no active request");
        cancel_requested.store(true);
        published_snapshot.cancel_requested = true;
        published_snapshot.state = WiaWorkerState::cancelling;
    }

    void shutdown() noexcept {
        {
            std::lock_guard lock(mutex);
            if (!thread.joinable()) {
                started = false;
                accepting = false;
                published_snapshot = {};
                return;
            }
            accepting = false;
            stopping = true;
            if (active) {
                cancel_requested.store(true);
                published_snapshot.cancel_requested = true;
                published_snapshot.state = WiaWorkerState::cancelling;
            }
        }
        work_cv.notify_one();
        thread.join();
        std::lock_guard lock(mutex);
        started = false;
        active = false;
        published_snapshot = {};
    }

    WiaWorkerSnapshot snapshot() const noexcept {
        std::lock_guard lock(mutex);
        return published_snapshot;
    }

    void publish(const WiaWorkerSnapshot next) noexcept {
        std::lock_guard lock(mutex);
        published_snapshot = next;
    }

    void cancel_queued_requests() noexcept {
        std::deque<std::shared_ptr<PendingRequest>> cancelled;
        {
            std::lock_guard lock(mutex);
            cancelled.swap(queue);
        }
        for (const auto& pending : cancelled) {
            pending->promise.set_value(failure_reply(pending->request, "cancelled"));
        }
    }

    void run() noexcept {
        const bool apartment_ready = apartment->initialize();
        bool backend_ready = false;
        if (apartment_ready) {
            try {
                backend->open();
                backend_ready = true;
            } catch (...) {
                backend->close();
            }
        }

        WiaWorkerModel lifecycle;
        if (backend_ready) {
            lifecycle.start();
            publish(lifecycle.snapshot());
        }
        {
            std::lock_guard lock(mutex);
            startup_succeeded = backend_ready;
            startup_done = true;
        }
        startup_cv.notify_one();

        if (!backend_ready) {
            if (apartment_ready) apartment->uninitialize();
            return;
        }

        for (;;) {
            std::shared_ptr<PendingRequest> pending;
            {
                std::unique_lock lock(mutex);
                work_cv.wait(lock, [this] { return stopping || !queue.empty(); });
                if (stopping) break;
                pending = queue.front();
                queue.pop_front();
                active = true;
                cancel_requested.store(false);
            }

            lifecycle.begin(pending->request.operation);
            publish(lifecycle.snapshot());
            WiaWorkerReply reply;
            try {
                reply = backend->execute(pending->request, cancel_requested);
                reply.request_id = pending->request.request_id;
                reply.operation = pending->request.operation;
                if (!reply.success && !is_safe_issue_code(reply.issue_code)) {
                    reply.issue_code = "driver_failure";
                }
                if (reply.success) reply.issue_code.clear();
            } catch (...) {
                reply = failure_reply(pending->request, "driver_failure");
            }

            if (cancel_requested.load()) {
                lifecycle.request_cancel();
                reply = failure_reply(pending->request, "cancelled");
            }
            lifecycle.complete();
            {
                std::lock_guard lock(mutex);
                active = false;
                cancel_requested.store(false);
                published_snapshot = lifecycle.snapshot();
            }
            pending->promise.set_value(std::move(reply));
        }

        cancel_queued_requests();
        backend->close();
        lifecycle.shutdown();
        publish(lifecycle.snapshot());
        apartment->uninitialize();
    }

    std::shared_ptr<IWiaWorkerBackend> backend;
    std::unique_ptr<IComApartment> apartment;
    mutable std::mutex mutex;
    std::condition_variable startup_cv;
    std::condition_variable work_cv;
    std::deque<std::shared_ptr<PendingRequest>> queue;
    std::thread thread;
    std::atomic_bool cancel_requested{};
    WiaWorkerSnapshot published_snapshot;
    bool started{};
    bool accepting{};
    bool stopping{};
    bool active{};
    bool startup_done{};
    bool startup_succeeded{};
};

WiaComWorker::WiaComWorker(
    std::shared_ptr<IWiaWorkerBackend> backend,
    std::unique_ptr<IComApartment> apartment)
    : impl_(std::make_unique<Impl>(std::move(backend), std::move(apartment))) {}

WiaComWorker::~WiaComWorker() = default;

void WiaComWorker::start() { impl_->start(); }

std::future<WiaWorkerReply> WiaComWorker::submit(WiaWorkerRequest request) {
    return impl_->submit(std::move(request));
}

void WiaComWorker::request_cancel() { impl_->request_cancel(); }

void WiaComWorker::shutdown() { impl_->shutdown(); }

WiaWorkerSnapshot WiaComWorker::snapshot() const noexcept { return impl_->snapshot(); }

}  // namespace just_scanner
