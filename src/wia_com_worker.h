#pragma once

#include "scanner_core.h"
#include "wia_capability_model.h"
#include "wia_discovery_model.h"
#include "wia_transfer_model.h"
#include "wia_worker_model.h"

#include <atomic>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <string>

namespace just_scanner {

struct WiaWorkerRequest {
    std::uint64_t request_id{};
    WiaWorkerOperation operation{WiaWorkerOperation::none};
    std::string opaque_device_id;
    std::uint64_t discovery_generation{};
    std::optional<ScanRequest> scan_request;
};

struct WiaWorkerReply {
    std::uint64_t request_id{};
    WiaWorkerOperation operation{WiaWorkerOperation::none};
    bool success{};
    std::string issue_code;
    WiaDiscoveryResult discovery;
    WiaCapabilityResult capabilities;
    TransferOutcome transfer;
};

class IWiaWorkerBackend {
public:
    virtual ~IWiaWorkerBackend() = default;
    virtual void open() = 0;
    virtual WiaWorkerReply execute(
        const WiaWorkerRequest& request,
        const std::atomic_bool& cancel_requested) = 0;
    virtual void close() noexcept = 0;
};

class IComApartment {
public:
    virtual ~IComApartment() = default;
    virtual bool initialize() noexcept = 0;
    virtual void uninitialize() noexcept = 0;
};

class WindowsMtaApartment final : public IComApartment {
public:
    bool initialize() noexcept override;
    void uninitialize() noexcept override;

private:
    bool initialized_{};
};

class WiaComWorker {
public:
    explicit WiaComWorker(
        std::shared_ptr<IWiaWorkerBackend> backend,
        std::unique_ptr<IComApartment> apartment = std::make_unique<WindowsMtaApartment>());
    ~WiaComWorker();

    WiaComWorker(const WiaComWorker&) = delete;
    WiaComWorker& operator=(const WiaComWorker&) = delete;

    void start();
    std::future<WiaWorkerReply> submit(WiaWorkerRequest request);
    void request_cancel();
    void shutdown();
    WiaWorkerSnapshot snapshot() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace just_scanner
