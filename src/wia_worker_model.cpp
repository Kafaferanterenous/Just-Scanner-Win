#include "wia_worker_model.h"

#include "scanner_core.h"

namespace just_scanner {

void WiaWorkerModel::start() {
    if (state_ != WiaWorkerState::stopped) throw ScannerError("WIA worker is already started");
    state_ = WiaWorkerState::idle;
}

void WiaWorkerModel::begin(const WiaWorkerOperation operation) {
    if (state_ != WiaWorkerState::idle) throw ScannerError("WIA worker is not idle");
    if (operation == WiaWorkerOperation::none) throw ScannerError("WIA worker operation is invalid");
    operation_ = operation;
    cancel_requested_ = false;
    if (operation == WiaWorkerOperation::refresh) state_ = WiaWorkerState::refreshing;
    if (operation == WiaWorkerOperation::connect) state_ = WiaWorkerState::connecting;
    if (operation == WiaWorkerOperation::scan) state_ = WiaWorkerState::scanning;
}

void WiaWorkerModel::request_cancel() {
    if (state_ != WiaWorkerState::refreshing && state_ != WiaWorkerState::connecting &&
        state_ != WiaWorkerState::scanning) {
        throw ScannerError("WIA worker has no cancellable operation");
    }
    cancel_requested_ = true;
    state_ = WiaWorkerState::cancelling;
}

void WiaWorkerModel::complete() {
    if (state_ != WiaWorkerState::refreshing && state_ != WiaWorkerState::connecting &&
        state_ != WiaWorkerState::scanning && state_ != WiaWorkerState::cancelling) {
        throw ScannerError("WIA worker has no active operation");
    }
    state_ = WiaWorkerState::idle;
    operation_ = WiaWorkerOperation::none;
    cancel_requested_ = false;
}

void WiaWorkerModel::shutdown() {
    if (state_ != WiaWorkerState::idle && state_ != WiaWorkerState::stopped) {
        throw ScannerError("WIA worker operation must complete before shutdown");
    }
    state_ = WiaWorkerState::stopped;
    operation_ = WiaWorkerOperation::none;
    cancel_requested_ = false;
}

WiaWorkerSnapshot WiaWorkerModel::snapshot() const noexcept {
    return {state_, operation_, cancel_requested_};
}

}  // namespace just_scanner
