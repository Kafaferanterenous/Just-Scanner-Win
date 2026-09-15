#pragma once

namespace just_scanner {

enum class WiaWorkerState { stopped, idle, refreshing, connecting, scanning, cancelling };
enum class WiaWorkerOperation { none, refresh, connect, scan };

struct WiaWorkerSnapshot {
    WiaWorkerState state{WiaWorkerState::stopped};
    WiaWorkerOperation operation{WiaWorkerOperation::none};
    bool cancel_requested{};
};

class WiaWorkerModel {
public:
    void start();
    void begin(WiaWorkerOperation operation);
    void request_cancel();
    void complete();
    void shutdown();
    WiaWorkerSnapshot snapshot() const noexcept;

private:
    WiaWorkerState state_{WiaWorkerState::stopped};
    WiaWorkerOperation operation_{WiaWorkerOperation::none};
    bool cancel_requested_{};
};

}  // namespace just_scanner
