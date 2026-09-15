#pragma once

#include "wsd_scan_model.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace just_scanner {

// Transport values are private routing data. They must not be shown in the UI
// or copied to journals, support bundles, or public discovery results.
struct WsdHttpLimits {
    std::size_t max_uri_bytes{2048U};
    std::size_t max_request_bytes{1024U * 1024U};
    std::size_t max_response_bytes{4U * 1024U * 1024U};
    std::uint32_t timeout_milliseconds{15000U};
};

struct WsdHttpRequest {
    std::string transport_uri;
    std::string logical_destination;
    std::string content_type;
    std::string payload;
};

struct WsdHttpResponse {
    std::uint32_t status_code{};
    std::string content_type;
    std::string body;
    bool redirected{false};
};

// The model and its tests use this seam. An implementation may perform I/O,
// but constructing BoundedWsdHttpTransport never contacts a device or network.
class IWsdHttpExecutor {
public:
    virtual ~IWsdHttpExecutor() = default;
    virtual WsdHttpResponse execute(
        const WsdHttpRequest& request,
        const WsdHttpLimits& limits,
        const std::atomic_bool& cancel_requested) = 0;
};

class BoundedWsdHttpTransport {
public:
    explicit BoundedWsdHttpTransport(IWsdHttpExecutor& executor, WsdHttpLimits limits = {});

    WsdHttpResponse post(
        const WsdHttpRequest& request,
        const std::atomic_bool& cancel_requested) const;

private:
    IWsdHttpExecutor& executor_;
    WsdHttpLimits limits_;
};

// Creates the only production executor. It uses WinHTTP with no proxy and a
// no-redirect policy; it makes no request until execute() is called.
std::unique_ptr<IWsdHttpExecutor> make_winhttp_wsd_executor();

}  // namespace just_scanner
