#include "wsd_http_transport.h"

#include <algorithm>
#include <cctype>
#include <limits>
#include <memory>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#endif

namespace just_scanner {
namespace {

void validate_limits(const WsdHttpLimits& limits) {
    if (limits.max_uri_bytes == 0U || limits.max_uri_bytes > 8192U ||
        limits.max_request_bytes == 0U || limits.max_request_bytes > 16U * 1024U * 1024U ||
        limits.max_response_bytes == 0U || limits.max_response_bytes > 64U * 1024U * 1024U ||
        limits.timeout_milliseconds == 0U || limits.timeout_milliseconds > 120000U) {
        throw WsdScanError("invalid_wsd_http_limits");
    }
}

bool is_ascii_token(const std::string_view value) {
    return !value.empty() && std::all_of(value.begin(), value.end(), [](const unsigned char c) {
        return c >= 0x21U && c <= 0x7eU && c != '\\r' && c != '\\n';
    });
}

bool is_ipv4_literal(const std::string_view value) {
    std::size_t start = 0U;
    for (unsigned part = 0U; part < 4U; ++part) {
        const auto end = value.find('.', start);
        if ((part < 3U && end == std::string_view::npos) ||
            (part == 3U && end != std::string_view::npos)) return false;
        const auto stop = end == std::string_view::npos ? value.size() : end;
        if (stop == start || stop - start > 3U) return false;
        unsigned octet = 0U;
        for (std::size_t i = start; i < stop; ++i) {
            const auto c = static_cast<unsigned char>(value[i]);
            if (std::isdigit(c) == 0) return false;
            octet = octet * 10U + static_cast<unsigned>(c - '0');
            if (octet > 255U) return false;
        }
        start = stop + 1U;
    }
    return start == value.size() + 1U;
}

bool is_safe_transport_uri(const std::string_view uri) {
    const std::size_t scheme = uri.starts_with("http://") ? 7U :
                               uri.starts_with("https://") ? 8U : 0U;
    if (scheme == 0U || uri.find_first_of("?#", scheme) != std::string_view::npos) return false;
    const auto path = uri.find('/', scheme);
    const auto authority = uri.substr(scheme, path == std::string_view::npos ? uri.size() - scheme : path - scheme);
    if (authority.empty() || authority.find('@') != std::string_view::npos || authority.starts_with('[')) return false;
    const auto colon = authority.find(':');
    const auto host = authority.substr(0U, colon);
    if (!is_ipv4_literal(host)) return false;
    if (colon != std::string_view::npos) {
        const auto port = authority.substr(colon + 1U);
        if (port.empty() || port.size() > 5U ||
            !std::all_of(port.begin(), port.end(), [](const unsigned char c) { return std::isdigit(c) != 0; })) return false;
        unsigned value = 0U;
        for (const unsigned char c : port) value = value * 10U + static_cast<unsigned>(c - '0');
        if (value == 0U || value > 65535U) return false;
    }
    return path == std::string_view::npos || uri[path] == '/';
}

bool media_type_matches(const std::string_view actual, const std::string_view expected) {
    const auto delimiter = actual.find(';');
    const auto type = actual.substr(0U, delimiter);
    if (type.size() != expected.size()) return false;
    return std::equal(type.begin(), type.end(), expected.begin(), expected.end(),
                      [](const unsigned char a, const unsigned char b) {
                          return std::tolower(a) == std::tolower(b);
                      });
}

void validate_request(const WsdHttpRequest& request, const WsdHttpLimits& limits) {
    validate_limits(limits);
    if (request.transport_uri.empty() || request.transport_uri.size() > limits.max_uri_bytes ||
        !is_safe_transport_uri(request.transport_uri)) throw WsdScanError("unsafe_wsd_transport_uri");
    if (!is_ascii_token(request.logical_destination) || request.logical_destination.size() > limits.max_uri_bytes ||
        !is_ascii_token(request.content_type) || request.payload.empty() ||
        request.payload.size() > limits.max_request_bytes) throw WsdScanError("invalid_wsd_http_request");
}

#ifdef _WIN32
class WinHttpHandle final {
public:
    explicit WinHttpHandle(HINTERNET handle = nullptr) noexcept : handle_(handle) {}
    ~WinHttpHandle() { if (handle_ != nullptr) WinHttpCloseHandle(handle_); }
    WinHttpHandle(const WinHttpHandle&) = delete;
    WinHttpHandle& operator=(const WinHttpHandle&) = delete;
    HINTERNET get() const noexcept { return handle_; }
private:
    HINTERNET handle_;
};

std::wstring utf8_to_wide(const std::string& value) {
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                          static_cast<int>(value.size()), nullptr, 0);
    if (count <= 0) throw WsdScanError("invalid_wsd_http_text");
    std::wstring result(static_cast<std::size_t>(count), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
                            result.data(), count) != count) throw WsdScanError("invalid_wsd_http_text");
    return result;
}

std::string wide_to_utf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                                          static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (count <= 0) throw WsdScanError("invalid_wsd_http_text");
    std::string result(static_cast<std::size_t>(count), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
                            result.data(), count, nullptr, nullptr) != count) {
        throw WsdScanError("invalid_wsd_http_text");
    }
    return result;
}

class WinHttpWsdExecutor final : public IWsdHttpExecutor {
public:
    WsdHttpResponse execute(const WsdHttpRequest& request, const WsdHttpLimits& limits,
                            const std::atomic_bool& cancel_requested) override {
        if (cancel_requested.load()) throw WsdScanError("cancelled");
        const auto uri = utf8_to_wide(request.transport_uri);
        URL_COMPONENTS parts{};
        parts.dwStructSize = sizeof(parts);
        parts.dwSchemeLength = static_cast<DWORD>(-1);
        parts.dwHostNameLength = static_cast<DWORD>(-1);
        parts.dwUrlPathLength = static_cast<DWORD>(-1);
        if (!WinHttpCrackUrl(uri.c_str(), static_cast<DWORD>(uri.size()), 0U, &parts)) throw WsdScanError("http_uri_parse_failed");
        WinHttpHandle session(WinHttpOpen(L"JustScanner/0.1", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0U));
        if (session.get() == nullptr) throw WsdScanError("http_open_failed");
        const int timeout = static_cast<int>(limits.timeout_milliseconds);
        if (!WinHttpSetTimeouts(session.get(), timeout, timeout, timeout, timeout)) throw WsdScanError("http_timeout_setup_failed");
        WinHttpHandle connection(WinHttpConnect(session.get(), std::wstring(parts.lpszHostName, parts.dwHostNameLength).c_str(),
                                                parts.nPort, 0U));
        if (connection.get() == nullptr) throw WsdScanError("http_connect_setup_failed");
        const std::wstring path = parts.dwUrlPathLength == 0U ? L"/" : std::wstring(parts.lpszUrlPath, parts.dwUrlPathLength);
        const DWORD flags = parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0U;
        WinHttpHandle operation(WinHttpOpenRequest(connection.get(), L"POST", path.c_str(), nullptr,
                                                    WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags));
        if (operation.get() == nullptr) throw WsdScanError("http_request_setup_failed");
        DWORD no_redirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        if (!WinHttpSetOption(operation.get(), WINHTTP_OPTION_REDIRECT_POLICY, &no_redirect, sizeof(no_redirect))) {
            throw WsdScanError("http_redirect_policy_failed");
        }
        const auto headers = utf8_to_wide("Content-Type: " + request.content_type + "\r\n");
        if (!WinHttpSendRequest(operation.get(), headers.c_str(), static_cast<DWORD>(headers.size()),
                                const_cast<char*>(request.payload.data()), static_cast<DWORD>(request.payload.size()),
                                static_cast<DWORD>(request.payload.size()), 0U) ||
            !WinHttpReceiveResponse(operation.get(), nullptr)) throw WsdScanError("http_request_failed");
        if (cancel_requested.load()) throw WsdScanError("cancelled");
        DWORD status = 0U;
        DWORD status_size = sizeof(status);
        if (!WinHttpQueryHeaders(operation.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                 WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX)) {
            throw WsdScanError("http_status_missing");
        }
        DWORD type_size = 0U;
        WinHttpQueryHeaders(operation.get(), WINHTTP_QUERY_CONTENT_TYPE, WINHTTP_HEADER_NAME_BY_INDEX,
                            nullptr, &type_size, WINHTTP_NO_HEADER_INDEX);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || type_size < sizeof(wchar_t)) throw WsdScanError("http_content_type_missing");
        std::wstring content_type(type_size / sizeof(wchar_t), L'\0');
        if (!WinHttpQueryHeaders(operation.get(), WINHTTP_QUERY_CONTENT_TYPE, WINHTTP_HEADER_NAME_BY_INDEX,
                                 content_type.data(), &type_size, WINHTTP_NO_HEADER_INDEX)) throw WsdScanError("http_content_type_missing");
        content_type.resize((type_size / sizeof(wchar_t)) - 1U);
        std::string body;
        for (;;) {
            if (cancel_requested.load()) throw WsdScanError("cancelled");
            DWORD available = 0U;
            if (!WinHttpQueryDataAvailable(operation.get(), &available)) throw WsdScanError("http_read_failed");
            if (available == 0U) break;
            if (available > limits.max_response_bytes - body.size()) throw WsdScanError("http_response_too_large");
            const auto old_size = body.size();
            body.resize(old_size + available);
            DWORD read = 0U;
            if (!WinHttpReadData(operation.get(), body.data() + old_size, available, &read)) throw WsdScanError("http_read_failed");
            body.resize(old_size + read);
        }
        return {status, wide_to_utf8(content_type), std::move(body), false};
    }
};
#endif

}  // namespace

BoundedWsdHttpTransport::BoundedWsdHttpTransport(IWsdHttpExecutor& executor, WsdHttpLimits limits)
    : executor_(executor), limits_(limits) { validate_limits(limits_); }

WsdHttpResponse BoundedWsdHttpTransport::post(const WsdHttpRequest& request,
                                               const std::atomic_bool& cancel_requested) const {
    validate_request(request, limits_);
    if (cancel_requested.load()) throw WsdScanError("cancelled");
    auto response = executor_.execute(request, limits_, cancel_requested);
    if (cancel_requested.load()) throw WsdScanError("cancelled");
    if (response.redirected) throw WsdScanError("http_redirect_rejected");
    if (response.status_code < 200U || response.status_code >= 300U) throw WsdScanError("http_status_rejected");
    if (response.body.size() > limits_.max_response_bytes) throw WsdScanError("http_response_too_large");
    if (!media_type_matches(response.content_type, request.content_type)) throw WsdScanError("http_content_type_rejected");
    return response;
}

std::unique_ptr<IWsdHttpExecutor> make_winhttp_wsd_executor() {
#ifdef _WIN32
    return std::make_unique<WinHttpWsdExecutor>();
#else
    return {};
#endif
}

}  // namespace just_scanner
