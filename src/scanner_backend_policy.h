#pragma once

#include <array>
#include <string_view>

namespace just_scanner {

enum class ScannerBackendKind {
    mock_fixture,
    windows_wia2,
    wsd_network,
    escl_network,
    native_usb,
};

enum class ScannerBackendMaturity {
    offline_tested,
    discovery_only,
    planned,
    research_only,
};

enum class ScannerBackendOperation {
    discover,
    connect,
    scan,
};

struct ScannerBackendPolicy {
    ScannerBackendKind kind;
    std::string_view stable_id;
    ScannerBackendMaturity maturity;
    bool transport_built_into_app;
    bool requires_external_driver;
    bool requires_network;
    bool supports_discovery;
    bool supports_connect;
    bool supports_scan;
};

struct ScannerBackendPermission {
    bool explicit_user_action{false};
    bool allow_local_device_io{false};
    bool allow_network_io{false};
    bool allow_native_usb_io{false};
};

using ScannerBackendPolicies = std::array<ScannerBackendPolicy, 5>;

const ScannerBackendPolicies& default_scanner_backend_policies() noexcept;

const ScannerBackendPolicy* find_scanner_backend_policy(
    ScannerBackendKind kind) noexcept;

bool scanner_backend_operation_allowed(
    const ScannerBackendPolicy& policy,
    ScannerBackendOperation operation,
    const ScannerBackendPermission& permission) noexcept;

}  // namespace just_scanner
