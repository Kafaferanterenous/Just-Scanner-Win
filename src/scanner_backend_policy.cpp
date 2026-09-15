#include "scanner_backend_policy.h"

namespace just_scanner {

const ScannerBackendPolicies& default_scanner_backend_policies() noexcept {
    static constexpr ScannerBackendPolicies policies{{
        {ScannerBackendKind::mock_fixture,
         "mock_fixture",
         ScannerBackendMaturity::offline_tested,
         true,
         false,
         false,
         false,
         false,
         true},
        {ScannerBackendKind::windows_wia2,
         "windows_wia2",
         ScannerBackendMaturity::discovery_only,
         false,
         true,
         false,
         true,
         false,
         false},
        {ScannerBackendKind::wsd_network,
         "wsd_network",
         ScannerBackendMaturity::planned,
         true,
         false,
         true,
         false,
         false,
         false},
        {ScannerBackendKind::escl_network,
         "escl_network",
         ScannerBackendMaturity::research_only,
         true,
         false,
         true,
         false,
         false,
         false},
        {ScannerBackendKind::native_usb,
         "native_usb",
         ScannerBackendMaturity::research_only,
         true,
         false,
         false,
         false,
         false,
         false},
    }};
    return policies;
}

const ScannerBackendPolicy* find_scanner_backend_policy(
    const ScannerBackendKind kind) noexcept {
    for (const auto& policy : default_scanner_backend_policies()) {
        if (policy.kind == kind) return &policy;
    }
    return nullptr;
}

bool scanner_backend_operation_allowed(
    const ScannerBackendPolicy& policy,
    const ScannerBackendOperation operation,
    const ScannerBackendPermission& permission) noexcept {
    bool operation_supported = false;
    switch (operation) {
        case ScannerBackendOperation::discover:
            operation_supported = policy.supports_discovery;
            break;
        case ScannerBackendOperation::connect:
            operation_supported = policy.supports_connect;
            break;
        case ScannerBackendOperation::scan:
            operation_supported = policy.supports_scan;
            break;
    }
    if (!operation_supported) return false;

    if (policy.kind == ScannerBackendKind::mock_fixture) return true;
    if (!permission.explicit_user_action) return false;

    if (policy.kind == ScannerBackendKind::native_usb) {
        return permission.allow_local_device_io && permission.allow_native_usb_io;
    }
    if (policy.requires_network) return permission.allow_network_io;
    return permission.allow_local_device_io;
}

}  // namespace just_scanner
