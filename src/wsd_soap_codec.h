#pragma once

#include "wsd_scan_model.h"

#include <string>
#include <string_view>
#include <vector>

namespace just_scanner {

enum class WsdScannerElement {
    description,
    configuration,
    status,
};

struct WsdScannerDescription {
    std::string name;
    std::string information;
    std::string location;
};

struct WsdScannerConfiguration {
    bool supports_platen{false};
    bool supports_adf{false};
    bool supports_film{false};
    bool adf_supports_duplex{false};
    std::vector<std::string> formats;
};

enum class WsdScannerState {
    idle,
    processing,
    stopped,
    vendor_extended,
};

struct WsdScannerStatus {
    WsdScannerState state{WsdScannerState::vendor_extended};
    std::string state_value;
    std::vector<std::string> reasons;
};

enum class WsdSoapFaultKind {
    action_not_supported,
    invalid_arguments,
    operation_failed,
    temporary_error,
    internal_error,
    other,
};

struct WsdSoapFault {
    WsdSoapFaultKind kind{WsdSoapFaultKind::other};
    std::string code;
    std::string subcode;
    std::string reason;
    bool retryable{false};
};

std::string encode_wsd_get_scanner_elements_request(
    std::string_view service_endpoint,
    std::string_view message_id,
    const std::vector<WsdScannerElement>& elements,
    const WsdSafetyLimits& limits = {});

WsdScannerDescription decode_wsd_scanner_description_response(
    std::string_view xml,
    const WsdSafetyLimits& limits = {});

WsdScannerConfiguration decode_wsd_scanner_configuration_response(
    std::string_view xml,
    const WsdSafetyLimits& limits = {});

WsdScannerStatus decode_wsd_scanner_status_response(
    std::string_view xml,
    const WsdSafetyLimits& limits = {});

WsdSoapFault decode_wsd_soap_fault(
    std::string_view xml,
    const WsdSafetyLimits& limits = {});

}  // namespace just_scanner
