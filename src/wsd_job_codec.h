#pragma once

#include "wsd_scan_model.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace just_scanner {

struct WsdMtomImage {
    std::string content_type;
    std::vector<std::uint8_t> bytes;
};

struct WsdCreatedJob {
    WsdJobCredentials credentials;
    std::string final_format;
};

std::string encode_wsd_create_scan_job_request(std::string_view service_to, std::string_view message_id,
                                               const WsdScanTicket& ticket, const WsdSafetyLimits& limits = {});
std::string encode_wsd_retrieve_image_request(std::string_view service_to, std::string_view message_id,
                                              const WsdJobCredentials& credentials, std::string_view document_name,
                                              const WsdSafetyLimits& limits = {});
std::string encode_wsd_cancel_job_request(std::string_view service_to, std::string_view message_id,
                                          const WsdJobCredentials& credentials, const WsdSafetyLimits& limits = {});
WsdCreatedJob decode_wsd_create_scan_job_response(std::string_view xml, std::string_view expected_relates_to,
                                                  const WsdSafetyLimits& limits = {});
WsdMtomImage decode_wsd_retrieve_mtom_response(std::string_view content_type,
                                               const std::vector<std::uint8_t>& body,
                                               std::string_view expected_content_id,
                                               const WsdSafetyLimits& limits = {});

}  // namespace just_scanner
