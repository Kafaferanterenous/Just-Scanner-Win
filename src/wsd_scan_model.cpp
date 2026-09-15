#include "wsd_scan_model.h"

#include <limits>

namespace just_scanner {
namespace {

void validate_limits(const WsdSafetyLimits& limits) {
    if (limits.max_xml_bytes == 0U || limits.max_image_bytes == 0U ||
        limits.max_images == 0U || limits.max_job_token_bytes == 0U) {
        throw WsdScanError("invalid_wsd_limits");
    }
}

void validate_ticket(const WsdScanTicket& ticket, const WsdSafetyLimits& limits) {
    validate_limits(limits);
    if (ticket.horizontal_dpi < 50U || ticket.horizontal_dpi > 2400U ||
        ticket.vertical_dpi < 50U || ticket.vertical_dpi > 2400U) {
        throw WsdScanError("invalid_wsd_resolution");
    }
    if (ticket.images_to_transfer == 0U ||
        ticket.images_to_transfer > limits.max_images) {
        throw WsdScanError("invalid_wsd_image_count");
    }
}

void validate_credentials(
    const WsdJobCredentials& credentials,
    const WsdSafetyLimits& limits) {
    validate_limits(limits);
    if (credentials.job_id == 0U || credentials.job_token.empty() ||
        credentials.job_token.size() > limits.max_job_token_bytes) {
        throw WsdScanError("invalid_wsd_job_credentials");
    }
    for (const unsigned char character : credentials.job_token) {
        if (character < 0x21U || character > 0x7eU || character == '<' ||
            character == '>' || character == '&' || character == '"' ||
            character == '\'') {
            throw WsdScanError("unsafe_wsd_job_token");
        }
    }
}

bool same_credentials(
    const WsdJobCredentials& left,
    const WsdJobCredentials& right) noexcept {
    return left.job_id == right.job_id && left.job_token == right.job_token;
}

}  // namespace

WsdRequest make_wsd_get_scanner_elements_request() {
    return {WsdRequestKind::get_scanner_elements, std::nullopt, std::nullopt};
}

WsdRequest make_wsd_validate_ticket_request(
    const WsdScanTicket& ticket,
    const WsdSafetyLimits& limits) {
    validate_ticket(ticket, limits);
    return {WsdRequestKind::validate_scan_ticket, ticket, std::nullopt};
}

WsdRequest make_wsd_create_job_request(
    const WsdScanTicket& ticket,
    const WsdSafetyLimits& limits) {
    validate_ticket(ticket, limits);
    return {WsdRequestKind::create_scan_job, ticket, std::nullopt};
}

WsdRequest make_wsd_retrieve_image_request(
    const WsdJobCredentials& credentials,
    const WsdSafetyLimits& limits) {
    validate_credentials(credentials, limits);
    return {WsdRequestKind::retrieve_image, std::nullopt, credentials};
}

WsdRequest make_wsd_cancel_job_request(
    const WsdJobCredentials& credentials,
    const WsdSafetyLimits& limits) {
    validate_credentials(credentials, limits);
    return {WsdRequestKind::cancel_job, std::nullopt, credentials};
}

WsdJobModel::WsdJobModel(WsdSafetyLimits limits) : limits_(limits) {
    validate_limits(limits_);
}

WsdJobState WsdJobModel::state() const noexcept {
    return state_;
}

std::uint32_t WsdJobModel::images_received() const noexcept {
    return images_received_;
}

std::size_t WsdJobModel::image_bytes_received() const noexcept {
    return image_bytes_received_;
}

void WsdJobModel::accept_ticket_validation(const bool valid) {
    if (state_ != WsdJobState::idle) throw WsdScanError("invalid_wsd_state");
    state_ = valid ? WsdJobState::ticket_validated : WsdJobState::failed;
}

void WsdJobModel::accept_job_created(const WsdJobCredentials& credentials) {
    if (state_ != WsdJobState::ticket_validated) throw WsdScanError("invalid_wsd_state");
    validate_credentials(credentials, limits_);
    credentials_ = credentials;
    state_ = WsdJobState::job_created;
}

void WsdJobModel::begin_retrieve(const WsdJobCredentials& credentials) {
    if (state_ != WsdJobState::job_created || !credentials_.has_value()) {
        throw WsdScanError("invalid_wsd_state");
    }
    validate_credentials(credentials, limits_);
    if (!same_credentials(*credentials_, credentials)) {
        throw WsdScanError("mismatched_wsd_job_credentials");
    }
    state_ = WsdJobState::retrieving;
}

void WsdJobModel::accept_image(const std::size_t image_bytes, const bool more_images) {
    if (state_ != WsdJobState::retrieving) throw WsdScanError("invalid_wsd_state");
    if (image_bytes == 0U || image_bytes > limits_.max_image_bytes ||
        image_bytes_received_ > limits_.max_image_bytes - image_bytes) {
        state_ = WsdJobState::failed;
        throw WsdScanError("wsd_image_limit_exceeded");
    }
    if (images_received_ == limits_.max_images) {
        state_ = WsdJobState::failed;
        throw WsdScanError("wsd_image_count_exceeded");
    }
    ++images_received_;
    image_bytes_received_ += image_bytes;
    state_ = more_images ? WsdJobState::job_created : WsdJobState::complete;
}

void WsdJobModel::cancel() {
    if (state_ != WsdJobState::job_created && state_ != WsdJobState::retrieving) {
        throw WsdScanError("invalid_wsd_state");
    }
    state_ = WsdJobState::cancelled;
}

void WsdJobModel::fail() noexcept {
    state_ = WsdJobState::failed;
}

}  // namespace just_scanner
