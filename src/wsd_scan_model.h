#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>

namespace just_scanner {

class WsdScanError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

enum class WsdRequestKind {
    get_scanner_elements,
    validate_scan_ticket,
    create_scan_job,
    retrieve_image,
    cancel_job,
};

enum class WsdInputSource {
    platen,
    adf,
};

enum class WsdColorProcessing {
    monochrome,
    grayscale,
    rgb24,
};

enum class WsdDocumentFormat {
    jpeg,
    png,
    tiff,
};

struct WsdScanTicket {
    WsdInputSource source{WsdInputSource::platen};
    WsdColorProcessing color{WsdColorProcessing::rgb24};
    WsdDocumentFormat format{WsdDocumentFormat::jpeg};
    std::uint32_t horizontal_dpi{300U};
    std::uint32_t vertical_dpi{300U};
    std::uint32_t images_to_transfer{1U};
};

struct WsdJobCredentials {
    std::uint32_t job_id{0U};
    std::string job_token;
};

struct WsdRequest {
    WsdRequestKind kind{WsdRequestKind::get_scanner_elements};
    std::optional<WsdScanTicket> ticket;
    std::optional<WsdJobCredentials> credentials;
};

struct WsdSafetyLimits {
    std::size_t max_xml_bytes{1024U * 1024U};
    std::size_t max_image_bytes{512U * 1024U * 1024U};
    std::uint32_t max_images{100U};
    std::size_t max_job_token_bytes{256U};
};

WsdRequest make_wsd_get_scanner_elements_request();
WsdRequest make_wsd_validate_ticket_request(
    const WsdScanTicket& ticket,
    const WsdSafetyLimits& limits = {});
WsdRequest make_wsd_create_job_request(
    const WsdScanTicket& ticket,
    const WsdSafetyLimits& limits = {});
WsdRequest make_wsd_retrieve_image_request(
    const WsdJobCredentials& credentials,
    const WsdSafetyLimits& limits = {});
WsdRequest make_wsd_cancel_job_request(
    const WsdJobCredentials& credentials,
    const WsdSafetyLimits& limits = {});

enum class WsdJobState {
    idle,
    ticket_validated,
    job_created,
    retrieving,
    complete,
    cancelled,
    failed,
};

class WsdJobModel {
public:
    explicit WsdJobModel(WsdSafetyLimits limits = {});

    WsdJobState state() const noexcept;
    std::uint32_t images_received() const noexcept;
    std::size_t image_bytes_received() const noexcept;

    void accept_ticket_validation(bool valid);
    void accept_job_created(const WsdJobCredentials& credentials);
    void begin_retrieve(const WsdJobCredentials& credentials);
    void accept_image(std::size_t image_bytes, bool more_images);
    void cancel();
    void fail() noexcept;

private:
    WsdSafetyLimits limits_;
    WsdJobState state_{WsdJobState::idle};
    std::optional<WsdJobCredentials> credentials_;
    std::uint32_t images_received_{0U};
    std::size_t image_bytes_received_{0U};
};

}  // namespace just_scanner
