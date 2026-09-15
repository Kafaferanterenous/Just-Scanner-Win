#pragma once

#include "scanner_core.h"

#include <cstdint>
#include <string>

namespace just_scanner {

enum class TransferState { idle, configured, transferring, cancelling, completed, failed };
enum class TransferFailure {
    none,
    cancelled,
    feeder_empty,
    paper_jam,
    device_lost,
    transfer_limit,
    invalid_image,
    protocol_error,
};

struct TransferLimits {
    std::uint32_t max_pages{1000U};
    std::uint64_t max_page_bytes{256U * 1024U * 1024U};
    std::uint64_t max_total_bytes{1024ULL * 1024ULL * 1024ULL};
    std::uint32_t max_dimension{200000U};
};

struct TransferOutcome {
    TransferState state{TransferState::idle};
    TransferFailure failure{TransferFailure::none};
    std::uint32_t completed_pages{};
    std::uint64_t completed_bytes{};
    bool short_batch{};
};

class WiaTransferModel {
public:
    explicit WiaTransferModel(TransferLimits limits = {});

    void configure(SourceType source, std::uint32_t requested_pages);
    void begin_transfer();
    void begin_page(std::uint32_t width, std::uint32_t height, std::uint64_t declared_bytes);
    void accept_chunk(std::uint64_t bytes);
    void complete_page(bool image_valid);
    void request_cancel();
    void acknowledge_cancel();
    void report_feeder_empty();
    void report_failure(TransferFailure failure);
    void finish_transfer();

    TransferOutcome outcome() const noexcept;

private:
    [[noreturn]] void protocol_failure(const char* message);
    void fail(TransferFailure failure) noexcept;

    TransferLimits limits_;
    TransferState state_{TransferState::idle};
    TransferFailure failure_{TransferFailure::none};
    SourceType source_{SourceType::flatbed};
    std::uint32_t requested_pages_{};
    std::uint32_t completed_pages_{};
    std::uint64_t completed_bytes_{};
    std::uint64_t current_page_bytes_{};
    std::uint64_t declared_page_bytes_{};
    bool page_open_{};
    bool short_batch_{};
};

const char* transfer_failure_code(TransferFailure failure) noexcept;

}  // namespace just_scanner
