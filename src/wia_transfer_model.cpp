#include "wia_transfer_model.h"

#include <limits>

namespace just_scanner {

WiaTransferModel::WiaTransferModel(const TransferLimits limits) : limits_(limits) {
    if (limits_.max_pages == 0U || limits_.max_page_bytes == 0U || limits_.max_total_bytes == 0U ||
        limits_.max_page_bytes > limits_.max_total_bytes || limits_.max_dimension == 0U) {
        throw ScannerError("transfer limits are invalid");
    }
}

[[noreturn]] void WiaTransferModel::protocol_failure(const char* message) {
    fail(TransferFailure::protocol_error);
    throw ScannerError(message);
}

void WiaTransferModel::fail(const TransferFailure failure) noexcept {
    state_ = TransferState::failed;
    failure_ = failure;
    page_open_ = false;
    current_page_bytes_ = 0U;
    declared_page_bytes_ = 0U;
}

void WiaTransferModel::configure(const SourceType source, const std::uint32_t requested_pages) {
    if (state_ != TransferState::idle) protocol_failure("transfer was configured out of sequence");
    if (requested_pages == 0U || requested_pages > limits_.max_pages ||
        (source == SourceType::flatbed && requested_pages != 1U)) {
        fail(TransferFailure::transfer_limit);
        throw ScannerError("requested transfer exceeds its limits");
    }
    source_ = source;
    requested_pages_ = requested_pages;
    state_ = TransferState::configured;
}

void WiaTransferModel::begin_transfer() {
    if (state_ != TransferState::configured) protocol_failure("transfer start was out of sequence");
    state_ = TransferState::transferring;
}

void WiaTransferModel::begin_page(
    const std::uint32_t width,
    const std::uint32_t height,
    const std::uint64_t declared_bytes) {
    if (state_ != TransferState::transferring || page_open_ || completed_pages_ >= requested_pages_) {
        protocol_failure("page start was out of sequence");
    }
    if (width == 0U || height == 0U || width > limits_.max_dimension || height > limits_.max_dimension ||
        declared_bytes == 0U || declared_bytes > limits_.max_page_bytes ||
        declared_bytes > limits_.max_total_bytes - completed_bytes_) {
        fail(TransferFailure::transfer_limit);
        throw ScannerError("page transfer exceeds its limits");
    }
    page_open_ = true;
    current_page_bytes_ = 0U;
    declared_page_bytes_ = declared_bytes;
}

void WiaTransferModel::accept_chunk(const std::uint64_t bytes) {
    if (state_ != TransferState::transferring || !page_open_ || bytes == 0U) {
        protocol_failure("transfer chunk was out of sequence");
    }
    if (bytes > limits_.max_page_bytes - current_page_bytes_ ||
        bytes > limits_.max_total_bytes - completed_bytes_ - current_page_bytes_ ||
        bytes > declared_page_bytes_ - current_page_bytes_) {
        fail(TransferFailure::transfer_limit);
        throw ScannerError("transfer chunk exceeds its limits");
    }
    current_page_bytes_ += bytes;
}

void WiaTransferModel::complete_page(const bool image_valid) {
    if (state_ != TransferState::transferring || !page_open_ || current_page_bytes_ == 0U ||
        current_page_bytes_ != declared_page_bytes_) {
        protocol_failure("page completion was out of sequence");
    }
    if (!image_valid) {
        fail(TransferFailure::invalid_image);
        throw ScannerError("transferred image failed validation");
    }
    ++completed_pages_;
    completed_bytes_ += current_page_bytes_;
    page_open_ = false;
    current_page_bytes_ = 0U;
    declared_page_bytes_ = 0U;
}

void WiaTransferModel::request_cancel() {
    if (state_ != TransferState::transferring) protocol_failure("cancellation was requested out of sequence");
    state_ = TransferState::cancelling;
}

void WiaTransferModel::acknowledge_cancel() {
    if (state_ != TransferState::cancelling) protocol_failure("cancellation acknowledgement was out of sequence");
    fail(TransferFailure::cancelled);
}

void WiaTransferModel::report_feeder_empty() {
    if (state_ != TransferState::transferring || page_open_ || source_ == SourceType::flatbed) {
        protocol_failure("feeder state was reported out of sequence");
    }
    if (completed_pages_ == 0U) {
        fail(TransferFailure::feeder_empty);
        return;
    }
    state_ = TransferState::completed;
    short_batch_ = completed_pages_ < requested_pages_;
}

void WiaTransferModel::report_failure(const TransferFailure failure) {
    if (state_ != TransferState::transferring && state_ != TransferState::cancelling) {
        protocol_failure("device failure was reported out of sequence");
    }
    if (failure != TransferFailure::paper_jam && failure != TransferFailure::device_lost) {
        protocol_failure("device failure code is invalid");
    }
    fail(failure);
}

void WiaTransferModel::finish_transfer() {
    if (state_ != TransferState::transferring || page_open_) {
        protocol_failure("transfer completion was out of sequence");
    }
    if (completed_pages_ != requested_pages_) {
        fail(TransferFailure::protocol_error);
        throw ScannerError("transfer ended before every requested page completed");
    }
    state_ = TransferState::completed;
}

TransferOutcome WiaTransferModel::outcome() const noexcept {
    return {state_, failure_, completed_pages_, completed_bytes_, short_batch_};
}

const char* transfer_failure_code(const TransferFailure failure) noexcept {
    switch (failure) {
        case TransferFailure::none: return "none";
        case TransferFailure::cancelled: return "cancelled";
        case TransferFailure::feeder_empty: return "feeder_empty";
        case TransferFailure::paper_jam: return "paper_jam";
        case TransferFailure::device_lost: return "device_lost";
        case TransferFailure::transfer_limit: return "transfer_limit";
        case TransferFailure::invalid_image: return "invalid_image";
        case TransferFailure::protocol_error: return "protocol_error";
    }
    return "protocol_error";
}

}  // namespace just_scanner
