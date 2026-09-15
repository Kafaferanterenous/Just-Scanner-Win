#pragma once

#include "scanner_core.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace just_scanner {

enum class WiaItemCategory { root, flatbed, feeder, feeder_front, feeder_back, film, unknown };
enum class WiaPropertyShape { scalar, list, range, flags };
enum class WiaDataType : std::int32_t { threshold = 1, grayscale = 2, color = 3 };

enum WiaHandlingFlag : std::uint32_t {
    wia_flatbed = 1U << 0U,
    wia_feeder = 1U << 1U,
    wia_duplex = 1U << 2U,
    wia_advanced_duplex = 1U << 3U,
};

struct WiaIntProperty {
    WiaPropertyShape shape{WiaPropertyShape::scalar};
    std::int32_t current{};
    std::vector<std::int32_t> values;
    std::int32_t minimum{};
    std::int32_t maximum{};
    std::int32_t step{};
    bool readable{true};
    bool writable{};
};

struct WiaItemModel {
    WiaItemCategory category{WiaItemCategory::unknown};
    bool transfer_capable{};
    std::optional<WiaIntProperty> x_resolution;
    std::optional<WiaIntProperty> y_resolution;
    std::optional<WiaIntProperty> data_type;
    std::optional<WiaIntProperty> bit_depth;
    std::optional<WiaIntProperty> page_count;
    std::optional<WiaIntProperty> handling_capabilities;
};

struct WiaDeviceModel {
    std::string opaque_id;
    std::vector<WiaItemModel> items;
};

struct SourceCapabilityProfile {
    SourceType source{SourceType::flatbed};
    std::vector<std::uint32_t> dpi_values;
    std::vector<ColorMode> color_modes;
    std::vector<std::uint32_t> bit_depths;
    std::uint32_t max_pages{1U};
    bool advanced_duplex{};
};

struct WiaCapabilityResult {
    std::vector<SourceCapabilityProfile> profiles;
    std::vector<std::string> issue_codes;
};

struct WiaReadback {
    std::uint32_t x_dpi{};
    std::uint32_t y_dpi{};
    ColorMode color{ColorMode::gray8};
    std::uint32_t bit_depth{};
    std::uint32_t pages{};
};

struct AcceptedWiaSettings {
    std::uint32_t dpi{};
    ColorMode color{ColorMode::gray8};
    std::uint32_t bit_depth{};
    std::uint32_t pages{};
    bool driver_coerced{};
};

struct WiaPropertyWriteSet {
    std::int32_t x_dpi{};
    std::int32_t y_dpi{};
    std::int32_t data_type{};
    std::int32_t bit_depth{};
    std::int32_t pages{};
};

WiaCapabilityResult map_wia_capabilities(const WiaDeviceModel& device);
WiaPropertyWriteSet prepare_wia_property_writes(
    const WiaCapabilityResult& capabilities,
    const ScanRequest& request);
AcceptedWiaSettings validate_wia_readback(
    const SourceCapabilityProfile& profile,
    const ScanRequest& request,
    const WiaReadback& readback);

}  // namespace just_scanner
