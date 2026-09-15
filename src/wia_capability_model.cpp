#include "wia_capability_model.h"

#include <algorithm>
#include <limits>
#include <set>

namespace just_scanner {
namespace {

constexpr std::int32_t kMinDpi = 50;
constexpr std::int32_t kMaxDpi = 9600;
constexpr std::size_t kMaxPropertyValues = 256U;

std::vector<std::int32_t> allowed_values(const WiaIntProperty& property, const char* issue) {
    if (!property.readable) throw ScannerError(issue);
    if (property.shape == WiaPropertyShape::list) {
        if (property.values.empty() || property.values.size() > kMaxPropertyValues) throw ScannerError(issue);
        std::set<std::int32_t> unique(property.values.begin(), property.values.end());
        return {unique.begin(), unique.end()};
    }
    if (property.shape == WiaPropertyShape::range) {
        if (property.step <= 0 || property.minimum > property.maximum) throw ScannerError(issue);
        const auto span = static_cast<std::int64_t>(property.maximum) - property.minimum;
        if (span / property.step + 1 > static_cast<std::int64_t>(kMaxPropertyValues)) throw ScannerError(issue);
        std::vector<std::int32_t> values;
        for (std::int64_t value = property.minimum; value <= property.maximum; value += property.step) {
            values.push_back(static_cast<std::int32_t>(value));
        }
        return values;
    }
    if (property.shape == WiaPropertyShape::scalar) return {property.current};
    throw ScannerError(issue);
}

std::vector<std::uint32_t> resolution_intersection(const WiaItemModel& item) {
    if (!item.x_resolution.has_value() || !item.y_resolution.has_value()) {
        throw ScannerError("missing_resolution");
    }
    const auto x = allowed_values(*item.x_resolution, "invalid_x_resolution");
    const auto y = allowed_values(*item.y_resolution, "invalid_y_resolution");
    std::vector<std::uint32_t> result;
    for (const auto value : x) {
        if (value >= kMinDpi && value <= kMaxDpi && std::binary_search(y.begin(), y.end(), value)) {
            result.push_back(static_cast<std::uint32_t>(value));
        }
    }
    if (result.empty()) throw ScannerError("no_compatible_resolution");
    return result;
}

std::vector<ColorMode> color_modes(const WiaItemModel& item) {
    if (!item.data_type.has_value()) throw ScannerError("missing_data_type");
    const auto values = allowed_values(*item.data_type, "invalid_data_type");
    std::vector<ColorMode> result;
    if (std::find(values.begin(), values.end(), static_cast<std::int32_t>(WiaDataType::grayscale)) != values.end()) {
        result.push_back(ColorMode::gray8);
    }
    if (std::find(values.begin(), values.end(), static_cast<std::int32_t>(WiaDataType::color)) != values.end()) {
        result.push_back(ColorMode::rgb24);
    }
    if (result.empty()) throw ScannerError("unsupported_data_type");
    return result;
}

std::vector<std::uint32_t> bit_depths(const WiaItemModel& item) {
    if (!item.bit_depth.has_value()) throw ScannerError("missing_bit_depth");
    const auto values = allowed_values(*item.bit_depth, "invalid_bit_depth");
    std::vector<std::uint32_t> result;
    for (const auto value : values) {
        if (value == 1 || value == 8 || value == 16 || value == 24 || value == 48) {
            result.push_back(static_cast<std::uint32_t>(value));
        }
    }
    if (result.empty()) throw ScannerError("unsupported_bit_depth");
    return result;
}

std::uint32_t max_pages(const WiaItemModel& item) {
    if (!item.page_count.has_value()) throw ScannerError("missing_page_count");
    const auto& pages = *item.page_count;
    if (!pages.readable || pages.shape != WiaPropertyShape::range || pages.minimum < 0 ||
        pages.maximum <= 0 || pages.step <= 0) {
        throw ScannerError("invalid_page_count");
    }
    return static_cast<std::uint32_t>(std::min<std::int32_t>(pages.maximum, 10000));
}

std::uint32_t handling_flags(const WiaItemModel& item) {
    if (!item.handling_capabilities.has_value()) return 0U;
    const auto& property = *item.handling_capabilities;
    if (!property.readable || property.shape != WiaPropertyShape::flags || property.current < 0) {
        throw ScannerError("invalid_handling_capabilities");
    }
    return static_cast<std::uint32_t>(property.current);
}

SourceCapabilityProfile profile_for(const WiaItemModel& item, const SourceType source) {
    if (!item.transfer_capable) throw ScannerError("item_not_transfer_capable");
    SourceCapabilityProfile profile;
    profile.source = source;
    profile.dpi_values = resolution_intersection(item);
    profile.color_modes = color_modes(item);
    profile.bit_depths = bit_depths(item);
    profile.max_pages = source == SourceType::flatbed ? 1U : max_pages(item);
    return profile;
}

template <typename T>
bool has(const std::vector<T>& values, const T value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

void validate_request(const SourceCapabilityProfile& profile, const ScanRequest& request) {
    if (profile.source != request.source || !has(profile.dpi_values, request.dpi) ||
        !has(profile.color_modes, request.color) || !has(profile.bit_depths, request.bit_depth) ||
        request.max_pages == 0U || request.max_pages > profile.max_pages) {
        throw ScannerError("requested settings are not supported");
    }
}

}  // namespace

WiaCapabilityResult map_wia_capabilities(const WiaDeviceModel& device) {
    WiaCapabilityResult result;
    if (device.opaque_id.empty() || device.opaque_id.size() > 64U) {
        result.issue_codes.push_back("invalid_opaque_device_id");
        return result;
    }
    const bool has_front = std::any_of(device.items.begin(), device.items.end(),
                                       [](const WiaItemModel& item) { return item.category == WiaItemCategory::feeder_front; });
    const bool has_back = std::any_of(device.items.begin(), device.items.end(),
                                      [](const WiaItemModel& item) { return item.category == WiaItemCategory::feeder_back; });
    bool saw_flatbed = false;
    bool saw_feeder = false;
    for (const auto& item : device.items) {
        try {
            if (item.category == WiaItemCategory::flatbed) {
                if (saw_flatbed) throw ScannerError("duplicate_flatbed");
                saw_flatbed = true;
                result.profiles.push_back(profile_for(item, SourceType::flatbed));
            } else if (item.category == WiaItemCategory::feeder) {
                if (saw_feeder) throw ScannerError("duplicate_feeder");
                saw_feeder = true;
                auto simplex = profile_for(item, SourceType::adf_simplex);
                result.profiles.push_back(simplex);
                const auto flags = handling_flags(item);
                if ((flags & wia_duplex) != 0U) {
                    auto duplex = simplex;
                    duplex.source = SourceType::adf_duplex;
                    duplex.advanced_duplex = (flags & wia_advanced_duplex) != 0U && has_front && has_back;
                    result.profiles.push_back(std::move(duplex));
                    if ((flags & wia_advanced_duplex) != 0U && (!has_front || !has_back)) {
                        result.issue_codes.push_back("incomplete_advanced_duplex_tree");
                    }
                }
            }
        } catch (const ScannerError& error) {
            result.issue_codes.push_back(error.what());
        }
    }
    if (!saw_flatbed && !saw_feeder) result.issue_codes.push_back("no_supported_scan_item");
    return result;
}

WiaPropertyWriteSet prepare_wia_property_writes(
    const WiaCapabilityResult& capabilities,
    const ScanRequest& request) {
    const auto match = std::find_if(capabilities.profiles.begin(), capabilities.profiles.end(),
                                    [&](const SourceCapabilityProfile& profile) {
                                        return profile.source == request.source;
                                    });
    if (match == capabilities.profiles.end()) throw ScannerError("requested source is unavailable");
    validate_request(*match, request);
    const auto data_type = request.color == ColorMode::gray8 ? WiaDataType::grayscale : WiaDataType::color;
    if (request.dpi > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()) ||
        request.bit_depth > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()) ||
        request.max_pages > static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max())) {
        throw ScannerError("requested settings exceed the WIA property range");
    }
    return {static_cast<std::int32_t>(request.dpi), static_cast<std::int32_t>(request.dpi),
            static_cast<std::int32_t>(data_type), static_cast<std::int32_t>(request.bit_depth),
            static_cast<std::int32_t>(request.max_pages)};
}

AcceptedWiaSettings validate_wia_readback(
    const SourceCapabilityProfile& profile,
    const ScanRequest& request,
    const WiaReadback& readback) {
    validate_request(profile, request);
    if (readback.x_dpi != readback.y_dpi || !has(profile.dpi_values, readback.x_dpi) ||
        !has(profile.color_modes, readback.color) || !has(profile.bit_depths, readback.bit_depth) ||
        readback.pages == 0U || readback.pages > profile.max_pages) {
        throw ScannerError("driver read-back is outside reported capabilities");
    }
    return {readback.x_dpi, readback.color, readback.bit_depth, readback.pages,
            readback.x_dpi != request.dpi || readback.color != request.color ||
                readback.bit_depth != request.bit_depth || readback.pages != request.max_pages};
}

}  // namespace just_scanner
