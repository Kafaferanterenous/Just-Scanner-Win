#include "wia_discovery_model.h"

#include "scanner_core.h"

#include <algorithm>
#include <iomanip>
#include <limits>
#include <sstream>
#include <unordered_set>

namespace just_scanner {
namespace {

constexpr std::size_t kMaxRawIdBytes = 4096U;
constexpr std::size_t kMaxPublicTextBytes = 128U;
constexpr std::size_t kMaxDiscoveredDevices = 1024U;

bool valid_driver_text(const std::string& value, const std::size_t maximum) {
    return !value.empty() && value.size() <= maximum &&
           std::none_of(value.begin(), value.end(), [](const unsigned char ch) {
               return ch < 0x20U || ch == 0x7fU;
           });
}

std::string make_opaque_id(const std::size_t ordinal) {
    std::ostringstream output;
    output << "wia-device-" << std::setw(4) << std::setfill('0') << ordinal;
    return output.str();
}

}  // namespace

WiaDiscoveryResult WiaDiscoveryModel::refresh(const std::vector<WiaDiscoveredDevice>& discovered) {
    if (generation_ == std::numeric_limits<std::uint64_t>::max()) {
        throw ScannerError("WIA discovery generation limit was reached");
    }
    ++generation_;
    raw_ids_.clear();

    WiaDiscoveryResult result;
    result.generation = generation_;
    if (discovered.size() > kMaxDiscoveredDevices) {
        result.issue_codes.push_back("discovery_limit");
        return result;
    }

    std::unordered_set<std::string> seen_raw_ids;
    for (const auto& candidate : discovered) {
        if (candidate.device_class != WiaDeviceClass::scanner) continue;
        if (!valid_driver_text(candidate.raw_device_id, kMaxRawIdBytes)) {
            result.issue_codes.push_back("invalid_device_id");
            continue;
        }
        if (!seen_raw_ids.insert(candidate.raw_device_id).second) {
            result.issue_codes.push_back("duplicate_device_id");
            continue;
        }
        if (!valid_driver_text(candidate.display_name, kMaxPublicTextBytes) ||
            !valid_driver_text(candidate.manufacturer, kMaxPublicTextBytes)) {
            result.issue_codes.push_back("invalid_public_metadata");
            continue;
        }
        const auto token = make_opaque_id(result.devices.size() + 1U);
        raw_ids_.emplace(token, candidate.raw_device_id);
        result.devices.push_back({token, candidate.display_name, candidate.manufacturer});
    }
    return result;
}

std::string WiaDiscoveryModel::resolve_for_connection(
    const std::string& opaque_id,
    const std::uint64_t generation) const {
    if (generation == 0U || generation != generation_) {
        throw ScannerError("scanner selection is stale");
    }
    const auto found = raw_ids_.find(opaque_id);
    if (found == raw_ids_.end()) throw ScannerError("scanner selection is unavailable");
    return found->second;
}

}  // namespace just_scanner
