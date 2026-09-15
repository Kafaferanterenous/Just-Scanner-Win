#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace just_scanner {

enum class WiaDeviceClass { scanner, camera, video, unknown };

struct WiaDiscoveredDevice {
    WiaDeviceClass device_class{WiaDeviceClass::unknown};
    std::string raw_device_id;
    std::string display_name;
    std::string manufacturer;
};

struct PublicWiaDevice {
    std::string opaque_id;
    std::string display_name;
    std::string manufacturer;
};

struct WiaDiscoveryResult {
    std::uint64_t generation{};
    std::vector<PublicWiaDevice> devices;
    std::vector<std::string> issue_codes;
};

class WiaDiscoveryModel {
public:
    WiaDiscoveryResult refresh(const std::vector<WiaDiscoveredDevice>& discovered);
    std::string resolve_for_connection(const std::string& opaque_id, std::uint64_t generation) const;
    std::uint64_t generation() const noexcept { return generation_; }

private:
    std::uint64_t generation_{};
    std::unordered_map<std::string, std::string> raw_ids_;
};

}  // namespace just_scanner
