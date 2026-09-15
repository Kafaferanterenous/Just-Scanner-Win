#pragma once

#include "wsd_scan_model.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace just_scanner {

struct WsdDiscoveryLimits {
    std::size_t max_xml_bytes{1024U * 1024U};
    std::size_t max_datagrams{32U};
    std::size_t max_matches_per_datagram{16U};
    std::size_t max_candidates{16U};
    std::size_t max_uri_bytes{2048U};
    std::size_t max_public_text_bytes{256U};
};

struct WsdReceivedDatagram {
    std::string xml;
    std::string remote_ipv4;
};

struct WsdProbeCandidate {
    // These routing values are private implementation data. They must not be
    // placed in UI text, journals, support bundles, or public discovery results.
    std::string logical_device_address;
    std::string transport_uri;
};

struct WsdDeviceMetadata {
    std::string manufacturer;
    std::string model_name;
    std::string logical_device_address;
    std::string logical_service_address;
    std::string scan_namespace;
};

struct PublicWsdDevice {
    std::string opaque_id;
    std::string display_name;
    std::string manufacturer;
};

struct WsdResolvedEndpoint {
    std::string transport_uri;
    std::string logical_service_address;
    std::string scan_namespace;
};

struct WsdDiscoveryResult {
    std::uint64_t generation{};
    std::vector<PublicWsdDevice> devices;
    std::vector<std::string> issue_codes;
};

// Injectable seam only. No production network implementation is provided by
// this milestone, so constructing and testing WsdDiscoveryModel cannot contact
// a scanner or the network.
class IWsdDiscoveryExchange {
public:
    virtual ~IWsdDiscoveryExchange() = default;
    virtual std::vector<WsdReceivedDatagram> probe(
        std::string_view request_xml,
        const std::atomic_bool& cancel_requested) = 0;
    virtual std::string get_metadata(
        const WsdProbeCandidate& candidate,
        std::string_view request_xml,
        const std::atomic_bool& cancel_requested) = 0;
};

std::string encode_wsd_probe_request(
    std::string_view message_id,
    const WsdDiscoveryLimits& limits = {});

std::vector<WsdProbeCandidate> decode_wsd_probe_matches_response(
    std::string_view xml,
    std::string_view expected_relates_to,
    std::string_view remote_ipv4,
    const WsdDiscoveryLimits& limits = {});

std::string encode_dpws_get_metadata_request(
    std::string_view logical_device_address,
    std::string_view message_id,
    const WsdDiscoveryLimits& limits = {});

WsdDeviceMetadata decode_dpws_get_metadata_response(
    std::string_view xml,
    std::string_view expected_relates_to,
    const WsdDiscoveryLimits& limits = {});

class WsdDiscoveryModel {
public:
    explicit WsdDiscoveryModel(WsdDiscoveryLimits limits = {});

    WsdDiscoveryResult refresh(
        IWsdDiscoveryExchange& exchange,
        std::string_view probe_message_id,
        const std::vector<std::string>& metadata_message_ids,
        const std::atomic_bool& cancel_requested);

    WsdResolvedEndpoint resolve_for_connection(
        const std::string& opaque_id,
        std::uint64_t generation) const;

    std::uint64_t generation() const noexcept { return generation_; }

private:
    WsdDiscoveryLimits limits_;
    std::uint64_t generation_{};
    std::unordered_map<std::string, WsdResolvedEndpoint> endpoints_;
};

}  // namespace just_scanner
