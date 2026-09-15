#include "wsd_discovery_model.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <unordered_set>

#ifdef _WIN32
#include <windows.h>
#include <xmllite.h>
#endif

namespace just_scanner {
namespace {

constexpr std::string_view soap_namespace = "http://www.w3.org/2003/05/soap-envelope";
constexpr std::string_view addressing_namespace =
    "http://schemas.xmlsoap.org/ws/2004/08/addressing";
constexpr std::string_view discovery_namespace =
    "http://schemas.xmlsoap.org/ws/2005/04/discovery";
constexpr std::string_view transfer_namespace =
    "http://schemas.xmlsoap.org/ws/2004/09/transfer";
constexpr std::string_view metadata_namespace =
    "http://schemas.xmlsoap.org/ws/2004/09/mex";
constexpr std::string_view device_profile_namespace =
    "http://schemas.xmlsoap.org/ws/2006/02/devprof";
constexpr std::string_view deployed_scan_namespace =
    "http://schemas.microsoft.com/windows/2006/08/wdp/scan";
constexpr std::string_view documented_scan_namespace =
    "https://schemas.microsoft.com/windows/2006/01/wdp/scan";
constexpr std::string_view discovery_to =
    "urn:schemas-xmlsoap-org:ws:2005:04:discovery";
constexpr std::string_view anonymous_reply_to =
    "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous";

void validate_limits(const WsdDiscoveryLimits& limits) {
    if (limits.max_xml_bytes == 0U || limits.max_xml_bytes > 16U * 1024U * 1024U ||
        limits.max_datagrams == 0U || limits.max_datagrams > 1024U ||
        limits.max_matches_per_datagram == 0U || limits.max_matches_per_datagram > 256U ||
        limits.max_candidates == 0U || limits.max_candidates > 256U ||
        limits.max_uri_bytes == 0U || limits.max_uri_bytes > 8192U ||
        limits.max_public_text_bytes == 0U || limits.max_public_text_bytes > 1024U) {
        throw WsdScanError("invalid_wsd_discovery_limits");
    }
}

bool is_safe_message_id(const std::string_view value) {
    const std::size_t prefix = value.starts_with("urn:uuid:") ? 9U : 5U;
    if ((!value.starts_with("urn:uuid:") && !value.starts_with("uuid:")) ||
        value.size() <= prefix || value.size() > 128U) {
        return false;
    }
    return std::all_of(value.begin() + static_cast<std::ptrdiff_t>(prefix), value.end(),
                       [](const unsigned char character) {
        return std::isdigit(character) != 0 ||
               (character >= 'a' && character <= 'f') ||
               (character >= 'A' && character <= 'F') || character == '-';
    });
}

bool is_safe_logical_address(const std::string_view value, const std::size_t maximum) {
    if (value.empty() || value.size() > maximum) return false;
    if (value.starts_with("urn:uuid:")) return is_safe_message_id(value);
    return value.starts_with("http://") || value.starts_with("https://");
}

std::string xml_escape(const std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (const char character : value) {
        switch (character) {
            case '&': escaped += "&amp;"; break;
            case '<': escaped += "&lt;"; break;
            case '>': escaped += "&gt;"; break;
            case '"': escaped += "&quot;"; break;
            case '\'': escaped += "&apos;"; break;
            default:
                if (static_cast<unsigned char>(character) < 0x20U &&
                    character != '\t' && character != '\r' && character != '\n') {
                    throw WsdScanError("invalid_wsd_xml_text");
                }
                escaped.push_back(character);
                break;
        }
    }
    return escaped;
}

std::string trim_ascii(std::string value) {
    const auto space = [](const unsigned char character) {
        return std::isspace(character) != 0;
    };
    const auto first = std::find_if_not(value.begin(), value.end(), space);
    const auto last = std::find_if_not(value.rbegin(), value.rend(), space).base();
    if (first >= last) return {};
    return std::string(first, last);
}

std::vector<std::string> split_ascii_whitespace(const std::string& value) {
    std::istringstream input(value);
    std::vector<std::string> tokens;
    std::string token;
    while (input >> token) tokens.push_back(token);
    return tokens;
}

bool parse_ipv4(const std::string_view value, std::uint32_t& result) {
    std::uint32_t parsed = 0U;
    std::size_t start = 0U;
    for (unsigned part = 0U; part < 4U; ++part) {
        const auto end = value.find('.', start);
        if ((part < 3U && end == std::string_view::npos) ||
            (part == 3U && end != std::string_view::npos)) {
            return false;
        }
        const auto stop = end == std::string_view::npos ? value.size() : end;
        if (stop == start || stop - start > 3U) return false;
        unsigned octet = 0U;
        for (std::size_t index = start; index < stop; ++index) {
            const unsigned char character = static_cast<unsigned char>(value[index]);
            if (std::isdigit(character) == 0) return false;
            octet = octet * 10U + static_cast<unsigned>(character - '0');
            if (octet > 255U) return false;
        }
        parsed = (parsed << 8U) | octet;
        start = stop + 1U;
    }
    if (start != value.size() + 1U) return false;
    result = parsed;
    return true;
}

bool transport_host_matches(const std::string_view uri, const std::string_view remote_ipv4) {
    const std::size_t scheme_length = uri.starts_with("http://") ? 7U :
                                      uri.starts_with("https://") ? 8U : 0U;
    if (scheme_length == 0U) return false;
    const auto authority_end = uri.find_first_of("/?#", scheme_length);
    const auto authority = uri.substr(
        scheme_length,
        authority_end == std::string_view::npos ? uri.size() - scheme_length :
                                                  authority_end - scheme_length);
    if (authority.empty() || authority.find('@') != std::string_view::npos ||
        authority.starts_with('[')) {
        return false;
    }
    const auto colon = authority.find(':');
    const auto host = authority.substr(0U, colon);
    if (colon != std::string_view::npos) {
        const auto port = authority.substr(colon + 1U);
        if (port.empty() || port.size() > 5U ||
            !std::all_of(port.begin(), port.end(), [](const unsigned char character) {
                return std::isdigit(character) != 0;
            })) {
            return false;
        }
        unsigned port_value = 0U;
        for (const unsigned char character : port) {
            port_value = port_value * 10U + static_cast<unsigned>(character - '0');
        }
        if (port_value == 0U || port_value > 65535U) return false;
    }
    std::uint32_t uri_address = 0U;
    std::uint32_t remote_address = 0U;
    return parse_ipv4(host, uri_address) && parse_ipv4(remote_ipv4, remote_address) &&
           uri_address == remote_address;
}

bool valid_public_text(const std::string& value, const std::size_t maximum) {
    return !value.empty() && value.size() <= maximum &&
           std::none_of(value.begin(), value.end(), [](const unsigned char character) {
               return character < 0x20U || character == 0x7fU;
           });
}

std::string make_opaque_id(const std::size_t ordinal) {
    std::ostringstream output;
    output << "wsd-device-" << std::setw(4) << std::setfill('0') << ordinal;
    return output.str();
}

#ifdef _WIN32
class ComRelease final {
public:
    explicit ComRelease(IUnknown* value = nullptr) noexcept : value_(value) {}
    ~ComRelease() { if (value_ != nullptr) value_->Release(); }
    ComRelease(const ComRelease&) = delete;
    ComRelease& operator=(const ComRelease&) = delete;

private:
    IUnknown* value_;
};

std::string wide_to_utf8(const wchar_t* value, const UINT length) {
    if (value == nullptr || length == 0U) return {};
    if (length > static_cast<UINT>(std::numeric_limits<int>::max())) {
        throw WsdScanError("wsd_text_too_large");
    }
    const int required = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value, static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    if (required <= 0) throw WsdScanError("invalid_wsd_utf16");
    std::string output(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, static_cast<int>(length),
                            output.data(), required, nullptr, nullptr) != required) {
        throw WsdScanError("invalid_wsd_utf16");
    }
    return output;
}

std::wstring ascii_to_wide(const std::string_view value) {
    if (value.empty() || !std::all_of(value.begin(), value.end(), [](const unsigned char character) {
            return character >= 0x21U && character <= 0x7eU;
        })) {
        throw WsdScanError("invalid_wsd_qname_prefix");
    }
    return std::wstring(value.begin(), value.end());
}

class XmlReader final {
public:
    XmlReader(const std::string_view xml, const WsdDiscoveryLimits& limits) {
        try {
            validate_limits(limits);
            if (xml.empty() || xml.size() > limits.max_xml_bytes) {
                throw WsdScanError("wsd_xml_limit_exceeded");
            }
            if (xml.find("<!DOCTYPE") != std::string_view::npos ||
                xml.find("<!ENTITY") != std::string_view::npos) {
                throw WsdScanError("unsafe_wsd_xml_declaration");
            }
            memory_ = GlobalAlloc(GMEM_MOVEABLE, xml.size());
            if (memory_ == nullptr) throw WsdScanError("wsd_xml_memory_failure");
            void* bytes = GlobalLock(memory_);
            if (bytes == nullptr) throw WsdScanError("wsd_xml_memory_failure");
            std::memcpy(bytes, xml.data(), xml.size());
            GlobalUnlock(memory_);
            if (FAILED(CreateStreamOnHGlobal(memory_, TRUE, &stream_))) {
                throw WsdScanError("wsd_xml_stream_failure");
            }
            memory_owned_by_stream_ = true;
            if (FAILED(CreateXmlReader(
                    __uuidof(IXmlReader), reinterpret_cast<void**>(&reader_), nullptr)) ||
                reader_ == nullptr ||
                FAILED(reader_->SetProperty(
                    XmlReaderProperty_DtdProcessing, DtdProcessing_Prohibit)) ||
                FAILED(reader_->SetProperty(XmlReaderProperty_MaxElementDepth, 64)) ||
                FAILED(reader_->SetInput(stream_))) {
                throw WsdScanError("wsd_xml_reader_failure");
            }
        } catch (...) {
            release_resources();
            throw;
        }
    }

    ~XmlReader() { release_resources(); }
    XmlReader(const XmlReader&) = delete;
    XmlReader& operator=(const XmlReader&) = delete;

    bool read(XmlNodeType& type) {
        const HRESULT status = reader_->Read(&type);
        if (status == S_FALSE) return false;
        if (status != S_OK) throw WsdScanError("invalid_wsd_xml");
        if (++node_count_ > 10000U) throw WsdScanError("wsd_xml_node_limit_exceeded");
        if (type == XmlNodeType_Element) update_namespace_scope();
        return true;
    }

    std::string local_name() const {
        const wchar_t* value = nullptr;
        UINT length = 0U;
        if (FAILED(reader_->GetLocalName(&value, &length))) throw WsdScanError("invalid_wsd_xml");
        return wide_to_utf8(value, length);
    }

    std::string namespace_uri() const {
        const wchar_t* value = nullptr;
        UINT length = 0U;
        if (FAILED(reader_->GetNamespaceUri(&value, &length))) throw WsdScanError("invalid_wsd_xml");
        return wide_to_utf8(value, length);
    }

    std::string value() const {
        const wchar_t* value = nullptr;
        UINT length = 0U;
        if (FAILED(reader_->GetValue(&value, &length))) throw WsdScanError("invalid_wsd_xml");
        return wide_to_utf8(value, length);
    }

    std::string resolve_prefix(const std::string_view prefix) const {
        (void)ascii_to_wide(prefix);
        if (namespace_scopes_.empty()) return {};
        const auto found = namespace_scopes_.back().find(std::string(prefix));
        return found == namespace_scopes_.back().end() ? std::string{} : found->second;
    }

private:
    void release_resources() noexcept {
        if (reader_ != nullptr) {
            reader_->Release();
            reader_ = nullptr;
        }
        if (stream_ != nullptr) {
            stream_->Release();
            stream_ = nullptr;
            memory_ = nullptr;
        } else if (memory_ != nullptr && !memory_owned_by_stream_) {
            GlobalFree(memory_);
            memory_ = nullptr;
        }
    }

    void update_namespace_scope() {
        UINT depth = 0U;
        if (FAILED(reader_->GetDepth(&depth))) throw WsdScanError("invalid_wsd_xml");
        std::unordered_map<std::string, std::string> scope;
        if (depth > 0U && namespace_scopes_.size() >= depth) {
            scope = namespace_scopes_[depth - 1U];
        }

        HRESULT attribute_status = reader_->MoveToFirstAttribute();
        while (attribute_status == S_OK) {
            const wchar_t* local = nullptr;
            const wchar_t* uri = nullptr;
            const wchar_t* value = nullptr;
            UINT local_length = 0U;
            UINT uri_length = 0U;
            UINT value_length = 0U;
            if (FAILED(reader_->GetLocalName(&local, &local_length)) ||
                FAILED(reader_->GetNamespaceUri(&uri, &uri_length)) ||
                FAILED(reader_->GetValue(&value, &value_length))) {
                throw WsdScanError("invalid_wsd_xml");
            }
            const auto namespace_uri_value = wide_to_utf8(uri, uri_length);
            if (namespace_uri_value == "http://www.w3.org/2000/xmlns/") {
                auto prefix = wide_to_utf8(local, local_length);
                if (prefix == "xmlns") prefix.clear();
                scope[prefix] = wide_to_utf8(value, value_length);
            }
            attribute_status = reader_->MoveToNextAttribute();
        }
        if (attribute_status != S_FALSE || FAILED(reader_->MoveToElement())) {
            throw WsdScanError("invalid_wsd_xml");
        }
        namespace_scopes_.resize(static_cast<std::size_t>(depth) + 1U);
        namespace_scopes_[depth] = std::move(scope);
    }

    HGLOBAL memory_{};
    IStream* stream_{};
    IXmlReader* reader_{};
    bool memory_owned_by_stream_{false};
    std::size_t node_count_{};
    std::vector<std::unordered_map<std::string, std::string>> namespace_scopes_;
};

bool token_is_scan_type(XmlReader& reader, const std::string& token) {
    const auto separator = token.find(':');
    if (separator == std::string::npos || separator == 0U || separator + 1U >= token.size()) {
        return false;
    }
    const auto local = token.substr(separator + 1U);
    if (local != "ScanDeviceType" && local != "ScannerServiceType") return false;
    const auto uri = reader.resolve_prefix(std::string_view(token).substr(0U, separator));
    return uri == deployed_scan_namespace || uri == documented_scan_namespace;
}
#endif

}  // namespace

std::string encode_wsd_probe_request(
    const std::string_view message_id,
    const WsdDiscoveryLimits& limits) {
    validate_limits(limits);
    if (!is_safe_message_id(message_id)) throw WsdScanError("invalid_wsd_message_id");
    std::ostringstream xml;
    xml << "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        << "<soap:Envelope xmlns:soap=\"" << soap_namespace << "\" "
        << "xmlns:wsa=\"" << addressing_namespace << "\" "
        << "xmlns:wsd=\"" << discovery_namespace << "\" "
        << "xmlns:wscn=\"" << deployed_scan_namespace << "\">"
        << "<soap:Header><wsa:MessageID>" << message_id << "</wsa:MessageID>"
        << "<wsa:To soap:mustUnderstand=\"true\">" << discovery_to << "</wsa:To>"
        << "<wsa:Action soap:mustUnderstand=\"true\">" << discovery_namespace
        << "/Probe</wsa:Action></soap:Header><soap:Body><wsd:Probe>"
        << "<wsd:Types>wscn:ScanDeviceType</wsd:Types></wsd:Probe>"
        << "</soap:Body></soap:Envelope>";
    auto result = xml.str();
    if (result.size() > limits.max_xml_bytes) throw WsdScanError("wsd_xml_limit_exceeded");
    return result;
}

std::vector<WsdProbeCandidate> decode_wsd_probe_matches_response(
    const std::string_view xml,
    const std::string_view expected_relates_to,
    const std::string_view remote_ipv4,
    const WsdDiscoveryLimits& limits) {
    validate_limits(limits);
    if (!is_safe_message_id(expected_relates_to)) throw WsdScanError("invalid_wsd_message_id");
    std::uint32_t ignored_address = 0U;
    if (!parse_ipv4(remote_ipv4, ignored_address)) throw WsdScanError("invalid_wsd_remote_address");
#ifndef _WIN32
    (void)xml;
    throw WsdScanError("wsd_xml_decoder_unavailable");
#else
    XmlReader reader(xml, limits);
    bool envelope_seen = false;
    bool probe_matches_seen = false;
    bool in_match = false;
    bool in_endpoint_reference = false;
    enum class Field { none, relates_to, action, address, types, xaddrs } field = Field::none;
    std::string relates_to;
    std::string action;
    std::string address;
    std::string xaddrs;
    bool scan_type = false;
    std::vector<WsdProbeCandidate> result;
    XmlNodeType type = XmlNodeType_None;
    while (reader.read(type)) {
        if (type == XmlNodeType_Element) {
            const auto local = reader.local_name();
            const auto uri = reader.namespace_uri();
            if (local == "Envelope" && uri == soap_namespace) envelope_seen = true;
            else if (local == "ProbeMatches" && uri == discovery_namespace) probe_matches_seen = true;
            else if (local == "ProbeMatch" && uri == discovery_namespace) {
                if (in_match) throw WsdScanError("nested_wsd_probe_match");
                in_match = true;
                address.clear();
                xaddrs.clear();
                scan_type = false;
            } else if (in_match && local == "EndpointReference" && uri == addressing_namespace) {
                in_endpoint_reference = true;
            } else if (local == "RelatesTo" && uri == addressing_namespace) field = Field::relates_to;
            else if (local == "Action" && uri == addressing_namespace) field = Field::action;
            else if (in_match && in_endpoint_reference && local == "Address" &&
                     uri == addressing_namespace) field = Field::address;
            else if (in_match && local == "Types" && uri == discovery_namespace) field = Field::types;
            else if (in_match && local == "XAddrs" && uri == discovery_namespace) field = Field::xaddrs;
        } else if (type == XmlNodeType_Text || type == XmlNodeType_CDATA) {
            const auto text = reader.value();
            switch (field) {
                case Field::relates_to: relates_to += text; break;
                case Field::action: action += text; break;
                case Field::address: address += text; break;
                case Field::xaddrs: xaddrs += text; break;
                case Field::types:
                    for (const auto& token : split_ascii_whitespace(text)) {
                        if (token_is_scan_type(reader, token)) scan_type = true;
                    }
                    break;
                case Field::none: break;
            }
        } else if (type == XmlNodeType_EndElement) {
            const auto local = reader.local_name();
            const auto uri = reader.namespace_uri();
            if (local == "EndpointReference" && uri == addressing_namespace) {
                in_endpoint_reference = false;
            }
            if (local == "ProbeMatch" && uri == discovery_namespace) {
                if (result.size() == limits.max_matches_per_datagram) {
                    throw WsdScanError("wsd_probe_match_limit_exceeded");
                }
                address = trim_ascii(std::move(address));
                xaddrs = trim_ascii(std::move(xaddrs));
                if (scan_type && is_safe_logical_address(address, limits.max_uri_bytes)) {
                    for (const auto& transport : split_ascii_whitespace(xaddrs)) {
                        if (transport.size() <= limits.max_uri_bytes &&
                            transport_host_matches(transport, remote_ipv4)) {
                            result.push_back({address, transport});
                            break;
                        }
                    }
                }
                in_match = false;
            }
            field = Field::none;
        }
    }
    relates_to = trim_ascii(std::move(relates_to));
    action = trim_ascii(std::move(action));
    if (!envelope_seen || !probe_matches_seen || in_match || relates_to != expected_relates_to ||
        action != std::string(discovery_namespace) + "/ProbeMatches") {
        throw WsdScanError("invalid_wsd_probe_matches_response");
    }
    return result;
#endif
}

std::string encode_dpws_get_metadata_request(
    const std::string_view logical_device_address,
    const std::string_view message_id,
    const WsdDiscoveryLimits& limits) {
    validate_limits(limits);
    if (!is_safe_logical_address(logical_device_address, limits.max_uri_bytes)) {
        throw WsdScanError("invalid_wsd_logical_address");
    }
    if (!is_safe_message_id(message_id)) throw WsdScanError("invalid_wsd_message_id");
    std::ostringstream xml;
    xml << "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        << "<soap:Envelope xmlns:soap=\"" << soap_namespace << "\" "
        << "xmlns:wsa=\"" << addressing_namespace << "\">"
        << "<soap:Header><wsa:Action soap:mustUnderstand=\"true\">"
        << transfer_namespace << "/Get</wsa:Action><wsa:MessageID>" << message_id
        << "</wsa:MessageID><wsa:ReplyTo><wsa:Address>" << anonymous_reply_to
        << "</wsa:Address></wsa:ReplyTo><wsa:To soap:mustUnderstand=\"true\">"
        << xml_escape(logical_device_address)
        << "</wsa:To></soap:Header><soap:Body /></soap:Envelope>";
    auto result = xml.str();
    if (result.size() > limits.max_xml_bytes) throw WsdScanError("wsd_xml_limit_exceeded");
    return result;
}

WsdDeviceMetadata decode_dpws_get_metadata_response(
    const std::string_view xml,
    const std::string_view expected_relates_to,
    const WsdDiscoveryLimits& limits) {
    validate_limits(limits);
    if (!is_safe_message_id(expected_relates_to)) throw WsdScanError("invalid_wsd_message_id");
#ifndef _WIN32
    (void)xml;
    throw WsdScanError("wsd_xml_decoder_unavailable");
#else
    XmlReader reader(xml, limits);
    bool envelope_seen = false;
    bool metadata_seen = false;
    bool in_this_model = false;
    bool in_host = false;
    bool in_hosted = false;
    bool in_endpoint_reference = false;
    enum class Field {
        none, relates_to, action, manufacturer, model_name, host_address,
        service_address, hosted_types
    } field = Field::none;
    std::string relates_to;
    std::string action;
    WsdDeviceMetadata result;
    bool hosted_scan_type = false;
    std::string current_service_address;
    std::string current_scan_namespace;
    XmlNodeType type = XmlNodeType_None;
    while (reader.read(type)) {
        if (type == XmlNodeType_Element) {
            const auto local = reader.local_name();
            const auto uri = reader.namespace_uri();
            if (local == "Envelope" && uri == soap_namespace) envelope_seen = true;
            else if (local == "Metadata" && uri == metadata_namespace) metadata_seen = true;
            else if (local == "ThisModel" && uri == device_profile_namespace) in_this_model = true;
            else if (local == "Host" && uri == device_profile_namespace) in_host = true;
            else if (local == "Hosted" && uri == device_profile_namespace) {
                in_hosted = true;
                hosted_scan_type = false;
                current_service_address.clear();
                current_scan_namespace.clear();
            } else if ((in_host || in_hosted) && local == "EndpointReference" &&
                       uri == addressing_namespace) {
                in_endpoint_reference = true;
            } else if (local == "RelatesTo" && uri == addressing_namespace) field = Field::relates_to;
            else if (local == "Action" && uri == addressing_namespace) field = Field::action;
            else if (in_this_model && local == "Manufacturer" && uri == device_profile_namespace) {
                field = Field::manufacturer;
            } else if (in_this_model && local == "ModelName" && uri == device_profile_namespace) {
                field = Field::model_name;
            } else if (in_host && in_endpoint_reference && local == "Address" &&
                       uri == addressing_namespace) {
                field = Field::host_address;
            } else if (in_hosted && in_endpoint_reference && local == "Address" &&
                       uri == addressing_namespace) {
                field = Field::service_address;
            } else if (in_hosted && local == "Types" && uri == device_profile_namespace) {
                field = Field::hosted_types;
            }
        } else if (type == XmlNodeType_Text || type == XmlNodeType_CDATA) {
            const auto text = reader.value();
            switch (field) {
                case Field::relates_to: relates_to += text; break;
                case Field::action: action += text; break;
                case Field::manufacturer: result.manufacturer += text; break;
                case Field::model_name: result.model_name += text; break;
                case Field::host_address: result.logical_device_address += text; break;
                case Field::service_address: current_service_address += text; break;
                case Field::hosted_types:
                    for (const auto& token : split_ascii_whitespace(text)) {
                        if (token_is_scan_type(reader, token)) {
                            hosted_scan_type = true;
                            const auto separator = token.find(':');
                            current_scan_namespace = reader.resolve_prefix(
                                std::string_view(token).substr(0U, separator));
                        }
                    }
                    break;
                case Field::none: break;
            }
        } else if (type == XmlNodeType_EndElement) {
            const auto local = reader.local_name();
            const auto uri = reader.namespace_uri();
            if (local == "EndpointReference" && uri == addressing_namespace) {
                in_endpoint_reference = false;
            } else if (local == "ThisModel" && uri == device_profile_namespace) {
                in_this_model = false;
            } else if (local == "Host" && uri == device_profile_namespace) {
                in_host = false;
            } else if (local == "Hosted" && uri == device_profile_namespace) {
                if (hosted_scan_type && result.logical_service_address.empty()) {
                    result.logical_service_address = trim_ascii(std::move(current_service_address));
                    result.scan_namespace = std::move(current_scan_namespace);
                }
                in_hosted = false;
            }
            field = Field::none;
        }
    }
    relates_to = trim_ascii(std::move(relates_to));
    action = trim_ascii(std::move(action));
    result.manufacturer = trim_ascii(std::move(result.manufacturer));
    result.model_name = trim_ascii(std::move(result.model_name));
    result.logical_device_address = trim_ascii(std::move(result.logical_device_address));
    result.logical_service_address = trim_ascii(std::move(result.logical_service_address));
    if (!envelope_seen || !metadata_seen || relates_to != expected_relates_to ||
        action != std::string(transfer_namespace) + "/GetResponse" ||
        !valid_public_text(result.manufacturer, limits.max_public_text_bytes) ||
        !valid_public_text(result.model_name, limits.max_public_text_bytes) ||
        !is_safe_logical_address(result.logical_device_address, limits.max_uri_bytes) ||
        !is_safe_logical_address(result.logical_service_address, limits.max_uri_bytes) ||
        (result.scan_namespace != deployed_scan_namespace &&
         result.scan_namespace != documented_scan_namespace)) {
        throw WsdScanError("invalid_dpws_metadata_response");
    }
    return result;
#endif
}

WsdDiscoveryModel::WsdDiscoveryModel(WsdDiscoveryLimits limits) : limits_(limits) {
    validate_limits(limits_);
}

WsdDiscoveryResult WsdDiscoveryModel::refresh(
    IWsdDiscoveryExchange& exchange,
    const std::string_view probe_message_id,
    const std::vector<std::string>& metadata_message_ids,
    const std::atomic_bool& cancel_requested) {
    if (generation_ == std::numeric_limits<std::uint64_t>::max()) {
        throw WsdScanError("wsd_discovery_generation_limit");
    }
    ++generation_;
    endpoints_.clear();
    WsdDiscoveryResult result;
    result.generation = generation_;
    if (cancel_requested.load()) {
        result.issue_codes.push_back("cancelled");
        return result;
    }

    const auto request = encode_wsd_probe_request(probe_message_id, limits_);
    const auto datagrams = exchange.probe(request, cancel_requested);
    if (cancel_requested.load()) {
        result.issue_codes.push_back("cancelled");
        return result;
    }
    if (datagrams.size() > limits_.max_datagrams) {
        result.issue_codes.push_back("discovery_limit");
        return result;
    }

    std::vector<WsdProbeCandidate> candidates;
    std::unordered_set<std::string> candidate_addresses;
    for (const auto& datagram : datagrams) {
        try {
            for (auto& candidate : decode_wsd_probe_matches_response(
                     datagram.xml, probe_message_id, datagram.remote_ipv4, limits_)) {
                if (!candidate_addresses.insert(candidate.logical_device_address).second) continue;
                if (candidates.size() == limits_.max_candidates) {
                    result.issue_codes.push_back("candidate_limit");
                    candidates.clear();
                    return result;
                }
                candidates.push_back(std::move(candidate));
            }
        } catch (const WsdScanError&) {
            result.issue_codes.push_back("invalid_probe_response");
        }
    }

    if (metadata_message_ids.size() < candidates.size()) {
        result.issue_codes.push_back("metadata_id_limit");
        return result;
    }
    std::unordered_set<std::string> confirmed_addresses;
    for (std::size_t index = 0U; index < candidates.size(); ++index) {
        if (cancel_requested.load()) {
            endpoints_.clear();
            result.devices.clear();
            result.issue_codes.push_back("cancelled");
            return result;
        }
        try {
            const auto metadata_request = encode_dpws_get_metadata_request(
                candidates[index].logical_device_address, metadata_message_ids[index], limits_);
            const auto metadata_xml = exchange.get_metadata(
                candidates[index], metadata_request, cancel_requested);
            const auto metadata = decode_dpws_get_metadata_response(
                metadata_xml, metadata_message_ids[index], limits_);
            if (metadata.logical_device_address != candidates[index].logical_device_address) {
                result.issue_codes.push_back("metadata_device_mismatch");
                continue;
            }
            if (!confirmed_addresses.insert(metadata.logical_device_address).second) continue;
            const auto opaque_id = make_opaque_id(result.devices.size() + 1U);
            endpoints_.emplace(opaque_id, WsdResolvedEndpoint{
                candidates[index].transport_uri,
                metadata.logical_service_address,
                metadata.scan_namespace,
            });
            result.devices.push_back({opaque_id, metadata.model_name, metadata.manufacturer});
        } catch (const WsdScanError&) {
            result.issue_codes.push_back("invalid_metadata_response");
        }
    }
    return result;
}

WsdResolvedEndpoint WsdDiscoveryModel::resolve_for_connection(
    const std::string& opaque_id,
    const std::uint64_t generation) const {
    if (generation == 0U || generation != generation_) {
        throw WsdScanError("WSD scanner selection is stale");
    }
    const auto found = endpoints_.find(opaque_id);
    if (found == endpoints_.end()) throw WsdScanError("WSD scanner selection is unavailable");
    return found->second;
}

}  // namespace just_scanner
