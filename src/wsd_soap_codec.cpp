#include "wsd_soap_codec.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <functional>
#include <limits>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <xmllite.h>
#endif

namespace just_scanner {
namespace {

constexpr std::string_view deployed_scan_namespace =
    "http://schemas.microsoft.com/windows/2006/08/wdp/scan";
constexpr std::string_view documented_scan_namespace =
    "https://schemas.microsoft.com/windows/2006/01/wdp/scan";
constexpr std::string_view deployed_soap_namespace =
    "http://www.w3.org/2003/05/soap-envelope";
constexpr std::string_view deployed_addressing_namespace =
    "http://schemas.xmlsoap.org/ws/2004/08/addressing";
constexpr std::string_view anonymous_reply_to =
    "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous";

void validate_codec_limits(const WsdSafetyLimits& limits) {
    if (limits.max_xml_bytes == 0U || limits.max_xml_bytes > 16U * 1024U * 1024U) {
        throw WsdScanError("invalid_wsd_xml_limit");
    }
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

bool is_safe_message_id(const std::string_view message_id) {
    const std::size_t prefix_length = message_id.starts_with("urn:uuid:") ? 9U : 5U;
    if ((!message_id.starts_with("uuid:") && !message_id.starts_with("urn:uuid:")) ||
        message_id.size() <= prefix_length || message_id.size() > 128U) {
        return false;
    }
    return std::all_of(message_id.begin() + static_cast<std::ptrdiff_t>(prefix_length),
                       message_id.end(), [](const char character) {
        const auto value = static_cast<unsigned char>(character);
        return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') ||
               (value >= 'A' && value <= 'F') || character == '-';
    });
}

bool is_scan_namespace(const std::string_view value) {
    return value == deployed_scan_namespace || value == documented_scan_namespace;
}

bool is_safe_service_address(const std::string_view value) {
    return value.starts_with("http://") || value.starts_with("https://") ||
           (value.starts_with("urn:uuid:") && is_safe_message_id(value));
}

std::string_view element_qname(const WsdScannerElement element) {
    switch (element) {
        case WsdScannerElement::description: return "wscn:ScannerDescription";
        case WsdScannerElement::configuration: return "wscn:ScannerConfiguration";
        case WsdScannerElement::status: return "wscn:ScannerStatus";
    }
    throw WsdScanError("invalid_wsd_scanner_element");
}

#ifdef _WIN32
class ComRelease final {
public:
    explicit ComRelease(IUnknown* value = nullptr) noexcept : value_(value) {}
    ~ComRelease() {
        if (value_ != nullptr) value_->Release();
    }
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
    if (WideCharToMultiByte(CP_UTF8,
                            WC_ERR_INVALID_CHARS,
                            value,
                            static_cast<int>(length),
                            output.data(),
                            required,
                            nullptr,
                            nullptr) != required) {
        throw WsdScanError("invalid_wsd_utf16");
    }
    return output;
}

void append_bounded(std::string& target, const std::string& value, const std::size_t maximum) {
    if (target.size() > maximum - std::min(maximum, value.size())) {
        throw WsdScanError("wsd_description_field_too_large");
    }
    target += value;
    if (target.size() > maximum) throw WsdScanError("wsd_description_field_too_large");
}

struct WsdXmlNode {
    XmlNodeType type{XmlNodeType_None};
    std::string local_name;
    std::string namespace_uri;
    std::string value;
    UINT depth{0U};
};

void read_wsd_xml(
    const std::string_view xml,
    const WsdSafetyLimits& limits,
    const std::function<void(const WsdXmlNode&)>& callback) {
    validate_codec_limits(limits);
    if (xml.empty() || xml.size() > limits.max_xml_bytes) {
        throw WsdScanError("wsd_xml_limit_exceeded");
    }
    if (xml.find("<!DOCTYPE") != std::string_view::npos ||
        xml.find("<!ENTITY") != std::string_view::npos) {
        throw WsdScanError("unsafe_wsd_xml_declaration");
    }

    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, xml.size());
    if (memory == nullptr) throw WsdScanError("wsd_xml_memory_failure");
    void* bytes = GlobalLock(memory);
    if (bytes == nullptr) {
        GlobalFree(memory);
        throw WsdScanError("wsd_xml_memory_failure");
    }
    std::memcpy(bytes, xml.data(), xml.size());
    GlobalUnlock(memory);

    IStream* stream = nullptr;
    if (FAILED(CreateStreamOnHGlobal(memory, TRUE, &stream))) {
        GlobalFree(memory);
        throw WsdScanError("wsd_xml_stream_failure");
    }
    ComRelease stream_release(stream);

    IXmlReader* reader = nullptr;
    if (FAILED(CreateXmlReader(__uuidof(IXmlReader), reinterpret_cast<void**>(&reader), nullptr))) {
        throw WsdScanError("wsd_xml_reader_failure");
    }
    ComRelease reader_release(reader);
    if (FAILED(reader->SetProperty(XmlReaderProperty_DtdProcessing, DtdProcessing_Prohibit)) ||
        FAILED(reader->SetProperty(XmlReaderProperty_MaxElementDepth, 64)) ||
        FAILED(reader->SetInput(stream))) {
        throw WsdScanError("wsd_xml_reader_failure");
    }

    std::size_t node_count = 0U;
    XmlNodeType node_type = XmlNodeType_None;
    HRESULT status = S_OK;
    while ((status = reader->Read(&node_type)) == S_OK) {
        if (++node_count > 10000U) throw WsdScanError("wsd_xml_node_limit_exceeded");
        WsdXmlNode node;
        node.type = node_type;
        if (FAILED(reader->GetDepth(&node.depth))) throw WsdScanError("invalid_wsd_xml");
        if (node_type == XmlNodeType_Element || node_type == XmlNodeType_EndElement) {
            const wchar_t* local_name = nullptr;
            const wchar_t* namespace_uri = nullptr;
            UINT local_length = 0U;
            UINT namespace_length = 0U;
            if (FAILED(reader->GetLocalName(&local_name, &local_length)) ||
                FAILED(reader->GetNamespaceUri(&namespace_uri, &namespace_length))) {
                throw WsdScanError("invalid_wsd_xml");
            }
            node.local_name = wide_to_utf8(local_name, local_length);
            node.namespace_uri = wide_to_utf8(namespace_uri, namespace_length);
        } else if (node_type == XmlNodeType_Text || node_type == XmlNodeType_CDATA) {
            const wchar_t* value = nullptr;
            UINT value_length = 0U;
            if (FAILED(reader->GetValue(&value, &value_length))) {
                throw WsdScanError("invalid_wsd_xml");
            }
            node.value = wide_to_utf8(value, value_length);
        }
        callback(node);
    }
    if (status != S_FALSE) throw WsdScanError("invalid_wsd_xml");
}

std::string trim_ascii(std::string value) {
    const auto is_space = [](const unsigned char character) {
        return std::isspace(character) != 0;
    };
    const auto first = std::find_if_not(value.begin(), value.end(), is_space);
    const auto last = std::find_if_not(value.rbegin(), value.rend(), is_space).base();
    if (first >= last) return {};
    return std::string(first, last);
}

void validate_short_token(const std::string& value, const std::size_t maximum) {
    if (value.empty() || value.size() > maximum) throw WsdScanError("invalid_wsd_token");
    for (const unsigned char character : value) {
        if (character < 0x21U || character > 0x7eU || character == '<' ||
            character == '>' || character == '&' || character == '"' || character == '\'') {
            throw WsdScanError("invalid_wsd_token");
        }
    }
}

bool parse_wsd_boolean(const std::string& value) {
    if (value == "true" || value == "1") return true;
    if (value == "false" || value == "0") return false;
    throw WsdScanError("invalid_wsd_boolean");
}

bool is_soap_namespace(const std::string_view value) {
    return value == "http://www.w3.org/2003/05/soap-envelope" ||
           value == "https://www.w3.org/2003/05/soap-envelope";
}

std::string qname_local_value(const std::string& value) {
    const auto separator = value.find(':');
    return separator == std::string::npos ? value : value.substr(separator + 1U);
}
#endif

}  // namespace

std::string encode_wsd_get_scanner_elements_request(
    const std::string_view service_endpoint,
    const std::string_view message_id,
    const std::vector<WsdScannerElement>& elements,
    const WsdSafetyLimits& limits) {
    validate_codec_limits(limits);
    if (service_endpoint.empty() || service_endpoint.size() > 2048U ||
        !is_safe_service_address(service_endpoint)) {
        throw WsdScanError("invalid_wsd_service_endpoint");
    }
    if (!is_safe_message_id(message_id)) throw WsdScanError("invalid_wsd_message_id");
    if (elements.empty() || elements.size() > 3U) {
        throw WsdScanError("invalid_wsd_requested_elements");
    }
    for (std::size_t index = 0; index < elements.size(); ++index) {
        if (std::find(elements.begin() + static_cast<std::ptrdiff_t>(index + 1U),
                      elements.end(),
                      elements[index]) != elements.end()) {
            throw WsdScanError("duplicate_wsd_requested_element");
        }
    }

    std::ostringstream xml;
    xml << "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        << "<soap:Envelope xmlns:soap=\"" << deployed_soap_namespace << "\" "
        << "xmlns:wsa=\"" << deployed_addressing_namespace << "\" "
        << "xmlns:wscn=\"" << deployed_scan_namespace << "\">"
        << "<soap:Header><wsa:Action soap:mustUnderstand=\"true\">"
        << deployed_scan_namespace << "/GetScannerElements</wsa:Action>"
        << "<wsa:MessageID>" << message_id << "</wsa:MessageID>"
        << "<wsa:ReplyTo><wsa:Address>" << anonymous_reply_to
        << "</wsa:Address></wsa:ReplyTo><wsa:To soap:mustUnderstand=\"true\">"
        << xml_escape(service_endpoint) << "</wsa:To></soap:Header>"
        << "<soap:Body><wscn:GetScannerElementsRequest>"
        << "<wscn:RequestedElements>";
    for (const auto element : elements) {
        xml << "<wscn:Name>" << element_qname(element) << "</wscn:Name>";
    }
    xml << "</wscn:RequestedElements></wscn:GetScannerElementsRequest>"
        << "</soap:Body></soap:Envelope>";
    auto result = xml.str();
    if (result.size() > limits.max_xml_bytes) throw WsdScanError("wsd_xml_limit_exceeded");
    return result;
}

WsdScannerDescription decode_wsd_scanner_description_response(
    const std::string_view xml,
    const WsdSafetyLimits& limits) {
    validate_codec_limits(limits);
    if (xml.empty() || xml.size() > limits.max_xml_bytes) {
        throw WsdScanError("wsd_xml_limit_exceeded");
    }
    if (xml.find("<!DOCTYPE") != std::string_view::npos ||
        xml.find("<!ENTITY") != std::string_view::npos) {
        throw WsdScanError("unsafe_wsd_xml_declaration");
    }

#ifndef _WIN32
    (void)xml;
    throw WsdScanError("wsd_xml_decoder_unavailable");
#else
    if (xml.size() > static_cast<std::size_t>(std::numeric_limits<SIZE_T>::max())) {
        throw WsdScanError("wsd_xml_limit_exceeded");
    }
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, xml.size());
    if (memory == nullptr) throw WsdScanError("wsd_xml_memory_failure");
    void* bytes = GlobalLock(memory);
    if (bytes == nullptr) {
        GlobalFree(memory);
        throw WsdScanError("wsd_xml_memory_failure");
    }
    std::memcpy(bytes, xml.data(), xml.size());
    GlobalUnlock(memory);

    IStream* stream = nullptr;
    if (FAILED(CreateStreamOnHGlobal(memory, TRUE, &stream))) {
        GlobalFree(memory);
        throw WsdScanError("wsd_xml_stream_failure");
    }
    ComRelease stream_release(stream);

    IXmlReader* reader = nullptr;
    if (FAILED(CreateXmlReader(__uuidof(IXmlReader), reinterpret_cast<void**>(&reader), nullptr))) {
        throw WsdScanError("wsd_xml_reader_failure");
    }
    ComRelease reader_release(reader);
    if (FAILED(reader->SetProperty(XmlReaderProperty_DtdProcessing, DtdProcessing_Prohibit)) ||
        FAILED(reader->SetProperty(XmlReaderProperty_MaxElementDepth, 64)) ||
        FAILED(reader->SetInput(stream))) {
        throw WsdScanError("wsd_xml_reader_failure");
    }

    WsdScannerDescription result;
    bool response_seen = false;
    bool description_seen = false;
    enum class Field { none, name, information, location } field = Field::none;
    XmlNodeType node_type = XmlNodeType_None;
    HRESULT status = S_OK;
    while ((status = reader->Read(&node_type)) == S_OK) {
        if (node_type == XmlNodeType_Element) {
            const wchar_t* local_name = nullptr;
            const wchar_t* namespace_uri = nullptr;
            UINT local_length = 0U;
            UINT namespace_length = 0U;
            if (FAILED(reader->GetLocalName(&local_name, &local_length)) ||
                FAILED(reader->GetNamespaceUri(&namespace_uri, &namespace_length))) {
                throw WsdScanError("invalid_wsd_xml");
            }
            const auto local = wide_to_utf8(local_name, local_length);
            const auto uri = wide_to_utf8(namespace_uri, namespace_length);
            if (is_scan_namespace(uri) && local == "GetScannerElementsResponse") {
                response_seen = true;
            } else if (is_scan_namespace(uri) && local == "ScannerDescription") {
                description_seen = true;
            } else if (description_seen && is_scan_namespace(uri) && local == "ScannerName") {
                field = Field::name;
            } else if (description_seen && is_scan_namespace(uri) && local == "ScannerInfo") {
                field = Field::information;
            } else if (description_seen && is_scan_namespace(uri) && local == "ScannerLocation") {
                field = Field::location;
            }
        } else if (node_type == XmlNodeType_EndElement) {
            field = Field::none;
        } else if (node_type == XmlNodeType_Text || node_type == XmlNodeType_CDATA) {
            if (field == Field::none) continue;
            const wchar_t* value = nullptr;
            UINT length = 0U;
            if (FAILED(reader->GetValue(&value, &length))) throw WsdScanError("invalid_wsd_xml");
            const auto text_value = wide_to_utf8(value, length);
            if (field == Field::name) append_bounded(result.name, text_value, 256U);
            if (field == Field::information) append_bounded(result.information, text_value, 1024U);
            if (field == Field::location) append_bounded(result.location, text_value, 512U);
        }
    }
    if (status != S_FALSE || !response_seen || !description_seen || result.name.empty()) {
        throw WsdScanError("invalid_wsd_scanner_description_response");
    }
    return result;
#endif
}

WsdScannerConfiguration decode_wsd_scanner_configuration_response(
    const std::string_view xml,
    const WsdSafetyLimits& limits) {
#ifndef _WIN32
    (void)xml;
    (void)limits;
    throw WsdScanError("wsd_xml_decoder_unavailable");
#else
    WsdScannerConfiguration result;
    bool response_seen = false;
    bool duplex_seen = false;
    int configuration_depth = -1;
    enum class Field { none, format, duplex } field = Field::none;
    std::string field_value;

    read_wsd_xml(xml, limits, [&](const WsdXmlNode& node) {
        if (node.type == XmlNodeType_Element) {
            if (is_scan_namespace(node.namespace_uri) &&
                node.local_name == "GetScannerElementsResponse") {
                response_seen = true;
            } else if (is_scan_namespace(node.namespace_uri) &&
                       node.local_name == "ScannerConfiguration") {
                configuration_depth = static_cast<int>(node.depth);
            } else if (configuration_depth >= 0 && is_scan_namespace(node.namespace_uri)) {
                if (node.local_name == "Platen") result.supports_platen = true;
                if (node.local_name == "ADF") result.supports_adf = true;
                if (node.local_name == "Film") result.supports_film = true;
                if (node.local_name == "FormatValue") {
                    field = Field::format;
                    field_value.clear();
                } else if (node.local_name == "ADFSupportsDuplex") {
                    field = Field::duplex;
                    field_value.clear();
                }
            }
        } else if ((node.type == XmlNodeType_Text || node.type == XmlNodeType_CDATA) &&
                   field != Field::none) {
            append_bounded(field_value, node.value, 64U);
        } else if (node.type == XmlNodeType_EndElement) {
            const bool field_ended =
                (field == Field::format && node.local_name == "FormatValue") ||
                (field == Field::duplex && node.local_name == "ADFSupportsDuplex");
            if (is_scan_namespace(node.namespace_uri) && field_ended) {
                const auto value = trim_ascii(field_value);
                if (field == Field::format) {
                    validate_short_token(value, 64U);
                    if (result.formats.size() == 32U) {
                        throw WsdScanError("wsd_format_count_exceeded");
                    }
                    if (std::find(result.formats.begin(), result.formats.end(), value) !=
                        result.formats.end()) {
                        throw WsdScanError("duplicate_wsd_format");
                    }
                    result.formats.push_back(value);
                } else {
                    result.adf_supports_duplex = parse_wsd_boolean(value);
                    duplex_seen = true;
                }
                field = Field::none;
                field_value.clear();
            }
            if (is_scan_namespace(node.namespace_uri) &&
                node.local_name == "ScannerConfiguration") {
                configuration_depth = -1;
            }
        }
    });

    if (!response_seen) throw WsdScanError("missing_wsd_scanner_elements_response");
    if (configuration_depth >= 0) throw WsdScanError("unterminated_wsd_configuration");
    if (!result.supports_platen && !result.supports_adf && !result.supports_film) {
        throw WsdScanError("missing_wsd_scanner_source");
    }
    if (result.supports_adf && !duplex_seen) throw WsdScanError("missing_wsd_adf_duplex");
    if (!result.supports_adf && duplex_seen) throw WsdScanError("invalid_wsd_duplex_without_adf");
    return result;
#endif
}

WsdScannerStatus decode_wsd_scanner_status_response(
    const std::string_view xml,
    const WsdSafetyLimits& limits) {
#ifndef _WIN32
    (void)xml;
    (void)limits;
    throw WsdScanError("wsd_xml_decoder_unavailable");
#else
    WsdScannerStatus result;
    bool response_seen = false;
    int status_depth = -1;
    enum class Field { none, state, reason } field = Field::none;
    std::string field_value;

    read_wsd_xml(xml, limits, [&](const WsdXmlNode& node) {
        if (node.type == XmlNodeType_Element) {
            if (is_scan_namespace(node.namespace_uri) &&
                node.local_name == "GetScannerElementsResponse") {
                response_seen = true;
            } else if (is_scan_namespace(node.namespace_uri) &&
                       node.local_name == "ScannerStatus") {
                status_depth = static_cast<int>(node.depth);
            } else if (status_depth >= 0 && is_scan_namespace(node.namespace_uri) &&
                       (node.local_name == "ScannerState" ||
                        node.local_name == "ScannerStateReason")) {
                field = node.local_name == "ScannerState" ? Field::state : Field::reason;
                field_value.clear();
            }
        } else if ((node.type == XmlNodeType_Text || node.type == XmlNodeType_CDATA) &&
                   field != Field::none) {
            append_bounded(field_value, node.value, 128U);
        } else if (node.type == XmlNodeType_EndElement) {
            const bool field_ended =
                (field == Field::state && node.local_name == "ScannerState") ||
                (field == Field::reason && node.local_name == "ScannerStateReason");
            if (is_scan_namespace(node.namespace_uri) && field_ended) {
                const auto value = trim_ascii(field_value);
                validate_short_token(value, 128U);
                if (field == Field::state) {
                    if (!result.state_value.empty()) throw WsdScanError("duplicate_wsd_state");
                    result.state_value = value;
                    if (value == "Idle") result.state = WsdScannerState::idle;
                    else if (value == "Processing") result.state = WsdScannerState::processing;
                    else if (value == "Stopped") result.state = WsdScannerState::stopped;
                    else result.state = WsdScannerState::vendor_extended;
                } else {
                    if (result.reasons.size() == 32U) {
                        throw WsdScanError("wsd_state_reason_count_exceeded");
                    }
                    if (std::find(result.reasons.begin(), result.reasons.end(), value) !=
                        result.reasons.end()) {
                        throw WsdScanError("duplicate_wsd_state_reason");
                    }
                    result.reasons.push_back(value);
                }
                field = Field::none;
                field_value.clear();
            }
            if (is_scan_namespace(node.namespace_uri) && node.local_name == "ScannerStatus") {
                status_depth = -1;
            }
        }
    });

    if (!response_seen || status_depth >= 0 || result.state_value.empty()) {
        throw WsdScanError("invalid_wsd_scanner_status_response");
    }
    return result;
#endif
}

WsdSoapFault decode_wsd_soap_fault(
    const std::string_view xml,
    const WsdSafetyLimits& limits) {
#ifndef _WIN32
    (void)xml;
    (void)limits;
    throw WsdScanError("wsd_xml_decoder_unavailable");
#else
    WsdSoapFault result;
    int fault_depth = -1;
    int code_depth = -1;
    int subcode_depth = -1;
    int reason_depth = -1;
    enum class Field { none, code, subcode, reason } field = Field::none;
    std::string field_value;

    read_wsd_xml(xml, limits, [&](const WsdXmlNode& node) {
        if (node.type == XmlNodeType_Element) {
            if (is_soap_namespace(node.namespace_uri) && node.local_name == "Fault") {
                fault_depth = static_cast<int>(node.depth);
            } else if (fault_depth >= 0 && is_soap_namespace(node.namespace_uri) &&
                       node.local_name == "Code") {
                code_depth = static_cast<int>(node.depth);
            } else if (code_depth >= 0 && is_soap_namespace(node.namespace_uri) &&
                       node.local_name == "Subcode") {
                subcode_depth = static_cast<int>(node.depth);
            } else if (fault_depth >= 0 && is_soap_namespace(node.namespace_uri) &&
                       node.local_name == "Reason") {
                reason_depth = static_cast<int>(node.depth);
            } else if (is_soap_namespace(node.namespace_uri) && node.local_name == "Value") {
                field = subcode_depth >= 0 ? Field::subcode : Field::code;
                field_value.clear();
            } else if (reason_depth >= 0 && is_soap_namespace(node.namespace_uri) &&
                       node.local_name == "Text") {
                field = Field::reason;
                field_value.clear();
            }
        } else if ((node.type == XmlNodeType_Text || node.type == XmlNodeType_CDATA) &&
                   field != Field::none) {
            append_bounded(field_value, node.value, field == Field::reason ? 1024U : 128U);
        } else if (node.type == XmlNodeType_EndElement) {
            const bool field_ended =
                ((field == Field::code || field == Field::subcode) &&
                 node.local_name == "Value") ||
                (field == Field::reason && node.local_name == "Text");
            if (is_soap_namespace(node.namespace_uri) && field_ended) {
                const auto value = trim_ascii(field_value);
                if (field == Field::reason) {
                    if (value.empty()) throw WsdScanError("invalid_wsd_fault_reason");
                    result.reason = value;
                } else {
                    validate_short_token(value, 128U);
                    if (field == Field::code) result.code = value;
                    if (field == Field::subcode) result.subcode = value;
                }
                field = Field::none;
                field_value.clear();
            }
            if (is_soap_namespace(node.namespace_uri) && node.local_name == "Subcode") {
                subcode_depth = -1;
            }
            if (is_soap_namespace(node.namespace_uri) && node.local_name == "Code") {
                code_depth = -1;
            }
            if (is_soap_namespace(node.namespace_uri) && node.local_name == "Reason") {
                reason_depth = -1;
            }
            if (is_soap_namespace(node.namespace_uri) && node.local_name == "Fault") {
                fault_depth = -1;
            }
        }
    });

    if (fault_depth >= 0 || result.code.empty() || result.subcode.empty() ||
        result.reason.empty()) {
        throw WsdScanError("invalid_wsd_soap_fault");
    }
    const auto fault_name = qname_local_value(result.subcode);
    if (fault_name == "ActionNotSupported") {
        result.kind = WsdSoapFaultKind::action_not_supported;
    } else if (fault_name == "InvalidArgs") {
        result.kind = WsdSoapFaultKind::invalid_arguments;
    } else if (fault_name == "OperationFailed") {
        result.kind = WsdSoapFaultKind::operation_failed;
    } else if (fault_name == "ServerErrorTemporaryError") {
        result.kind = WsdSoapFaultKind::temporary_error;
        result.retryable = true;
    } else if (fault_name == "ServerErrorInternalError") {
        result.kind = WsdSoapFaultKind::internal_error;
    }
    return result;
#endif
}

}  // namespace just_scanner
