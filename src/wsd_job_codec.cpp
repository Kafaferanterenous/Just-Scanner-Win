#include "wsd_job_codec.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <sstream>

namespace just_scanner {
namespace {
constexpr std::string_view ns = "http://schemas.microsoft.com/windows/2006/08/wdp/scan";
constexpr std::string_view soap = "http://www.w3.org/2003/05/soap-envelope";
constexpr std::string_view wsa = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
bool safe(const std::string_view value, const std::size_t max) {
    return !value.empty() && value.size() <= max && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return c >= 0x21U && c <= 0x7eU && c != '<' && c != '>' && c != '&' && c != '"' && c != '\'';
    });
}
std::string source(const WsdInputSource value) { return value == WsdInputSource::platen ? "Platen" : "ADF"; }
std::string color(const WsdColorProcessing value) { return value == WsdColorProcessing::monochrome ? "BlackAndWhite1" : value == WsdColorProcessing::grayscale ? "Grayscale8" : "RGB24"; }
std::string format(const WsdDocumentFormat value) { return value == WsdDocumentFormat::jpeg ? "exif" : value == WsdDocumentFormat::png ? "png" : "tiff-single-g4"; }
void validate(const WsdScanTicket& ticket, const WsdSafetyLimits& limits) { (void)make_wsd_create_job_request(ticket, limits); }
void validate(const WsdJobCredentials& job, const WsdSafetyLimits& limits) { (void)make_wsd_retrieve_image_request(job, limits); }
std::string envelope(std::string_view to, std::string_view id, std::string_view action, std::string_view body) {
    if (!safe(to, 2048U) || !safe(id, 128U)) throw WsdScanError("invalid_wsd_job_address");
    std::ostringstream out;
    out << "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"" << soap
        << "\" xmlns:wsa=\"" << wsa << "\" xmlns:wscn=\"" << ns << "\"><soap:Header><wsa:Action>"
        << ns << '/' << action << "</wsa:Action><wsa:MessageID>" << id << "</wsa:MessageID><wsa:To>" << to
        << "</wsa:To></soap:Header><soap:Body>" << body << "</soap:Body></soap:Envelope>";
    return out.str();
}
std::string header(const std::string& headers, const std::string_view name) {
    const auto needle = std::string("\r\n") + std::string(name) + ":";
    auto pos = headers.find(needle); if (pos == std::string::npos && headers.starts_with(std::string(name) + ":")) pos = 0; else if (pos != std::string::npos) pos += 2U;
    if (pos == std::string::npos) return {}; pos += name.size() + 1U; const auto end = headers.find("\r\n", pos);
    auto value = headers.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
    const auto first = value.find_first_not_of(" \t");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t");
    return value.substr(first, last - first + 1U);
}
std::string unique_xml_text(const std::string_view xml, const std::string_view open,
                            const std::string_view close, const std::size_t maximum) {
    const auto first = xml.find(open);
    if (first == std::string_view::npos || xml.find(open, first + open.size()) != std::string_view::npos) {
        throw WsdScanError("invalid_wsd_job_response");
    }
    const auto begin = first + open.size();
    const auto end = xml.find(close, begin);
    if (end == std::string_view::npos || end == begin || end - begin > maximum ||
        xml.find('<', begin) < end) throw WsdScanError("invalid_wsd_job_response");
    return std::string(xml.substr(begin, end - begin));
}
}
std::string encode_wsd_create_scan_job_request(std::string_view to, std::string_view id, const WsdScanTicket& ticket, const WsdSafetyLimits& limits) {
    validate(ticket, limits); std::ostringstream body;
    body << "<wscn:CreateScanJobRequest><wscn:ScanTicket><wscn:DocumentParameters><wscn:Format>" << format(ticket.format)
         << "</wscn:Format><wscn:ImagesToTransfer>" << ticket.images_to_transfer << "</wscn:ImagesToTransfer><wscn:InputSource>" << source(ticket.source)
         << "</wscn:InputSource><wscn:MediaSides><wscn:MediaFront><wscn:ColorProcessing>" << color(ticket.color)
         << "</wscn:ColorProcessing><wscn:Resolution><wscn:Width>" << ticket.horizontal_dpi << "</wscn:Width><wscn:Height>" << ticket.vertical_dpi
         << "</wscn:Height></wscn:Resolution></wscn:MediaFront></wscn:MediaSides></wscn:DocumentParameters></wscn:ScanTicket></wscn:CreateScanJobRequest>";
    return envelope(to, id, "CreateScanJob", body.str());
}
std::string encode_wsd_retrieve_image_request(std::string_view to, std::string_view id, const WsdJobCredentials& job, std::string_view name, const WsdSafetyLimits& limits) {
    validate(job, limits); if (!safe(name, 128U)) throw WsdScanError("invalid_wsd_document_name");
    return envelope(to, id, "RetrieveImage", "<wscn:RetrieveImageRequest><wscn:JobId>" + std::to_string(job.job_id) + "</wscn:JobId><wscn:JobToken>" + job.job_token + "</wscn:JobToken><wscn:DocumentDescription><wscn:DocumentName>" + std::string(name) + "</wscn:DocumentName></wscn:DocumentDescription></wscn:RetrieveImageRequest>");
}
std::string encode_wsd_cancel_job_request(std::string_view to, std::string_view id, const WsdJobCredentials& job, const WsdSafetyLimits& limits) {
    validate(job, limits); return envelope(to, id, "CancelJob", "<wscn:CancelJobRequest><wscn:JobId>" + std::to_string(job.job_id) + "</wscn:JobId></wscn:CancelJobRequest>");
}
WsdCreatedJob decode_wsd_create_scan_job_response(std::string_view xml, std::string_view relates,
                                                   const WsdSafetyLimits& limits) {
    if (xml.empty() || xml.size() > limits.max_xml_bytes || xml.find("<!DOCTYPE") != std::string_view::npos ||
        xml.find("<!ENTITY") != std::string_view::npos) throw WsdScanError("invalid_wsd_job_response");
    if (unique_xml_text(xml, "<wsa:RelatesTo>", "</wsa:RelatesTo>", 128U) != relates) {
        throw WsdScanError("wsd_job_response_not_correlated");
    }
    const auto id_text = unique_xml_text(xml, "<wscn:JobId>", "</wscn:JobId>", 10U);
    std::uint32_t id{}; const auto parsed = std::from_chars(id_text.data(), id_text.data() + id_text.size(), id);
    if (parsed.ec != std::errc{} || parsed.ptr != id_text.data() + id_text.size() || id == 0U) {
        throw WsdScanError("invalid_wsd_job_response");
    }
    WsdCreatedJob result{{id, unique_xml_text(xml, "<wscn:JobToken>", "</wscn:JobToken>", limits.max_job_token_bytes)}, {}};
    validate(result.credentials, limits);
    const auto format_open = std::string_view("<wscn:Format>");
    if (xml.find(format_open) != std::string_view::npos) {
        result.final_format = unique_xml_text(xml, format_open, "</wscn:Format>", 64U);
    }
    return result;
}
WsdMtomImage decode_wsd_retrieve_mtom_response(std::string_view type, const std::vector<std::uint8_t>& bytes, std::string_view wanted, const WsdSafetyLimits& limits) {
    if (bytes.empty() || bytes.size() > limits.max_image_bytes || !type.starts_with("multipart/related")) throw WsdScanError("invalid_wsd_mtom_response");
    const auto key = type.find("boundary="); if (key == std::string_view::npos) throw WsdScanError("missing_wsd_mtom_boundary");
    auto boundary = std::string(type.substr(key + 9U)); if (!boundary.empty() && boundary.front() == '"') { const auto end=boundary.find('"',1U); boundary=boundary.substr(1U,end-1U); } else boundary=boundary.substr(0U,boundary.find(';'));
    if (!safe(boundary, 200U) || !safe(wanted, 512U)) throw WsdScanError("invalid_wsd_mtom_boundary");
    const std::string raw(bytes.begin(), bytes.end()), mark="--"+boundary; const auto start=raw.find(mark); if(start==std::string::npos) throw WsdScanError("invalid_wsd_mtom_body");
    auto pos=start; while ((pos=raw.find(mark,pos))!=std::string::npos) { pos+=mark.size(); if(raw.compare(pos,2,"--")==0) break; if(raw.compare(pos,2,"\r\n")!=0) throw WsdScanError("invalid_wsd_mtom_body"); pos+=2; const auto end=raw.find("\r\n\r\n",pos); if(end==std::string::npos||end-pos>16384U) throw WsdScanError("invalid_wsd_mtom_headers"); const auto next=raw.find("\r\n"+mark,end+4U); if(next==std::string::npos) throw WsdScanError("invalid_wsd_mtom_body"); const auto headers=raw.substr(pos,end-pos); auto id=header(headers,"Content-ID"); if(id.size()>1U&&id.front()=='<'&&id.back()=='>') id=id.substr(1U,id.size()-2U); if(id==wanted) { auto ct=header(headers,"Content-Type"); if(!safe(ct,256U)||next-(end+4U)>limits.max_image_bytes) throw WsdScanError("invalid_wsd_mtom_image"); return {ct,{bytes.begin()+static_cast<std::ptrdiff_t>(end+4U),bytes.begin()+static_cast<std::ptrdiff_t>(next)}}; } pos=next; }
    throw WsdScanError("missing_wsd_mtom_image");
}
}  // namespace just_scanner
