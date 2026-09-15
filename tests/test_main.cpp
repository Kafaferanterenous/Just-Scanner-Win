#include "scanner_backend_policy.h"
#include "scanner_core.h"
#include "wia2_backend.h"
#include "wia_capability_model.h"
#include "wia_com_worker.h"
#include "wia_discovery_model.h"
#include "wia_transfer_model.h"
#include "wia_worker_model.h"
#include "wsd_discovery_model.h"
#include "wsd_http_transport.h"
#include "wsd_job_codec.h"
#include "wsd_scan_model.h"
#include "wsd_soap_codec.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#include <wincodec.h>
#endif

using just_scanner::ColorMode;
using just_scanner::CropRect;
using just_scanner::ImageExportFormat;
using just_scanner::IComApartment;
using just_scanner::IWiaWorkerBackend;
using just_scanner::MockScanner;
using just_scanner::make_windows_wia2_backend;
using just_scanner::ScanRequest;
using just_scanner::ScanSession;
using just_scanner::ScannerBackendKind;
using just_scanner::ScannerBackendMaturity;
using just_scanner::ScannerBackendOperation;
using just_scanner::ScannerBackendPermission;
using just_scanner::ScannerError;
using just_scanner::SourceType;
using just_scanner::WiaCapabilityResult;
using just_scanner::WiaComWorker;
using just_scanner::WiaDataType;
using just_scanner::WiaDeviceModel;
using just_scanner::WiaDeviceClass;
using just_scanner::WiaDiscoveredDevice;
using just_scanner::WiaDiscoveryModel;
using just_scanner::WiaIntProperty;
using just_scanner::WiaItemCategory;
using just_scanner::WiaItemModel;
using just_scanner::WiaPropertyShape;
using just_scanner::WiaReadback;
using just_scanner::TransferFailure;
using just_scanner::TransferLimits;
using just_scanner::TransferState;
using just_scanner::WiaTransferModel;
using just_scanner::WiaWorkerModel;
using just_scanner::WiaWorkerOperation;
using just_scanner::WiaWorkerReply;
using just_scanner::WiaWorkerRequest;
using just_scanner::WiaWorkerState;
using just_scanner::WsdJobCredentials;
using just_scanner::WsdJobModel;
using just_scanner::WsdJobState;
using just_scanner::BoundedWsdHttpTransport;
using just_scanner::IWsdHttpExecutor;
using just_scanner::WsdHttpLimits;
using just_scanner::WsdHttpRequest;
using just_scanner::WsdHttpResponse;
using just_scanner::WsdProbeCandidate;
using just_scanner::WsdReceivedDatagram;
using just_scanner::WsdRequestKind;
using just_scanner::WsdSafetyLimits;
using just_scanner::WsdScanError;
using just_scanner::WsdScanTicket;
using just_scanner::WsdScannerElement;
using just_scanner::WsdScannerState;
using just_scanner::WsdSoapFaultKind;

namespace {

void check(const bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

template <typename Callback>
void expect_wsd_error(Callback callback, const std::string& message) {
    try {
        callback();
    } catch (const WsdScanError&) {
        return;
    }
    throw std::runtime_error(message);
}

void test_backend_policy_is_fail_closed() {
    const auto& policies = just_scanner::default_scanner_backend_policies();
    check(policies.size() == 5U, "backend policy registry is incomplete");

    for (std::size_t index = 0; index < policies.size(); ++index) {
        check(!policies[index].stable_id.empty(), "backend policy has an empty stable id");
        for (std::size_t other = index + 1U; other < policies.size(); ++other) {
            check(policies[index].kind != policies[other].kind,
                  "backend policy contains a duplicate kind");
            check(policies[index].stable_id != policies[other].stable_id,
                  "backend policy contains a duplicate stable id");
        }
    }

    const auto* mock = just_scanner::find_scanner_backend_policy(
        ScannerBackendKind::mock_fixture);
    check(mock != nullptr && mock->maturity == ScannerBackendMaturity::offline_tested,
          "mock backend policy is missing or not offline-tested");
    check(just_scanner::scanner_backend_operation_allowed(
              *mock, ScannerBackendOperation::scan, {}),
          "offline mock scan was unexpectedly permission gated");

    const auto* wia = just_scanner::find_scanner_backend_policy(
        ScannerBackendKind::windows_wia2);
    check(wia != nullptr && wia->maturity == ScannerBackendMaturity::discovery_only,
          "WIA policy did not remain discovery-only");
    check(!wia->transport_built_into_app && wia->requires_external_driver,
          "WIA policy incorrectly claims an in-app hardware driver");
    check(!just_scanner::scanner_backend_operation_allowed(
              *wia, ScannerBackendOperation::discover, {}),
          "WIA discovery was allowed without explicit local permission");

    ScannerBackendPermission local_permission;
    local_permission.explicit_user_action = true;
    local_permission.allow_local_device_io = true;
    check(just_scanner::scanner_backend_operation_allowed(
              *wia, ScannerBackendOperation::discover, local_permission),
          "explicitly permitted WIA discovery was rejected");
    check(!just_scanner::scanner_backend_operation_allowed(
              *wia, ScannerBackendOperation::connect, local_permission) &&
              !just_scanner::scanner_backend_operation_allowed(
                  *wia, ScannerBackendOperation::scan, local_permission),
          "discovery-only WIA policy allowed connection or scanning");

    ScannerBackendPermission network_permission;
    network_permission.explicit_user_action = true;
    network_permission.allow_network_io = true;
    for (const auto kind : {ScannerBackendKind::wsd_network,
                            ScannerBackendKind::escl_network}) {
        const auto* network = just_scanner::find_scanner_backend_policy(kind);
        check(network != nullptr && network->transport_built_into_app &&
                  !network->requires_external_driver && network->requires_network,
              "network backend policy has incorrect driver or transport flags");
        check(!just_scanner::scanner_backend_operation_allowed(
                  *network, ScannerBackendOperation::discover, network_permission) &&
                  !just_scanner::scanner_backend_operation_allowed(
                      *network, ScannerBackendOperation::scan, network_permission),
              "unimplemented network backend became live through permission alone");
    }

    const auto* native_usb = just_scanner::find_scanner_backend_policy(
        ScannerBackendKind::native_usb);
    ScannerBackendPermission usb_permission;
    usb_permission.explicit_user_action = true;
    usb_permission.allow_local_device_io = true;
    usb_permission.allow_native_usb_io = true;
    check(native_usb != nullptr &&
              native_usb->maturity == ScannerBackendMaturity::research_only &&
              !just_scanner::scanner_backend_operation_allowed(
                  *native_usb, ScannerBackendOperation::scan, usb_permission),
          "research-only native USB backend was allowed to scan");
}

void test_wsd_request_and_job_models_fail_closed() {
    const auto elements = just_scanner::make_wsd_get_scanner_elements_request();
    check(elements.kind == WsdRequestKind::get_scanner_elements &&
              !elements.ticket.has_value() && !elements.credentials.has_value(),
          "WSD scanner-elements request contains unexpected data");

    WsdScanTicket ticket;
    ticket.horizontal_dpi = 600U;
    ticket.vertical_dpi = 600U;
    ticket.images_to_transfer = 2U;
    const auto validate = just_scanner::make_wsd_validate_ticket_request(ticket);
    const auto create = just_scanner::make_wsd_create_job_request(ticket);
    check(validate.kind == WsdRequestKind::validate_scan_ticket &&
              validate.ticket.has_value() && !validate.credentials.has_value(),
          "WSD validate-ticket request shape is invalid");
    check(create.kind == WsdRequestKind::create_scan_job &&
              create.ticket.has_value() && !create.credentials.has_value(),
          "WSD create-job request shape is invalid");

    auto invalid_ticket = ticket;
    invalid_ticket.horizontal_dpi = 0U;
    expect_wsd_error(
        [&] { (void)just_scanner::make_wsd_create_job_request(invalid_ticket); },
        "WSD accepted an invalid resolution");
    invalid_ticket = ticket;
    invalid_ticket.images_to_transfer = 101U;
    expect_wsd_error(
        [&] { (void)just_scanner::make_wsd_validate_ticket_request(invalid_ticket); },
        "WSD accepted an image count above its default bound");

    const WsdJobCredentials credentials{17U, "sanitized-token-17"};
    const auto retrieve = just_scanner::make_wsd_retrieve_image_request(credentials);
    const auto cancel = just_scanner::make_wsd_cancel_job_request(credentials);
    check(retrieve.kind == WsdRequestKind::retrieve_image &&
              retrieve.credentials.has_value() && !retrieve.ticket.has_value() &&
              cancel.kind == WsdRequestKind::cancel_job,
          "WSD job request shapes are invalid");
    expect_wsd_error(
        [&] {
            (void)just_scanner::make_wsd_retrieve_image_request(
                WsdJobCredentials{17U, "unsafe<&token"});
        },
        "WSD accepted an unsafe job token");

    WsdSafetyLimits limits;
    limits.max_image_bytes = 1000U;
    limits.max_images = 2U;
    WsdJobModel job(limits);
    expect_wsd_error([&] { job.accept_job_created(credentials); },
                     "WSD job skipped ticket validation");
    job.accept_ticket_validation(true);
    job.accept_job_created(credentials);
    expect_wsd_error(
        [&] { job.begin_retrieve(WsdJobCredentials{17U, "different-token"}); },
        "WSD accepted mismatched job credentials");
    job.begin_retrieve(credentials);
    job.accept_image(400U, true);
    check(job.state() == WsdJobState::job_created && job.images_received() == 1U &&
              job.image_bytes_received() == 400U,
          "WSD did not preserve bounded multi-image state");
    job.begin_retrieve(credentials);
    job.accept_image(500U, false);
    check(job.state() == WsdJobState::complete && job.images_received() == 2U &&
              job.image_bytes_received() == 900U,
          "WSD did not complete a bounded image sequence");

    WsdJobModel oversized(limits);
    oversized.accept_ticket_validation(true);
    oversized.accept_job_created(credentials);
    oversized.begin_retrieve(credentials);
    expect_wsd_error([&] { oversized.accept_image(1001U, false); },
                     "WSD accepted an oversized image");
    check(oversized.state() == WsdJobState::failed,
          "WSD oversized-image failure did not become terminal");

    WsdJobModel cancelled(limits);
    cancelled.accept_ticket_validation(true);
    cancelled.accept_job_created(credentials);
    cancelled.cancel();
    check(cancelled.state() == WsdJobState::cancelled,
          "WSD cancellation did not become terminal");
}

void test_wsd_soap_codec_is_bounded(const std::filesystem::path& fixtures) {
    const auto request = just_scanner::encode_wsd_get_scanner_elements_request(
        "http://scanner.invalid/wsd?one=1&two=2",
        "uuid:00000000-0000-0000-0000-000000000001",
        {WsdScannerElement::description, WsdScannerElement::configuration});
    check(request.find("GetScannerElementsRequest") != std::string::npos &&
              request.find("wscn:ScannerDescription") != std::string::npos &&
              request.find("wscn:ScannerConfiguration") != std::string::npos &&
              request.find("http://schemas.microsoft.com/windows/2006/08/wdp/scan") !=
                  std::string::npos &&
              request.find("http://schemas.xmlsoap.org/ws/2004/08/addressing") !=
                  std::string::npos &&
              request.find("https://schemas.xmlsoap.org/ws/2003/03/addressing") ==
                  std::string::npos &&
              request.find("one=1&amp;two=2") != std::string::npos,
          "WSD scanner-elements request encoding is incomplete or unescaped");

    const auto logical_endpoint_request =
        just_scanner::encode_wsd_get_scanner_elements_request(
            "urn:uuid:00000000-0000-0000-0000-000000000002",
            "urn:uuid:00000000-0000-0000-0000-000000000003",
            {WsdScannerElement::status});
    check(logical_endpoint_request.find(
              "<wsa:To soap:mustUnderstand=\"true\">urn:uuid:00000000-0000-0000-0000-000000000002</wsa:To>") !=
              std::string::npos &&
              logical_endpoint_request.find(
                  "<wsa:ReplyTo><wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous") !=
                  std::string::npos,
          "WSD deployed-profile logical endpoint encoding is incomplete");
    expect_wsd_error(
        [&] {
            (void)just_scanner::encode_wsd_get_scanner_elements_request(
                "file:///not-a-network-endpoint",
                "uuid:00000000-0000-0000-0000-000000000001",
                {WsdScannerElement::description});
        },
        "WSD accepted a non-HTTP service endpoint");
    expect_wsd_error(
        [&] {
            (void)just_scanner::encode_wsd_get_scanner_elements_request(
                "http://scanner.invalid/wsd",
                "not-a-uuid",
                {WsdScannerElement::description});
        },
        "WSD accepted an unsafe message id");
    expect_wsd_error(
        [&] {
            (void)just_scanner::encode_wsd_get_scanner_elements_request(
                "http://scanner.invalid/wsd",
                "uuid:00000000-0000-0000-0000-000000000001",
                {WsdScannerElement::description, WsdScannerElement::description});
        },
        "WSD accepted a duplicate requested element");

    std::ifstream input(fixtures / "wsd_scanner_description.xml", std::ios::binary);
    check(input.good(), "sanitized WSD response fixture is missing");
    const std::string response(
        (std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    const auto description =
        just_scanner::decode_wsd_scanner_description_response(response);
    check(description.name == "Sanitized Test Scanner" &&
              description.information == "Offline fixture only" &&
              description.location == "Test Lab",
          "WSD scanner description fixture decoded incorrectly");

    auto deployed_profile_response = response;
    const auto replace_all = [](std::string& value,
                                const std::string& from,
                                const std::string& to) {
        std::size_t position = 0U;
        while ((position = value.find(from, position)) != std::string::npos) {
            value.replace(position, from.size(), to);
            position += to.size();
        }
    };
    replace_all(deployed_profile_response,
                "https://schemas.microsoft.com/windows/2006/01/wdp/scan",
                "http://schemas.microsoft.com/windows/2006/08/wdp/scan");
    replace_all(deployed_profile_response,
                "https://www.w3.org/2003/05/soap-envelope",
                "http://www.w3.org/2003/05/soap-envelope");
    replace_all(deployed_profile_response,
                "https://schemas.xmlsoap.org/ws/2003/03/addressing",
                "http://schemas.xmlsoap.org/ws/2004/08/addressing");
    const auto deployed_description =
        just_scanner::decode_wsd_scanner_description_response(deployed_profile_response);
    check(deployed_description.name == description.name &&
              deployed_description.information == description.information &&
              deployed_description.location == description.location,
          "WSD deployed-profile response was not decoded consistently");

    auto wrong_namespace = response;
    const std::string expected_namespace =
        "https://schemas.microsoft.com/windows/2006/01/wdp/scan";
    const auto namespace_position = wrong_namespace.find(expected_namespace);
    check(namespace_position != std::string::npos, "WSD fixture namespace is missing");
    wrong_namespace.replace(namespace_position, expected_namespace.size(), "urn:invalid:scan");
    expect_wsd_error(
        [&] {
            (void)just_scanner::decode_wsd_scanner_description_response(wrong_namespace);
        },
        "WSD accepted a response in the wrong namespace");

    const auto unsafe_response =
        std::string("<!DOCTYPE x [<!ENTITY y SYSTEM \"file:///private\">]>") + response;
    expect_wsd_error(
        [&] { (void)just_scanner::decode_wsd_scanner_description_response(unsafe_response); },
        "WSD accepted a DTD or entity declaration");

    WsdSafetyLimits tiny_limit;
    tiny_limit.max_xml_bytes = 32U;
    expect_wsd_error(
        [&] { (void)just_scanner::decode_wsd_scanner_description_response(response, tiny_limit); },
        "WSD accepted an XML payload over the configured bound");
}

void test_wsd_configuration_status_and_fault_codec(
    const std::filesystem::path& fixtures) {
    const auto read_fixture = [&](const std::string& name) {
        std::ifstream input(fixtures / name, std::ios::binary);
        check(input.good(), "sanitized WSD fixture is missing: " + name);
        return std::string(
            (std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    };

    const auto configuration_xml = read_fixture("wsd_scanner_configuration.xml");
    const auto configuration =
        just_scanner::decode_wsd_scanner_configuration_response(configuration_xml);
    check(configuration.supports_platen && configuration.supports_adf &&
              !configuration.supports_film && configuration.adf_supports_duplex,
          "WSD configuration sources or duplex capability decoded incorrectly");
    check(configuration.formats ==
              std::vector<std::string>({"png", "jfif", "tiff-single-uncompressed"}),
          "WSD configuration formats decoded incorrectly");

    auto invalid_boolean = configuration_xml;
    const std::string valid_duplex =
        "<wscn:ADFSupportsDuplex>true</wscn:ADFSupportsDuplex>";
    const auto duplex_position = invalid_boolean.find(valid_duplex);
    check(duplex_position != std::string::npos, "WSD duplex fixture value is missing");
    invalid_boolean.replace(
        duplex_position,
        valid_duplex.size(),
        "<wscn:ADFSupportsDuplex>maybe</wscn:ADFSupportsDuplex>");
    expect_wsd_error(
        [&] {
            (void)just_scanner::decode_wsd_scanner_configuration_response(invalid_boolean);
        },
        "WSD configuration accepted an invalid Boolean");

    auto missing_duplex = configuration_xml;
    const auto missing_duplex_position = missing_duplex.find(valid_duplex);
    check(missing_duplex_position != std::string::npos,
          "WSD duplex fixture value is missing for omission test");
    missing_duplex.erase(missing_duplex_position, valid_duplex.size());
    expect_wsd_error(
        [&] {
            (void)just_scanner::decode_wsd_scanner_configuration_response(missing_duplex);
        },
        "WSD configuration accepted an ADF without its required duplex flag");

    auto duplicate_format = configuration_xml;
    const std::string format_marker = "<wscn:FormatValue>png</wscn:FormatValue>";
    const auto format_position = duplicate_format.find(format_marker);
    check(format_position != std::string::npos, "WSD format fixture value is missing");
    duplicate_format.insert(format_position + format_marker.size(), format_marker);
    expect_wsd_error(
        [&] {
            (void)just_scanner::decode_wsd_scanner_configuration_response(duplicate_format);
        },
        "WSD configuration accepted a duplicate format");

    const auto status_xml = read_fixture("wsd_scanner_status.xml");
    const auto status = just_scanner::decode_wsd_scanner_status_response(status_xml);
    check(status.state == WsdScannerState::stopped && status.state_value == "Stopped" &&
              status.reasons == std::vector<std::string>({"MediaJam", "CoverOpen"}),
          "WSD scanner status decoded incorrectly");

    auto duplicate_reason = status_xml;
    const std::string reason_marker =
        "<wscn:ScannerStateReason>MediaJam</wscn:ScannerStateReason>";
    const auto reason_position = duplicate_reason.find(reason_marker);
    check(reason_position != std::string::npos, "WSD reason fixture value is missing");
    duplicate_reason.insert(reason_position + reason_marker.size(), reason_marker);
    expect_wsd_error(
        [&] { (void)just_scanner::decode_wsd_scanner_status_response(duplicate_reason); },
        "WSD status accepted a duplicate state reason");

    auto vendor_status_xml = status_xml;
    const auto stopped_position = vendor_status_xml.find(">Stopped<");
    check(stopped_position != std::string::npos, "WSD status fixture value is missing");
    vendor_status_xml.replace(stopped_position, std::string(">Stopped<").size(),
                              ">VendorCalibration<");
    const auto vendor_status =
        just_scanner::decode_wsd_scanner_status_response(vendor_status_xml);
    check(vendor_status.state == WsdScannerState::vendor_extended &&
              vendor_status.state_value == "VendorCalibration",
          "WSD vendor-extended state was not preserved");

    const auto fault_xml = read_fixture("wsd_operation_fault.xml");
    const auto fault = just_scanner::decode_wsd_soap_fault(fault_xml);
    check(fault.kind == WsdSoapFaultKind::operation_failed && !fault.retryable &&
              fault.code == "soap:Receiver" && fault.subcode == "wscn:OperationFailed" &&
              fault.reason == "Sanitized operation failure",
          "WSD SOAP operation fault decoded incorrectly");

    auto temporary_fault_xml = fault_xml;
    const auto subcode_position = temporary_fault_xml.find("OperationFailed");
    check(subcode_position != std::string::npos, "WSD fault fixture subcode is missing");
    temporary_fault_xml.replace(
        subcode_position,
        std::string("OperationFailed").size(),
        "ServerErrorTemporaryError");
    const auto temporary_fault = just_scanner::decode_wsd_soap_fault(temporary_fault_xml);
    check(temporary_fault.kind == WsdSoapFaultKind::temporary_error &&
              temporary_fault.retryable,
          "WSD temporary fault was not marked retryable");

    auto wrong_soap_namespace = fault_xml;
    const std::string soap_namespace = "https://www.w3.org/2003/05/soap-envelope";
    const auto soap_position = wrong_soap_namespace.find(soap_namespace);
    check(soap_position != std::string::npos, "WSD fault SOAP namespace is missing");
    wrong_soap_namespace.replace(soap_position, soap_namespace.size(), "urn:invalid:soap");
    expect_wsd_error(
        [&] { (void)just_scanner::decode_wsd_soap_fault(wrong_soap_namespace); },
        "WSD fault accepted the wrong SOAP namespace");
}

class FixtureWsdDiscoveryExchange final : public just_scanner::IWsdDiscoveryExchange {
public:
    FixtureWsdDiscoveryExchange(std::string probe_xml, std::string metadata_xml)
        : probe_xml_(std::move(probe_xml)), metadata_xml_(std::move(metadata_xml)) {}

    std::vector<WsdReceivedDatagram> probe(
        const std::string_view request_xml,
        const std::atomic_bool& cancel_requested) override {
        check(!cancel_requested.load(), "cancelled injected WSD probe was invoked");
        probe_request.assign(request_xml);
        return {{probe_xml_, "192.0.2.10"}};
    }

    std::string get_metadata(
        const WsdProbeCandidate& candidate,
        const std::string_view request_xml,
        const std::atomic_bool& cancel_requested) override {
        check(!cancel_requested.load(), "cancelled injected WSD metadata request was invoked");
        metadata_candidate = candidate;
        metadata_request.assign(request_xml);
        return metadata_xml_;
    }

    std::string probe_request;
    std::string metadata_request;
    WsdProbeCandidate metadata_candidate;

private:
    std::string probe_xml_;
    std::string metadata_xml_;
};

void test_wsd_discovery_metadata_model_is_injectable_and_private(
    const std::filesystem::path& fixtures) {
    const auto read_fixture = [&](const std::string& name) {
        std::ifstream input(fixtures / name, std::ios::binary);
        check(input.good(), "sanitized WSD discovery fixture is missing: " + name);
        return std::string(
            (std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    };
    const auto probe_xml = read_fixture("wsd_probe_matches.xml");
    const auto metadata_xml = read_fixture("wsd_device_metadata.xml");
    const std::string probe_id = "urn:uuid:11111111-1111-1111-1111-111111111111";
    const std::string metadata_id = "urn:uuid:33333333-3333-3333-3333-333333333333";

    const auto probe_request = just_scanner::encode_wsd_probe_request(probe_id);
    check(probe_request.find("/Probe</wsa:Action>") != std::string::npos &&
              probe_request.find("wscn:ScanDeviceType") != std::string::npos,
          "WSD probe request encoding is incomplete");
    const auto candidates = just_scanner::decode_wsd_probe_matches_response(
        probe_xml, probe_id, "192.0.2.10");
    check(candidates.size() == 1U &&
              candidates.front().logical_device_address ==
                  "urn:uuid:22222222-2222-2222-2222-222222222222" &&
              candidates.front().transport_uri ==
                  "http://192.0.2.10:5357/synthetic-device",
          "sanitized WSD ProbeMatches fixture decoded incorrectly");
    check(just_scanner::decode_wsd_probe_matches_response(
              probe_xml, probe_id, "192.0.2.11").empty(),
          "WSD accepted an XAddr from a different datagram source");
    expect_wsd_error(
        [&] {
            (void)just_scanner::decode_wsd_probe_matches_response(
                probe_xml,
                "urn:uuid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "192.0.2.10");
        },
        "WSD accepted an uncorrelated ProbeMatches response");

    const auto metadata_request = just_scanner::encode_dpws_get_metadata_request(
        candidates.front().logical_device_address, metadata_id);
    check(metadata_request.find("/transfer/Get</wsa:Action>") != std::string::npos &&
              metadata_request.find(candidates.front().logical_device_address) != std::string::npos,
          "DPWS metadata request encoding is incomplete");
    const auto metadata = just_scanner::decode_dpws_get_metadata_response(
        metadata_xml, metadata_id);
    check(metadata.manufacturer == "Synthetic Devices" &&
              metadata.model_name == "Offline Lab Scanner" &&
              metadata.logical_device_address == candidates.front().logical_device_address &&
              metadata.logical_service_address ==
                  "urn:uuid:44444444-4444-4444-4444-444444444444" &&
              metadata.scan_namespace ==
                  "http://schemas.microsoft.com/windows/2006/08/wdp/scan",
          "sanitized DPWS metadata fixture decoded incorrectly");

    auto multi_service_metadata = metadata_xml;
    const std::string relationship_end = "</dpws:Relationship>";
    const auto relationship_end_position = multi_service_metadata.find(relationship_end);
    check(relationship_end_position != std::string::npos,
          "DPWS relationship fixture closing element is missing");
    multi_service_metadata.insert(
        relationship_end_position,
        "<dpws:Hosted xmlns:other=\"urn:synthetic:other-service\">"
        "<wsa:EndpointReference><wsa:Address>"
        "urn:uuid:55555555-5555-5555-5555-555555555555"
        "</wsa:Address></wsa:EndpointReference>"
        "<dpws:Types>other:PrinterServiceType</dpws:Types></dpws:Hosted>");
    const auto multi_service = just_scanner::decode_dpws_get_metadata_response(
        multi_service_metadata, metadata_id);
    check(multi_service.logical_service_address == metadata.logical_service_address &&
              multi_service.scan_namespace == metadata.scan_namespace,
          "an unrelated hosted service displaced the WSD scan service");

    FixtureWsdDiscoveryExchange exchange(probe_xml, metadata_xml);
    just_scanner::WsdDiscoveryModel discovery;
    std::atomic_bool cancel_requested{false};
    const auto result = discovery.refresh(
        exchange, probe_id, {metadata_id}, cancel_requested);
    check(result.generation == 1U && result.devices.size() == 1U &&
              result.issue_codes.empty(),
          "injected WSD discovery did not publish one valid scanner");
    check(result.devices.front().opaque_id == "wsd-device-0001" &&
              result.devices.front().display_name == "Offline Lab Scanner" &&
              result.devices.front().manufacturer == "Synthetic Devices",
          "WSD public discovery metadata is invalid");
    const auto public_text = result.devices.front().opaque_id +
                             result.devices.front().display_name +
                             result.devices.front().manufacturer;
    check(public_text.find("192.0.2.10") == std::string::npos &&
              public_text.find("22222222") == std::string::npos &&
              public_text.find("44444444") == std::string::npos,
          "private WSD routing data leaked into public discovery output");
    const auto endpoint = discovery.resolve_for_connection(
        result.devices.front().opaque_id, result.generation);
    check(endpoint.transport_uri == "http://192.0.2.10:5357/synthetic-device" &&
              endpoint.logical_service_address ==
                  "urn:uuid:44444444-4444-4444-4444-444444444444",
          "opaque WSD selection did not resolve to its internal endpoint");
    check(exchange.probe_request == probe_request &&
              exchange.metadata_request == metadata_request &&
              exchange.metadata_candidate.logical_device_address ==
                  candidates.front().logical_device_address,
          "WSD discovery exchange was not driven through the injected seam");

    cancel_requested.store(true);
    const auto cancelled = discovery.refresh(
        exchange, probe_id, {metadata_id}, cancel_requested);
    check(cancelled.devices.empty() &&
              cancelled.issue_codes == std::vector<std::string>({"cancelled"}),
          "cancelled WSD discovery did not fail closed");
    expect_wsd_error(
        [&] {
            (void)discovery.resolve_for_connection(
                result.devices.front().opaque_id, result.generation);
        },
        "stale WSD discovery selection remained usable");

    auto unsafe_metadata = metadata_xml;
    unsafe_metadata.insert(0U, "<!DOCTYPE x [<!ENTITY y SYSTEM \"file:///private\">]>");
    expect_wsd_error(
        [&] {
            (void)just_scanner::decode_dpws_get_metadata_response(
                unsafe_metadata, metadata_id);
        },
        "DPWS metadata accepted a DTD or entity declaration");
}

template <typename Callback>
void expect_scanner_error(Callback callback, const std::string& message) {
    try {
        callback();
    } catch (const ScannerError&) {
        return;
    }
    throw std::runtime_error(message);
}

std::filesystem::path unique_test_root() {
    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() /
           ("just_scanner_mock_core_" + std::to_string(stamp));
}

WiaIntProperty wia_list(std::initializer_list<std::int32_t> values) {
    WiaIntProperty property;
    property.shape = WiaPropertyShape::list;
    property.values = values;
    property.current = property.values.empty() ? 0 : property.values.front();
    property.writable = true;
    return property;
}

WiaIntProperty wia_range(const std::int32_t minimum, const std::int32_t maximum, const std::int32_t step) {
    WiaIntProperty property;
    property.shape = WiaPropertyShape::range;
    property.minimum = minimum;
    property.maximum = maximum;
    property.step = step;
    property.current = minimum;
    property.writable = true;
    return property;
}

WiaIntProperty wia_flags(const std::uint32_t value) {
    WiaIntProperty property;
    property.shape = WiaPropertyShape::flags;
    property.current = static_cast<std::int32_t>(value);
    return property;
}

WiaItemModel acquisition_item(const WiaItemCategory category) {
    WiaItemModel item;
    item.category = category;
    item.transfer_capable = true;
    item.x_resolution = wia_list({150, 300, 600});
    item.y_resolution = wia_list({150, 300, 600});
    item.data_type = wia_list({static_cast<std::int32_t>(WiaDataType::grayscale),
                               static_cast<std::int32_t>(WiaDataType::color)});
    item.bit_depth = wia_list({8, 24});
    if (category == WiaItemCategory::feeder) {
        item.page_count = wia_range(1, 100, 1);
        item.handling_capabilities = wia_flags(just_scanner::wia_feeder);
    }
    return item;
}

#ifdef _WIN32
std::pair<std::uint32_t, std::uint32_t> decode_wic_dimensions(const std::filesystem::path& path) {
    const HRESULT apartment = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool uninitialize = SUCCEEDED(apartment);
    HRESULT result = (FAILED(apartment) && apartment != RPC_E_CHANGED_MODE) ? apartment : S_OK;
    IWICImagingFactory* factory = nullptr;
    IWICBitmapDecoder* decoder = nullptr;
    IWICBitmapFrameDecode* frame = nullptr;
    UINT width = 0U;
    UINT height = 0U;
    if (SUCCEEDED(result)) {
        result = CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(&factory));
    }
    if (SUCCEEDED(result)) {
        result = factory->CreateDecoderFromFilename(path.c_str(), nullptr, GENERIC_READ,
                                                    WICDecodeMetadataCacheOnLoad, &decoder);
    }
    if (SUCCEEDED(result)) result = decoder->GetFrame(0U, &frame);
    if (SUCCEEDED(result)) result = frame->GetSize(&width, &height);
    if (frame != nullptr) frame->Release();
    if (decoder != nullptr) decoder->Release();
    if (factory != nullptr) factory->Release();
    if (uninitialize) CoUninitialize();
    check(SUCCEEDED(result), "Windows decoder rejected an encoded image");
    return {width, height};
}
#endif

class FakeWsdHttpExecutor final : public IWsdHttpExecutor {
public:
    WsdHttpResponse execute(const WsdHttpRequest& request, const WsdHttpLimits& limits,
                            const std::atomic_bool& cancel_requested) override {
        check(!cancel_requested.load(), "cancelled HTTP request reached injected executor");
        seen_request = request;
        seen_limits = limits;
        ++calls;
        return response;
    }

    WsdHttpRequest seen_request;
    WsdHttpLimits seen_limits;
    WsdHttpResponse response{200U, "application/soap+xml; charset=utf-8", "<soap:Envelope/>", false};
    unsigned calls{};
};

void test_wsd_http_transport_is_bounded_and_injectable() {
    FakeWsdHttpExecutor executor;
    WsdHttpLimits limits;
    limits.max_request_bytes = 128U;
    limits.max_response_bytes = 256U;
    limits.timeout_milliseconds = 2500U;
    BoundedWsdHttpTransport transport(executor, limits);
    const std::atomic_bool not_cancelled{false};
    const WsdHttpRequest request{
        "http://192.0.2.10:5357/wsd", "urn:uuid:22222222-2222-2222-2222-222222222222",
        "application/soap+xml", "<soap:Envelope/>"};
    const auto response = transport.post(request, not_cancelled);
    check(response.status_code == 200U && executor.calls == 1U &&
              executor.seen_request.logical_destination == request.logical_destination &&
              executor.seen_limits.timeout_milliseconds == 2500U,
          "injected bounded HTTP exchange lost request data or limits");

    for (const auto& unsafe_uri : {"https://scanner.invalid/wsd", "http://user@192.0.2.10/wsd",
                                   "http://192.0.2.10/wsd?query=1", "http://192.0.2.10:0/wsd"}) {
        auto unsafe = request;
        unsafe.transport_uri = unsafe_uri;
        expect_wsd_error([&] { (void)transport.post(unsafe, not_cancelled); },
                         "unsafe WSD HTTP transport URI was accepted");
    }
    auto oversized = request;
    oversized.payload.assign(129U, 'x');
    expect_wsd_error([&] { (void)transport.post(oversized, not_cancelled); },
                     "oversized WSD HTTP request body was accepted");

    executor.response.redirected = true;
    expect_wsd_error([&] { (void)transport.post(request, not_cancelled); },
                     "redirected WSD HTTP response was accepted");
    executor.response.redirected = false;
    executor.response.status_code = 302U;
    expect_wsd_error([&] { (void)transport.post(request, not_cancelled); },
                     "non-success WSD HTTP status was accepted");
    executor.response.status_code = 200U;
    executor.response.content_type = "text/plain";
    expect_wsd_error([&] { (void)transport.post(request, not_cancelled); },
                     "unexpected WSD HTTP content type was accepted");
    executor.response.content_type = "application/soap+xml";
    executor.response.body.assign(257U, 'x');
    expect_wsd_error([&] { (void)transport.post(request, not_cancelled); },
                     "oversized WSD HTTP response was accepted");

    const std::atomic_bool cancelled{true};
    expect_wsd_error([&] { (void)transport.post(request, cancelled); },
                     "cancelled WSD HTTP request reached the transport executor");
}

void test_wsd_job_codec_and_mtom_are_bounded() {
    WsdScanTicket ticket;
    ticket.source = just_scanner::WsdInputSource::adf;
    ticket.images_to_transfer = 2U;
    const auto create = just_scanner::encode_wsd_create_scan_job_request(
        "urn:uuid:22222222-2222-2222-2222-222222222222",
        "urn:uuid:11111111-1111-1111-1111-111111111111", ticket);
    check(create.find("CreateScanJobRequest") != std::string::npos &&
              create.find("ImagesToTransfer>2<") != std::string::npos &&
              create.find("InputSource>ADF<") != std::string::npos,
          "CreateScanJob encoder lost bounded ticket values");
    const WsdJobCredentials job{7U, "sanitized-token-7"};
    const auto retrieve = just_scanner::encode_wsd_retrieve_image_request(
        "urn:uuid:22222222-2222-2222-2222-222222222222",
        "urn:uuid:33333333-3333-3333-3333-333333333333", job, "page_1.jpg");
    const auto cancel = just_scanner::encode_wsd_cancel_job_request(
        "urn:uuid:22222222-2222-2222-2222-222222222222",
        "urn:uuid:44444444-4444-4444-4444-444444444444", job);
    check(retrieve.find("RetrieveImageRequest") != std::string::npos &&
              retrieve.find("sanitized-token-7") != std::string::npos &&
              cancel.find("CancelJobRequest") != std::string::npos,
          "WSD job encoders omitted required request data");
    const std::string create_response =
        "<soap:Envelope><soap:Header><wsa:RelatesTo>urn:uuid:11111111-1111-1111-1111-111111111111"
        "</wsa:RelatesTo></soap:Header><soap:Body><wscn:CreateScanJobResponse><wscn:JobId>7</wscn:JobId>"
        "<wscn:JobToken>sanitized-token-7</wscn:JobToken><wscn:Format>exif</wscn:Format>"
        "</wscn:CreateScanJobResponse></soap:Body></soap:Envelope>";
    const auto decoded = just_scanner::decode_wsd_create_scan_job_response(
        create_response, "urn:uuid:11111111-1111-1111-1111-111111111111");
    check(decoded.credentials.job_id == 7U && decoded.credentials.job_token == "sanitized-token-7" &&
              decoded.final_format == "exif", "CreateScanJob response decoder lost correlated job values");
    expect_wsd_error([&] { (void)just_scanner::decode_wsd_create_scan_job_response(
                         create_response, "urn:uuid:99999999-9999-9999-9999-999999999999"); },
                     "CreateScanJob response accepted mismatched correlation");
    const auto unsafe_response = std::string("<!DOCTYPE x><x/>");
    expect_wsd_error([&] { (void)just_scanner::decode_wsd_create_scan_job_response(
                         unsafe_response, "urn:uuid:11111111-1111-1111-1111-111111111111"); },
                     "CreateScanJob response accepted unsafe XML declaration");
    const std::string body = "--bound\r\nContent-Type: application/xop+xml\r\nContent-ID: <soap>\r\n\r\n<soap/>\r\n--bound\r\nContent-Type: image/jpeg\r\nContent-ID: <image-1>\r\n\r\nJPEG\r\n--bound--";
    const std::vector<std::uint8_t> bytes(body.begin(), body.end());
    const auto image = just_scanner::decode_wsd_retrieve_mtom_response(
        "multipart/related; boundary=bound", bytes, "image-1");
    check(image.content_type == "image/jpeg" && image.bytes.size() == 4U,
          "MTOM extractor did not return the referenced image part");
    expect_wsd_error([&] { (void)just_scanner::decode_wsd_retrieve_mtom_response(
                         "multipart/related; boundary=bound", bytes, "missing"); },
                     "MTOM extractor accepted an absent content ID");
}

void test_capabilities_and_validation(const std::filesystem::path& fixtures) {
    MockScanner scanner(fixtures);
    const auto caps = scanner.capabilities();
    check(scanner.provider_id() == "mock-v1", "provider identity changed");
    check(scanner.device_id() == "synthetic-device", "device identity changed");
    check(caps.sources.size() == 2U && caps.max_batch_pages == 100U, "capabilities changed");
    check(caps.can_preview && caps.can_cancel, "mock controls changed");

    ScanRequest unsupported;
    unsupported.color = ColorMode::rgb24;
    expect_scanner_error([&] { (void)scanner.scan(unsupported); }, "unsupported colour was accepted");
    unsupported.color = ColorMode::gray8;
    unsupported.source = SourceType::adf_duplex;
    expect_scanner_error([&] { (void)scanner.scan(unsupported); }, "unsupported duplex was accepted");
    unsupported.source = SourceType::flatbed;
    unsupported.max_pages = 2U;
    expect_scanner_error([&] { (void)scanner.scan(unsupported); }, "flatbed batch was accepted");
}

void test_mock_batch_is_deterministic(const std::filesystem::path& fixtures) {
    MockScanner scanner(fixtures);
    ScanRequest request;
    request.source = SourceType::adf_simplex;
    request.max_pages = 2U;
    const auto frames = scanner.scan(request);
    check(frames.size() == 2U, "mock batch page count changed");
    check(frames[0].fixture_id == "synthetic-a" && frames[1].fixture_id == "synthetic-b",
          "mock fixture sequence changed");
    check(frames[0].width == 8U && frames[0].height == 6U && !frames[0].bytes.empty(),
          "mock frame metadata changed");
}

void test_session_operations_and_recovery(const std::filesystem::path& fixtures) {
    const auto root = unique_test_root();
    std::filesystem::create_directories(root);
    try {
        MockScanner scanner(fixtures);
        ScanRequest request;
        request.source = SourceType::adf_simplex;
        request.max_pages = 2U;
        const auto frames = scanner.scan(request);
        auto session = ScanSession::create(
            root, "synthetic-session", "2026-08-26T01:30:00Z", scanner.provider_id(), scanner.device_id());
        const auto first = session.add_page(frames[0]);
        const auto second = session.add_page(frames[1]);
        check(session.pages().size() == 2U, "pages were not added");
        check(std::filesystem::is_regular_file(root / session.pages()[0].current_master),
              "first master was not published");

        session.reorder({second, first});
        check(session.pages()[0].id == second, "reorder failed");
        session.rotate(first, 90U);
        session.set_crop(first, CropRect{1U, 1U, 6U, 4U});
        session.set_tone(first, 15, -20);
        session.set_included(second, false);
        expect_scanner_error([&] { session.set_crop(first, CropRect{7U, 0U, 2U, 1U}); },
                             "out-of-bounds crop was accepted");
        expect_scanner_error([&] { session.reorder({first, first}); }, "duplicate reorder was accepted");

        const auto original_before_rescan = session.pages()[1].current_master;
        const auto replacement = scanner.scan(ScanRequest{}).front();
        session.rescan(first, replacement);
        const auto& rescanned = session.pages()[1];
        check(rescanned.revision == 2U && rescanned.preserved_masters.size() == 1U,
              "rescan revision history failed");
        check(rescanned.preserved_masters[0] == original_before_rescan &&
                  std::filesystem::is_regular_file(root / original_before_rescan),
              "rescan overwrote the original master");
        check(rescanned.rotation == 0U && !rescanned.crop.has_value() && rescanned.brightness == 0 &&
                  rescanned.contrast == 0,
              "rescan did not reset derivatives");

        session.save();
        {
            std::ofstream abandoned(root / "session.jscan.tmp", std::ios::binary | std::ios::trunc);
            abandoned << "incomplete";
        }
        bool recovered = true;
        auto loaded = ScanSession::load(root, &recovered);
        check(!recovered && loaded.pages().size() == 2U, "stage file affected current session");
        check(loaded.pages()[0].id == second && !loaded.pages()[0].included, "session state was not restored");

        loaded.set_included(second, true);
        loaded.save();
        {
            std::ofstream corrupt(root / "session.jscan", std::ios::binary | std::ios::trunc);
            corrupt << "not-a-session\n";
        }
        auto backup = ScanSession::load(root, &recovered);
        check(recovered, "valid backup was not used after current corruption");
        check(!backup.pages()[0].included, "backup did not preserve the prior committed state");
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
        throw;
    }
    std::error_code error;
    std::filesystem::remove_all(root, error);
    check(!error, "test session cleanup failed");
}

void test_manifest_traversal_fails_closed(const std::filesystem::path& fixtures) {
    const auto root = unique_test_root();
    std::filesystem::create_directories(root / "originals");
    try {
        MockScanner scanner(fixtures);
        auto frame = scanner.scan(ScanRequest{}).front();
        auto session = ScanSession::create(
            root, "safe-session", "2026-08-26T01:30:00Z", scanner.provider_id(), scanner.device_id());
        (void)session.add_page(frame);
        session.save();
        std::filesystem::remove(root / "session.jscan.bak");
        {
            std::ofstream manifest(root / "session.jscan", std::ios::binary | std::ios::trunc);
            manifest << "JSCAN\t1\n"
                     << "SESSION\tsafe-session\t2026-08-26T01:30:00Z\tmock-v1\tsynthetic-device\n"
                     << "PAGE\tpage-0001\tsynthetic-a\t../private.pgm\t1\t8\t6\t300\tgray8\t8\tflatbed\t0\t1\t0\t0\t0\t0\t0\n"
                     << "END\n";
        }
        expect_scanner_error([&] { (void)ScanSession::load(root); }, "traversal manifest was accepted");
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
        throw;
    }
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

void test_fixture_exports_are_ordered_and_collision_safe(const std::filesystem::path& fixtures) {
    const auto root = unique_test_root();
    std::filesystem::create_directories(root);
    try {
        MockScanner scanner(fixtures);
        ScanRequest request;
        request.source = SourceType::adf_simplex;
        request.max_pages = 2U;
        const auto frames = scanner.scan(request);
        auto session = ScanSession::create(
            root, "export-session", "2026-08-26T02:00:00Z", scanner.provider_id(), scanner.device_id());
        const auto first = session.add_page(frames[0]);
        const auto second = session.add_page(frames[1]);
        session.reorder({second, first});
        std::filesystem::create_directories(root / "output");

        const auto images = session.export_included_pgm(root / "output", "document");
        check(images.size() == 2U && images[0].filename() == "document_0001.pgm" &&
                  images[1].filename() == "document_0002.pgm",
              "separate-image naming or order changed");
        std::ifstream first_image(images[0], std::ios::binary);
        const std::string first_pgm((std::istreambuf_iterator<char>(first_image)), std::istreambuf_iterator<char>());
        check(first_pgm.starts_with("P2\n") && first_pgm.find("8 6\n255\n") != std::string::npos,
              "first exported image dimensions are invalid");
        expect_scanner_error([&] { (void)session.export_included_pgm(root / "output", "document"); },
                             "image collision overwrote an export");

        const auto pdf_path = root / "output" / "document.pdf";
        session.export_multipage_pdf(pdf_path);
        std::ifstream pdf_input(pdf_path, std::ios::binary);
        const std::string pdf((std::istreambuf_iterator<char>(pdf_input)), std::istreambuf_iterator<char>());
        check(pdf.starts_with("%PDF-1.4") && pdf.find("/Count 2") != std::string::npos,
              "multipage PDF structure is invalid");
        check(pdf.find("/Width 8 /Height 6") != std::string::npos && pdf.ends_with("%%EOF\n"),
              "PDF dimensions or final marker are invalid");
        const auto startxref_marker = pdf.rfind("startxref\n");
        check(startxref_marker != std::string::npos, "PDF startxref marker is missing");
        const auto xref_value_start = startxref_marker + std::string("startxref\n").size();
        const auto xref_value_end = pdf.find('\n', xref_value_start);
        check(xref_value_end != std::string::npos, "PDF startxref value is incomplete");
        const auto xref_offset = static_cast<std::size_t>(
            std::stoull(pdf.substr(xref_value_start, xref_value_end - xref_value_start)));
        check(xref_offset < pdf.size() && pdf.compare(xref_offset, 5U, "xref\n") == 0,
              "PDF startxref does not identify the xref table");
        for (std::size_t object = 1U; object <= 8U; ++object) {
            check(pdf.find(std::to_string(object) + " 0 obj\n") != std::string::npos,
                  "PDF object table is incomplete");
        }
        expect_scanner_error([&] { session.export_multipage_pdf(pdf_path); },
                             "PDF collision overwrote an export");
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
        throw;
    }
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

void test_empty_and_fully_excluded_sessions_do_not_export(const std::filesystem::path& fixtures) {
    const auto root = unique_test_root();
    std::filesystem::create_directories(root / "output");
    try {
        MockScanner scanner(fixtures);
        auto session = ScanSession::create(
            root, "empty-session", "2026-08-26T05:00:00Z", scanner.provider_id(), scanner.device_id());
        session.save();
        check(ScanSession::load(root).pages().empty(), "empty session did not survive persistence");
        expect_scanner_error([&] { (void)session.export_included_pgm(root / "output", "empty"); },
                             "empty session produced a PGM export");
        expect_scanner_error([&] { session.export_multipage_pdf(root / "output" / "empty.pdf"); },
                             "empty session produced a PDF export");
        const auto page_id = session.add_page(scanner.scan(ScanRequest{}).front());
        session.set_included(page_id, false);
        expect_scanner_error([&] { (void)session.export_included_pgm(root / "output", "excluded"); },
                             "fully excluded session produced a PGM export");
        expect_scanner_error(
            [&] { (void)session.export_included_wic(root / "output", "excluded", ImageExportFormat::png); },
            "fully excluded session produced a native image export");
        expect_scanner_error([&] { session.export_multipage_pdf(root / "output" / "excluded.pdf"); },
                             "fully excluded session produced a PDF export");
        check(std::filesystem::is_empty(root / "output"), "rejected empty export left output files");
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
        throw;
    }
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

void test_windows_native_image_exports(const std::filesystem::path& fixtures) {
    const auto root = unique_test_root();
    std::filesystem::create_directories(root);
    try {
        MockScanner scanner(fixtures);
        auto session = ScanSession::create(
            root, "wic-export", "2026-08-26T02:10:00Z", scanner.provider_id(), scanner.device_id());
        (void)session.add_page(scanner.scan(ScanRequest{}).front());
        std::filesystem::create_directories(root / "output");
        const auto png = session.export_included_wic(root / "output", "image_png", ImageExportFormat::png).front();
        const auto jpeg = session.export_included_wic(root / "output", "image_jpeg", ImageExportFormat::jpeg).front();
        const auto tiff = session.export_included_wic(root / "output", "image_tiff", ImageExportFormat::tiff).front();
        const auto read_prefix = [](const std::filesystem::path& path, const std::size_t count) {
            std::ifstream input(path, std::ios::binary);
            std::string prefix(count, '\0');
            input.read(prefix.data(), static_cast<std::streamsize>(prefix.size()));
            check(input.gcount() == static_cast<std::streamsize>(count), "encoded image is truncated");
            return prefix;
        };
        check(read_prefix(png, 8U) == std::string("\x89PNG\r\n\x1a\n", 8U), "PNG signature is invalid");
        check(read_prefix(jpeg, 2U) == std::string("\xff\xd8", 2U), "JPEG signature is invalid");
        const auto tiff_prefix = read_prefix(tiff, 4U);
        check(tiff_prefix == std::string("II\x2a\0", 4U) || tiff_prefix == std::string("MM\0\x2a", 4U),
              "TIFF signature is invalid");
#ifdef _WIN32
        check(decode_wic_dimensions(png) == std::pair<std::uint32_t, std::uint32_t>{8U, 6U},
              "PNG decoder dimensions changed");
        check(decode_wic_dimensions(jpeg) == std::pair<std::uint32_t, std::uint32_t>{8U, 6U},
              "JPEG decoder dimensions changed");
        check(decode_wic_dimensions(tiff) == std::pair<std::uint32_t, std::uint32_t>{8U, 6U},
              "TIFF decoder dimensions changed");
#endif
        expect_scanner_error(
            [&] { (void)session.export_included_wic(root / "output", "image_png", ImageExportFormat::png); },
            "native image collision overwrote an export");
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
        throw;
    }
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

void test_unicode_and_invalid_export_paths(const std::filesystem::path& fixtures) {
    const auto root = unique_test_root();
    std::filesystem::create_directories(root);
    try {
        MockScanner scanner(fixtures);
        auto session = ScanSession::create(
            root, "unicode-export", "2026-08-26T02:20:00Z", scanner.provider_id(), scanner.device_id());
        (void)session.add_page(scanner.scan(ScanRequest{}).front());
        std::filesystem::create_directories(root / "output");
        const std::string unicode_name = "Résumé_日本";
        const auto pgm = session.export_included_pgm(root / "output", unicode_name).front();
        const auto png = session.export_included_wic(root / "output", unicode_name, ImageExportFormat::png).front();
        check(std::filesystem::is_regular_file(pgm) && std::filesystem::is_regular_file(png),
              "Unicode exports were not published");
        expect_scanner_error([&] { (void)session.export_included_pgm(root / "output", "CON"); },
                             "reserved Windows name was accepted");
        expect_scanner_error([&] { (void)session.export_included_pgm(root / "output", "bad/name"); },
                             "path separator was accepted in a document name");
        {
            std::ofstream not_directory(root / "not-directory", std::ios::binary);
            not_directory << "synthetic";
        }
        expect_scanner_error([&] { (void)session.export_included_pgm(root / "not-directory", "blocked"); },
                             "non-directory export destination was accepted");
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
        throw;
    }
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

void test_larger_session_order_and_persistence(const std::filesystem::path& fixtures) {
    const auto root = unique_test_root();
    std::filesystem::create_directories(root);
    try {
        MockScanner scanner(fixtures);
        ScanRequest request;
        request.source = SourceType::adf_simplex;
        request.max_pages = 50U;
        const auto frames = scanner.scan(request);
        auto session = ScanSession::create(
            root, "larger-session", "2026-08-26T02:30:00Z", scanner.provider_id(), scanner.device_id());
        std::vector<std::string> ids;
        for (const auto& frame : frames) ids.push_back(session.add_page(frame));
        std::reverse(ids.begin(), ids.end());
        session.reorder(ids);
        session.save();
        const auto loaded = ScanSession::load(root);
        check(loaded.pages().size() == 50U && loaded.pages().front().id == "page-0050" &&
                  loaded.pages().back().id == "page-0001",
              "larger session order did not survive persistence");
        std::filesystem::create_directories(root / "output");
        const auto pdf_path = root / "output" / "fifty-pages.pdf";
        loaded.export_multipage_pdf(pdf_path);
        std::ifstream input(pdf_path, std::ios::binary);
        const std::string pdf((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        check(pdf.find("/Count 50") != std::string::npos, "larger PDF page count is invalid");
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
        throw;
    }
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

void test_wia_flatbed_and_feeder_capability_mapping() {
    WiaDeviceModel device{"opaque-device-1", {acquisition_item(WiaItemCategory::flatbed),
                                               acquisition_item(WiaItemCategory::feeder)}};
    const WiaCapabilityResult result = just_scanner::map_wia_capabilities(device);
    check(result.issue_codes.empty() && result.profiles.size() == 2U,
          "valid flatbed/feeder capability tree was rejected");
    check(result.profiles[0].source == SourceType::flatbed && result.profiles[0].max_pages == 1U,
          "flatbed mapping changed");
    check(result.profiles[1].source == SourceType::adf_simplex && result.profiles[1].max_pages == 100U,
          "simplex feeder mapping changed");
    check(result.profiles[0].dpi_values == std::vector<std::uint32_t>({150U, 300U, 600U}),
          "DPI intersection changed");
}

void test_wia_duplex_and_malformed_driver_models() {
    auto feeder = acquisition_item(WiaItemCategory::feeder);
    feeder.handling_capabilities = wia_flags(just_scanner::wia_feeder | just_scanner::wia_duplex |
                                             just_scanner::wia_advanced_duplex);
    WiaDeviceModel duplex{"opaque-device-2", {feeder, WiaItemModel{WiaItemCategory::feeder_front},
                                               WiaItemModel{WiaItemCategory::feeder_back}}};
    const auto duplex_result = just_scanner::map_wia_capabilities(duplex);
    check(duplex_result.profiles.size() == 2U &&
              duplex_result.profiles[1].source == SourceType::adf_duplex &&
              duplex_result.profiles[1].advanced_duplex,
          "advanced duplex tree was not mapped");

    auto incomplete = feeder;
    WiaDeviceModel incomplete_tree{"opaque-device-3", {incomplete, WiaItemModel{WiaItemCategory::feeder_front}}};
    const auto incomplete_result = just_scanner::map_wia_capabilities(incomplete_tree);
    check(incomplete_result.profiles.size() == 2U && !incomplete_result.profiles[1].advanced_duplex &&
              std::find(incomplete_result.issue_codes.begin(), incomplete_result.issue_codes.end(),
                        "incomplete_advanced_duplex_tree") != incomplete_result.issue_codes.end(),
          "incomplete advanced duplex tree did not fail closed");

    auto malformed = acquisition_item(WiaItemCategory::flatbed);
    malformed.y_resolution.reset();
    const auto malformed_result = just_scanner::map_wia_capabilities({"opaque-device-4", {malformed}});
    check(malformed_result.profiles.empty() && malformed_result.issue_codes == std::vector<std::string>{"missing_resolution"},
          "malformed driver properties were exposed as capabilities");
}

void test_wia_readback_accepts_only_reported_coercion() {
    auto feeder = acquisition_item(WiaItemCategory::feeder);
    const auto mapping = just_scanner::map_wia_capabilities({"opaque-device-5", {feeder}});
    check(mapping.profiles.size() == 1U, "feeder profile is unavailable");
    ScanRequest request;
    request.source = SourceType::adf_simplex;
    request.dpi = 300U;
    request.color = ColorMode::gray8;
    request.bit_depth = 8U;
    request.max_pages = 2U;
    const auto accepted = just_scanner::validate_wia_readback(
        mapping.profiles.front(), request, WiaReadback{150U, 150U, ColorMode::gray8, 8U, 1U});
    check(accepted.driver_coerced && accepted.dpi == 150U && accepted.pages == 1U,
          "reported driver coercion was not preserved");
    expect_scanner_error(
        [&] {
            (void)just_scanner::validate_wia_readback(
                mapping.profiles.front(), request, WiaReadback{300U, 301U, ColorMode::gray8, 8U, 2U});
        },
        "asymmetric driver read-back was accepted");
    expect_scanner_error(
        [&] {
            (void)just_scanner::validate_wia_readback(
                mapping.profiles.front(), request, WiaReadback{1200U, 1200U, ColorMode::gray8, 8U, 2U});
        },
        "unreported driver read-back was accepted");
}

void test_wia_property_writes_are_prevalidated() {
    WiaDeviceModel device{"opaque-device", {acquisition_item(WiaItemCategory::flatbed),
                                               acquisition_item(WiaItemCategory::feeder)}};
    const auto capabilities = just_scanner::map_wia_capabilities(device);
    ScanRequest request;
    request.source = SourceType::adf_simplex;
    request.dpi = 600U;
    request.color = ColorMode::rgb24;
    request.bit_depth = 24U;
    request.max_pages = 10U;
    const auto writes = just_scanner::prepare_wia_property_writes(capabilities, request);
    check(writes.x_dpi == 600 && writes.y_dpi == 600 &&
              writes.data_type == static_cast<std::int32_t>(WiaDataType::color) &&
              writes.bit_depth == 24 && writes.pages == 10,
          "prevalidated WIA property writes changed");

    request.dpi = 1200U;
    expect_scanner_error([&] { (void)just_scanner::prepare_wia_property_writes(capabilities, request); },
                         "unreported WIA resolution reached the property-write stage");
    request.dpi = 300U;
    request.source = SourceType::adf_duplex;
    expect_scanner_error([&] { (void)just_scanner::prepare_wia_property_writes(capabilities, request); },
                         "unreported WIA source reached the property-write stage");
    request.source = SourceType::flatbed;
    request.max_pages = 2U;
    expect_scanner_error([&] { (void)just_scanner::prepare_wia_property_writes(capabilities, request); },
                         "flatbed batch reached the property-write stage");
}

void test_blocked_stage_paths_preserve_committed_state(const std::filesystem::path& fixtures) {
    const auto root = unique_test_root();
    std::filesystem::create_directories(root);
    try {
        MockScanner scanner(fixtures);
        auto session = ScanSession::create(
            root, "failure-session", "2026-08-26T03:20:00Z", scanner.provider_id(), scanner.device_id());
        const auto page_id = session.add_page(scanner.scan(ScanRequest{}).front());
        session.save();
        const auto read_all = [](const std::filesystem::path& path) {
            std::ifstream input(path, std::ios::binary);
            return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
        };
        const auto committed_manifest = read_all(root / "session.jscan");

        std::filesystem::create_directories(root / "session.jscan.tmp");
        {
            std::ofstream blocker(root / "session.jscan.tmp" / "occupied", std::ios::binary);
            blocker << "synthetic-blocker";
        }
        session.rotate(page_id, 90U);
        expect_scanner_error([&] { session.save(); }, "blocked manifest stage was accepted");
        check(read_all(root / "session.jscan") == committed_manifest,
              "failed save changed the committed manifest");
        std::filesystem::remove_all(root / "session.jscan.tmp");

        const auto master_before = session.pages().front().current_master;
        std::filesystem::create_directories(root / "originals" / "page-0001-r0002.pgm.tmp");
        {
            std::ofstream blocker(root / "originals" / "page-0001-r0002.pgm.tmp" / "occupied");
            blocker << "synthetic-blocker";
        }
        expect_scanner_error([&] { session.rescan(page_id, scanner.scan(ScanRequest{}).front()); },
                             "blocked master stage was accepted");
        check(session.pages().front().current_master == master_before && session.pages().front().revision == 1U,
              "failed rescan changed the active master");

        std::filesystem::create_directories(root / "output");
        std::filesystem::create_directories(root / "output" / "blocked_0001.pgm.tmp");
        {
            std::ofstream blocker(root / "output" / "blocked_0001.pgm.tmp" / "occupied");
            blocker << "synthetic-blocker";
        }
        expect_scanner_error([&] { (void)session.export_included_pgm(root / "output", "blocked"); },
                             "blocked PGM stage was accepted");
        check(!std::filesystem::exists(root / "output" / "blocked_0001.pgm"),
              "failed PGM export published a destination");

        std::filesystem::create_directories(root / "output" / "wicblocked_0001.png.tmp");
        {
            std::ofstream blocker(root / "output" / "wicblocked_0001.png.tmp" / "occupied");
            blocker << "synthetic-blocker";
        }
        expect_scanner_error(
            [&] { (void)session.export_included_wic(root / "output", "wicblocked", ImageExportFormat::png); },
            "blocked WIC stage was accepted");
        check(!std::filesystem::exists(root / "output" / "wicblocked_0001.png"),
              "failed WIC export published a destination");
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
        throw;
    }
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

void test_managed_paths_reject_relative_and_unc_roots(const std::filesystem::path& fixtures) {
    MockScanner scanner(fixtures);
    expect_scanner_error(
        [&] {
            (void)ScanSession::create("relative-session", "bad-relative", "2026-08-26T04:00:00Z",
                                      scanner.provider_id(), scanner.device_id());
        },
        "relative session root was accepted");
#ifdef _WIN32
    expect_scanner_error(
        [&] {
            (void)ScanSession::create("\\\\synthetic-server\\synthetic-share\\session", "bad-unc",
                                      "2026-08-26T04:00:00Z", scanner.provider_id(), scanner.device_id());
        },
        "UNC session root was accepted");
#endif
}

void test_impossible_frame_dimensions_fail_before_publication(const std::filesystem::path& fixtures) {
    const auto root = unique_test_root();
    std::filesystem::create_directories(root);
    try {
        MockScanner scanner(fixtures);
        auto session = ScanSession::create(
            root, "dimension-session", "2026-08-26T04:10:00Z", scanner.provider_id(), scanner.device_id());
        auto frame = scanner.scan(ScanRequest{}).front();
        frame.width = 200001U;
        expect_scanner_error([&] { (void)session.add_page(frame); }, "impossible frame width was accepted");
        check(session.pages().empty() && std::filesystem::is_empty(root / "originals"),
              "rejected frame published session state or a master");

        frame = scanner.scan(ScanRequest{}).front();
        frame.width = 9U;
        expect_scanner_error([&] { (void)session.add_page(frame); },
                             "PGM dimensions inconsistent with metadata were accepted");
        frame = scanner.scan(ScanRequest{}).front();
        frame.bytes = {'n', 'o', 't', '-', 'p', 'g', 'm'};
        expect_scanner_error([&] { (void)session.add_page(frame); }, "malformed PGM master was accepted");
        frame = scanner.scan(ScanRequest{}).front();
        frame.color = ColorMode::rgb24;
        expect_scanner_error([&] { (void)session.add_page(frame); },
                             "colour metadata inconsistent with the grayscale master was accepted");
        check(session.pages().empty() && std::filesystem::is_empty(root / "originals"),
              "invalid master validation published state or bytes");

        const auto page_id = session.add_page(scanner.scan(ScanRequest{}).front());
        const auto original_path = session.pages().front().current_master;
        const auto revision = session.pages().front().revision;
        auto invalid_rescan = scanner.scan(ScanRequest{}).front();
        invalid_rescan.bytes = {'b', 'a', 'd'};
        expect_scanner_error([&] { session.rescan(page_id, invalid_rescan); },
                             "malformed rescan master was accepted");
        check(session.pages().front().current_master == original_path &&
                  session.pages().front().revision == revision &&
                  session.pages().front().preserved_masters.empty(),
              "rejected rescan changed the committed page");
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
        throw;
    }
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

void test_crop_and_rotation_apply_only_to_derivatives(const std::filesystem::path& fixtures) {
    const auto root = unique_test_root();
    std::filesystem::create_directories(root);
    try {
        MockScanner scanner(fixtures);
        auto session = ScanSession::create(
            root, "derivative-session", "2026-08-26T04:20:00Z", scanner.provider_id(), scanner.device_id());
        const auto page_id = session.add_page(scanner.scan(ScanRequest{}).front());
        const auto master_path = root / session.pages().front().current_master;
        std::ifstream master_input(master_path, std::ios::binary);
        const std::string master_before((std::istreambuf_iterator<char>(master_input)),
                                        std::istreambuf_iterator<char>());
        session.set_crop(page_id, CropRect{1U, 1U, 6U, 4U});
        session.rotate(page_id, 90U);
        session.set_tone(page_id, 10, 20);
        std::filesystem::create_directories(root / "output");

        const auto pgm = session.export_included_pgm(root / "output", "adjusted").front();
        std::ifstream pgm_input(pgm, std::ios::binary);
        const std::string pgm_text((std::istreambuf_iterator<char>(pgm_input)), std::istreambuf_iterator<char>());
        check(pgm_text.find("4 6\n255\n") != std::string::npos,
              "cropped/rotated PGM dimensions are invalid");
        check(pgm_text.find("192 154 115 77\n230 192 154 115\n") != std::string::npos,
              "brightness/contrast were not applied after crop and rotation");
        const auto png = session.export_included_wic(root / "output", "adjusted", ImageExportFormat::png).front();
#ifdef _WIN32
        check(decode_wic_dimensions(png) == std::pair<std::uint32_t, std::uint32_t>{4U, 6U},
              "cropped/rotated PNG dimensions are invalid");
#endif
        const auto pdf = root / "output" / "adjusted.pdf";
        session.export_multipage_pdf(pdf);
        std::ifstream pdf_input(pdf, std::ios::binary);
        const std::string pdf_text((std::istreambuf_iterator<char>(pdf_input)), std::istreambuf_iterator<char>());
        check(pdf_text.find("/Width 4 /Height 6") != std::string::npos,
              "cropped/rotated PDF dimensions are invalid");

        std::ifstream master_after_input(master_path, std::ios::binary);
        const std::string master_after((std::istreambuf_iterator<char>(master_after_input)),
                                       std::istreambuf_iterator<char>());
        check(master_after == master_before, "derivative export modified the immutable master");
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
        throw;
    }
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

void test_tone_validation_and_manifest_migration(const std::filesystem::path& fixtures) {
    const auto root = unique_test_root();
    std::filesystem::create_directories(root);
    const auto read_all = [](const std::filesystem::path& path) {
        std::ifstream input(path, std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    };
    try {
        MockScanner scanner(fixtures);
        auto session = ScanSession::create(
            root, "tone-session", "2026-08-26T04:30:00Z", scanner.provider_id(), scanner.device_id());
        const auto page_id = session.add_page(scanner.scan(ScanRequest{}).front());
        expect_scanner_error([&] { session.set_tone(page_id, 101, 0); },
                             "out-of-range brightness was accepted");
        expect_scanner_error([&] { session.set_tone(page_id, 0, -101); },
                             "out-of-range contrast was accepted");
        session.set_tone(page_id, -10, 25);
        session.save();
        auto loaded = ScanSession::load(root);
        check(loaded.pages().front().brightness == -10 && loaded.pages().front().contrast == 25,
              "version 2 manifest did not preserve tone settings");

        auto version_one = read_all(root / "session.jscan");
        check(version_one.starts_with("JSCAN\t2\n"), "saved manifest was not version 2");
        version_one.replace(6U, 1U, "1");
        const auto page_start = version_one.find("PAGE\t");
        const auto page_end = version_one.find('\n', page_start);
        check(page_start != std::string::npos && page_end != std::string::npos,
              "saved page record was unavailable");
        const auto final_tab = version_one.rfind('\t', page_end);
        const auto prior_tab = version_one.rfind('\t', final_tab - 1U);
        check(final_tab != std::string::npos && prior_tab != std::string::npos,
              "saved tone fields were unavailable");
        version_one.erase(prior_tab, page_end - prior_tab);
        {
            std::ofstream output(root / "session.jscan", std::ios::binary | std::ios::trunc);
            output << version_one;
        }
        std::filesystem::remove(root / "session.jscan.bak");
        auto migrated = ScanSession::load(root);
        check(migrated.pages().front().brightness == 0 && migrated.pages().front().contrast == 0,
              "version 1 migration did not default tone settings");
        migrated.save();
        check(read_all(root / "session.jscan").starts_with("JSCAN\t2\n"),
              "version 1 session was not upgraded on save");

        auto invalid = read_all(root / "session.jscan");
        const auto invalid_page_start = invalid.find("PAGE\t");
        const auto invalid_page_end = invalid.find('\n', invalid_page_start);
        const auto invalid_final_tab = invalid.rfind('\t', invalid_page_end);
        const auto invalid_prior_tab = invalid.rfind('\t', invalid_final_tab - 1U);
        invalid.replace(invalid_prior_tab + 1U, invalid_final_tab - invalid_prior_tab - 1U, "101");
        {
            std::ofstream output(root / "session.jscan", std::ios::binary | std::ios::trunc);
            output << invalid;
        }
        std::filesystem::remove(root / "session.jscan.bak");
        expect_scanner_error([&] { (void)ScanSession::load(root); },
                             "out-of-range tone in a version 2 manifest was accepted");
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
        throw;
    }
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

void complete_transfer_page(WiaTransferModel& transfer, const std::uint64_t bytes = 100U) {
    transfer.begin_page(8U, 6U, bytes);
    transfer.accept_chunk(bytes / 2U);
    transfer.accept_chunk(bytes - bytes / 2U);
    transfer.complete_page(true);
}

void test_wia_transfer_success_and_short_feeder_batch() {
    WiaTransferModel complete;
    complete.configure(SourceType::adf_simplex, 2U);
    complete.begin_transfer();
    complete_transfer_page(complete);
    complete_transfer_page(complete, 120U);
    complete.finish_transfer();
    const auto completed = complete.outcome();
    check(completed.state == TransferState::completed && completed.failure == TransferFailure::none &&
              completed.completed_pages == 2U && completed.completed_bytes == 220U && !completed.short_batch,
          "complete feeder transfer state is invalid");

    WiaTransferModel short_batch;
    short_batch.configure(SourceType::adf_simplex, 3U);
    short_batch.begin_transfer();
    complete_transfer_page(short_batch);
    short_batch.report_feeder_empty();
    const auto short_outcome = short_batch.outcome();
    check(short_outcome.state == TransferState::completed && short_outcome.completed_pages == 1U &&
              short_outcome.short_batch,
          "short feeder batch was not distinguished");
}

void test_wia_transfer_cancel_and_device_failures() {
    WiaTransferModel cancelled;
    cancelled.configure(SourceType::adf_simplex, 2U);
    cancelled.begin_transfer();
    cancelled.request_cancel();
    cancelled.acknowledge_cancel();
    check(cancelled.outcome().state == TransferState::failed &&
              cancelled.outcome().failure == TransferFailure::cancelled &&
              std::string(just_scanner::transfer_failure_code(cancelled.outcome().failure)) == "cancelled",
          "cancel acknowledgement was not preserved");

    WiaTransferModel jammed;
    jammed.configure(SourceType::adf_simplex, 2U);
    jammed.begin_transfer();
    jammed.report_failure(TransferFailure::paper_jam);
    check(jammed.outcome().failure == TransferFailure::paper_jam, "paper jam was not distinguished");

    WiaTransferModel empty;
    empty.configure(SourceType::adf_simplex, 1U);
    empty.begin_transfer();
    empty.report_feeder_empty();
    check(empty.outcome().failure == TransferFailure::feeder_empty,
          "empty feeder before the first page was not distinguished");
}

void test_wia_transfer_limits_fail_closed() {
    WiaTransferModel limited(TransferLimits{2U, 100U, 150U, 1000U});
    limited.configure(SourceType::adf_simplex, 2U);
    limited.begin_transfer();
    complete_transfer_page(limited, 100U);
    expect_scanner_error([&] { limited.begin_page(8U, 6U, 60U); },
                         "total transfer limit was exceeded");
    check(limited.outcome().failure == TransferFailure::transfer_limit,
          "transfer-limit failure code changed");

    WiaTransferModel invalid_image;
    invalid_image.configure(SourceType::flatbed, 1U);
    invalid_image.begin_transfer();
    invalid_image.begin_page(8U, 6U, 48U);
    invalid_image.accept_chunk(48U);
    expect_scanner_error([&] { invalid_image.complete_page(false); }, "invalid image was accepted");
    check(invalid_image.outcome().failure == TransferFailure::invalid_image,
          "invalid-image failure code changed");
}

void test_wia_transfer_protocol_order_is_enforced() {
    WiaTransferModel transfer;
    expect_scanner_error([&] { transfer.begin_transfer(); }, "unconfigured transfer started");
    check(transfer.outcome().failure == TransferFailure::protocol_error,
          "out-of-sequence start did not fail as a protocol error");

    WiaTransferModel early_finish;
    early_finish.configure(SourceType::adf_simplex, 2U);
    early_finish.begin_transfer();
    complete_transfer_page(early_finish);
    expect_scanner_error([&] { early_finish.finish_transfer(); }, "incomplete batch was accepted");
    check(early_finish.outcome().failure == TransferFailure::protocol_error,
          "incomplete batch did not fail as a protocol error");
}

void test_wia_discovery_filters_and_hides_raw_ids() {
    WiaDiscoveryModel discovery;
    const auto result = discovery.refresh({
        {WiaDeviceClass::camera, "private-camera-id", "Synthetic Camera", "Fixture Maker"},
        {WiaDeviceClass::scanner, "private-scanner-alpha", "Desk Scanner", "Fixture Maker"},
        {WiaDeviceClass::scanner, "private-scanner-beta", "Photo Scanner", "Fixture Maker"},
    });
    check(result.generation == 1U && result.devices.size() == 2U && result.issue_codes.empty(),
          "scanner discovery filtering changed");
    check(result.devices[0].opaque_id == "wia-device-0001" &&
              result.devices[1].opaque_id == "wia-device-0002",
          "opaque discovery identifiers changed");
    std::string public_text;
    for (const auto& device : result.devices) {
        public_text += device.opaque_id + device.display_name + device.manufacturer;
    }
    check(public_text.find("private-scanner") == std::string::npos,
          "raw WIA identifier leaked into public discovery data");
    check(discovery.resolve_for_connection(result.devices[1].opaque_id, result.generation) ==
              "private-scanner-beta",
          "opaque selection did not resolve internally");
}

void test_wia_discovery_rejects_malformed_and_duplicate_records() {
    WiaDiscoveryModel discovery;
    std::string oversized_name(129U, 'x');
    const auto result = discovery.refresh({
        {WiaDeviceClass::scanner, "", "Missing ID", "Fixture Maker"},
        {WiaDeviceClass::scanner, "duplicate-id", "First", "Fixture Maker"},
        {WiaDeviceClass::scanner, "duplicate-id", "Second", "Fixture Maker"},
        {WiaDeviceClass::scanner, "bad-name", oversized_name, "Fixture Maker"},
    });
    check(result.devices.size() == 1U && result.issue_codes.size() == 3U,
          "malformed discovery records were not isolated");
    check(result.issue_codes[0] == "invalid_device_id" &&
              result.issue_codes[1] == "duplicate_device_id" &&
              result.issue_codes[2] == "invalid_public_metadata",
          "sanitized discovery issue codes changed");
}

void test_wia_discovery_invalidates_stale_selection() {
    WiaDiscoveryModel discovery;
    const auto initial = discovery.refresh({
        {WiaDeviceClass::scanner, "first-private-id", "First Scanner", "Fixture Maker"},
    });
    const auto refreshed = discovery.refresh({
        {WiaDeviceClass::scanner, "second-private-id", "Second Scanner", "Fixture Maker"},
    });
    expect_scanner_error(
        [&] { (void)discovery.resolve_for_connection(initial.devices.front().opaque_id, initial.generation); },
        "stale WIA selection remained usable");
    check(discovery.resolve_for_connection(refreshed.devices.front().opaque_id, refreshed.generation) ==
              "second-private-id",
          "refreshed WIA selection could not be resolved");
    expect_scanner_error([&] { (void)discovery.resolve_for_connection("wia-device-9999", refreshed.generation); },
                         "unknown WIA selection was accepted");
}

void test_wia_discovery_limit_clears_prior_selection() {
    WiaDiscoveryModel discovery;
    const auto initial = discovery.refresh({
        {WiaDeviceClass::scanner, "initial-private-id", "Initial Scanner", "Fixture Maker"},
    });
    std::vector<WiaDiscoveredDevice> excessive(1025U);
    const auto limited = discovery.refresh(excessive);
    check(limited.devices.empty() && limited.issue_codes == std::vector<std::string>{"discovery_limit"},
          "oversized WIA discovery result was accepted");
    expect_scanner_error(
        [&] { (void)discovery.resolve_for_connection(initial.devices.front().opaque_id, limited.generation); },
        "discovery-limit refresh retained a prior raw identifier");
}

void test_wia_worker_lifecycle_and_cancellation() {
    WiaWorkerModel worker;
    check(worker.snapshot().state == WiaWorkerState::stopped, "WIA worker did not start stopped");
    expect_scanner_error([&] { worker.begin(WiaWorkerOperation::refresh); },
                         "stopped WIA worker accepted an operation");
    worker.start();
    expect_scanner_error([&] { worker.start(); }, "WIA worker started twice");
    expect_scanner_error([&] { worker.begin(WiaWorkerOperation::none); },
                         "WIA worker accepted an empty operation");
    check(worker.snapshot().state == WiaWorkerState::idle,
          "invalid WIA operation changed worker state");
    worker.begin(WiaWorkerOperation::connect);
    check(worker.snapshot().state == WiaWorkerState::connecting, "WIA connect state changed");
    worker.complete();
    worker.begin(WiaWorkerOperation::scan);
    check(worker.snapshot().state == WiaWorkerState::scanning, "WIA scan state changed");
    worker.complete();
    worker.begin(WiaWorkerOperation::refresh);
    check(worker.snapshot().state == WiaWorkerState::refreshing, "WIA refresh state changed");
    expect_scanner_error([&] { worker.begin(WiaWorkerOperation::scan); },
                         "WIA worker accepted concurrent operations");
    worker.request_cancel();
    check(worker.snapshot().state == WiaWorkerState::cancelling && worker.snapshot().cancel_requested,
          "WIA cancellation was not represented as value-only state");
    expect_scanner_error([&] { worker.shutdown(); },
                         "WIA worker shut down before cancellation completed");
    worker.complete();
    expect_scanner_error([&] { worker.request_cancel(); },
                         "idle WIA worker accepted cancellation");
    worker.shutdown();
    check(worker.snapshot().state == WiaWorkerState::stopped &&
              worker.snapshot().operation == WiaWorkerOperation::none,
          "WIA worker shutdown did not clear operation state");
    worker.shutdown();
}

struct FakeApartmentState {
    bool initialize_succeeds{true};
    bool initialized{};
    bool uninitialized{};
    std::thread::id initialize_thread;
    std::thread::id uninitialize_thread;
};

class FakeApartment final : public IComApartment {
public:
    explicit FakeApartment(std::shared_ptr<FakeApartmentState> state) : state_(std::move(state)) {}

    bool initialize() noexcept override {
        state_->initialize_thread = std::this_thread::get_id();
        state_->initialized = state_->initialize_succeeds;
        return state_->initialize_succeeds;
    }

    void uninitialize() noexcept override {
        state_->uninitialize_thread = std::this_thread::get_id();
        state_->uninitialized = true;
    }

private:
    std::shared_ptr<FakeApartmentState> state_;
};

struct FakeWorkerBackendState {
    std::mutex mutex;
    std::condition_variable condition;
    bool opened{};
    bool closed{};
    bool scan_entered{};
    bool throw_on_connect{};
    std::thread::id open_thread;
    std::thread::id close_thread;
    std::vector<std::thread::id> execute_threads;
    std::vector<WiaWorkerOperation> operations;
};

class FakeWorkerBackend final : public IWiaWorkerBackend {
public:
    explicit FakeWorkerBackend(std::shared_ptr<FakeWorkerBackendState> state) : state_(std::move(state)) {}

    void open() override {
        std::lock_guard lock(state_->mutex);
        state_->opened = true;
        state_->open_thread = std::this_thread::get_id();
    }

    WiaWorkerReply execute(
        const WiaWorkerRequest& request,
        const std::atomic_bool& cancel_requested) override {
        {
            std::lock_guard lock(state_->mutex);
            state_->execute_threads.push_back(std::this_thread::get_id());
            state_->operations.push_back(request.operation);
            if (request.operation == WiaWorkerOperation::scan) state_->scan_entered = true;
        }
        state_->condition.notify_all();
        if (request.operation == WiaWorkerOperation::connect && state_->throw_on_connect) {
            throw std::runtime_error("private driver detail must be sanitized");
        }
        if (request.operation == WiaWorkerOperation::scan) {
            while (!cancel_requested.load()) std::this_thread::yield();
        }

        WiaWorkerReply reply;
        reply.success = true;
        if (request.operation == WiaWorkerOperation::refresh) {
            reply.discovery.generation = 7U;
            reply.discovery.devices.push_back({"wia-device-0001", "Synthetic Scanner", "Fixture Maker"});
        }
        return reply;
    }

    void close() noexcept override {
        std::lock_guard lock(state_->mutex);
        state_->closed = true;
        state_->close_thread = std::this_thread::get_id();
    }

private:
    std::shared_ptr<FakeWorkerBackendState> state_;
};

void test_wia_com_worker_thread_queue_and_sanitization() {
    check(static_cast<bool>(make_windows_wia2_backend()),
          "WIA 2.0 backend factory returned no backend");
    const auto apartment_state = std::make_shared<FakeApartmentState>();
    const auto backend_state = std::make_shared<FakeWorkerBackendState>();
    auto backend = std::make_shared<FakeWorkerBackend>(backend_state);
    WiaComWorker worker(backend, std::make_unique<FakeApartment>(apartment_state));

    check(worker.snapshot().state == WiaWorkerState::stopped,
          "WIA COM worker did not begin stopped");
    worker.start();
    check(worker.snapshot().state == WiaWorkerState::idle,
          "WIA COM worker did not become idle after startup");
    expect_scanner_error([&] { worker.request_cancel(); },
                         "idle WIA COM worker accepted cancellation");
    expect_scanner_error(
        [&] { (void)worker.submit({}); },
        "WIA COM worker accepted an empty request");
    WiaWorkerRequest incomplete_connect;
    incomplete_connect.request_id = 40U;
    incomplete_connect.operation = WiaWorkerOperation::connect;
    expect_scanner_error(
        [&] { (void)worker.submit(incomplete_connect); },
        "WIA COM worker accepted a missing device selection");

    WiaWorkerRequest refresh;
    refresh.request_id = 41U;
    refresh.operation = WiaWorkerOperation::refresh;
    WiaWorkerRequest connect;
    connect.request_id = 42U;
    connect.operation = WiaWorkerOperation::connect;
    connect.opaque_device_id = "wia-device-0001";
    connect.discovery_generation = 7U;
    auto refresh_future = worker.submit(refresh);
    auto connect_future = worker.submit(connect);
    const auto refresh_reply = refresh_future.get();
    const auto connect_reply = connect_future.get();
    check(refresh_reply.success && refresh_reply.request_id == 41U &&
              refresh_reply.discovery.devices.size() == 1U,
          "WIA COM refresh reply lost value-only data");
    check(connect_reply.success && connect_reply.request_id == 42U,
          "WIA COM connect reply was not correlated");

    WiaWorkerRequest scan;
    scan.request_id = 43U;
    scan.operation = WiaWorkerOperation::scan;
    scan.opaque_device_id = "wia-device-0001";
    scan.discovery_generation = 7U;
    scan.scan_request = ScanRequest{};
    auto scan_future = worker.submit(scan);
    {
        std::unique_lock lock(backend_state->mutex);
        check(backend_state->condition.wait_for(
                  lock, std::chrono::seconds(2), [&] { return backend_state->scan_entered; }),
              "fake WIA scan did not enter the worker thread");
    }
    worker.request_cancel();
    const auto cancelled = scan_future.get();
    check(!cancelled.success && cancelled.issue_code == "cancelled",
          "WIA COM cancellation was not sanitized");
    check(worker.snapshot().state == WiaWorkerState::idle,
          "WIA COM worker did not return to idle after cancellation");
    worker.shutdown();

    check(apartment_state->initialized && apartment_state->uninitialized,
          "WIA COM apartment lifecycle was incomplete");
    check(backend_state->opened && backend_state->closed,
          "WIA backend lifecycle was incomplete");
    check(apartment_state->initialize_thread == apartment_state->uninitialize_thread &&
              apartment_state->initialize_thread == backend_state->open_thread &&
              apartment_state->initialize_thread == backend_state->close_thread,
          "WIA COM resources crossed worker threads");
    check(backend_state->operations == std::vector<WiaWorkerOperation>{
                                           WiaWorkerOperation::refresh,
                                           WiaWorkerOperation::connect,
                                           WiaWorkerOperation::scan},
          "WIA COM request queue did not preserve order");
    check(std::all_of(
              backend_state->execute_threads.begin(), backend_state->execute_threads.end(),
              [&](const std::thread::id id) { return id == apartment_state->initialize_thread; }),
          "WIA backend request executed outside the COM worker thread");

    const auto failing_backend_state = std::make_shared<FakeWorkerBackendState>();
    failing_backend_state->throw_on_connect = true;
    WiaComWorker failing_worker(
        std::make_shared<FakeWorkerBackend>(failing_backend_state),
        std::make_unique<FakeApartment>(std::make_shared<FakeApartmentState>()));
    failing_worker.start();
    const auto sanitized = failing_worker.submit(connect).get();
    check(!sanitized.success && sanitized.issue_code == "driver_failure",
          "WIA backend exception exposed an unstable error");
    failing_worker.shutdown();

    const auto shutdown_backend_state = std::make_shared<FakeWorkerBackendState>();
    WiaComWorker shutdown_worker(
        std::make_shared<FakeWorkerBackend>(shutdown_backend_state),
        std::make_unique<FakeApartment>(std::make_shared<FakeApartmentState>()));
    shutdown_worker.start();
    scan.request_id = 44U;
    auto active_future = shutdown_worker.submit(scan);
    refresh.request_id = 45U;
    auto queued_future = shutdown_worker.submit(refresh);
    {
        std::unique_lock lock(shutdown_backend_state->mutex);
        check(shutdown_backend_state->condition.wait_for(
                  lock, std::chrono::seconds(2), [&] { return shutdown_backend_state->scan_entered; }),
              "shutdown fixture did not enter active WIA work");
    }
    shutdown_worker.shutdown();
    check(active_future.get().issue_code == "cancelled" && queued_future.get().issue_code == "cancelled",
          "WIA shutdown did not cancel active and queued work");
    expect_scanner_error([&] { (void)shutdown_worker.submit(refresh); },
                         "stopped WIA COM worker accepted work");

    const auto rejected_apartment = std::make_shared<FakeApartmentState>();
    rejected_apartment->initialize_succeeds = false;
    WiaComWorker rejected_worker(
        std::make_shared<FakeWorkerBackend>(std::make_shared<FakeWorkerBackendState>()),
        std::make_unique<FakeApartment>(rejected_apartment));
    expect_scanner_error([&] { rejected_worker.start(); },
                         "WIA COM worker accepted apartment initialization failure");
}

void emit_synthetic_pdf(
    const std::filesystem::path& fixtures,
    const std::filesystem::path& output_file) {
    if (std::filesystem::exists(output_file)) throw std::runtime_error("Synthetic PDF destination already exists");
    std::filesystem::create_directories(output_file.parent_path());
    const auto work = unique_test_root();
    std::filesystem::create_directories(work);
    try {
        MockScanner scanner(fixtures);
        ScanRequest request;
        request.source = SourceType::adf_simplex;
        request.max_pages = 2U;
        const auto frames = scanner.scan(request);
        auto session = ScanSession::create(
            work, "render-fixture", "2026-08-26T03:30:00Z", scanner.provider_id(), scanner.device_id());
        (void)session.add_page(frames[0]);
        (void)session.add_page(frames[1]);
        session.export_multipage_pdf(output_file);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(work, ignored);
        throw;
    }
    std::error_code error;
    std::filesystem::remove_all(work, error);
    if (error) throw std::runtime_error("Synthetic PDF work cleanup failed");
}

}  // namespace

int main(const int argc, char** argv) {
    if (argc == 4 && std::string(argv[1]) == "--emit-pdf") {
        try {
            emit_synthetic_pdf(std::filesystem::path(argv[2]), std::filesystem::path(argv[3]));
            std::cout << "PASS: synthetic PDF emitted for local renderer validation\n";
            return 0;
        } catch (const std::exception& error) {
            std::cerr << "FAIL: " << error.what() << '\n';
            return 1;
        }
    }
    if (argc != 2) {
        std::cerr << "Expected sanitized fixture directory.\n";
        return 2;
    }
    try {
        const std::filesystem::path fixtures(argv[1]);
        test_backend_policy_is_fail_closed();
        test_wsd_request_and_job_models_fail_closed();
        test_wsd_soap_codec_is_bounded(fixtures);
        test_wsd_configuration_status_and_fault_codec(fixtures);
        test_wsd_discovery_metadata_model_is_injectable_and_private(fixtures);
        test_wsd_http_transport_is_bounded_and_injectable();
        test_wsd_job_codec_and_mtom_are_bounded();
        test_capabilities_and_validation(fixtures);
        test_mock_batch_is_deterministic(fixtures);
        test_session_operations_and_recovery(fixtures);
        test_manifest_traversal_fails_closed(fixtures);
        test_fixture_exports_are_ordered_and_collision_safe(fixtures);
        test_empty_and_fully_excluded_sessions_do_not_export(fixtures);
        test_windows_native_image_exports(fixtures);
        test_unicode_and_invalid_export_paths(fixtures);
        test_larger_session_order_and_persistence(fixtures);
        test_wia_flatbed_and_feeder_capability_mapping();
        test_wia_duplex_and_malformed_driver_models();
        test_wia_readback_accepts_only_reported_coercion();
        test_wia_property_writes_are_prevalidated();
        test_blocked_stage_paths_preserve_committed_state(fixtures);
        test_wia_transfer_success_and_short_feeder_batch();
        test_wia_transfer_cancel_and_device_failures();
        test_wia_transfer_limits_fail_closed();
        test_wia_transfer_protocol_order_is_enforced();
        test_wia_discovery_filters_and_hides_raw_ids();
        test_wia_discovery_rejects_malformed_and_duplicate_records();
        test_wia_discovery_invalidates_stale_selection();
        test_wia_discovery_limit_clears_prior_selection();
        test_wia_worker_lifecycle_and_cancellation();
        test_wia_com_worker_thread_queue_and_sanitization();
        test_managed_paths_reject_relative_and_unc_roots(fixtures);
        test_impossible_frame_dimensions_fail_before_publication(fixtures);
        test_crop_and_rotation_apply_only_to_derivatives(fixtures);
        test_tone_validation_and_manifest_migration(fixtures);
        std::cout << "PASS: 35 offline mock/session/export/backend-policy/WIA/WSD-model-codec-discovery-HTTP-and-MTOM test groups; network=false; hardware=false\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
