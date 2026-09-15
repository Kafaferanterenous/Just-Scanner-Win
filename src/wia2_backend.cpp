#include "wia2_backend.h"

#include <limits>
#include <string>
#include <vector>

#ifdef _WIN32
#include <objbase.h>
#include <propidl.h>
#include <sti.h>
#include <wia.h>
#include <windows.h>
#endif

namespace just_scanner {
namespace {

#ifdef _WIN32

template <typename Interface>
void release_interface(Interface*& value) noexcept {
    if (value) value->Release();
    value = nullptr;
}

std::string utf8_from_bstr(const BSTR value) {
    if (!value) return {};
    const UINT length = SysStringLen(value);
    if (length == 0U || length > 4096U || length > static_cast<UINT>(std::numeric_limits<int>::max())) {
        return {};
    }
    const int required = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value, static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string converted(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, value, static_cast<int>(length), converted.data(), required,
            nullptr, nullptr) != required) {
        return {};
    }
    return converted;
}

class WindowsWia2Backend final : public IWiaWorkerBackend {
public:
    ~WindowsWia2Backend() override { close(); }

    void open() override {
        if (manager_) throw ScannerError("WIA 2.0 backend is already open");
        const HRESULT result = CoCreateInstance(
            CLSID_WiaDevMgr2, nullptr, CLSCTX_LOCAL_SERVER, IID_IWiaDevMgr2,
            reinterpret_cast<void**>(&manager_));
        if (FAILED(result) || !manager_) {
            release_interface(manager_);
            throw ScannerError("WIA 2.0 device manager is unavailable");
        }
    }

    WiaWorkerReply execute(
        const WiaWorkerRequest& request,
        const std::atomic_bool& cancel_requested) override {
        if (!manager_) throw ScannerError("WIA 2.0 backend is not open");
        if (request.operation != WiaWorkerOperation::refresh) {
            WiaWorkerReply reply;
            reply.issue_code = "unsupported_request";
            return reply;
        }
        if (cancel_requested.load()) {
            WiaWorkerReply reply;
            reply.issue_code = "cancelled";
            return reply;
        }

        IEnumWIA_DEV_INFO* enumerator = nullptr;
        const HRESULT enum_result = manager_->EnumDeviceInfo(WIA_DEVINFO_ENUM_LOCAL, &enumerator);
        if (FAILED(enum_result) || !enumerator) {
            release_interface(enumerator);
            throw ScannerError("WIA 2.0 discovery failed");
        }

        std::vector<WiaDiscoveredDevice> discovered;
        try {
            for (std::size_t ordinal = 0U; ordinal <= 1024U; ++ordinal) {
                if (cancel_requested.load()) break;
                IWiaPropertyStorage* properties = nullptr;
                ULONG fetched = 0U;
                const HRESULT next_result = enumerator->Next(1U, &properties, &fetched);
                if (next_result == S_FALSE || fetched == 0U) {
                    release_interface(properties);
                    break;
                }
                if (FAILED(next_result) || !properties) {
                    release_interface(properties);
                    throw ScannerError("WIA 2.0 discovery enumeration failed");
                }

                PROPSPEC specs[3]{};
                PROPVARIANT values[3]{};
                const PROPID property_ids[3]{WIA_DIP_DEV_ID, WIA_DIP_DEV_NAME, WIA_DIP_VEND_DESC};
                for (std::size_t index = 0U; index < 3U; ++index) {
                    specs[index].ulKind = PRSPEC_PROPID;
                    specs[index].propid = property_ids[index];
                    PropVariantInit(&values[index]);
                }
                const HRESULT read_result = properties->ReadMultiple(3U, specs, values);
                release_interface(properties);

                WiaDiscoveredDevice candidate;
                candidate.device_class = WiaDeviceClass::scanner;
                if (SUCCEEDED(read_result)) {
                    if (values[0].vt == VT_BSTR) candidate.raw_device_id = utf8_from_bstr(values[0].bstrVal);
                    if (values[1].vt == VT_BSTR) candidate.display_name = utf8_from_bstr(values[1].bstrVal);
                    if (values[2].vt == VT_BSTR) candidate.manufacturer = utf8_from_bstr(values[2].bstrVal);
                }
                for (auto& value : values) PropVariantClear(&value);
                discovered.push_back(std::move(candidate));
            }
        } catch (...) {
            release_interface(enumerator);
            throw;
        }
        release_interface(enumerator);

        if (cancel_requested.load()) {
            WiaWorkerReply reply;
            reply.issue_code = "cancelled";
            return reply;
        }
        WiaWorkerReply reply;
        reply.discovery = discovery_.refresh(discovered);
        reply.success = true;
        return reply;
    }

    void close() noexcept override {
        discovery_ = WiaDiscoveryModel{};
        release_interface(manager_);
    }

private:
    IWiaDevMgr2* manager_{};
    WiaDiscoveryModel discovery_;
};

#else

class WindowsWia2Backend final : public IWiaWorkerBackend {
public:
    void open() override { throw ScannerError("WIA 2.0 is unavailable on this platform"); }
    WiaWorkerReply execute(const WiaWorkerRequest&, const std::atomic_bool&) override {
        throw ScannerError("WIA 2.0 is unavailable on this platform");
    }
    void close() noexcept override {}
};

#endif

}  // namespace

std::shared_ptr<IWiaWorkerBackend> make_windows_wia2_backend() {
    return std::make_shared<WindowsWia2Backend>();
}

}  // namespace just_scanner
