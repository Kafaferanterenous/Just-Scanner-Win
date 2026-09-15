#include "scanner_core.h"
#include "wia2_backend.h"
#include "wia_com_worker.h"

#include <windows.h>
#include <commctrl.h>
#include <shobjidl.h>

#include <algorithm>
#include <cmath>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

using just_scanner::CropRect;
using just_scanner::ImageExportFormat;
using just_scanner::MockScanner;
using just_scanner::ScanFrame;
using just_scanner::ScanRequest;
using just_scanner::ScanSession;
using just_scanner::SourceType;

constexpr wchar_t kWindowClass[] = L"JustScannerMockWindow";
constexpr int kBaseWidth = 1000;
constexpr int kBaseHeight = 690;
constexpr int kModeCombo = 1001;
constexpr int kDpiCombo = 1002;
constexpr int kPreScanButton = 1003;
constexpr int kScanButton = 1004;
constexpr int kPageList = 1005;
constexpr int kRotateButton = 1006;
constexpr int kIncludeButton = 1007;
constexpr int kFormatCombo = 1008;
constexpr int kFolderButton = 1009;
constexpr int kSaveButton = 1010;
constexpr int kScannerCombo = 1011;
constexpr int kRefreshScannersButton = 1012;
constexpr UINT_PTR kDiscoveryTimer = 1U;

struct ChildLayout {
    HWND window{};
    RECT initial{};
    bool anchor_right{};
    bool stretch_width{};
};

struct GrayBitmap {
    std::uint32_t width{};
    std::uint32_t height{};
    std::vector<std::uint8_t> pixels;
};

struct AppState {
    std::filesystem::path project_root;
    std::filesystem::path fixture_root;
    std::filesystem::path output_directory;
    std::unique_ptr<MockScanner> scanner;
    std::optional<ScanSession> session;
    std::optional<ScanFrame> prescan_frame;
    std::optional<CropRect> selected_crop;
    std::unique_ptr<just_scanner::WiaComWorker> wia_worker;
    std::optional<std::future<just_scanner::WiaWorkerReply>> discovery_future;
    std::vector<ChildLayout> child_layouts;
    int initial_client_width{};
    int initial_client_height{};
    double scale{1.0};
    RECT preview_image_rect{};
    POINT drag_start{};
    POINT drag_current{};
    bool dragging{};
    HWND mode_combo{};
    HWND scanner_combo{};
    HWND dpi_combo{};
    HWND format_combo{};
    HWND page_list{};
    HWND output_label{};
    HWND status{};
    HFONT title_font{};
    HFONT heading_font{};
    HFONT body_font{};
    HBRUSH background_brush{};
    HBRUSH card_brush{};
};

int scaled(const AppState& state, const int value) {
    return static_cast<int>(std::lround(static_cast<double>(value) * state.scale));
}

RECT scaled_rect(const AppState& state, const int left, const int top, const int right, const int bottom) {
    return RECT{scaled(state, left), scaled(state, top), scaled(state, right), scaled(state, bottom)};
}

std::filesystem::path executable_directory() {
    std::wstring buffer(32768U, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0U || length >= buffer.size()) return {};
    buffer.resize(length);
    return std::filesystem::path(buffer).parent_path();
}

std::filesystem::path find_project_root() {
    auto candidate = executable_directory();
    for (int depth = 0; depth < 3 && !candidate.empty(); ++depth) {
        if (std::filesystem::exists(candidate / "fixtures" / "sanitized")) return candidate;
        candidate = candidate.parent_path();
    }
    return {};
}

std::string utc_timestamp() {
    SYSTEMTIME now{};
    GetSystemTime(&now);
    char text[32]{};
    std::snprintf(text, sizeof(text), "%04u-%02u-%02uT%02u:%02u:%02uZ", now.wYear, now.wMonth,
                  now.wDay, now.wHour, now.wMinute, now.wSecond);
    return text;
}

double fit_aware_scale() {
    RECT work{};
    if (!SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0)) return 1.0;
    constexpr DWORD window_style = WS_OVERLAPPEDWINDOW;
    RECT frame{0, 0, 100, 100};
    AdjustWindowRectEx(&frame, window_style, FALSE, 0);
    const LONG frame_overhead = (frame.bottom - frame.top) - 100L;
    const LONG available_client_height = std::max(
        1L, work.bottom - work.top - 24L - frame_overhead);
    return std::clamp(static_cast<double>(available_client_height) / kBaseHeight, 0.80, 1.15);
}

void set_status(AppState& state, const std::wstring& message) {
    SetWindowTextW(state.status, message.c_str());
}

void apply_font(const HWND control, const HFONT font) {
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
}

HWND add_label(HWND parent, AppState& state, const wchar_t* text, const int x, const int y,
               const int width, const int height, const bool heading = false, const DWORD style = 0) {
    HWND label = CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE | style, scaled(state, x),
        scaled(state, y), scaled(state, width), scaled(state, height), parent, nullptr,
        GetModuleHandleW(nullptr), nullptr);
    apply_font(label, heading ? state.heading_font : state.body_font);
    return label;
}

HWND add_button(HWND parent, AppState& state, const wchar_t* text, const int id, const int x,
                const int y, const int width, const int height, const bool prominent = false) {
    HWND button = CreateWindowExW(0, L"BUTTON", text,
        WS_CHILD | WS_VISIBLE | (prominent ? BS_DEFPUSHBUTTON : 0), scaled(state, x), scaled(state, y),
        scaled(state, width), scaled(state, height), parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
    apply_font(button, prominent ? state.heading_font : state.body_font);
    return button;
}

BOOL CALLBACK capture_child(HWND child, LPARAM context) {
    auto& state = *reinterpret_cast<AppState*>(context);
    RECT rect{};
    GetWindowRect(child, &rect);
    POINT top_left{rect.left, rect.top};
    POINT bottom_right{rect.right, rect.bottom};
    ScreenToClient(GetParent(child), &top_left);
    ScreenToClient(GetParent(child), &bottom_right);
    rect = RECT{top_left.x, top_left.y, bottom_right.x, bottom_right.y};
    const bool is_status = child == state.status;
    state.child_layouts.push_back(ChildLayout{
        child, rect, rect.left >= scaled(state, 700), is_status});
    return TRUE;
}

void capture_layout(HWND window, AppState& state) {
    RECT client{};
    GetClientRect(window, &client);
    state.initial_client_width = client.right;
    state.initial_client_height = client.bottom;
    state.child_layouts.clear();
    EnumChildWindows(window, capture_child, reinterpret_cast<LPARAM>(&state));
}

void arrange_children(HWND window, AppState& state) {
    if (state.child_layouts.empty()) return;
    RECT client{};
    GetClientRect(window, &client);
    const int horizontal_growth = client.right - state.initial_client_width;
    for (const auto& layout : state.child_layouts) {
        int left = layout.initial.left;
        int width = layout.initial.right - layout.initial.left;
        if (layout.anchor_right) left += horizontal_growth;
        if (layout.stretch_width) width = std::max(scaled(state, 300), width + horizontal_growth);
        MoveWindow(layout.window, left, layout.initial.top, width,
                   layout.initial.bottom - layout.initial.top, TRUE);
    }
    InvalidateRect(window, nullptr, FALSE);
}

std::wstring widen_utf8(const std::string& value) {
    if (value.empty()) return {};
    const int required = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (required <= 0) return {};
    std::wstring converted(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                           static_cast<int>(value.size()), converted.data(), required) != required) {
        return {};
    }
    return converted;
}

void refresh_live_scanners(HWND window, AppState& state) {
    if (state.discovery_future) {
        set_status(state, L"Scanner discovery is already in progress.");
        return;
    }
    try {
        if (!state.wia_worker) {
            state.wia_worker = std::make_unique<just_scanner::WiaComWorker>(
                just_scanner::make_windows_wia2_backend());
            state.wia_worker->start();
        }
        just_scanner::WiaWorkerRequest request;
        request.request_id = GetTickCount64();
        request.operation = just_scanner::WiaWorkerOperation::refresh;
        state.discovery_future.emplace(state.wia_worker->submit(std::move(request)));
        SendMessageW(state.scanner_combo, CB_RESETCONTENT, 0, 0);
        SendMessageW(state.scanner_combo, CB_ADDSTRING, 0,
                     reinterpret_cast<LPARAM>(L"Searching for accessible scanners..."));
        SendMessageW(state.scanner_combo, CB_SETCURSEL, 0, 0);
        SetTimer(window, kDiscoveryTimer, 100U, nullptr);
        set_status(state, L"Refreshing locally accessible WIA scanners...");
    } catch (const std::exception&) {
        set_status(state, L"Live scanner discovery could not be started.");
    }
}

void poll_live_scanners(HWND window, AppState& state) {
    if (!state.discovery_future ||
        state.discovery_future->wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
        return;
    }
    KillTimer(window, kDiscoveryTimer);
    try {
        const auto reply = state.discovery_future->get();
        state.discovery_future.reset();
        SendMessageW(state.scanner_combo, CB_RESETCONTENT, 0, 0);
        if (!reply.success || reply.discovery.devices.empty()) {
            SendMessageW(state.scanner_combo, CB_ADDSTRING, 0,
                         reinterpret_cast<LPARAM>(L"No accessible WIA scanners found"));
            SendMessageW(state.scanner_combo, CB_SETCURSEL, 0, 0);
            set_status(state, reply.success
                ? L"No locally accessible WIA scanners are currently available."
                : L"Live scanner discovery failed safely.");
            return;
        }
        for (const auto& device : reply.discovery.devices) {
            std::wstring label = widen_utf8(device.display_name);
            const std::wstring maker = widen_utf8(device.manufacturer);
            if (!maker.empty() && label.find(maker) == std::wstring::npos) {
                label += L" - " + maker;
            }
            if (label.empty()) label = L"Unnamed WIA scanner";
            SendMessageW(state.scanner_combo, CB_ADDSTRING, 0,
                         reinterpret_cast<LPARAM>(label.c_str()));
        }
        SendMessageW(state.scanner_combo, CB_SETCURSEL, 0, 0);
        std::wostringstream message;
        message << L"Found " << reply.discovery.devices.size() << L" accessible local WIA scanner"
                << (reply.discovery.devices.size() == 1U ? L"." : L"s.");
        set_status(state, message.str());
    } catch (const std::exception&) {
        state.discovery_future.reset();
        set_status(state, L"Live scanner discovery failed safely.");
    }
}

std::filesystem::path new_session_root(const AppState& state) {
    auto base = state.project_root.parent_path() / "Temp" / "JustScannerMockSessions";
    if (state.project_root.empty()) base = std::filesystem::temp_directory_path() / "JustScannerMockSessions";
    return base / ("session-" + std::to_string(GetTickCount64()));
}

ScanRequest current_request(const AppState& state, const bool batch) {
    ScanRequest request;
    const LRESULT mode = SendMessageW(state.mode_combo, CB_GETCURSEL, 0, 0);
    request.source = mode == 2 ? SourceType::adf_simplex : SourceType::flatbed;
    request.max_pages = batch && mode == 2 ? 2U : 1U;
    const LRESULT dpi_index = SendMessageW(state.dpi_combo, CB_GETCURSEL, 0, 0);
    request.dpi = dpi_index == 0 ? 150U : (dpi_index == 2 ? 600U : 300U);
    return request;
}

bool is_adf_mode(const AppState& state) {
    return SendMessageW(state.mode_combo, CB_GETCURSEL, 0, 0) == 2;
}

std::optional<std::string> next_pgm_token(const std::string& text, std::size_t& cursor) {
    while (cursor < text.size()) {
        const unsigned char value = static_cast<unsigned char>(text[cursor]);
        if (value == '#') {
            while (cursor < text.size() && text[cursor] != '\n') ++cursor;
        } else if (value == ' ' || value == '\t' || value == '\r' || value == '\n') {
            ++cursor;
        } else {
            break;
        }
    }
    if (cursor >= text.size()) return std::nullopt;
    const std::size_t start = cursor;
    while (cursor < text.size()) {
        const unsigned char value = static_cast<unsigned char>(text[cursor]);
        if (value == '#' || value == ' ' || value == '\t' || value == '\r' || value == '\n') break;
        ++cursor;
    }
    return text.substr(start, cursor - start);
}

std::optional<GrayBitmap> decode_pgm(const ScanFrame& frame) {
    try {
        const std::string text(frame.bytes.begin(), frame.bytes.end());
        std::size_t cursor = 0;
        const auto magic = next_pgm_token(text, cursor);
        const auto width_token = next_pgm_token(text, cursor);
        const auto height_token = next_pgm_token(text, cursor);
        const auto maximum_token = next_pgm_token(text, cursor);
        if (!magic || *magic != "P2" || !width_token || !height_token || !maximum_token) return std::nullopt;
        GrayBitmap bitmap;
        bitmap.width = static_cast<std::uint32_t>(std::stoul(*width_token));
        bitmap.height = static_cast<std::uint32_t>(std::stoul(*height_token));
        const unsigned long maximum = std::stoul(*maximum_token);
        if (bitmap.width == 0U || bitmap.height == 0U || maximum == 0UL || maximum > 65535UL) return std::nullopt;
        const std::size_t count = static_cast<std::size_t>(bitmap.width) * bitmap.height;
        bitmap.pixels.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            const auto token = next_pgm_token(text, cursor);
            if (!token) return std::nullopt;
            const unsigned long sample = std::stoul(*token);
            if (sample > maximum) return std::nullopt;
            bitmap.pixels.push_back(static_cast<std::uint8_t>((sample * 255UL) / maximum));
        }
        return bitmap;
    } catch (...) {
        return std::nullopt;
    }
}

void refresh_page_list(HWND window, AppState& state) {
    SendMessageW(state.page_list, LB_RESETCONTENT, 0, 0);
    if (!state.session) {
        InvalidateRect(window, nullptr, FALSE);
        return;
    }
    for (std::size_t index = 0; index < state.session->pages().size(); ++index) {
        const auto& page = state.session->pages()[index];
        std::wostringstream label;
        label << L"Page " << (index + 1U) << L"  " << page.width << L" x " << page.height
              << L"  " << page.rotation << L" deg";
        if (page.crop) label << L"  [cropped]";
        if (!page.included) label << L"  [excluded]";
        const std::wstring value = label.str();
        SendMessageW(state.page_list, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(value.c_str()));
    }
    if (!state.session->pages().empty()) {
        SendMessageW(state.page_list, LB_SETCURSEL, state.session->pages().size() - 1U, 0);
    }
    InvalidateRect(window, nullptr, FALSE);
}

std::optional<std::size_t> selected_page(const AppState& state) {
    if (!state.session) return std::nullopt;
    const LRESULT selected = SendMessageW(state.page_list, LB_GETCURSEL, 0, 0);
    if (selected == LB_ERR || static_cast<std::size_t>(selected) >= state.session->pages().size()) return std::nullopt;
    return static_cast<std::size_t>(selected);
}

void prescan(HWND window, AppState& state) {
    try {
        if (!state.scanner) state.scanner = std::make_unique<MockScanner>(state.fixture_root);
        const auto frames = state.scanner->scan(current_request(state, false));
        if (frames.empty()) throw std::runtime_error("empty synthetic pre-scan");
        state.prescan_frame = frames.front();
        state.selected_crop = CropRect{0U, 0U, frames.front().width, frames.front().height};
        InvalidateRect(window, nullptr, FALSE);
        set_status(state, is_adf_mode(state)
            ? L"Synthetic ADF pre-scan ready. ADF pages scan at full size; PDF is the default."
            : L"Synthetic pre-scan ready. Drag over the preview to choose the scan area.");
    } catch (const std::exception&) {
        set_status(state, L"Pre-scan failed. No hardware was accessed.");
        MessageBoxW(window, L"The synthetic pre-scan could not be created.", L"Just Scanner", MB_OK | MB_ICONERROR);
    }
}

void scan_selected_area(HWND window, AppState& state) {
    if (!state.prescan_frame || !state.selected_crop) {
        set_status(state, L"Run Pre-scan first, then choose the area before scanning.");
        return;
    }
    try {
        if (!state.scanner) state.scanner = std::make_unique<MockScanner>(state.fixture_root);
        const auto frames = state.scanner->scan(current_request(state, true));
        if (!state.session) {
            const auto root = new_session_root(state);
            state.session.emplace(ScanSession::create(root,
                "mock-session-" + std::to_string(GetTickCount64()), utc_timestamp(),
                state.scanner->provider_id(), state.scanner->device_id()));
        }
        const bool adf = is_adf_mode(state);
        for (const auto& frame : frames) {
            const std::string page_id = state.session->add_page(frame);
            if (!adf) state.session->set_crop(page_id, *state.selected_crop);
        }
        refresh_page_list(window, state);
        std::wostringstream message;
        message << L"Added " << frames.size() << L" synthetic page" << (frames.size() == 1U ? L"" : L"s")
                << (adf ? L" at full size." : L" with a non-destructive area selection.");
        set_status(state, message.str());
    } catch (const std::exception&) {
        set_status(state, L"Synthetic scan failed. No hardware was accessed.");
        MessageBoxW(window, L"The synthetic scan could not be created.", L"Just Scanner", MB_OK | MB_ICONERROR);
    }
}

void rotate_selected(HWND window, AppState& state) {
    const auto index = selected_page(state);
    if (!index) return;
    try {
        const auto page = state.session->pages()[*index];
        state.session->rotate(page.id, static_cast<std::uint16_t>((page.rotation + 90U) % 360U));
        refresh_page_list(window, state);
        SendMessageW(state.page_list, LB_SETCURSEL, *index, 0);
        set_status(state, L"Rotated the selected derivative non-destructively.");
    } catch (const std::exception&) {
        set_status(state, L"The selected page could not be rotated.");
    }
}

void toggle_selected(HWND window, AppState& state) {
    const auto index = selected_page(state);
    if (!index) return;
    try {
        const auto page = state.session->pages()[*index];
        state.session->set_included(page.id, !page.included);
        refresh_page_list(window, state);
        SendMessageW(state.page_list, LB_SETCURSEL, *index, 0);
        set_status(state, page.included ? L"Page excluded from output." : L"Page restored to output.");
    } catch (const std::exception&) {
        set_status(state, L"The selected page could not be updated.");
    }
}

bool choose_output_directory(HWND owner, std::filesystem::path& output) {
    IFileOpenDialog* dialog = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog)))) return false;
    DWORD options = 0;
    HRESULT result = dialog->GetOptions(&options);
    if (SUCCEEDED(result)) result = dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
    if (SUCCEEDED(result)) result = dialog->SetTitle(L"Choose where scans will be saved");
    if (SUCCEEDED(result)) result = dialog->Show(owner);
    IShellItem* item = nullptr;
    if (SUCCEEDED(result)) result = dialog->GetResult(&item);
    PWSTR raw_path = nullptr;
    if (SUCCEEDED(result)) result = item->GetDisplayName(SIGDN_FILESYSPATH, &raw_path);
    if (SUCCEEDED(result) && raw_path) output = raw_path;
    CoTaskMemFree(raw_path);
    if (item) item->Release();
    dialog->Release();
    return SUCCEEDED(result) && !output.empty();
}

void select_output_directory(HWND window, AppState& state) {
    std::filesystem::path selected;
    if (!choose_output_directory(window, selected)) return;
    state.output_directory = std::move(selected);
    SetWindowTextW(state.output_label, state.output_directory.wstring().c_str());
    set_status(state, L"Output folder selected. Choose PDF or JPG, then Save.");
}

void save_output(HWND window, AppState& state) {
    if (!state.session || state.session->pages().empty()) {
        set_status(state, L"Scan at least one synthetic page before saving.");
        return;
    }
    if (state.output_directory.empty()) {
        set_status(state, L"Choose an output folder before saving.");
        return;
    }
    try {
        const std::string stem = "scan-" + std::to_string(GetTickCount64());
        const bool pdf = SendMessageW(state.format_combo, CB_GETCURSEL, 0, 0) == 0;
        if (pdf) {
            const auto output = state.output_directory / (stem + ".pdf");
            state.session->export_multipage_pdf(output);
            set_status(state, L"Saved one PDF containing all included session pages.");
            MessageBoxW(window, output.wstring().c_str(), L"PDF saved", MB_OK | MB_ICONINFORMATION);
        } else {
            const auto outputs = state.session->export_included_wic(
                state.output_directory, stem, ImageExportFormat::jpeg);
            std::wostringstream message;
            message << L"Saved " << outputs.size() << L" separate JPG file"
                    << (outputs.size() == 1U ? L"." : L"s.");
            set_status(state, message.str());
            MessageBoxW(window, state.output_directory.wstring().c_str(), L"JPG files saved",
                        MB_OK | MB_ICONINFORMATION);
        }
    } catch (const std::exception&) {
        set_status(state, L"Save failed; committed session pages remain unchanged.");
        MessageBoxW(window, L"The selected output could not be saved.", L"Just Scanner", MB_OK | MB_ICONERROR);
    }
}

void draw_text(HDC dc, const int x, const int y, const std::wstring_view text) {
    TextOutW(dc, x, y, text.data(), static_cast<int>(text.size()));
}

RECT fit_bitmap_rect(const RECT bounds, const std::uint32_t width, const std::uint32_t height) {
    const int available_width = bounds.right - bounds.left;
    const int available_height = bounds.bottom - bounds.top;
    const double factor = std::min(static_cast<double>(available_width) / width,
                                   static_cast<double>(available_height) / height);
    const int target_width = std::max(1, static_cast<int>(std::lround(width * factor)));
    const int target_height = std::max(1, static_cast<int>(std::lround(height * factor)));
    const int left = bounds.left + (available_width - target_width) / 2;
    const int top = bounds.top + (available_height - target_height) / 2;
    return RECT{left, top, left + target_width, top + target_height};
}

void draw_prescan(HDC dc, AppState& state, const RECT bounds) {
    state.preview_image_rect = bounds;
    if (!state.prescan_frame) {
        SetTextColor(dc, RGB(75, 92, 108));
        SelectObject(dc, state.heading_font);
        draw_text(dc, bounds.left + scaled(state, 100), bounds.top + scaled(state, 150), L"No pre-scan yet");
        SelectObject(dc, state.body_font);
        draw_text(dc, bounds.left + scaled(state, 52), bounds.top + scaled(state, 185),
                  L"Choose settings, then run Pre-scan.");
        return;
    }
    const auto bitmap = decode_pgm(*state.prescan_frame);
    if (!bitmap) return;
    state.preview_image_rect = fit_bitmap_rect(bounds, bitmap->width, bitmap->height);
    std::vector<std::uint32_t> dib(bitmap->pixels.size());
    for (std::size_t index = 0; index < bitmap->pixels.size(); ++index) {
        const std::uint32_t gray = bitmap->pixels[index];
        dib[index] = gray | (gray << 8U) | (gray << 16U);
    }
    BITMAPINFO info{};
    info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = static_cast<LONG>(bitmap->width);
    info.bmiHeader.biHeight = -static_cast<LONG>(bitmap->height);
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    const int target_width = state.preview_image_rect.right - state.preview_image_rect.left;
    const int target_height = state.preview_image_rect.bottom - state.preview_image_rect.top;
    StretchDIBits(dc, state.preview_image_rect.left, state.preview_image_rect.top, target_width, target_height,
        0, 0, static_cast<int>(bitmap->width), static_cast<int>(bitmap->height), dib.data(), &info,
        DIB_RGB_COLORS, SRCCOPY);
    FrameRect(dc, &state.preview_image_rect, static_cast<HBRUSH>(GetStockObject(GRAY_BRUSH)));

    if (state.selected_crop) {
        const CropRect crop = *state.selected_crop;
        const double scale_x = static_cast<double>(target_width) / state.prescan_frame->width;
        const double scale_y = static_cast<double>(target_height) / state.prescan_frame->height;
        RECT selected{
            state.preview_image_rect.left + static_cast<int>(std::lround(crop.x * scale_x)),
            state.preview_image_rect.top + static_cast<int>(std::lround(crop.y * scale_y)),
            state.preview_image_rect.left + static_cast<int>(std::lround((crop.x + crop.width) * scale_x)),
            state.preview_image_rect.top + static_cast<int>(std::lround((crop.y + crop.height) * scale_y))};
        const HBRUSH selection_brush = CreateSolidBrush(RGB(16, 126, 214));
        FrameRect(dc, &selected, selection_brush);
        InflateRect(&selected, -1, -1);
        FrameRect(dc, &selected, selection_brush);
        DeleteObject(selection_brush);
    }
}

void draw_interface(HWND window, AppState& state) {
    PAINTSTRUCT paint{};
    HDC dc = BeginPaint(window, &paint);
    RECT client{};
    GetClientRect(window, &client);
    FillRect(dc, &client, state.background_brush);
    const HBRUSH header = CreateSolidBrush(RGB(26, 61, 91));
    RECT header_rect{0, 0, client.right, scaled(state, 78)};
    FillRect(dc, &header_rect, header);
    DeleteObject(header);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(255, 255, 255));
    SelectObject(dc, state.title_font);
    draw_text(dc, scaled(state, 28), scaled(state, 17), L"JUST SCANNER");
    SelectObject(dc, state.body_font);
    draw_text(dc, scaled(state, 30), scaled(state, 49),
              L"Offline mock workspace - pre-scan, select, scan, save");

    const int margin = scaled(state, 12);
    const int card_top = scaled(state, 88);
    const int card_bottom = std::max(
        card_top + scaled(state, 360), static_cast<int>(client.bottom) - scaled(state, 62));
    RECT left_card{margin, card_top, scaled(state, 280), card_bottom};
    RECT right_card{client.right - scaled(state, 274), card_top, client.right - margin, card_bottom};
    RECT preview_card{left_card.right + margin, card_top, right_card.left - margin, card_bottom};
    FillRect(dc, &left_card, state.card_brush);
    FillRect(dc, &preview_card, state.card_brush);
    FillRect(dc, &right_card, state.card_brush);
    RECT preview{preview_card.left + margin, preview_card.top + scaled(state, 54),
                 preview_card.right - margin, preview_card.bottom - scaled(state, 42)};
    const HBRUSH preview_background = CreateSolidBrush(RGB(226, 232, 238));
    FillRect(dc, &preview, preview_background);
    DeleteObject(preview_background);
    draw_prescan(dc, state, preview);
    SetTextColor(dc, RGB(54, 75, 94));
    SelectObject(dc, state.body_font);
    if (state.prescan_frame) {
        draw_text(dc, preview_card.left + margin, preview_card.bottom - scaled(state, 32),
                  is_adf_mode(state) ? L"ADF scans full pages" : L"Drag on preview to select area");
    }
    EndPaint(window, &paint);
}

POINT client_point(const LPARAM value) {
    return POINT{static_cast<short>(LOWORD(value)), static_cast<short>(HIWORD(value))};
}

POINT clamp_to_rect(POINT point, const RECT& bounds) {
    point.x = std::clamp(point.x, bounds.left, bounds.right);
    point.y = std::clamp(point.y, bounds.top, bounds.bottom);
    return point;
}

bool point_in_rect_inclusive(const RECT& bounds, const POINT point) {
    return point.x >= bounds.left && point.x <= bounds.right &&
           point.y >= bounds.top && point.y <= bounds.bottom;
}

void finish_selection(HWND window, AppState& state) {
    if (!state.prescan_frame) return;
    const RECT& image = state.preview_image_rect;
    const int left = std::min(state.drag_start.x, state.drag_current.x);
    const int right = std::max(state.drag_start.x, state.drag_current.x);
    const int top = std::min(state.drag_start.y, state.drag_current.y);
    const int bottom = std::max(state.drag_start.y, state.drag_current.y);
    if (right - left < 4 || bottom - top < 4) {
        set_status(state, L"Selection was too small; the previous scan area was kept.");
        return;
    }
    const double frame_width = static_cast<double>(state.prescan_frame->width);
    const double frame_height = static_cast<double>(state.prescan_frame->height);
    const double image_width = static_cast<double>(image.right - image.left);
    const double image_height = static_cast<double>(image.bottom - image.top);
    const auto x = static_cast<std::uint32_t>(std::floor((left - image.left) * frame_width / image_width));
    const auto y = static_cast<std::uint32_t>(std::floor((top - image.top) * frame_height / image_height));
    const auto right_pixel = static_cast<std::uint32_t>(
        std::ceil((right - image.left) * frame_width / image_width));
    const auto bottom_pixel = static_cast<std::uint32_t>(
        std::ceil((bottom - image.top) * frame_height / image_height));
    const std::uint32_t safe_right = std::min(right_pixel, state.prescan_frame->width);
    const std::uint32_t safe_bottom = std::min(bottom_pixel, state.prescan_frame->height);
    state.selected_crop = CropRect{x, y, std::max(1U, safe_right - x), std::max(1U, safe_bottom - y)};
    InvalidateRect(window, nullptr, FALSE);
    set_status(state, L"Scan area selected. Press Scan selected area when ready.");
}

LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM w_param, LPARAM l_param) {
    auto* state = reinterpret_cast<AppState*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<CREATESTRUCTW*>(l_param);
        state = static_cast<AppState*>(create->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
    }
    if (!state) return DefWindowProcW(window, message, w_param, l_param);

    switch (message) {
        case WM_CREATE: {
            state->title_font = CreateFontW(-scaled(*state, 25), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                DEFAULT_PITCH, L"Segoe UI");
            state->heading_font = CreateFontW(-scaled(*state, 18), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                DEFAULT_PITCH, L"Segoe UI");
            state->body_font = CreateFontW(-scaled(*state, 16), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                DEFAULT_PITCH, L"Segoe UI");
            state->background_brush = CreateSolidBrush(RGB(238, 242, 246));
            state->card_brush = CreateSolidBrush(RGB(255, 255, 255));

            add_label(window, *state, L"Scan setup", 38, 116, 210, 26, true);
            add_label(window, *state, L"Available scanner", 38, 149, 210, 22);
            state->scanner_combo = CreateWindowExW(0, WC_COMBOBOXW, nullptr,
                WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, scaled(*state, 38), scaled(*state, 171),
                scaled(*state, 148), scaled(*state, 180), window,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(kScannerCombo)), GetModuleHandleW(nullptr), nullptr);
            apply_font(state->scanner_combo, state->body_font);
            SendMessageW(state->scanner_combo, CB_ADDSTRING, 0,
                         reinterpret_cast<LPARAM>(L"Refresh to find scanners"));
            SendMessageW(state->scanner_combo, CB_SETCURSEL, 0, 0);
            add_button(window, *state, L"Refresh", kRefreshScannersButton, 192, 171, 70, 28);

            add_label(window, *state, L"Mode", 38, 214, 210, 22);
            state->mode_combo = CreateWindowExW(0, WC_COMBOBOXW, nullptr,
                WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, scaled(*state, 38), scaled(*state, 236),
                scaled(*state, 224), scaled(*state, 130), window,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(kModeCombo)), GetModuleHandleW(nullptr), nullptr);
            apply_font(state->mode_combo, state->body_font);
            SendMessageW(state->mode_combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Photo / image"));
            SendMessageW(state->mode_combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Flatbed document"));
            SendMessageW(state->mode_combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"ADF batch (mock)"));
            SendMessageW(state->mode_combo, CB_SETCURSEL, 1, 0);

            add_label(window, *state, L"Resolution", 38, 282, 210, 22);
            state->dpi_combo = CreateWindowExW(0, WC_COMBOBOXW, nullptr,
                WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, scaled(*state, 38), scaled(*state, 304),
                scaled(*state, 224), scaled(*state, 110), window,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(kDpiCombo)), GetModuleHandleW(nullptr), nullptr);
            apply_font(state->dpi_combo, state->body_font);
            SendMessageW(state->dpi_combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"150 DPI"));
            SendMessageW(state->dpi_combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"300 DPI"));
            SendMessageW(state->dpi_combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"600 DPI"));
            SendMessageW(state->dpi_combo, CB_SETCURSEL, 1, 0);
            add_label(window, *state, L"Colour: Grayscale (fixture)", 38, 355, 224, 22);
            add_button(window, *state, L"1. Pre-scan", kPreScanButton, 38, 390, 224, 36);
            add_button(window, *state, L"2. Scan selected area", kScanButton, 38, 436, 224, 40, true);
            add_label(window, *state, L"Synthetic scan stays offline; Refresh checks local WIA.", 38, 490, 224, 52);

            add_label(window, *state, L"Pre-scan preview", 318, 116, 220, 26, true);
            add_label(window, *state, L"Session and save", 744, 116, 215, 26, true);
            state->page_list = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", nullptr,
                WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL, scaled(*state, 744), scaled(*state, 150),
                scaled(*state, 218), scaled(*state, 188), window,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPageList)), GetModuleHandleW(nullptr), nullptr);
            apply_font(state->page_list, state->body_font);
            add_button(window, *state, L"Rotate 90 degrees", kRotateButton, 744, 350, 218, 32);
            add_button(window, *state, L"Include / exclude", kIncludeButton, 744, 390, 218, 32);

            add_label(window, *state, L"Save format", 744, 432, 100, 22);
            state->format_combo = CreateWindowExW(0, WC_COMBOBOXW, nullptr,
                WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, scaled(*state, 844), scaled(*state, 428),
                scaled(*state, 118), scaled(*state, 92), window,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(kFormatCombo)), GetModuleHandleW(nullptr), nullptr);
            apply_font(state->format_combo, state->body_font);
            SendMessageW(state->format_combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"PDF"));
            SendMessageW(state->format_combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"JPG files"));
            SendMessageW(state->format_combo, CB_SETCURSEL, 0, 0);
            add_button(window, *state, L"Choose output folder...", kFolderButton, 744, 470, 218, 32);
            state->output_label = add_label(window, *state, L"No output folder selected",
                744, 510, 218, 42, false, SS_PATHELLIPSIS);
            add_button(window, *state, L"3. Save", kSaveButton, 744, 555, 218, 38, true);
            state->status = CreateWindowExW(0, L"STATIC",
                L"Ready in offline mock mode. Start with Pre-scan.", WS_CHILD | WS_VISIBLE,
                scaled(*state, 24), scaled(*state, 620), scaled(*state, 948), scaled(*state, 32),
                window, nullptr, GetModuleHandleW(nullptr), nullptr);
            apply_font(state->status, state->body_font);
            capture_layout(window, *state);
            return 0;
        }
        case WM_COMMAND: {
            const int id = LOWORD(w_param);
            if (id == kPreScanButton) prescan(window, *state);
            if (id == kScanButton) scan_selected_area(window, *state);
            if (id == kRotateButton) rotate_selected(window, *state);
            if (id == kIncludeButton) toggle_selected(window, *state);
            if (id == kFolderButton) select_output_directory(window, *state);
            if (id == kSaveButton) save_output(window, *state);
            if (id == kRefreshScannersButton) refresh_live_scanners(window, *state);
            if (id == kPageList && HIWORD(w_param) == LBN_SELCHANGE) InvalidateRect(window, nullptr, FALSE);
            if (id == kModeCombo && HIWORD(w_param) == CBN_SELCHANGE) {
                state->prescan_frame.reset();
                state->selected_crop.reset();
                if (is_adf_mode(*state)) SendMessageW(state->format_combo, CB_SETCURSEL, 0, 0);
                InvalidateRect(window, nullptr, FALSE);
                set_status(*state, is_adf_mode(*state)
                    ? L"ADF mode: pre-scan, then scan full pages. PDF is default; JPG creates separate files."
                    : L"Mode changed. Run a new Pre-scan before scanning.");
            }
            return 0;
        }
        case WM_TIMER:
            if (w_param == kDiscoveryTimer) poll_live_scanners(window, *state);
            return 0;
        case WM_SIZE:
            arrange_children(window, *state);
            return 0;
        case WM_GETMINMAXINFO: {
            auto* limits = reinterpret_cast<MINMAXINFO*>(l_param);
            limits->ptMinTrackSize.x = scaled(*state, 900);
            limits->ptMinTrackSize.y = scaled(*state, 620);
            return 0;
        }
        case WM_LBUTTONDOWN: {
            if (!state->prescan_frame || is_adf_mode(*state)) return 0;
            const POINT point = client_point(l_param);
            if (!point_in_rect_inclusive(state->preview_image_rect, point)) return 0;
            state->drag_start = clamp_to_rect(point, state->preview_image_rect);
            state->drag_current = state->drag_start;
            state->dragging = true;
            SetCapture(window);
            return 0;
        }
        case WM_MOUSEMOVE:
            if (state->dragging) {
                state->drag_current = clamp_to_rect(client_point(l_param), state->preview_image_rect);
            }
            return 0;
        case WM_LBUTTONUP:
            if (state->dragging) {
                state->drag_current = clamp_to_rect(client_point(l_param), state->preview_image_rect);
                state->dragging = false;
                ReleaseCapture();
                finish_selection(window, *state);
            }
            return 0;
        case WM_CAPTURECHANGED:
            state->dragging = false;
            return 0;
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(w_param);
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, RGB(43, 55, 67));
            return reinterpret_cast<LRESULT>(state->card_brush);
        }
        case WM_PAINT:
            draw_interface(window, *state);
            return 0;
        case WM_DESTROY:
            KillTimer(window, kDiscoveryTimer);
            if (state->wia_worker) {
                try {
                    state->wia_worker->shutdown();
                } catch (...) {
                }
                state->wia_worker.reset();
            }
            DeleteObject(state->title_font);
            DeleteObject(state->heading_font);
            DeleteObject(state->body_font);
            DeleteObject(state->background_brush);
            DeleteObject(state->card_brush);
            PostQuitMessage(0);
            return 0;
        case WM_NCDESTROY:
            SetWindowLongPtrW(window, GWLP_USERDATA, 0);
            delete state;
            return DefWindowProcW(window, message, w_param, l_param);
        default:
            return DefWindowProcW(window, message, w_param, l_param);
    }
}

int self_check() {
    try {
        const auto project = find_project_root();
        if (project.empty()) return 2;
        MockScanner scanner(project / "fixtures" / "sanitized");
        ScanRequest request;
        const auto frames = scanner.scan(request);
        if (frames.size() != 1U || frames.front().bytes.empty()) return 3;
        const auto bitmap = decode_pgm(frames.front());
        if (!bitmap || bitmap->width != frames.front().width || bitmap->height != frames.front().height) return 4;
        const double scale = fit_aware_scale();
        return scale >= 0.80 && scale <= 1.15 ? 0 : 5;
    } catch (...) {
        return 6;
    }
}

}  // namespace

int APIENTRY wWinMain(
    _In_ HINSTANCE instance,
    _In_opt_ HINSTANCE previous_instance,
    _In_ PWSTR command_line,
    _In_ int show_command) {
    (void)previous_instance;
    if (command_line && std::wstring(command_line).find(L"--self-check") != std::wstring::npos) {
        return self_check();
    }
    const HRESULT com_result = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    INITCOMMONCONTROLSEX common_controls{sizeof(common_controls), ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&common_controls);

    WNDCLASSEXW window_class{sizeof(window_class)};
    window_class.lpfnWndProc = window_proc;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    window_class.hbrBackground = static_cast<HBRUSH>(GetStockObject(WHITE_BRUSH));
    window_class.lpszClassName = kWindowClass;
    if (!RegisterClassExW(&window_class)) {
        if (SUCCEEDED(com_result)) CoUninitialize();
        return 1;
    }

    auto* state = new AppState;
    state->project_root = find_project_root();
    state->fixture_root = state->project_root / "fixtures" / "sanitized";
    state->scale = fit_aware_scale();
    const DWORD style = WS_OVERLAPPEDWINDOW;
    RECT window_rect{0, 0, scaled(*state, kBaseWidth), scaled(*state, kBaseHeight)};
    AdjustWindowRectEx(&window_rect, style, FALSE, 0);
    const int window_width = window_rect.right - window_rect.left;
    const int window_height = window_rect.bottom - window_rect.top;
    RECT work{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    const int left = static_cast<int>(work.left + std::max<LONG>(
        0L, (work.right - work.left - static_cast<LONG>(window_width)) / 2L));
    const int top = static_cast<int>(work.top + std::max<LONG>(
        0L, (work.bottom - work.top - static_cast<LONG>(window_height)) / 2L));
    HWND window = CreateWindowExW(0, kWindowClass, L"Just Scanner - Offline Mock", style,
        left, top, window_width, window_height, nullptr, nullptr, instance, state);
    if (!window) {
        delete state;
        if (SUCCEEDED(com_result)) CoUninitialize();
        return 1;
    }
    ShowWindow(window, show_command);
    UpdateWindow(window);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    if (SUCCEEDED(com_result)) CoUninitialize();
    return static_cast<int>(message.wParam);
}
