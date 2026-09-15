#include "scanner_core.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cwctype>
#include <fstream>
#include <iomanip>
#include <limits>
#include <cmath>
#include <set>
#include <sstream>
#include <system_error>

#ifdef _WIN32
#include <windows.h>
#include <wincodec.h>
#endif

namespace just_scanner {
namespace {

constexpr std::uintmax_t kMaxFixtureBytes = 1024U * 1024U;
constexpr std::uintmax_t kMaxManifestBytes = 1024U * 1024U;
constexpr std::size_t kMaxExportBytes = 512U * 1024U * 1024U;
constexpr std::size_t kMaxPages = 10000U;
constexpr std::size_t kMaxHistoryRecords = 100000U;
constexpr std::uint32_t kMaxImageDimension = 200000U;

bool is_reparse_entry(const std::filesystem::path& path) {
#ifdef _WIN32
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U;
#else
    std::error_code error;
    return std::filesystem::is_symlink(std::filesystem::symlink_status(path, error));
#endif
}

void require_regular_non_reparse(const std::filesystem::path& path, const char* failure) {
    std::error_code error;
    if (!std::filesystem::is_regular_file(path, error) || error || is_reparse_entry(path)) {
        throw ScannerError(failure);
    }
}

void require_local_managed_root(const std::filesystem::path& root, const bool must_exist) {
    if (root.empty() || !root.is_absolute() || root.lexically_normal() != root) {
        throw ScannerError("managed path must be an absolute local path");
    }
#ifdef _WIN32
    const auto native = root.native();
    if (native.starts_with(L"\\\\") || native.starts_with(L"\\?\\UNC\\")) {
        throw ScannerError("managed path must be an absolute local path");
    }
    const auto volume = root.root_name() / root.root_directory();
    const UINT drive_type = GetDriveTypeW(volume.c_str());
    if (drive_type != DRIVE_FIXED && drive_type != DRIVE_REMOVABLE) {
        throw ScannerError("managed path must use a local fixed or removable volume");
    }
#endif
    std::filesystem::path current;
    for (const auto& component : root) {
        current /= component;
        std::error_code error;
        const bool exists = std::filesystem::exists(current, error);
        if (error) throw ScannerError("managed path could not be inspected");
        if (exists && is_reparse_entry(current)) throw ScannerError("managed path contains a reparse point");
    }
    if (must_exist) {
        std::error_code error;
        if (!std::filesystem::is_directory(root, error) || error) {
            throw ScannerError("managed directory is unavailable");
        }
    }
}

template <typename T>
bool contains(const std::vector<T>& values, const T value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

void require_identifier(const std::string& value, const char* field) {
    if (value.empty() || value.size() > 64U) {
        throw ScannerError(std::string(field) + " is invalid");
    }
    for (const unsigned char ch : value) {
        const bool allowed = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                             (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.';
        if (!allowed) {
            throw ScannerError(std::string(field) + " is invalid");
        }
    }
}

void require_text(const std::string& value, const char* field) {
    if (value.empty() || value.size() > 128U) {
        throw ScannerError(std::string(field) + " is invalid");
    }
    for (const unsigned char ch : value) {
        if (ch < 0x20U || ch == 0x7fU) {
            throw ScannerError(std::string(field) + " is invalid");
        }
    }
}

std::filesystem::path document_component(const std::string& utf8) {
    if (utf8.empty() || utf8.size() > 256U) throw ScannerError("document name is invalid");
#ifdef _WIN32
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(),
                                             static_cast<int>(utf8.size()), nullptr, 0);
    if (required <= 0 || required > 128) throw ScannerError("document name is invalid");
    std::wstring name(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()),
                            name.data(), required) != required) {
        throw ScannerError("document name is invalid");
    }
    if (name.back() == L' ' || name.back() == L'.') throw ScannerError("document name is invalid");
    for (const wchar_t ch : name) {
        if (ch < 0x20 || ch == L'<' || ch == L'>' || ch == L':' || ch == L'"' || ch == L'/' ||
            ch == L'\\' || ch == L'|' || ch == L'?' || ch == L'*') {
            throw ScannerError("document name is invalid");
        }
    }
    auto stem = name.substr(0U, name.find(L'.'));
    std::transform(stem.begin(), stem.end(), stem.begin(),
                   [](const wchar_t ch) { return static_cast<wchar_t>(std::towupper(ch)); });
    const bool numbered_device = stem.size() == 4U &&
        (stem.starts_with(L"COM") || stem.starts_with(L"LPT")) && stem[3] >= L'1' && stem[3] <= L'9';
    if (stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL" || numbered_device) {
        throw ScannerError("document name is invalid");
    }
    return std::filesystem::path(name);
#else
    for (const unsigned char ch : utf8) {
        if (ch < 0x20U || ch == 0x7fU || ch == '/' || ch == '\\') throw ScannerError("document name is invalid");
    }
    return std::filesystem::path(utf8);
#endif
}

std::vector<std::uint8_t> read_bounded_file(
    const std::filesystem::path& path,
    const std::uintmax_t limit,
    const char* failure) {
    require_regular_non_reparse(path, failure);
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    if (error || size == 0U || size > limit || size > std::numeric_limits<std::size_t>::max()) {
        throw ScannerError(failure);
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw ScannerError(failure);
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!input || input.peek() != std::char_traits<char>::eof()) {
        throw ScannerError(failure);
    }
    return bytes;
}

std::string encode_field(const std::string& value) {
    std::ostringstream output;
    output << std::uppercase << std::hex;
    for (const unsigned char ch : value) {
        if (ch == '%' || ch == '\t' || ch == '\r' || ch == '\n' || ch < 0x20U || ch == 0x7fU) {
            output << '%' << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(ch);
        } else {
            output << static_cast<char>(ch);
        }
    }
    return output.str();
}

unsigned int hex_value(const char ch) {
    if (ch >= '0' && ch <= '9') {
        return static_cast<unsigned int>(ch - '0');
    }
    if (ch >= 'A' && ch <= 'F') {
        return 10U + static_cast<unsigned int>(ch - 'A');
    }
    if (ch >= 'a' && ch <= 'f') {
        return 10U + static_cast<unsigned int>(ch - 'a');
    }
    throw ScannerError("manifest encoding is invalid");
}

std::string decode_field(const std::string& value) {
    std::string decoded;
    decoded.reserve(value.size());
    for (std::size_t index = 0; index < value.size(); ++index) {
        const unsigned char ch = static_cast<unsigned char>(value[index]);
        if (ch != '%') {
            if (ch < 0x20U || ch == 0x7fU) {
                throw ScannerError("manifest text is invalid");
            }
            decoded.push_back(static_cast<char>(ch));
            continue;
        }
        if (index + 2U >= value.size()) {
            throw ScannerError("manifest encoding is invalid");
        }
        const auto byte = (hex_value(value[index + 1U]) << 4U) | hex_value(value[index + 2U]);
        decoded.push_back(static_cast<char>(byte));
        index += 2U;
    }
    return decoded;
}

std::vector<std::string> split_tabs(const std::string& line) {
    std::vector<std::string> fields;
    std::size_t start = 0U;
    while (true) {
        const auto position = line.find('\t', start);
        fields.push_back(line.substr(start, position == std::string::npos ? position : position - start));
        if (position == std::string::npos) {
            break;
        }
        start = position + 1U;
    }
    return fields;
}

std::uint32_t parse_u32(const std::string& text, const char* field) {
    std::uint32_t value{};
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (text.empty() || result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        throw ScannerError(std::string(field) + " is invalid");
    }
    return value;
}

std::int32_t parse_i32(const std::string& text, const char* field) {
    std::int32_t value{};
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (text.empty() || result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        throw ScannerError(std::string(field) + " is invalid");
    }
    return value;
}

std::string source_name(const SourceType source) {
    switch (source) {
        case SourceType::flatbed: return "flatbed";
        case SourceType::adf_simplex: return "adf-simplex";
        case SourceType::adf_duplex: return "adf-duplex";
    }
    throw ScannerError("source is invalid");
}

SourceType parse_source(const std::string& value) {
    if (value == "flatbed") return SourceType::flatbed;
    if (value == "adf-simplex") return SourceType::adf_simplex;
    if (value == "adf-duplex") return SourceType::adf_duplex;
    throw ScannerError("source is invalid");
}

std::string color_name(const ColorMode color) {
    switch (color) {
        case ColorMode::gray8: return "gray8";
        case ColorMode::rgb24: return "rgb24";
    }
    throw ScannerError("colour mode is invalid");
}

ColorMode parse_color(const std::string& value) {
    if (value == "gray8") return ColorMode::gray8;
    if (value == "rgb24") return ColorMode::rgb24;
    throw ScannerError("colour mode is invalid");
}

bool safe_relative_path(const std::filesystem::path& path) {
    if (path.empty() || path.is_absolute() || path.has_root_name() || path.has_root_directory()) {
        return false;
    }
    for (const auto& part : path) {
        if (part == ".." || part == "." || part.empty()) {
            return false;
        }
    }
    return path.lexically_normal() == path;
}

std::vector<std::uint8_t> decode_pgm(
    const std::vector<std::uint8_t>& bytes,
    std::uint32_t expected_width,
    std::uint32_t expected_height);

void validate_frame(const ScanFrame& frame) {
    require_identifier(frame.fixture_id, "fixture id");
    if (frame.extension != ".pgm" || frame.bytes.empty() || frame.bytes.size() > kMaxFixtureBytes ||
        frame.width == 0U || frame.height == 0U || frame.width > kMaxImageDimension ||
        frame.height > kMaxImageDimension || frame.dpi == 0U || frame.color != ColorMode::gray8 ||
        frame.bit_depth != 8U) {
        throw ScannerError("scan frame is invalid");
    }
    (void)decode_pgm(frame.bytes, frame.width, frame.height);
}

void validate_page(const Page& page, const std::filesystem::path& root) {
    require_identifier(page.id, "page id");
    require_identifier(page.fixture_id, "fixture id");
    if (!safe_relative_path(page.current_master) || page.revision == 0U || page.width == 0U ||
        page.height == 0U || page.dpi == 0U || page.bit_depth != 8U ||
        (page.rotation != 0U && page.rotation != 90U && page.rotation != 180U && page.rotation != 270U) ||
        page.brightness < -100 || page.brightness > 100 || page.contrast < -100 || page.contrast > 100) {
        throw ScannerError("page record is invalid");
    }
    require_regular_non_reparse(root / page.current_master, "page master is unavailable");
    if (page.crop.has_value()) {
        const auto& crop = *page.crop;
        if (crop.width == 0U || crop.height == 0U || crop.x > page.width || crop.y > page.height ||
            crop.width > page.width - crop.x || crop.height > page.height - crop.y) {
            throw ScannerError("page crop is invalid");
        }
    }
    for (const auto& history : page.preserved_masters) {
        if (!safe_relative_path(history)) {
            throw ScannerError("page history is invalid");
        }
        require_regular_non_reparse(root / history, "page history is invalid");
    }
}

std::uint32_t parse_pgm_number(const std::string& token) {
    return parse_u32(token, "PGM value");
}

std::vector<std::string> pgm_tokens(const std::vector<std::uint8_t>& bytes) {
    std::vector<std::string> tokens;
    std::size_t index = 0U;
    while (index < bytes.size()) {
        const auto ch = bytes[index];
        if (ch == '#') {
            while (index < bytes.size() && bytes[index] != '\n') ++index;
            continue;
        }
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
            ++index;
            continue;
        }
        std::string token;
        while (index < bytes.size()) {
            const auto current = bytes[index];
            if (current == '#' || current == ' ' || current == '\t' || current == '\r' || current == '\n') break;
            if (current < 0x21U || current > 0x7eU || token.size() >= 16U) {
                throw ScannerError("PGM fixture is invalid");
            }
            token.push_back(static_cast<char>(current));
            ++index;
        }
        if (token.empty()) throw ScannerError("PGM fixture is invalid");
        tokens.push_back(std::move(token));
        if (tokens.size() > kMaxFixtureBytes / 2U) throw ScannerError("PGM fixture is invalid");
    }
    return tokens;
}

std::vector<std::uint8_t> decode_pgm(
    const std::vector<std::uint8_t>& bytes,
    const std::uint32_t expected_width,
    const std::uint32_t expected_height) {
    const auto tokens = pgm_tokens(bytes);
    const auto pixel_count = static_cast<std::uint64_t>(expected_width) * expected_height;
    if (pixel_count > kMaxExportBytes || tokens.size() != pixel_count + 4U || tokens[0] != "P2" ||
        parse_pgm_number(tokens[1]) != expected_width || parse_pgm_number(tokens[2]) != expected_height ||
        parse_pgm_number(tokens[3]) != 255U) {
        throw ScannerError("PGM fixture does not match page metadata");
    }
    std::vector<std::uint8_t> pixels;
    pixels.reserve(static_cast<std::size_t>(pixel_count));
    for (std::size_t index = 4U; index < tokens.size(); ++index) {
        const auto value = parse_pgm_number(tokens[index]);
        if (value > 255U) throw ScannerError("PGM fixture is invalid");
        pixels.push_back(static_cast<std::uint8_t>(value));
    }
    return pixels;
}

struct RenderedGrayPage {
    std::uint32_t width{};
    std::uint32_t height{};
    std::vector<std::uint8_t> pixels;
};

RenderedGrayPage render_page(const std::filesystem::path& root, const Page& page) {
    const auto master = read_bounded_file(root / page.current_master, kMaxFixtureBytes,
                                          "page master is unavailable");
    RenderedGrayPage rendered{page.width, page.height, decode_pgm(master, page.width, page.height)};
    if (page.crop.has_value()) {
        const auto crop = *page.crop;
        std::vector<std::uint8_t> cropped;
        cropped.reserve(static_cast<std::size_t>(crop.width) * crop.height);
        for (std::uint32_t y = 0U; y < crop.height; ++y) {
            const auto source_offset = static_cast<std::size_t>(crop.y + y) * rendered.width + crop.x;
            cropped.insert(cropped.end(), rendered.pixels.begin() + static_cast<std::ptrdiff_t>(source_offset),
                           rendered.pixels.begin() + static_cast<std::ptrdiff_t>(source_offset + crop.width));
        }
        rendered.width = crop.width;
        rendered.height = crop.height;
        rendered.pixels = std::move(cropped);
    }
    if (page.rotation != 0U) {
        const auto source_width = rendered.width;
        const auto source_height = rendered.height;
        const bool swaps_dimensions = page.rotation == 90U || page.rotation == 270U;
        const auto target_width = swaps_dimensions ? source_height : source_width;
        const auto target_height = swaps_dimensions ? source_width : source_height;
        std::vector<std::uint8_t> rotated(rendered.pixels.size());
        for (std::uint32_t y = 0U; y < source_height; ++y) {
            for (std::uint32_t x = 0U; x < source_width; ++x) {
                std::uint32_t target_x{};
                std::uint32_t target_y{};
                if (page.rotation == 90U) {
                    target_x = source_height - 1U - y;
                    target_y = x;
                } else if (page.rotation == 180U) {
                    target_x = source_width - 1U - x;
                    target_y = source_height - 1U - y;
                } else {
                    target_x = y;
                    target_y = source_width - 1U - x;
                }
                rotated[static_cast<std::size_t>(target_y) * target_width + target_x] =
                    rendered.pixels[static_cast<std::size_t>(y) * source_width + x];
            }
        }
        rendered = {target_width, target_height, std::move(rotated)};
    }
    if (page.brightness != 0 || page.contrast != 0) {
        const double contrast_factor = (100.0 + page.contrast) / 100.0;
        const double brightness_offset = static_cast<double>(page.brightness) * 2.55;
        for (auto& pixel : rendered.pixels) {
            const auto adjusted = std::lround((static_cast<double>(pixel) - 127.5) * contrast_factor +
                                              127.5 + brightness_offset);
            pixel = static_cast<std::uint8_t>(std::clamp<long>(adjusted, 0L, 255L));
        }
    }
    return rendered;
}

std::vector<std::uint8_t> encode_ascii_pgm(const RenderedGrayPage& page) {
    std::ostringstream output;
    output << "P2\n# Just Scanner synthetic derivative\n" << page.width << ' ' << page.height << "\n255\n";
    for (std::uint32_t y = 0U; y < page.height; ++y) {
        for (std::uint32_t x = 0U; x < page.width; ++x) {
            if (x != 0U) output << ' ';
            output << static_cast<unsigned int>(page.pixels[static_cast<std::size_t>(y) * page.width + x]);
        }
        output << '\n';
    }
    const auto text = output.str();
    if (text.size() > kMaxFixtureBytes) throw ScannerError("PGM derivative exceeds its safe limit");
    return {text.begin(), text.end()};
}

void publish_new_file(const std::filesystem::path& destination, const std::vector<std::uint8_t>& bytes) {
    if (destination.empty() || bytes.empty() || bytes.size() > kMaxExportBytes ||
        !std::filesystem::is_directory(destination.parent_path()) || std::filesystem::exists(destination)) {
        throw ScannerError("export destination is unavailable or already exists");
    }
    auto stage = destination;
    stage += ".tmp";
    {
        std::ofstream output(stage, std::ios::binary | std::ios::trunc);
        if (!output) throw ScannerError("export could not be staged");
        output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        output.flush();
        if (!output) throw ScannerError("export could not be staged");
    }
#ifdef _WIN32
    if (!MoveFileExW(stage.c_str(), destination.c_str(), MOVEFILE_WRITE_THROUGH)) {
        std::filesystem::remove(stage);
        throw ScannerError("export could not be published");
    }
#else
    std::error_code error;
    std::filesystem::rename(stage, destination, error);
    if (error) {
        std::filesystem::remove(stage);
        throw ScannerError("export could not be published");
    }
#endif
}

std::string pdf_number(const double value) {
    std::ostringstream output;
    output << std::fixed << std::setprecision(4) << value;
    auto result = output.str();
    while (!result.empty() && result.back() == '0') result.pop_back();
    if (!result.empty() && result.back() == '.') result.pop_back();
    return result.empty() ? "0" : result;
}

#ifdef _WIN32
template <typename T>
class ComOwner {
public:
    ~ComOwner() { if (value_ != nullptr) value_->Release(); }
    ComOwner(const ComOwner&) = delete;
    ComOwner& operator=(const ComOwner&) = delete;
    ComOwner() = default;
    T* get() const noexcept { return value_; }
    T** put() noexcept {
        if (value_ != nullptr) {
            value_->Release();
            value_ = nullptr;
        }
        return &value_;
    }
private:
    T* value_{};
};

struct WicFormat {
    const GUID* container;
    const wchar_t* extension;
};

WicFormat wic_format(const ImageExportFormat format) {
    switch (format) {
        case ImageExportFormat::png: return {&GUID_ContainerFormatPng, L".png"};
        case ImageExportFormat::jpeg: return {&GUID_ContainerFormatJpeg, L".jpg"};
        case ImageExportFormat::tiff: return {&GUID_ContainerFormatTiff, L".tiff"};
    }
    throw ScannerError("image export format is invalid");
}

void encode_wic_gray(
    const std::filesystem::path& destination,
    const WicFormat format,
    const std::uint32_t width,
    const std::uint32_t height,
    const std::uint32_t dpi,
    const std::vector<std::uint8_t>& pixels) {
    if (std::filesystem::exists(destination)) {
        throw ScannerError("export destination is unavailable or already exists");
    }
    auto stage = destination;
    stage += ".tmp";
    std::error_code ignored;
    std::filesystem::remove(stage, ignored);

    const HRESULT apartment = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool uninitialize = SUCCEEDED(apartment);
    if (FAILED(apartment) && apartment != RPC_E_CHANGED_MODE) {
        throw ScannerError("Windows image encoder could not initialize");
    }
    try {
        ComOwner<IWICImagingFactory> factory;
        ComOwner<IWICStream> stream;
        ComOwner<IWICBitmapEncoder> encoder;
        ComOwner<IWICBitmapFrameEncode> frame;
        ComOwner<IPropertyBag2> options;
        HRESULT result = CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                          IID_PPV_ARGS(factory.put()));
        if (SUCCEEDED(result)) result = factory.get()->CreateStream(stream.put());
        if (SUCCEEDED(result)) result = stream.get()->InitializeFromFilename(stage.c_str(), GENERIC_WRITE);
        if (SUCCEEDED(result)) result = factory.get()->CreateEncoder(*format.container, nullptr, encoder.put());
        if (SUCCEEDED(result)) result = encoder.get()->Initialize(stream.get(), WICBitmapEncoderNoCache);
        if (SUCCEEDED(result)) result = encoder.get()->CreateNewFrame(frame.put(), options.put());
        if (SUCCEEDED(result)) result = frame.get()->Initialize(options.get());
        if (SUCCEEDED(result)) result = frame.get()->SetSize(width, height);
        if (SUCCEEDED(result)) result = frame.get()->SetResolution(static_cast<double>(dpi), static_cast<double>(dpi));
        WICPixelFormatGUID pixel_format = GUID_WICPixelFormat8bppGray;
        if (SUCCEEDED(result)) result = frame.get()->SetPixelFormat(&pixel_format);
        if (SUCCEEDED(result) && pixel_format != GUID_WICPixelFormat8bppGray) result = WINCODEC_ERR_UNSUPPORTEDPIXELFORMAT;
        if (SUCCEEDED(result)) {
            result = frame.get()->WritePixels(height, width, static_cast<UINT>(pixels.size()),
                                              const_cast<BYTE*>(pixels.data()));
        }
        if (SUCCEEDED(result)) result = frame.get()->Commit();
        if (SUCCEEDED(result)) result = encoder.get()->Commit();
        if (FAILED(result)) throw ScannerError("Windows image encoding failed");
    } catch (...) {
        if (uninitialize) CoUninitialize();
        std::filesystem::remove(stage, ignored);
        throw;
    }
    if (uninitialize) CoUninitialize();
    if (!MoveFileExW(stage.c_str(), destination.c_str(), MOVEFILE_WRITE_THROUGH)) {
        std::filesystem::remove(stage, ignored);
        throw ScannerError("export could not be published");
    }
}
#endif

}  // namespace

MockScanner::MockScanner(std::filesystem::path fixture_root) : fixture_root_(std::move(fixture_root)) {
    if (!std::filesystem::is_directory(fixture_root_)) {
        throw ScannerError("mock fixture set is unavailable");
    }
}

std::string MockScanner::provider_id() const { return "mock-v1"; }
std::string MockScanner::device_id() const { return "synthetic-device"; }

ScannerCapabilities MockScanner::capabilities() const {
    return {{SourceType::flatbed, SourceType::adf_simplex}, {150U, 300U, 600U},
            {ColorMode::gray8}, {8U}, true, true, 100U};
}

std::vector<ScanFrame> MockScanner::scan(const ScanRequest& request) {
    const auto caps = capabilities();
    if (!contains(caps.sources, request.source) || !contains(caps.dpi_values, request.dpi) ||
        !contains(caps.color_modes, request.color) || !contains(caps.bit_depths, request.bit_depth) ||
        request.max_pages == 0U || request.max_pages > caps.max_batch_pages ||
        (request.source == SourceType::flatbed && request.max_pages != 1U)) {
        throw ScannerError("scan request is not supported by this device");
    }

    const std::array<std::string, 2U> names{"page_a.pgm", "page_b.pgm"};
    std::vector<ScanFrame> frames;
    frames.reserve(request.max_pages);
    for (std::uint32_t index = 0U; index < request.max_pages; ++index) {
        const auto fixture_index = next_fixture_ % names.size();
        ++next_fixture_;
        ScanFrame frame;
        frame.fixture_id = fixture_index == 0U ? "synthetic-a" : "synthetic-b";
        frame.extension = ".pgm";
        frame.bytes = read_bounded_file(fixture_root_ / names[fixture_index], kMaxFixtureBytes,
                                        "mock fixture is unavailable");
        frame.width = 8U;
        frame.height = 6U;
        frame.dpi = request.dpi;
        frame.color = request.color;
        frame.bit_depth = request.bit_depth;
        frame.source = request.source;
        frames.push_back(std::move(frame));
    }
    return frames;
}

ScanSession ScanSession::create(
    std::filesystem::path root,
    std::string session_id,
    std::string created_utc,
    std::string provider_id,
    std::string device_id) {
    require_identifier(session_id, "session id");
    require_text(created_utc, "creation time");
    require_identifier(provider_id, "provider id");
    require_identifier(device_id, "device id");
    require_local_managed_root(root, false);
    std::error_code error;
    for (const auto* directory : {"originals", "previews", "derivatives", "exports"}) {
        std::filesystem::create_directories(root / directory, error);
        if (error) throw ScannerError("session directories could not be created");
    }
    require_local_managed_root(root, true);
    for (const auto* directory : {"originals", "previews", "derivatives", "exports"}) {
        require_local_managed_root(root / directory, true);
    }

    ScanSession session;
    session.root_ = std::move(root);
    session.session_id_ = std::move(session_id);
    session.created_utc_ = std::move(created_utc);
    session.provider_id_ = std::move(provider_id);
    session.device_id_ = std::move(device_id);
    return session;
}

Page& ScanSession::page_by_id(const std::string& page_id) {
    const auto match = std::find_if(pages_.begin(), pages_.end(), [&](const Page& page) { return page.id == page_id; });
    if (match == pages_.end()) {
        throw ScannerError("page does not exist");
    }
    return *match;
}

const Page& ScanSession::page_by_id(const std::string& page_id) const {
    const auto match = std::find_if(pages_.begin(), pages_.end(), [&](const Page& page) { return page.id == page_id; });
    if (match == pages_.end()) {
        throw ScannerError("page does not exist");
    }
    return *match;
}

void ScanSession::publish_master(
    const std::filesystem::path& relative_path,
    const std::vector<std::uint8_t>& bytes) const {
    if (!safe_relative_path(relative_path) || relative_path.parent_path() != std::filesystem::path("originals") ||
        bytes.empty() || bytes.size() > kMaxFixtureBytes) {
        throw ScannerError("master publication is invalid");
    }
    require_local_managed_root(root_, true);
    require_local_managed_root(root_ / "originals", true);
    const auto destination = root_ / relative_path;
    if (std::filesystem::exists(destination)) {
        throw ScannerError("master revision already exists");
    }
    const auto stage = destination.string() + ".tmp";
    {
        std::ofstream output(stage, std::ios::binary | std::ios::trunc);
        if (!output) {
            throw ScannerError("master could not be staged");
        }
        output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        output.flush();
        if (!output) {
            throw ScannerError("master could not be staged");
        }
    }
    std::error_code error;
    std::filesystem::rename(stage, destination, error);
    if (error) {
        std::filesystem::remove(stage);
        throw ScannerError("master could not be published");
    }
}

std::string ScanSession::add_page(const ScanFrame& frame) {
    validate_frame(frame);
    if (pages_.size() >= kMaxPages) {
        throw ScannerError("session page limit was reached");
    }
    std::ostringstream id;
    id << "page-" << std::setw(4) << std::setfill('0') << (pages_.size() + 1U);
    Page page;
    page.id = id.str();
    page.fixture_id = frame.fixture_id;
    page.current_master = std::filesystem::path("originals") / (page.id + "-r0001" + frame.extension);
    page.width = frame.width;
    page.height = frame.height;
    page.dpi = frame.dpi;
    page.color = frame.color;
    page.bit_depth = frame.bit_depth;
    page.source = frame.source;
    publish_master(page.current_master, frame.bytes);
    pages_.push_back(std::move(page));
    return pages_.back().id;
}

void ScanSession::reorder(const std::vector<std::string>& page_ids) {
    if (page_ids.size() != pages_.size()) {
        throw ScannerError("page order must contain every page exactly once");
    }
    std::set<std::string> unique(page_ids.begin(), page_ids.end());
    if (unique.size() != pages_.size()) {
        throw ScannerError("page order must contain every page exactly once");
    }
    std::vector<Page> ordered;
    ordered.reserve(pages_.size());
    for (const auto& id : page_ids) {
        ordered.push_back(page_by_id(id));
    }
    pages_ = std::move(ordered);
}

void ScanSession::rotate(const std::string& page_id, const std::uint16_t degrees_clockwise) {
    if (degrees_clockwise != 90U && degrees_clockwise != 180U && degrees_clockwise != 270U) {
        throw ScannerError("rotation must be 90, 180, or 270 degrees");
    }
    auto& page = page_by_id(page_id);
    page.rotation = static_cast<std::uint16_t>((page.rotation + degrees_clockwise) % 360U);
}

void ScanSession::set_crop(const std::string& page_id, const CropRect crop) {
    auto& page = page_by_id(page_id);
    if (crop.width == 0U || crop.height == 0U || crop.x > page.width || crop.y > page.height ||
        crop.width > page.width - crop.x || crop.height > page.height - crop.y) {
        throw ScannerError("crop must remain inside the master image");
    }
    page.crop = crop;
}

void ScanSession::clear_crop(const std::string& page_id) { page_by_id(page_id).crop.reset(); }
void ScanSession::set_tone(
    const std::string& page_id,
    const std::int16_t brightness,
    const std::int16_t contrast) {
    if (brightness < -100 || brightness > 100 || contrast < -100 || contrast > 100) {
        throw ScannerError("brightness and contrast must be between -100 and 100");
    }
    auto& page = page_by_id(page_id);
    page.brightness = brightness;
    page.contrast = contrast;
}
void ScanSession::set_included(const std::string& page_id, const bool included) {
    page_by_id(page_id).included = included;
}

void ScanSession::rescan(const std::string& page_id, const ScanFrame& frame) {
    validate_frame(frame);
    auto& page = page_by_id(page_id);
    if (page.revision == std::numeric_limits<std::uint32_t>::max() ||
        page.preserved_masters.size() >= kMaxHistoryRecords) {
        throw ScannerError("page revision limit was reached");
    }
    const auto next_revision = page.revision + 1U;
    std::ostringstream filename;
    filename << page.id << "-r" << std::setw(4) << std::setfill('0') << next_revision << frame.extension;
    const auto next_master = std::filesystem::path("originals") / filename.str();
    publish_master(next_master, frame.bytes);
    page.preserved_masters.push_back(page.current_master);
    page.current_master = next_master;
    page.fixture_id = frame.fixture_id;
    page.revision = next_revision;
    page.width = frame.width;
    page.height = frame.height;
    page.dpi = frame.dpi;
    page.color = frame.color;
    page.bit_depth = frame.bit_depth;
    page.source = frame.source;
    page.rotation = 0U;
    page.crop.reset();
    page.brightness = 0;
    page.contrast = 0;
}

void ScanSession::save() const {
    require_local_managed_root(root_, true);
    require_identifier(session_id_, "session id");
    require_text(created_utc_, "creation time");
    require_identifier(provider_id_, "provider id");
    require_identifier(device_id_, "device id");
    if (pages_.size() > kMaxPages) {
        throw ScannerError("session page limit was reached");
    }
    std::size_t history_records = 0U;
    for (const auto& page : pages_) {
        validate_page(page, root_);
        if (page.preserved_masters.size() > kMaxHistoryRecords - history_records) {
            throw ScannerError("session history limit was reached");
        }
        history_records += page.preserved_masters.size();
    }

    const auto current = root_ / "session.jscan";
    const auto backup = root_ / "session.jscan.bak";
    const auto stage = root_ / "session.jscan.tmp";
    {
        std::ofstream output(stage, std::ios::binary | std::ios::trunc);
        if (!output) {
            throw ScannerError("session could not be staged");
        }
        output << "JSCAN\t2\n";
        output << "SESSION\t" << encode_field(session_id_) << '\t' << encode_field(created_utc_) << '\t'
               << encode_field(provider_id_) << '\t' << encode_field(device_id_) << '\n';
        for (const auto& page : pages_) {
            const CropRect crop = page.crop.value_or(CropRect{});
            output << "PAGE\t" << encode_field(page.id) << '\t' << encode_field(page.fixture_id) << '\t'
                   << encode_field(page.current_master.generic_string()) << '\t' << page.revision << '\t'
                   << page.width << '\t' << page.height << '\t' << page.dpi << '\t'
                   << color_name(page.color) << '\t' << page.bit_depth << '\t' << source_name(page.source) << '\t'
                   << page.rotation << '\t' << (page.included ? 1 : 0) << '\t' << (page.crop.has_value() ? 1 : 0)
                   << '\t' << crop.x << '\t' << crop.y << '\t' << crop.width << '\t' << crop.height << '\t'
                   << page.brightness << '\t' << page.contrast << '\n';
            for (const auto& history : page.preserved_masters) {
                output << "HISTORY\t" << encode_field(page.id) << '\t'
                       << encode_field(history.generic_string()) << '\n';
            }
        }
        output << "END\n";
        output.flush();
        if (!output) {
            throw ScannerError("session could not be staged");
        }
    }

    std::error_code size_error;
    const auto staged_size = std::filesystem::file_size(stage, size_error);
    if (size_error || staged_size == 0U || staged_size > kMaxManifestBytes) {
        std::filesystem::remove(stage);
        throw ScannerError("session manifest exceeds its safe limit");
    }

    std::error_code error;
    if (std::filesystem::exists(current)) {
        std::filesystem::copy_file(current, backup, std::filesystem::copy_options::overwrite_existing, error);
        if (error) {
            std::filesystem::remove(stage);
            throw ScannerError("session backup could not be written");
        }
    }
#ifdef _WIN32
    if (!MoveFileExW(stage.c_str(), current.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::filesystem::remove(stage);
        throw ScannerError("session could not be published");
    }
#else
    std::filesystem::rename(stage, current, error);
    if (error) {
        std::filesystem::remove(stage);
        throw ScannerError("session could not be published");
    }
#endif
}

std::vector<std::filesystem::path> ScanSession::export_included_pgm(
    const std::filesystem::path& output_directory,
    const std::string& document_name) const {
    const auto name_component = document_component(document_name);
    require_local_managed_root(output_directory, true);
    std::vector<const Page*> included;
    for (const auto& page : pages_) {
        if (page.included) included.push_back(&page);
    }
    if (included.empty()) throw ScannerError("session has no included pages");

    std::vector<std::filesystem::path> destinations;
    destinations.reserve(included.size());
    for (std::size_t index = 0U; index < included.size(); ++index) {
        std::wostringstream filename;
        filename << name_component.wstring() << L'_' << std::setw(4) << std::setfill(L'0') <<
                    (index + 1U) << L".pgm";
        const auto destination = output_directory / filename.str();
        if (std::filesystem::exists(destination)) {
            throw ScannerError("export destination is unavailable or already exists");
        }
        destinations.push_back(destination);
    }
    for (std::size_t index = 0U; index < included.size(); ++index) {
        publish_new_file(destinations[index], encode_ascii_pgm(render_page(root_, *included[index])));
    }
    return destinations;
}

std::vector<std::filesystem::path> ScanSession::export_included_wic(
    const std::filesystem::path& output_directory,
    const std::string& document_name,
    const ImageExportFormat format) const {
#ifndef _WIN32
    (void)output_directory;
    (void)document_name;
    (void)format;
    throw ScannerError("Windows image export is unavailable on this platform");
#else
    const auto name_component = document_component(document_name);
    require_local_managed_root(output_directory, true);
    const auto selected_format = wic_format(format);
    std::vector<const Page*> included;
    for (const auto& page : pages_) if (page.included) included.push_back(&page);
    if (included.empty()) throw ScannerError("session has no included pages");
    std::vector<std::filesystem::path> destinations;
    for (std::size_t index = 0U; index < included.size(); ++index) {
        std::wostringstream filename;
        filename << name_component.wstring() << L'_' << std::setw(4) <<
                    std::setfill(L'0') << (index + 1U) << selected_format.extension;
        const auto destination = output_directory / filename.str();
        if (std::filesystem::exists(destination)) throw ScannerError("export destination is unavailable or already exists");
        destinations.push_back(destination);
    }
    for (std::size_t index = 0U; index < included.size(); ++index) {
        const auto& page = *included[index];
        const auto rendered = render_page(root_, page);
        encode_wic_gray(destinations[index], selected_format, rendered.width, rendered.height, page.dpi,
                        rendered.pixels);
    }
    return destinations;
#endif
}

void ScanSession::export_multipage_pdf(const std::filesystem::path& output_file) const {
    if (output_file.extension() != ".pdf") throw ScannerError("PDF destination must use the .pdf extension");
    std::vector<const Page*> included;
    for (const auto& page : pages_) {
        if (page.included) included.push_back(&page);
    }
    if (included.empty() || included.size() > 1000U) throw ScannerError("PDF page count is unsupported");

    const std::size_t object_count = 2U + included.size() * 3U;
    std::vector<std::size_t> offsets(object_count + 1U, 0U);
    std::string pdf("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n", 15U);
    auto append_object = [&](const std::size_t number, const std::string& body) {
        if (number == 0U || number > object_count || pdf.size() > kMaxExportBytes - body.size() - 64U) {
            throw ScannerError("PDF output exceeds the safe limit");
        }
        offsets[number] = pdf.size();
        pdf += std::to_string(number) + " 0 obj\n" + body + "\nendobj\n";
    };

    append_object(1U, "<< /Type /Catalog /Pages 2 0 R >>");
    std::string kids;
    for (std::size_t index = 0U; index < included.size(); ++index) {
        kids += std::to_string(3U + index * 3U) + " 0 R ";
    }
    append_object(2U, "<< /Type /Pages /Count " + std::to_string(included.size()) + " /Kids [ " + kids + "] >>");

    for (std::size_t index = 0U; index < included.size(); ++index) {
        const auto& page = *included[index];
        const auto page_object = 3U + index * 3U;
        const auto content_object = page_object + 1U;
        const auto image_object = page_object + 2U;
        const auto rendered = render_page(root_, page);
        const auto width_points = pdf_number(static_cast<double>(rendered.width) * 72.0 / page.dpi);
        const auto height_points = pdf_number(static_cast<double>(rendered.height) * 72.0 / page.dpi);
        append_object(page_object,
                      "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 " + width_points + ' ' +
                          height_points + "] /Resources << /XObject << /Im0 " +
                          std::to_string(image_object) + " 0 R >> >> /Contents " +
                          std::to_string(content_object) + " 0 R >>");
        const std::string content = "q\n" + width_points + " 0 0 " + height_points + " 0 0 cm\n/Im0 Do\nQ\n";
        append_object(content_object,
                      "<< /Length " + std::to_string(content.size()) + " >>\nstream\n" + content + "endstream");
        std::string image_body =
            "<< /Type /XObject /Subtype /Image /Width " + std::to_string(rendered.width) +
            " /Height " + std::to_string(rendered.height) +
            " /ColorSpace /DeviceGray /BitsPerComponent 8 /Length " + std::to_string(rendered.pixels.size()) +
            " >>\nstream\n";
        image_body.append(reinterpret_cast<const char*>(rendered.pixels.data()), rendered.pixels.size());
        image_body += "\nendstream";
        append_object(image_object, image_body);
    }

    const auto xref_offset = pdf.size();
    pdf += "xref\n0 " + std::to_string(object_count + 1U) + "\n";
    pdf += "0000000000 65535 f \n";
    for (std::size_t number = 1U; number <= object_count; ++number) {
        std::ostringstream entry;
        entry << std::setw(10) << std::setfill('0') << offsets[number] << " 00000 n \n";
        pdf += entry.str();
    }
    pdf += "trailer\n<< /Size " + std::to_string(object_count + 1U) + " /Root 1 0 R >>\nstartxref\n" +
           std::to_string(xref_offset) + "\n%%EOF\n";
    publish_new_file(output_file, std::vector<std::uint8_t>(pdf.begin(), pdf.end()));
}

ScanSession ScanSession::load_manifest(
    const std::filesystem::path& root,
    const std::filesystem::path& manifest) {
    const auto bytes = read_bounded_file(manifest, kMaxManifestBytes, "session manifest is unavailable");
    const std::string text(bytes.begin(), bytes.end());
    std::istringstream input(text);
    std::string line;
    if (!std::getline(input, line) || (line != "JSCAN\t1" && line != "JSCAN\t2")) {
        throw ScannerError("session manifest header is invalid");
    }
    const bool version_two = line == "JSCAN\t2";

    ScanSession session;
    session.root_ = root;
    bool saw_session = false;
    bool saw_end = false;
    std::size_t history_count = 0U;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) throw ScannerError("session manifest contains an empty record");
        const auto fields = split_tabs(line);
        if (fields[0] == "SESSION") {
            if (saw_session || !session.pages_.empty() || fields.size() != 5U) {
                throw ScannerError("session record is invalid");
            }
            session.session_id_ = decode_field(fields[1]);
            session.created_utc_ = decode_field(fields[2]);
            session.provider_id_ = decode_field(fields[3]);
            session.device_id_ = decode_field(fields[4]);
            require_identifier(session.session_id_, "session id");
            require_text(session.created_utc_, "creation time");
            require_identifier(session.provider_id_, "provider id");
            require_identifier(session.device_id_, "device id");
            saw_session = true;
        } else if (fields[0] == "PAGE") {
            const std::size_t expected_fields = version_two ? 20U : 18U;
            if (!saw_session || saw_end || fields.size() != expected_fields || session.pages_.size() >= kMaxPages) {
                throw ScannerError("page record is invalid");
            }
            Page page;
            page.id = decode_field(fields[1]);
            page.fixture_id = decode_field(fields[2]);
            page.current_master = std::filesystem::path(decode_field(fields[3]));
            page.revision = parse_u32(fields[4], "revision");
            page.width = parse_u32(fields[5], "width");
            page.height = parse_u32(fields[6], "height");
            page.dpi = parse_u32(fields[7], "dpi");
            page.color = parse_color(fields[8]);
            page.bit_depth = parse_u32(fields[9], "bit depth");
            page.source = parse_source(fields[10]);
            const auto rotation = parse_u32(fields[11], "rotation");
            if (rotation > std::numeric_limits<std::uint16_t>::max()) throw ScannerError("rotation is invalid");
            page.rotation = static_cast<std::uint16_t>(rotation);
            const auto included = parse_u32(fields[12], "included flag");
            const auto has_crop = parse_u32(fields[13], "crop flag");
            if (included > 1U || has_crop > 1U) throw ScannerError("page flags are invalid");
            page.included = included == 1U;
            CropRect crop{parse_u32(fields[14], "crop x"), parse_u32(fields[15], "crop y"),
                          parse_u32(fields[16], "crop width"), parse_u32(fields[17], "crop height")};
            if (has_crop == 1U) page.crop = crop;
            if (version_two) {
                const auto brightness = parse_i32(fields[18], "brightness");
                const auto contrast = parse_i32(fields[19], "contrast");
                if (brightness < -100 || brightness > 100 || contrast < -100 || contrast > 100) {
                    throw ScannerError("page tone settings are invalid");
                }
                page.brightness = static_cast<std::int16_t>(brightness);
                page.contrast = static_cast<std::int16_t>(contrast);
            }
            if (std::any_of(session.pages_.begin(), session.pages_.end(),
                            [&](const Page& existing) { return existing.id == page.id; })) {
                throw ScannerError("page identifier is duplicated");
            }
            session.pages_.push_back(std::move(page));
        } else if (fields[0] == "HISTORY") {
            if (!saw_session || saw_end || fields.size() != 3U || ++history_count > kMaxHistoryRecords) {
                throw ScannerError("history record is invalid");
            }
            session.page_by_id(decode_field(fields[1])).preserved_masters.emplace_back(decode_field(fields[2]));
        } else if (fields[0] == "END") {
            if (!saw_session || saw_end || fields.size() != 1U) throw ScannerError("end record is invalid");
            saw_end = true;
            std::string trailing;
            if (std::getline(input, trailing)) throw ScannerError("session manifest has trailing records");
            break;
        } else {
            throw ScannerError("session manifest contains an unknown record");
        }
    }
    if (!saw_session || !saw_end) throw ScannerError("session manifest is incomplete");
    for (const auto& page : session.pages_) validate_page(page, root);
    return session;
}

ScanSession ScanSession::load(const std::filesystem::path& root, bool* recovered_from_backup) {
    require_local_managed_root(root, true);
    if (recovered_from_backup != nullptr) *recovered_from_backup = false;
    try {
        return load_manifest(root, root / "session.jscan");
    } catch (const ScannerError&) {
        try {
            auto recovered = load_manifest(root, root / "session.jscan.bak");
            if (recovered_from_backup != nullptr) *recovered_from_backup = true;
            return recovered;
        } catch (const ScannerError&) {
            throw ScannerError("no valid session manifest is available");
        }
    }
}

}  // namespace just_scanner
