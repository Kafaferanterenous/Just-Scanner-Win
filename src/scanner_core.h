#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace just_scanner {

enum class SourceType { flatbed, adf_simplex, adf_duplex };
enum class ColorMode { gray8, rgb24 };
enum class ImageExportFormat { png, jpeg, tiff };

struct CropRect {
    std::uint32_t x{};
    std::uint32_t y{};
    std::uint32_t width{};
    std::uint32_t height{};
};

struct ScannerCapabilities {
    std::vector<SourceType> sources;
    std::vector<std::uint32_t> dpi_values;
    std::vector<ColorMode> color_modes;
    std::vector<std::uint32_t> bit_depths;
    bool can_preview{};
    bool can_cancel{};
    std::uint32_t max_batch_pages{};
};

struct ScanRequest {
    SourceType source{SourceType::flatbed};
    std::uint32_t dpi{300};
    ColorMode color{ColorMode::gray8};
    std::uint32_t bit_depth{8};
    std::uint32_t max_pages{1};
};

struct ScanFrame {
    std::string fixture_id;
    std::string extension;
    std::vector<std::uint8_t> bytes;
    std::uint32_t width{};
    std::uint32_t height{};
    std::uint32_t dpi{};
    ColorMode color{ColorMode::gray8};
    std::uint32_t bit_depth{};
    SourceType source{SourceType::flatbed};
};

class ScannerError : public std::runtime_error {
public:
    explicit ScannerError(const std::string& message) : std::runtime_error(message) {}
};

class ScannerProvider {
public:
    virtual ~ScannerProvider() = default;
    virtual std::string provider_id() const = 0;
    virtual std::string device_id() const = 0;
    virtual ScannerCapabilities capabilities() const = 0;
    virtual std::vector<ScanFrame> scan(const ScanRequest& request) = 0;
};

class MockScanner final : public ScannerProvider {
public:
    explicit MockScanner(std::filesystem::path fixture_root);
    std::string provider_id() const override;
    std::string device_id() const override;
    ScannerCapabilities capabilities() const override;
    std::vector<ScanFrame> scan(const ScanRequest& request) override;

private:
    std::filesystem::path fixture_root_;
    std::size_t next_fixture_{};
};

struct Page {
    std::string id;
    std::string fixture_id;
    std::filesystem::path current_master;
    std::vector<std::filesystem::path> preserved_masters;
    std::uint32_t revision{1};
    std::uint32_t width{};
    std::uint32_t height{};
    std::uint32_t dpi{};
    ColorMode color{ColorMode::gray8};
    std::uint32_t bit_depth{};
    SourceType source{SourceType::flatbed};
    std::uint16_t rotation{};
    std::optional<CropRect> crop;
    std::int16_t brightness{};
    std::int16_t contrast{};
    bool included{true};
};

class ScanSession {
public:
    static ScanSession create(
        std::filesystem::path root,
        std::string session_id,
        std::string created_utc,
        std::string provider_id,
        std::string device_id);
    static ScanSession load(const std::filesystem::path& root, bool* recovered_from_backup = nullptr);

    const std::filesystem::path& root() const noexcept { return root_; }
    const std::string& id() const noexcept { return session_id_; }
    const std::vector<Page>& pages() const noexcept { return pages_; }

    std::string add_page(const ScanFrame& frame);
    void reorder(const std::vector<std::string>& page_ids);
    void rotate(const std::string& page_id, std::uint16_t degrees_clockwise);
    void set_crop(const std::string& page_id, CropRect crop);
    void clear_crop(const std::string& page_id);
    void set_tone(const std::string& page_id, std::int16_t brightness, std::int16_t contrast);
    void set_included(const std::string& page_id, bool included);
    void rescan(const std::string& page_id, const ScanFrame& frame);
    void save() const;
    std::vector<std::filesystem::path> export_included_pgm(
        const std::filesystem::path& output_directory,
        const std::string& document_name) const;
    std::vector<std::filesystem::path> export_included_wic(
        const std::filesystem::path& output_directory,
        const std::string& document_name,
        ImageExportFormat format) const;
    void export_multipage_pdf(const std::filesystem::path& output_file) const;

private:
    Page& page_by_id(const std::string& page_id);
    const Page& page_by_id(const std::string& page_id) const;
    void publish_master(const std::filesystem::path& relative_path, const std::vector<std::uint8_t>& bytes) const;
    static ScanSession load_manifest(const std::filesystem::path& root, const std::filesystem::path& manifest);

    std::filesystem::path root_;
    std::string session_id_;
    std::string created_utc_;
    std::string provider_id_;
    std::string device_id_;
    std::vector<Page> pages_;
};

}  // namespace just_scanner
