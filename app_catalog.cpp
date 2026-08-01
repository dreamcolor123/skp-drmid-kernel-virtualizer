#include "app_catalog.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <map>
#include <sstream>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <unordered_map>
#include <unistd.h>
#include <vector>

#include <zlib.h>

namespace drmid {
namespace {

constexpr size_t kMaxPackagesListLine = 4096;
constexpr size_t kPackageDumpMaxBytes = 16 * 1024 * 1024;
constexpr size_t kLabelHelperMaxBytes = 1024 * 1024;
constexpr size_t kLabelHelperMaxFileBytes = 128 * 1024;
constexpr size_t kMaxIconBytes = 128 * 1024;
constexpr size_t kIconPackageScanLimit = 64;
constexpr char kDefaultLabel[] = "应用";
constexpr char kLabelHelperName[] = "drmid_label_helper.jar";

bool valid_package_name(const std::string& package_name) {
    if (package_name.empty() || package_name.size() > 127 ||
        package_name.front() == '.' || package_name.back() == '.') {
        return false;
    }
    bool saw_dot = false;
    for (const unsigned char ch : package_name) {
        if (ch == '.') {
            saw_dot = true;
        } else if (!((ch >= 'a' && ch <= 'z') ||
                     (ch >= 'A' && ch <= 'Z') ||
                     (ch >= '0' && ch <= '9') || ch == '_')) {
            return false;
        }
    }
    return saw_dot;
}

bool parse_uid(const std::string& text, uint32_t& uid) {
    uid = 0;
    if (text.empty()) return false;
    errno = 0;
    char* end = nullptr;
    const unsigned long long value = std::strtoull(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str() || *end != '\0' || value == 0 ||
        value > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    uid = static_cast<uint32_t>(value);
    return true;
}

std::string trim_ascii(const std::string& value) {
    size_t begin = 0;
    while (begin < value.size() &&
           std::isspace(static_cast<unsigned char>(value[begin]))) {
        ++begin;
    }
    size_t end = value.size();
    while (end > begin &&
           std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }
    return value.substr(begin, end - begin);
}

bool parse_packages_list_line(const std::string& line,
                              DeviceAppInfo& info) {
    std::istringstream stream(line);
    std::string package;
    std::string uid_text;
    if (!(stream >> package >> uid_text) || !valid_package_name(package) ||
        !parse_uid(uid_text, info.uid)) {
        return false;
    }
    info = {};
    info.package_name = package;
    if (!parse_uid(uid_text, info.uid)) return false;
    std::string token;
    while (stream >> token) {
        if (token == "@system") info.system = true;
    }
    return true;
}

uint32_t stable_color(std::string_view package_name) {
    uint32_t hash = 2166136261U;
    for (const unsigned char ch : package_name) {
        hash ^= ch;
        hash *= 16777619U;
    }
    // Keep generated icons readable on the dark WebUI background.
    return 0xff000000U | ((hash >> 16) & 0x7f7f7fU) | 0x303030U;
}

std::string hex_color(uint32_t color) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(7, '#');
    for (int index = 0; index < 6; ++index) {
        const int shift = (5 - index) * 4;
        out[1 + index] = kHex[(color >> shift) & 0xf];
    }
    return out;
}

std::string first_ascii_letter(const std::string& package_name) {
    for (const unsigned char ch : package_name) {
        if (std::isalnum(ch)) {
            std::string value(1, static_cast<char>(std::toupper(ch)));
            return value;
        }
    }
    return "?";
}

std::string base64_encode(const std::string& input) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    output.reserve(((input.size() + 2) / 3) * 4);
    size_t index = 0;
    while (index + 2 < input.size()) {
        const uint32_t value = (static_cast<uint32_t>(
                                    static_cast<unsigned char>(input[index]))
                                << 16) |
                               (static_cast<uint32_t>(
                                    static_cast<unsigned char>(input[index + 1]))
                                << 8) |
                               static_cast<unsigned char>(input[index + 2]);
        output.push_back(kAlphabet[(value >> 18) & 63]);
        output.push_back(kAlphabet[(value >> 12) & 63]);
        output.push_back(kAlphabet[(value >> 6) & 63]);
        output.push_back(kAlphabet[value & 63]);
        index += 3;
    }
    const size_t remaining = input.size() - index;
    if (remaining != 0) {
        uint32_t value = static_cast<uint32_t>(
            static_cast<unsigned char>(input[index]))
                         << 16;
        if (remaining == 2) {
            value |= static_cast<uint32_t>(
                         static_cast<unsigned char>(input[index + 1]))
                     << 8;
        }
        output.push_back(kAlphabet[(value >> 18) & 63]);
        output.push_back(kAlphabet[(value >> 12) & 63]);
        output.push_back(remaining == 2 ? kAlphabet[(value >> 6) & 63] : '=');
        output.push_back('=');
    }
    return output;
}

int base64_digit(unsigned char ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

bool base64_decode(const std::string& input, std::string& output) {
    output.clear();
    if (input.empty() || input.size() > 1024 || input.size() % 4 != 0) {
        return false;
    }
    output.reserve((input.size() / 4) * 3);
    for (size_t index = 0; index < input.size(); index += 4) {
        const int first = base64_digit(input[index]);
        const int second = base64_digit(input[index + 1]);
        const bool third_padding = input[index + 2] == '=';
        const bool fourth_padding = input[index + 3] == '=';
        const int third = third_padding ? 0 : base64_digit(input[index + 2]);
        const int fourth = fourth_padding ? 0 : base64_digit(input[index + 3]);
        if (first < 0 || second < 0 || third < 0 || fourth < 0 ||
            (third_padding && !fourth_padding) ||
            ((third_padding || fourth_padding) && index + 4 != input.size())) {
            output.clear();
            return false;
        }
        const uint32_t value = (static_cast<uint32_t>(first) << 18) |
                               (static_cast<uint32_t>(second) << 12) |
                               (static_cast<uint32_t>(third) << 6) |
                               static_cast<uint32_t>(fourth);
        output.push_back(static_cast<char>((value >> 16) & 0xff));
        if (!third_padding) {
            output.push_back(static_cast<char>((value >> 8) & 0xff));
        }
        if (!fourth_padding) output.push_back(static_cast<char>(value & 0xff));
    }
    return !output.empty();
}

bool valid_utf8_label(const std::string& value) {
    size_t index = 0;
    while (index < value.size()) {
        const uint8_t first = static_cast<uint8_t>(value[index]);
        if (first < 0x80) {
            if (first < 0x20 || first == 0x7f) return false;
            ++index;
            continue;
        }
        size_t width = 0;
        uint32_t codepoint = 0;
        uint32_t minimum = 0;
        if ((first & 0xe0) == 0xc0) {
            width = 2;
            codepoint = first & 0x1f;
            minimum = 0x80;
        } else if ((first & 0xf0) == 0xe0) {
            width = 3;
            codepoint = first & 0x0f;
            minimum = 0x800;
        } else if ((first & 0xf8) == 0xf0) {
            width = 4;
            codepoint = first & 0x07;
            minimum = 0x10000;
        } else {
            return false;
        }
        if (index + width > value.size()) return false;
        for (size_t offset = 1; offset < width; ++offset) {
            const uint8_t continuation =
                static_cast<uint8_t>(value[index + offset]);
            if ((continuation & 0xc0) != 0x80) return false;
            codepoint = (codepoint << 6) | (continuation & 0x3f);
        }
        if (codepoint < minimum || codepoint > 0x10ffff ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff)) {
            return false;
        }
        index += width;
    }
    return !value.empty();
}

std::string shell_single_quote(const std::string& value) {
    std::string quoted("'");
    for (const char ch : value) {
        if (ch == '\'') quoted += "'\\''";
        else quoted.push_back(ch);
    }
    quoted.push_back('\'');
    return quoted;
}

uint16_t le16(const uint8_t* data) {
    return static_cast<uint16_t>(data[0]) |
           (static_cast<uint16_t>(data[1]) << 8);
}

uint32_t le32(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
}

bool read_at(int fd, off_t offset, void* destination, size_t size) {
    size_t used = 0;
    while (used < size) {
        const ssize_t count = pread(fd,
                                    static_cast<uint8_t*>(destination) + used,
                                    size - used,
                                    offset + static_cast<off_t>(used));
        if (count > 0) {
            used += static_cast<size_t>(count);
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

bool icon_name_candidate(const std::string& name) {
    if (name.size() < 9 || name.compare(0, 4, "res/") != 0 ||
        name.compare(name.size() - 4, 4, ".png") != 0) {
        return false;
    }
    std::string lower = name;
    for (char& ch : lower) ch = static_cast<char>(std::tolower(
        static_cast<unsigned char>(ch)));
    return lower.find("ic_launcher") != std::string::npos ||
           lower.find("launcher") != std::string::npos ||
           lower.find("app_icon") != std::string::npos ||
           lower.find("/icon") != std::string::npos;
}

int icon_density_score(const std::string& name) {
    if (name.find("xxxhdpi") != std::string::npos) return 5;
    if (name.find("xxhdpi") != std::string::npos) return 4;
    if (name.find("xhdpi") != std::string::npos) return 3;
    if (name.find("hdpi") != std::string::npos) return 2;
    if (name.find("mdpi") != std::string::npos) return 1;
    return 0;
}

bool extract_png_from_apk(const std::string& apk_path,
                          std::string& png_base64) {
    png_base64.clear();
    const int fd = open(apk_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    const off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size <= 22) {
        close(fd);
        return false;
    }
    const size_t tail_size = static_cast<size_t>(std::min<off_t>(
        file_size, 22 + 0xffff));
    std::vector<uint8_t> tail(tail_size);
    if (!read_at(fd, file_size - static_cast<off_t>(tail_size),
                 tail.data(), tail.size())) {
        close(fd);
        return false;
    }
    size_t eocd = std::string::npos;
    for (size_t index = tail.size(); index >= 4; --index) {
        const size_t begin = index - 4;
        if (le32(tail.data() + begin) == 0x06054b50U) {
            eocd = begin;
            break;
        }
        if (begin == 0) break;
    }
    if (eocd == std::string::npos || eocd + 22 > tail.size()) {
        close(fd);
        return false;
    }
    const uint32_t central_size = le32(tail.data() + eocd + 12);
    const uint32_t central_offset = le32(tail.data() + eocd + 16);
    if (central_size == 0 || central_size > 4 * 1024 * 1024 ||
        static_cast<uint64_t>(central_offset) + central_size >
            static_cast<uint64_t>(file_size)) {
        close(fd);
        return false;
    }
    std::vector<uint8_t> central(central_size);
    if (!read_at(fd, central_offset, central.data(), central.size())) {
        close(fd);
        return false;
    }

    int best_score = -1;
    uint32_t best_compressed = 0;
    uint32_t best_uncompressed = 0;
    uint16_t best_method = 0;
    uint32_t best_local_offset = 0;
    size_t cursor = 0;
    while (cursor + 46 <= central.size()) {
        const uint8_t* entry = central.data() + cursor;
        if (le32(entry) != 0x02014b50U) break;
        const uint16_t method = le16(entry + 10);
        const uint32_t compressed = le32(entry + 20);
        const uint32_t uncompressed = le32(entry + 24);
        const uint16_t name_length = le16(entry + 28);
        const uint16_t extra_length = le16(entry + 30);
        const uint16_t comment_length = le16(entry + 32);
        const uint32_t local_offset = le32(entry + 42);
        if (cursor + 46 + name_length + extra_length + comment_length >
            central.size()) {
            break;
        }
        const std::string name(reinterpret_cast<const char*>(entry + 46),
                               name_length);
        if (icon_name_candidate(name) && uncompressed > 0 &&
            uncompressed <= kMaxIconBytes &&
            (method == 0 || method == 8)) {
            const int score = icon_density_score(name) * 10 -
                              static_cast<int>(name.size());
            if (score > best_score) {
                best_score = score;
                best_compressed = compressed;
                best_uncompressed = uncompressed;
                best_method = method;
                best_local_offset = local_offset;
            }
        }
        cursor += 46 + name_length + extra_length + comment_length;
    }
    if (best_score < 0 || best_compressed == 0) {
        close(fd);
        return false;
    }
    std::array<uint8_t, 30> local_header{};
    if (!read_at(fd, best_local_offset, local_header.data(), local_header.size()) ||
        le32(local_header.data()) != 0x04034b50U) {
        close(fd);
        return false;
    }
    const uint16_t local_name_length = le16(local_header.data() + 26);
    const uint16_t local_extra_length = le16(local_header.data() + 28);
    const uint64_t payload_offset = static_cast<uint64_t>(best_local_offset) +
                                    local_header.size() + local_name_length +
                                    local_extra_length;
    if (payload_offset + best_compressed > static_cast<uint64_t>(file_size)) {
        close(fd);
        return false;
    }
    std::vector<uint8_t> compressed(best_compressed);
    if (!read_at(fd, static_cast<off_t>(payload_offset), compressed.data(),
                 compressed.size())) {
        close(fd);
        return false;
    }
    close(fd);

    std::string png;
    png.resize(best_uncompressed);
    if (best_method == 0) {
        if (compressed.size() != png.size()) return false;
        std::memcpy(png.data(), compressed.data(), png.size());
    } else {
        z_stream stream{};
        stream.next_in = compressed.data();
        stream.avail_in = compressed.size();
        stream.next_out = reinterpret_cast<Bytef*>(png.data());
        stream.avail_out = png.size();
        if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) return false;
        const int result = inflate(&stream, Z_FINISH);
        inflateEnd(&stream);
        if (result != Z_STREAM_END || stream.total_out != png.size()) {
            return false;
        }
    }
    if (png.size() < 8 ||
        static_cast<unsigned char>(png[0]) != 0x89 || png.compare(1, 3, "PNG") != 0) {
        return false;
    }
    png_base64 = base64_encode(png);
    return !png_base64.empty();
}

std::string generated_icon(const DeviceAppInfo& info) {
    const std::string label = first_ascii_letter(info.package_name);
    const std::string background = hex_color(stable_color(info.package_name));
    std::string svg =
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 64 64\">";
    svg += "<rect width=\"64\" height=\"64\" rx=\"16\" fill=\"" +
           background + "\"/>";
    svg += "<text x=\"32\" y=\"43\" text-anchor=\"middle\" "
           "font-family=\"sans-serif\" font-size=\"32\" font-weight=\"700\" "
           "fill=\"#ffffff\">" + label + "</text></svg>";
    return "data:image/svg+xml;base64," + base64_encode(svg);
}

std::string package_fallback_label(const std::string& package_name) {
    // Keep the user-provided custom package useful even when PackageManager is
    // still starting during early boot.
    if (package_name == "com.sf.activity") return "顺风速运";
    const size_t dot = package_name.rfind('.');
    const std::string tail = dot == std::string::npos
                                 ? package_name
                                 : package_name.substr(dot + 1);
    return tail.empty() ? std::string(kDefaultLabel) : tail;
}

void best_effort_labels(const char* root_key,
                        const char* module_private_dir,
                        std::vector<DeviceAppInfo>& apps) {
    if (root_key == nullptr || root_key[0] == '\0' ||
        module_private_dir == nullptr || module_private_dir[0] == '\0' ||
        apps.empty()) {
        return;
    }
    std::string helper_path(module_private_dir);
    if (helper_path.back() != '/') helper_path.push_back('/');
    helper_path += kLabelHelperName;
    struct stat helper_info {};
    if (lstat(helper_path.c_str(), &helper_info) != 0 ||
        !S_ISREG(helper_info.st_mode) || helper_info.st_size <= 0 ||
        static_cast<uint64_t>(helper_info.st_size) > kLabelHelperMaxFileBytes) {
        return;
    }

    // Android's current Resources configuration performs the same locale
    // selection as PackageManager.getApplicationLabel. The helper emits only
    // package names plus base64 UTF-8 labels and is private to this module.
    const std::string command =
        "CLASSPATH=" + shell_single_quote(helper_path) +
        " /system/bin/app_process /system/bin DrmidAppLabels";
    std::string output;
    const KModErr err = skroot_env::run_root_cmd(
        root_key, command.c_str(), output);
    if (is_failed(err) || output.empty() ||
        output.size() > kLabelHelperMaxBytes) {
        return;
    }

    std::unordered_map<std::string, std::string> labels;
    std::istringstream stream(output);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty() || line[0] == '#') continue;
        const size_t separator = line.find('\t');
        if (separator == std::string::npos ||
            line.find('\t', separator + 1) != std::string::npos) {
            continue;
        }
        const std::string package = line.substr(0, separator);
        if (!valid_package_name(package) ||
            labels.size() >= kDeviceAppCatalogLimit) {
            continue;
        }
        std::string label;
        if (!base64_decode(line.substr(separator + 1), label) ||
            label.size() > 256 || !valid_utf8_label(label)) {
            continue;
        }
        label = trim_ascii(label);
        if (!label.empty()) labels.emplace(package, std::move(label));
    }

    for (auto& app : apps) {
        const auto it = labels.find(app.package_name);
        if (it != labels.end()) {
            app.label = trim_ascii(it->second);
            app.label_from_package_manager = !app.label.empty();
        }
    }
}

void best_effort_icons(const char* root_key,
                       std::vector<DeviceAppInfo>& apps) {
    if (root_key == nullptr || root_key[0] == '\0' || apps.empty()) return;
    std::string listing;
    const KModErr err = skroot_env::run_root_cmd(
        root_key, "/system/bin/cmd package list packages -f -U", listing);
    if (is_failed(err) || listing.empty() || listing.size() > kPackageDumpMaxBytes) {
        return;
    }
    std::unordered_map<std::string, std::string> apk_paths;
    std::istringstream stream(listing);
    std::string line;
    while (std::getline(stream, line)) {
        const size_t package_prefix = line.find("package:");
        if (package_prefix == std::string::npos) continue;
        const size_t equals = line.find('=', package_prefix + 8);
        if (equals == std::string::npos || equals <= package_prefix + 8) continue;
        const std::string path = line.substr(package_prefix + 8,
                                             equals - package_prefix - 8);
        size_t package_end = equals + 1;
        while (package_end < line.size() &&
               !std::isspace(static_cast<unsigned char>(line[package_end]))) {
            ++package_end;
        }
        const std::string package = line.substr(equals + 1,
                                                package_end - equals - 1);
        if (valid_package_name(package) && !path.empty() && path.front() == '/') {
            apk_paths[package] = path;
        }
    }

    size_t scanned = 0;
    // Prefer user packages and the configured custom package, then fill the
    // remaining budget in deterministic package order.
    std::vector<size_t> order;
    order.reserve(apps.size());
    for (size_t index = 0; index < apps.size(); ++index) {
        if (!apps[index].system || apps[index].package_name == "com.sf.activity") {
            order.push_back(index);
        }
    }
    for (size_t index = 0; index < apps.size(); ++index) {
        if (std::find(order.begin(), order.end(), index) == order.end()) {
            order.push_back(index);
        }
    }
    for (const size_t index : order) {
        if (scanned++ >= kIconPackageScanLimit) break;
        auto path_it = apk_paths.find(apps[index].package_name);
        if (path_it == apk_paths.end()) continue;
        std::string icon_base64;
        if (extract_png_from_apk(path_it->second, icon_base64)) {
            apps[index].icon_data_uri = "data:image/png;base64," + icon_base64;
            apps[index].icon_source = "apk-resource";
        }
    }
}

KModErr read_packages_list(std::vector<DeviceAppInfo>& apps,
                           bool& truncated) {
    apps.clear();
    truncated = false;
    std::ifstream file("/data/system/packages.list");
    if (!file.is_open()) return KModErr::ERR_MODULE_STORAGE_NOT_FOUND;
    std::string line;
    while (std::getline(file, line)) {
        if (line.size() > kMaxPackagesListLine) continue;
        DeviceAppInfo info;
        if (!parse_packages_list_line(line, info)) continue;
        if (apps.size() >= kDeviceAppCatalogLimit) {
            truncated = true;
            continue;
        }
        apps.push_back(std::move(info));
    }
    std::sort(apps.begin(), apps.end(), [](const auto& left, const auto& right) {
        return left.package_name < right.package_name;
    });
    return apps.empty() ? KModErr::ERR_MODULE_STORAGE_NOT_FOUND : KModErr::OK;
}

} // namespace

KModErr enumerate_device_apps(const char* root_key,
                              const char* module_private_dir,
                              std::vector<DeviceAppInfo>& apps,
                              bool& truncated) {
    KModErr err = read_packages_list(apps, truncated);
    if (is_failed(err)) return err;
    best_effort_labels(root_key, module_private_dir, apps);
    for (auto& app : apps) {
        if (app.label.empty()) app.label = package_fallback_label(app.package_name);
        app.icon_data_uri = generated_icon(app);
    }
    best_effort_icons(root_key, apps);
    return KModErr::OK;
}

} // namespace drmid
