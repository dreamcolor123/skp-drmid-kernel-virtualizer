#include "target_config.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace drmid {
namespace {

constexpr uint64_t kTargetConfigV1Magic = 0x37304746434d5244ULL;
constexpr uint32_t kTargetConfigV1Version = 1;
constexpr uint64_t kTargetConfigV2Magic = 0x36314746434d5244ULL; // DRMCFG16
constexpr uint32_t kTargetConfigV2Version = 2;
constexpr uint32_t kTargetConfigEnabled = 1U << 0;
constexpr char kTargetConfigV1File[] = "drmid_target_config_v1.bin";
constexpr char kTargetConfigV2File[] = "drmid_target_config_v2.bin";
constexpr char kKnownManagerPackage[] = "com.sf.activity";
constexpr char kKnownManagerLabel[] = "顺风速运";

struct TargetConfigRecordV1 {
    uint64_t magic;
    uint32_t version;
    uint32_t record_size;
    uint64_t generation;
    uint32_t rule_mode;
    uint32_t configured_euid;
    uint32_t resolved_euid;
    uint32_t flags;
    char package_name[128];
    char display_name[64];
    uint8_t reserved[16];
    uint32_t crc32;
    uint32_t tail_reserved;
};

struct TargetConfigRecordV2 {
    uint64_t magic;
    uint32_t version;
    uint32_t record_size;
    uint64_t generation;
    uint32_t rule_mode;
    uint32_t package_count;
    uint32_t target_count;
    uint32_t flags;
    char profile_domain[128];
    char package_names[kTargetPackageLimit][128];
    uint32_t resolved_euids[kTargetPackageLimit];
    uint32_t target_euids[kTargetPackageLimit];
    uint8_t reserved[16];
    uint32_t crc32;
    uint32_t tail_reserved;
};

static_assert(sizeof(TargetConfigRecordV1) == 256);
static_assert(offsetof(TargetConfigRecordV1, crc32) == 248);
static_assert(sizeof(TargetConfigRecordV2) == 4544);
static_assert(offsetof(TargetConfigRecordV2, package_names) == 168);
static_assert(offsetof(TargetConfigRecordV2, resolved_euids) == 4264);
static_assert(offsetof(TargetConfigRecordV2, target_euids) == 4392);
static_assert(offsetof(TargetConfigRecordV2, crc32) == 4536);

uint32_t crc32(const void* data, size_t size) {
    uint32_t value = 0xffffffffU;
    const auto* bytes = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < size; ++i) {
        value ^= bytes[i];
        for (int bit = 0; bit < 8; ++bit) {
            const uint32_t mask = 0U - (value & 1U);
            value = (value >> 1) ^ (0xedb88320U & mask);
        }
    }
    return value ^ 0xffffffffU;
}

std::string config_path(const char* directory, const char* name) {
    std::string path(directory);
    if (!path.empty() && path.back() != '/') path.push_back('/');
    path += name;
    return path;
}

bool bounded_c_string(const char* value, size_t capacity) {
    return value != nullptr && std::memchr(value, '\0', capacity) != nullptr;
}

bool all_zero(const void* data, size_t size) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    for (size_t index = 0; index < size; ++index) {
        if (bytes[index] != 0) return false;
    }
    return true;
}

bool valid_package_name(const std::string& package_name) {
    if (package_name.empty() || package_name.size() > kTargetPackageMaxBytes ||
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

bool strictly_sorted_nonzero(const uint32_t* values, size_t count) {
    if (count == 0 || count > kTargetPackageLimit) return false;
    for (size_t index = 0; index < count; ++index) {
        if (values[index] == 0 ||
            (index != 0 && values[index - 1] >= values[index])) {
            return false;
        }
    }
    return true;
}

bool validate_v1_record(const TargetConfigRecordV1& record) {
    if (record.magic != kTargetConfigV1Magic ||
        record.version != kTargetConfigV1Version ||
        record.record_size != sizeof(record) || record.generation == 0 ||
        (record.flags & kTargetConfigEnabled) == 0 ||
        record.rule_mode > static_cast<uint32_t>(TargetRuleMode::kExactPackage) ||
        !bounded_c_string(record.package_name, sizeof(record.package_name)) ||
        !bounded_c_string(record.display_name, sizeof(record.display_name)) ||
        record.tail_reserved != 0 ||
        record.crc32 != crc32(&record, offsetof(TargetConfigRecordV1, crc32))) {
        return false;
    }
    const auto mode = static_cast<TargetRuleMode>(record.rule_mode);
    if (mode == TargetRuleMode::kExactPackage) {
        return valid_package_name(record.package_name) &&
               record.configured_euid == 0 && record.resolved_euid != 0;
    }
    if (mode == TargetRuleMode::kExactEuid) {
        return record.configured_euid != 0 &&
               record.resolved_euid == record.configured_euid &&
               record.package_name[0] == '\0';
    }
    return record.configured_euid == 0 && record.resolved_euid == 0 &&
           record.package_name[0] == '\0';
}

bool validate_v2_record(const TargetConfigRecordV2& record) {
    if (record.magic != kTargetConfigV2Magic ||
        record.version != kTargetConfigV2Version ||
        record.record_size != sizeof(record) || record.generation == 0 ||
        (record.flags & kTargetConfigEnabled) == 0 ||
        record.rule_mode > static_cast<uint32_t>(TargetRuleMode::kExactPackage) ||
        record.package_count > kTargetPackageLimit ||
        record.target_count > kTargetPackageLimit ||
        !bounded_c_string(record.profile_domain,
                          sizeof(record.profile_domain)) ||
        !all_zero(record.reserved, sizeof(record.reserved)) ||
        record.tail_reserved != 0 ||
        record.crc32 != crc32(&record, offsetof(TargetConfigRecordV2, crc32))) {
        return false;
    }

    const auto mode = static_cast<TargetRuleMode>(record.rule_mode);
    if (mode == TargetRuleMode::kExactPackage) {
        if (record.package_count == 0 || record.target_count == 0 ||
            !valid_package_name(record.profile_domain) ||
            !strictly_sorted_nonzero(record.target_euids,
                                     record.target_count)) {
            return false;
        }
        std::vector<uint32_t> derived;
        std::string previous;
        for (size_t index = 0; index < record.package_count; ++index) {
            if (!bounded_c_string(record.package_names[index], 128)) {
                return false;
            }
            const std::string package(record.package_names[index]);
            if (!valid_package_name(package) ||
                (!previous.empty() && previous >= package) ||
                record.resolved_euids[index] == 0) {
                return false;
            }
            previous = package;
            derived.push_back(record.resolved_euids[index]);
        }
        for (size_t index = record.package_count;
             index < kTargetPackageLimit;
             ++index) {
            if (!all_zero(record.package_names[index], 128) ||
                record.resolved_euids[index] != 0) {
                return false;
            }
        }
        for (size_t index = record.target_count;
             index < kTargetPackageLimit;
             ++index) {
            if (record.target_euids[index] != 0) return false;
        }
        std::sort(derived.begin(), derived.end());
        derived.erase(std::unique(derived.begin(), derived.end()), derived.end());
        return derived.size() == record.target_count &&
               std::equal(derived.begin(),
                          derived.end(),
                          record.target_euids);
    }

    if (record.package_count != 0 ||
        !all_zero(record.package_names, sizeof(record.package_names)) ||
        !all_zero(record.resolved_euids, sizeof(record.resolved_euids)) ||
        record.profile_domain[0] != '\0') {
        return false;
    }
    if (mode == TargetRuleMode::kExactEuid) {
        return record.target_count == 1 && record.target_euids[0] != 0 &&
               all_zero(record.target_euids + 1,
                        sizeof(record.target_euids) - sizeof(uint32_t));
    }
    return record.target_count == 0 &&
           all_zero(record.target_euids, sizeof(record.target_euids));
}

template <typename Record>
KModErr read_exact_record(const std::string& path, Record& record) {
    record = {};
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return errno == ENOENT ? KModErr::ERR_MODULE_STORAGE_NOT_FOUND
                              : KModErr::ERR_MODULE_STORAGE_READ;
    }
    size_t used = 0;
    while (used < sizeof(record)) {
        const ssize_t count = read(fd,
                                   reinterpret_cast<uint8_t*>(&record) + used,
                                   sizeof(record) - used);
        if (count > 0) {
            used += static_cast<size_t>(count);
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    uint8_t extra = 0;
    const ssize_t tail = read(fd, &extra, 1);
    close(fd);
    if (used != sizeof(record) || tail != 0) {
        record = {};
        return KModErr::ERR_MODULE_STORAGE_READ;
    }
    return KModErr::OK;
}

KModErr ensure_directory(const char* directory) {
    if (mkdir(directory, 0700) != 0 && errno != EEXIST) {
        return KModErr::ERR_MODULE_STORAGE_WRITE;
    }
    return KModErr::OK;
}

KModErr write_v2_record(const char* directory,
                        const std::string& path,
                        TargetConfigRecordV2& record) {
    RETURN_IF_ERROR(ensure_directory(directory));
    record.magic = kTargetConfigV2Magic;
    record.version = kTargetConfigV2Version;
    record.record_size = sizeof(record);
    record.flags = kTargetConfigEnabled;
    record.crc32 = crc32(&record, offsetof(TargetConfigRecordV2, crc32));
    if (!validate_v2_record(record)) {
        return KModErr::ERR_MODULE_PARAM;
    }
    const std::string temporary = path + ".tmp";
    const int fd = open(temporary.c_str(),
                        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                        0600);
    if (fd < 0) return KModErr::ERR_MODULE_STORAGE_WRITE;
    size_t written = 0;
    while (written < sizeof(record)) {
        const ssize_t count = write(
            fd,
            reinterpret_cast<const uint8_t*>(&record) + written,
            sizeof(record) - written);
        if (count > 0) {
            written += static_cast<size_t>(count);
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            close(fd);
            unlink(temporary.c_str());
            return KModErr::ERR_MODULE_STORAGE_WRITE;
        }
    }
    const bool sync_ok = fchmod(fd, 0600) == 0 && fsync(fd) == 0;
    const bool close_ok = close(fd) == 0;
    if (!sync_ok || !close_ok || rename(temporary.c_str(), path.c_str()) != 0) {
        unlink(temporary.c_str());
        return KModErr::ERR_MODULE_STORAGE_WRITE;
    }
    const int dir_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                          O_NOFOLLOW);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }
    return KModErr::OK;
}

bool parse_uid(const char* text, uint32_t& uid) {
    if (text == nullptr || text[0] == '\0') return false;
    errno = 0;
    char* end = nullptr;
    const unsigned long long parsed = std::strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed == 0 ||
        parsed > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    uid = static_cast<uint32_t>(parsed);
    return true;
}

KModErr resolve_package_uid_from_packages_list(
    const std::string& package_name,
    uint32_t& uid) {
    uid = 0;
    FILE* file = std::fopen("/data/system/packages.list", "r");
    if (file == nullptr) {
        return KModErr::ERR_MODULE_STORAGE_NOT_FOUND;
    }
    char line[4096]{};
    KModErr result = KModErr::ERR_MODULE_STORAGE_NOT_FOUND;
    while (std::fgets(line, sizeof(line), file) != nullptr) {
        const char* separator = std::strchr(line, ' ');
        if (separator == nullptr ||
            static_cast<size_t>(separator - line) != package_name.size() ||
            std::memcmp(line, package_name.data(), package_name.size()) != 0) {
            continue;
        }
        const char* value = separator + 1;
        const char* end = value;
        while (*end >= '0' && *end <= '9') ++end;
        const std::string uid_text(value, static_cast<size_t>(end - value));
        uint32_t parsed = 0;
        if (parse_uid(uid_text.c_str(), parsed)) {
            uid = parsed;
            result = KModErr::OK;
        }
        break;
    }
    std::fclose(file);
    return result;
}

KModErr resolve_package_uid(const char* root_key,
                            const std::string& package_name,
                            uint32_t& uid) {
    uid = 0;
    if (!valid_package_name(package_name) || root_key == nullptr ||
        root_key[0] == '\0') {
        return KModErr::ERR_MODULE_PARAM;
    }
    const KModErr local_err =
        resolve_package_uid_from_packages_list(package_name, uid);
    if (is_ok(local_err)) return KModErr::OK;

    const std::string command =
        "/system/bin/cmd package list packages -U " + package_name;
    std::string output;
    RETURN_IF_ERROR(skroot_env::run_root_cmd(
        root_key, command.c_str(), output));
    const std::string prefix = "package:" + package_name + " uid:";
    size_t cursor = 0;
    while ((cursor = output.find(prefix, cursor)) != std::string::npos) {
        const size_t value_start = cursor + prefix.size();
        size_t value_end = value_start;
        while (value_end < output.size() &&
               output[value_end] >= '0' && output[value_end] <= '9') {
            ++value_end;
        }
        uint32_t parsed = 0;
        const std::string value =
            output.substr(value_start, value_end - value_start);
        if (parse_uid(value.c_str(), parsed)) {
            uid = parsed;
            return KModErr::OK;
        }
        cursor = value_end;
    }
    return KModErr::ERR_MODULE_STORAGE_NOT_FOUND;
}

void copy_string(char* destination,
                 size_t capacity,
                 const std::string& value) {
    std::memset(destination, 0, capacity);
    if (capacity == 0) return;
    const size_t length = std::min(value.size(), capacity - 1);
    std::memcpy(destination, value.data(), length);
}

std::string trim_ascii_space(const std::string& value) {
    size_t begin = 0;
    while (begin < value.size() &&
           (value[begin] == ' ' || value[begin] == '\t')) {
        ++begin;
    }
    size_t end = value.size();
    while (end > begin && (value[end - 1] == ' ' || value[end - 1] == '\t')) {
        --end;
    }
    return value.substr(begin, end - begin);
}

KModErr normalize_packages(const std::string& text,
                           std::vector<std::string>& packages,
                           size_t& input_count,
                           size_t& duplicate_count) {
    packages.clear();
    input_count = 0;
    duplicate_count = 0;
    size_t cursor = 0;
    while (cursor <= text.size()) {
        const size_t separator = text.find_first_of(",\r\n", cursor);
        const size_t end = separator == std::string::npos
                               ? text.size()
                               : separator;
        const std::string package =
            trim_ascii_space(text.substr(cursor, end - cursor));
        if (!package.empty()) {
            ++input_count;
            if (!valid_package_name(package)) {
                packages.clear();
                return KModErr::ERR_MODULE_PARAM;
            }
            packages.push_back(package);
        }
        if (separator == std::string::npos) break;
        cursor = separator + 1;
    }
    if (packages.empty()) return KModErr::ERR_MODULE_PARAM;
    std::sort(packages.begin(), packages.end());
    const auto unique_end = std::unique(packages.begin(), packages.end());
    duplicate_count = static_cast<size_t>(packages.end() - unique_end);
    packages.erase(unique_end, packages.end());
    if (packages.size() > kTargetPackageLimit) {
        packages.clear();
        return KModErr::ERR_MODULE_PARAM;
    }
    return KModErr::OK;
}

void fill_v2_from_v1(const TargetConfigRecordV1& old_record,
                     TargetConfigRecordV2& migrated) {
    migrated = {};
    migrated.generation = old_record.generation;
    migrated.rule_mode = old_record.rule_mode;
    const auto mode = static_cast<TargetRuleMode>(old_record.rule_mode);
    if (mode == TargetRuleMode::kExactPackage) {
        migrated.package_count = 1;
        migrated.target_count = 1;
        copy_string(migrated.profile_domain,
                    sizeof(migrated.profile_domain),
                    old_record.package_name);
        copy_string(migrated.package_names[0],
                    sizeof(migrated.package_names[0]),
                    old_record.package_name);
        migrated.resolved_euids[0] = old_record.resolved_euid;
        migrated.target_euids[0] = old_record.resolved_euid;
    } else if (mode == TargetRuleMode::kExactEuid) {
        migrated.target_count = 1;
        migrated.target_euids[0] = old_record.resolved_euid;
    }
}

void fill_result(const TargetConfigRecordV2& record,
                 ResolvedTargetConfig& config) {
    config.rule_mode = static_cast<TargetRuleMode>(record.rule_mode);
    config.generation = record.generation;
    config.profile_domain = record.profile_domain;
    config.packages.clear();
    for (size_t index = 0; index < record.package_count; ++index) {
        config.packages.push_back(
            {record.package_names[index], record.resolved_euids[index]});
    }
    config.target_euids.assign(record.target_euids,
                               record.target_euids + record.target_count);
    config.shared_uid = record.package_count > record.target_count;
    config.target_euid = config.target_euids.empty()
                             ? 0
                             : config.target_euids.front();
    config.package_name = config.packages.empty()
                              ? std::string()
                              : config.packages.front().package_name;
    config.display_name = config.package_name == kKnownManagerPackage
                              ? std::string(kKnownManagerLabel)
                              : std::string();
}

bool semantic_equal(const TargetConfigRecordV2& left,
                    const TargetConfigRecordV2& right) {
    return left.rule_mode == right.rule_mode &&
           left.package_count == right.package_count &&
           left.target_count == right.target_count &&
           std::memcmp(left.profile_domain,
                       right.profile_domain,
                       sizeof(left.profile_domain)) == 0 &&
           std::memcmp(left.package_names,
                       right.package_names,
                       sizeof(left.package_names)) == 0 &&
           std::memcmp(left.resolved_euids,
                       right.resolved_euids,
                       sizeof(left.resolved_euids)) == 0 &&
           std::memcmp(left.target_euids,
                       right.target_euids,
                       sizeof(left.target_euids)) == 0;
}

} // namespace

KModErr read_target_config_snapshot(const char* module_private_dir,
                                    ResolvedTargetConfig& config) {
    config = {};
    if (module_private_dir == nullptr || module_private_dir[0] == '\0') {
        return KModErr::ERR_MODULE_PARAM;
    }
    TargetConfigRecordV2 record{};
    RETURN_IF_ERROR(read_exact_record(
        config_path(module_private_dir, kTargetConfigV2File), record));
    if (!validate_v2_record(record)) {
        return KModErr::ERR_MODULE_STORAGE_TYPE;
    }
    fill_result(record, config);
    config.input_package_count = config.packages.size();
    return KModErr::OK;
}

KModErr load_or_resolve_target_config(const char* root_key,
                                      const char* module_private_dir,
                                      ResolvedTargetConfig& config) {
    config = {};
    if (module_private_dir == nullptr || module_private_dir[0] == '\0') {
        return KModErr::ERR_MODULE_PARAM;
    }
    const std::string v2_path =
        config_path(module_private_dir, kTargetConfigV2File);
    TargetConfigRecordV2 stored{};
    KModErr read_err = read_exact_record(v2_path, stored);
    bool found = is_ok(read_err);
    if (found && !validate_v2_record(stored)) {
        return KModErr::ERR_MODULE_STORAGE_TYPE;
    }
    if (!found && read_err != KModErr::ERR_MODULE_STORAGE_NOT_FOUND) {
        return read_err;
    }

    bool migrated_v1 = false;
    bool created = false;
    if (!found) {
        TargetConfigRecordV1 old_record{};
        const KModErr old_err = read_exact_record(
            config_path(module_private_dir, kTargetConfigV1File), old_record);
        if (is_ok(old_err)) {
            if (!validate_v1_record(old_record)) {
                return KModErr::ERR_MODULE_STORAGE_TYPE;
            }
            fill_v2_from_v1(old_record, stored);
            RETURN_IF_ERROR(write_v2_record(module_private_dir, v2_path, stored));
            found = true;
            migrated_v1 = true;
        } else if (old_err != KModErr::ERR_MODULE_STORAGE_NOT_FOUND) {
            return old_err;
        } else {
            created = true;
        }
    }

    TargetConfigRecordV2 desired = found ? stored : TargetConfigRecordV2{};
    bool explicit_rule = false;
    std::vector<std::string> requested_packages;
    size_t input_count = 0;
    size_t duplicate_count = 0;
    const char* packages_env = std::getenv("DRMID_TARGET_PACKAGES");
    const char* package_env = std::getenv("DRMID_TARGET_PACKAGE");
    if (packages_env != nullptr || package_env != nullptr) {
        const std::string input = packages_env != nullptr
                                      ? std::string(packages_env)
                                      : std::string(package_env);
        RETURN_IF_ERROR(normalize_packages(
            input, requested_packages, input_count, duplicate_count));
        const std::string stable_domain =
            found && static_cast<TargetRuleMode>(stored.rule_mode) ==
                         TargetRuleMode::kExactPackage &&
                    stored.profile_domain[0] != '\0'
                ? std::string(stored.profile_domain)
                : requested_packages.front();
        desired = {};
        desired.rule_mode =
            static_cast<uint32_t>(TargetRuleMode::kExactPackage);
        desired.generation = found ? stored.generation : 0;
        desired.package_count = requested_packages.size();
        copy_string(desired.profile_domain,
                    sizeof(desired.profile_domain),
                    stable_domain);
        for (size_t index = 0; index < requested_packages.size(); ++index) {
            copy_string(desired.package_names[index],
                        sizeof(desired.package_names[index]),
                        requested_packages[index]);
        }
        explicit_rule = true;
    } else if (const char* uid_env = std::getenv("DRMID_TARGET_UID")) {
        desired = {};
        desired.generation = found ? stored.generation : 0;
        if (std::strcmp(uid_env, "all") == 0) {
            desired.rule_mode = static_cast<uint32_t>(TargetRuleMode::kAll);
        } else {
            uint32_t uid = 0;
            if (!parse_uid(uid_env, uid)) return KModErr::ERR_MODULE_PARAM;
            desired.rule_mode =
                static_cast<uint32_t>(TargetRuleMode::kExactEuid);
            desired.target_count = 1;
            desired.target_euids[0] = uid;
        }
        explicit_rule = true;
    } else if (!found) {
        // A fresh installation has no device-independent package name. Start
        // with an unconfigured, zero-target kAll record; module_main forces
        // this state to Dry-run, so it can install the Hook/control socket
        // without modifying any reply. The first successful WebUI APPLY
        // atomically replaces this bootstrap generation with exact packages.
        desired = {};
        desired.rule_mode = static_cast<uint32_t>(TargetRuleMode::kAll);
    }

    const auto mode = static_cast<TargetRuleMode>(desired.rule_mode);
    if (mode == TargetRuleMode::kExactPackage) {
        std::array<uint32_t, kTargetPackageLimit> resolved{};
        bool all_resolved = true;
        KModErr first_error = KModErr::OK;
        for (size_t index = 0; index < desired.package_count; ++index) {
            const KModErr resolve_err = resolve_package_uid(
                root_key, desired.package_names[index], resolved[index]);
            if (is_failed(resolve_err) || resolved[index] == 0) {
                all_resolved = false;
                if (is_ok(first_error)) {
                    first_error = is_failed(resolve_err)
                                      ? resolve_err
                                      : KModErr::ERR_MODULE_STORAGE_NOT_FOUND;
                }
            }
        }
        if (!all_resolved) {
            // Boot-time package-service unavailability reuses one complete
            // previously verified generation. Explicit APPLY never falls back
            // to a mixture of current and stale UIDs.
            if (found && !explicit_rule) {
                desired = stored;
                std::printf("[drmid612] package service not ready; retained "
                            "complete target generation=%" PRIu64 "\n",
                            stored.generation);
            } else {
                config.rule_mode = TargetRuleMode::kExactPackage;
                config.profile_domain = desired.profile_domain;
                config.input_package_count = input_count;
                config.duplicate_package_count = duplicate_count;
                for (size_t index = 0; index < desired.package_count; ++index) {
                    config.packages.push_back(
                        {desired.package_names[index], resolved[index]});
                }
                std::vector<uint32_t> partial;
                size_t resolved_count = 0;
                for (const auto& item : config.packages) {
                    if (item.resolved_euid != 0) {
                        partial.push_back(item.resolved_euid);
                        ++resolved_count;
                    }
                }
                std::sort(partial.begin(), partial.end());
                partial.erase(std::unique(partial.begin(), partial.end()),
                              partial.end());
                config.target_euids = std::move(partial);
                config.shared_uid =
                    resolved_count > config.target_euids.size();
                return is_failed(first_error)
                           ? first_error
                           : KModErr::ERR_MODULE_STORAGE_NOT_FOUND;
            }
        } else {
            std::memset(desired.resolved_euids,
                        0,
                        sizeof(desired.resolved_euids));
            std::memset(desired.target_euids,
                        0,
                        sizeof(desired.target_euids));
            std::copy(resolved.begin(),
                      resolved.begin() + desired.package_count,
                      desired.resolved_euids);
            std::vector<uint32_t> unique(
                resolved.begin(), resolved.begin() + desired.package_count);
            std::sort(unique.begin(), unique.end());
            unique.erase(std::unique(unique.begin(), unique.end()), unique.end());
            desired.target_count = unique.size();
            std::copy(unique.begin(), unique.end(), desired.target_euids);
        }
    }

    const bool changed = !found || !semantic_equal(desired, stored);
    if (changed) {
        if (found && stored.generation == std::numeric_limits<uint64_t>::max()) {
            return KModErr::ERR_MODULE_PARAM;
        }
        desired.generation = found ? stored.generation + 1 : 1;
        RETURN_IF_ERROR(write_v2_record(module_private_dir, v2_path, desired));
    } else {
        desired.generation = stored.generation;
    }

    fill_result(desired, config);
    config.input_package_count = explicit_rule
                                     ? input_count
                                     : config.packages.size();
    config.duplicate_package_count = duplicate_count;
    config.created = created;
    config.updated = found && changed;
    config.migrated_v1 = migrated_v1;
    return KModErr::OK;
}

} // namespace drmid
