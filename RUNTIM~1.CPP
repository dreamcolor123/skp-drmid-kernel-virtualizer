#include "runtime_control.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace drmid {
namespace {

constexpr uint64_t kRuntimeControlV2Magic =
    0x36314c54434d5244ULL; // DRMCTL16
constexpr uint32_t kRuntimeControlV2Version = 2;
constexpr uint32_t kRuntimeControlV2Bytes = 256;
constexpr size_t kLegacyTargetLimit = 32;

struct RuntimeControlRecordV2 {
    uint64_t magic;
    uint32_t version;
    uint32_t record_size;
    uint64_t config_generation;
    uint64_t seed_generation;
    uint64_t profile_fingerprint;
    uint32_t replacement_mode;
    uint32_t rule_mode;
    uint32_t target_count;
    uint32_t virtual_id_length;
    uint32_t target_euids[kLegacyTargetLimit];
    uint8_t virtual_id[64];
    uint32_t crc32;
    uint32_t tail_reserved;
};

struct RuntimeControlRecordV3 {
    uint64_t magic;
    uint32_t version;
    uint32_t record_size;
    uint64_t config_generation;
    uint64_t seed_generation;
    uint64_t profile_fingerprint;
    uint32_t replacement_mode;
    uint32_t virtual_id_length;
    uint8_t virtual_id[64];
    uint64_t reserved;
    uint32_t crc32;
    uint32_t tail_reserved;
};

static_assert(sizeof(RuntimeControlRecordV2) == kRuntimeControlV2Bytes);
static_assert(offsetof(RuntimeControlRecordV2, target_euids) == 56);
static_assert(offsetof(RuntimeControlRecordV2, virtual_id) == 184);
static_assert(offsetof(RuntimeControlRecordV2, crc32) == 248);
static_assert(sizeof(RuntimeControlRecordV3) == kRuntimeControlRecordBytes);
static_assert(offsetof(RuntimeControlRecordV3, virtual_id) == 48);
static_assert(offsetof(RuntimeControlRecordV3, crc32) == 120);

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

template <typename Record>
KModErr read_exact_record(const char* path, Record& record) {
    record = {};
    const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return errno == ENOENT ? KModErr::ERR_MODULE_STORAGE_NOT_FOUND
                              : KModErr::ERR_MODULE_STORAGE_READ;
    }
    size_t used = 0;
    while (used < sizeof(record)) {
        const ssize_t count = read(
            fd,
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

bool valid_legacy_target_set(uint32_t rule_mode,
                             uint32_t target_count,
                             const uint32_t* target_euids) {
    if (rule_mode > 2 || target_count > kLegacyTargetLimit) return false;
    if ((rule_mode == 0 && target_count != 0) ||
        (rule_mode != 0 && target_count == 0)) {
        return false;
    }
    for (size_t index = 0; index < kLegacyTargetLimit; ++index) {
        if (index < target_count) {
            if (target_euids[index] == 0 ||
                (index != 0 &&
                 target_euids[index - 1] >= target_euids[index])) {
                return false;
            }
        } else if (target_euids[index] != 0) {
            return false;
        }
    }
    return true;
}

bool validate_v2_record(const RuntimeControlRecordV2& record) {
    return record.magic == kRuntimeControlV2Magic &&
           record.version == kRuntimeControlV2Version &&
           record.record_size == sizeof(record) &&
           record.config_generation != 0 && record.seed_generation != 0 &&
           record.replacement_mode <=
               static_cast<uint32_t>(ReplacementMode::kWriteTest) &&
           valid_legacy_target_set(record.rule_mode,
                                   record.target_count,
                                   record.target_euids) &&
           record.virtual_id_length == kWidevineDeviceUniqueIdBytes &&
           record.tail_reserved == 0 &&
           record.crc32 ==
               crc32(&record, offsetof(RuntimeControlRecordV2, crc32));
}

bool validate_v3_record(const RuntimeControlRecordV3& record) {
    return record.magic == kRuntimeControlMagic &&
           record.version == kRuntimeControlVersion &&
           record.record_size == sizeof(record) &&
           record.config_generation != 0 && record.seed_generation != 0 &&
           record.replacement_mode <=
               static_cast<uint32_t>(ReplacementMode::kWriteTest) &&
           record.virtual_id_length == kWidevineDeviceUniqueIdBytes &&
           record.profile_fingerprint != 0 && record.reserved == 0 &&
           record.tail_reserved == 0 &&
           record.crc32 ==
               crc32(&record, offsetof(RuntimeControlRecordV3, crc32));
}

bool validate_config(const ReplacementConfig& config) {
    return config.config_generation != 0 && config.seed_generation != 0 &&
           config.profile_fingerprint != 0 &&
           static_cast<uint32_t>(config.mode) <=
               static_cast<uint32_t>(ReplacementMode::kWriteTest) &&
           config.virtual_id_length == kWidevineDeviceUniqueIdBytes;
}

KModErr write_record(const char* path, RuntimeControlRecordV3& record) {
    record.magic = kRuntimeControlMagic;
    record.version = kRuntimeControlVersion;
    record.record_size = sizeof(record);
    record.crc32 = crc32(&record, offsetof(RuntimeControlRecordV3, crc32));
    const std::string temporary = std::string(path) + ".tmp";
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
    if (!sync_ok || !close_ok || rename(temporary.c_str(), path) != 0) {
        unlink(temporary.c_str());
        return KModErr::ERR_MODULE_STORAGE_WRITE;
    }
    std::string directory(path);
    const size_t slash = directory.find_last_of('/');
    directory = slash == std::string::npos ? "." : directory.substr(0, slash);
    const int dir_fd = open(directory.c_str(),
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }
    return KModErr::OK;
}

std::string sibling_path(const char* path, const char* file_name) {
    std::string sibling(path);
    const size_t slash = sibling.find_last_of('/');
    sibling = slash == std::string::npos ? std::string()
                                         : sibling.substr(0, slash + 1);
    sibling += file_name;
    return sibling;
}

void fill_config_from_v3(const RuntimeControlRecordV3& record,
                         ReplacementConfig& config) {
    config = {};
    config.config_generation = record.config_generation;
    config.seed_generation = record.seed_generation;
    config.profile_fingerprint = record.profile_fingerprint;
    config.mode = static_cast<ReplacementMode>(record.replacement_mode);
    config.virtual_id_length = record.virtual_id_length;
    std::memcpy(config.virtual_id.data(),
                record.virtual_id,
                record.virtual_id_length);
}

} // namespace

KModErr read_runtime_control_file(const char* path,
                                  ReplacementConfig& config) {
    config = {};
    if (path == nullptr || path[0] == '\0') {
        return KModErr::ERR_MODULE_PARAM;
    }
    RuntimeControlRecordV3 record{};
    RETURN_IF_ERROR(read_exact_record(path, record));
    if (!validate_v3_record(record)) {
        return KModErr::ERR_MODULE_STORAGE_TYPE;
    }
    fill_config_from_v3(record, config);
    return KModErr::OK;
}

KModErr write_runtime_control_file(const char* path,
                                   const ReplacementConfig& config) {
    if (path == nullptr || path[0] == '\0' || !validate_config(config)) {
        return KModErr::ERR_MODULE_PARAM;
    }
    RuntimeControlRecordV3 record{};
    record.config_generation = config.config_generation;
    record.seed_generation = config.seed_generation;
    record.profile_fingerprint = config.profile_fingerprint;
    record.replacement_mode = static_cast<uint32_t>(config.mode);
    record.virtual_id_length = config.virtual_id_length;
    std::memcpy(record.virtual_id,
                config.virtual_id.data(),
                config.virtual_id_length);
    return write_record(path, record);
}

KModErr migrate_runtime_control_v2(const char* v3_path, bool& migrated) {
    migrated = false;
    if (v3_path == nullptr || v3_path[0] == '\0') {
        return KModErr::ERR_MODULE_PARAM;
    }

    RuntimeControlRecordV3 current{};
    const KModErr v3_err = read_exact_record(v3_path, current);
    if (is_ok(v3_err)) {
        return validate_v3_record(current) ? KModErr::OK
                                           : KModErr::ERR_MODULE_STORAGE_TYPE;
    }
    if (v3_err != KModErr::ERR_MODULE_STORAGE_NOT_FOUND) return v3_err;

    RuntimeControlRecordV2 legacy{};
    const std::string legacy_path =
        sibling_path(v3_path, "drmid_runtime_control_v2.bin");
    const KModErr legacy_err = read_exact_record(legacy_path.c_str(), legacy);
    if (legacy_err == KModErr::ERR_MODULE_STORAGE_NOT_FOUND) {
        return KModErr::OK;
    }
    if (is_failed(legacy_err)) return legacy_err;
    if (!validate_v2_record(legacy)) {
        return KModErr::ERR_MODULE_STORAGE_TYPE;
    }

    ReplacementConfig converted{};
    converted.config_generation = legacy.config_generation;
    converted.seed_generation = legacy.seed_generation;
    converted.profile_fingerprint = legacy.profile_fingerprint;
    converted.mode =
        static_cast<ReplacementMode>(legacy.replacement_mode);
    converted.virtual_id_length = legacy.virtual_id_length;
    std::memcpy(converted.virtual_id.data(),
                legacy.virtual_id,
                legacy.virtual_id_length);
    RETURN_IF_ERROR(write_runtime_control_file(v3_path, converted));

    ReplacementConfig verified{};
    RETURN_IF_ERROR(read_runtime_control_file(v3_path, verified));
    if (verified.config_generation != converted.config_generation ||
        verified.seed_generation != converted.seed_generation ||
        verified.profile_fingerprint != converted.profile_fingerprint ||
        verified.mode != converted.mode ||
        verified.virtual_id_length != converted.virtual_id_length ||
        verified.virtual_id != converted.virtual_id) {
        return KModErr::ERR_MODULE_STORAGE_READ;
    }
    migrated = true;
    return KModErr::OK;
}

std::string default_runtime_control_path(const char* module_private_dir) {
    if (module_private_dir == nullptr || module_private_dir[0] == '\0') {
        return {};
    }
    std::string path(module_private_dir);
    if (path.back() != '/') path.push_back('/');
    path += "drmid_runtime_control_v3.bin";
    return path;
}

} // namespace drmid
