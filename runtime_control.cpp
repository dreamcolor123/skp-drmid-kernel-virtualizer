#include "runtime_control.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace drmid {
namespace {

constexpr uint64_t kRuntimeControlV1Magic = 0x38304c54434d5244ULL;
constexpr uint32_t kRuntimeControlV1Version = 1;

struct RuntimeControlRecordV1 {
    uint64_t magic;
    uint32_t version;
    uint32_t record_size;
    uint64_t config_generation;
    uint64_t seed_generation;
    uint64_t profile_fingerprint;
    uint32_t replacement_mode;
    uint32_t rule_mode;
    uint32_t target_euid;
    uint32_t virtual_id_length;
    uint8_t virtual_id[64];
    uint32_t crc32;
    uint32_t tail_reserved;
};

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
    uint32_t target_euids[kRuntimeTargetLimit];
    uint8_t virtual_id[64];
    uint32_t crc32;
    uint32_t tail_reserved;
};

static_assert(sizeof(RuntimeControlRecordV1) == 128);
static_assert(offsetof(RuntimeControlRecordV1, crc32) == 120);
static_assert(sizeof(RuntimeControlRecordV2) == kRuntimeControlRecordBytes);
static_assert(offsetof(RuntimeControlRecordV2, target_euids) == 56);
static_assert(offsetof(RuntimeControlRecordV2, virtual_id) == 184);
static_assert(offsetof(RuntimeControlRecordV2, crc32) == 248);

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

bool valid_target_set(uint32_t rule_mode,
                      uint32_t target_count,
                      const uint32_t* target_euids) {
    if (rule_mode > 2 || target_count > kRuntimeTargetLimit) return false;
    if (rule_mode == 0) {
        if (target_count != 0) return false;
    } else if (target_count == 0) {
        return false;
    }
    for (size_t index = 0; index < kRuntimeTargetLimit; ++index) {
        if (index < target_count) {
            if (target_euids[index] == 0 ||
                (index != 0 && target_euids[index - 1] >= target_euids[index])) {
                return false;
            }
        } else if (target_euids[index] != 0) {
            return false;
        }
    }
    return true;
}

bool validate_v1_record(const RuntimeControlRecordV1& record) {
    if (record.magic != kRuntimeControlV1Magic ||
        record.version != kRuntimeControlV1Version ||
        record.record_size != sizeof(record) ||
        record.config_generation == 0 || record.seed_generation == 0 ||
        record.replacement_mode >
            static_cast<uint32_t>(ReplacementMode::kWriteTest) ||
        record.rule_mode > 2 || record.virtual_id_length == 0 ||
        record.virtual_id_length > sizeof(record.virtual_id) ||
        record.tail_reserved != 0 ||
        record.crc32 !=
            crc32(&record, offsetof(RuntimeControlRecordV1, crc32))) {
        return false;
    }
    return record.rule_mode == 0 ? record.target_euid == 0
                                 : record.target_euid != 0;
}

bool validate_v2_record(const RuntimeControlRecordV2& record) {
    return record.magic == kRuntimeControlMagic &&
           record.version == kRuntimeControlVersion &&
           record.record_size == sizeof(record) &&
           record.config_generation != 0 && record.seed_generation != 0 &&
           record.replacement_mode <=
               static_cast<uint32_t>(ReplacementMode::kWriteTest) &&
           valid_target_set(record.rule_mode,
                            record.target_count,
                            record.target_euids) &&
           record.virtual_id_length != 0 &&
           record.virtual_id_length <= sizeof(record.virtual_id) &&
           record.tail_reserved == 0 &&
           record.crc32 ==
               crc32(&record, offsetof(RuntimeControlRecordV2, crc32));
}

bool validate_config(const ReplacementConfig& config) {
    return config.config_generation != 0 && config.seed_generation != 0 &&
           static_cast<uint32_t>(config.mode) <=
               static_cast<uint32_t>(ReplacementMode::kWriteTest) &&
           valid_target_set(config.rule_mode,
                            config.target_count,
                            config.target_euids.data()) &&
           config.virtual_id_length != 0 &&
           config.virtual_id_length <= config.virtual_id.size();
}

KModErr write_record(const char* path, RuntimeControlRecordV2& record) {
    record.magic = kRuntimeControlMagic;
    record.version = kRuntimeControlVersion;
    record.record_size = sizeof(record);
    record.crc32 = crc32(&record, offsetof(RuntimeControlRecordV2, crc32));
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

std::string sibling_v1_path(const char* v2_path) {
    std::string path(v2_path);
    const size_t slash = path.find_last_of('/');
    path = slash == std::string::npos ? std::string()
                                      : path.substr(0, slash + 1);
    path += "drmid_runtime_control_v1.bin";
    return path;
}

} // namespace

KModErr read_runtime_control_file(const char* path,
                                  ReplacementConfig& config) {
    config = {};
    if (path == nullptr || path[0] == '\0') {
        return KModErr::ERR_MODULE_PARAM;
    }
    RuntimeControlRecordV2 record{};
    RETURN_IF_ERROR(read_exact_record(path, record));
    if (!validate_v2_record(record)) {
        return KModErr::ERR_MODULE_STORAGE_TYPE;
    }
    config.config_generation = record.config_generation;
    config.seed_generation = record.seed_generation;
    config.profile_fingerprint = record.profile_fingerprint;
    config.mode = static_cast<ReplacementMode>(record.replacement_mode);
    config.rule_mode = record.rule_mode;
    config.target_count = record.target_count;
    config.virtual_id_length = record.virtual_id_length;
    std::copy(record.target_euids,
              record.target_euids + kRuntimeTargetLimit,
              config.target_euids.begin());
    std::memcpy(config.virtual_id.data(),
                record.virtual_id,
                record.virtual_id_length);
    return KModErr::OK;
}

KModErr write_runtime_control_file(const char* path,
                                   const ReplacementConfig& config) {
    if (path == nullptr || path[0] == '\0' || !validate_config(config)) {
        return KModErr::ERR_MODULE_PARAM;
    }
    RuntimeControlRecordV2 record{};
    record.config_generation = config.config_generation;
    record.seed_generation = config.seed_generation;
    record.profile_fingerprint = config.profile_fingerprint;
    record.replacement_mode = static_cast<uint32_t>(config.mode);
    record.rule_mode = config.rule_mode;
    record.target_count = config.target_count;
    record.virtual_id_length = config.virtual_id_length;
    std::copy(config.target_euids.begin(),
              config.target_euids.end(),
              record.target_euids);
    std::memcpy(record.virtual_id,
                config.virtual_id.data(),
                config.virtual_id_length);
    return write_record(path, record);
}

KModErr migrate_runtime_control_v1(const char* v2_path,
                                   const ReplacementConfig& target_template,
                                   bool& migrated) {
    migrated = false;
    if (v2_path == nullptr || v2_path[0] == '\0' ||
        !validate_config(target_template)) {
        return KModErr::ERR_MODULE_PARAM;
    }
    RuntimeControlRecordV2 existing{};
    const KModErr v2_err = read_exact_record(v2_path, existing);
    if (is_ok(v2_err)) {
        return validate_v2_record(existing) ? KModErr::OK
                                            : KModErr::ERR_MODULE_STORAGE_TYPE;
    }
    if (v2_err != KModErr::ERR_MODULE_STORAGE_NOT_FOUND) return v2_err;

    RuntimeControlRecordV1 old_record{};
    const KModErr v1_err =
        read_exact_record(sibling_v1_path(v2_path).c_str(), old_record);
    if (v1_err == KModErr::ERR_MODULE_STORAGE_NOT_FOUND) return KModErr::OK;
    if (is_failed(v1_err)) return v1_err;
    if (!validate_v1_record(old_record) ||
        old_record.rule_mode != target_template.rule_mode ||
        (old_record.rule_mode != 0 &&
         (target_template.target_count != 1 ||
          target_template.target_euids[0] != old_record.target_euid))) {
        return KModErr::ERR_MODULE_STORAGE_TYPE;
    }

    ReplacementConfig converted = target_template;
    converted.mode =
        static_cast<ReplacementMode>(old_record.replacement_mode);
    converted.config_generation =
        std::max(target_template.config_generation,
                 old_record.config_generation);
    converted.seed_generation = old_record.seed_generation;
    converted.profile_fingerprint = old_record.profile_fingerprint;
    converted.virtual_id_length = old_record.virtual_id_length;
    std::memset(converted.virtual_id.data(), 0, converted.virtual_id.size());
    std::memcpy(converted.virtual_id.data(),
                old_record.virtual_id,
                old_record.virtual_id_length);
    RETURN_IF_ERROR(write_runtime_control_file(v2_path, converted));
    migrated = true;
    return KModErr::OK;
}

std::string default_runtime_control_path(const char* module_private_dir) {
    if (module_private_dir == nullptr || module_private_dir[0] == '\0') {
        return {};
    }
    std::string path(module_private_dir);
    if (path.back() != '/') path.push_back('/');
    path += "drmid_runtime_control_v2.bin";
    return path;
}

} // namespace drmid
