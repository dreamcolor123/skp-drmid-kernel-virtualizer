#include "device_id_fingerprint.h"

#include <media/NdkMediaDrm.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include "runtime_profile.h"

namespace drmid {
namespace {

constexpr char kRecordName[] = "drmid_original_fingerprint_v1.bin";
constexpr char kTemporaryName[] = "drmid_original_fingerprint_v1.bin.tmp";
constexpr uint64_t kRecordMagic = 0x3147504644495244ULL; // "DRIDFPG1"
constexpr uint32_t kRecordVersion = 1;
constexpr uint32_t kWidevineIdBytes = 32;

struct OriginalFingerprintRecord {
    uint64_t magic;
    uint32_t version;
    uint32_t id_length;
    uint64_t fingerprint;
    uint32_t crc32;
    uint32_t reserved;
};

static_assert(sizeof(OriginalFingerprintRecord) == 32);
static_assert(offsetof(OriginalFingerprintRecord, crc32) == 24);

uint32_t crc32(const void* data, size_t size) {
    uint32_t value = 0xffffffffU;
    const auto* bytes = static_cast<const uint8_t*>(data);
    for (size_t index = 0; index < size; ++index) {
        value ^= bytes[index];
        for (int bit = 0; bit < 8; ++bit) {
            const uint32_t mask = 0U - (value & 1U);
            value = (value >> 1) ^ (0xedb88320U & mask);
        }
    }
    return value ^ 0xffffffffU;
}

bool valid_record(const OriginalFingerprintRecord& record) {
    return record.magic == kRecordMagic &&
           record.version == kRecordVersion &&
           record.id_length == kWidevineIdBytes &&
           record.fingerprint != 0 && record.reserved == 0 &&
           record.crc32 ==
               crc32(&record, offsetof(OriginalFingerprintRecord, crc32));
}

KModErr open_private_directory(const char* path, int& directory_fd) {
    directory_fd = -1;
    if (path == nullptr || path[0] == '\0') {
        return KModErr::ERR_MODULE_PARAM;
    }
    directory_fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    return directory_fd >= 0 ? KModErr::OK
                             : KModErr::ERR_MODULE_STORAGE_READ;
}

bool read_exact(int fd, void* data, size_t size) {
    size_t used = 0;
    while (used < size) {
        const ssize_t count = read(
            fd, static_cast<uint8_t*>(data) + used, size - used);
        if (count > 0) {
            used += static_cast<size_t>(count);
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    uint8_t extra = 0;
    return read(fd, &extra, 1) == 0;
}

bool write_exact(int fd, const void* data, size_t size) {
    size_t written = 0;
    while (written < size) {
        const ssize_t count = write(
            fd, static_cast<const uint8_t*>(data) + written, size - written);
        if (count > 0) {
            written += static_cast<size_t>(count);
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

KModErr read_record_at(int directory_fd, OriginalFingerprintRecord& record) {
    record = {};
    const int fd = openat(directory_fd,
                          kRecordName,
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return errno == ENOENT ? KModErr::ERR_MODULE_STORAGE_NOT_FOUND
                              : KModErr::ERR_MODULE_STORAGE_READ;
    }
    struct stat info {};
    const bool regular = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
                         info.st_size == sizeof(record);
    const bool read_ok = regular && read_exact(fd, &record, sizeof(record));
    close(fd);
    if (!read_ok || !valid_record(record)) {
        record = {};
        return KModErr::ERR_MODULE_STORAGE_TYPE;
    }
    return KModErr::OK;
}

KModErr write_record_at(int directory_fd,
                        OriginalFingerprintRecord& record) {
    record.crc32 =
        crc32(&record, offsetof(OriginalFingerprintRecord, crc32));
    if (!valid_record(record)) return KModErr::ERR_MODULE_PARAM;

    const int fd = openat(directory_fd,
                          kTemporaryName,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                          0600);
    if (fd < 0) return KModErr::ERR_MODULE_STORAGE_WRITE;
    struct stat info {};
    const bool regular = fstat(fd, &info) == 0 && S_ISREG(info.st_mode);
    const bool file_ok = regular && write_exact(fd, &record, sizeof(record)) &&
                         fsync(fd) == 0;
    close(fd);
    if (!file_ok ||
        renameat(directory_fd,
                 kTemporaryName,
                 directory_fd,
                 kRecordName) != 0) {
        unlinkat(directory_fd, kTemporaryName, 0);
        return KModErr::ERR_MODULE_STORAGE_WRITE;
    }
    if (fsync(directory_fd) != 0) {
        return KModErr::ERR_MODULE_STORAGE_WRITE;
    }
    return KModErr::OK;
}

KModErr query_original_widevine_fingerprint(uint64_t& fingerprint) {
    fingerprint = 0;
    constexpr uint8_t kWidevineUuid[16] = {
        0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce,
        0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed,
    };
    AMediaDrm* drm = AMediaDrm_createByUUID(kWidevineUuid);
    if (drm == nullptr) return KModErr::ERR_MODULE_STORAGE_READ;
    AMediaDrmByteArray value{};
    const media_status_t status =
        AMediaDrm_getPropertyByteArray(drm, "deviceUniqueId", &value);
    if (status == AMEDIA_OK && value.ptr != nullptr &&
        value.length == kWidevineIdBytes) {
        fingerprint = virtual_id_fingerprint(value.ptr, value.length);
    }
    AMediaDrm_release(drm);
    return fingerprint != 0 ? KModErr::OK
                            : KModErr::ERR_MODULE_STORAGE_READ;
}

} // namespace

KModErr read_original_id_fingerprint(const char* module_private_dir,
                                      uint64_t& fingerprint) {
    fingerprint = 0;
    int directory_fd = -1;
    RETURN_IF_ERROR(open_private_directory(module_private_dir, directory_fd));
    OriginalFingerprintRecord record{};
    const KModErr err = read_record_at(directory_fd, record);
    close(directory_fd);
    if (is_ok(err)) fingerprint = record.fingerprint;
    return err;
}

KModErr capture_original_id_fingerprint_if_missing(
    const char* module_private_dir,
    uint64_t& fingerprint) {
    fingerprint = 0;
    int directory_fd = -1;
    RETURN_IF_ERROR(open_private_directory(module_private_dir, directory_fd));

    OriginalFingerprintRecord record{};
    const KModErr read_err = read_record_at(directory_fd, record);
    if (is_ok(read_err)) {
        fingerprint = record.fingerprint;
        close(directory_fd);
        return KModErr::OK;
    }
    if (read_err != KModErr::ERR_MODULE_STORAGE_NOT_FOUND) {
        close(directory_fd);
        return read_err;
    }

    uint64_t observed = 0;
    const KModErr query_err = query_original_widevine_fingerprint(observed);
    if (is_failed(query_err)) {
        close(directory_fd);
        return query_err;
    }
    record.magic = kRecordMagic;
    record.version = kRecordVersion;
    record.id_length = kWidevineIdBytes;
    record.fingerprint = observed;
    const KModErr write_err = write_record_at(directory_fd, record);
    close(directory_fd);
    if (is_ok(write_err)) fingerprint = observed;
    return write_err;
}

} // namespace drmid
