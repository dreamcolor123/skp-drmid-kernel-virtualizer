#include "tee_firmware_identity.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>

namespace drmid {
namespace {

bool pread_exact(int fd, void* output, size_t size, off_t offset) {
    auto* bytes = static_cast<uint8_t*>(output);
    size_t used = 0;
    while (used < size) {
        const ssize_t count = pread(
            fd, bytes + used, size - used, offset + static_cast<off_t>(used));
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

} // namespace

KModErr read_tee_firmware_identity(const char* path,
                                   uint64_t generation,
                                   TeeFirmwareIdentity& identity) {
    identity = {};
    if (path == nullptr || path[0] == '\0' || generation == 0) {
        return KModErr::ERR_MODULE_PARAM;
    }

    const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return errno == ENOENT ? KModErr::ERR_MODULE_STORAGE_NOT_FOUND
                              : KModErr::ERR_MODULE_STORAGE_READ;
    }
    struct stat info {};
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 0 ||
        static_cast<uint64_t>(info.st_size) < kTeeFirmwareMinimumBytes ||
        static_cast<uint64_t>(info.st_size) > kTeeFirmwareMaximumBytes) {
        close(fd);
        return KModErr::ERR_MODULE_STORAGE_TYPE;
    }

    TeeFirmwareIdentity next{};
    next.generation = generation;
    next.file_size = static_cast<uint64_t>(info.st_size);
    next.edge_bytes = kTeeFirmwareEdgeBytes;
    const off_t suffix_offset =
        info.st_size - static_cast<off_t>(kTeeFirmwareEdgeBytes);
    const bool ok = pread_exact(fd,
                                next.prefix.data(),
                                next.prefix.size(),
                                0) &&
                    pread_exact(fd,
                                next.suffix.data(),
                                next.suffix.size(),
                                suffix_offset);
    const bool close_ok = close(fd) == 0;
    if (!ok || !close_ok) {
        return KModErr::ERR_MODULE_STORAGE_READ;
    }
    next.path = path;
    identity = next;
    return KModErr::OK;
}

KModErr discover_tee_firmware_identity(
    uint64_t generation,
    TeeFirmwareIdentity& identity,
    const std::vector<std::string>* candidate_override) {
    identity = {};
    static const std::vector<std::string> kDefaultCandidates = {
        "/vendor/firmware_mnt/image/widevine.mbn",
        "/vendor/firmware/widevine.mbn",
        "/vendor/etc/firmware/widevine.mbn",
        "/system/etc/firmware/widevine.mbn",
    };
    const auto& candidates = candidate_override != nullptr
                                 ? *candidate_override
                                 : kDefaultCandidates;
    KModErr last_error = KModErr::ERR_MODULE_STORAGE_NOT_FOUND;
    for (const std::string& path : candidates) {
        TeeFirmwareIdentity candidate;
        const KModErr err = read_tee_firmware_identity(
            path.c_str(), generation, candidate);
        if (is_ok(err)) {
            identity = candidate;
            return KModErr::OK;
        }
        if (err != KModErr::ERR_MODULE_STORAGE_NOT_FOUND) {
            last_error = err;
        }
    }
    return last_error;
}

} // namespace drmid
