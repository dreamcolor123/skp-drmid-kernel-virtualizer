#include "file_lifecycle.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>

namespace drmid {
namespace {

constexpr char kLegacyPublicMarker[] =
    "/data/local/tmp/drmid_disable_boot_cleanup";
constexpr char kPublicTemporaryDirectory[] = "/data/local/tmp";
constexpr char kSeedTempPrefix[] = "drmid_seed_record_v1.bin.tmp.";
constexpr char kDaemonLockName[] = "drmid_daemon_v1.lock";
constexpr const char* kLegacyDevelopmentPayloads[] = {
    "drmid-0.9.0-rc10.zip",
    "drmid-0.9.0-rc12.zip",
    "drmid_aidl_probe",
    "drmid_probe_runner",
    "drmid_rc13.zip",
    "drmid_rc13_runner",
    "drmid_rc14.zip",
    "drmid_rc14_runner",
};

void reset_lock_handle(DaemonLockHandle& handle) {
    handle.directory_fd = -1;
    handle.lock_fd = -1;
    handle.device = 0;
    handle.inode = 0;
}

bool write_all(int fd, const char* data, size_t size) {
    size_t written = 0;
    while (written < size) {
        const ssize_t count = write(fd, data + written, size - written);
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

} // namespace

bool is_seed_temp_orphan_name(const char* name) {
    if (name == nullptr) return false;
    const size_t prefix_length = sizeof(kSeedTempPrefix) - 1;
    if (std::strncmp(name, kSeedTempPrefix, prefix_length) != 0) {
        return false;
    }
    const char* suffix = name + prefix_length;
    if (*suffix == '\0') return false;
    for (const char* cursor = suffix; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') return false;
    }
    return true;
}

bool is_legacy_development_payload_name(const char* name) {
    if (name == nullptr || name[0] == '\0') return false;
    for (const char* expected : kLegacyDevelopmentPayloads) {
        if (std::strcmp(name, expected) == 0) return true;
    }
    return false;
}

size_t cleanup_legacy_development_payloads(const char* public_tmp_dir) {
    if (public_tmp_dir == nullptr || public_tmp_dir[0] == '\0') return 0;
    const int directory_fd = open(public_tmp_dir,
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                      O_NOFOLLOW);
    if (directory_fd < 0) return 0;
    DIR* directory = fdopendir(directory_fd);
    if (directory == nullptr) {
        close(directory_fd);
        return 0;
    }

    size_t removed = 0;
    const int owned_fd = dirfd(directory);
    errno = 0;
    while (dirent* entry = readdir(directory)) {
        if (!is_legacy_development_payload_name(entry->d_name)) continue;
        struct stat info {};
        if (fstatat(owned_fd,
                    entry->d_name,
                    &info,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISREG(info.st_mode)) {
            continue;
        }
        if (unlinkat(owned_fd, entry->d_name, 0) == 0) ++removed;
    }
    closedir(directory);
    return removed;
}

size_t cleanup_seed_temp_orphans(const char* module_private_dir) {
    if (module_private_dir == nullptr || module_private_dir[0] == '\0') {
        return 0;
    }
    const int directory_fd = open(module_private_dir,
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                      O_NOFOLLOW);
    if (directory_fd < 0) return 0;
    DIR* directory = fdopendir(directory_fd);
    if (directory == nullptr) {
        close(directory_fd);
        return 0;
    }

    size_t removed = 0;
    const int owned_fd = dirfd(directory);
    errno = 0;
    while (dirent* entry = readdir(directory)) {
        if (!is_seed_temp_orphan_name(entry->d_name)) continue;
        struct stat info {};
        if (fstatat(owned_fd,
                    entry->d_name,
                    &info,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISREG(info.st_mode)) {
            continue;
        }
        if (unlinkat(owned_fd, entry->d_name, 0) == 0) {
            ++removed;
        }
    }
    closedir(directory);
    return removed;
}

void cleanup_legacy_public_marker() {
    if (unlink(kLegacyPublicMarker) != 0 && errno != ENOENT) {
        // Compatibility cleanup is deliberately silent and best-effort.
    }
}

void cleanup_legacy_public_artifacts() {
    cleanup_legacy_public_marker();
    cleanup_legacy_development_payloads(kPublicTemporaryDirectory);
}

size_t cleanup_legacy_target_state_after_global_migration(
    const char* module_private_dir) {
    if (module_private_dir == nullptr || module_private_dir[0] == '\0') {
        return 0;
    }
    const int directory_fd = open(module_private_dir,
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                      O_NOFOLLOW);
    if (directory_fd < 0) return 0;
    constexpr const char* kLegacyTargetFiles[] = {
        "drmid_runtime_control_v1.bin",
        "drmid_runtime_control_v1.bin.tmp",
        "drmid_runtime_control_v2.bin",
        "drmid_runtime_control_v2.bin.tmp",
        "drmid_target_config_v1.bin",
        "drmid_target_config_v1.bin.tmp",
        "drmid_target_config_v2.bin",
        "drmid_target_config_v2.bin.tmp",
        "drmid_label_helper.jar",
    };
    size_t removed = 0;
    for (const char* name : kLegacyTargetFiles) {
        struct stat info {};
        if (fstatat(directory_fd, name, &info, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISREG(info.st_mode)) {
            continue;
        }
        if (unlinkat(directory_fd, name, 0) == 0) ++removed;
    }
    if (removed != 0) fsync(directory_fd);
    close(directory_fd);
    return removed;
}

void cleanup_module_state_files(const char* module_private_dir) {
    cleanup_legacy_public_artifacts();
    if (module_private_dir == nullptr || module_private_dir[0] == '\0') return;

    cleanup_seed_temp_orphans(module_private_dir);
    constexpr const char* kStateFiles[] = {
        "drmid_control_v1.sock",
        "drmid_control_v2.sock",
        "drmid_control_v3.sock",
        "drmid_control_v4.sock",
        "drmid_runtime_control_v1.bin",
        "drmid_runtime_control_v1.bin.tmp",
        "drmid_runtime_control_v2.bin",
        "drmid_runtime_control_v2.bin.tmp",
        "drmid_runtime_control_v3.bin",
        "drmid_runtime_control_v3.bin.tmp",
        "drmid_target_config_v1.bin",
        "drmid_target_config_v1.bin.tmp",
        "drmid_target_config_v2.bin",
        "drmid_target_config_v2.bin.tmp",
        "drmid_seed_record_v1.bin",
        "drmid_seed_record_v1.bin.tmp",
        "drmid_original_fingerprint_v1.bin",
        "drmid_original_fingerprint_v1.bin.tmp",
        "drmid_label_helper.jar",
        kDaemonLockName,
        "drmid_boot_cleanup.flag",
        "webroot/drmid_boot_cleanup.flag",
    };
    for (const char* name : kStateFiles) {
        std::string path(module_private_dir);
        if (path.back() != '/') path.push_back('/');
        path += name;
        if (unlink(path.c_str()) != 0 && errno != ENOENT) {
            std::printf("[drmid612] state cleanup failed path=%s errno=%d\n",
                        path.c_str(),
                        errno);
        }
    }
}

bool acquire_daemon_lock(const char* module_private_dir,
                         DaemonLockHandle& handle) {
    reset_lock_handle(handle);
    if (module_private_dir == nullptr || module_private_dir[0] == '\0') {
        return false;
    }
    handle.directory_fd = open(module_private_dir,
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                   O_NOFOLLOW);
    if (handle.directory_fd < 0) return false;

    handle.lock_fd = openat(handle.directory_fd,
                            kDaemonLockName,
                            O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
                            0600);
    if (handle.lock_fd < 0 ||
        flock(handle.lock_fd, LOCK_EX | LOCK_NB) != 0) {
        if (handle.lock_fd >= 0) close(handle.lock_fd);
        close(handle.directory_fd);
        reset_lock_handle(handle);
        return false;
    }

    struct stat info {};
    if (fstat(handle.lock_fd, &info) != 0 || !S_ISREG(info.st_mode)) {
        flock(handle.lock_fd, LOCK_UN);
        close(handle.lock_fd);
        close(handle.directory_fd);
        reset_lock_handle(handle);
        return false;
    }
    handle.device = info.st_dev;
    handle.inode = info.st_ino;
    return true;
}

bool write_daemon_lock_pid(const DaemonLockHandle& handle, pid_t pid) {
    if (handle.lock_fd < 0 || ftruncate(handle.lock_fd, 0) != 0) {
        return false;
    }
    const std::string text = std::to_string(static_cast<long>(pid)) + "\n";
    return write_all(handle.lock_fd, text.data(), text.size()) &&
           fsync(handle.lock_fd) == 0;
}

bool daemon_lock_owner_alive(const char* module_private_dir, pid_t& pid) {
    pid = -1;
    if (module_private_dir == nullptr || module_private_dir[0] == '\0') {
        return false;
    }
    const int directory_fd = open(module_private_dir,
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                      O_NOFOLLOW);
    if (directory_fd < 0) return false;
    const int lock_fd = openat(directory_fd,
                               kDaemonLockName,
                               O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    close(directory_fd);
    if (lock_fd < 0) return false;
    struct stat info {};
    if (fstat(lock_fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_size <= 1 || info.st_size > 31) {
        close(lock_fd);
        return false;
    }
    // A successfully acquired probe lock means the path is stale rather than
    // owned by the running daemon. Never unlink it from the WebUI path.
    if (flock(lock_fd, LOCK_EX | LOCK_NB) == 0) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        return false;
    }
    if (errno != EWOULDBLOCK && errno != EAGAIN) {
        close(lock_fd);
        return false;
    }
    char text[32]{};
    const ssize_t count = pread(lock_fd, text, sizeof(text) - 1, 0);
    close(lock_fd);
    if (count <= 1 || count >= static_cast<ssize_t>(sizeof(text))) return false;
    text[count] = '\0';
    char* end = nullptr;
    errno = 0;
    const long value = std::strtol(text, &end, 10);
    if (errno != 0 || end == text ||
        (*end != '\n' && *end != '\0') ||
        (*end == '\n' && end[1] != '\0') || value <= 1 ||
        value > std::numeric_limits<pid_t>::max()) {
        return false;
    }
    const pid_t candidate = static_cast<pid_t>(value);
    if (kill(candidate, 0) != 0 && errno != EPERM) return false;
    pid = candidate;
    return true;
}

void release_daemon_lock(DaemonLockHandle& handle) {
    if (handle.lock_fd < 0) {
        if (handle.directory_fd >= 0) close(handle.directory_fd);
        reset_lock_handle(handle);
        return;
    }

    if (handle.directory_fd >= 0) {
        struct stat current {};
        if (fstatat(handle.directory_fd,
                    kDaemonLockName,
                    &current,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
            current.st_dev == handle.device &&
            current.st_ino == handle.inode) {
            if (unlinkat(handle.directory_fd, kDaemonLockName, 0) == 0) {
                fsync(handle.directory_fd);
            }
        }
    }

    flock(handle.lock_fd, LOCK_UN);
    close(handle.lock_fd);
    if (handle.directory_fd >= 0) close(handle.directory_fd);
    reset_lock_handle(handle);
}

} // namespace drmid
