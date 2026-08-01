#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "control_ipc.h"
#include "kernel_module_kit_umbrella.h"

namespace {

constexpr char kModuleId[] = "drmidKern612Probe20260728Alpha01";
constexpr char kLegacyMarker[] =
    "/data/local/tmp/drmid_disable_boot_cleanup";
constexpr char kPrivateSuffix[] =
    "/modules/drmidKern612Probe20260728Alpha01";
constexpr char kDaemonExeSuffix[] =
    "/modules/drmidKern612Probe20260728Alpha01/webroot/drmid_daemon";

constexpr char kFixtureOrphan[] = "drmid_seed_record_v1.bin.tmp.424242";
constexpr char kFixtureNonNumeric[] = "drmid_seed_record_v1.bin.tmp.pid";
constexpr char kFixtureSymlink[] = "drmid_seed_record_v1.bin.tmp.424243";
constexpr char kFixtureDirectory[] = "drmid_seed_record_v1.bin.tmp.424244";
constexpr char kFixtureAdjacent[] = "other.tmp.123";

bool ends_with(std::string_view value, std::string_view suffix) {
    return value.size() >= suffix.size() &&
           value.substr(value.size() - suffix.size()) == suffix;
}

bool all_decimal(std::string_view value) {
    if (value.empty()) return false;
    return std::all_of(value.begin(), value.end(), [](char ch) {
        return ch >= '0' && ch <= '9';
    });
}

bool read_link(const std::string& path, std::string& output) {
    std::vector<char> buffer(4096);
    const ssize_t size = readlink(path.c_str(), buffer.data(), buffer.size() - 1);
    if (size <= 0 || static_cast<size_t>(size) >= buffer.size()) return false;
    buffer[static_cast<size_t>(size)] = '\0';
    output.assign(buffer.data(), static_cast<size_t>(size));
    return true;
}

bool validate_private_dir(const std::string& path) {
    return ends_with(path, kPrivateSuffix) &&
           path.size() > std::strlen(kPrivateSuffix) &&
           path.front() == '/' && path.find("/../") == std::string::npos;
}

bool find_private_dir_from_proc(std::string& output) {
    DIR* proc = opendir("/proc");
    if (proc == nullptr) return false;
    std::string match;
    size_t matches = 0;
    while (dirent* entry = readdir(proc)) {
        if (!all_decimal(entry->d_name)) continue;
        std::string exe_path = "/proc/";
        exe_path += entry->d_name;
        exe_path += "/exe";
        std::string exe;
        if (!read_link(exe_path, exe)) {
            continue;
        }
        constexpr std::string_view kDeletedSuffix = " (deleted)";
        if (ends_with(exe, kDeletedSuffix)) {
            exe.resize(exe.size() - kDeletedSuffix.size());
        }
        if (!ends_with(exe, kDaemonExeSuffix)) {
            continue;
        }
        const size_t private_size =
            exe.size() - std::strlen("/webroot/drmid_daemon");
        std::string candidate = exe.substr(0, private_size);
        if (!validate_private_dir(candidate)) continue;
        match = std::move(candidate);
        ++matches;
    }
    closedir(proc);
    if (matches != 1) return false;
    output = std::move(match);
    return true;
}

bool is_directory_at(int parent_fd, const char* name) {
    struct stat info {};
    return fstatat(parent_fd, name, &info, AT_SYMLINK_NOFOLLOW) == 0 &&
           S_ISDIR(info.st_mode);
}

bool find_private_dir_from_data(std::string& output) {
    const int data_fd = open("/data", O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                         O_NOFOLLOW);
    if (data_fd < 0) return false;
    DIR* data = fdopendir(data_fd);
    if (data == nullptr) {
        close(data_fd);
        return false;
    }

    std::string match;
    size_t matches = 0;
    const int owned_data_fd = dirfd(data);
    while (dirent* entry = readdir(data)) {
        if (entry->d_name[0] == '.' ||
            !is_directory_at(owned_data_fd, entry->d_name)) {
            continue;
        }
        const int root_fd = openat(owned_data_fd,
                                   entry->d_name,
                                   O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                       O_NOFOLLOW);
        if (root_fd < 0) continue;
        const int modules_fd = openat(root_fd,
                                      "modules",
                                      O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                          O_NOFOLLOW);
        close(root_fd);
        if (modules_fd < 0) continue;
        const bool found = is_directory_at(modules_fd, kModuleId);
        close(modules_fd);
        if (!found) continue;

        std::string candidate = "/data/";
        candidate += entry->d_name;
        candidate += kPrivateSuffix;
        if (!validate_private_dir(candidate)) continue;
        match = std::move(candidate);
        ++matches;
    }
    closedir(data);
    if (matches != 1) return false;
    output = std::move(match);
    return true;
}

bool find_private_dir(std::string& output) {
    if (find_private_dir_from_proc(output)) return true;
    return find_private_dir_from_data(output);
}

const char* file_kind(mode_t mode) {
    if (S_ISREG(mode)) return "regular";
    if (S_ISLNK(mode)) return "symlink";
    if (S_ISDIR(mode)) return "directory";
    if (S_ISSOCK(mode)) return "socket";
    return "other";
}

void print_path_state_at(int directory_fd,
                         const char* label,
                         const char* name,
                         bool with_crc) {
    struct stat info {};
    if (fstatat(directory_fd, name, &info, AT_SYMLINK_NOFOLLOW) != 0) {
        std::printf("%s=absent\n", label);
        return;
    }
    std::printf("%s=%s mode=%04o size=%" PRId64 " inode=%" PRIu64,
                label,
                file_kind(info.st_mode),
                static_cast<unsigned>(info.st_mode & 07777),
                static_cast<int64_t>(info.st_size),
                static_cast<uint64_t>(info.st_ino));
    if (with_crc && S_ISREG(info.st_mode)) {
        const int fd = openat(directory_fd,
                              name,
                              O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd >= 0) {
            uint64_t digest = 1469598103934665603ULL;
            char buffer[4096];
            bool ok = true;
            for (;;) {
                const ssize_t count = read(fd, buffer, sizeof(buffer));
                if (count > 0) {
                    for (ssize_t index = 0; index < count; ++index) {
                        digest ^= static_cast<unsigned char>(buffer[index]);
                        digest *= 1099511628211ULL;
                    }
                } else if (count == 0) {
                    break;
                } else if (errno != EINTR) {
                    ok = false;
                    break;
                }
            }
            close(fd);
            if (ok) std::printf(" fnv64=%016" PRIx64, digest);
        }
    }
    std::printf("\n");
}

void print_legacy_marker_state() {
    struct stat info {};
    if (lstat(kLegacyMarker, &info) != 0) {
        std::printf("legacy_marker=absent\n");
        return;
    }
    std::printf("legacy_marker=%s mode=%04o size=%" PRId64
                " inode=%" PRIu64 "\n",
                file_kind(info.st_mode),
                static_cast<unsigned>(info.st_mode & 07777),
                static_cast<int64_t>(info.st_size),
                static_cast<uint64_t>(info.st_ino));
}

bool write_regular_at(int directory_fd,
                      const char* name,
                      const char* content) {
    const int fd = openat(directory_fd,
                          name,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
                              O_NOFOLLOW,
                          0600);
    if (fd < 0) return false;
    const size_t length = std::strlen(content);
    size_t written = 0;
    while (written < length) {
        const ssize_t count = write(fd, content + written, length - written);
        if (count > 0) {
            written += static_cast<size_t>(count);
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            close(fd);
            return false;
        }
    }
    const bool ok = fsync(fd) == 0;
    close(fd);
    return ok;
}

void remove_fixture_at(int directory_fd,
                       const char* name,
                       bool directory) {
    if (unlinkat(directory_fd, name, directory ? AT_REMOVEDIR : 0) != 0 &&
        errno != ENOENT && !(directory && errno == ENOTDIR)) {
        std::fprintf(stderr, "fixture cleanup failed name=%s errno=%d\n",
                     name,
                     errno);
    }
}

bool prepare_fixtures(int directory_fd) {
    remove_fixture_at(directory_fd, kFixtureOrphan, false);
    remove_fixture_at(directory_fd, kFixtureNonNumeric, false);
    remove_fixture_at(directory_fd, kFixtureSymlink, false);
    remove_fixture_at(directory_fd, kFixtureAdjacent, false);
    remove_fixture_at(directory_fd, kFixtureDirectory, true);

    if (!write_regular_at(directory_fd, kFixtureOrphan, "orphan-fixture\n") ||
        !write_regular_at(directory_fd,
                          kFixtureNonNumeric,
                          "nonnumeric-fixture\n") ||
        !write_regular_at(directory_fd,
                          kFixtureAdjacent,
                          "adjacent-fixture\n") ||
        symlinkat("fixture-target-do-not-follow",
                  directory_fd,
                  kFixtureSymlink) != 0 ||
        mkdirat(directory_fd, kFixtureDirectory, 0700) != 0) {
        return false;
    }

    const int marker_fd = open(kLegacyMarker,
                               O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
                                   O_NOFOLLOW,
                               0600);
    if (marker_fd < 0) return false;
    constexpr char marker[] = "legacy-marker-fixture\n";
    const ssize_t written = write(marker_fd, marker, sizeof(marker) - 1);
    const bool marker_ok =
        written == static_cast<ssize_t>(sizeof(marker) - 1) &&
        fsync(marker_fd) == 0;
    close(marker_fd);
    return marker_ok && fsync(directory_fd) == 0;
}

void cleanup_fixtures(int directory_fd) {
    remove_fixture_at(directory_fd, kFixtureOrphan, false);
    remove_fixture_at(directory_fd, kFixtureNonNumeric, false);
    remove_fixture_at(directory_fd, kFixtureSymlink, false);
    remove_fixture_at(directory_fd, kFixtureAdjacent, false);
    remove_fixture_at(directory_fd, kFixtureDirectory, true);
    if (unlink(kLegacyMarker) != 0 && errno != ENOENT) {
        std::fprintf(stderr, "legacy marker cleanup failed errno=%d\n", errno);
    }
    fsync(directory_fd);
}

void inventory(int directory_fd) {
    print_legacy_marker_state();
    print_path_state_at(directory_fd, "seed", "drmid_seed_record_v1.bin", true);
    print_path_state_at(directory_fd,
                        "target_config",
                        "drmid_target_config_v2.bin",
                        true);
    print_path_state_at(directory_fd,
                        "runtime_control",
                        "drmid_runtime_control_v2.bin",
                        true);
    print_path_state_at(directory_fd,
                        "control_socket",
                        "drmid_control_v2.sock",
                        false);
    print_path_state_at(directory_fd,
                        "daemon_lock",
                        "drmid_daemon_v1.lock",
                        false);
    print_path_state_at(directory_fd,
                        "fixture_orphan",
                        kFixtureOrphan,
                        false);
    print_path_state_at(directory_fd,
                        "fixture_nonnumeric",
                        kFixtureNonNumeric,
                        false);
    print_path_state_at(directory_fd,
                        "fixture_symlink",
                        kFixtureSymlink,
                        false);
    print_path_state_at(directory_fd,
                        "fixture_directory",
                        kFixtureDirectory,
                        false);
    print_path_state_at(directory_fd,
                        "fixture_adjacent",
                        kFixtureAdjacent,
                        false);
}

int run_ipc_action(const std::string& private_dir,
                   drmid::ControlIpcOperation operation) {
    const std::string socket_path =
        drmid::default_control_socket_path(private_dir.c_str());
    drmid::ControlIpcResponse response{};
    const KModErr err =
        drmid::send_control_ipc_request(socket_path.c_str(), operation, response);
    if (is_failed(err)) {
        std::fprintf(stderr, "control IPC transport result=%s\n",
                     to_string(err).c_str());
        return 8;
    }
    std::printf("control=%s\n",
                drmid::control_response_json(response).c_str());
    return response.result == 0 ? 0 : 9;
}

} // namespace

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    std::string root_key;
    if (!std::getline(std::cin, root_key) || root_key.empty()) {
        std::fprintf(stderr, "missing root key on stdin\n");
        return 2;
    }
    const KModErr root_err = skroot_env::get_root(root_key.c_str());
    std::fill(root_key.begin(), root_key.end(), '\0');
    root_key.clear();
    if (is_failed(root_err)) {
        std::fprintf(stderr, "get_root result=%s\n", to_string(root_err).c_str());
        return 3;
    }

    const char* action_text = std::getenv("DRMID_LIFECYCLE_ACTION");
    const std::string action = action_text != nullptr ? action_text : "";
    if (action != "inventory" && action != "prepare" &&
        action != "cleanup-fixtures" && action != "ipc-status" &&
        action != "ipc-stop" && action != "ipc-stop-cleanup-fixtures") {
        std::fprintf(stderr, "invalid fixed lifecycle action\n");
        return 4;
    }

    std::string private_dir;
    if (!find_private_dir(private_dir)) {
        std::fprintf(stderr, "module private directory validation failed\n");
        return 5;
    }
    const int directory_fd = open(private_dir.c_str(),
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                      O_NOFOLLOW);
    if (directory_fd < 0) {
        std::fill(private_dir.begin(), private_dir.end(), '\0');
        std::fprintf(stderr, "module private directory open failed errno=%d\n",
                     errno);
        return 6;
    }

    std::printf("result=ok action=%s private_dir=validated\n", action.c_str());
    int result = 0;
    if (action == "ipc-status" || action == "ipc-stop" ||
        action == "ipc-stop-cleanup-fixtures") {
        result = run_ipc_action(
            private_dir,
            action == "ipc-status" ? drmid::ControlIpcOperation::kStatus
                                    : drmid::ControlIpcOperation::kStop);
        if (action != "ipc-status" && result == 0) {
            // The response is sent before the daemon unlinks its socket and
            // inode-checked lock. Bound the observation window to five seconds.
            for (int elapsed = 0; elapsed < 5000; elapsed += 25) {
                struct stat socket_info {};
                struct stat lock_info {};
                const bool socket_gone =
                    fstatat(directory_fd,
                            "drmid_control_v2.sock",
                            &socket_info,
                            AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
                const bool lock_gone =
                    fstatat(directory_fd,
                            "drmid_daemon_v1.lock",
                            &lock_info,
                            AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
                if (socket_gone && lock_gone) break;
                usleep(25000);
            }
        }
        inventory(directory_fd);
        if (action == "ipc-stop-cleanup-fixtures" && result == 0) {
            std::printf("cleanup_phase=begin\n");
            cleanup_fixtures(directory_fd);
            inventory(directory_fd);
        }
    } else if (action == "prepare") {
        if (!prepare_fixtures(directory_fd)) {
            std::fprintf(stderr, "fixture preparation failed errno=%d\n", errno);
            result = 7;
        }
        inventory(directory_fd);
    } else if (action == "cleanup-fixtures") {
        cleanup_fixtures(directory_fd);
        inventory(directory_fd);
    } else {
        inventory(directory_fd);
    }
    std::fill(private_dir.begin(), private_dir.end(), '\0');
    close(directory_fd);
    return result;
}
