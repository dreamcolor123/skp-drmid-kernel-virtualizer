#include "hal_identity.h"

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>

namespace drmid {
namespace {

bool decimal_name(const char* text) {
    if (text == nullptr || text[0] == '\0') return false;
    for (const unsigned char ch : std::string(text)) {
        if (!std::isdigit(ch)) return false;
    }
    return true;
}

std::string join_path(const std::string& left, const std::string& right) {
    if (left.empty()) return right;
    return left.back() == '/' ? left + right : left + "/" + right;
}

bool read_link(const std::string& path, std::string& result) {
    result.clear();
    char buffer[PATH_MAX + 1]{};
    const ssize_t count = readlink(path.c_str(), buffer, PATH_MAX);
    if (count <= 0 || count > PATH_MAX) return false;
    buffer[count] = '\0';
    result.assign(buffer, static_cast<size_t>(count));
    return true;
}

bool read_bounded_file(const std::string& path,
                       size_t limit,
                       std::string& result) {
    result.clear();
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    std::string bytes(limit, '\0');
    size_t used = 0;
    while (used < limit) {
        const ssize_t count = read(fd, bytes.data() + used, limit - used);
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
    if (tail > 0) return false;
    bytes.resize(used);
    result = std::move(bytes);
    return true;
}

std::string basename_of(const std::string& path) {
    const size_t slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

bool looks_like_widevine_exe(const std::string& exe) {
    const std::string base = basename_of(exe);
    return base.find("drm") != std::string::npos &&
           (base.find("widevine") != std::string::npos ||
            exe.find("/widevine/") != std::string::npos);
}

bool cmdline_matches_exe(const std::string& cmdline,
                         const std::string& exe) {
    const size_t end = cmdline.find('\0');
    const std::string argv0 = cmdline.substr(0, end);
    return !argv0.empty() && basename_of(argv0) == basename_of(exe);
}

bool parse_uid(const std::string& status, uint32_t& uid) {
    const size_t offset = status.find("Uid:");
    if (offset == std::string::npos) return false;
    unsigned parsed = 0;
    if (std::sscanf(status.c_str() + offset, "Uid:\t%u", &parsed) != 1) {
        return false;
    }
    uid = parsed;
    return uid == 1013U || uid == 1019U || uid == 1031U;
}

bool widevine_domain(const std::string& domain) {
    return domain.find("hal_drm_widevine") != std::string::npos ||
           (domain.find("drm") != std::string::npos &&
            domain.find("widevine") != std::string::npos);
}

bool find_binder_fd(const std::string& process_root,
                    std::string& binder_path) {
    binder_path.clear();
    const std::string fd_root = join_path(process_root, "fd");
    DIR* directory = opendir(fd_root.c_str());
    if (directory == nullptr) return false;
    while (dirent* entry = readdir(directory)) {
        if (!decimal_name(entry->d_name)) continue;
        std::string target;
        if (!read_link(join_path(fd_root, entry->d_name), target)) continue;
        const std::string base = basename_of(target);
        if (base == "binder" || base == "hwbinder" ||
            base == "vndbinder") {
            binder_path = std::move(target);
            closedir(directory);
            return true;
        }
    }
    closedir(directory);
    return false;
}

bool inspect_candidate(const std::string& proc_root,
                       const char* pid_text,
                       HalProcessInfo& info) {
    if (!decimal_name(pid_text)) return false;
    const unsigned long parsed = std::strtoul(pid_text, nullptr, 10);
    if (parsed == 0 || parsed > UINT32_MAX) return false;
    const std::string root = join_path(proc_root, pid_text);
    if (!read_link(join_path(root, "exe"), info.exe) ||
        !looks_like_widevine_exe(info.exe)) {
        return false;
    }
    std::string cmdline;
    std::string status;
    if (!read_bounded_file(join_path(root, "cmdline"), 4096, cmdline) ||
        !cmdline_matches_exe(cmdline, info.exe) ||
        !read_bounded_file(join_path(root, "status"), 32768, status) ||
        !parse_uid(status, info.uid) ||
        !read_bounded_file(join_path(root, "attr/current"), 512, info.domain) ||
        !widevine_domain(info.domain) ||
        !find_binder_fd(root, info.binder_path)) {
        return false;
    }
    info.tgid = static_cast<uint32_t>(parsed);
    return true;
}

} // namespace

KModErr discover_widevine_hal_identities(
    const char* proc_root,
    uint64_t generation,
    HalIdentityConfig& identities,
    std::vector<HalProcessInfo>* details) {
    identities = {};
    if (details != nullptr) details->clear();
    if (proc_root == nullptr || proc_root[0] == '\0' || generation == 0) {
        return KModErr::ERR_MODULE_PARAM;
    }
    DIR* directory = opendir(proc_root);
    if (directory == nullptr) return KModErr::ERR_MODULE_OPEN_FILE;
    std::vector<HalProcessInfo> matches;
    while (dirent* entry = readdir(directory)) {
        HalProcessInfo info;
        if (inspect_candidate(proc_root, entry->d_name, info)) {
            matches.push_back(std::move(info));
        }
    }
    closedir(directory);
    std::sort(matches.begin(), matches.end(),
              [](const HalProcessInfo& left, const HalProcessInfo& right) {
                  return left.tgid < right.tgid;
              });
    matches.erase(
        std::unique(matches.begin(), matches.end(),
                    [](const HalProcessInfo& left,
                       const HalProcessInfo& right) {
                        return left.tgid == right.tgid;
                    }),
        matches.end());
    if (matches.size() > kHalIdentityLimit) {
        return KModErr::ERR_MODULE_PARAM;
    }
    identities.generation = generation;
    identities.count = static_cast<uint32_t>(matches.size());
    for (size_t index = 0; index < matches.size(); ++index) {
        identities.tgids[index] = matches[index].tgid;
    }
    if (details != nullptr) *details = std::move(matches);
    return KModErr::OK;
}

int open_hal_pidfd(uint32_t tgid) {
    if (tgid == 0) {
        errno = EINVAL;
        return -1;
    }
#if defined(SYS_pidfd_open)
    return static_cast<int>(syscall(SYS_pidfd_open, tgid, 0));
#elif defined(__NR_pidfd_open)
    return static_cast<int>(syscall(__NR_pidfd_open, tgid, 0));
#else
    errno = ENOSYS;
    return -1;
#endif
}

} // namespace drmid
