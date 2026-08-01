#include <algorithm>
#include <array>
#include <cerrno>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

#include "control_ipc.h"
#include "kernel_module_kit_umbrella.h"
#include "runtime_control.h"
#include "runtime_profile.h"
#include "target_config.h"

namespace {

constexpr char kDaemonSuffix[] =
    "/modules/drmidKern612Probe20260728Alpha01/webroot/drmid_daemon";
constexpr char kPrivateSuffix[] =
    "/modules/drmidKern612Probe20260728Alpha01";
constexpr char kExpectedPath[] = "/data/local/tmp/drmid_rc16_expected.bin";
constexpr char kAidlProbePath[] = "/data/local/tmp/drmid_aidl_probe_rc16";

constexpr uint64_t kV1Magic = 0x39304350494d5244ULL;
constexpr uint32_t kV1Version = 1;

enum class V1Operation : uint32_t {
    kStatus = 1,
    kStop = 3,
};

struct V1Request {
    uint64_t magic;
    uint32_t version;
    uint32_t operation;
    uint64_t request_id;
    uint32_t crc32;
    uint32_t reserved;
};

struct V1Response {
    uint64_t magic;
    uint32_t version;
    int32_t result;
    uint64_t request_id;
    uint64_t daemon_pid;
    uint64_t active_calls;
    uint64_t config_generation;
    uint64_t seed_generation;
    uint64_t profile_fingerprint;
    uint64_t switches;
    uint64_t rejections;
    uint64_t rule_checks;
    uint64_t rule_matches;
    uint64_t rule_misses;
    uint32_t active_slot;
    uint32_t replacement_mode;
    uint32_t rule_mode;
    uint32_t target_euid;
    uint32_t virtual_id_length;
    uint32_t crc32;
};

static_assert(sizeof(V1Request) == 32);
static_assert(sizeof(V1Response) == 128);
static_assert(offsetof(V1Response, crc32) == 124);

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

bool all_decimal(std::string_view value) {
    return !value.empty() &&
           std::all_of(value.begin(), value.end(), [](char ch) {
               return ch >= '0' && ch <= '9';
           });
}

bool ends_with(std::string_view value, std::string_view suffix) {
    return value.size() >= suffix.size() &&
           value.substr(value.size() - suffix.size()) == suffix;
}

bool find_private_dir(std::string& output) {
    output.clear();
    DIR* proc = opendir("/proc");
    if (proc == nullptr) return false;
    size_t matches = 0;
    while (dirent* entry = readdir(proc)) {
        if (!all_decimal(entry->d_name)) continue;
        std::string path = "/proc/";
        path += entry->d_name;
        path += "/exe";
        std::array<char, 4096> buffer{};
        const ssize_t size =
            readlink(path.c_str(), buffer.data(), buffer.size() - 1);
        if (size <= 0) continue;
        std::string exe(buffer.data(), static_cast<size_t>(size));
        constexpr std::string_view deleted = " (deleted)";
        if (ends_with(exe, deleted)) exe.resize(exe.size() - deleted.size());
        if (!ends_with(exe, kDaemonSuffix)) continue;
        const size_t private_size =
            exe.size() - std::strlen("/webroot/drmid_daemon");
        std::string candidate = exe.substr(0, private_size);
        if (!ends_with(candidate, kPrivateSuffix) || candidate.front() != '/' ||
            candidate.find("/../") != std::string::npos) {
            continue;
        }
        output = std::move(candidate);
        ++matches;
    }
    closedir(proc);
    return matches == 1;
}

bool read_exact(int fd, void* data, size_t size) {
    size_t used = 0;
    while (used < size) {
        const ssize_t count =
            read(fd, static_cast<uint8_t*>(data) + used, size - used);
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

bool write_exact(int fd, const void* data, size_t size) {
    size_t used = 0;
    while (used < size) {
        const ssize_t count =
            write(fd, static_cast<const uint8_t*>(data) + used, size - used);
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

bool unix_address(const std::string& path, sockaddr_un& address) {
    address = {};
    if (path.empty() || path.size() >= sizeof(address.sun_path)) return false;
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
    return true;
}

int v1_request(const std::string& private_dir, V1Operation operation) {
    const std::string path = private_dir + "/drmid_control_v1.sock";
    sockaddr_un address{};
    if (!unix_address(path, address)) return 10;
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 11;
    if (connect(fd,
                reinterpret_cast<const sockaddr*>(&address),
                sizeof(address)) != 0) {
        close(fd);
        return 12;
    }
    V1Request request{};
    request.magic = kV1Magic;
    request.version = kV1Version;
    request.operation = static_cast<uint32_t>(operation);
    request.request_id =
        (static_cast<uint64_t>(getpid()) << 32) ^ gettid();
    request.crc32 = crc32(&request, offsetof(V1Request, crc32));
    V1Response response{};
    const bool ok = write_exact(fd, &request, sizeof(request)) &&
                    read_exact(fd, &response, sizeof(response));
    close(fd);
    if (!ok || response.magic != kV1Magic || response.version != kV1Version ||
        response.request_id != request.request_id ||
        response.crc32 != crc32(&response, offsetof(V1Response, crc32))) {
        return 13;
    }
    std::printf(
        "v1 result=%d daemon=%" PRIu64 " generation=%" PRIu64
        " seed=%" PRIu64 " fingerprint=%016" PRIx64
        " slot=%u mode=%u rule=%u target=%u length=%u"
        " switches=%" PRIu64 " rejections=%" PRIu64
        " checks=%" PRIu64 " matches=%" PRIu64 " misses=%" PRIu64 "\n",
        response.result,
        response.daemon_pid,
        response.config_generation,
        response.seed_generation,
        response.profile_fingerprint,
        response.active_slot,
        response.replacement_mode,
        response.rule_mode,
        response.target_euid,
        response.virtual_id_length,
        response.switches,
        response.rejections,
        response.rule_checks,
        response.rule_matches,
        response.rule_misses);
    return response.result == 0 ? 0 : 14;
}

void print_target(const drmid::ResolvedTargetConfig& target) {
    std::printf("target generation=%" PRIu64
                " packages=%zu targets=%zu duplicates=%zu shared_uid=%u "
                "profile_domain=%s created=%u updated=%u migrated_v1=%u\n",
                target.generation,
                target.packages.size(),
                target.target_euids.size(),
                target.duplicate_package_count,
                target.shared_uid ? 1U : 0U,
                target.profile_domain.empty() ? "-" : target.profile_domain.c_str(),
                target.created ? 1U : 0U,
                target.updated ? 1U : 0U,
                target.migrated_v1 ? 1U : 0U);
    for (const auto& item : target.packages) {
        std::printf("package=%s uid=%u status=%s\n",
                    item.package_name.c_str(),
                    item.resolved_euid,
                    item.resolved_euid == 0 ? "unresolved" : "resolved");
    }
    std::printf("target_euids=");
    for (size_t index = 0; index < target.target_euids.size(); ++index) {
        std::printf("%s%u", index == 0 ? "" : ",", target.target_euids[index]);
    }
    std::printf("\n");
}

bool same_active_targets(const drmid::ControlIpcResponse& current,
                         const drmid::ResolvedTargetConfig& target) {
    return current.target_count == target.target_euids.size() &&
           current.target_count <= drmid::kRuntimeTargetLimit &&
           std::equal(target.target_euids.begin(),
                      target.target_euids.end(),
                      current.target_euids);
}

int v2_status(const std::string& private_dir,
              drmid::ControlIpcOperation operation) {
    drmid::ControlIpcResponse response{};
    const KModErr err = drmid::send_control_ipc_request(
        drmid::default_control_socket_path(private_dir.c_str()).c_str(),
        operation,
        response);
    if (is_failed(err)) {
        std::fprintf(stderr, "v2 IPC transport=%s\n", to_string(err).c_str());
        return 20;
    }
    std::printf("v2 %s\n", drmid::control_response_json(response).c_str());
    if (operation == drmid::ControlIpcOperation::kStatus) {
        drmid::ResolvedTargetConfig target;
        const KModErr target_err = drmid::read_target_config_snapshot(
            private_dir.c_str(), target);
        if (is_failed(target_err)) return 21;
        print_target(target);
    }
    return response.result == 0 ? 0 : 22;
}

int apply_v2(const std::string& root_key,
             const std::string& private_dir) {
    const char* packages_text = std::getenv("DRMID_TEST_PACKAGES");
    if (packages_text == nullptr || packages_text[0] == '\0') return 30;
    const char* mode_text = std::getenv("DRMID_TEST_MODE");
    const char* id_action = std::getenv("DRMID_TEST_ID_ACTION");
    const std::string mode = mode_text == nullptr ? "keep" : mode_text;
    const std::string id = id_action == nullptr ? "keep" : id_action;
    if ((mode != "keep" && mode != "dry" && mode != "write") ||
        (id != "keep" && id != "derive")) {
        return 31;
    }

    const std::string socket_path =
        drmid::default_control_socket_path(private_dir.c_str());
    const std::string control_path =
        drmid::default_runtime_control_path(private_dir.c_str());
    drmid::ControlIpcResponse current{};
    KModErr err = drmid::send_control_ipc_request(
        socket_path.c_str(), drmid::ControlIpcOperation::kStatus, current);
    if (is_failed(err) || current.result != 0) return 32;

    setenv("DRMID_TARGET_PACKAGES", packages_text, 1);
    unsetenv("DRMID_TARGET_PACKAGE");
    unsetenv("DRMID_TARGET_UID");
    drmid::ResolvedTargetConfig target;
    err = drmid::load_or_resolve_target_config(
        root_key.c_str(), private_dir.c_str(), target);
    unsetenv("DRMID_TARGET_PACKAGES");
    print_target(target);
    if (is_failed(err)) {
        std::fprintf(stderr, "target apply rejected=%s\n", to_string(err).c_str());
        return 33;
    }

    drmid::RuntimeProfile profile;
    err = drmid::load_or_create_runtime_profile(
        false,
        private_dir.c_str(),
        target.rule_mode,
        target.target_euid,
        target.profile_domain.c_str(),
        profile);
    if (is_failed(err)) return 34;

    drmid::ReplacementConfig persisted;
    err = drmid::read_runtime_control_file(control_path.c_str(), persisted);
    if (is_failed(err) || persisted.profile_fingerprint !=
                              current.profile_fingerprint) {
        return 35;
    }

    drmid::ReplacementConfig next = persisted;
    next.mode = mode == "keep"
                    ? static_cast<drmid::ReplacementMode>(current.replacement_mode)
                    : (mode == "write" ? drmid::ReplacementMode::kWriteTest
                                       : drmid::ReplacementMode::kDryRun);
    next.rule_mode = static_cast<uint32_t>(target.rule_mode);
    next.target_count = target.target_euids.size();
    next.target_euids = {};
    std::copy(target.target_euids.begin(),
              target.target_euids.end(),
              next.target_euids.begin());
    if (id == "derive") {
        next.seed_generation = profile.seed_generation;
        next.virtual_id_length = 32;
        next.virtual_id = profile.virtual_stream;
        next.profile_fingerprint = profile.profile_fingerprint;
    }

    const bool no_op =
        !target.updated && same_active_targets(current, target) &&
        current.rule_mode == next.rule_mode &&
        current.replacement_mode == static_cast<uint32_t>(next.mode) &&
        current.profile_fingerprint == next.profile_fingerprint &&
        current.virtual_id_length == next.virtual_id_length;
    if (no_op) {
        std::printf("apply=no-op generation=%" PRIu64 "\n",
                    current.config_generation);
        return 0;
    }
    const uint64_t base =
        std::max(current.config_generation, target.generation);
    if (base == std::numeric_limits<uint64_t>::max()) return 36;
    next.config_generation = base + 1;
    err = drmid::write_runtime_control_file(control_path.c_str(), next);
    if (is_failed(err)) return 37;
    drmid::ControlIpcResponse applied{};
    err = drmid::send_control_ipc_request(
        socket_path.c_str(), drmid::ControlIpcOperation::kApply, applied);
    if (is_failed(err)) return 38;
    std::printf("apply %s\n", drmid::control_response_json(applied).c_str());
    return applied.result == 0 ? 0 : 39;
}

int export_active_id(const std::string& private_dir) {
    drmid::ReplacementConfig config;
    const KModErr err = drmid::read_runtime_control_file(
        drmid::default_runtime_control_path(private_dir.c_str()).c_str(),
        config);
    if (is_failed(err) || config.virtual_id_length != 32) return 40;
    const int fd = open(kExpectedPath,
                        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                        0600);
    if (fd < 0) return 41;
    const bool ok = write_exact(fd, config.virtual_id.data(), 32) &&
                    fchmod(fd, 0600) == 0 && fsync(fd) == 0;
    close(fd);
    std::printf("expected_export=%s bytes=32 fingerprint=%016" PRIx64 "\n",
                ok ? "ready" : "error",
                config.profile_fingerprint);
    return ok ? 0 : 42;
}

int run_aidl() {
    const char* euid_text = std::getenv("DRMID_TEST_EUID");
    if (euid_text == nullptr || !all_decimal(euid_text)) return 50;
    errno = 0;
    char* end = nullptr;
    const unsigned long value = std::strtoul(euid_text, &end, 10);
    if (errno != 0 || end == euid_text || *end != '\0' || value == 0 ||
        value > UINT32_MAX) {
        return 51;
    }
    setenv("DRMID_DROP_EUID", euid_text, 1);
    if (std::getenv("DRMID_TEST_EXPECTED") != nullptr) {
        setenv("DRMID_EXPECTED_FILE", kExpectedPath, 1);
    } else {
        unsetenv("DRMID_EXPECTED_FILE");
    }
    execl(kAidlProbePath, kAidlProbePath, nullptr);
    return 52;
}

} // namespace

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    std::string root_key;
    if (!std::getline(std::cin, root_key) || root_key.empty()) return 2;
    const KModErr root_err = skroot_env::get_root(root_key.c_str());
    if (is_failed(root_err)) {
        std::fill(root_key.begin(), root_key.end(), '\0');
        return 3;
    }
    const char* action_text = std::getenv("DRMID_MULTI_ACTION");
    const std::string action = action_text == nullptr ? "" : action_text;
    if (action == "run-aidl") {
        std::fill(root_key.begin(), root_key.end(), '\0');
        return run_aidl();
    }

    std::string private_dir;
    if (!find_private_dir(private_dir)) {
        std::fill(root_key.begin(), root_key.end(), '\0');
        return 4;
    }
    int result = 5;
    if (action == "v1-status") {
        result = v1_request(private_dir, V1Operation::kStatus);
    } else if (action == "v1-stop") {
        result = v1_request(private_dir, V1Operation::kStop);
    } else if (action == "v2-status") {
        result = v2_status(private_dir, drmid::ControlIpcOperation::kStatus);
    } else if (action == "v2-stop") {
        result = v2_status(private_dir, drmid::ControlIpcOperation::kStop);
    } else if (action == "apply") {
        result = apply_v2(root_key, private_dir);
    } else if (action == "export-active-id") {
        result = export_active_id(private_dir);
    } else if (action == "cleanup-export") {
        result = unlink(kExpectedPath) == 0 || errno == ENOENT ? 0 : 53;
    }
    std::fill(root_key.begin(), root_key.end(), '\0');
    std::fill(private_dir.begin(), private_dir.end(), '\0');
    return result;
}
