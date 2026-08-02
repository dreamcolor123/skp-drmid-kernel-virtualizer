#include "control_ipc.h"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>

#include "runtime_control.h"

namespace drmid {
namespace {

volatile sig_atomic_t g_control_stop_requested = 0;

void control_stop_signal_handler(int) {
    g_control_stop_requested = 1;
}

struct ControlIpcRequest {
    uint64_t magic;
    uint32_t version;
    uint32_t operation;
    uint64_t request_id;
    uint32_t crc32;
    uint32_t reserved;
};

static_assert(sizeof(ControlIpcRequest) == 32);
static_assert(offsetof(ControlIpcRequest, crc32) == 24);
static_assert(offsetof(ControlIpcResponse, target_euids) == 124);
static_assert(offsetof(ControlIpcResponse, crc32) == 252);

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
    return true;
}

bool write_exact(int fd, const void* data, size_t size) {
    size_t written = 0;
    while (written < size) {
        const ssize_t count = write(
            fd, static_cast<const uint8_t*>(data) + written,
            size - written);
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

bool fill_unix_address(const char* path, sockaddr_un& address) {
    address = {};
    if (path == nullptr || path[0] == '\0' ||
        std::strlen(path) >= sizeof(address.sun_path)) {
        return false;
    }
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path, std::strlen(path) + 1);
    return true;
}

bool validate_request(const ControlIpcRequest& request) {
    return request.magic == kControlIpcMagic &&
           request.version == kControlIpcVersion && request.reserved == 0 &&
           request.operation >=
               static_cast<uint32_t>(ControlIpcOperation::kStatus) &&
           request.operation <=
               static_cast<uint32_t>(ControlIpcOperation::kStop) &&
           request.crc32 ==
               crc32(&request, offsetof(ControlIpcRequest, crc32));
}

void fill_response(const KernelCounterContext& snapshot,
                   uint64_t request_id,
                   KModErr result,
                   ControlIpcResponse& response) {
    response = {};
    response.magic = kControlIpcMagic;
    response.version = kControlIpcVersion;
    response.result = static_cast<int32_t>(to_num(result));
    response.request_id = request_id;
    response.daemon_pid = static_cast<uint64_t>(getpid());
    response.active_calls = snapshot.active_calls;
    const uint32_t slot = snapshot.active_config_slot & 1U;
    const RuntimeConfigSlot& config = snapshot.config_slots[slot];
    response.config_generation = config.config_generation;
    response.seed_generation = config.seed_generation;
    response.profile_fingerprint = config.profile_fingerprint;
    response.switches = snapshot.runtime_config_switches;
    response.rejections = snapshot.runtime_config_rejections;
    response.rule_checks = snapshot.rule_checks;
    response.rule_matches = snapshot.rule_matches;
    response.rule_misses = snapshot.rule_misses;
    response.active_slot = slot;
    response.replacement_mode = config.replacement_mode;
    response.rule_mode = config.rule_mode;
    response.target_count = config.target_count;
    response.virtual_id_length = config.virtual_id_length;
    std::memcpy(response.target_euids,
                config.target_euids,
                sizeof(response.target_euids));
    response.crc32 =
        crc32(&response, offsetof(ControlIpcResponse, crc32));
}

KModErr increment_rejections(const CounterHookSession& session) {
    KernelCounterContext snapshot{};
    RETURN_IF_ERROR(read_counter_snapshot(session, snapshot));
    const uint64_t next = snapshot.runtime_config_rejections + 1;
    return kernel_module::write_kernel_mem(
        session.context_kaddr +
            offsetof(KernelCounterContext, runtime_config_rejections),
        &next,
        static_cast<uint32_t>(sizeof(next)),
        kernel_module::KernMemProt::KMP_RW);
}

} // namespace

std::string default_control_socket_path(const char* module_private_dir) {
    if (module_private_dir == nullptr || module_private_dir[0] == '\0') {
        return {};
    }
    std::string path(module_private_dir);
    if (path.back() != '/') path.push_back('/');
    path += "drmid_control_v2.sock";
    return path;
}

KModErr run_control_socket_server(const CounterHookSession& session,
                                  const char* socket_path,
                                  const char* runtime_control_path,
                                  uint32_t max_runtime_ms) {
    if (session.context_kaddr == 0 || socket_path == nullptr ||
        runtime_control_path == nullptr) {
        return KModErr::ERR_MODULE_PARAM;
    }
    sockaddr_un address{};
    if (!fill_unix_address(socket_path, address)) {
        return KModErr::ERR_MODULE_PARAM;
    }
    const int server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server_fd < 0) return KModErr::ERR_MODULE_SOCKET;
    unlink(socket_path);
    if (bind(server_fd,
             reinterpret_cast<const sockaddr*>(&address),
             sizeof(address)) != 0 ||
        chmod(socket_path, 0600) != 0 || listen(server_fd, 4) != 0) {
        close(server_fd);
        unlink(socket_path);
        return KModErr::ERR_MODULE_SOCKET;
    }
    printf("[drmid612] control socket ready path=%s pid=%ld max_ms=%u\n",
           socket_path,
           static_cast<long>(getpid()),
           max_runtime_ms);

    g_control_stop_requested = 0;
    struct sigaction action{};
    struct sigaction old_term{};
    struct sigaction old_int{};
    action.sa_handler = control_stop_signal_handler;
    sigemptyset(&action.sa_mask);
    const bool term_handler = sigaction(SIGTERM, &action, &old_term) == 0;
    const bool int_handler = sigaction(SIGINT, &action, &old_int) == 0;

    bool stop = false;
    KModErr server_result = KModErr::OK;
    uint32_t elapsed_ms = 0;
    while (!stop && !g_control_stop_requested &&
           (max_runtime_ms == 0 || elapsed_ms < max_runtime_ms)) {
        constexpr int kPollMs = 200;
        pollfd descriptor{server_fd, POLLIN, 0};
        // Production uses an unlimited lifetime. Block until a client or
        // signal instead of waking the daemon five times per second forever;
        // bounded fixture runs retain the 200 ms accounting interval.
        const int poll_timeout_ms = max_runtime_ms == 0 ? -1 : kPollMs;
        const int poll_result = poll(&descriptor, 1, poll_timeout_ms);
        if (poll_result < 0) {
            if (errno == EINTR) continue;
            server_result = KModErr::ERR_MODULE_SOCKET;
            break;
        }
        if (max_runtime_ms != 0) elapsed_ms += kPollMs;
        if (poll_result == 0 || (descriptor.revents & POLLIN) == 0) continue;

        const int client_fd = accept4(server_fd, nullptr, nullptr, SOCK_CLOEXEC);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            continue;
        }
        ControlIpcRequest request{};
        KModErr operation_result = KModErr::ERR_MODULE_PARAM;
        if (read_exact(client_fd, &request, sizeof(request)) &&
            validate_request(request)) {
            const auto operation =
                static_cast<ControlIpcOperation>(request.operation);
            if (operation == ControlIpcOperation::kStatus) {
                operation_result = KModErr::OK;
            } else if (operation == ControlIpcOperation::kApply) {
                ReplacementConfig config;
                operation_result = read_runtime_control_file(
                    runtime_control_path, config);
                if (is_ok(operation_result)) {
                    KernelCounterContext current{};
                    operation_result = read_counter_snapshot(session, current);
                    const uint32_t slot = current.active_config_slot & 1U;
                    if (is_ok(operation_result) &&
                        config.config_generation ==
                            current.config_slots[slot].config_generation) {
                        operation_result = KModErr::OK;
                    } else if (is_ok(operation_result)) {
                        uint32_t published_slot = 0;
                        operation_result = publish_runtime_config(
                            session, config, published_slot);
                        if (is_ok(operation_result)) {
                            printf("[drmid612] IPC config published generation="
                                   "%" PRIu64 " slot=%u\n",
                                   config.config_generation,
                                   published_slot);
                        }
                    }
                }
                if (is_failed(operation_result)) {
                    increment_rejections(session);
                }
            } else if (operation == ControlIpcOperation::kStop) {
                operation_result = KModErr::OK;
                stop = true;
            }
        }

        KernelCounterContext snapshot{};
        KModErr snapshot_err = read_counter_snapshot(session, snapshot);
        if (is_failed(snapshot_err) && is_ok(operation_result)) {
            operation_result = snapshot_err;
        }
        ControlIpcResponse response{};
        fill_response(snapshot, request.request_id, operation_result, response);
        write_exact(client_fd, &response, sizeof(response));
        close(client_fd);
    }

    if (term_handler) sigaction(SIGTERM, &old_term, nullptr);
    if (int_handler) sigaction(SIGINT, &old_int, nullptr);
    close(server_fd);
    unlink(socket_path);
    printf("[drmid612] control socket stopped elapsed_ms=%u\n", elapsed_ms);
    return server_result;
}

KModErr send_control_ipc_request(const char* socket_path,
                                 ControlIpcOperation operation,
                                 ControlIpcResponse& response) {
    response = {};
    sockaddr_un address{};
    if (!fill_unix_address(socket_path, address)) {
        return KModErr::ERR_MODULE_PARAM;
    }
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return KModErr::ERR_MODULE_SOCKET;
    if (connect(fd,
                reinterpret_cast<const sockaddr*>(&address),
                sizeof(address)) != 0) {
        close(fd);
        return KModErr::ERR_MODULE_SOCKET;
    }
    ControlIpcRequest request{};
    request.magic = kControlIpcMagic;
    request.version = kControlIpcVersion;
    request.operation = static_cast<uint32_t>(operation);
    request.request_id =
        (static_cast<uint64_t>(getpid()) << 32) ^
        static_cast<uint64_t>(gettid());
    request.crc32 = crc32(&request, offsetof(ControlIpcRequest, crc32));
    const bool ok = write_exact(fd, &request, sizeof(request)) &&
                    read_exact(fd, &response, sizeof(response));
    close(fd);
    if (!ok || response.magic != kControlIpcMagic ||
        response.version != kControlIpcVersion ||
        response.request_id != request.request_id ||
        response.tail_reserved[0] != 0 || response.tail_reserved[1] != 0 ||
        response.crc32 !=
            crc32(&response, offsetof(ControlIpcResponse, crc32))) {
        response = {};
        return KModErr::ERR_MODULE_SOCKET;
    }
    return KModErr::OK;
}

std::string control_response_json(const ControlIpcResponse& response) {
    char text[1024]{};
    std::snprintf(
        text,
        sizeof(text),
        "{\"result\":%d,\"daemon_pid\":%" PRIu64
        ",\"active_calls\":%" PRIu64
        ",\"generation\":%" PRIu64
        ",\"seed_generation\":%" PRIu64
        ",\"fingerprint\":\"%016" PRIx64
        "\",\"switches\":%" PRIu64
        ",\"rejections\":%" PRIu64
        ",\"rule_checks\":%" PRIu64
        ",\"rule_matches\":%" PRIu64
        ",\"rule_misses\":%" PRIu64
        ",\"slot\":%u,\"mode\":%u,\"rule\":%u,\"target_count\":%u"
        ",\"target_euid\":%u,\"length\":%u,\"target_euids\":[",
        response.result,
        response.daemon_pid,
        response.active_calls,
        response.config_generation,
        response.seed_generation,
        response.profile_fingerprint,
        response.switches,
        response.rejections,
        response.rule_checks,
        response.rule_matches,
        response.rule_misses,
        response.active_slot,
        response.replacement_mode,
        response.rule_mode,
        response.target_count,
        response.target_count == 0 ? 0 : response.target_euids[0],
        response.virtual_id_length);
    std::string json(text);
    const uint32_t count = response.target_count <= kRuntimeTargetLimit
                               ? response.target_count
                               : 0;
    for (uint32_t index = 0; index < count; ++index) {
        if (index != 0) json.push_back(',');
        json += std::to_string(response.target_euids[index]);
    }
    json += "]}";
    return json;
}

} // namespace drmid
