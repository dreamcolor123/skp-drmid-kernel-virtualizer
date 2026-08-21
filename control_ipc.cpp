#include "control_ipc.h"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "hal_identity.h"
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
static_assert(offsetof(ControlIpcResponse, hal_tgids) == 172);
static_assert(offsetof(ControlIpcResponse, hal_monitor_backend) == 188);
static_assert(offsetof(ControlIpcResponse, crc32) == 196);

constexpr uint32_t kHalRediscoveryInitialMs = 50;
constexpr uint32_t kHalRediscoveryMaximumMs = 2000;
constexpr uint32_t kHalProcFallbackPollMs = 5000;

enum class HalMonitorBackend : uint32_t {
    kWaiting = 0,
    kPidfd = 1,
    kProcfsFallback = 2,
};

struct HalMonitorState {
    HalIdentityConfig active;
    HalMonitorBackend backend = HalMonitorBackend::kWaiting;
    uint32_t wakeups = 0;
    uint32_t retry_ms = kHalRediscoveryInitialMs;
    std::vector<int> pidfds;
};

void close_pidfds(HalMonitorState& monitor) {
    for (const int fd : monitor.pidfds) {
        if (fd >= 0) close(fd);
    }
    monitor.pidfds.clear();
}

bool same_hal_tgids(const HalIdentityConfig& left,
                    const HalIdentityConfig& right) {
    if (left.count != right.count) return false;
    for (uint32_t index = 0; index < left.count; ++index) {
        if (left.tgids[index] != right.tgids[index]) return false;
    }
    return true;
}

enum class PidfdOpenResult {
    kReady,
    kUnsupported,
    kProcessGone,
};

PidfdOpenResult open_identity_pidfds(const HalIdentityConfig& identities,
                                     HalMonitorState& monitor) {
    close_pidfds(monitor);
    for (uint32_t index = 0; index < identities.count; ++index) {
        const int fd = open_hal_pidfd(identities.tgids[index]);
        if (fd >= 0) {
            monitor.pidfds.push_back(fd);
            continue;
        }
        const int saved_errno = errno;
        close_pidfds(monitor);
        if (saved_errno == ENOSYS || saved_errno == EPERM ||
            saved_errno == EACCES) {
            return PidfdOpenResult::kUnsupported;
        }
        return PidfdOpenResult::kProcessGone;
    }
    return PidfdOpenResult::kReady;
}

KModErr increment_kernel_counter(const CounterHookSession& session,
                                 size_t offset) {
    KernelCounterContext snapshot{};
    RETURN_IF_ERROR(read_counter_snapshot(session, snapshot));
    uint64_t current = 0;
    std::memcpy(&current,
                reinterpret_cast<const uint8_t*>(&snapshot) + offset,
                sizeof(current));
    if (current == UINT64_MAX) return KModErr::ERR_MODULE_PARAM;
    const uint64_t next = current + 1;
    return kernel_module::write_kernel_mem(
        session.context_kaddr + offset,
        &next,
        static_cast<uint32_t>(sizeof(next)),
        kernel_module::KernMemProt::KMP_RW);
}

KModErr publish_monitored_identities(const CounterHookSession& session,
                                     HalMonitorState& monitor,
                                     HalIdentityConfig identities) {
    if (monitor.active.generation == UINT64_MAX) {
        return KModErr::ERR_MODULE_PARAM;
    }
    identities.generation = monitor.active.generation + 1;
    uint32_t published_slot = 0;
    const KModErr err = publish_hal_identities(
        session, identities, published_slot);
    if (is_failed(err)) {
        increment_kernel_counter(
            session, offsetof(KernelCounterContext, hal_identity_rejections));
        return err;
    }
    monitor.active = identities;
    printf("[drmid612] HAL identities published generation=%" PRIu64
           " slot=%u count=%u\n",
           identities.generation,
           published_slot,
           identities.count);
    return KModErr::OK;
}

KModErr clear_monitored_identities(const CounterHookSession& session,
                                   HalMonitorState& monitor,
                                   bool count_restart) {
    close_pidfds(monitor);
    if (monitor.active.count == 0) {
        monitor.backend = HalMonitorBackend::kWaiting;
        monitor.retry_ms = kHalRediscoveryInitialMs;
        return KModErr::OK;
    }
    HalIdentityConfig empty;
    RETURN_IF_ERROR(publish_monitored_identities(session, monitor, empty));
    if (count_restart) {
        increment_kernel_counter(
            session, offsetof(KernelCounterContext, hal_identity_restarts));
    }
    monitor.backend = HalMonitorBackend::kWaiting;
    monitor.retry_ms = kHalRediscoveryInitialMs;
    return KModErr::OK;
}

KModErr adopt_discovered_identities(const CounterHookSession& session,
                                    HalMonitorState& monitor,
                                    HalIdentityConfig discovered) {
    if (discovered.count == 0) {
        monitor.backend = HalMonitorBackend::kWaiting;
        monitor.retry_ms = std::min(
            monitor.retry_ms * 2U, kHalRediscoveryMaximumMs);
        return KModErr::OK;
    }

    const bool force_procfs =
        monitor.backend == HalMonitorBackend::kProcfsFallback;
    const PidfdOpenResult pidfd_result = force_procfs
        ? PidfdOpenResult::kUnsupported
        : open_identity_pidfds(discovered, monitor);
    if (pidfd_result == PidfdOpenResult::kProcessGone) {
        monitor.backend = HalMonitorBackend::kWaiting;
        monitor.retry_ms = std::min(
            monitor.retry_ms * 2U, kHalRediscoveryMaximumMs);
        return KModErr::OK;
    }
    if (!same_hal_tgids(monitor.active, discovered)) {
        RETURN_IF_ERROR(publish_monitored_identities(
            session, monitor, discovered));
    }
    monitor.backend = pidfd_result == PidfdOpenResult::kReady
        ? HalMonitorBackend::kPidfd
        : HalMonitorBackend::kProcfsFallback;
    monitor.retry_ms = kHalRediscoveryInitialMs;
    printf("[drmid612] HAL monitor backend=%s count=%u\n",
           monitor.backend == HalMonitorBackend::kPidfd
               ? "pidfd"
               : "procfs-fallback",
           monitor.active.count);
    return KModErr::OK;
}

KModErr rediscover_hal_identities(const CounterHookSession& session,
                                  HalMonitorState& monitor) {
    if (monitor.wakeups != UINT32_MAX) ++monitor.wakeups;
    HalIdentityConfig discovered;
    const uint64_t generation = monitor.active.generation == UINT64_MAX
        ? UINT64_MAX
        : monitor.active.generation + 1;
    RETURN_IF_ERROR(discover_widevine_hal_identities(
        "/proc", generation, discovered, nullptr));

    if (monitor.active.count != 0 &&
        !same_hal_tgids(monitor.active, discovered)) {
        RETURN_IF_ERROR(clear_monitored_identities(
            session, monitor, true));
    }
    return adopt_discovered_identities(session, monitor, discovered);
}

KModErr initialize_hal_monitor(const CounterHookSession& session,
                               HalMonitorState& monitor) {
    KernelCounterContext snapshot{};
    RETURN_IF_ERROR(read_counter_snapshot(session, snapshot));
    const HalIdentitySet& active = snapshot.hal_identity_slots[
        snapshot.active_hal_identity_slot & 1U];
    monitor = {};
    monitor.active.generation = active.generation;
    monitor.active.count = active.count;
    std::copy(std::begin(active.tgids),
              std::end(active.tgids),
              monitor.active.tgids.begin());
    if (monitor.active.count == 0) return KModErr::OK;

    const PidfdOpenResult result = open_identity_pidfds(
        monitor.active, monitor);
    if (result == PidfdOpenResult::kReady) {
        monitor.backend = HalMonitorBackend::kPidfd;
        return KModErr::OK;
    }
    if (result == PidfdOpenResult::kUnsupported) {
        monitor.backend = HalMonitorBackend::kProcfsFallback;
        return KModErr::OK;
    }
    RETURN_IF_ERROR(clear_monitored_identities(session, monitor, true));
    return KModErr::OK;
}

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
                   const HalMonitorState& monitor,
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
    response.server_request_hits = snapshot.server_request_hits;
    response.correlated_reply_candidates =
        snapshot.correlated_reply_candidates;
    response.replacement_candidates = snapshot.replacement_candidates;
    response.replacement_dry_run_hits = snapshot.replacement_dry_run_hits;
    response.replacement_write_ok = snapshot.replacement_write_ok;
    response.replacement_write_faults = snapshot.replacement_write_faults;
    const uint32_t hal_slot = snapshot.active_hal_identity_slot & 1U;
    const HalIdentitySet& hal = snapshot.hal_identity_slots[hal_slot];
    response.hal_identity_generation = hal.generation;
    response.hal_identity_switches = snapshot.hal_identity_switches;
    response.hal_gate_hits = snapshot.hal_gate_hits;
    response.active_slot = slot;
    response.replacement_mode = config.replacement_mode;
    response.virtual_id_length = config.virtual_id_length;
    response.hal_state = hal.count == 0 ? 0U : 1U;
    response.hal_count = hal.count;
    std::memcpy(response.hal_tgids, hal.tgids, sizeof(response.hal_tgids));
    response.hal_monitor_backend =
        static_cast<uint32_t>(monitor.backend);
    response.hal_monitor_wakeups = monitor.wakeups;
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
    path += "drmid_control_v3.sock";
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

    HalMonitorState hal_monitor;
    KModErr server_result = initialize_hal_monitor(session, hal_monitor);
    if (is_failed(server_result)) {
        if (term_handler) sigaction(SIGTERM, &old_term, nullptr);
        if (int_handler) sigaction(SIGINT, &old_int, nullptr);
        close(server_fd);
        unlink(socket_path);
        return server_result;
    }

    bool stop = false;
    uint32_t elapsed_ms = 0;
    const auto server_started = std::chrono::steady_clock::now();
    while (!stop && !g_control_stop_requested &&
           (max_runtime_ms == 0 || elapsed_ms < max_runtime_ms)) {
        std::vector<pollfd> descriptors;
        descriptors.push_back({server_fd, POLLIN, 0});
        for (const int pidfd : hal_monitor.pidfds) {
            descriptors.push_back({pidfd, POLLIN, 0});
        }

        int lifecycle_timeout_ms = -1;
        if (hal_monitor.backend == HalMonitorBackend::kWaiting) {
            lifecycle_timeout_ms = static_cast<int>(hal_monitor.retry_ms);
        } else if (hal_monitor.backend ==
                   HalMonitorBackend::kProcfsFallback) {
            lifecycle_timeout_ms = static_cast<int>(kHalProcFallbackPollMs);
        }
        int poll_timeout_ms = lifecycle_timeout_ms;
        if (max_runtime_ms != 0) {
            const auto elapsed = std::chrono::duration_cast<
                std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - server_started);
            elapsed_ms = elapsed.count() >= max_runtime_ms
                ? max_runtime_ms
                : static_cast<uint32_t>(elapsed.count());
            if (elapsed_ms >= max_runtime_ms) break;
            const uint32_t remaining = max_runtime_ms - elapsed_ms;
            poll_timeout_ms = poll_timeout_ms < 0
                ? static_cast<int>(remaining)
                : std::min(poll_timeout_ms, static_cast<int>(remaining));
        }
        const int poll_result = poll(
            descriptors.data(), descriptors.size(), poll_timeout_ms);
        if (poll_result < 0) {
            if (errno == EINTR) continue;
            server_result = KModErr::ERR_MODULE_SOCKET;
            break;
        }
        if (max_runtime_ms != 0) {
            const auto elapsed = std::chrono::duration_cast<
                std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - server_started);
            elapsed_ms = elapsed.count() >= max_runtime_ms
                ? max_runtime_ms
                : static_cast<uint32_t>(elapsed.count());
        }

        bool pidfd_event = false;
        for (size_t index = 1; index < descriptors.size(); ++index) {
            if ((descriptors[index].revents &
                 (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
                pidfd_event = true;
                break;
            }
        }
        if (pidfd_event) {
            if (hal_monitor.wakeups != UINT32_MAX) ++hal_monitor.wakeups;
            const KModErr clear_err = clear_monitored_identities(
                session, hal_monitor, true);
            if (is_failed(clear_err)) {
                server_result = clear_err;
                break;
            }
        } else if (poll_result == 0 &&
                   lifecycle_timeout_ms >= 0 &&
                   poll_timeout_ms == lifecycle_timeout_ms) {
            const KModErr discover_err = rediscover_hal_identities(
                session, hal_monitor);
            if (is_failed(discover_err)) {
                printf("[drmid612] HAL rediscovery failed: %s\n",
                       to_string(discover_err).c_str());
                const KModErr clear_err = clear_monitored_identities(
                    session, hal_monitor, true);
                if (is_failed(clear_err)) {
                    server_result = clear_err;
                    break;
                }
                hal_monitor.retry_ms = std::min(
                    hal_monitor.retry_ms * 2U,
                    kHalRediscoveryMaximumMs);
            }
        }

        if (poll_result == 0 ||
            (descriptors[0].revents & POLLIN) == 0) {
            continue;
        }

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
        fill_response(snapshot,
                      request.request_id,
                      operation_result,
                      hal_monitor,
                      response);
        write_exact(client_fd, &response, sizeof(response));
        close(client_fd);
    }

    const KModErr clear_err = clear_monitored_identities(
        session, hal_monitor, false);
    if (is_failed(clear_err) && is_ok(server_result)) {
        server_result = clear_err;
    }
    close_pidfds(hal_monitor);
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
        response.crc32 !=
            crc32(&response, offsetof(ControlIpcResponse, crc32))) {
        response = {};
        return KModErr::ERR_MODULE_SOCKET;
    }
    return KModErr::OK;
}

std::string control_response_json(const ControlIpcResponse& response) {
    char text[2048]{};
    std::snprintf(
        text,
        sizeof(text),
        "{\"result\":%d,\"daemon_pid\":%" PRIu64
        ",\"backend\":\"hal-outbound-binder\""
        ",\"active_calls\":%" PRIu64
        ",\"generation\":%" PRIu64
        ",\"seed_generation\":%" PRIu64
        ",\"fingerprint\":\"%016" PRIx64
        "\",\"switches\":%" PRIu64
        ",\"rejections\":%" PRIu64
        ",\"server_request_hits\":%" PRIu64
        ",\"correlated_reply_candidates\":%" PRIu64
        ",\"replacement_candidates\":%" PRIu64
        ",\"dry_run_hits\":%" PRIu64
        ",\"write_ok\":%" PRIu64
        ",\"write_faults\":%" PRIu64
        ",\"hal_identity_generation\":%" PRIu64
        ",\"hal_identity_switches\":%" PRIu64
        ",\"hal_gate_hits\":%" PRIu64
        ",\"hal_state\":%u,\"hal_count\":%u"
        ",\"hal_monitor_backend\":%u,\"hal_monitor_wakeups\":%u"
        ",\"slot\":%u,\"mode\":%u,\"length\":%u,\"hal_tgids\":[",
        response.result,
        response.daemon_pid,
        response.active_calls,
        response.config_generation,
        response.seed_generation,
        response.profile_fingerprint,
        response.switches,
        response.rejections,
        response.server_request_hits,
        response.correlated_reply_candidates,
        response.replacement_candidates,
        response.replacement_dry_run_hits,
        response.replacement_write_ok,
        response.replacement_write_faults,
        response.hal_identity_generation,
        response.hal_identity_switches,
        response.hal_gate_hits,
        response.hal_state,
        response.hal_count,
        response.hal_monitor_backend,
        response.hal_monitor_wakeups,
        response.active_slot,
        response.replacement_mode,
        response.virtual_id_length);
    std::string json(text);
    const uint32_t count = response.hal_count <= kHalIdentityLimit
                               ? response.hal_count
                               : 0;
    for (uint32_t index = 0; index < count; ++index) {
        if (index != 0) json.push_back(',');
        json += std::to_string(response.hal_tgids[index]);
    }
    json += "]}";
    return json;
}

} // namespace drmid
