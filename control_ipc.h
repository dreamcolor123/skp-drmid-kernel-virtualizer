#pragma once

#include <cstdint>
#include <string>

#include "binder_hook_builder.h"

namespace drmid {

constexpr uint64_t kControlIpcMagic = 0x38314350494d5244ULL; // DRMIPC18
constexpr uint32_t kControlIpcVersion = 3;

enum class ControlIpcOperation : uint32_t {
    kStatus = 1,
    kApply = 2,
    kStop = 3,
};

struct ControlIpcResponse {
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
    uint64_t server_request_hits;
    uint64_t correlated_reply_candidates;
    uint64_t replacement_candidates;
    uint64_t replacement_dry_run_hits;
    uint64_t replacement_write_ok;
    uint64_t replacement_write_faults;
    uint64_t hal_identity_generation;
    uint64_t hal_identity_switches;
    uint64_t hal_gate_hits;
    uint32_t active_slot;
    uint32_t replacement_mode;
    uint32_t virtual_id_length;
    uint32_t hal_state;
    uint32_t hal_count;
    uint32_t hal_tgids[kHalIdentityLimit];
    uint32_t hal_monitor_backend;
    uint32_t hal_monitor_wakeups;
    uint32_t crc32;
};

static_assert(sizeof(ControlIpcResponse) == 200);

std::string default_control_socket_path(const char* module_private_dir);

// max_runtime_ms=0 keeps the server alive until a stop command or process
// termination. A positive value is used by the development runner.
KModErr run_control_socket_server(const CounterHookSession& session,
                                  const char* socket_path,
                                  const char* runtime_control_path,
                                  uint32_t max_runtime_ms);

KModErr send_control_ipc_request(const char* socket_path,
                                 ControlIpcOperation operation,
                                 ControlIpcResponse& response);

std::string control_response_json(const ControlIpcResponse& response);

} // namespace drmid
