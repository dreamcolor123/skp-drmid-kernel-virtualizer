#pragma once

#include <cstdint>
#include <string>

#include "binder_hook_builder.h"

namespace drmid {

constexpr uint64_t kControlIpcMagic = 0x36314350494d5244ULL; // DRMIPC16
constexpr uint32_t kControlIpcVersion = 2;

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
    uint64_t rule_checks;
    uint64_t rule_matches;
    uint64_t rule_misses;
    uint32_t active_slot;
    uint32_t replacement_mode;
    uint32_t rule_mode;
    uint32_t target_count;
    uint32_t virtual_id_length;
    uint32_t target_euids[kRuntimeTargetLimit];
    uint32_t crc32;
    uint32_t tail_reserved[2];
};

static_assert(sizeof(ControlIpcResponse) == 264);

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
