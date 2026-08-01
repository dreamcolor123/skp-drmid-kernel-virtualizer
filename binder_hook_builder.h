#pragma once

#include <array>
#include <cstdint>

#include "kernel_context.h"
#include "kernel_module_kit_umbrella.h"

namespace drmid {

struct TaskIdentityOffsets {
    uint32_t pid = 0;
    uint32_t tgid = 0;
    uint32_t cred = 0;
    uint32_t cred_euid = 0;
};

struct ReplacementConfig {
    ReplacementMode mode = ReplacementMode::kDryRun;
    uint32_t rule_mode = 0;
    uint32_t target_count = 0;
    uint32_t virtual_id_length = 0;
    uint64_t config_generation = 0;
    uint64_t seed_generation = 0;
    uint64_t profile_fingerprint = 0;
    std::array<uint32_t, kRuntimeTargetLimit> target_euids{};
    std::array<uint8_t, 64> virtual_id{};
};

struct CounterHookSession {
    uint64_t target_kaddr = 0;
    uint64_t context_kaddr = 0;
    uint64_t active_at_remove = 0;
    kernel_module::HookHandle hook = nullptr;
};

// Publishes a complete policy into the inactive kernel slot and flips the
// active index with a release store. In-flight handlers continue using the
// slot they acquired at the start of their reply parse.
KModErr publish_runtime_config(const CounterHookSession& session,
                               const ReplacementConfig& config,
                               uint32_t& published_slot);

// Installs the bounded Binder parser/replacement probe. Dry-run is the default;
// write-test performs only an exact-length replacement after all reply guards.
KModErr resolve_and_validate_task_identity_offsets(TaskIdentityOffsets& offsets);

KModErr install_readonly_parser_hook(uint64_t target_kaddr,
                                     const TaskIdentityOffsets& task_offsets,
                                     const ReplacementConfig& config,
                                     CounterHookSession& session);
KModErr read_counter_snapshot(const CounterHookSession& session,
                              KernelCounterContext& snapshot);

// Unhook the entry but retain the tiny RW context until reboot. Blocking Binder
// reads may keep handlers inside the original ioctl, and the SDK does not
// expose a synchronize/RCU grace-period primitive for proving every CPU has
// passed the first active_calls increment.
KModErr remove_readonly_parser_hook(CounterHookSession& session);

} // namespace drmid
