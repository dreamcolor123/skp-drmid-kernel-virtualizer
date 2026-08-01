#pragma once

#include <cstddef>
#include <cstdint>
#include <sys/types.h>

namespace drmid {

// Post-boot Hook activation is selected from observed Android/process state.
// The deadline is a compatibility ceiling, not an unconditional sleep.
struct StartupReadinessPolicy {
    uint32_t poll_ms = 250;
    uint32_t stable_ms = 3000;
    uint32_t deadline_ms = 45000;
    uint32_t max_cpu_permille = 500;
};

struct StartupProcessObservation {
    pid_t pid = -1;
    char state = '?';
    uint64_t start_time_ticks = 0;
    uint64_t cpu_ticks = 0;
};

struct StartupReadinessObservation {
    bool boot_animation_stopped = false;
    bool device_boot_complete = false;
    bool user_storage_ready = false;
    bool service_manager_running = false;
    bool media_drm_running = false;
    bool drm_service_running = false;
    StartupProcessObservation system_server;
    StartupProcessObservation surface_flinger;
    size_t process_count = 0;
};

struct StartupReadinessResult {
    uint32_t elapsed_ms = 0;
    uint32_t stable_ms = 0;
    bool deadline_fallback = false;
    StartupReadinessObservation observation;
};

bool startup_base_services_ready(const StartupReadinessObservation& observation);
bool startup_observations_quiet(const StartupReadinessObservation& previous,
                                const StartupReadinessObservation& current,
                                const StartupReadinessPolicy& policy,
                                uint64_t clock_ticks_per_second);
StartupReadinessPolicy startup_readiness_policy_from_environment();
StartupReadinessResult wait_for_adaptive_startup_readiness(
    const StartupReadinessPolicy& policy);

} // namespace drmid
