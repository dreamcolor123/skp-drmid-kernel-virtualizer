#include "startup_readiness.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

extern "C" int __system_property_get(const char*, char* value) {
    if (value != nullptr) value[0] = '\0';
    return 0;
}

namespace {

drmid::StartupReadinessObservation ready_observation() {
    drmid::StartupReadinessObservation observation;
    observation.boot_animation_stopped = true;
    observation.device_boot_complete = true;
    observation.user_storage_ready = true;
    observation.service_manager_running = true;
    observation.media_drm_running = true;
    observation.drm_service_running = true;
    observation.system_server = {4100, 'S', 1000, 500};
    observation.surface_flinger = {2200, 'S', 500, 200};
    observation.process_count = 900;
    return observation;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) return 64;
    const std::string operation(argv[1]);
    drmid::StartupReadinessPolicy policy;
    auto previous = ready_observation();
    auto current = previous;
    current.system_server.cpu_ticks += 5;
    current.surface_flinger.cpu_ticks += 2;

    if (operation == "ready") {
        std::cout << drmid::startup_base_services_ready(current) << '\n';
        return 0;
    }
    if (operation == "missing-service") {
        current.media_drm_running = false;
        std::cout << drmid::startup_base_services_ready(current) << '\n';
        return 0;
    }
    if (operation == "quiet") {
        std::cout << drmid::startup_observations_quiet(
            previous, current, policy, 100) << '\n';
        return 0;
    }
    if (operation == "busy") {
        current.system_server.cpu_ticks += 100;
        std::cout << drmid::startup_observations_quiet(
            previous, current, policy, 100) << '\n';
        return 0;
    }
    if (operation == "process-churn") {
        ++current.process_count;
        std::cout << drmid::startup_observations_quiet(
            previous, current, policy, 100) << '\n';
        return 0;
    }
    if (operation == "identity-change") {
        ++current.system_server.start_time_ticks;
        std::cout << drmid::startup_observations_quiet(
            previous, current, policy, 100) << '\n';
        return 0;
    }
    if (operation == "policy-default") {
        const auto value = drmid::startup_readiness_policy_from_environment();
        std::cout << value.poll_ms << ' ' << value.stable_ms << ' '
                  << value.deadline_ms << ' ' << value.max_cpu_permille << '\n';
        return 0;
    }
    if (operation == "policy-bounded") {
        setenv("DRMID_READY_POLL_MS", "99", 1);
        setenv("DRMID_READY_STABLE_MS", "900", 1);
        setenv("DRMID_READY_DEADLINE_MS", "4000", 1);
        setenv("DRMID_READY_CPU_PERMILLE", "49", 1);
        const auto value = drmid::startup_readiness_policy_from_environment();
        std::cout << value.poll_ms << ' ' << value.stable_ms << ' '
                  << value.deadline_ms << ' ' << value.max_cpu_permille << '\n';
        return 0;
    }
    return 65;
}
