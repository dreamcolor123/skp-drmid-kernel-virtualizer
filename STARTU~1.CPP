#include "startup_readiness.h"

#include <dirent.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>

namespace drmid {
namespace {

// Readiness is still sampled at the configured poll interval, but an
// unchanged state does not need a progress line every couple of seconds.
// Keep the first sample and state transitions immediate, then rate-limit
// unchanged progress output to keep the boot log useful and compact.
constexpr uint32_t kReadinessProgressLogIntervalMs = 10000;

bool decimal_name(const char* text) {
    if (text == nullptr || text[0] == '\0') return false;
    for (const unsigned char ch : std::string(text)) {
        if (ch < '0' || ch > '9') return false;
    }
    return true;
}

std::string property_value(const char* name) {
    char value[PROP_VALUE_MAX]{};
    if (__system_property_get(name, value) <= 0) return {};
    return value;
}

bool property_equals(const char* name, const char* expected) {
    return property_value(name) == expected;
}

bool property_equals_or_absent(const char* name, const char* expected) {
    const std::string value = property_value(name);
    return value.empty() || value == expected;
}

bool process_alive(const StartupProcessObservation& process) {
    return process.pid > 1 && process.start_time_ticks != 0 &&
           process.state != 'Z' && process.state != 'X' &&
           process.state != 'x' && process.state != '?';
}

bool read_process_observation(pid_t pid,
                              StartupProcessObservation& observation) {
    observation = {};
    observation.pid = -1;
    if (pid <= 1) return false;
    std::ifstream file("/proc/" + std::to_string(pid) + "/stat");
    std::string line;
    if (!file.is_open() || !std::getline(file, line)) return false;
    const size_t close = line.rfind(')');
    if (close == std::string::npos || close + 2 >= line.size()) return false;
    std::istringstream fields(line.substr(close + 2));
    std::string token;
    char state = '?';
    uint64_t user_ticks = 0;
    uint64_t system_ticks = 0;
    uint64_t start_ticks = 0;
    // The stream begins at proc stat field 3 (state).
    for (int field = 3; field <= 22; ++field) {
        if (!(fields >> token)) return false;
        if (field == 3) {
            if (token.size() != 1) return false;
            state = token[0];
        } else if (field == 14 || field == 15 || field == 22) {
            errno = 0;
            char* end = nullptr;
            const unsigned long long value =
                std::strtoull(token.c_str(), &end, 10);
            if (errno != 0 || end == token.c_str() || *end != '\0') {
                return false;
            }
            if (field == 14) user_ticks = value;
            else if (field == 15) system_ticks = value;
            else start_ticks = value;
        }
    }
    if (user_ticks > std::numeric_limits<uint64_t>::max() - system_ticks) {
        return false;
    }
    observation.pid = pid;
    observation.state = state;
    observation.start_time_ticks = start_ticks;
    observation.cpu_ticks = user_ticks + system_ticks;
    return process_alive(observation);
}

bool read_process_name(pid_t pid, std::string& name) {
    name.clear();
    std::ifstream file("/proc/" + std::to_string(pid) + "/comm");
    return file.is_open() && std::getline(file, name) && !name.empty();
}

void sample_processes(pid_t& cached_system_server,
                      pid_t& cached_surface_flinger,
                      StartupReadinessObservation& observation) {
    observation.process_count = 0;
    StartupProcessObservation system_server;
    StartupProcessObservation surface_flinger;
    std::string cached_name;
    const bool cached_system_ok =
        read_process_observation(cached_system_server, system_server) &&
        read_process_name(cached_system_server, cached_name) &&
        cached_name == "system_server";
    const bool cached_surface_ok =
        read_process_observation(cached_surface_flinger, surface_flinger) &&
        read_process_name(cached_surface_flinger, cached_name) &&
        cached_name == "surfaceflinger";

    DIR* directory = opendir("/proc");
    if (directory == nullptr) return;
    while (dirent* entry = readdir(directory)) {
        if (!decimal_name(entry->d_name)) continue;
        ++observation.process_count;
        if (cached_system_ok && cached_surface_ok) continue;
        errno = 0;
        char* end = nullptr;
        const long parsed = std::strtol(entry->d_name, &end, 10);
        if (errno != 0 || end == entry->d_name || *end != '\0' ||
            parsed <= 1 || parsed > std::numeric_limits<pid_t>::max()) {
            continue;
        }
        const pid_t pid = static_cast<pid_t>(parsed);
        std::string name;
        if (!read_process_name(pid, name)) continue;
        if (!cached_system_ok && name == "system_server") {
            read_process_observation(pid, system_server);
        } else if (!cached_surface_ok && name == "surfaceflinger") {
            read_process_observation(pid, surface_flinger);
        }
    }
    closedir(directory);
    if (process_alive(system_server)) cached_system_server = system_server.pid;
    else cached_system_server = -1;
    if (process_alive(surface_flinger)) {
        cached_surface_flinger = surface_flinger.pid;
    } else {
        cached_surface_flinger = -1;
    }
    observation.system_server = system_server;
    observation.surface_flinger = surface_flinger;
}

StartupReadinessObservation sample_observation(pid_t& cached_system_server,
                                               pid_t& cached_surface_flinger) {
    StartupReadinessObservation observation;
    observation.boot_animation_stopped =
        property_equals("init.svc.bootanim", "stopped");
    observation.device_boot_complete =
        property_equals_or_absent("dev.bootcomplete", "1");
    observation.user_storage_ready =
        property_equals_or_absent("sys.user.0.ce_available", "true");
    observation.service_manager_running =
        property_equals("init.svc.servicemanager", "running");
    observation.media_drm_running =
        property_equals("init.svc.mediadrm", "running");
    observation.drm_service_running =
        property_equals_or_absent("init.svc.drm64", "running");
    sample_processes(cached_system_server, cached_surface_flinger, observation);
    return observation;
}

uint32_t bounded_environment_u32(const char* name,
                                 uint32_t fallback,
                                 uint32_t minimum,
                                 uint32_t maximum) {
    const char* text = std::getenv(name);
    if (text == nullptr || text[0] == '\0') return fallback;
    errno = 0;
    char* end = nullptr;
    const unsigned long value = std::strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < minimum ||
        value > maximum) {
        return fallback;
    }
    return static_cast<uint32_t>(value);
}

uint32_t readiness_bits(const StartupReadinessObservation& observation) {
    return (observation.boot_animation_stopped ? 1U << 0 : 0) |
           (observation.device_boot_complete ? 1U << 1 : 0) |
           (observation.user_storage_ready ? 1U << 2 : 0) |
           (observation.service_manager_running ? 1U << 3 : 0) |
           (observation.media_drm_running ? 1U << 4 : 0) |
           (observation.drm_service_running ? 1U << 5 : 0) |
           (process_alive(observation.system_server) ? 1U << 6 : 0) |
           (process_alive(observation.surface_flinger) ? 1U << 7 : 0);
}

} // namespace

bool startup_base_services_ready(
    const StartupReadinessObservation& observation) {
    return readiness_bits(observation) == 0xffU &&
           observation.process_count != 0;
}

bool startup_observations_quiet(const StartupReadinessObservation& previous,
                                const StartupReadinessObservation& current,
                                const StartupReadinessPolicy& policy,
                                uint64_t clock_ticks_per_second) {
    if (!startup_base_services_ready(current) ||
        !process_alive(previous.system_server) ||
        !process_alive(previous.surface_flinger) ||
        previous.system_server.pid != current.system_server.pid ||
        previous.system_server.start_time_ticks !=
            current.system_server.start_time_ticks ||
        previous.surface_flinger.pid != current.surface_flinger.pid ||
        previous.surface_flinger.start_time_ticks !=
            current.surface_flinger.start_time_ticks ||
        previous.process_count != current.process_count ||
        current.system_server.cpu_ticks < previous.system_server.cpu_ticks ||
        current.surface_flinger.cpu_ticks < previous.surface_flinger.cpu_ticks ||
        clock_ticks_per_second == 0 || policy.poll_ms == 0) {
        return false;
    }
    const uint64_t system_delta =
        current.system_server.cpu_ticks - previous.system_server.cpu_ticks;
    const uint64_t surface_delta =
        current.surface_flinger.cpu_ticks - previous.surface_flinger.cpu_ticks;
    // CPU permille is normalized to one fully occupied core. Saturating the
    // multiplication keeps malformed diagnostic policies fail-closed.
    const uint64_t allowed_numerator =
        static_cast<uint64_t>(policy.max_cpu_permille) * policy.poll_ms *
        clock_ticks_per_second;
    const uint64_t allowed_ticks = allowed_numerator / 1000000ULL + 1ULL;
    return system_delta <= allowed_ticks && surface_delta <= allowed_ticks;
}

StartupReadinessPolicy startup_readiness_policy_from_environment() {
    StartupReadinessPolicy policy;
    policy.poll_ms = bounded_environment_u32(
        "DRMID_READY_POLL_MS", policy.poll_ms, 100, 1000);
    policy.stable_ms = bounded_environment_u32(
        "DRMID_READY_STABLE_MS", policy.stable_ms, 1000, 15000);
    policy.deadline_ms = bounded_environment_u32(
        "DRMID_READY_DEADLINE_MS", policy.deadline_ms, 5000, 60000);
    policy.max_cpu_permille = bounded_environment_u32(
        "DRMID_READY_CPU_PERMILLE", policy.max_cpu_permille, 50, 4000);
    if (policy.deadline_ms < policy.stable_ms) {
        policy.deadline_ms = policy.stable_ms;
    }
    return policy;
}

StartupReadinessResult wait_for_adaptive_startup_readiness(
    const StartupReadinessPolicy& policy) {
    StartupReadinessResult result;
    pid_t system_server_pid = -1;
    pid_t surface_flinger_pid = -1;
    const long configured_ticks = sysconf(_SC_CLK_TCK);
    const uint64_t clock_ticks_per_second =
        configured_ticks > 0 ? static_cast<uint64_t>(configured_ticks) : 100ULL;
    StartupReadinessObservation previous;
    bool have_previous = false;
    uint32_t last_bits = UINT32_MAX;
    uint32_t next_progress_log_ms = 0;

    std::printf("[drmid612] adaptive readiness begin poll=%u stable=%u "
                "deadline=%u cpu_permille=%u\n",
                policy.poll_ms,
                policy.stable_ms,
                policy.deadline_ms,
                policy.max_cpu_permille);
    while (result.elapsed_ms < policy.deadline_ms) {
        result.observation =
            sample_observation(system_server_pid, surface_flinger_pid);
        const uint32_t bits = readiness_bits(result.observation);
        const bool quiet = have_previous &&
            startup_observations_quiet(previous,
                                       result.observation,
                                       policy,
                                       clock_ticks_per_second);
        if (quiet) {
            result.stable_ms = std::min<uint32_t>(
                policy.stable_ms, result.stable_ms + policy.poll_ms);
        } else {
            result.stable_ms = 0;
        }
        if (bits != last_bits || result.elapsed_ms >= next_progress_log_ms) {
            std::printf("[drmid612] readiness sample elapsed=%u bits=%02x "
                        "stable=%u processes=%zu system=%ld/%c surface=%ld/%c\n",
                        result.elapsed_ms,
                        bits,
                        result.stable_ms,
                        result.observation.process_count,
                        static_cast<long>(result.observation.system_server.pid),
                        result.observation.system_server.state,
                        static_cast<long>(result.observation.surface_flinger.pid),
                        result.observation.surface_flinger.state);
            last_bits = bits;
            next_progress_log_ms = result.elapsed_ms +
                kReadinessProgressLogIntervalMs;
        }
        if (result.stable_ms >= policy.stable_ms) {
            std::printf("[drmid612] adaptive readiness satisfied elapsed=%u "
                        "stable=%u\n",
                        result.elapsed_ms,
                        result.stable_ms);
            return result;
        }
        previous = result.observation;
        have_previous = true;
        usleep(static_cast<useconds_t>(policy.poll_ms) * 1000U);
        if (policy.deadline_ms - result.elapsed_ms < policy.poll_ms) {
            result.elapsed_ms = policy.deadline_ms;
        } else {
            result.elapsed_ms += policy.poll_ms;
        }
    }
    result.deadline_fallback = true;
    std::printf("[drmid612] adaptive readiness deadline fallback elapsed=%u "
                "bits=%02x stable=%u\n",
                result.elapsed_ms,
                readiness_bits(result.observation),
                result.stable_ms);
    return result;
}

} // namespace drmid
