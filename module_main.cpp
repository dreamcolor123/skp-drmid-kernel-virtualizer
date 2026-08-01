#include <android/api-level.h>
#include <fcntl.h>
#include <linux/android/binder.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cinttypes>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>

#include "binder_hook_builder.h"
#include "binder_ioctl_resolver.h"
#include "control_ipc.h"
#include "device_id_fingerprint.h"
#include "file_lifecycle.h"
#include "kernel_module_kit_umbrella.h"
#include "runtime_control.h"
#include "runtime_profile.h"
#include "startup_readiness.h"
#include "target_config.h"

namespace {

constexpr int kSelfTestIoctlCount = 8;
constexpr uint32_t kDeviceReplyLength = 32;
constexpr uint32_t kDefaultBootWaitTimeoutMs = 180000;
constexpr uint32_t kDefaultTargetWaitTimeoutMs = 120000;
constexpr char kPrivateBootCleanupMarker[] =
    "webroot/drmid_boot_cleanup.flag";
static_assert(drmid::kTargetPackageLimit == drmid::kRuntimeTargetLimit);
static_assert(kDeviceReplyLength == drmid::kVirtualIdBytes);

int open_binder_driver(std::string& selected_path) {
    constexpr const char* kCandidates[] = {
        "/dev/binder",
        "/dev/binderfs/binder",
    };
    for (const char* path : kCandidates) {
        const int fd = open(path, O_RDWR | O_CLOEXEC);
        if (fd >= 0) {
            selected_path = path;
            return fd;
        }
    }
    return -1;
}

void print_resolution(const drmid::BinderIoctlResolution& resolution) {
    printf("[drmid612] backend=%s fd=%d\n",
           drmid::binder_backend_name(resolution.backend),
           resolution.binder_fd);
    printf("[drmid612] file=%p fops=%p unlocked_ioctl=%p\n",
           reinterpret_cast<void*>(resolution.file_kaddr),
           reinterpret_cast<void*>(resolution.fops_kaddr),
           reinterpret_cast<void*>(resolution.ioctl_kaddr));
    printf("[drmid612] offsets task.files=%u files.fdt=%u fdt.fd=%u "
           "file.f_op=%u fops.unlocked_ioctl=%u\n",
           resolution.offsets.task_files,
           resolution.offsets.files_fdt,
           resolution.offsets.fdtable_fd,
           resolution.offsets.file_f_op,
           resolution.offsets.fops_unlocked_ioctl);
    printf("[drmid612] prologue=%08x %08x %08x %08x\n",
           resolution.prologue[0],
           resolution.prologue[1],
           resolution.prologue[2],
           resolution.prologue[3]);
}

void print_parser_snapshot(const char* label,
                           const drmid::KernelCounterContext& s) {
    printf("[drmid612] %s calls active/pre/post/bwr=%" PRIu64 "/%" PRIu64
           "/%" PRIu64 "/%" PRIu64
           " header pre-ok/fault=%" PRIu64 "/%" PRIu64
           " post-ok/fault=%" PRIu64 "/%" PRIu64
           " invalid=%" PRIu64 "\n",
           label,
           s.active_calls,
           s.pre_calls,
           s.post_calls,
           s.bwr_calls,
           s.pre_header_ok,
           s.pre_header_faults,
           s.post_header_ok,
           s.post_header_faults,
           s.invalid_consumed);
    printf("[drmid612] %s streams write/read=%" PRIu64 "/%" PRIu64
           " commands BC/BR=%" PRIu64 "/%" PRIu64
           " transactions BC/BR=%" PRIu64 "/%" PRIu64
           " boundary write/read=%" PRIu64 "/%" PRIu64
           " copy-fault write/read=%" PRIu64 "/%" PRIu64
           " capped write/read=%" PRIu64 "/%" PRIu64 "\n",
           label,
           s.write_streams,
           s.read_streams,
           s.bc_commands,
           s.br_commands,
           s.bc_transaction_commands,
           s.br_transaction_commands,
           s.write_boundary_errors,
           s.read_boundary_errors,
           s.write_copy_faults,
           s.read_copy_faults,
           s.write_capped,
           s.read_capped);
    printf("[drmid612] %s metadata ok/fault=%" PRIu64 "/%" PRIu64
           " events=%" PRIu64
           " pending push/pop/terminal=%" PRIu64 "/%" PRIu64
           "/%" PRIu64 " miss/overflow/reclaim/oneway=%" PRIu64
           "/%" PRIu64 "/%" PRIu64 "/%" PRIu64
           " lock-state/drops=%" PRIu64 "/%" PRIu64 "\n",
           label,
           s.transaction_metadata_ok,
           s.transaction_metadata_faults,
           s.event_write_index,
           s.pending_pushes,
           s.pending_pops,
           s.pending_terminal_pops,
           s.pending_misses,
           s.pending_overflows,
           s.pending_collisions,
           s.pending_oneway_ignored,
           s.pending_lock_state,
           s.pending_lock_drops);
    printf("[drmid612] %s parcel prefix ok/fault=%" PRIu64 "/%" PRIu64
           " token factory/plugin/device/unknown=%" PRIu64 "/%" PRIu64
           "/%" PRIu64 "/%" PRIu64 "\n",
           label,
           s.parcel_prefix_ok,
           s.parcel_prefix_faults,
           s.parcel_factory_hits,
           s.parcel_plugin_hits,
           s.parcel_device_unique_id_hits,
           s.parcel_unknown_tokens);
    printf("[drmid612] %s reply candidate/header-ok/fault=%" PRIu64
           "/%" PRIu64 "/%" PRIu64
           " status ok/nonzero=%" PRIu64 "/%" PRIu64
           " array valid/invalid=%" PRIu64 "/%" PRIu64
           " content ok/fault=%" PRIu64 "/%" PRIu64 "\n",
           label,
           s.reply_candidates,
           s.reply_header_copy_ok,
           s.reply_header_copy_faults,
           s.reply_status_ok,
           s.reply_status_nonzero,
           s.reply_array_valid,
           s.reply_array_invalid,
           s.reply_content_copy_ok,
           s.reply_content_copy_faults);
    printf("[drmid612] %s replacement candidate/mismatch/dry/write/fault="
           "%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64
           "/%" PRIu64
           " copy_to_user-fault/access_vm-ok/fault=%" PRIu64
           "/%" PRIu64 "/%" PRIu64
           " page-pin-ok/fault/page-write-ok/fault=%" PRIu64
           "/%" PRIu64 "/%" PRIu64 "/%" PRIu64
           " last access_vm/page_pin=%" PRId64 "/%" PRId64
           " last-success request/flags/length=%" PRIu64 "/%08x/%d"
           " config generation/mode/length=%" PRIu64
           "/%u/%u\n",
           label,
           s.replacement_candidates,
           s.replacement_length_mismatch,
           s.replacement_dry_run_hits,
           s.replacement_write_ok,
           s.replacement_write_faults,
           s.replacement_copy_to_user_faults,
           s.replacement_access_vm_ok,
           s.replacement_access_vm_faults,
           s.replacement_page_pin_ok,
           s.replacement_page_pin_faults,
           s.replacement_page_write_ok,
           s.replacement_page_write_faults,
           s.replacement_access_vm_last_result,
           s.replacement_page_pin_last_result,
           s.replacement_last_request_id,
           s.replacement_last_reply_flags,
           s.replacement_last_array_length,
           s.config_generation,
           s.replacement_mode,
           s.virtual_id_length);
    printf("[drmid612] %s rules check/match/miss/cred-fault=%" PRIu64
           "/%" PRIu64 "/%" PRIu64 "/%" PRIu64
           " last-euid=%" PRIu64
           " config generation/seed/mode/rule/targets/length/fingerprint="
           "%" PRIu64 "/%" PRIu64 "/%u/%u/%u/%u/%016" PRIx64 "\n",
           label,
           s.rule_checks,
           s.rule_matches,
           s.rule_misses,
           s.rule_cred_faults,
           s.last_client_euid,
           s.config_generation,
           s.seed_generation,
           s.replacement_mode,
           s.rule_mode,
           s.target_count,
           s.virtual_id_length,
           s.profile_fingerprint);
    const uint32_t active_slot = s.active_config_slot & 1U;
    const drmid::RuntimeConfigSlot& active_config =
        s.config_slots[active_slot];
    printf("[drmid612] %s runtime-config slot/switch/reject=%u/%" PRIu64
           "/%" PRIu64
           " generation/seed/mode/rule/targets/length/fingerprint="
           "%" PRIu64 "/%" PRIu64 "/%u/%u/%u/%u/%016" PRIx64
           " slot-generation=%" PRIu64 "/%" PRIu64 "\n",
           label,
           active_slot,
           s.runtime_config_switches,
           s.runtime_config_rejections,
           active_config.config_generation,
           active_config.seed_generation,
           active_config.replacement_mode,
           active_config.rule_mode,
           active_config.target_count,
           active_config.virtual_id_length,
           active_config.profile_fingerprint,
           s.config_slots[0].config_generation,
           s.config_slots[1].config_generation);
    printf("[drmid612] %s plugin create-request/reply-ok/fault=%" PRIu64
           "/%" PRIu64 "/%" PRIu64
           " map insert/reuse/reclaim/active=%" PRIu64 "/%" PRIu64
           "/%" PRIu64 "/%" PRIu64
           " lookup/hit/miss=%" PRIu64 "/%" PRIu64 "/%" PRIu64
           " release/miss=%" PRIu64 "/%" PRIu64
           " lock-state/drops=%" PRIu64 "/%" PRIu64
           " last-create data/offsets/stage/status/object-off/type/handle="
           "%" PRIu64 "/%" PRIu64 "/%u/%d/%u/%08x/%u\n",
           label,
           s.widevine_create_requests,
           s.create_reply_ok,
           s.create_reply_faults,
           s.plugin_map_inserts,
           s.plugin_map_reuses,
           s.plugin_map_collisions,
           s.plugin_map_active,
           s.plugin_map_lookups,
           s.plugin_map_hits,
           s.plugin_map_misses,
           s.plugin_map_releases,
           s.plugin_map_release_misses,
           s.plugin_lock_state,
           s.plugin_lock_drops,
           s.last_create_data_size,
           s.last_create_offsets_size,
           s.last_create_stage,
           s.last_create_status,
           s.last_create_object_offset,
           s.last_create_object_type,
           s.last_create_handle);
}

const char* event_kind_name(uint32_t kind) {
    switch (static_cast<drmid::BinderEventKind>(kind)) {
        case drmid::BinderEventKind::kBcTransaction:
            return "BC_TX";
        case drmid::BinderEventKind::kBcReply:
            return "BC_REPLY";
        case drmid::BinderEventKind::kBrTransaction:
            return "BR_TX";
        case drmid::BinderEventKind::kBrTransactionSecCtx:
            return "BR_TX_SECCTX";
        case drmid::BinderEventKind::kBrReply:
            return "BR_REPLY";
        case drmid::BinderEventKind::kUnknown:
        default:
            return "UNKNOWN";
    }
}

const char* parcel_token_name(uint32_t kind) {
    switch (static_cast<drmid::ParcelTokenKind>(kind)) {
        case drmid::ParcelTokenKind::kDrmFactory:
            return "IDrmFactory";
        case drmid::ParcelTokenKind::kDrmPlugin:
            return "IDrmPlugin";
        case drmid::ParcelTokenKind::kNone:
        default:
            return "-";
    }
}

void print_recent_events(const drmid::KernelCounterContext& snapshot,
                         size_t max_events) {
    const uint64_t end = snapshot.event_write_index;
    const uint64_t retained_begin =
        end > drmid::kTransactionEventCapacity
            ? end - drmid::kTransactionEventCapacity
            : 0;
    const uint64_t begin =
        end > max_events && end - max_events > retained_begin
            ? end - max_events
            : retained_begin;
    size_t token_events = 0;
    size_t device_events = 0;
    for (uint64_t ticket = retained_begin; ticket < end; ++ticket) {
        const uint64_t event_id = ticket + 1;
        const auto& event =
            snapshot.events[ticket & (drmid::kTransactionEventCapacity - 1)];
        if (event.sequence != event_id * 2 || event.event_id != event_id ||
            event.parcel_token_kind == 0) {
            continue;
        }
        ++token_events;
        if ((event.parcel_flags & drmid::kParcelFlagDeviceUniqueId) != 0) {
            ++device_events;
        }
        if (token_events <= 32) {
            uint64_t reply_event_id = 0;
            uint64_t reply_data_size = 0;
            int32_t reply_status = 0;
            int32_t reply_array_length = 0;
            uint32_t reply_array_offset = 0;
            uint32_t reply_parse_flags = 0;
            for (uint64_t reply_ticket = retained_begin;
                 reply_ticket < end;
                 ++reply_ticket) {
                const uint64_t expected_reply_id = reply_ticket + 1;
                const auto& reply = snapshot.events[
                    reply_ticket & (drmid::kTransactionEventCapacity - 1)];
                if (reply.sequence == expected_reply_id * 2 &&
                    reply.event_id == expected_reply_id &&
                    reply.correlated_request_id == event.event_id) {
                    reply_event_id = reply.event_id;
                    reply_data_size = reply.data_size;
                    reply_status = reply.reply_status_code;
                    reply_array_length = reply.reply_byte_array_length;
                    reply_array_offset = reply.reply_byte_array_offset;
                    reply_parse_flags = reply.reply_flags;
                    break;
                }
            }
            printf("[drmid612] token-event id=%" PRIu64
                   " kind=%s tid/tgid=%u/%u target=%" PRIu64
                   " code=%u data=%" PRIu64 " token=%s@%u"
                   " prefix=%u parcel_flags=%08x request=%" PRIu64
                   " reply=%" PRIu64 "/%" PRIu64
                   " status=%d array=%d@%u reply_flags=%08x"
                   " uuid_off=%u plugin_handle=%u\n",
                   event.event_id,
                   event_kind_name(event.kind),
                   event.pid,
                   event.tgid,
                   event.target,
                   event.code,
                   event.data_size,
                   parcel_token_name(event.parcel_token_kind),
                   event.parcel_token_offset,
                   event.parcel_prefix_size,
                   event.parcel_flags,
                   event.correlated_request_id,
                   reply_event_id,
                   reply_data_size,
                   reply_status,
                   reply_array_length,
                   reply_array_offset,
                   reply_parse_flags,
                   event.factory_uuid_offset,
                   event.plugin_handle);
        }
    }
    printf("[drmid612] token snapshot retained=%zu deviceUniqueId=%zu\n",
           token_events,
           device_events);

    size_t printed = 0;
    size_t correlated = 0;
    for (uint64_t ticket = begin; ticket < end; ++ticket) {
        const uint64_t event_id = ticket + 1;
        const auto& event =
            snapshot.events[ticket & (drmid::kTransactionEventCapacity - 1)];
        if (event.sequence != event_id * 2 || event.event_id != event_id) {
            continue;
        }
        if (event.correlated_request_id != 0) {
            ++correlated;
        }
        printf("[drmid612] event id=%" PRIu64 " kind=%s tid/tgid=%u/%u "
               "cmd=%08x target=%" PRIu64 " code=%u flags=%08x "
               "data=%" PRIu64 " offsets=%" PRIu64
               " sender=%u/%u request=%" PRIu64
               " token=%s@%u prefix=%u parcel_flags=%08x"
               " reply=%d/%d@%u/%08x uuid_off=%u plugin_handle=%u\n",
               event.event_id,
               event_kind_name(event.kind),
               event.pid,
               event.tgid,
               event.command,
               event.target,
               event.code,
               event.flags,
               event.data_size,
               event.offsets_size,
               event.sender_pid,
               event.sender_euid,
               event.correlated_request_id,
               parcel_token_name(event.parcel_token_kind),
               event.parcel_token_offset,
               event.parcel_prefix_size,
               event.parcel_flags,
               event.reply_status_code,
               event.reply_byte_array_length,
               event.reply_byte_array_offset,
               event.reply_flags,
               event.factory_uuid_offset,
               event.plugin_handle);
        ++printed;
    }
    printf("[drmid612] event snapshot printed=%zu correlated=%zu "
           "window=%" PRIu64 "..%" PRIu64 "\n",
           printed,
           correlated,
           begin,
           end);
}

uint64_t delta(uint64_t after, uint64_t before) {
    return after - before;
}

KModErr note_runtime_control_rejection(
    const drmid::CounterHookSession& session) {
    drmid::KernelCounterContext snapshot{};
    RETURN_IF_ERROR(drmid::read_counter_snapshot(session, snapshot));
    const uint64_t next = snapshot.runtime_config_rejections + 1;
    return kernel_module::write_kernel_mem(
        session.context_kaddr +
            offsetof(drmid::KernelCounterContext,
                     runtime_config_rejections),
        &next,
        static_cast<uint32_t>(sizeof(next)),
        kernel_module::KernMemProt::KMP_RW);
}

KModErr run_readonly_parser_probe(const char* root_key,
                                  const char* module_private_dir) {
    const bool daemon_mode = getenv("DRMID_DAEMON_MODE") != nullptr;
    if (daemon_mode) {
        drmid::cleanup_legacy_public_artifacts();
    }
    std::string private_cleanup_marker;
    if (module_private_dir != nullptr && module_private_dir[0] != '\0') {
        private_cleanup_marker = module_private_dir;
        if (private_cleanup_marker.back() != '/') {
            private_cleanup_marker.push_back('/');
        }
        private_cleanup_marker += kPrivateBootCleanupMarker;
    }
    if (daemon_mode && !private_cleanup_marker.empty() &&
        access(private_cleanup_marker.c_str(), F_OK) == 0) {
        printf("[drmid612] boot cleanup marker detected; removing persistent "
               "state and skipping Hook\n");
        drmid::cleanup_module_state_files(module_private_dir);
        return KModErr::OK;
    }
    if (daemon_mode) {
        uint32_t boot_wait_ms = kDefaultBootWaitTimeoutMs;
        if (const char* wait_text = getenv("DRMID_BOOT_WAIT_MS")) {
            const unsigned long requested = strtoul(wait_text, nullptr, 10);
            if (requested <= 600000UL) {
                boot_wait_ms = static_cast<uint32_t>(requested);
            }
        }
        char boot_value[PROP_VALUE_MAX]{};
        uint32_t boot_elapsed_ms = 0;
        while (__system_property_get("sys.boot_completed", boot_value) <= 0 ||
               std::strcmp(boot_value, "1") != 0) {
            if (boot_elapsed_ms >= boot_wait_ms) {
                printf("[drmid612] Android boot wait timed out after %u ms\n",
                       boot_elapsed_ms);
                return KModErr::ERR_MODULE_NO_BOOT;
            }
            if (boot_elapsed_ms == 0) {
                printf("[drmid612] waiting for sys.boot_completed; "
                       "timeout=%u ms\n",
                       boot_wait_ms);
            }
            constexpr uint32_t kBootPollMs = 500;
            usleep(kBootPollMs * 1000U);
            boot_elapsed_ms += kBootPollMs;
            boot_value[0] = '\0';
        }
        if (boot_elapsed_ms != 0) {
            printf("[drmid612] Android boot completed after %u ms\n",
                   boot_elapsed_ms);
        }
        // Replace the old unconditional 45-second sleep with an observed
        // stability gate. Hook insertion proceeds after Android/DRM services,
        // the long-lived graphics/system processes and a bounded low-activity
        // window are coherent. Forty-five seconds remains only the fallback
        // deadline when a vendor omits one of the readiness signals.
        const drmid::StartupReadinessPolicy readiness_policy =
            drmid::startup_readiness_policy_from_environment();
        const drmid::StartupReadinessResult readiness =
            drmid::wait_for_adaptive_startup_readiness(readiness_policy);
        printf("[drmid612] post-boot readiness elapsed=%u stable=%u "
               "deadline_fallback=%u\n",
               readiness.elapsed_ms,
               readiness.stable_ms,
               readiness.deadline_fallback ? 1U : 0U);

        uint64_t original_fingerprint = 0;
        const KModErr fingerprint_err =
            drmid::capture_original_id_fingerprint_if_missing(
                module_private_dir, original_fingerprint);
        printf("[drmid612] original DRM ID fingerprint capture=%s "
               "available=%u\n",
               to_string(fingerprint_err).c_str(),
               is_ok(fingerprint_err) && original_fingerprint != 0 ? 1U : 0U);
    }
    drmid::ResolvedTargetConfig target;
    KModErr err = KModErr::ERR_MODULE_STORAGE_NOT_FOUND;
    uint32_t target_wait_ms = daemon_mode
                                  ? kDefaultTargetWaitTimeoutMs
                                  : 0U;
    if (const char* wait_text = getenv("DRMID_TARGET_WAIT_MS")) {
        const unsigned long requested = strtoul(wait_text, nullptr, 10);
        if (requested <= 600000UL) {
            target_wait_ms = static_cast<uint32_t>(requested);
        }
    }
    uint32_t target_elapsed_ms = 0;
    do {
        err = drmid::load_or_resolve_target_config(
            root_key, module_private_dir, target);
        if (is_ok(err) ||
            err != KModErr::ERR_MODULE_STORAGE_NOT_FOUND ||
            target_elapsed_ms >= target_wait_ms) {
            break;
        }
        if (target_elapsed_ms == 0) {
            printf("[drmid612] waiting for Android package service; "
                   "timeout=%u ms\n",
                   target_wait_ms);
        }
        constexpr uint32_t kTargetPollMs = 500;
        usleep(kTargetPollMs * 1000U);
        target_elapsed_ms += kTargetPollMs;
    } while (true);
    if (is_failed(err)) {
        printf("[drmid612] target configuration failed: %s\n",
               to_string(err).c_str());
        return err;
    }
    if (target_elapsed_ms != 0) {
        printf("[drmid612] package service ready after %u ms\n",
               target_elapsed_ms);
    }
    const drmid::TargetRuleMode rule_mode = target.rule_mode;
    const uint32_t target_euid = target.target_euid;
    const bool unconfigured_target =
        rule_mode == drmid::TargetRuleMode::kAll &&
        target.packages.empty() && target.target_euids.empty();
    const char* rule_name = rule_mode == drmid::TargetRuleMode::kExactPackage
                                ? "exact-package"
                            : rule_mode == drmid::TargetRuleMode::kExactEuid
                                ? "exact-euid"
                                : "all";
    printf("[drmid612] target config generation=%" PRIu64
           " state=%s rule=%s packages=%zu targets=%zu first-package=%s "
           "profile-domain=%s first-euid=%u shared-uid=%u duplicates=%zu\n",
           target.generation,
           target.created ? "created" : (target.updated ? "updated" : "loaded"),
           rule_name,
           target.packages.size(),
           target.target_euids.size(),
           target.package_name.empty() ? "-" : target.package_name.c_str(),
           target.profile_domain.empty() ? "-" : target.profile_domain.c_str(),
           target_euid,
           target.shared_uid ? 1U : 0U,
           target.duplicate_package_count);
    if (unconfigured_target) {
        printf("[drmid612] unconfigured bootstrap: no target package; "
               "starting zero-target Dry-run for WebUI configuration\n");
    }
    const bool requested_write_test = getenv("DRMID_WRITE_TEST") != nullptr;
    const bool write_test = requested_write_test && !unconfigured_target;
    if (requested_write_test && unconfigured_target) {
        printf("[drmid612] bootstrap ignored write-test request; "
               "Dry-run is mandatory until a package resolves\n");
    }
    if (write_test && rule_mode == drmid::TargetRuleMode::kAll &&
        getenv("DRMID_ALLOW_ALL_UIDS") == nullptr) {
        printf("[drmid612] write-test requires DRMID_TARGET_UID or "
               "DRMID_ALLOW_ALL_UIDS=1\n");
        return KModErr::ERR_MODULE_PARAM;
    }
    drmid::RuntimeProfile profile;
    err = drmid::load_or_create_runtime_profile(
        getenv("DRMID_REGENERATE_SEED") != nullptr,
        module_private_dir,
        rule_mode,
        target_euid,
        target.profile_domain.empty() ? nullptr : target.profile_domain.c_str(),
        profile);
    if (is_failed(err)) {
        printf("[drmid612] runtime profile failed: %s\n",
               to_string(err).c_str());
        return err;
    }
    printf("[drmid612] crypto self-test=pass seed=%s generation=%" PRIu64
           " profile_fingerprint=%016" PRIx64
           " rule=%s target_euid=%u\n",
           profile.seed_created ? "created" : "loaded",
           profile.seed_generation,
           profile.profile_fingerprint,
           rule_name,
           target_euid);
    if (getenv("DRMID_CONFIG_ONLY") != nullptr) {
        printf("[drmid612] config-only mode: persistent profile verified\n");
        return KModErr::OK;
    }

    const int api_level = android_get_device_api_level();
    const std::string kernel_version = kernel_module::get_kernel_version();
    printf("[drmid612] Android API=%d kernel=%s\n",
           api_level,
           kernel_version.c_str());
    const bool supported_kernel_family =
        kernel_version.rfind("6.6.", 0) == 0 ||
        kernel_version.rfind("6.12.", 0) == 0;
    if (api_level < 34 || !supported_kernel_family) {
        return KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
    }

    std::string binder_path;
    const int binder_fd = open_binder_driver(binder_path);
    if (binder_fd < 0) {
        printf("[drmid612] open binder failed: errno=%d (%s)\n",
               errno,
               strerror(errno));
        return KModErr::ERR_MODULE_OPEN_FILE;
    }
    printf("[drmid612] binder path=%s\n", binder_path.c_str());

    drmid::BinderIoctlResolution resolution;
    err = drmid::resolve_binder_ioctl_from_fd(binder_fd, resolution);
    if (is_failed(err)) {
        printf("[drmid612] resolver failed: %s\n", to_string(err).c_str());
        close(binder_fd);
        return err;
    }
    print_resolution(resolution);

    if (!drmid::is_supported_ioctl_profile(resolution, kernel_version)) {
        printf("[drmid612] strict kernel/backend profile guard rejected "
               "kernel=%s backend=%s\n",
               kernel_version.c_str(),
               drmid::binder_backend_name(resolution.backend));
        close(binder_fd);
        return KModErr::ERR_MODULE_FUNC_NOT_STANDARD;
    }

    drmid::TaskIdentityOffsets task_offsets;
    err = drmid::resolve_and_validate_task_identity_offsets(task_offsets);
    printf("[drmid612] task identity offsets pid=%u tgid=%u cred=%u "
           "cred.euid=%u result=%s\n",
           task_offsets.pid,
           task_offsets.tgid,
           task_offsets.cred,
           task_offsets.cred_euid,
           to_string(err).c_str());
    if (is_failed(err)) {
        close(binder_fd);
        return err;
    }

    if (getenv("DRMID_RESOLVE_ONLY") != nullptr) {
        printf("[drmid612] resolver-only mode: profile and task identity "
               "verified, no Hook installed\n");
        close(binder_fd);
        return KModErr::OK;
    }

    drmid::ReplacementConfig config;
    config.mode = write_test ? drmid::ReplacementMode::kWriteTest
                             : drmid::ReplacementMode::kDryRun;
    config.rule_mode = static_cast<uint32_t>(rule_mode);
    config.target_count = target.target_euids.size();
    if (config.target_count > drmid::kRuntimeTargetLimit) {
        return KModErr::ERR_MODULE_PARAM;
    }
    std::copy(target.target_euids.begin(),
              target.target_euids.end(),
              config.target_euids.begin());
    config.virtual_id_length = kDeviceReplyLength;
    config.config_generation = target.generation;
    config.seed_generation = profile.seed_generation;
    config.virtual_id = profile.virtual_stream;
    config.profile_fingerprint = drmid::virtual_id_fingerprint(
        config.virtual_id.data(), config.virtual_id_length);
    std::string runtime_control_path;
    if (const char* override_path = getenv("DRMID_RUNTIME_CONTROL_FILE")) {
        runtime_control_path = override_path;
    } else if (daemon_mode) {
        runtime_control_path =
            drmid::default_runtime_control_path(module_private_dir);
    }
    if (daemon_mode && !runtime_control_path.empty()) {
        bool migrated_control = false;
        const KModErr migration_err = drmid::migrate_runtime_control_v1(
            runtime_control_path.c_str(), config, migrated_control);
        if (is_failed(migration_err)) {
            printf("[drmid612] startup control migration rejected: %s\n",
                   to_string(migration_err).c_str());
        } else if (migrated_control) {
            printf("[drmid612] startup control migrated v1-to-v2\n");
        }
        drmid::ReplacementConfig persisted;
        const KModErr persisted_err = drmid::read_runtime_control_file(
            runtime_control_path.c_str(), persisted);
        if (is_ok(persisted_err)) {
            const bool same_targets =
                persisted.rule_mode == config.rule_mode &&
                persisted.target_count == config.target_count &&
                persisted.target_euids == config.target_euids;
            if (same_targets &&
                persisted.config_generation >= config.config_generation) {
                config = persisted;
            } else if (!same_targets) {
                const uint64_t base_generation =
                    std::max(persisted.config_generation,
                             config.config_generation);
                if (base_generation == std::numeric_limits<uint64_t>::max()) {
                    close(binder_fd);
                    return KModErr::ERR_MODULE_PARAM;
                }
                persisted.rule_mode = config.rule_mode;
                persisted.target_count = config.target_count;
                persisted.target_euids = config.target_euids;
                persisted.config_generation = base_generation + 1;
                const KModErr rebind_err = drmid::write_runtime_control_file(
                    runtime_control_path.c_str(), persisted);
                if (is_failed(rebind_err)) {
                    close(binder_fd);
                    return rebind_err;
                }
                config = persisted;
                printf("[drmid612] startup control rebound to resolved target "
                       "set generation=%" PRIu64 " targets=%u\n",
                       config.config_generation,
                       config.target_count);
            }
            const uint64_t actual_fingerprint = drmid::virtual_id_fingerprint(
                config.virtual_id.data(), config.virtual_id_length);
            if (actual_fingerprint == 0) {
                close(binder_fd);
                return KModErr::ERR_MODULE_STORAGE_TYPE;
            }
            if (config.profile_fingerprint != actual_fingerprint) {
                config.profile_fingerprint = actual_fingerprint;
                const KModErr repair_err = drmid::write_runtime_control_file(
                    runtime_control_path.c_str(), config);
                if (is_failed(repair_err)) {
                    close(binder_fd);
                    return repair_err;
                }
                printf("[drmid612] runtime fingerprint normalized to active "
                       "ID bytes\n");
            }
            printf("[drmid612] startup control restored generation=%" PRIu64
                   " mode=%u rule=%u targets=%u fingerprint=%016" PRIx64
                   "\n",
                   config.config_generation,
                   static_cast<uint32_t>(config.mode),
                   config.rule_mode,
                   config.target_count,
                   config.profile_fingerprint);
        } else if (persisted_err == KModErr::ERR_MODULE_STORAGE_NOT_FOUND) {
            const KModErr persist_initial_err =
                drmid::write_runtime_control_file(
                    runtime_control_path.c_str(), config);
            if (is_failed(persist_initial_err)) {
                close(binder_fd);
                return persist_initial_err;
            }
            printf("[drmid612] startup control initialized generation=%" PRIu64
                   " targets=%u\n",
                   config.config_generation,
                   config.target_count);
        } else if (is_failed(persisted_err)) {
            printf("[drmid612] startup control ignored: %s\n",
                   to_string(persisted_err).c_str());
        }
    }
    if (unconfigured_target) {
        // A stale development control record must not turn the bootstrap
        // generation into a write-to-all rule. Production starts with a
        // zero-target Dry-run and waits for the first exact-package APPLY.
        config.mode = drmid::ReplacementMode::kDryRun;
        config.rule_mode = static_cast<uint32_t>(drmid::TargetRuleMode::kAll);
        config.target_count = 0;
        config.target_euids.fill(0);
    }
    printf("[drmid612] replacement mode=%s virtual_length=%u\n",
           config.mode == drmid::ReplacementMode::kWriteTest
               ? "write-test"
               : "dry-run",
           config.virtual_id_length);

    drmid::CounterHookSession session;
    err = drmid::install_readonly_parser_hook(
        resolution.ioctl_kaddr, task_offsets, config, session);
    if (is_failed(err)) {
        printf("[drmid612] hook install failed: %s\n", to_string(err).c_str());
        close(binder_fd);
        return err;
    }
    printf("[drmid612] Binder parser hook installed context=%p abi=%" PRIu64
           " size=%zu\n",
           reinterpret_cast<void*>(session.context_kaddr),
           drmid::kCounterContextAbi,
           sizeof(drmid::KernelCounterContext));

    drmid::KernelCounterContext before{};
    drmid::KernelCounterContext after{};
    err = drmid::read_counter_snapshot(session, before);

    int successful_ioctls = 0;
    if (is_ok(err)) {
        for (int i = 0; i < kSelfTestIoctlCount; ++i) {
            binder_write_read bwr{};
            if (ioctl(binder_fd, BINDER_WRITE_READ, &bwr) == 0) {
                ++successful_ioctls;
            } else {
                printf("[drmid612] BINDER_WRITE_READ #%d failed: errno=%d (%s)\n",
                       i,
                       errno,
                       strerror(errno));
            }
        }
        int observation_ms = daemon_mode ? 0 : 750;
        if (const char* value = getenv("DRMID_OBSERVE_MS")) {
            const int requested = atoi(value);
            // Early-boot lifecycle probes need to cover service registration
            // and the first Widevine factory transaction in one Hook session.
            if (requested >= 0 && requested <= 60000) {
                observation_ms = requested;
            }
        }
        if (observation_ms > 0) {
            printf("[drmid612] passive observation window=%d ms\n",
                   observation_ms);
            if (!daemon_mode && !runtime_control_path.empty()) {
                const char* control_path = runtime_control_path.c_str();
                int poll_ms = 25;
                if (const char* poll_text =
                        getenv("DRMID_RUNTIME_CONTROL_POLL_MS")) {
                    const int requested = atoi(poll_text);
                    if (requested >= 5 && requested <= 1000) {
                        poll_ms = requested;
                    }
                }
                uint64_t published_generation = config.config_generation;
                KModErr last_control_err = KModErr::OK;
                int elapsed_ms = 0;
                while (elapsed_ms < observation_ms) {
                    drmid::ReplacementConfig runtime_config;
                    const KModErr read_err = drmid::read_runtime_control_file(
                        control_path, runtime_config);
                    if (is_ok(read_err)) {
                        last_control_err = KModErr::OK;
                        if (runtime_config.config_generation >
                            published_generation) {
                            uint32_t published_slot = 0;
                            const KModErr publish_err =
                                drmid::publish_runtime_config(
                                    session,
                                    runtime_config,
                                    published_slot);
                            if (is_failed(publish_err)) {
                                note_runtime_control_rejection(session);
                                printf("[drmid612] runtime control rejected "
                                       "generation=%" PRIu64
                                       " result=%s\n",
                                       runtime_config.config_generation,
                                       to_string(publish_err).c_str());
                            } else {
                                published_generation =
                                    runtime_config.config_generation;
                                printf("[drmid612] runtime control published "
                                       "generation=%" PRIu64
                                       " slot=%u mode=%u rule=%u targets=%u "
                                       "length=%u fingerprint=%016" PRIx64
                                       "\n",
                                       runtime_config.config_generation,
                                       published_slot,
                                       static_cast<uint32_t>(
                                           runtime_config.mode),
                                       runtime_config.rule_mode,
                                       runtime_config.target_count,
                                       runtime_config.virtual_id_length,
                                       runtime_config.profile_fingerprint);
                            }
                        }
                    } else if (read_err !=
                               KModErr::ERR_MODULE_STORAGE_NOT_FOUND &&
                               read_err != last_control_err) {
                        note_runtime_control_rejection(session);
                        last_control_err = read_err;
                        printf("[drmid612] runtime control read rejected: %s\n",
                               to_string(read_err).c_str());
                    }
                    usleep(static_cast<useconds_t>(poll_ms) * 1000U);
                    elapsed_ms += poll_ms;
                }
                printf("[drmid612] runtime control polling path=%s "
                       "elapsed=%d ms generation=%" PRIu64 "\n",
                       control_path,
                       elapsed_ms,
                       published_generation);
            } else if (const char* trigger =
                           getenv("DRMID_ROOT_DEVICE_TRIGGER")) {
                std::string trigger_output;
                const KModErr trigger_err = skroot_env::run_root_cmd(
                    root_key, trigger, trigger_output);
                if (!trigger_output.empty()) {
                    printf("%s%s",
                           trigger_output.c_str(),
                           trigger_output.back() == '\n' ? "" : "\n");
                }
                printf("[drmid612] root device trigger result=%s\n",
                       to_string(trigger_err).c_str());
            } else if (const char* trigger = getenv("DRMID_DEVICE_TRIGGER")) {
                const int trigger_status = system(trigger);
                printf("[drmid612] device trigger status=%d\n",
                       trigger_status);
            } else if (const char* until_file =
                    getenv("DRMID_OBSERVE_UNTIL_FILE")) {
                int elapsed_ms = 0;
                while (elapsed_ms < observation_ms &&
                       access(until_file, F_OK) != 0) {
                    usleep(1000U);
                    ++elapsed_ms;
                }
                printf("[drmid612] observation trigger=%s elapsed=%d ms\n",
                       access(until_file, F_OK) == 0 ? "seen" : "timeout",
                       elapsed_ms);
            } else {
                usleep(static_cast<useconds_t>(observation_ms) * 1000U);
            }
        }
        err = drmid::read_counter_snapshot(session, after);
    }

    if (is_ok(err)) {
        const uint64_t pre_delta = after.pre_calls - before.pre_calls;
        const uint64_t post_delta = after.post_calls - before.post_calls;
        const uint64_t bwr_delta = delta(after.bwr_calls, before.bwr_calls);
        const uint64_t pre_ok_delta =
            delta(after.pre_header_ok, before.pre_header_ok);
        const uint64_t post_ok_delta =
            delta(after.post_header_ok, before.post_header_ok);
        printf("[drmid612] BINDER_WRITE_READ empty ok=%d/%d\n",
               successful_ioctls,
               kSelfTestIoctlCount);
        print_parser_snapshot("before", before);
        print_parser_snapshot("after", after);
        print_recent_events(after, 16);
        printf("[drmid612] required deltas pre/post/bwr/pre-ok/post-ok="
               "%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64
               "/%" PRIu64 "\n",
               pre_delta,
               post_delta,
               bwr_delta,
               pre_ok_delta,
               post_ok_delta);
        if (successful_ioctls != kSelfTestIoctlCount ||
            pre_delta < static_cast<uint64_t>(kSelfTestIoctlCount) ||
            post_delta < static_cast<uint64_t>(kSelfTestIoctlCount) ||
            bwr_delta < static_cast<uint64_t>(kSelfTestIoctlCount) ||
            pre_ok_delta < static_cast<uint64_t>(kSelfTestIoctlCount) ||
            post_ok_delta < static_cast<uint64_t>(kSelfTestIoctlCount)) {
            err = KModErr::ERR_MODULE_TEST_CHANNEL;
        }
    }

    if (is_ok(err) && daemon_mode) {
        std::string socket_path;
        if (const char* override_path = getenv("DRMID_CONTROL_SOCKET_PATH")) {
            socket_path = override_path;
        } else {
            socket_path = drmid::default_control_socket_path(module_private_dir);
        }
        uint32_t max_runtime_ms = 0;
        if (const char* text = getenv("DRMID_DAEMON_MAX_MS")) {
            const unsigned long requested = strtoul(text, nullptr, 10);
            if (requested <= 3600000UL) {
                max_runtime_ms = static_cast<uint32_t>(requested);
            }
        }
        if (socket_path.empty() || runtime_control_path.empty()) {
            err = KModErr::ERR_MODULE_PARAM;
        } else {
            err = drmid::run_control_socket_server(
                session,
                socket_path.c_str(),
                runtime_control_path.c_str(),
                max_runtime_ms);
            drmid::KernelCounterContext final_snapshot{};
            const KModErr final_err =
                drmid::read_counter_snapshot(session, final_snapshot);
            if (is_ok(final_err)) {
                print_parser_snapshot("daemon-final", final_snapshot);
            } else if (is_ok(err)) {
                err = final_err;
            }
        }
    }

    const KModErr remove_err = drmid::remove_readonly_parser_hook(session);
    if (is_failed(remove_err)) {
        // session keeps its context address on failure; see the removal helper.
        printf("[drmid612] hook removal failed; RW context retained: %s\n",
               to_string(remove_err).c_str());
        close(binder_fd);
        return remove_err;
    }
    printf("[drmid612] parser hook removed; context=%p retained until "
           "reboot for active_calls=%" PRIu64 "\n",
           reinterpret_cast<void*>(session.context_kaddr),
           session.active_at_remove);
    close(binder_fd);
    return err;
}

} // namespace

int skroot_module_main(const char* root_key, const char* module_private_dir) {
    printf("[drmid612] DRM ID Binder virtualizer probe starting; private_dir=%s\n",
           module_private_dir != nullptr ? module_private_dir : "");
    const bool foreground = getenv("DRMID_FOREGROUND") != nullptr;
    const bool exec_daemon = getenv("DRMID_EXEC_DAEMON") != nullptr;
    drmid::DaemonLockHandle daemon_lock;
    if (!foreground) {
        if (root_key == nullptr || root_key[0] == '\0' ||
            module_private_dir == nullptr || module_private_dir[0] == '\0') {
            return static_cast<int>(to_num(KModErr::ERR_MODULE_PARAM));
        }
        std::string daemon_path(module_private_dir);
        if (daemon_path.back() != '/') daemon_path.push_back('/');
        daemon_path += "webroot/drmid_daemon";
        if (chmod(daemon_path.c_str(), 0700) != 0) {
            printf("[drmid612] daemon executable unavailable errno=%d\n",
                   errno);
            return static_cast<int>(to_num(KModErr::ERR_MODULE_OPEN_FILE));
        }
        int key_pipe[2] = {-1, -1};
        if (pipe2(key_pipe, O_CLOEXEC) != 0) {
            return static_cast<int>(to_num(KModErr::ERR_MODULE_TEST_CHANNEL));
        }
        fflush(nullptr);
        const pid_t child = fork();
        if (child < 0) {
            close(key_pipe[0]);
            close(key_pipe[1]);
            printf("[drmid612] daemon fork failed: errno=%d (%s)\n",
                   errno,
                   strerror(errno));
            return static_cast<int>(to_num(KModErr::ERR_MODULE_TEST_CHANNEL));
        }
        if (child > 0) {
            close(key_pipe[0]);
            const size_t key_length = std::strlen(root_key);
            size_t written = 0;
            while (written < key_length + 1) {
                const char* data = written < key_length
                                       ? root_key + written
                                       : "\n";
                const size_t remaining = written < key_length
                                             ? key_length - written
                                             : 1;
                const ssize_t count = write(key_pipe[1], data, remaining);
                if (count > 0) {
                    written += static_cast<size_t>(count);
                } else if (count < 0 && errno == EINTR) {
                    continue;
                } else {
                    break;
                }
            }
            close(key_pipe[1]);
            printf("[drmid612] exec daemon spawned pid=%ld\n",
                   static_cast<long>(child));
            // The SKP loader process returns immediately while the detached
            // daemon waits for the post-boot readiness gate. Explicitly keep
            // the installed-module card in Running instead of leaving the
            // loader's default NotRunning state.
            kernel_module::set_current_module_run_state(
                skroot_env::ModuleRunState::Running);
            return 0;
        }
        close(key_pipe[1]);
        if (setsid() < 0) {
            _exit(static_cast<int>(to_num(KModErr::ERR_MODULE_TEST_CHANNEL)) &
                  0xff);
        }
        if (dup2(key_pipe[0], STDIN_FILENO) < 0) {
            _exit(static_cast<int>(to_num(KModErr::ERR_MODULE_TEST_CHANNEL)) &
                  0xff);
        }
        close(key_pipe[0]);
        umask(0077);
        signal(SIGPIPE, SIG_IGN);
        setenv("DRMID_EXEC_DAEMON", "1", 1);
        setenv("DRMID_FOREGROUND", "1", 1);
        setenv("DRMID_DAEMON_MODE", "1", 1);
        setenv("DRMID_MODULE_PRIVATE_DIR", module_private_dir, 1);
        execl(daemon_path.c_str(), daemon_path.c_str(), nullptr);
        _exit(static_cast<int>(to_num(KModErr::ERR_MODULE_OPEN_FILE)) & 0xff);
    }

    if (exec_daemon) {
        umask(0077);
        signal(SIGPIPE, SIG_IGN);
        setenv("DRMID_DAEMON_MODE", "1", 1);
        if (module_private_dir == nullptr || module_private_dir[0] == '\0' ||
            (mkdir(module_private_dir, 0700) != 0 && errno != EEXIST)) {
            _exit(static_cast<int>(to_num(KModErr::ERR_MODULE_STORAGE_WRITE)) &
                  0xff);
        }
        if (!drmid::acquire_daemon_lock(module_private_dir, daemon_lock)) {
            _exit(0);
        }
        drmid::cleanup_seed_temp_orphans(module_private_dir);
        if (!drmid::write_daemon_lock_pid(daemon_lock, getpid())) {
            drmid::release_daemon_lock(daemon_lock);
            _exit(static_cast<int>(to_num(KModErr::ERR_MODULE_STORAGE_WRITE)) &
                  0xff);
        }
    }

    const KModErr err = run_readonly_parser_probe(root_key, module_private_dir);
    printf("[drmid612] Binder virtualizer probe result=%s (%zd)\n",
           to_string(err).c_str(),
           to_num(err));
    const int result = static_cast<int>(to_num(err));
    if (exec_daemon) {
        drmid::release_daemon_lock(daemon_lock);
        fflush(nullptr);
    }
    return result;
}

void module_on_uninstall(const char*, const char* module_private_dir) {
    const std::string socket_path =
        drmid::default_control_socket_path(module_private_dir);
    drmid::ControlIpcResponse response{};
    const KModErr err = drmid::send_control_ipc_request(
        socket_path.c_str(),
        drmid::ControlIpcOperation::kStop,
        response);
    printf("[drmid612] uninstall stop result=%s daemon_result=%d\n",
           to_string(err).c_str(),
           response.result);
    drmid::cleanup_module_state_files(module_private_dir);
}

SKROOT_MODULE_NAME("虚拟化DRM ID")
SKROOT_MODULE_VERSION("1.1.2")
SKROOT_MODULE_DESC("面向 Android 14+ / Linux 6.6与6.12 的多应用内核级 DRM ID 虚拟化，支持 WebUI 实时配置")
SKROOT_MODULE_AUTHOR("斓梦语")
SKROOT_MODULE_ID32("drmidKern612Probe20260728Alpha01")
SKROOT_MODULE_ON_UNINSTALL(module_on_uninstall)
