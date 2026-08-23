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
#include <vector>

#include "binder_hook_builder.h"
#include "binder_ioctl_resolver.h"
#include "control_ipc.h"
#include "device_id_fingerprint.h"
#include "file_lifecycle.h"
#include "hal_identity.h"
#include "kernel_module_kit_umbrella.h"
#include "runtime_control.h"
#include "runtime_profile.h"
#include "startup_readiness.h"
#include "tee_firmware_identity.h"
#include "tee_hook_builder.h"

namespace {

constexpr int kSelfTestIoctlCount = 8;
constexpr uint32_t kDeviceReplyLength =
    drmid::kWidevineDeviceUniqueIdBytes;
constexpr uint32_t kDefaultBootWaitTimeoutMs = 180000;
constexpr char kPrivateBootCleanupMarker[] =
    "webroot/drmid_boot_cleanup.flag";
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
    const uint32_t config_slot = s.active_config_slot & 1U;
    const auto& config = s.config_slots[config_slot];
    const uint32_t hal_slot = s.active_hal_identity_slot & 1U;
    const auto& hal = s.hal_identity_slots[hal_slot];
    printf("[drmid612] %s calls active/pre/post/bwr=%" PRIu64
           "/%" PRIu64 "/%" PRIu64 "/%" PRIu64
           " hal-gate=%" PRIu64 " identities=%u/%" PRIu64 "\n",
           label,
           s.active_calls,
           s.pre_calls,
           s.post_calls,
           s.bwr_calls,
           s.hal_gate_hits,
           hal.count,
           hal.generation);
    printf("[drmid612] %s streams BC/BR=%" PRIu64 "/%" PRIu64
           " transactions=%" PRIu64 "/%" PRIu64
           " boundary=%" PRIu64 "/%" PRIu64
           " copy-fault=%" PRIu64 "/%" PRIu64 "\n",
           label,
           s.bc_commands,
           s.br_commands,
           s.bc_transaction_commands,
           s.br_transaction_commands,
           s.write_boundary_errors,
           s.read_boundary_errors,
           s.write_copy_faults,
           s.read_copy_faults);
    printf("[drmid612] %s server request/correlated/reply-no-pending="
           "%" PRIu64 "/%" PRIu64 "/%" PRIu64
           " pending push/pop/miss/stale/drop=%" PRIu64 "/%" PRIu64
           "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 "\n",
           label,
           s.server_request_hits,
           s.correlated_reply_candidates,
           s.reply_without_pending,
           s.pending_pushes,
           s.pending_pops,
           s.pending_misses,
           s.pending_generation_stale,
           s.pending_lock_drops);
    printf("[drmid612] %s replacement candidate/dry/write/fault/copy-fault="
           "%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64
           "/%" PRIu64
           " config slot/gen/seed/mode/length/fingerprint=%u/%" PRIu64
           "/%" PRIu64 "/%u/%u/%016" PRIx64 "\n",
           label,
           s.replacement_candidates,
           s.replacement_dry_run_hits,
           s.replacement_write_ok,
           s.replacement_write_faults,
           s.replacement_copy_to_user_faults,
           config_slot,
           config.config_generation,
           config.seed_generation,
           config.replacement_mode,
           config.virtual_id_length,
           config.profile_fingerprint);
    size_t controller_count = 0;
    size_t tee_object_count = 0;
    for (const uint64_t object : s.tee_controller_objects) {
        if (object != 0) ++controller_count;
    }
    for (const uint64_t object : s.tee_widevine_objects) {
        if (object != 0) ++tee_object_count;
    }
    printf("[drmid612] %s TEE state/controllers/objects=%u/%zu/%zu "
           "invoke/free=%" PRIu64 "/%" PRIu64
           " loader/hit/fault=%" PRIu64 "/%" PRIu64 "/%" PRIu64
           " op9/dry/write/fault=%" PRIu64 "/%" PRIu64 "/%" PRIu64
           "/%" PRIu64 "\n",
           label,
           s.tee_backend_state,
           controller_count,
           tee_object_count,
           s.tee_invoke_calls,
           s.tee_free_calls,
           s.tee_loader_candidates,
           s.tee_loader_identity_hits,
           s.tee_loader_identity_faults,
           s.tee_op9_candidates,
           s.tee_op9_dry_run_hits,
           s.tee_op9_write_ok,
           s.tee_op9_write_faults);
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
                   " status=%d array=%d@%u reply_flags=%08x\n",
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
                   reply_parse_flags);
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
               " reply=%d/%d@%u/%08x\n",
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
               event.reply_flags);
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
    KModErr err = KModErr::OK;
    const bool write_test = getenv("DRMID_WRITE_TEST") != nullptr;
    drmid::RuntimeProfile profile;
    err = drmid::load_or_create_runtime_profile(
        getenv("DRMID_REGENERATE_SEED") != nullptr,
        module_private_dir,
        profile);
    if (is_failed(err)) {
        printf("[drmid612] global runtime profile failed: %s\n",
               to_string(err).c_str());
        return err;
    }
    printf("[drmid612] crypto self-test=pass seed=%s generation=%" PRIu64
           " global-profile-fingerprint=%016" PRIx64 "\n",
           profile.seed_created ? "created" : "loaded",
           profile.seed_generation,
           profile.profile_fingerprint);
    if (getenv("DRMID_CONFIG_ONLY") != nullptr) {
        printf("[drmid612] config-only mode: global profile verified\n");
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

    drmid::TeeFirmwareIdentity tee_firmware;
    drmid::TeeHookResolution tee_resolution;
    KModErr tee_firmware_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
    KModErr tee_resolution_err = KModErr::ERR_MODULE_SYMBOL_NOT_MATCH_LINUX_VER;
    if (kernel_version.rfind("6.12.", 0) == 0) {
        if (const char* firmware_path =
                getenv("DRMID_WIDEVINE_FIRMWARE_PATH")) {
            tee_firmware_err = drmid::read_tee_firmware_identity(
                firmware_path, 1, tee_firmware);
        } else {
            tee_firmware_err = drmid::discover_tee_firmware_identity(
                1, tee_firmware);
        }
        if (is_ok(tee_firmware_err)) {
            tee_resolution_err = drmid::resolve_and_validate_tee_hooks(
                tee_resolution);
        }
    }
    printf("[drmid612] Widevine TEE firmware=%s available=%u size=%" PRIu64
           " result=%s symbols=%s invoke=%p free=%p\n",
           tee_firmware.path.empty() ? "-" : tee_firmware.path.c_str(),
           is_ok(tee_firmware_err) ? 1U : 0U,
           tee_firmware.file_size,
           to_string(tee_firmware_err).c_str(),
           to_string(tee_resolution_err).c_str(),
           reinterpret_cast<void*>(tee_resolution.invoke_kaddr),
           reinterpret_cast<void*>(tee_resolution.free_kaddr));

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
    printf("[drmid612] task identity offsets pid=%u tgid=%u result=%s\n",
           task_offsets.pid,
           task_offsets.tgid,
           to_string(err).c_str());
    if (is_failed(err)) {
        close(binder_fd);
        return err;
    }

    if (getenv("DRMID_RESOLVE_ONLY") != nullptr) {
        printf("[drmid612] resolver-only mode: profile and task identity "
               "verified, TEE profile checked, no Hook installed\n");
        close(binder_fd);
        return KModErr::OK;
    }

    drmid::ReplacementConfig config;
    config.mode = write_test ? drmid::ReplacementMode::kWriteTest
                             : drmid::ReplacementMode::kDryRun;
    config.virtual_id_length = kDeviceReplyLength;
    config.config_generation = 1;
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
        err = drmid::migrate_runtime_control_v2(
            runtime_control_path.c_str(), migrated_control);
        if (is_failed(err)) {
            printf("[drmid612] runtime control v2-to-v3 migration rejected: %s\n",
                   to_string(err).c_str());
            close(binder_fd);
            return err;
        }
        if (migrated_control) {
            printf("[drmid612] runtime control migrated v2-to-v3 with ID preserved\n");
        }
        const size_t removed_legacy_state =
            drmid::cleanup_legacy_target_state_after_global_migration(
                module_private_dir);
        if (removed_legacy_state != 0) {
            printf("[drmid612] legacy target state removed files=%zu\n",
                   removed_legacy_state);
        }
        drmid::ReplacementConfig persisted;
        const KModErr persisted_err = drmid::read_runtime_control_file(
            runtime_control_path.c_str(), persisted);
        if (is_ok(persisted_err)) {
            const uint64_t actual_fingerprint = drmid::virtual_id_fingerprint(
                persisted.virtual_id.data(), persisted.virtual_id_length);
            if (actual_fingerprint == 0 ||
                actual_fingerprint != persisted.profile_fingerprint) {
                close(binder_fd);
                return KModErr::ERR_MODULE_STORAGE_TYPE;
            }
            config = persisted;
            printf("[drmid612] global control restored generation=%" PRIu64
                   " mode=%u length=%u fingerprint=%016" PRIx64 "\n",
                   config.config_generation,
                   static_cast<uint32_t>(config.mode),
                   config.virtual_id_length,
                   config.profile_fingerprint);
        } else if (persisted_err == KModErr::ERR_MODULE_STORAGE_NOT_FOUND) {
            err = drmid::write_runtime_control_file(
                runtime_control_path.c_str(), config);
            if (is_failed(err)) {
                close(binder_fd);
                return err;
            }
            printf("[drmid612] global control initialized generation=%" PRIu64
                   " mode=%u\n",
                   config.config_generation,
                   static_cast<uint32_t>(config.mode));
        } else {
            close(binder_fd);
            return persisted_err;
        }
    }

    drmid::HalIdentityConfig hal_identities;
    std::vector<drmid::HalProcessInfo> hal_details;
    err = drmid::discover_widevine_hal_identities(
        "/proc", 1, hal_identities, &hal_details);
    if (is_failed(err)) {
        printf("[drmid612] Widevine HAL discovery failed: %s\n",
               to_string(err).c_str());
        close(binder_fd);
        return err;
    }
    printf("[drmid612] Widevine HAL identities generation=%" PRIu64
           " count=%u\n",
           hal_identities.generation,
           hal_identities.count);
    for (const auto& hal : hal_details) {
        printf("[drmid612] HAL tgid=%u uid=%u exe=%s binder=%s\n",
               hal.tgid,
               hal.uid,
               hal.exe.c_str(),
               hal.binder_path.c_str());
    }

    printf("[drmid612] replacement mode=%s virtual_length=%u backend="
           "hal-binder+widevine-smcinvoke-global\n",
           config.mode == drmid::ReplacementMode::kWriteTest
               ? "write-test"
               : "dry-run",
           config.virtual_id_length);

    drmid::CounterHookSession session;
    err = drmid::install_readonly_parser_hook(
        resolution.ioctl_kaddr,
        task_offsets,
        config,
        hal_identities,
        session);
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
    printf("[drmid612] Binder entry gate=installer-tgid,widevine-hal-tgid "
           "installer-tgid=%d hal-count=%u\n",
           getpid(),
           hal_identities.count);

    bool tee_hooks_installed = false;
    if (is_ok(tee_firmware_err) && is_ok(tee_resolution_err)) {
        const KModErr tee_install_err = drmid::install_global_tee_hooks(
            tee_resolution, tee_firmware, session);
        tee_hooks_installed = is_ok(tee_install_err);
        printf("[drmid612] caller-global TEE hooks install=%s "
               "invoke=%p free=%p euid-filter=absent\n",
               to_string(tee_install_err).c_str(),
               reinterpret_cast<void*>(tee_resolution.invoke_kaddr),
               reinterpret_cast<void*>(tee_resolution.free_kaddr));
    } else {
        printf("[drmid612] caller-global TEE backend inactive; "
               "Binder backend remains active\n");
    }

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
                                       " slot=%u mode=%u length=%u "
                                       "fingerprint=%016" PRIx64
                                       "\n",
                                       runtime_config.config_generation,
                                       published_slot,
                                       static_cast<uint32_t>(
                                           runtime_config.mode),
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

    if (tee_hooks_installed) {
        const KModErr tee_remove_err = drmid::remove_global_tee_hooks(session);
        if (is_failed(tee_remove_err)) {
            printf("[drmid612] TEE hook removal failed; RW context retained: %s\n",
                   to_string(tee_remove_err).c_str());
            close(binder_fd);
            return tee_remove_err;
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
    printf("[drmid612] DRM ID global virtualizer probe starting; private_dir=%s\n",
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
SKROOT_MODULE_VERSION("1.3.0-rc2")
SKROOT_MODULE_DESC("面向 Android 14+ / Linux 6.6与6.12 的 Widevine Binder 与 TEE 直连全局 DRM ID 内核虚拟化")
SKROOT_MODULE_AUTHOR("斓梦语")
SKROOT_MODULE_ID32("drmidKern612Probe20260728Alpha01")
SKROOT_MODULE_ON_UNINSTALL(module_on_uninstall)
