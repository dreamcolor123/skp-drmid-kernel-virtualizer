#pragma once

#include <cstddef>
#include <cstdint>

namespace drmid {

constexpr uint64_t kCounterContextMagic = 0x44524d4944363132ULL; // "DRMID612"
constexpr uint64_t kCounterContextAbi = 16;
constexpr size_t kRuntimeTargetLimit = 32;
constexpr size_t kTransactionEventCapacity = 256;
constexpr size_t kPendingSlotCapacity = 256;
constexpr size_t kPendingBucketWays = 8;
constexpr size_t kPendingDepth = 4;
constexpr size_t kPluginSlotCapacity = 256;
constexpr size_t kPluginBucketWays = 8;

enum class BinderEventKind : uint32_t {
    kUnknown = 0,
    kBcTransaction = 1,
    kBcReply = 2,
    kBrTransaction = 3,
    kBrTransactionSecCtx = 4,
    kBrReply = 5,
};

enum class ParcelTokenKind : uint32_t {
    kNone = 0,
    kDrmFactory = 1,
    kDrmPlugin = 2,
};

constexpr uint32_t kParcelFlagDeviceUniqueId = 1U << 0;
constexpr uint32_t kParcelFlagWidevineCreate = 1U << 1;
constexpr uint32_t kParcelFlagWidevinePluginMatched = 1U << 2;
constexpr uint32_t kReplyFlagCorrelatedDeviceUniqueId = 1U << 0;
constexpr uint32_t kReplyFlagStatusOk = 1U << 1;
constexpr uint32_t kReplyFlagArrayValid = 1U << 2;
constexpr uint32_t kReplyFlagContentReadable = 1U << 3;
constexpr uint32_t kReplyFlagReplacementCandidate = 1U << 4;
constexpr uint32_t kReplyFlagDryRun = 1U << 5;
constexpr uint32_t kReplyFlagReplaced = 1U << 6;
constexpr uint32_t kReplyFlagRuleMatched = 1U << 7;
constexpr uint32_t kReplyFlagWidevinePluginRegistered = 1U << 8;

enum class ReplacementMode : uint32_t {
    kDryRun = 0,
    kWriteTest = 1,
};

// Seqlock-style ring entry. Writers publish an odd sequence, fill the record,
// then store the expected even sequence with release ordering. EL0 accepts a
// snapshot entry only when sequence == event_id * 2.
struct alignas(8) BinderTransactionEvent {
    uint64_t sequence;
    uint64_t event_id;
    uint64_t task_kaddr;
    uint64_t target;
    uint64_t cookie;
    uint64_t data_size;
    uint64_t offsets_size;
    uint64_t buffer;
    uint64_t offsets;
    uint64_t correlated_request_id;
    uint32_t pid;
    uint32_t tgid;
    uint32_t command;
    uint32_t code;
    uint32_t flags;
    uint32_t sender_pid;
    uint32_t sender_euid;
    uint32_t kind;
    uint32_t parcel_token_kind;
    uint32_t parcel_token_offset;
    uint32_t parcel_prefix_size;
    uint32_t parcel_flags;
    uint32_t correlated_request_flags;
    uint32_t reply_prefix_size;
    int32_t reply_status_code;
    int32_t reply_byte_array_length;
    uint32_t reply_byte_array_offset;
    uint32_t reply_flags;
    uint32_t factory_uuid_offset;
    uint32_t plugin_handle;
};

struct alignas(8) BinderPendingFrame {
    uint64_t request_event_id;
    uint64_t target;
    uint64_t data_size;
    uint32_t code;
    uint32_t flags;
    uint32_t parcel_flags;
    uint32_t reserved;
};

// Eight-way bucketed table keyed by current task pointer and checked against
// pid/tgid to detect task-struct address reuse. A bounded fail-open try-lock
// protects only lookup/push/pop; contention skips correlation instead of
// blocking the global Binder ioctl path. Full buckets reclaim their oldest
// outstanding frame so an exited client cannot permanently poison a bucket.
struct alignas(8) BinderPendingSlot {
    uint64_t task_kaddr;
    uint32_t pid;
    uint32_t tgid;
    uint32_t depth;
    uint32_t reserved;
    BinderPendingFrame frames[kPendingDepth];
};

// Eight-way table of Widevine plugin handles owned by a Binder client. The
// Binder file pointer prevents cross-context handle aliasing; owner_tgid and
// handle prevent cross-process reuse. registered_event_id is also the bounded
// LRU age used to reclaim entries left behind by a client that exited without
// emitting BC_RELEASE.
struct alignas(8) BinderPluginSlot {
    uint64_t binder_file;
    uint64_t registered_event_id;
    uint32_t owner_tgid;
    uint32_t handle;
    uint32_t generation;
    uint32_t reserved;
};

// A complete replacement policy is published as one immutable slot. The
// active slot index in KernelCounterContext is acquired by the generated
// Binder handler, so a request observes either the old or the new policy and
// never a partially written combination of fields.
struct alignas(8) RuntimeConfigSlot {
    uint64_t config_generation;
    uint64_t seed_generation;
    uint64_t profile_fingerprint;
    uint32_t replacement_mode;
    uint32_t rule_mode;
    uint32_t target_count;
    uint32_t virtual_id_length;
    uint32_t target_euids[kRuntimeTargetLimit];
    uint8_t virtual_id[64];
};

static_assert(sizeof(RuntimeConfigSlot) == 232);
static_assert(offsetof(RuntimeConfigSlot, replacement_mode) == 24);
static_assert(offsetof(RuntimeConfigSlot, target_euids) == 40);
static_assert(offsetof(RuntimeConfigSlot, virtual_id) == 168);

// This object lives in preallocated kernel RW memory. Request/reply parsing is
// bounded; write-test mode modifies only a validated, exact-length Binder
// reply range and records the selected fallback path here.
struct alignas(8) KernelCounterContext {
    uint64_t magic;
    uint64_t abi_version;
    uint64_t active_calls;
    uint64_t pre_calls;
    uint64_t post_calls;
    uint64_t bwr_calls;
    uint64_t pre_header_ok;
    uint64_t pre_header_faults;
    uint64_t post_header_ok;
    uint64_t post_header_faults;
    uint64_t invalid_consumed;
    uint64_t write_streams;
    uint64_t read_streams;
    uint64_t bc_commands;
    uint64_t br_commands;
    uint64_t bc_transaction_commands;
    uint64_t br_transaction_commands;
    uint64_t write_boundary_errors;
    uint64_t read_boundary_errors;
    uint64_t write_copy_faults;
    uint64_t read_copy_faults;
    uint64_t write_capped;
    uint64_t read_capped;

    uint64_t transaction_metadata_ok;
    uint64_t transaction_metadata_faults;
    uint64_t event_write_index;
    uint64_t pending_lock_state;
    uint64_t pending_lock_drops;
    uint64_t pending_pushes;
    uint64_t pending_pops;
    uint64_t pending_terminal_pops;
    uint64_t pending_misses;
    uint64_t pending_overflows;
    uint64_t pending_collisions;
    uint64_t pending_oneway_ignored;
    uint64_t parcel_prefix_ok;
    uint64_t parcel_prefix_faults;
    uint64_t parcel_factory_hits;
    uint64_t parcel_plugin_hits;
    uint64_t parcel_device_unique_id_hits;
    uint64_t parcel_unknown_tokens;
    uint64_t reply_candidates;
    uint64_t reply_header_copy_ok;
    uint64_t reply_header_copy_faults;
    uint64_t reply_status_ok;
    uint64_t reply_status_nonzero;
    uint64_t reply_array_valid;
    uint64_t reply_array_invalid;
    uint64_t reply_content_copy_ok;
    uint64_t reply_content_copy_faults;
    uint64_t replacement_candidates;
    uint64_t replacement_length_mismatch;
    uint64_t replacement_dry_run_hits;
    uint64_t replacement_write_ok;
    uint64_t replacement_write_faults;
    uint64_t replacement_copy_to_user_faults;
    uint64_t replacement_access_vm_ok;
    uint64_t replacement_access_vm_faults;
    uint64_t replacement_page_pin_ok;
    uint64_t replacement_page_pin_faults;
    uint64_t replacement_page_write_ok;
    uint64_t replacement_page_write_faults;
    int64_t replacement_access_vm_last_result;
    int64_t replacement_page_pin_last_result;
    uint64_t replacement_last_request_id;
    uint32_t replacement_last_reply_flags;
    int32_t replacement_last_array_length;

    uint64_t rule_checks;
    uint64_t rule_matches;
    uint64_t rule_misses;
    uint64_t rule_cred_faults;
    uint64_t last_client_euid;

    uint64_t plugin_lock_state;
    uint64_t plugin_lock_drops;
    uint64_t widevine_create_requests;
    uint64_t create_reply_candidates;
    uint64_t create_reply_ok;
    uint64_t create_reply_faults;
    uint64_t plugin_map_inserts;
    uint64_t plugin_map_reuses;
    uint64_t plugin_map_collisions;
    uint64_t plugin_map_lookups;
    uint64_t plugin_map_hits;
    uint64_t plugin_map_misses;
    uint64_t plugin_map_releases;
    uint64_t plugin_map_release_misses;
    uint64_t plugin_map_active;

    uint64_t last_create_data_size;
    uint64_t last_create_offsets_size;
    uint32_t last_create_stage;
    int32_t last_create_status;
    uint32_t last_create_object_offset;
    uint32_t last_create_object_type;
    uint32_t last_create_handle;
    uint32_t last_create_reserved;

    uint64_t config_generation;
    uint64_t seed_generation;
    uint64_t profile_fingerprint;
    uint32_t replacement_mode;
    uint32_t rule_mode;
    uint32_t target_count;
    uint32_t virtual_id_length;
    uint32_t target_euids[kRuntimeTargetLimit];
    uint8_t virtual_id[64];

    BinderTransactionEvent events[kTransactionEventCapacity];
    BinderPendingSlot pending[kPendingSlotCapacity];
    BinderPluginSlot plugins[kPluginSlotCapacity];

    // Published with release ordering after the inactive RuntimeConfigSlot
    // has been fully written. The low bit is the active slot number.
    uint32_t active_config_slot;
    uint32_t active_config_reserved;
    uint64_t runtime_config_switches;
    uint64_t runtime_config_rejections;
    RuntimeConfigSlot config_slots[2];
};

static_assert(sizeof(BinderTransactionEvent) == 160);
static_assert(offsetof(BinderTransactionEvent, correlated_request_id) == 72);
static_assert(offsetof(BinderTransactionEvent, pid) == 80);
static_assert(offsetof(BinderTransactionEvent, kind) == 108);
static_assert(offsetof(BinderTransactionEvent, parcel_token_kind) == 112);
static_assert(offsetof(BinderTransactionEvent, parcel_flags) == 124);
static_assert(offsetof(BinderTransactionEvent, correlated_request_flags) == 128);
static_assert(offsetof(BinderTransactionEvent, reply_flags) == 148);
static_assert(offsetof(BinderTransactionEvent, factory_uuid_offset) == 152);
static_assert(offsetof(BinderTransactionEvent, plugin_handle) == 156);
static_assert(sizeof(BinderPendingFrame) == 40);
static_assert(sizeof(BinderPendingSlot) == 184);
static_assert(offsetof(BinderPendingSlot, frames) == 24);
static_assert(sizeof(BinderPluginSlot) == 32);
static_assert(offsetof(BinderPluginSlot, owner_tgid) == 16);

static_assert(offsetof(KernelCounterContext, active_calls) == 16);
static_assert(offsetof(KernelCounterContext, bwr_calls) == 40);
static_assert(offsetof(KernelCounterContext, bc_transaction_commands) == 120);
static_assert(offsetof(KernelCounterContext, write_capped) == 168);
static_assert(offsetof(KernelCounterContext, transaction_metadata_ok) == 184);
static_assert(offsetof(KernelCounterContext, event_write_index) == 200);
static_assert(offsetof(KernelCounterContext, pending_lock_state) == 208);
static_assert(offsetof(KernelCounterContext, pending_lock_drops) == 216);
static_assert(offsetof(KernelCounterContext, pending_pushes) == 224);
static_assert(offsetof(KernelCounterContext, parcel_prefix_ok) == 280);
static_assert(offsetof(KernelCounterContext, reply_candidates) == 328);
static_assert(offsetof(KernelCounterContext, replacement_candidates) == 400);
static_assert(offsetof(KernelCounterContext,
                       replacement_copy_to_user_faults) == 440);
static_assert(offsetof(KernelCounterContext, replacement_access_vm_ok) == 448);
static_assert(offsetof(KernelCounterContext,
                       replacement_access_vm_faults) == 456);
static_assert(offsetof(KernelCounterContext, replacement_page_pin_ok) == 464);
static_assert(offsetof(KernelCounterContext,
                       replacement_page_write_faults) == 488);
static_assert(offsetof(KernelCounterContext,
                       replacement_access_vm_last_result) == 496);
static_assert(offsetof(KernelCounterContext,
                       replacement_page_pin_last_result) == 504);
static_assert(offsetof(KernelCounterContext,
                       replacement_last_request_id) == 512);
static_assert(offsetof(KernelCounterContext,
                       replacement_last_reply_flags) == 520);
static_assert(offsetof(KernelCounterContext,
                       replacement_last_array_length) == 524);
static_assert(offsetof(KernelCounterContext, rule_checks) == 528);
static_assert(offsetof(KernelCounterContext, last_client_euid) == 560);
static_assert(offsetof(KernelCounterContext, plugin_lock_state) == 568);
static_assert(offsetof(KernelCounterContext, plugin_lock_drops) == 576);
static_assert(offsetof(KernelCounterContext, widevine_create_requests) == 584);
static_assert(offsetof(KernelCounterContext, plugin_map_inserts) == 616);
static_assert(offsetof(KernelCounterContext, plugin_map_lookups) == 640);
static_assert(offsetof(KernelCounterContext, plugin_map_active) == 680);
static_assert(offsetof(KernelCounterContext, last_create_data_size) == 688);
static_assert(offsetof(KernelCounterContext, last_create_stage) == 704);
static_assert(offsetof(KernelCounterContext, last_create_handle) == 720);
static_assert(offsetof(KernelCounterContext, config_generation) == 728);
static_assert(offsetof(KernelCounterContext, seed_generation) == 736);
static_assert(offsetof(KernelCounterContext, profile_fingerprint) == 744);
static_assert(offsetof(KernelCounterContext, replacement_mode) == 752);
static_assert(offsetof(KernelCounterContext, rule_mode) == 756);
static_assert(offsetof(KernelCounterContext, target_count) == 760);
static_assert(offsetof(KernelCounterContext, virtual_id_length) == 764);
static_assert(offsetof(KernelCounterContext, target_euids) == 768);
static_assert(offsetof(KernelCounterContext, virtual_id) == 896);
static_assert(offsetof(KernelCounterContext, events) == 960);
static_assert(offsetof(KernelCounterContext, pending) ==
              960 + sizeof(BinderTransactionEvent) * kTransactionEventCapacity);
static_assert(offsetof(KernelCounterContext, plugins) ==
              960 + sizeof(BinderTransactionEvent) * kTransactionEventCapacity +
                  sizeof(BinderPendingSlot) * kPendingSlotCapacity);
static_assert(offsetof(KernelCounterContext, active_config_slot) == 97216);
static_assert(offsetof(KernelCounterContext, runtime_config_switches) == 97224);
static_assert(offsetof(KernelCounterContext, runtime_config_rejections) ==
              97232);
static_assert(offsetof(KernelCounterContext, config_slots) == 97240);
static_assert(sizeof(KernelCounterContext) == 97704);

} // namespace drmid
