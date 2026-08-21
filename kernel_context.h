#pragma once

#include <cstddef>
#include <cstdint>

namespace drmid {

constexpr uint64_t kCounterContextMagic = 0x44524d4944363132ULL; // DRMID612
constexpr uint64_t kCounterContextAbi = 18;
constexpr size_t kHalIdentityLimit = 4;
constexpr uint32_t kWidevineDeviceUniqueIdBytes = 32;
constexpr size_t kTransactionEventCapacity = 256;
constexpr size_t kPendingSlotCapacity = 256;
constexpr size_t kPendingBucketWays = 8;
constexpr size_t kPendingDepth = 4;

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
    kDrmPlugin = 1,
};

constexpr uint32_t kParcelFlagDeviceUniqueId = 1U << 0;
constexpr uint32_t kReplyFlagCorrelatedDeviceUniqueId = 1U << 0;
constexpr uint32_t kReplyFlagStatusOk = 1U << 1;
constexpr uint32_t kReplyFlagArrayValid = 1U << 2;
constexpr uint32_t kReplyFlagContentReadable = 1U << 3;
constexpr uint32_t kReplyFlagReplacementCandidate = 1U << 4;
constexpr uint32_t kReplyFlagDryRun = 1U << 5;
constexpr uint32_t kReplyFlagReplaced = 1U << 6;
constexpr uint32_t kReplyFlagHalCorrelated = 1U << 7;

enum class ReplacementMode : uint32_t {
    kDryRun = 0,
    kWriteTest = 1,
};

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
    uint32_t reserved0;
    uint32_t reserved1;
};

struct alignas(8) BinderPendingFrame {
    uint64_t request_event_id;
    uint64_t target;
    uint64_t data_size;
    uint64_t hal_identity_generation;
    uint32_t code;
    uint32_t flags;
    uint32_t parcel_flags;
    uint32_t reserved;
};

// Eight-way bucket keyed by Binder thread task pointer and checked against
// pid/tgid. A bounded fail-open try-lock protects lookup/push/pop.
struct alignas(8) BinderPendingSlot {
    uint64_t task_kaddr;
    uint32_t pid;
    uint32_t tgid;
    uint32_t depth;
    uint32_t reserved;
    BinderPendingFrame frames[kPendingDepth];
};

struct alignas(8) RuntimeConfigSlot {
    uint64_t config_generation;
    uint64_t seed_generation;
    uint64_t profile_fingerprint;
    uint32_t replacement_mode;
    uint32_t virtual_id_length;
    uint8_t virtual_id[64];
};

struct alignas(8) HalIdentitySet {
    uint64_t generation;
    uint32_t count;
    uint32_t reserved;
    uint32_t tgids[kHalIdentityLimit];
};

static_assert(sizeof(BinderTransactionEvent) == 160);
static_assert(sizeof(BinderPendingFrame) == 48);
static_assert(sizeof(BinderPendingSlot) == 216);
static_assert(sizeof(RuntimeConfigSlot) == 96);
static_assert(offsetof(RuntimeConfigSlot, virtual_id) == 32);
static_assert(sizeof(HalIdentitySet) == 32);
static_assert(offsetof(HalIdentitySet, tgids) == 16);

// Preallocated EL1 RW state. Both configuration and internal HAL identities
// use immutable double slots with release-published active indices.
struct alignas(8) KernelCounterContext {
    uint64_t magic;
    uint64_t abi_version;
    uint64_t active_calls;
    uint64_t pre_calls;
    uint64_t post_calls;
    uint64_t bwr_calls;

    uint64_t hal_gate_hits;
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
    uint64_t pending_generation_stale;
    uint64_t reply_without_pending;

    uint64_t parcel_prefix_ok;
    uint64_t parcel_prefix_faults;
    uint64_t parcel_plugin_hits;
    uint64_t parcel_device_unique_id_hits;
    uint64_t parcel_unknown_tokens;
    uint64_t server_request_hits;

    uint64_t reply_candidates;
    uint64_t reply_header_copy_ok;
    uint64_t reply_header_copy_faults;
    uint64_t reply_status_ok;
    uint64_t reply_status_nonzero;
    uint64_t reply_array_valid;
    uint64_t reply_array_invalid;
    uint64_t reply_content_copy_ok;
    uint64_t reply_content_copy_faults;
    uint64_t correlated_reply_candidates;
    uint64_t replacement_candidates;
    uint64_t replacement_length_mismatch;
    uint64_t replacement_dry_run_hits;
    uint64_t replacement_write_ok;
    uint64_t replacement_write_faults;
    uint64_t replacement_copy_to_user_faults;
    uint64_t replacement_last_request_id;
    uint32_t replacement_last_reply_flags;
    int32_t replacement_last_array_length;

    BinderTransactionEvent events[kTransactionEventCapacity];
    BinderPendingSlot pending[kPendingSlotCapacity];

    uint32_t active_config_slot;
    uint32_t active_config_reserved;
    uint64_t runtime_config_switches;
    uint64_t runtime_config_rejections;
    RuntimeConfigSlot config_slots[2];

    uint32_t active_hal_identity_slot;
    uint32_t active_hal_identity_reserved;
    uint64_t hal_identity_switches;
    uint64_t hal_identity_rejections;
    uint64_t hal_identity_restarts;
    HalIdentitySet hal_identity_slots[2];
};

static_assert(offsetof(KernelCounterContext, active_calls) == 16);
static_assert(offsetof(KernelCounterContext, events) % 8 == 0);
static_assert(offsetof(KernelCounterContext, pending) % 8 == 0);
static_assert(offsetof(KernelCounterContext, config_slots) % 8 == 0);
static_assert(offsetof(KernelCounterContext, hal_identity_slots) % 8 == 0);
static_assert(sizeof(KernelCounterContext) % 8 == 0);

} // namespace drmid
