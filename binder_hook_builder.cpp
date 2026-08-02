#include "binder_hook_builder.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <linux/android/binder.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string_view>
#include <vector>

using namespace asmjit;
using namespace asmjit::a64;

namespace drmid {
namespace {

constexpr uint64_t kMaxParsedStreamBytes = 64 * 1024;
constexpr uint64_t kMaxParsedCommands = 128;
constexpr uint64_t kPendingBucketCount =
    kPendingSlotCapacity / kPendingBucketWays;
static_assert((kPendingBucketWays & (kPendingBucketWays - 1)) == 0);
static_assert(kPendingBucketWays == 8);
constexpr uint32_t kPendingBucketWayShift = 3;
constexpr uint32_t kTransactionScratchOffset = 16;
constexpr uint32_t kParcelPrefixScratchOffset = 80;
constexpr uint32_t kParcelPrefixMaxBytes = 256;
constexpr uint32_t kParcelTokenKindScratchOffset = 336;
constexpr uint32_t kParcelTokenOffsetScratchOffset = 340;
constexpr uint32_t kParcelPrefixSizeScratchOffset = 344;
constexpr uint32_t kParcelFlagsScratchOffset = 348;
constexpr uint32_t kCorrelatedRequestFlagsScratchOffset = 352;
constexpr uint32_t kReplyPrefixSizeScratchOffset = 356;
constexpr uint32_t kReplyStatusScratchOffset = 360;
constexpr uint32_t kReplyArrayLengthScratchOffset = 364;
constexpr uint32_t kReplyArrayOffsetScratchOffset = 368;
constexpr uint32_t kReplyFlagsScratchOffset = 372;
constexpr uint32_t kPinnedPagesScratchOffset = 384;
constexpr uint32_t kPinnedPageCountScratchOffset = 400;
constexpr uint32_t kPinnedPageResultScratchOffset = 404;
constexpr uint32_t kBinderFileScratchOffset = 408;
constexpr uint32_t kFactoryUuidOffsetScratchOffset = 416;
constexpr uint32_t kPluginHandleScratchOffset = 420;
constexpr uint32_t kReplyObjectOffsetScratchOffset = 424;
constexpr uint32_t kParcelTokenHeaderExtraScratchOffset = 428;
constexpr uint32_t kRuntimeConfigPointerScratchOffset = 432;
constexpr uint32_t kParserScratchBytes = 448;

struct DirectPageMapProfile {
    uint64_t vmemmap = 0;
    uint64_t phys_offset = 0;
    uint64_t linear_map_base = 0;
    uint32_t struct_page_size = 0;
    uint32_t page_size = 0;
    uint32_t page_shift = 0;
};

static_assert((kTransactionEventCapacity &
               (kTransactionEventCapacity - 1)) == 0);
static_assert((kPendingBucketCount & (kPendingBucketCount - 1)) == 0);
constexpr uint64_t kPluginBucketCount =
    kPluginSlotCapacity / kPluginBucketWays;
static_assert((kPluginBucketWays & (kPluginBucketWays - 1)) == 0);
static_assert((kPluginBucketCount & (kPluginBucketCount - 1)) == 0);
static_assert(kPluginBucketWays == 8);
constexpr uint32_t kPluginBucketWayShift = 3;
constexpr uint32_t kMapLockTryCount = 8;
constexpr uint32_t kAndroidAppUidStart = 10000;

// Stack-local layout used by the generated handler. All fields are 64-bit;
// kLocalHeader is a 48-byte binder_write_read scratch buffer.
constexpr int32_t kLocalFile = 0;
constexpr int32_t kLocalCmd = 8;
constexpr int32_t kLocalArg = 16;
constexpr int32_t kLocalReturn = 24;
constexpr int32_t kLocalWriteSize = 32;
constexpr int32_t kLocalWriteBuffer = 40;
constexpr int32_t kLocalReadSize = 48;
constexpr int32_t kLocalReadBuffer = 56;
constexpr int32_t kLocalPreHeaderValid = 64;
constexpr int32_t kLocalHeader = 80;
constexpr int32_t kLocalBytes = 128;

static_assert(sizeof(binder_write_read) == 48);
static_assert(offsetof(binder_write_read, write_size) == 0);
static_assert(offsetof(binder_write_read, write_consumed) == 8);
static_assert(offsetof(binder_write_read, write_buffer) == 16);
static_assert(offsetof(binder_write_read, read_size) == 24);
static_assert(offsetof(binder_write_read, read_consumed) == 32);
static_assert(offsetof(binder_write_read, read_buffer) == 40);
static_assert(sizeof(binder_transaction_data) == 64);

bool validate_runtime_targets(const ReplacementConfig& config) {
    if (config.rule_mode > 2 || config.target_count > kRuntimeTargetLimit) {
        return false;
    }
    if ((config.rule_mode == 0 && config.target_count != 0) ||
        (config.rule_mode != 0 && config.target_count == 0)) {
        return false;
    }
    for (size_t index = 0; index < kRuntimeTargetLimit; ++index) {
        const uint32_t value = config.target_euids[index];
        if (index < config.target_count) {
            if (value == 0 ||
                (index != 0 && config.target_euids[index - 1] >= value)) {
                return false;
            }
        } else if (value != 0) {
            return false;
        }
    }
    return true;
}

void emit_atomic_increment(Assembler* a, uint64_t counter_kaddr) {
    aarch64_asm_mov_x(a, x9, counter_kaddr);
    aarch64_asm_mov_x(a, x10, 1);
    // The target profile has CONFIG_ARM64_LSE_ATOMICS and
    // CONFIG_ARM64_USE_LSE_ATOMICS. LDADDAL performs a 64-bit atomic add and
    // discards the old value through XZR.
    a->ldaddal(x10, xzr, ptr(x9));
}

void emit_atomic_decrement(Assembler* a, uint64_t counter_kaddr) {
    aarch64_asm_mov_x(a, x9, counter_kaddr);
    aarch64_asm_mov_x(a, x10, UINT64_MAX);
    a->ldaddal(x10, xzr, ptr(x9));
}

void emit_counter_increment(Assembler* a,
                            uint64_t context_kaddr,
                            size_t member_offset) {
    emit_atomic_increment(a, context_kaddr + member_offset);
}

// binder_ioctl is a global kernel entry used by nearly every Android process.
// Parsing every system_server/service transaction makes the diagnostic ring,
// copy helpers and atomic counters a permanent system-wide hot path. Keep the
// installer task for the eight-call startup self-test, keep every currently
// selected EUID (including a package that uses a low shared system UID), and
// keep ordinary Android application UIDs so adding a new package remains a
// hot configuration change. Core service UIDs that satisfy none of those
// conditions jump directly to the original ioctl without touching counters,
// user headers, command streams, maps or the event ring.
void emit_package_uid_or_target_gate(
    Assembler* a,
    uint64_t context_kaddr,
    const TaskIdentityOffsets& task_offsets,
    uint32_t installer_tgid,
    Label tracked,
    Label bypass) {
    kernel_module::export_symbol::get_current(a, x9);
    a->cbz(x9, bypass);
    a->ldr(w10, ptr(x9, task_offsets.tgid));
    aarch64_asm_mov_w(a, w12, installer_tgid);
    a->cmp(w10, w12);
    a->b(CondCode::kEQ, tracked);

    a->ldr(x10, ptr(x9, task_offsets.cred));
    a->cbz(x10, bypass);
    a->ldr(w11, ptr(x10, task_offsets.cred_euid));

    aarch64_asm_mov_x(
        a,
        x12,
        context_kaddr + offsetof(KernelCounterContext, active_config_slot));
    a->ldar(w13, ptr(x12));
    a->and_(w13, w13, 1);
    aarch64_asm_mov_x(a, x14, sizeof(RuntimeConfigSlot));
    a->mul(x13, x13, x14);
    aarch64_asm_mov_x(
        a,
        x14,
        context_kaddr + offsetof(KernelCounterContext, config_slots));
    a->add(x13, x14, x13);
    a->ldr(w15, ptr(x13, offsetof(RuntimeConfigSlot, target_count)));
    a->cmp(w15, static_cast<uint32_t>(kRuntimeTargetLimit));
    a->b(CondCode::kHI, bypass);
    a->add(x16, x13, offsetof(RuntimeConfigSlot, target_euids));
    const Label app_uid_check = a->newLabel();
    for (uint32_t index = 0; index < kRuntimeTargetLimit; ++index) {
        a->cmp(w15, index + 1);
        a->b(CondCode::kLO, app_uid_check);
        a->ldr(w17, ptr(x16, index * sizeof(uint32_t)));
        a->cmp(w11, w17);
        a->b(CondCode::kEQ, tracked);
    }

    a->bind(app_uid_check);
    // AArch64 CMP-immediate accepts a 12-bit value (optionally shifted by
    // 12). 10000 is outside that encoding and AsmJit correctly rejects the
    // direct form on-device. Materialize the threshold in a scratch register
    // so this final gate remains valid for every supported SDK assembler.
    aarch64_asm_mov_w(a, w12, kAndroidAppUidStart);
    a->cmp(w11, w12);
    a->b(CondCode::kHS, tracked);
    a->b(bypass);
}

// Acquires the active slot once for the current parsed transaction and keeps
// the immutable slot pointer in parser scratch. A concurrent publisher fills
// the other slot and release-flips the index; this transaction therefore sees
// one complete generation from rule check through final byte copy.
void emit_capture_active_runtime_config(Assembler* a,
                                        uint64_t context_kaddr) {
    aarch64_asm_mov_x(
        a,
        x9,
        context_kaddr + offsetof(KernelCounterContext, active_config_slot));
    a->ldar(w10, ptr(x9));
    a->and_(w10, w10, 1);
    aarch64_asm_mov_x(a, x11, sizeof(RuntimeConfigSlot));
    a->mul(x10, x10, x11);
    aarch64_asm_mov_x(
        a,
        x11,
        context_kaddr + offsetof(KernelCounterContext, config_slots));
    a->add(x10, x11, x10);
    a->str(x10, ptr(x23, kRuntimeConfigPointerScratchOffset));
}

KModErr resolve_direct_page_map_profile(DirectPageMapProfile& profile) {
    profile = {};
    RETURN_IF_ERROR(
        kernel_module::export_symbol::get_vmemmap(profile.vmemmap));
    RETURN_IF_ERROR(
        kernel_module::get_struct_page_size(profile.struct_page_size));
    RETURN_IF_ERROR(
        kernel_module::export_symbol::get_PHYS_OFFSET(profile.phys_offset));
    RETURN_IF_ERROR(kernel_module::export_symbol::phys_to_virt(
        profile.phys_offset, profile.linear_map_base));
    profile.page_size = kernel_module::get_page_size();
    if (profile.vmemmap == 0 || profile.struct_page_size == 0 ||
        profile.phys_offset == 0 || profile.linear_map_base == 0 ||
        profile.page_size < 4096 || profile.page_size > 65536 ||
        (profile.page_size & (profile.page_size - 1)) != 0) {
        profile = {};
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
    uint32_t value = profile.page_size;
    while ((value >>= 1) != 0) {
        ++profile.page_shift;
    }
    return KModErr::OK;
}

void emit_call_kernel_symbol_one_arg(Assembler* a,
                                     KModErr& out_err,
                                     const char* symbol,
                                     GpX arg) {
    out_err = Aarch64KernelSymCallHelper::callNameAuto(
        a,
        symbol,
        Aarch64KernelSymCallHelper::NeedReturnX0::No,
        arg);
}

void emit_call_kernel_symbol_two_args(Assembler* a,
                                      KModErr& out_err,
                                      const char* symbol,
                                      GpX arg0,
                                      GpX arg1) {
    out_err = Aarch64KernelSymCallHelper::callNameAuto(
        a,
        symbol,
        Aarch64KernelSymCallHelper::NeedReturnX0::No,
        arg0,
        arg1);
}

// x21 contains the correlated request event id and x23 the parser scratch.
void emit_replacement_success_telemetry(Assembler* a,
                                        uint64_t context_kaddr) {
    aarch64_asm_mov_x(
        a,
        x9,
        context_kaddr +
            offsetof(KernelCounterContext, replacement_last_request_id));
    a->str(x21, ptr(x9));
    a->ldr(w11, ptr(x23, kReplyFlagsScratchOffset));
    a->str(w11, ptr(x9, sizeof(uint64_t)));
    a->ldr(w12, ptr(x23, kReplyArrayLengthScratchOffset));
    a->str(w12, ptr(x9, sizeof(uint64_t) + sizeof(uint32_t)));
}

// Android arm64 kernels reserve x18 for CONFIG_SHADOW_CALL_STACK. The old
// ticket lock used x18 as a scratch/ticket register and then executed further
// kernel calls, which could corrupt the shadow-stack pointer. It also spun
// forever if a ticket owner stopped progressing. Use a bounded exclusive
// try-lock with ordinary caller-saved registers instead. On contention the
// caller skips only correlation metadata and preserves the Binder payload.
void emit_bounded_lock_acquire(Assembler* a,
                               uint64_t context_kaddr,
                               size_t state_offset,
                               size_t drops_offset,
                               Label failure) {
    const Label retry = a->newLabel();
    const Label busy = a->newLabel();
    const Label acquired = a->newLabel();
    aarch64_asm_mov_x(
        a,
        x9,
        context_kaddr + state_offset);
    aarch64_asm_mov_x(a, x10, 1);
    aarch64_asm_mov_w(a, w11, kMapLockTryCount);
    a->bind(retry);
    a->ldaxr(x12, ptr(x9));
    a->cbnz(x12, busy);
    a->stxr(w13, x10, ptr(x9));
    a->cbz(w13, acquired);
    a->bind(busy);
    a->clrex(15);
    a->subs(w11, w11, 1);
    a->b(CondCode::kNE, retry);
    emit_counter_increment(a, context_kaddr, drops_offset);
    a->b(failure);
    a->bind(acquired);
}

void emit_bounded_lock_release(Assembler* a,
                               uint64_t context_kaddr,
                               size_t state_offset) {
    aarch64_asm_mov_x(
        a,
        x9,
        context_kaddr + state_offset);
    a->stlr(xzr, ptr(x9));
}

void emit_pending_lock_acquire(Assembler* a,
                               uint64_t context_kaddr,
                               Label failure) {
    emit_bounded_lock_acquire(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, pending_lock_state),
        offsetof(KernelCounterContext, pending_lock_drops),
        failure);
}

void emit_pending_lock_release(Assembler* a, uint64_t context_kaddr) {
    emit_bounded_lock_release(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, pending_lock_state));
}

void emit_plugin_lock_acquire(Assembler* a,
                              uint64_t context_kaddr,
                              Label failure) {
    emit_bounded_lock_acquire(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, plugin_lock_state),
        offsetof(KernelCounterContext, plugin_lock_drops),
        failure);
}

void emit_plugin_lock_release(Assembler* a, uint64_t context_kaddr) {
    emit_bounded_lock_release(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, plugin_lock_state));
}

// x27=current task, x21=create request event id, parser scratch contains the
// Binder file and parsed handle.
void emit_plugin_map_register(Assembler* a,
                              uint64_t context_kaddr,
                              const TaskIdentityOffsets& task_offsets) {
    const Label found = a->newLabel();
    const Label use_empty = a->newLabel();
    const Label write = a->newLabel();
    const Label release = a->newLabel();
    const Label done = a->newLabel();

    emit_plugin_lock_acquire(a, context_kaddr, done);
    a->ldr(x12, ptr(x23, kBinderFileScratchOffset));
    a->ldr(w13, ptr(x27, task_offsets.tgid));
    a->ldr(w14, ptr(x23, kPluginHandleScratchOffset));
    a->lsr(x15, x12, 6);
    a->eor(x15, x15, x13);
    a->eor(x15, x15, x14);
    a->and_(x15, x15, kPluginBucketCount - 1);
    a->lsl(x15, x15, kPluginBucketWayShift);
    aarch64_asm_mov_x(a, x9, sizeof(BinderPluginSlot));
    a->mul(x15, x15, x9);
    aarch64_asm_mov_x(
        a,
        x16,
        context_kaddr + offsetof(KernelCounterContext, plugins));
    a->add(x16, x16, x15);
    a->mov(x11, xzr); // first empty slot
    a->mov(x10, xzr); // least-recently-used occupied slot
    aarch64_asm_mov_x(a, x17, UINT64_MAX); // oldest event id

    for (size_t way = 0; way < kPluginBucketWays; ++way) {
        const Label next = a->newLabel();
        const Label remember_empty = a->newLabel();
        const Label remember_oldest = a->newLabel();
        a->ldr(x9, ptr(x16, offsetof(BinderPluginSlot, binder_file)));
        a->cbz(x9, remember_empty);
        a->cmp(x9, x12);
        const Label consider_oldest = a->newLabel();
        a->b(CondCode::kNE, consider_oldest);
        a->ldr(w9, ptr(x16, offsetof(BinderPluginSlot, owner_tgid)));
        a->cmp(w9, w13);
        a->b(CondCode::kNE, consider_oldest);
        a->ldr(w9, ptr(x16, offsetof(BinderPluginSlot, handle)));
        a->cmp(w9, w14);
        a->b(CondCode::kEQ, found);
        a->bind(consider_oldest);
        a->ldr(x9, ptr(x16, offsetof(BinderPluginSlot, registered_event_id)));
        a->cbz(x10, remember_oldest);
        a->cmp(x9, x17);
        a->b(CondCode::kHS, next);
        a->bind(remember_oldest);
        a->mov(x10, x16);
        a->mov(x17, x9);
        a->b(next);
        a->bind(remember_empty);
        a->cbnz(x11, next);
        a->mov(x11, x16);
        a->bind(next);
        if (way + 1 < kPluginBucketWays) {
            a->add(x16, x16, sizeof(BinderPluginSlot));
        }
    }
    a->cbnz(x11, use_empty);
    // A client can be killed without sending BC_RELEASE. Never let those
    // stale keys make a later Widevine registration fail: replace the least
    // recently used entry in this bounded bucket. plugin_map_collisions now
    // counts recovered collision/eviction events; active stays at capacity.
    a->mov(x16, x10);
    aarch64_asm_mov_w(a, w15, 0); // replacement, not a new active slot
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, plugin_map_collisions));
    a->b(write);

    a->bind(use_empty);
    a->mov(x16, x11);
    aarch64_asm_mov_w(a, w15, 1); // newly active slot
    a->b(write);

    a->bind(found);
    a->str(x21, ptr(x16, offsetof(BinderPluginSlot, registered_event_id)));
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, plugin_map_reuses));
    a->b(release);

    a->bind(write);
    a->str(x21, ptr(x16, offsetof(BinderPluginSlot, registered_event_id)));
    a->str(w13, ptr(x16, offsetof(BinderPluginSlot, owner_tgid)));
    a->str(w14, ptr(x16, offsetof(BinderPluginSlot, handle)));
    emit_capture_active_runtime_config(a, context_kaddr);
    a->ldr(x9, ptr(x23, kRuntimeConfigPointerScratchOffset));
    a->ldr(w9, ptr(x9, offsetof(RuntimeConfigSlot, config_generation)));
    a->str(w9, ptr(x16, offsetof(BinderPluginSlot, generation)));
    a->stlr(x12, ptr(x16, offsetof(BinderPluginSlot, binder_file)));
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, plugin_map_inserts));
    a->cbz(w15, release);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, plugin_map_active));
    a->b(release);
    a->bind(release);
    emit_plugin_lock_release(a, context_kaddr);
    a->bind(done);
}

// Marks a deviceUniqueId request when its target handle belongs to a
// registered Widevine plugin for this client process and Binder file.
void emit_plugin_map_classify_request(
    Assembler* a,
    uint64_t context_kaddr,
    const TaskIdentityOffsets& task_offsets) {
    const Label found = a->newLabel();
    const Label miss = a->newLabel();
    const Label release = a->newLabel();
    const Label done = a->newLabel();

    a->ldr(w11, ptr(x23, kParcelFlagsScratchOffset));
    a->tbz(x11, 0, done);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, plugin_map_lookups));
    emit_plugin_lock_acquire(a, context_kaddr, done);
    a->ldr(x12, ptr(x23, kBinderFileScratchOffset));
    a->ldr(w13, ptr(x27, task_offsets.tgid));
    a->ldr(w14, ptr(x23, kTransactionScratchOffset));
    a->str(w14, ptr(x23, kPluginHandleScratchOffset));
    a->lsr(x15, x12, 6);
    a->eor(x15, x15, x13);
    a->eor(x15, x15, x14);
    a->and_(x15, x15, kPluginBucketCount - 1);
    a->lsl(x15, x15, kPluginBucketWayShift);
    aarch64_asm_mov_x(a, x9, sizeof(BinderPluginSlot));
    a->mul(x15, x15, x9);
    aarch64_asm_mov_x(
        a,
        x16,
        context_kaddr + offsetof(KernelCounterContext, plugins));
    a->add(x16, x16, x15);
    for (size_t way = 0; way < kPluginBucketWays; ++way) {
        const Label next = a->newLabel();
        a->ldr(x9, ptr(x16, offsetof(BinderPluginSlot, binder_file)));
        a->cmp(x9, x12);
        a->b(CondCode::kNE, next);
        a->ldr(w9, ptr(x16, offsetof(BinderPluginSlot, owner_tgid)));
        a->cmp(w9, w13);
        a->b(CondCode::kNE, next);
        a->ldr(w9, ptr(x16, offsetof(BinderPluginSlot, handle)));
        a->cmp(w9, w14);
        a->b(CondCode::kEQ, found);
        a->bind(next);
        if (way + 1 < kPluginBucketWays) {
            a->add(x16, x16, sizeof(BinderPluginSlot));
        }
    }
    a->b(miss);

    a->bind(found);
    // Refresh the entry age only after an exact file/tgid/handle hit. This
    // keeps an actively used plugin ahead of abandoned process entries when
    // a later registration needs bounded LRU reclamation.
    aarch64_asm_mov_x(
        a, x9, context_kaddr + offsetof(KernelCounterContext, event_write_index));
    a->ldr(x10, ptr(x9));
    a->str(x10, ptr(x16, offsetof(BinderPluginSlot, registered_event_id)));
    a->ldr(w11, ptr(x23, kParcelFlagsScratchOffset));
    a->orr(w11, w11, kParcelFlagWidevinePluginMatched);
    a->str(w11, ptr(x23, kParcelFlagsScratchOffset));
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, plugin_map_hits));
    a->b(release);
    a->bind(miss);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, plugin_map_misses));
    a->bind(release);
    emit_plugin_lock_release(a, context_kaddr);
    a->bind(done);
}

// x27=current task, parser scratch contains Binder file and released handle.
void emit_plugin_map_release(Assembler* a,
                             uint64_t context_kaddr,
                             const TaskIdentityOffsets& task_offsets) {
    const Label found = a->newLabel();
    const Label miss = a->newLabel();
    const Label release = a->newLabel();
    const Label done = a->newLabel();
    emit_plugin_lock_acquire(a, context_kaddr, done);
    a->ldr(x12, ptr(x23, kBinderFileScratchOffset));
    a->ldr(w13, ptr(x27, task_offsets.tgid));
    a->ldr(w14, ptr(x23, kPluginHandleScratchOffset));
    a->lsr(x15, x12, 6);
    a->eor(x15, x15, x13);
    a->eor(x15, x15, x14);
    a->and_(x15, x15, kPluginBucketCount - 1);
    a->lsl(x15, x15, kPluginBucketWayShift);
    aarch64_asm_mov_x(a, x9, sizeof(BinderPluginSlot));
    a->mul(x15, x15, x9);
    aarch64_asm_mov_x(
        a,
        x16,
        context_kaddr + offsetof(KernelCounterContext, plugins));
    a->add(x16, x16, x15);
    for (size_t way = 0; way < kPluginBucketWays; ++way) {
        const Label next = a->newLabel();
        a->ldr(x9, ptr(x16, offsetof(BinderPluginSlot, binder_file)));
        a->cmp(x9, x12);
        a->b(CondCode::kNE, next);
        a->ldr(w9, ptr(x16, offsetof(BinderPluginSlot, owner_tgid)));
        a->cmp(w9, w13);
        a->b(CondCode::kNE, next);
        a->ldr(w9, ptr(x16, offsetof(BinderPluginSlot, handle)));
        a->cmp(w9, w14);
        a->b(CondCode::kEQ, found);
        a->bind(next);
        if (way + 1 < kPluginBucketWays) {
            a->add(x16, x16, sizeof(BinderPluginSlot));
        }
    }
    a->b(miss);
    a->bind(found);
    a->stlr(xzr, ptr(x16, offsetof(BinderPluginSlot, binder_file)));
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, plugin_map_releases));
    emit_atomic_decrement(
        a, context_kaddr + offsetof(KernelCounterContext, plugin_map_active));
    a->b(release);
    a->bind(miss);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, plugin_map_release_misses));
    a->bind(release);
    emit_plugin_lock_release(a, context_kaddr);
    a->bind(done);
}

// x27: current task, x26: request event id, x23: parser scratch.
void emit_pending_push(Assembler* a,
                       uint64_t context_kaddr,
                       const TaskIdentityOffsets& task_offsets) {
    const Label ignored_oneway = a->newLabel();
    const Label found = a->newLabel();
    const Label reclaim_identity = a->newLabel();
    const Label use_empty = a->newLabel();
    const Label claim = a->newLabel();
    const Label claimed = a->newLabel();
    const Label overflow = a->newLabel();
    const Label release = a->newLabel();
    const Label done = a->newLabel();

    a->ldr(w11, ptr(x23, kTransactionScratchOffset + 20));
    a->tbnz(x11, 0, ignored_oneway);

    emit_pending_lock_acquire(a, context_kaddr, done);

    // Eight-way bucket: ((task >> 6) & (bucket_count - 1)) * 8.
    a->lsr(x13, x27, 6);
    a->and_(x13, x13, kPendingBucketCount - 1);
    a->lsl(x13, x13, kPendingBucketWayShift);
    aarch64_asm_mov_x(a, x12, sizeof(BinderPendingSlot));
    a->mul(x13, x13, x12);
    aarch64_asm_mov_x(
        a,
        x15,
        context_kaddr + offsetof(KernelCounterContext, pending));
    a->add(x15, x15, x13);
    a->mov(x14, xzr); // first empty slot
    a->mov(x10, xzr); // least-recently-used occupied slot
    aarch64_asm_mov_x(a, x17, UINT64_MAX); // oldest request event id

    for (size_t way = 0; way < kPendingBucketWays; ++way) {
        const Label next = a->newLabel();
        const Label remember_empty = a->newLabel();
        const Label consider_oldest = a->newLabel();
        const Label remember_oldest = a->newLabel();
        a->ldr(x16, ptr(x15));
        a->cbz(x16, remember_empty);
        a->cmp(x16, x27);
        a->b(CondCode::kNE, consider_oldest);
        // A freed task_struct address can be reused by a later application
        // thread. Require all three identity fields before appending to an
        // existing stack; otherwise reclaim this stale slot immediately.
        a->ldr(w12, ptr(x15, offsetof(BinderPendingSlot, pid)));
        a->ldr(w11, ptr(x27, task_offsets.pid));
        a->cmp(w12, w11);
        a->b(CondCode::kNE, reclaim_identity);
        a->ldr(w12, ptr(x15, offsetof(BinderPendingSlot, tgid)));
        a->ldr(w11, ptr(x27, task_offsets.tgid));
        a->cmp(w12, w11);
        a->b(CondCode::kEQ, found);
        a->b(reclaim_identity);
        a->bind(consider_oldest);
        a->mov(x9, xzr);
        a->ldr(w11, ptr(x15, offsetof(BinderPendingSlot, depth)));
        a->cbz(w11, remember_oldest);
        a->sub(w11, w11, 1);
        aarch64_asm_mov_x(a, x12, sizeof(BinderPendingFrame));
        a->mul(x12, x11, x12);
        a->add(x12, x12, offsetof(BinderPendingSlot, frames));
        a->add(x12, x15, x12);
        a->ldr(x9, ptr(x12, offsetof(BinderPendingFrame, request_event_id)));
        a->cbz(x10, remember_oldest);
        a->cmp(x9, x17);
        a->b(CondCode::kHS, next);
        a->bind(remember_oldest);
        a->mov(x10, x15);
        a->mov(x17, x9);
        a->b(next);
        a->bind(remember_empty);
        a->cbnz(x14, next);
        a->mov(x14, x15);
        a->bind(next);
        if (way + 1 < kPendingBucketWays) {
            a->add(x15, x15, sizeof(BinderPendingSlot));
        }
    }
    a->cbnz(x14, use_empty);
    // A killed client may leave a synchronous frame without a matching reply.
    // Reclaim the oldest entry in the bounded bucket instead of rejecting all
    // future correlations that hash to the same full bucket.
    a->mov(x15, x10);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, pending_collisions));
    a->b(claim);

    a->bind(reclaim_identity);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, pending_collisions));
    a->b(claim);

    a->bind(use_empty);
    a->mov(x15, x14);
    a->bind(claim);
    a->str(x27, ptr(x15, offsetof(BinderPendingSlot, task_kaddr)));
    a->ldr(w11, ptr(x27, task_offsets.pid));
    a->str(w11, ptr(x15, offsetof(BinderPendingSlot, pid)));
    a->ldr(w12, ptr(x27, task_offsets.tgid));
    a->str(w12, ptr(x15, offsetof(BinderPendingSlot, tgid)));
    a->str(wzr, ptr(x15, offsetof(BinderPendingSlot, depth)));
    a->b(claimed);

    a->bind(found);
    a->bind(claimed);
    a->ldr(w13, ptr(x15, offsetof(BinderPendingSlot, depth)));
    a->cmp(x13, kPendingDepth);
    a->b(CondCode::kHS, overflow);
    aarch64_asm_mov_x(a, x12, sizeof(BinderPendingFrame));
    a->mul(x14, x13, x12);
    a->add(x14, x14, offsetof(BinderPendingSlot, frames));
    a->add(x14, x15, x14);
    a->str(x26, ptr(x14, offsetof(BinderPendingFrame, request_event_id)));
    a->ldr(x16, ptr(x23, kTransactionScratchOffset + 0));
    a->str(x16, ptr(x14, offsetof(BinderPendingFrame, target)));
    a->ldr(x16, ptr(x23, kTransactionScratchOffset + 32));
    a->str(x16, ptr(x14, offsetof(BinderPendingFrame, data_size)));
    a->ldr(w16, ptr(x23, kTransactionScratchOffset + 16));
    a->str(w16, ptr(x14, offsetof(BinderPendingFrame, code)));
    a->ldr(w16, ptr(x23, kTransactionScratchOffset + 20));
    a->str(w16, ptr(x14, offsetof(BinderPendingFrame, flags)));
    a->ldr(w16, ptr(x23, kParcelFlagsScratchOffset));
    a->str(w16, ptr(x14, offsetof(BinderPendingFrame, parcel_flags)));
    a->str(wzr, ptr(x14, offsetof(BinderPendingFrame, reserved)));
    a->add(w13, w13, 1);
    a->str(w13, ptr(x15, offsetof(BinderPendingSlot, depth)));
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, pending_pushes));
    a->b(release);

    a->bind(overflow);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, pending_overflows));
    a->bind(release);
    emit_pending_lock_release(a, context_kaddr);
    a->b(done);

    a->bind(ignored_oneway);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, pending_oneway_ignored));
    a->bind(done);
}

// Pop the most recent synchronous request for current task. Returns request
// event id in x21 and request Parcel flags in w17, or zeros on a miss. x27
// must contain current task.
void emit_pending_pop(Assembler* a,
                      uint64_t context_kaddr,
                      bool terminal_reply) {
    const Label found = a->newLabel();
    const Label miss = a->newLabel();
    const Label release = a->newLabel();
    const Label done = a->newLabel();

    a->mov(x21, xzr);
    a->mov(x17, xzr);
    emit_pending_lock_acquire(a, context_kaddr, done);
    a->lsr(x13, x27, 6);
    a->and_(x13, x13, kPendingBucketCount - 1);
    a->lsl(x13, x13, kPendingBucketWayShift);
    aarch64_asm_mov_x(a, x12, sizeof(BinderPendingSlot));
    a->mul(x13, x13, x12);
    aarch64_asm_mov_x(
        a,
        x15,
        context_kaddr + offsetof(KernelCounterContext, pending));
    a->add(x15, x15, x13);
    for (size_t way = 0; way < kPendingBucketWays; ++way) {
        a->ldr(x16, ptr(x15));
        a->cmp(x16, x27);
        a->b(CondCode::kEQ, found);
        if (way + 1 < kPendingBucketWays) {
            a->add(x15, x15, sizeof(BinderPendingSlot));
        }
    }
    a->b(miss);

    a->bind(found);
    a->ldr(w13, ptr(x15, offsetof(BinderPendingSlot, depth)));
    a->cbz(x13, miss);
    a->sub(w13, w13, 1);
    a->str(w13, ptr(x15, offsetof(BinderPendingSlot, depth)));
    aarch64_asm_mov_x(a, x12, sizeof(BinderPendingFrame));
    a->mul(x14, x13, x12);
    a->add(x14, x14, offsetof(BinderPendingSlot, frames));
    a->add(x14, x15, x14);
    a->ldr(x21, ptr(x14, offsetof(BinderPendingFrame, request_event_id)));
    a->ldr(w17, ptr(x14, offsetof(BinderPendingFrame, parcel_flags)));
    a->cbnz(x13, release);
    // No frame remains; make this slot reusable before releasing the lock.
    a->stlr(xzr, ptr(x15));
    a->b(release);

    a->bind(miss);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, pending_misses));
    a->bind(release);
    if (terminal_reply) {
        const Label no_pop = a->newLabel();
        a->cbz(x21, no_pop);
        emit_counter_increment(
            a,
            context_kaddr,
            offsetof(KernelCounterContext, pending_terminal_pops));
        a->bind(no_pop);
    } else {
        const Label no_pop = a->newLabel();
        a->cbz(x21, no_pop);
        emit_counter_increment(
            a, context_kaddr, offsetof(KernelCounterContext, pending_pops));
        a->bind(no_pop);
    }
    emit_pending_lock_release(a, context_kaddr);
    a->bind(done);
}

void emit_reserve_event(Assembler* a, uint64_t context_kaddr) {
    aarch64_asm_mov_x(
        a,
        x9,
        context_kaddr + offsetof(KernelCounterContext, event_write_index));
    aarch64_asm_mov_x(a, x10, 1);
    a->ldaddal(x10, x11, ptr(x9)); // x11 = zero-based ticket
    a->add(x26, x11, 1);           // event id
    a->and_(x11, x11, kTransactionEventCapacity - 1);
    aarch64_asm_mov_x(a, x12, sizeof(BinderTransactionEvent));
    a->mul(x11, x11, x12);
    aarch64_asm_mov_x(
        a,
        x28,
        context_kaddr + offsetof(KernelCounterContext, events));
    a->add(x28, x28, x11);
    a->lsl(x12, x26, 1);
    a->sub(x12, x12, 1);
    a->str(x12, ptr(x28, offsetof(BinderTransactionEvent, sequence)));
    a->str(x26, ptr(x28, offsetof(BinderTransactionEvent, event_id)));
}

void emit_publish_event(Assembler* a) {
    a->lsl(x12, x26, 1);
    a->stlr(x12, ptr(x28, offsetof(BinderTransactionEvent, sequence)));
}

constexpr uint32_t align4(uint32_t value) {
    return (value + 3U) & ~3U;
}

void emit_match_utf16_string(Assembler* a,
                             uint32_t absolute_length_offset,
                             std::string_view value,
                             Label mismatch) {
    a->ldr(w11, ptr(x23, absolute_length_offset));
    a->cmp(w11, static_cast<uint32_t>(value.size()));
    a->b(CondCode::kNE, mismatch);
    for (size_t index = 0; index < value.size(); ++index) {
        a->ldrh(
            w11,
            ptr(x23,
                absolute_length_offset + sizeof(uint32_t) +
                    static_cast<uint32_t>(index * sizeof(char16_t))));
        a->cmp(w11, static_cast<uint32_t>(
                        static_cast<unsigned char>(value[index])));
        a->b(CondCode::kNE, mismatch);
    }
    a->ldrh(
        w11,
        ptr(x23,
            absolute_length_offset + sizeof(uint32_t) +
                static_cast<uint32_t>(value.size() * sizeof(char16_t))));
    a->cbnz(w11, mismatch);
}

void emit_match_utf16_contents(Assembler* a,
                               uint32_t absolute_chars_offset,
                               std::string_view value,
                               Label mismatch) {
    for (size_t index = 0; index < value.size(); ++index) {
        a->ldrh(
            w11,
            ptr(x23,
                absolute_chars_offset +
                    static_cast<uint32_t>(index * sizeof(char16_t))));
        a->cmp(w11, static_cast<uint32_t>(
                        static_cast<unsigned char>(value[index])));
        a->b(CondCode::kNE, mismatch);
    }
    a->ldrh(
        w11,
        ptr(x23,
            absolute_chars_offset +
                static_cast<uint32_t>(value.size() * sizeof(char16_t))));
    a->cbnz(w11, mismatch);
}

void emit_match_utf8_contents(Assembler* a,
                              uint32_t absolute_chars_offset,
                              std::string_view value,
                              Label mismatch) {
    for (size_t index = 0; index < value.size(); ++index) {
        a->ldrb(
            w11,
            ptr(x23,
                absolute_chars_offset +
                    static_cast<uint32_t>(index * sizeof(uint8_t))));
        a->cmp(w11, static_cast<uint32_t>(
                        static_cast<unsigned char>(value[index])));
        a->b(CondCode::kNE, mismatch);
    }
    a->ldrb(
        w11,
        ptr(x23,
            absolute_chars_offset +
                static_cast<uint32_t>(value.size() * sizeof(uint8_t))));
    a->cbnz(w11, mismatch);
}

// Some Android 16 platform Binder clients serialize a four-byte build-domain
// header (SYST/VNDR/RECO/UNKN) between the String16 length and descriptor.
// The header is not included in the UTF-16 length.
void emit_match_headered_utf16_string(Assembler* a,
                                      uint32_t absolute_length_offset,
                                      std::string_view value,
                                      Label mismatch) {
    const Label magic_ok = a->newLabel();
    a->ldr(w11, ptr(x23, absolute_length_offset));
    a->cmp(w11, static_cast<uint32_t>(value.size()));
    a->b(CondCode::kNE, mismatch);
    a->ldr(w12, ptr(x23, absolute_length_offset + sizeof(uint32_t)));
    for (uint32_t magic : {
             0x53595354U, // B_PACK_CHARS('S','Y','S','T')
             0x564e4452U, // B_PACK_CHARS('V','N','D','R')
             0x5245434fU, // B_PACK_CHARS('R','E','C','O')
             0x554e4b4eU, // B_PACK_CHARS('U','N','K','N')
         }) {
        aarch64_asm_mov_w(a, w11, magic);
        a->cmp(w12, w11);
        a->b(CondCode::kEQ, magic_ok);
    }
    a->b(mismatch);
    a->bind(magic_ok);
    for (size_t index = 0; index < value.size(); ++index) {
        a->ldrh(
            w11,
            ptr(x23,
                absolute_length_offset + 2 * sizeof(uint32_t) +
                    static_cast<uint32_t>(index * sizeof(char16_t))));
        a->cmp(w11, static_cast<uint32_t>(
                        static_cast<unsigned char>(value[index])));
        a->b(CondCode::kNE, mismatch);
    }
    a->ldrh(
        w11,
        ptr(x23,
            absolute_length_offset + 2 * sizeof(uint32_t) +
                static_cast<uint32_t>(value.size() * sizeof(char16_t))));
    a->cbnz(w11, mismatch);
}

void emit_try_parcel_descriptor(Assembler* a,
                                uint64_t context_kaddr,
                                std::string_view descriptor,
                                ParcelTokenKind token_kind,
                                size_t hit_counter_offset,
                                Label matched) {
    for (uint32_t token_offset = 0; token_offset <= 32; token_offset += 4) {
        const Label try_headered = a->newLabel();
        const Label try_raw_contents = a->newLabel();
        const Label descriptor_ready = a->newLabel();
        const Label next = a->newLabel();
        const uint32_t absolute_length_offset =
            kParcelPrefixScratchOffset + token_offset;
        const uint32_t required =
            token_offset + sizeof(uint32_t) +
            static_cast<uint32_t>((descriptor.size() + 1) * sizeof(char16_t));
        a->cmp(x17, required);
        a->b(CondCode::kLO, try_headered);
        emit_match_utf16_string(
            a, absolute_length_offset, descriptor, try_headered);
        a->str(wzr, ptr(x23, kParcelTokenHeaderExtraScratchOffset));
        a->b(descriptor_ready);

        a->bind(try_headered);
        a->cmp(x17, required + sizeof(uint32_t));
        a->b(CondCode::kLO, try_raw_contents);
        emit_match_headered_utf16_string(
            a, absolute_length_offset, descriptor, try_raw_contents);
        aarch64_asm_mov_w(a, w11, sizeof(uint32_t));
        a->str(w11, ptr(x23, kParcelTokenHeaderExtraScratchOffset));
        a->b(descriptor_ready);

        // Android 16 request headers can vary by the libbinder build domain.
        // As a final bounded form, accept the exact UTF-16 descriptor and its
        // terminator even when the preceding four-byte word is a domain tag.
        a->bind(try_raw_contents);
        a->cmp(x17,
               token_offset + sizeof(uint32_t) +
                   static_cast<uint32_t>(
                       (descriptor.size() + 1) * sizeof(char16_t)));
        a->b(CondCode::kLO, next);
        emit_match_utf16_contents(
            a,
            absolute_length_offset + sizeof(uint32_t),
            descriptor,
            next);
        a->str(wzr, ptr(x23, kParcelTokenHeaderExtraScratchOffset));
        a->bind(descriptor_ready);

        aarch64_asm_mov_x(a, x11, static_cast<uint32_t>(token_kind));
        a->str(w11, ptr(x23, kParcelTokenKindScratchOffset));
        aarch64_asm_mov_x(a, x11, token_offset);
        a->str(w11, ptr(x23, kParcelTokenOffsetScratchOffset));
        emit_counter_increment(a, context_kaddr, hit_counter_offset);

        if (token_kind == ParcelTokenKind::kDrmFactory) {
            static constexpr uint8_t kWidevineUuid[16] = {
                0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce,
                0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed,
            };
            const Label factory_done = a->newLabel();
            a->ldr(w11, ptr(x23, kTransactionScratchOffset + 16));
            a->cmp(w11, 1); // IDrmFactory.createDrmPlugin
            a->b(CondCode::kNE, factory_done);
            const uint32_t argument_start = align4(
                token_offset + sizeof(uint32_t) +
                static_cast<uint32_t>(
                    (descriptor.size() + 1) * sizeof(char16_t)));
            for (uint32_t uuid_offset = argument_start;
                 uuid_offset <= argument_start + 68;
                 uuid_offset += 4) {
                const Label next_uuid = a->newLabel();
                a->cmp(x17, uuid_offset + sizeof(kWidevineUuid));
                a->b(CondCode::kLO, next_uuid);
                for (size_t byte = 0; byte < sizeof(kWidevineUuid); ++byte) {
                    a->ldrb(
                        w11,
                        ptr(x23,
                            kParcelPrefixScratchOffset + uuid_offset + byte));
                    a->cmp(w11, kWidevineUuid[byte]);
                    a->b(CondCode::kNE, next_uuid);
                }
                a->ldr(w11, ptr(x23, kParcelFlagsScratchOffset));
                a->orr(w11, w11, kParcelFlagWidevineCreate);
                a->str(w11, ptr(x23, kParcelFlagsScratchOffset));
                aarch64_asm_mov_w(a, w11, uuid_offset);
                a->str(w11, ptr(x23, kFactoryUuidOffsetScratchOffset));
                emit_counter_increment(
                    a,
                    context_kaddr,
                    offsetof(KernelCounterContext, widevine_create_requests));
                a->b(factory_done);
                a->bind(next_uuid);
            }
            a->bind(factory_done);
        } else if (token_kind == ParcelTokenKind::kDrmPlugin) {
            constexpr std::string_view kDeviceUniqueId = "deviceUniqueId";
            const uint32_t property_offset = align4(
                token_offset + sizeof(uint32_t) +
                static_cast<uint32_t>(
                    (descriptor.size() + 1) * sizeof(char16_t)));
            const uint32_t property_required =
                property_offset + sizeof(uint32_t) +
                static_cast<uint32_t>(
                    (kDeviceUniqueId.size() + 1) * sizeof(char16_t));
            const Label headered_property = a->newLabel();
            const Label property_matched = a->newLabel();
            const Label no_property = a->newLabel();
            a->ldr(w11, ptr(x23, kParcelTokenHeaderExtraScratchOffset));
            a->cbnz(w11, headered_property);
            a->cmp(x17, property_required);
            a->b(CondCode::kLO, no_property);
            emit_match_utf16_string(
                a,
                kParcelPrefixScratchOffset + property_offset,
                kDeviceUniqueId,
                no_property);
            a->b(property_matched);
            a->bind(headered_property);
            a->cmp(x17, property_required + sizeof(uint32_t));
            a->b(CondCode::kLO, no_property);
            emit_match_utf16_string(
                a,
                kParcelPrefixScratchOffset + property_offset +
                    sizeof(uint32_t),
                kDeviceUniqueId,
                no_property);
            a->bind(property_matched);
            aarch64_asm_mov_x(a, x11, kParcelFlagDeviceUniqueId);
            a->str(w11, ptr(x23, kParcelFlagsScratchOffset));
            emit_counter_increment(
                a,
                context_kaddr,
                offsetof(KernelCounterContext,
                         parcel_device_unique_id_hits));
            a->bind(no_property);
            // Fallback for NDK String parcels whose UTF-8/UTF-16 framing is
            // preceded by a vendor/system header. Search only the bounded
            // prefix for the exact property name.
            const Label property_already_found = a->newLabel();
            const Label raw_property_found = a->newLabel();
            a->ldr(w11, ptr(x23, kParcelFlagsScratchOffset));
            a->tbnz(w11, 0, property_already_found);
            for (uint32_t raw_offset = 0; raw_offset <= 64; raw_offset += 4) {
                const Label next_raw = a->newLabel();
                a->cmp(x17, raw_offset +
                                 static_cast<uint32_t>(
                                     (kDeviceUniqueId.size() + 1) *
                                     sizeof(char16_t)));
                a->b(CondCode::kLO, next_raw);
                emit_match_utf16_contents(
                    a,
                    kParcelPrefixScratchOffset + raw_offset,
                    kDeviceUniqueId,
                    next_raw);
                a->b(raw_property_found);
                a->bind(next_raw);
            }
            for (uint32_t raw_offset = 0; raw_offset <= 64; raw_offset += 4) {
                const Label next_raw = a->newLabel();
                a->cmp(x17, raw_offset +
                                 static_cast<uint32_t>(
                                     kDeviceUniqueId.size() + 1));
                a->b(CondCode::kLO, next_raw);
                emit_match_utf8_contents(
                    a,
                    kParcelPrefixScratchOffset + raw_offset,
                    kDeviceUniqueId,
                    next_raw);
                a->b(raw_property_found);
                a->bind(next_raw);
            }
            a->b(property_already_found);
            a->bind(raw_property_found);
            aarch64_asm_mov_x(a, x11, kParcelFlagDeviceUniqueId);
            a->str(w11, ptr(x23, kParcelFlagsScratchOffset));
            emit_counter_increment(
                a,
                context_kaddr,
                offsetof(KernelCounterContext,
                         parcel_device_unique_id_hits));
            a->bind(property_already_found);
        }
        a->b(matched);
        a->bind(next);
    }
}

// Bounded, read-only Parcel prefix capture for request commands. Results are
// kept in parser scratch and copied into the transaction event later.
void emit_capture_parcel_prefix(Assembler* a,
                                uint64_t context_kaddr,
                                uint32_t expected_ioc_type,
                                KModErr& copy_helper_err) {
    constexpr std::string_view kDrmFactory =
        "android.hardware.drm.IDrmFactory";
    constexpr std::string_view kDrmPlugin =
        "android.hardware.drm.IDrmPlugin";

    const Label request = a->newLabel();
    const Label copy_fault = a->newLabel();
    const Label scan = a->newLabel();
    const Label matched = a->newLabel();
    const Label done = a->newLabel();

    a->str(wzr, ptr(x23, kParcelTokenKindScratchOffset));
    a->str(wzr, ptr(x23, kParcelTokenOffsetScratchOffset));
    a->str(wzr, ptr(x23, kParcelPrefixSizeScratchOffset));
    a->str(wzr, ptr(x23, kParcelFlagsScratchOffset));
    a->str(wzr, ptr(x23, kFactoryUuidOffsetScratchOffset));
    a->str(wzr, ptr(x23, kPluginHandleScratchOffset));
    a->str(wzr, ptr(x23, kParcelTokenHeaderExtraScratchOffset));

    auto emit_request_match = [&](uint32_t command) {
        aarch64_asm_mov_x(a, x11, command);
        a->cmp(w24, w11);
        a->b(CondCode::kEQ, request);
    };
    if (expected_ioc_type == static_cast<uint32_t>('c')) {
        emit_request_match(static_cast<uint32_t>(BC_TRANSACTION));
        emit_request_match(static_cast<uint32_t>(BC_TRANSACTION_SG));
    } else {
        emit_request_match(static_cast<uint32_t>(BR_TRANSACTION));
        emit_request_match(static_cast<uint32_t>(BR_TRANSACTION_SEC_CTX));
    }
    a->b(done);

    a->bind(request);
    a->ldr(x17, ptr(x23, kTransactionScratchOffset + 32));
    a->ldr(x16, ptr(x23, kTransactionScratchOffset + 48));
    a->cbz(x17, scan);
    a->cbz(x16, copy_fault);
    aarch64_asm_mov_x(a, x15, kParcelPrefixMaxBytes);
    a->cmp(x17, x15);
    const Label size_ready = a->newLabel();
    a->b(CondCode::kLS, size_ready);
    a->mov(x17, x15);
    a->bind(size_ready);
    a->add(x13, x23, kParcelPrefixScratchOffset);
    kernel_module::export_symbol::copy_from_user(
        a, copy_helper_err, x13, x16, x17);
    a->cbnz(x0, copy_fault);
    a->str(w17, ptr(x23, kParcelPrefixSizeScratchOffset));
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, parcel_prefix_ok));
    a->b(scan);

    a->bind(copy_fault);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, parcel_prefix_faults));
    a->b(done);

    a->bind(scan);
    emit_try_parcel_descriptor(
        a,
        context_kaddr,
        kDrmFactory,
        ParcelTokenKind::kDrmFactory,
        offsetof(KernelCounterContext, parcel_factory_hits),
        matched);
    emit_try_parcel_descriptor(
        a,
        context_kaddr,
        kDrmPlugin,
        ParcelTokenKind::kDrmPlugin,
        offsetof(KernelCounterContext, parcel_plugin_hits),
        matched);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, parcel_unknown_tokens));
    a->b(done);
    a->bind(matched);
    a->bind(done);
}

// Parse the nullable strong-binder object returned by a successful
// IDrmFactory.createDrmPlugin request. The 64-bit Binder ABI carries one
// binder_size_t offset and one 24-byte flat_binder_object in the reply.
void emit_parse_widevine_create_reply(
    Assembler* a,
    uint64_t context_kaddr,
    const TaskIdentityOffsets& task_offsets,
    KModErr& copy_helper_err) {
    const Label fault = a->newLabel();
    const Label done = a->newLabel();
    a->tbz(x17, 1, done);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, create_reply_candidates));

    a->ldr(x16, ptr(x23, kTransactionScratchOffset + 32)); // data_size
    a->ldr(x14, ptr(x23, kTransactionScratchOffset + 40)); // offsets_size
    a->ldr(x15, ptr(x23, kTransactionScratchOffset + 48)); // buffer
    a->ldr(x12, ptr(x23, kTransactionScratchOffset + 56)); // offsets
    aarch64_asm_mov_x(
        a,
        x9,
        context_kaddr + offsetof(KernelCounterContext, last_create_data_size));
    a->str(x16, ptr(x9));
    a->str(x14, ptr(x9, sizeof(uint64_t)));
    aarch64_asm_mov_w(a, w11, 1);
    a->str(w11, ptr(x9, 2 * sizeof(uint64_t)));
    a->cmp(x16, sizeof(flat_binder_object));
    a->b(CondCode::kLO, fault);
    a->cmp(x14, sizeof(binder_size_t));
    a->b(CondCode::kNE, fault);
    a->cbz(x15, fault);
    a->cbz(x12, fault);
    aarch64_asm_mov_w(a, w11, 2);
    a->str(w11, ptr(x9, 2 * sizeof(uint64_t)));

    a->add(x13, x23, kParcelPrefixScratchOffset);
    kernel_module::export_symbol::copy_from_user(
        a, copy_helper_err, x13, x15, sizeof(int32_t));
    a->cbnz(x0, fault);
    a->ldr(w11, ptr(x23, kParcelPrefixScratchOffset));
    a->str(w11, ptr(x23, kReplyStatusScratchOffset));
    aarch64_asm_mov_x(
        a,
        x9,
        context_kaddr + offsetof(KernelCounterContext, last_create_data_size));
    a->str(w11, ptr(x9, 2 * sizeof(uint64_t) + sizeof(uint32_t)));
    a->cbnz(w11, fault);
    aarch64_asm_mov_w(a, w11, 3);
    a->str(w11, ptr(x9, 2 * sizeof(uint64_t)));

    a->add(x13, x23, kParcelPrefixScratchOffset + 8);
    kernel_module::export_symbol::copy_from_user(
        a, copy_helper_err, x13, x12, sizeof(binder_size_t));
    a->cbnz(x0, fault);
    a->ldr(x14, ptr(x23, kParcelPrefixScratchOffset + 8));
    // AIDL status occupies four bytes, so the returned flat object is valid at
    // offset 4 even on the 64-bit Binder ABI; binder_size_t itself stays 64-bit.
    a->tst(x14, 3);
    a->b(CondCode::kNE, fault);
    a->add(x11, x14, sizeof(flat_binder_object));
    a->cmp(x11, x16);
    a->b(CondCode::kHI, fault);
    a->str(w14, ptr(x23, kReplyObjectOffsetScratchOffset));
    aarch64_asm_mov_x(
        a,
        x9,
        context_kaddr + offsetof(KernelCounterContext, last_create_data_size));
    a->str(w14, ptr(x9, 2 * sizeof(uint32_t) + 2 * sizeof(uint64_t)));
    aarch64_asm_mov_w(a, w11, 4);
    a->str(w11, ptr(x9, 2 * sizeof(uint64_t)));

    a->add(x12, x15, x14);
    a->add(x13, x23, kParcelPrefixScratchOffset + 16);
    kernel_module::export_symbol::copy_from_user(
        a, copy_helper_err, x13, x12, sizeof(flat_binder_object));
    a->cbnz(x0, fault);
    a->ldr(w11, ptr(x23, kParcelPrefixScratchOffset + 16));
    a->ldr(w10, ptr(x23, kParcelPrefixScratchOffset + 24));
    aarch64_asm_mov_x(
        a,
        x9,
        context_kaddr + offsetof(KernelCounterContext, last_create_data_size));
    a->str(w11, ptr(x9, 3 * sizeof(uint32_t) + 2 * sizeof(uint64_t)));
    a->str(w10, ptr(x9, 4 * sizeof(uint32_t) + 2 * sizeof(uint64_t)));
    aarch64_asm_mov_w(a, w12, 5);
    a->str(w12, ptr(x9, 2 * sizeof(uint64_t)));
    aarch64_asm_mov_w(a, w12, static_cast<uint32_t>(BINDER_TYPE_HANDLE));
    a->cmp(w11, w12);
    a->b(CondCode::kNE, fault);
    aarch64_asm_mov_w(a, w12, 6);
    a->str(w12, ptr(x9, 2 * sizeof(uint64_t)));
    a->mov(w11, w10);
    a->cbz(w11, fault);
    a->str(w11, ptr(x23, kPluginHandleScratchOffset));
    aarch64_asm_mov_w(a, w12, 7);
    a->str(w12, ptr(x9, 2 * sizeof(uint64_t)));

    emit_plugin_map_register(a, context_kaddr, task_offsets);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, create_reply_ok));
    aarch64_asm_mov_w(a, w11, sizeof(int32_t) + sizeof(flat_binder_object));
    a->str(w11, ptr(x23, kReplyPrefixSizeScratchOffset));
    a->ldr(w11, ptr(x23, kReplyFlagsScratchOffset));
    aarch64_asm_mov_w(
        a,
        w12,
        kReplyFlagStatusOk | kReplyFlagWidevinePluginRegistered);
    a->orr(w11, w11, w12);
    a->str(w11, ptr(x23, kReplyFlagsScratchOffset));
    a->b(done);

    a->bind(fault);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, create_reply_faults));
    a->bind(done);
}

// Parse only a BR_REPLY correlated to a deviceUniqueId request. The first
// copy reads the 8-byte successful AIDL status/byte-array header. A second
// bounded copy proves that the reported content range is readable; bytes stay
// in transient handler stack scratch and are never placed in the event ring.
void emit_parse_correlated_reply(Assembler* a,
                                 uint64_t context_kaddr,
                                 const TaskIdentityOffsets& task_offsets,
                                 const DirectPageMapProfile& page_map,
                                 KModErr& copy_helper_err) {
    const Label header_fault = a->newLabel();
    const Label status_nonzero = a->newLabel();
    const Label array_invalid = a->newLabel();
    const Label content_fault = a->newLabel();
    const Label length_mismatch = a->newLabel();
    const Label rule_match = a->newLabel();
    const Label rule_miss = a->newLabel();
    const Label rule_cred_fault = a->newLabel();
    const Label dry_run = a->newLabel();
    const Label copy_to_user_fault = a->newLabel();
    const Label access_vm_fault = a->newLabel();
    const Label page_pin_fault = a->newLabel();
    const Label page_pin_partial_cleanup = a->newLabel();
    const Label page_copy_loop = a->newLabel();
    const Label page_copy_done = a->newLabel();
    const Label page_flush_loop = a->newLabel();
    const Label page_flush_done = a->newLabel();
    const Label done = a->newLabel();

    a->str(w17, ptr(x23, kCorrelatedRequestFlagsScratchOffset));
    a->str(wzr, ptr(x23, kReplyPrefixSizeScratchOffset));
    a->str(wzr, ptr(x23, kReplyStatusScratchOffset));
    a->str(wzr, ptr(x23, kReplyArrayLengthScratchOffset));
    a->str(wzr, ptr(x23, kReplyArrayOffsetScratchOffset));
    a->str(wzr, ptr(x23, kReplyFlagsScratchOffset));
    a->tbz(x17, 0, done);
    a->tbz(x17, 2, done);
    emit_capture_active_runtime_config(a, context_kaddr);

    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, reply_candidates));
    aarch64_asm_mov_x(
        a, x11, kReplyFlagCorrelatedDeviceUniqueId);
    a->str(w11, ptr(x23, kReplyFlagsScratchOffset));

    a->ldr(x16, ptr(x23, kTransactionScratchOffset + 32));
    a->ldr(x15, ptr(x23, kTransactionScratchOffset + 48));
    a->cmp(x16, 8);
    a->b(CondCode::kLO, array_invalid);
    a->cbz(x15, header_fault);
    a->add(x13, x23, kParcelPrefixScratchOffset);
    kernel_module::export_symbol::copy_from_user(
        a, copy_helper_err, x13, x15, 8);
    a->cbnz(x0, header_fault);
    aarch64_asm_mov_x(a, x11, 8);
    a->str(w11, ptr(x23, kReplyPrefixSizeScratchOffset));
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, reply_header_copy_ok));

    a->ldr(w11, ptr(x23, kParcelPrefixScratchOffset));
    a->str(w11, ptr(x23, kReplyStatusScratchOffset));
    a->cbnz(w11, status_nonzero);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, reply_status_ok));
    a->ldr(w12, ptr(x23, kParcelPrefixScratchOffset + 4));
    a->str(w12, ptr(x23, kReplyArrayLengthScratchOffset));
    a->cbz(w12, array_invalid);
    a->cmp(w12, 64);
    a->b(CondCode::kHI, array_invalid);
    a->add(x14, x12, 8);
    a->cmp(x14, x16);
    a->b(CondCode::kHI, array_invalid);
    aarch64_asm_mov_x(a, x11, 8);
    a->str(w11, ptr(x23, kReplyArrayOffsetScratchOffset));
    a->ldr(w11, ptr(x23, kReplyFlagsScratchOffset));
    a->orr(w11, w11, kReplyFlagStatusOk | kReplyFlagArrayValid);
    a->str(w11, ptr(x23, kReplyFlagsScratchOffset));
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, reply_array_valid));

    a->add(x13, x23, kParcelPrefixScratchOffset + 16);
    a->add(x15, x15, 8);
    kernel_module::export_symbol::copy_from_user(
        a, copy_helper_err, x13, x15, x12);
    a->cbnz(x0, content_fault);
    a->ldr(w14, ptr(x23, kReplyArrayLengthScratchOffset));
    a->add(w14, w14, 8);
    a->str(w14, ptr(x23, kReplyPrefixSizeScratchOffset));
    a->ldr(w11, ptr(x23, kReplyFlagsScratchOffset));
    a->orr(w11, w11, kReplyFlagContentReadable);
    a->str(w11, ptr(x23, kReplyFlagsScratchOffset));
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, reply_content_copy_ok));

    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, replacement_candidates));
    a->ldr(w11, ptr(x23, kReplyFlagsScratchOffset));
    a->orr(w11, w11, kReplyFlagReplacementCandidate);
    a->str(w11, ptr(x23, kReplyFlagsScratchOffset));

    // Apply the configured client-EUID rule only after the request, status,
    // array and readable-range guards have all succeeded. x27 is the current
    // Binder client task for this BR_REPLY.
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, rule_checks));
    a->ldr(x9, ptr(x27, task_offsets.cred));
    a->cbz(x9, rule_cred_fault);
    a->ldr(w10, ptr(x9, task_offsets.cred_euid));
    aarch64_asm_mov_x(
        a, x9, context_kaddr + offsetof(KernelCounterContext, last_client_euid));
    a->str(x10, ptr(x9));
    a->ldr(x9, ptr(x23, kRuntimeConfigPointerScratchOffset));
    a->ldr(w11, ptr(x9, offsetof(RuntimeConfigSlot, rule_mode)));
    a->cbz(w11, rule_match);
    // Exact-EUID and exact-package modes both enforce one immutable, sorted
    // EUID set in EL1. The count is checked before a fully unrolled maximum-32
    // scan, so malformed or zero-bearing policies fail closed without dynamic
    // allocation or an attacker-controlled loop bound.
    a->ldr(x9, ptr(x23, kRuntimeConfigPointerScratchOffset));
    a->ldr(w11, ptr(x9, offsetof(RuntimeConfigSlot, target_count)));
    a->cbz(w11, rule_miss);
    a->cmp(w11, static_cast<uint32_t>(kRuntimeTargetLimit));
    a->b(CondCode::kHI, rule_miss);
    a->add(x12, x9, offsetof(RuntimeConfigSlot, target_euids));
    for (uint32_t index = 0; index < kRuntimeTargetLimit; ++index) {
        a->cmp(w11, index + 1);
        a->b(CondCode::kLO, rule_miss);
        a->ldr(w13, ptr(x12, index * sizeof(uint32_t)));
        a->cbz(w13, rule_miss);
        a->cmp(w10, w13);
        a->b(CondCode::kEQ, rule_match);
    }
    a->b(rule_miss);

    a->bind(rule_cred_fault);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, rule_cred_faults));
    a->b(done);
    a->bind(rule_miss);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, rule_misses));
    a->b(done);
    a->bind(rule_match);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, rule_matches));
    a->ldr(w11, ptr(x23, kReplyFlagsScratchOffset));
    a->orr(w11, w11, kReplyFlagRuleMatched);
    a->str(w11, ptr(x23, kReplyFlagsScratchOffset));

    a->ldr(x9, ptr(x23, kRuntimeConfigPointerScratchOffset));
    a->ldr(w12, ptr(x9, offsetof(RuntimeConfigSlot, virtual_id_length)));
    a->ldr(w14, ptr(x23, kReplyArrayLengthScratchOffset));
    a->cmp(w12, w14);
    a->b(CondCode::kNE, length_mismatch);
    a->ldr(x9, ptr(x23, kRuntimeConfigPointerScratchOffset));
    a->ldr(w11, ptr(x9, offsetof(RuntimeConfigSlot, replacement_mode)));
    a->cbz(w11, dry_run);

    // Write-test mode: exact-length replacement at the previously validated
    // buffer + 8 byte-array content address.
    a->ldr(x15, ptr(x23, kTransactionScratchOffset + 48));
    a->add(x15, x15, 8);
    a->ldr(x13, ptr(x23, kRuntimeConfigPointerScratchOffset));
    a->add(x13, x13, offsetof(RuntimeConfigSlot, virtual_id));
    a->ldr(w12, ptr(x23, kReplyArrayLengthScratchOffset));
    kernel_module::export_symbol::copy_to_user(
        a, copy_helper_err, x15, x13, x12);
    a->cbnz(x0, copy_to_user_fault);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, replacement_write_ok));
    a->ldr(w11, ptr(x23, kReplyFlagsScratchOffset));
    a->orr(w11, w11, kReplyFlagReplaced);
    a->str(w11, ptr(x23, kReplyFlagsScratchOffset));
    emit_replacement_success_telemetry(a, context_kaddr);
    a->b(done);

    a->bind(length_mismatch);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, replacement_length_mismatch));
    a->b(done);
    a->bind(dry_run);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, replacement_dry_run_hits));
    a->ldr(w11, ptr(x23, kReplyFlagsScratchOffset));
    a->orr(w11, w11, kReplyFlagDryRun);
    a->str(w11, ptr(x23, kReplyFlagsScratchOffset));
    a->b(done);
    a->bind(copy_to_user_fault);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, replacement_copy_to_user_faults));

    // Binder maps the receive buffer read-only in EL0. If ordinary
    // copy_to_user observes that VMA protection, use the kernel's remote-mm
    // helper with FOLL_WRITE | FOLL_FORCE. The target task is the current
    // Binder client captured in x27; both the target and exact length are
    // reloaded from validated scratch instead of trusting call-clobbered
    // registers from the first write attempt.
    a->ldr(x15, ptr(x23, kTransactionScratchOffset + 48));
    a->add(x15, x15, 8);
    a->ldr(x13, ptr(x23, kRuntimeConfigPointerScratchOffset));
    a->add(x13, x13, offsetof(RuntimeConfigSlot, virtual_id));
    a->ldr(w12, ptr(x23, kReplyArrayLengthScratchOffset));
    aarch64_asm_mov_w(a, w14, 0x11); // FOLL_WRITE | FOLL_FORCE
    kernel_module::export_symbol::linux_above_4_9_0::access_process_vm(
        a, copy_helper_err, x27, x15, x13, w12, w14);
    a->sxtw(x10, w0);
    aarch64_asm_mov_x(
        a,
        x9,
        context_kaddr +
            offsetof(KernelCounterContext,
                     replacement_access_vm_last_result));
    a->str(x10, ptr(x9));
    a->cmp(w0, w12);
    a->b(CondCode::kNE, access_vm_fault);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, replacement_access_vm_ok));
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, replacement_write_ok));
    a->ldr(w11, ptr(x23, kReplyFlagsScratchOffset));
    a->orr(w11, w11, kReplyFlagReplaced);
    a->str(w11, ptr(x23, kReplyFlagsScratchOffset));
    emit_replacement_success_telemetry(a, context_kaddr);
    a->b(done);

    a->bind(access_vm_fault);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, replacement_access_vm_faults));

    // FOLL_FORCE still rejects Binder's VM_MIXEDMAP receive VMA because the
    // driver intentionally removes VM_MAYWRITE. Pin the already-present
    // read-only pages without FOLL_WRITE, translate their struct page pointers
    // to the arm64 linear map, then overwrite only the validated byte range.
    // The 64-byte reply limit spans at most two pages.
    a->ldr(x15, ptr(x23, kTransactionScratchOffset + 48));
    a->add(x15, x15, 8);
    a->ldr(w12, ptr(x23, kReplyArrayLengthScratchOffset));
    a->and_(x14, x15, page_map.page_size - 1); // offset in first page
    a->add(x10, x14, x12);
    a->add(x10, x10, page_map.page_size - 1);
    a->lsr(x10, x10, page_map.page_shift); // one or two pages
    a->str(w10, ptr(x23, kPinnedPageCountScratchOffset));
    a->and_(x15, x15, ~(static_cast<uint64_t>(page_map.page_size) - 1));
    aarch64_asm_mov_w(a, w11, 0); // read pin; no FOLL_WRITE
    a->add(x13, x23, kPinnedPagesScratchOffset);
    kernel_module::export_symbol::linux_above_5_6_0::pin_user_pages_fast(
        a, copy_helper_err, x15, w10, w11, x13);
    a->str(w0, ptr(x23, kPinnedPageResultScratchOffset));
    a->sxtw(x11, w0);
    aarch64_asm_mov_x(
        a,
        x9,
        context_kaddr +
            offsetof(KernelCounterContext,
                     replacement_page_pin_last_result));
    a->str(x11, ptr(x9));
    a->ldr(w10, ptr(x23, kPinnedPageCountScratchOffset));
    a->cmp(w0, w10);
    a->b(CondCode::kNE, page_pin_partial_cleanup);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, replacement_page_pin_ok));

    aarch64_asm_mov_w(a, w10, 0); // copied byte index
    a->bind(page_copy_loop);
    a->cmp(w10, w12);
    a->b(CondCode::kHS, page_copy_done);
    a->add(x11, x14, x10);
    a->lsr(x9, x11, page_map.page_shift); // pinned page index
    a->lsl(x9, x9, 3);
    a->add(x9, x23, x9);
    a->ldr(x16, ptr(x9, kPinnedPagesScratchOffset));

    // page_to_pfn(page) followed by __va(PFN_PHYS(pfn)). All constants are
    // calibrated by the SDK while the handler is built on the target kernel.
    aarch64_asm_mov_x(a, x9, page_map.vmemmap);
    a->sub(x16, x16, x9);
    aarch64_asm_mov_x(a, x9, page_map.struct_page_size);
    a->udiv(x16, x16, x9);
    a->lsl(x16, x16, page_map.page_shift);
    aarch64_asm_mov_x(a, x9, page_map.phys_offset);
    a->sub(x16, x16, x9);
    aarch64_asm_mov_x(a, x9, page_map.linear_map_base);
    a->add(x16, x16, x9);
    a->and_(x11, x11, page_map.page_size - 1);
    a->add(x16, x16, x11);

    a->ldr(x13, ptr(x23, kRuntimeConfigPointerScratchOffset));
    a->add(x13, x13, offsetof(RuntimeConfigSlot, virtual_id));
    a->add(x13, x13, x10);
    a->ldrb(w9, ptr(x13));
    a->strb(w9, ptr(x16));
    a->add(w10, w10, 1);
    a->b(page_copy_loop);

    a->bind(page_copy_done);
    aarch64_asm_mov_w(a, w10, 0);
    a->bind(page_flush_loop);
    a->ldr(w12, ptr(x23, kPinnedPageCountScratchOffset));
    a->cmp(w10, w12);
    a->b(CondCode::kHS, page_flush_done);
    a->lsl(x11, x10, 3);
    a->add(x11, x23, x11);
    a->ldr(x16, ptr(x11, kPinnedPagesScratchOffset));
    emit_call_kernel_symbol_one_arg(
        a, copy_helper_err, "flush_dcache_page", x16);
    a->add(w10, w10, 1);
    a->b(page_flush_loop);

    a->bind(page_flush_done);
    a->add(x13, x23, kPinnedPagesScratchOffset);
    a->ldr(w12, ptr(x23, kPinnedPageCountScratchOffset));
    emit_call_kernel_symbol_two_args(
        a, copy_helper_err, "unpin_user_pages", x13, x12);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, replacement_page_write_ok));
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, replacement_write_ok));
    a->ldr(w11, ptr(x23, kReplyFlagsScratchOffset));
    a->orr(w11, w11, kReplyFlagReplaced);
    a->str(w11, ptr(x23, kReplyFlagsScratchOffset));
    emit_replacement_success_telemetry(a, context_kaddr);
    a->b(done);

    a->bind(page_pin_partial_cleanup);
    a->ldr(w11, ptr(x23, kPinnedPageResultScratchOffset));
    a->cmp(w11, 0);
    a->b(CondCode::kLE, page_pin_fault);
    a->add(x13, x23, kPinnedPagesScratchOffset);
    emit_call_kernel_symbol_two_args(
        a, copy_helper_err, "unpin_user_pages", x13, x11);
    a->bind(page_pin_fault);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, replacement_page_pin_faults));
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, replacement_page_write_faults));
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, replacement_write_faults));
    a->b(done);

    a->bind(header_fault);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, reply_header_copy_faults));
    a->b(done);
    a->bind(status_nonzero);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, reply_status_nonzero));
    a->b(done);
    a->bind(array_invalid);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, reply_array_invalid));
    a->b(done);
    a->bind(content_fault);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, reply_content_copy_faults));
    a->bind(done);
}

// The 64-byte binder_transaction_data has already been copied to x23 + 16.
void emit_record_transaction(Assembler* a,
                             uint64_t context_kaddr,
                             uint32_t expected_ioc_type,
                             const TaskIdentityOffsets& task_offsets,
                             const DirectPageMapProfile& page_map,
                             KModErr& copy_helper_err) {
    const Label correlation_ready = a->newLabel();
    const Label publish = a->newLabel();

    emit_capture_parcel_prefix(
        a, context_kaddr, expected_ioc_type, copy_helper_err);

    kernel_module::export_symbol::get_current(a, x27);
    a->mov(x21, xzr); // correlated request event id
    a->mov(x17, xzr); // correlated request Parcel flags

    if (expected_ioc_type == static_cast<uint32_t>('c')) {
        emit_plugin_map_classify_request(a, context_kaddr, task_offsets);
    }

    if (expected_ioc_type == static_cast<uint32_t>('r')) {
        aarch64_asm_mov_x(a, x12, static_cast<uint32_t>(BR_REPLY));
        a->cmp(w24, w12);
        a->b(CondCode::kNE, correlation_ready);
        emit_pending_pop(a, context_kaddr, false);
    }
    a->bind(correlation_ready);
    emit_parse_correlated_reply(
        a, context_kaddr, task_offsets, page_map, copy_helper_err);
    emit_parse_widevine_create_reply(
        a, context_kaddr, task_offsets, copy_helper_err);

    emit_reserve_event(a, context_kaddr);
    a->str(x27, ptr(x28, offsetof(BinderTransactionEvent, task_kaddr)));
    a->str(x21, ptr(x28, offsetof(BinderTransactionEvent,
                                  correlated_request_id)));
    a->ldr(w11, ptr(x27, task_offsets.pid));
    a->str(w11, ptr(x28, offsetof(BinderTransactionEvent, pid)));
    a->ldr(w12, ptr(x27, task_offsets.tgid));
    a->str(w12, ptr(x28, offsetof(BinderTransactionEvent, tgid)));
    a->str(w24, ptr(x28, offsetof(BinderTransactionEvent, command)));
    a->ldr(w11, ptr(x23, kParcelTokenKindScratchOffset));
    a->str(w11, ptr(x28, offsetof(BinderTransactionEvent, parcel_token_kind)));
    a->ldr(w11, ptr(x23, kParcelTokenOffsetScratchOffset));
    a->str(w11, ptr(x28, offsetof(BinderTransactionEvent, parcel_token_offset)));
    a->ldr(w11, ptr(x23, kParcelPrefixSizeScratchOffset));
    a->str(w11, ptr(x28, offsetof(BinderTransactionEvent, parcel_prefix_size)));
    a->ldr(w11, ptr(x23, kParcelFlagsScratchOffset));
    a->str(w11, ptr(x28, offsetof(BinderTransactionEvent, parcel_flags)));
    a->ldr(w11, ptr(x23, kCorrelatedRequestFlagsScratchOffset));
    a->str(w11,
           ptr(x28, offsetof(BinderTransactionEvent,
                             correlated_request_flags)));
    a->ldr(w11, ptr(x23, kReplyPrefixSizeScratchOffset));
    a->str(w11, ptr(x28, offsetof(BinderTransactionEvent, reply_prefix_size)));
    a->ldr(w11, ptr(x23, kReplyStatusScratchOffset));
    a->str(w11, ptr(x28, offsetof(BinderTransactionEvent, reply_status_code)));
    a->ldr(w11, ptr(x23, kReplyArrayLengthScratchOffset));
    a->str(w11,
           ptr(x28, offsetof(BinderTransactionEvent,
                             reply_byte_array_length)));
    a->ldr(w11, ptr(x23, kReplyArrayOffsetScratchOffset));
    a->str(w11,
           ptr(x28, offsetof(BinderTransactionEvent,
                             reply_byte_array_offset)));
    a->ldr(w11, ptr(x23, kReplyFlagsScratchOffset));
    a->str(w11, ptr(x28, offsetof(BinderTransactionEvent, reply_flags)));
    a->ldr(w11, ptr(x23, kFactoryUuidOffsetScratchOffset));
    a->str(w11, ptr(x28, offsetof(BinderTransactionEvent, factory_uuid_offset)));
    a->ldr(w11, ptr(x23, kPluginHandleScratchOffset));
    a->str(w11, ptr(x28, offsetof(BinderTransactionEvent, plugin_handle)));

    a->ldr(x11, ptr(x23, kTransactionScratchOffset + 0));
    a->str(x11, ptr(x28, offsetof(BinderTransactionEvent, target)));
    a->ldr(x11, ptr(x23, kTransactionScratchOffset + 8));
    a->str(x11, ptr(x28, offsetof(BinderTransactionEvent, cookie)));
    a->ldr(w11, ptr(x23, kTransactionScratchOffset + 16));
    a->str(w11, ptr(x28, offsetof(BinderTransactionEvent, code)));
    a->ldr(w11, ptr(x23, kTransactionScratchOffset + 20));
    a->str(w11, ptr(x28, offsetof(BinderTransactionEvent, flags)));
    a->ldr(w11, ptr(x23, kTransactionScratchOffset + 24));
    a->str(w11, ptr(x28, offsetof(BinderTransactionEvent, sender_pid)));
    a->ldr(w11, ptr(x23, kTransactionScratchOffset + 28));
    a->str(w11, ptr(x28, offsetof(BinderTransactionEvent, sender_euid)));
    a->ldr(x11, ptr(x23, kTransactionScratchOffset + 32));
    a->str(x11, ptr(x28, offsetof(BinderTransactionEvent, data_size)));
    a->ldr(x11, ptr(x23, kTransactionScratchOffset + 40));
    a->str(x11, ptr(x28, offsetof(BinderTransactionEvent, offsets_size)));
    a->ldr(x11, ptr(x23, kTransactionScratchOffset + 48));
    a->str(x11, ptr(x28, offsetof(BinderTransactionEvent, buffer)));
    a->ldr(x11, ptr(x23, kTransactionScratchOffset + 56));
    a->str(x11, ptr(x28, offsetof(BinderTransactionEvent, offsets)));

    if (expected_ioc_type == static_cast<uint32_t>('c')) {
        const Label is_request = a->newLabel();
        aarch64_asm_mov_x(a, x12, static_cast<uint32_t>(BC_TRANSACTION));
        a->cmp(w24, w12);
        a->b(CondCode::kEQ, is_request);
        aarch64_asm_mov_x(a, x12, static_cast<uint32_t>(BC_TRANSACTION_SG));
        a->cmp(w24, w12);
        a->b(CondCode::kEQ, is_request);
        aarch64_asm_mov_x(
            a, x12, static_cast<uint32_t>(BinderEventKind::kBcReply));
        a->str(w12, ptr(x28, offsetof(BinderTransactionEvent, kind)));
        a->b(publish);
        a->bind(is_request);
        aarch64_asm_mov_x(
            a, x12, static_cast<uint32_t>(BinderEventKind::kBcTransaction));
        a->str(w12, ptr(x28, offsetof(BinderTransactionEvent, kind)));
        emit_pending_push(a, context_kaddr, task_offsets);
        a->b(publish);
    } else {
        const Label not_reply = a->newLabel();
        const Label normal_transaction = a->newLabel();
        aarch64_asm_mov_x(a, x12, static_cast<uint32_t>(BR_REPLY));
        a->cmp(w24, w12);
        a->b(CondCode::kNE, not_reply);
        aarch64_asm_mov_x(
            a, x12, static_cast<uint32_t>(BinderEventKind::kBrReply));
        a->str(w12, ptr(x28, offsetof(BinderTransactionEvent, kind)));
        a->b(publish);
        a->bind(not_reply);
        aarch64_asm_mov_x(
            a, x12, static_cast<uint32_t>(BR_TRANSACTION_SEC_CTX));
        a->cmp(w24, w12);
        a->b(CondCode::kNE, normal_transaction);
        aarch64_asm_mov_x(
            a,
            x12,
            static_cast<uint32_t>(BinderEventKind::kBrTransactionSecCtx));
        a->str(w12, ptr(x28, offsetof(BinderTransactionEvent, kind)));
        a->b(publish);
        a->bind(normal_transaction);
        aarch64_asm_mov_x(
            a, x12, static_cast<uint32_t>(BinderEventKind::kBrTransaction));
        a->str(w12, ptr(x28, offsetof(BinderTransactionEvent, kind)));
        a->b(publish);
    }

    a->bind(publish);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, transaction_metadata_ok));
    emit_publish_event(a);
}

// Parse only the top-level Binder command framing. Each item is:
//   uint32_t command + _IOC_SIZE(command) payload bytes.
// Payloads are deliberately not read at this milestone.
void emit_parse_command_stream(Assembler* a,
                               uint64_t context_kaddr,
                               const TaskIdentityOffsets& task_offsets,
                               const DirectPageMapProfile& page_map,
                               GpX binder_file,
                               GpX user_buffer,
                               GpX consumed,
                               uint32_t expected_ioc_type,
                               size_t stream_counter_offset,
                               size_t command_counter_offset,
                               size_t transaction_counter_offset,
                               size_t boundary_counter_offset,
                               size_t copy_fault_counter_offset,
                               size_t capped_counter_offset,
                               KModErr& copy_helper_err) {
    const Label done = a->newLabel();
    const Label loop = a->newLabel();
    const Label boundary_error = a->newLabel();
    const Label copy_fault = a->newLabel();
    const Label capped = a->newLabel();

    RegProtectGuard preserve(
        a, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28);
    a->sub(sp, sp, kParserScratchBytes);
    a->mov(x23, sp);
    a->str(binder_file, ptr(x23, kBinderFileScratchOffset));
    a->mov(x19, user_buffer);
    a->mov(x20, consumed);
    a->mov(x22, 0);
    a->cbz(x20, done);
    a->cbz(x19, copy_fault);
    aarch64_asm_mov_x(a, x25, kMaxParsedStreamBytes);
    a->cmp(x20, x25);
    a->b(CondCode::kHI, capped);

    emit_counter_increment(a, context_kaddr, stream_counter_offset);
    a->bind(loop);
    a->cmp(x22, kMaxParsedCommands);
    a->b(CondCode::kHS, capped);
    a->cmp(x20, sizeof(uint32_t));
    a->b(CondCode::kLO, boundary_error);

    kernel_module::export_symbol::copy_from_user(
        a, copy_helper_err, x23, x19, sizeof(uint32_t));
    a->cbnz(x0, copy_fault);
    a->ldr(w24, ptr(x23));

    // Linux asm-generic ioctl encoding: type[15:8], size[29:16].
    a->ubfx(x25, x24, 8, 8);
    a->cmp(x25, expected_ioc_type);
    a->b(CondCode::kNE, boundary_error);
    a->ubfx(x25, x24, 16, 14);
    a->add(x25, x25, sizeof(uint32_t));
    a->cmp(x25, x20);
    a->b(CondCode::kHI, boundary_error);

    emit_counter_increment(a, context_kaddr, command_counter_offset);

    // Count the transaction-carrying commands needed by the next AIDL stage,
    // while still walking every valid top-level BC/BR command.
    const Label not_transaction = a->newLabel();
    const Label is_transaction = a->newLabel();
    const Label command_processed = a->newLabel();
    const Label metadata_fault = a->newLabel();
    auto emit_command_match = [&](uint32_t command) {
        aarch64_asm_mov_x(a, x26, command);
        a->cmp(w24, w26);
        a->b(CondCode::kEQ, is_transaction);
    };
    if (expected_ioc_type == static_cast<uint32_t>('c')) {
        emit_command_match(static_cast<uint32_t>(BC_TRANSACTION));
        emit_command_match(static_cast<uint32_t>(BC_REPLY));
        emit_command_match(static_cast<uint32_t>(BC_TRANSACTION_SG));
        emit_command_match(static_cast<uint32_t>(BC_REPLY_SG));
    } else {
        emit_command_match(static_cast<uint32_t>(BR_TRANSACTION));
        emit_command_match(static_cast<uint32_t>(BR_TRANSACTION_SEC_CTX));
        emit_command_match(static_cast<uint32_t>(BR_REPLY));
    }
    a->b(not_transaction);
    a->bind(is_transaction);
    emit_counter_increment(a, context_kaddr, transaction_counter_offset);

    // Every recognized transaction command begins with a 64-byte
    // binder_transaction_data. SG/secctx variants append data after it.
    a->add(x13, x23, kTransactionScratchOffset);
    a->add(x14, x19, sizeof(uint32_t));
    kernel_module::export_symbol::copy_from_user(
        a, copy_helper_err, x13, x14, sizeof(binder_transaction_data));
    a->cbnz(x0, metadata_fault);
    emit_record_transaction(
        a,
        context_kaddr,
        expected_ioc_type,
        task_offsets,
        page_map,
        copy_helper_err);
    a->b(command_processed);

    a->bind(metadata_fault);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, transaction_metadata_faults));
    a->b(command_processed);

    a->bind(not_transaction);
    if (expected_ioc_type == static_cast<uint32_t>('c')) {
        const Label not_release = a->newLabel();
        aarch64_asm_mov_w(a, w26, static_cast<uint32_t>(BC_RELEASE));
        a->cmp(w24, w26);
        a->b(CondCode::kNE, not_release);
        a->add(x14, x19, sizeof(uint32_t));
        a->add(x13, x23, kPluginHandleScratchOffset);
        kernel_module::export_symbol::copy_from_user(
            a, copy_helper_err, x13, x14, sizeof(uint32_t));
        a->cbnz(x0, copy_fault);
        kernel_module::export_symbol::get_current(a, x27);
        emit_plugin_map_release(a, context_kaddr, task_offsets);
        a->bind(not_release);
    } else {
        const Label terminal_reply = a->newLabel();
        const Label not_terminal = a->newLabel();
        auto emit_terminal_match = [&](uint32_t command) {
            aarch64_asm_mov_x(a, x26, command);
            a->cmp(w24, w26);
            a->b(CondCode::kEQ, terminal_reply);
        };
        emit_terminal_match(static_cast<uint32_t>(BR_DEAD_REPLY));
        emit_terminal_match(static_cast<uint32_t>(BR_FAILED_REPLY));
        emit_terminal_match(static_cast<uint32_t>(BR_FROZEN_REPLY));
        a->b(not_terminal);
        a->bind(terminal_reply);
        kernel_module::export_symbol::get_current(a, x27);
        emit_pending_pop(a, context_kaddr, true);
        a->bind(not_terminal);
    }

    a->bind(command_processed);

    a->add(x22, x22, 1);
    a->add(x19, x19, x25);
    a->sub(x20, x20, x25);
    a->cbnz(x20, loop);
    a->b(done);

    a->bind(capped);
    emit_counter_increment(a, context_kaddr, capped_counter_offset);
    a->b(done);
    a->bind(boundary_error);
    emit_counter_increment(a, context_kaddr, boundary_counter_offset);
    a->b(done);
    a->bind(copy_fault);
    emit_counter_increment(a, context_kaddr, copy_fault_counter_offset);
    a->bind(done);
    a->add(sp, sp, kParserScratchBytes);
}

KModErr build_readonly_parser_handler(uint64_t context_kaddr,
                                      const TaskIdentityOffsets& task_offsets,
                                      std::vector<uint8_t>& handler) {
    DirectPageMapProfile page_map;
    RETURN_IF_ERROR(resolve_direct_page_map_profile(page_map));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    Assembler* a = asm_ctx.assembler();
    if (a == nullptr) {
        return KModErr::ERR_MODULE_ASM;
    }

    kernel_module::arm64_before_hook_start(a);

    const Label tracked = a->newLabel();
    const Label bypass = a->newLabel();
    const Label finish = a->newLabel();
    emit_package_uid_or_target_gate(
        a,
        context_kaddr,
        task_offsets,
        static_cast<uint32_t>(getpid()),
        tracked,
        bypass);

    a->bind(bypass);
    // Fast path: original x0/x1/x2 arguments were never modified by the gate.
    kernel_module::arm64_emit_call_original(a);
    a->b(finish);

    a->bind(tracked);

    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, active_calls));
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, pre_calls));

    // The generated function calls copy_from_user and the original ioctl, so
    // retain all three original arguments and the eventual return value in a
    // private, 16-byte-aligned stack frame.
    a->sub(sp, sp, kLocalBytes);
    a->str(x0, ptr(sp, kLocalFile));
    a->str(x1, ptr(sp, kLocalCmd));
    a->str(x2, ptr(sp, kLocalArg));
    a->str(xzr, ptr(sp, kLocalPreHeaderValid));

    const Label before_original = a->newLabel();
    const Label pre_header_fault = a->newLabel();
    const Label pre_header_done = a->newLabel();
    aarch64_asm_mov_x(
        a, x9, static_cast<uint64_t>(static_cast<uint32_t>(BINDER_WRITE_READ)));
    a->cmp(w1, w9);
    a->b(CondCode::kNE, before_original);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, bwr_calls));
    a->cbz(x2, pre_header_fault);

    KModErr copy_helper_err = KModErr::OK;
    a->add(x9, sp, kLocalHeader);
    kernel_module::export_symbol::copy_from_user(
        a, copy_helper_err, x9, x2, sizeof(binder_write_read));
    if (is_failed(copy_helper_err)) {
        return copy_helper_err;
    }
    a->cbnz(x0, pre_header_fault);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, pre_header_ok));
    a->ldr(x9, ptr(sp, kLocalHeader + 0));
    a->str(x9, ptr(sp, kLocalWriteSize));
    a->ldr(x9, ptr(sp, kLocalHeader + 16));
    a->str(x9, ptr(sp, kLocalWriteBuffer));
    a->ldr(x9, ptr(sp, kLocalHeader + 24));
    a->str(x9, ptr(sp, kLocalReadSize));
    a->ldr(x9, ptr(sp, kLocalHeader + 40));
    a->str(x9, ptr(sp, kLocalReadBuffer));
    a->mov(x9, 1);
    a->str(x9, ptr(sp, kLocalPreHeaderValid));
    a->b(pre_header_done);
    a->bind(pre_header_fault);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, pre_header_faults));
    a->bind(pre_header_done);

    a->bind(before_original);
    a->ldr(x0, ptr(sp, kLocalFile));
    a->ldr(x1, ptr(sp, kLocalCmd));
    a->ldr(x2, ptr(sp, kLocalArg));
    kernel_module::arm64_emit_call_original(a);
    a->str(x0, ptr(sp, kLocalReturn));

    const Label post_done = a->newLabel();
    const Label post_header_fault = a->newLabel();
    const Label post_header_invalid = a->newLabel();
    a->ldr(x9, ptr(sp, kLocalPreHeaderValid));
    a->cbz(x9, post_done);
    a->ldr(x10, ptr(sp, kLocalArg));
    a->cbz(x10, post_header_fault);
    a->add(x9, sp, kLocalHeader);
    kernel_module::export_symbol::copy_from_user(
        a, copy_helper_err, x9, x10, sizeof(binder_write_read));
    if (is_failed(copy_helper_err)) {
        return copy_helper_err;
    }
    a->cbnz(x0, post_header_fault);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, post_header_ok));

    // The driver only advances consumed. Sizes and pointers must remain equal
    // to the pre-call snapshot, and consumed must not exceed its size.
    a->ldr(x9, ptr(sp, kLocalHeader + 0));
    a->ldr(x10, ptr(sp, kLocalWriteSize));
    a->cmp(x9, x10);
    a->b(CondCode::kNE, post_header_invalid);
    a->ldr(x9, ptr(sp, kLocalHeader + 16));
    a->ldr(x10, ptr(sp, kLocalWriteBuffer));
    a->cmp(x9, x10);
    a->b(CondCode::kNE, post_header_invalid);
    a->ldr(x9, ptr(sp, kLocalHeader + 24));
    a->ldr(x10, ptr(sp, kLocalReadSize));
    a->cmp(x9, x10);
    a->b(CondCode::kNE, post_header_invalid);
    a->ldr(x9, ptr(sp, kLocalHeader + 40));
    a->ldr(x10, ptr(sp, kLocalReadBuffer));
    a->cmp(x9, x10);
    a->b(CondCode::kNE, post_header_invalid);
    a->ldr(x14, ptr(sp, kLocalHeader + 8));
    a->ldr(x15, ptr(sp, kLocalWriteSize));
    a->cmp(x14, x15);
    a->b(CondCode::kHI, post_header_invalid);
    a->ldr(x16, ptr(sp, kLocalHeader + 32));
    a->ldr(x17, ptr(sp, kLocalReadSize));
    a->cmp(x16, x17);
    a->b(CondCode::kHI, post_header_invalid);

    // Parse the user write stream as BC ('c') and the driver read stream as
    // BR ('r'). The emitters touch only four bytes per top-level command.
    a->ldr(x13, ptr(sp, kLocalWriteBuffer));
    a->ldr(x12, ptr(sp, kLocalFile));
    emit_parse_command_stream(
        a,
        context_kaddr,
        task_offsets,
        page_map,
        x12,
        x13,
        x14,
        static_cast<uint32_t>('c'),
        offsetof(KernelCounterContext, write_streams),
        offsetof(KernelCounterContext, bc_commands),
        offsetof(KernelCounterContext, bc_transaction_commands),
        offsetof(KernelCounterContext, write_boundary_errors),
        offsetof(KernelCounterContext, write_copy_faults),
        offsetof(KernelCounterContext, write_capped),
        copy_helper_err);
    if (is_failed(copy_helper_err)) {
        return copy_helper_err;
    }
    a->ldr(x13, ptr(sp, kLocalReadBuffer));
    a->ldr(x12, ptr(sp, kLocalFile));
    // Reload consumed: x16 is caller-saved and the first parser calls a helper.
    a->ldr(x16, ptr(sp, kLocalHeader + 32));
    emit_parse_command_stream(
        a,
        context_kaddr,
        task_offsets,
        page_map,
        x12,
        x13,
        x16,
        static_cast<uint32_t>('r'),
        offsetof(KernelCounterContext, read_streams),
        offsetof(KernelCounterContext, br_commands),
        offsetof(KernelCounterContext, br_transaction_commands),
        offsetof(KernelCounterContext, read_boundary_errors),
        offsetof(KernelCounterContext, read_copy_faults),
        offsetof(KernelCounterContext, read_capped),
        copy_helper_err);
    if (is_failed(copy_helper_err)) {
        return copy_helper_err;
    }
    a->b(post_done);

    a->bind(post_header_invalid);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, invalid_consumed));
    a->b(post_done);
    a->bind(post_header_fault);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, post_header_faults));
    a->bind(post_done);

    a->ldr(x0, ptr(sp, kLocalReturn));
    a->add(sp, sp, kLocalBytes);
    {
        RegProtectGuard preserve_return(a, x0);
        emit_counter_increment(
            a, context_kaddr, offsetof(KernelCounterContext, post_calls));
        emit_atomic_decrement(
            a,
            context_kaddr + offsetof(KernelCounterContext, active_calls));
    }

    a->bind(finish);
    kernel_module::arm64_before_hook_end(a, false);

    if (asm_ctx.has_error()) {
        return KModErr::ERR_MODULE_ASM;
    }
    handler = aarch64_asm_to_bytes(a);
    return handler.empty() ? KModErr::ERR_MODULE_ASM : KModErr::OK;
}

} // namespace

KModErr resolve_and_validate_task_identity_offsets(TaskIdentityOffsets& offsets) {
    offsets = {};
    RETURN_IF_ERROR(kernel_module::get_task_struct_pid_offset(offsets.pid));
    RETURN_IF_ERROR(kernel_module::get_task_struct_tgid_offset(offsets.tgid));
    RETURN_IF_ERROR(kernel_module::get_task_struct_cred_offset(offsets.cred));
    RETURN_IF_ERROR(kernel_module::get_cred_euid_offset(offsets.cred_euid));

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    Assembler* a = asm_ctx.assembler();
    if (a == nullptr) {
        return KModErr::ERR_MODULE_ASM;
    }
    kernel_module::arm64_module_asm_func_start(a);
    kernel_module::export_symbol::get_current(a, x9);
    a->ldr(w10, ptr(x9, offsets.pid));
    a->ldr(w11, ptr(x9, offsets.tgid));
    a->lsl(x11, x11, 32);
    a->orr(x9, x10, x11);
    kernel_module::arm64_module_asm_func_end(a, x9);
    if (asm_ctx.has_error()) {
        return KModErr::ERR_MODULE_ASM;
    }

    uint64_t packed = 0;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(
        aarch64_asm_to_bytes(a), packed));
    const uint32_t observed_pid = static_cast<uint32_t>(packed);
    const uint32_t observed_tgid = static_cast<uint32_t>(packed >> 32);
    const uint32_t expected_pid =
        static_cast<uint32_t>(syscall(SYS_gettid));
    const uint32_t expected_tgid = static_cast<uint32_t>(getpid());
    if (observed_pid != expected_pid || observed_tgid != expected_tgid) {
        offsets = {};
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }

    aarch64_asm_ctx cred_ctx = init_aarch64_asm();
    Assembler* cred_a = cred_ctx.assembler();
    if (cred_a == nullptr) {
        offsets = {};
        return KModErr::ERR_MODULE_ASM;
    }
    kernel_module::arm64_module_asm_func_start(cred_a);
    kernel_module::export_symbol::get_current(cred_a, x9);
    cred_a->ldr(x9, ptr(x9, offsets.cred));
    cred_a->ldr(w9, ptr(x9, offsets.cred_euid));
    kernel_module::arm64_module_asm_func_end(cred_a, x9);
    if (cred_ctx.has_error()) {
        offsets = {};
        return KModErr::ERR_MODULE_ASM;
    }
    uint64_t observed_euid = UINT64_MAX;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(
        aarch64_asm_to_bytes(cred_a), observed_euid));
    if (static_cast<uint32_t>(observed_euid) !=
        static_cast<uint32_t>(geteuid())) {
        offsets = {};
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
    return KModErr::OK;
}

KModErr install_readonly_parser_hook(uint64_t target_kaddr,
                                     const TaskIdentityOffsets& task_offsets,
                                     const ReplacementConfig& config,
                                     CounterHookSession& session) {
    session = {};
    session.target_kaddr = target_kaddr;
    if (config.config_generation == 0 || config.seed_generation == 0 ||
        config.virtual_id_length == 0 || config.virtual_id_length > 64 ||
        !validate_runtime_targets(config)) {
        return KModErr::ERR_MODULE_PARAM;
    }

    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(
        static_cast<uint32_t>(sizeof(KernelCounterContext)),
        session.context_kaddr));

    KernelCounterContext initial{};
    initial.magic = kCounterContextMagic;
    initial.abi_version = kCounterContextAbi;
    initial.config_generation = config.config_generation;
    initial.seed_generation = config.seed_generation;
    initial.profile_fingerprint = config.profile_fingerprint;
    initial.replacement_mode = static_cast<uint32_t>(config.mode);
    initial.rule_mode = config.rule_mode;
    initial.target_count = config.target_count;
    initial.virtual_id_length = config.virtual_id_length;
    std::copy(config.target_euids.begin(),
              config.target_euids.end(),
              initial.target_euids);
    std::memcpy(initial.virtual_id,
                config.virtual_id.data(),
                config.virtual_id_length);
    initial.active_config_slot = 0;
    initial.active_config_reserved = 0;
    initial.runtime_config_switches = 0;
    initial.runtime_config_rejections = 0;
    RuntimeConfigSlot runtime_slot{};
    runtime_slot.config_generation = config.config_generation;
    runtime_slot.seed_generation = config.seed_generation;
    runtime_slot.profile_fingerprint = config.profile_fingerprint;
    runtime_slot.replacement_mode = static_cast<uint32_t>(config.mode);
    runtime_slot.rule_mode = config.rule_mode;
    runtime_slot.target_count = config.target_count;
    runtime_slot.virtual_id_length = config.virtual_id_length;
    std::copy(config.target_euids.begin(),
              config.target_euids.end(),
              runtime_slot.target_euids);
    std::memcpy(runtime_slot.virtual_id,
                config.virtual_id.data(),
                config.virtual_id_length);
    initial.config_slots[0] = runtime_slot;
    initial.config_slots[1] = runtime_slot;
    KModErr err = kernel_module::write_kernel_mem(
        session.context_kaddr,
        &initial,
        static_cast<uint32_t>(sizeof(initial)),
        kernel_module::KernMemProt::KMP_RW);
    if (is_failed(err)) {
        kernel_module::free_kernel_mem(session.context_kaddr);
        session = {};
        return err;
    }

    std::vector<uint8_t> handler;
    err = build_readonly_parser_handler(
        session.context_kaddr, task_offsets, handler);
    if (is_failed(err)) {
        kernel_module::free_kernel_mem(session.context_kaddr);
        session = {};
        return err;
    }

    err = kernel_module::install_kernel_function_before_hook(
        target_kaddr, handler, &session.hook);
    if (is_failed(err)) {
        kernel_module::free_kernel_mem(session.context_kaddr);
        session = {};
        return err;
    }
    return KModErr::OK;
}

namespace {

KModErr flip_runtime_config_slot(uint64_t context_kaddr,
                                  uint32_t slot) {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    Assembler* a = asm_ctx.assembler();
    if (a == nullptr || slot > 1) {
        return KModErr::ERR_MODULE_ASM;
    }
    kernel_module::arm64_module_asm_func_start(a);
    aarch64_asm_mov_x(
        a,
        x9,
        context_kaddr + offsetof(KernelCounterContext, active_config_slot));
    aarch64_asm_mov_w(a, w10, slot);
    // Release-publish the slot after the EL0 writer has filled every byte.
    a->stlr(w10, ptr(x9));
    aarch64_asm_mov_w(a, w0, 0);
    kernel_module::arm64_module_asm_func_end(a, x0);
    if (asm_ctx.has_error()) {
        return KModErr::ERR_MODULE_ASM;
    }
    uint64_t result = UINT64_MAX;
    RETURN_IF_ERROR(kernel_module::execute_kernel_asm_func(
        aarch64_asm_to_bytes(a), result));
    return static_cast<uint32_t>(result) == 0
               ? KModErr::OK
               : KModErr::ERR_MODULE_WRITE_FILE;
}

} // namespace

KModErr publish_runtime_config(const CounterHookSession& session,
                               const ReplacementConfig& config,
                               uint32_t& published_slot) {
    published_slot = 0;
    if (session.context_kaddr == 0 || config.config_generation == 0 ||
        config.seed_generation == 0 || config.virtual_id_length == 0 ||
        config.virtual_id_length > 64 || !validate_runtime_targets(config)) {
        return KModErr::ERR_MODULE_PARAM;
    }

    KernelCounterContext snapshot{};
    RETURN_IF_ERROR(read_counter_snapshot(session, snapshot));
    const uint32_t active = snapshot.active_config_slot & 1U;
    const uint32_t inactive = active ^ 1U;
    if (config.config_generation <=
        snapshot.config_slots[active].config_generation) {
        return KModErr::ERR_MODULE_PARAM;
    }

    RuntimeConfigSlot next{};
    next.config_generation = config.config_generation;
    next.seed_generation = config.seed_generation;
    next.profile_fingerprint = config.profile_fingerprint;
    next.replacement_mode = static_cast<uint32_t>(config.mode);
    next.rule_mode = config.rule_mode;
    next.target_count = config.target_count;
    next.virtual_id_length = config.virtual_id_length;
    std::copy(config.target_euids.begin(),
              config.target_euids.end(),
              next.target_euids);
    std::memcpy(next.virtual_id,
                config.virtual_id.data(),
                config.virtual_id_length);

    const uint64_t slot_kaddr =
        session.context_kaddr + offsetof(KernelCounterContext, config_slots) +
        static_cast<uint64_t>(inactive) * sizeof(RuntimeConfigSlot);
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(
        slot_kaddr,
        &next,
        static_cast<uint32_t>(sizeof(next)),
        kernel_module::KernMemProt::KMP_RW));

    // Keep the legacy diagnostic fields coherent for existing log readers.
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(
        session.context_kaddr + offsetof(KernelCounterContext,
                                          config_generation),
        &next,
        static_cast<uint32_t>(sizeof(next)),
        kernel_module::KernMemProt::KMP_RW));
    const uint64_t switches = snapshot.runtime_config_switches + 1;
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(
        session.context_kaddr +
            offsetof(KernelCounterContext, runtime_config_switches),
        &switches,
        static_cast<uint32_t>(sizeof(switches)),
        kernel_module::KernMemProt::KMP_RW));
    RETURN_IF_ERROR(flip_runtime_config_slot(session.context_kaddr, inactive));
    published_slot = inactive;
    return KModErr::OK;
}

KModErr read_counter_snapshot(const CounterHookSession& session,
                              KernelCounterContext& snapshot) {
    if (session.context_kaddr == 0) {
        return KModErr::ERR_MODULE_PARAM;
    }
    snapshot = {};
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(
        session.context_kaddr,
        &snapshot,
        static_cast<uint32_t>(sizeof(snapshot))));
    if (snapshot.magic != kCounterContextMagic ||
        snapshot.abi_version != kCounterContextAbi) {
        return KModErr::ERR_MODULE_PARAM;
    }
    return KModErr::OK;
}

KModErr remove_readonly_parser_hook(CounterHookSession& session) {
    if (session.hook != nullptr) {
        const KModErr err = kernel_module::uninstall_kernel_hook(session.hook);
        if (is_failed(err)) {
            return err;
        }
        session.hook = nullptr;
    }
    if (session.context_kaddr != 0) {
        KernelCounterContext snapshot{};
        const KModErr read_err = read_counter_snapshot(session, snapshot);
        if (is_failed(read_err)) {
            return read_err;
        }
        session.active_at_remove = snapshot.active_calls;
        // The run-once probe deliberately keeps this private context until a
        // full reboot. Even a zero snapshot is not a formal grace period: a
        // CPU could have entered the generated handler immediately before the
        // first active_calls increment when uninstall returned.
    }
    session.target_kaddr = 0;
    return KModErr::OK;
}

} // namespace drmid
