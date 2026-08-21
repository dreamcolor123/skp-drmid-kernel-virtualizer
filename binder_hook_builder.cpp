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
constexpr uint32_t kGetPropertyByteArrayTransactionCode = 11;
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
constexpr uint32_t kBinderFileScratchOffset = 408;
constexpr uint32_t kParcelTokenHeaderExtraScratchOffset = 428;
constexpr uint32_t kRuntimeConfigPointerScratchOffset = 432;
constexpr uint32_t kHalIdentityGenerationScratchOffset = 440;
constexpr uint32_t kParserScratchBytes = 448;

static_assert((kTransactionEventCapacity &
               (kTransactionEventCapacity - 1)) == 0);
static_assert((kPendingBucketCount & (kPendingBucketCount - 1)) == 0);
constexpr uint32_t kMapLockTryCount = 8;

// Stack-local layout used by the generated handler. All fields are 64-bit;
// kLocalHeader is a 48-byte binder_write_read scratch buffer.
constexpr int32_t kLocalFile = 0;
constexpr int32_t kLocalCmd = 8;
constexpr int32_t kLocalArg = 16;
constexpr int32_t kLocalReturn = 24;
constexpr int32_t kLocalWriteSize = 32;
constexpr int32_t kLocalWriteConsumed = 40;
constexpr int32_t kLocalWriteBuffer = 48;
constexpr int32_t kLocalReadSize = 56;
constexpr int32_t kLocalReadBuffer = 64;
constexpr int32_t kLocalPreHeaderValid = 72;
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

bool validate_runtime_config(const ReplacementConfig& config) {
    return config.config_generation != 0 && config.seed_generation != 0 &&
           config.profile_fingerprint != 0 &&
           static_cast<uint32_t>(config.mode) <=
               static_cast<uint32_t>(ReplacementMode::kWriteTest) &&
           config.virtual_id_length == kWidevineDeviceUniqueIdBytes;
}

bool validate_hal_identities(const HalIdentityConfig& identities) {
    if (identities.generation == 0 ||
        identities.count > kHalIdentityLimit) {
        return false;
    }
    for (size_t index = 0; index < kHalIdentityLimit; ++index) {
        const uint32_t value = identities.tgids[index];
        if (index < identities.count) {
            if (value == 0 ||
                (index != 0 && identities.tgids[index - 1] >= value)) {
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

// Only the installer self-test and the internally discovered Widevine HAL
// enter the parser. Every other Binder caller bypasses before counters, stack
// allocation, user copies and command-stream parsing.
void emit_hal_identity_gate(
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

    aarch64_asm_mov_x(
        a,
        x12,
        context_kaddr +
            offsetof(KernelCounterContext, active_hal_identity_slot));
    a->ldar(w13, ptr(x12));
    a->and_(w13, w13, 1);
    aarch64_asm_mov_x(a, x14, sizeof(HalIdentitySet));
    a->mul(x13, x13, x14);
    aarch64_asm_mov_x(
        a,
        x14,
        context_kaddr + offsetof(KernelCounterContext, hal_identity_slots));
    a->add(x13, x14, x13);
    a->ldr(w15, ptr(x13, offsetof(HalIdentitySet, count)));
    a->cmp(w15, static_cast<uint32_t>(kHalIdentityLimit));
    a->b(CondCode::kHI, bypass);
    a->add(x16, x13, offsetof(HalIdentitySet, tgids));
    for (uint32_t index = 0; index < kHalIdentityLimit; ++index) {
        a->cmp(w15, index + 1);
        a->b(CondCode::kLO, bypass);
        a->ldr(w17, ptr(x16, index * sizeof(uint32_t)));
        a->cmp(w10, w17);
        a->b(CondCode::kEQ, tracked);
    }
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

void emit_capture_active_hal_generation(Assembler* a,
                                        uint64_t context_kaddr) {
    aarch64_asm_mov_x(
        a,
        x9,
        context_kaddr +
            offsetof(KernelCounterContext, active_hal_identity_slot));
    a->ldar(w10, ptr(x9));
    a->and_(w10, w10, 1);
    aarch64_asm_mov_x(a, x11, sizeof(HalIdentitySet));
    a->mul(x10, x10, x11);
    aarch64_asm_mov_x(
        a,
        x11,
        context_kaddr + offsetof(KernelCounterContext, hal_identity_slots));
    a->add(x10, x11, x10);
    a->ldr(x11, ptr(x10, offsetof(HalIdentitySet, generation)));
    a->str(x11, ptr(x23, kHalIdentityGenerationScratchOffset));
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
    emit_capture_active_hal_generation(a, context_kaddr);
    a->ldr(x16, ptr(x23, kHalIdentityGenerationScratchOffset));
    a->str(x16,
           ptr(x14, offsetof(BinderPendingFrame, hal_identity_generation)));
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
    const Label generation_ready = a->newLabel();
    emit_capture_active_hal_generation(a, context_kaddr);
    a->ldr(x9, ptr(x23, kHalIdentityGenerationScratchOffset));
    a->ldr(x10,
           ptr(x14, offsetof(BinderPendingFrame, hal_identity_generation)));
    a->cmp(x9, x10);
    a->b(CondCode::kEQ, generation_ready);
    a->mov(x21, xzr);
    a->mov(x17, xzr);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, pending_generation_stale));
    a->bind(generation_ready);
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

        if (token_kind == ParcelTokenKind::kDrmPlugin) {
            constexpr std::string_view kDeviceUniqueId = "deviceUniqueId";
            a->ldr(w11, ptr(x23, kTransactionScratchOffset + 16));
            a->cmp(w11, kGetPropertyByteArrayTransactionCode);
            a->b(CondCode::kNE, next);
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

void emit_reset_transaction_parse_scratch(Assembler* a) {
    a->str(wzr, ptr(x23, kParcelTokenKindScratchOffset));
    a->str(wzr, ptr(x23, kParcelTokenOffsetScratchOffset));
    a->str(wzr, ptr(x23, kParcelPrefixSizeScratchOffset));
    a->str(wzr, ptr(x23, kParcelFlagsScratchOffset));
    a->str(wzr, ptr(x23, kCorrelatedRequestFlagsScratchOffset));
    a->str(wzr, ptr(x23, kReplyPrefixSizeScratchOffset));
    a->str(wzr, ptr(x23, kReplyStatusScratchOffset));
    a->str(wzr, ptr(x23, kReplyArrayLengthScratchOffset));
    a->str(wzr, ptr(x23, kReplyArrayOffsetScratchOffset));
    a->str(wzr, ptr(x23, kReplyFlagsScratchOffset));
    a->str(wzr, ptr(x23, kParcelTokenHeaderExtraScratchOffset));
}

// Bounded, read-only Parcel prefix capture for request commands. Results are
// kept in parser scratch and copied into the transaction event later.
void emit_capture_parcel_prefix(Assembler* a,
                                uint64_t context_kaddr,
                                uint32_t expected_ioc_type,
                                KModErr& copy_helper_err) {
    constexpr std::string_view kDrmPlugin =
        "android.hardware.drm.IDrmPlugin";

    const Label request = a->newLabel();
    const Label copy_fault = a->newLabel();
    const Label scan = a->newLabel();
    const Label matched = a->newLabel();
    const Label done = a->newLabel();

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

// Parse only a HAL BC_REPLY correlated to a deviceUniqueId request. The first
// copy reads the 8-byte successful AIDL status/byte-array header. A second
// bounded copy proves that the reported content range is readable; bytes stay
// in transient handler stack scratch and are never placed in the event ring.
void emit_parse_hal_correlated_reply(Assembler* a,
                                     uint64_t context_kaddr,
                                     KModErr& copy_helper_err) {
    const Label no_pending = a->newLabel();
    const Label header_fault = a->newLabel();
    const Label status_nonzero = a->newLabel();
    const Label array_invalid = a->newLabel();
    const Label content_fault = a->newLabel();
    const Label length_mismatch = a->newLabel();
    const Label dry_run = a->newLabel();
    const Label write_fault = a->newLabel();
    const Label done = a->newLabel();

    a->str(w17, ptr(x23, kCorrelatedRequestFlagsScratchOffset));
    a->str(wzr, ptr(x23, kReplyPrefixSizeScratchOffset));
    a->str(wzr, ptr(x23, kReplyStatusScratchOffset));
    a->str(wzr, ptr(x23, kReplyArrayLengthScratchOffset));
    a->str(wzr, ptr(x23, kReplyArrayOffsetScratchOffset));
    a->str(wzr, ptr(x23, kReplyFlagsScratchOffset));
    a->cbz(x21, no_pending);
    a->tbz(x17, 0, done);
    emit_capture_active_runtime_config(a, context_kaddr);

    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, reply_candidates));
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, correlated_reply_candidates));
    aarch64_asm_mov_w(
        a,
        w11,
        kReplyFlagCorrelatedDeviceUniqueId | kReplyFlagHalCorrelated);
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
    aarch64_asm_mov_w(a, w11, 8);
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
    a->cmp(w12, kWidevineDeviceUniqueIdBytes);
    a->b(CondCode::kNE, array_invalid);
    a->add(x14, x12, 8);
    a->cmp(x14, x16);
    a->b(CondCode::kHI, array_invalid);
    aarch64_asm_mov_w(a, w11, 8);
    a->str(w11, ptr(x23, kReplyArrayOffsetScratchOffset));
    a->ldr(w11, ptr(x23, kReplyFlagsScratchOffset));
    a->orr(w11, w11, kReplyFlagStatusOk | kReplyFlagArrayValid);
    a->str(w11, ptr(x23, kReplyFlagsScratchOffset));
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, reply_array_valid));

    a->add(x13, x23, kParcelPrefixScratchOffset + 16);
    a->add(x15, x15, 8);
    kernel_module::export_symbol::copy_from_user(
        a, copy_helper_err, x13, x15, kWidevineDeviceUniqueIdBytes);
    a->cbnz(x0, content_fault);
    aarch64_asm_mov_w(a, w14, 8 + kWidevineDeviceUniqueIdBytes);
    a->str(w14, ptr(x23, kReplyPrefixSizeScratchOffset));
    a->ldr(w11, ptr(x23, kReplyFlagsScratchOffset));
    a->orr(w11, w11, kReplyFlagContentReadable |
                         kReplyFlagReplacementCandidate);
    a->str(w11, ptr(x23, kReplyFlagsScratchOffset));
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, reply_content_copy_ok));
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, replacement_candidates));

    a->ldr(x9, ptr(x23, kRuntimeConfigPointerScratchOffset));
    a->ldr(w12, ptr(x9, offsetof(RuntimeConfigSlot, virtual_id_length)));
    a->cmp(w12, kWidevineDeviceUniqueIdBytes);
    a->b(CondCode::kNE, length_mismatch);
    a->ldr(w11, ptr(x9, offsetof(RuntimeConfigSlot, replacement_mode)));
    a->cbz(w11, dry_run);

    a->ldr(x15, ptr(x23, kTransactionScratchOffset + 48));
    a->add(x15, x15, 8);
    a->add(x13, x9, offsetof(RuntimeConfigSlot, virtual_id));
    kernel_module::export_symbol::copy_to_user(
        a, copy_helper_err, x15, x13, kWidevineDeviceUniqueIdBytes);
    a->cbnz(x0, write_fault);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, replacement_write_ok));
    a->ldr(w11, ptr(x23, kReplyFlagsScratchOffset));
    a->orr(w11, w11, kReplyFlagReplaced);
    a->str(w11, ptr(x23, kReplyFlagsScratchOffset));
    emit_replacement_success_telemetry(a, context_kaddr);
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

    a->bind(length_mismatch);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, replacement_length_mismatch));
    a->b(done);
    a->bind(write_fault);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, replacement_copy_to_user_faults));
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, replacement_write_faults));
    a->b(done);
    a->bind(no_pending);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, reply_without_pending));
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
                             KModErr& copy_helper_err) {
    const Label correlation_ready = a->newLabel();
    const Label publish = a->newLabel();

    emit_reset_transaction_parse_scratch(a);
    // Request recognition is required only for BR_TRANSACTION delivered to
    // the HAL. BC_REPLY correlation uses the Pending flags and parses the
    // reply body directly, so it avoids an extra prefix copy and token scan.
    if (expected_ioc_type == static_cast<uint32_t>('r')) {
        emit_capture_parcel_prefix(
            a, context_kaddr, expected_ioc_type, copy_helper_err);
    }

    kernel_module::export_symbol::get_current(a, x27);
    a->mov(x21, xzr); // correlated request event id
    a->mov(x17, xzr); // correlated request Parcel flags

    if (expected_ioc_type == static_cast<uint32_t>('c')) {
        const Label is_reply = a->newLabel();
        aarch64_asm_mov_x(a, x12, static_cast<uint32_t>(BC_REPLY));
        a->cmp(w24, w12);
        a->b(CondCode::kEQ, is_reply);
        aarch64_asm_mov_x(a, x12, static_cast<uint32_t>(BC_REPLY_SG));
        a->cmp(w24, w12);
        a->b(CondCode::kNE, correlation_ready);
        a->bind(is_reply);
        emit_pending_pop(a, context_kaddr, false);
        emit_parse_hal_correlated_reply(a, context_kaddr, copy_helper_err);
    }
    a->bind(correlation_ready);

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
    a->str(wzr, ptr(x28, offsetof(BinderTransactionEvent, reserved0)));
    a->str(wzr, ptr(x28, offsetof(BinderTransactionEvent, reserved1)));

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
        a->ldr(w11, ptr(x23, kParcelFlagsScratchOffset));
        const Label secctx_not_device_id = a->newLabel();
        a->tbz(x11, 0, secctx_not_device_id);
        emit_counter_increment(
            a,
            context_kaddr,
            offsetof(KernelCounterContext, server_request_hits));
        emit_pending_push(a, context_kaddr, task_offsets);
        a->bind(secctx_not_device_id);
        a->b(publish);
        a->bind(normal_transaction);
        aarch64_asm_mov_x(
            a, x12, static_cast<uint32_t>(BinderEventKind::kBrTransaction));
        a->str(w12, ptr(x28, offsetof(BinderTransactionEvent, kind)));
        a->ldr(w11, ptr(x23, kParcelFlagsScratchOffset));
        const Label transaction_not_device_id = a->newLabel();
        a->tbz(x11, 0, transaction_not_device_id);
        emit_counter_increment(
            a,
            context_kaddr,
            offsetof(KernelCounterContext, server_request_hits));
        emit_pending_push(a, context_kaddr, task_offsets);
        a->bind(transaction_not_device_id);
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
        copy_helper_err);
    a->b(command_processed);

    a->bind(metadata_fault);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, transaction_metadata_faults));
    a->b(command_processed);

    a->bind(not_transaction);

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
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    Assembler* a = asm_ctx.assembler();
    if (a == nullptr) {
        return KModErr::ERR_MODULE_ASM;
    }

    kernel_module::arm64_before_hook_start(a);

    const Label tracked = a->newLabel();
    const Label bypass = a->newLabel();
    const Label finish = a->newLabel();
    emit_hal_identity_gate(
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
        a, context_kaddr, offsetof(KernelCounterContext, hal_gate_hits));
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
    a->ldr(x9, ptr(sp, kLocalHeader + 8));
    a->str(x9, ptr(sp, kLocalWriteConsumed));
    a->ldr(x9, ptr(sp, kLocalHeader + 16));
    a->str(x9, ptr(sp, kLocalWriteBuffer));
    a->ldr(x9, ptr(sp, kLocalHeader + 24));
    a->str(x9, ptr(sp, kLocalReadSize));
    a->ldr(x9, ptr(sp, kLocalHeader + 40));
    a->str(x9, ptr(sp, kLocalReadBuffer));
    // HAL replies live in the unconsumed BC stream. Parse and, in Write mode,
    // replace the correlated BC_REPLY before the Binder driver copies it.
    a->ldr(x14, ptr(sp, kLocalWriteConsumed));
    a->ldr(x15, ptr(sp, kLocalWriteSize));
    a->cmp(x14, x15);
    a->b(CondCode::kHI, pre_header_fault);
    a->ldr(x13, ptr(sp, kLocalWriteBuffer));
    a->add(x13, x13, x14);
    a->sub(x15, x15, x14);
    a->ldr(x12, ptr(sp, kLocalFile));
    emit_parse_command_stream(
        a,
        context_kaddr,
        task_offsets,
        x12,
        x13,
        x15,
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
    a->ldr(x10, ptr(sp, kLocalWriteConsumed));
    a->cmp(x14, x10);
    a->b(CondCode::kLO, post_header_invalid);
    a->ldr(x16, ptr(sp, kLocalHeader + 32));
    a->ldr(x17, ptr(sp, kLocalReadSize));
    a->cmp(x16, x17);
    a->b(CondCode::kHI, post_header_invalid);

    // The post path only consumes BR commands returned by the driver. The BC
    // stream was parsed before the original ioctl so replacement was timely.
    a->ldr(x13, ptr(sp, kLocalReadBuffer));
    a->ldr(x12, ptr(sp, kLocalFile));
    // Reload consumed: x16 is caller-saved and the first parser calls a helper.
    a->ldr(x16, ptr(sp, kLocalHeader + 32));
    emit_parse_command_stream(
        a,
        context_kaddr,
        task_offsets,
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

    return KModErr::OK;
}

KModErr install_readonly_parser_hook(uint64_t target_kaddr,
                                     const TaskIdentityOffsets& task_offsets,
                                     const ReplacementConfig& config,
                                     const HalIdentityConfig& identities,
                                     CounterHookSession& session) {
    session = {};
    session.target_kaddr = target_kaddr;
    if (!validate_runtime_config(config) ||
        !validate_hal_identities(identities)) {
        return KModErr::ERR_MODULE_PARAM;
    }

    RETURN_IF_ERROR(kernel_module::alloc_kernel_mem(
        static_cast<uint32_t>(sizeof(KernelCounterContext)),
        session.context_kaddr));

    KernelCounterContext initial{};
    initial.magic = kCounterContextMagic;
    initial.abi_version = kCounterContextAbi;
    initial.active_config_slot = 0;
    initial.active_config_reserved = 0;
    initial.runtime_config_switches = 0;
    initial.runtime_config_rejections = 0;
    RuntimeConfigSlot runtime_slot{};
    runtime_slot.config_generation = config.config_generation;
    runtime_slot.seed_generation = config.seed_generation;
    runtime_slot.profile_fingerprint = config.profile_fingerprint;
    runtime_slot.replacement_mode = static_cast<uint32_t>(config.mode);
    runtime_slot.virtual_id_length = config.virtual_id_length;
    std::memcpy(runtime_slot.virtual_id,
                config.virtual_id.data(),
                config.virtual_id_length);
    initial.config_slots[0] = runtime_slot;
    initial.config_slots[1] = runtime_slot;
    initial.active_hal_identity_slot = 0;
    HalIdentitySet hal_set{};
    hal_set.generation = identities.generation;
    hal_set.count = identities.count;
    std::copy(identities.tgids.begin(),
              identities.tgids.end(),
              hal_set.tgids);
    initial.hal_identity_slots[0] = hal_set;
    initial.hal_identity_slots[1] = hal_set;
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

KModErr flip_slot_index(uint64_t context_kaddr,
                        size_t active_slot_offset,
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
        context_kaddr + active_slot_offset);
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
    if (session.context_kaddr == 0 || !validate_runtime_config(config)) {
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
    next.virtual_id_length = config.virtual_id_length;
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

    const uint64_t switches = snapshot.runtime_config_switches + 1;
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(
        session.context_kaddr +
            offsetof(KernelCounterContext, runtime_config_switches),
        &switches,
        static_cast<uint32_t>(sizeof(switches)),
        kernel_module::KernMemProt::KMP_RW));
    RETURN_IF_ERROR(flip_slot_index(
        session.context_kaddr,
        offsetof(KernelCounterContext, active_config_slot),
        inactive));
    published_slot = inactive;
    return KModErr::OK;
}

KModErr publish_hal_identities(const CounterHookSession& session,
                               const HalIdentityConfig& identities,
                               uint32_t& published_slot) {
    published_slot = 0;
    if (session.context_kaddr == 0 ||
        !validate_hal_identities(identities)) {
        return KModErr::ERR_MODULE_PARAM;
    }
    KernelCounterContext snapshot{};
    RETURN_IF_ERROR(read_counter_snapshot(session, snapshot));
    const uint32_t active = snapshot.active_hal_identity_slot & 1U;
    const uint32_t inactive = active ^ 1U;
    if (identities.generation <=
        snapshot.hal_identity_slots[active].generation) {
        return KModErr::ERR_MODULE_PARAM;
    }

    HalIdentitySet next{};
    next.generation = identities.generation;
    next.count = identities.count;
    std::copy(identities.tgids.begin(),
              identities.tgids.end(),
              next.tgids);
    const uint64_t slot_kaddr =
        session.context_kaddr +
        offsetof(KernelCounterContext, hal_identity_slots) +
        static_cast<uint64_t>(inactive) * sizeof(HalIdentitySet);
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(
        slot_kaddr,
        &next,
        static_cast<uint32_t>(sizeof(next)),
        kernel_module::KernMemProt::KMP_RW));
    const uint64_t switches = snapshot.hal_identity_switches + 1;
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(
        session.context_kaddr +
            offsetof(KernelCounterContext, hal_identity_switches),
        &switches,
        static_cast<uint32_t>(sizeof(switches)),
        kernel_module::KernMemProt::KMP_RW));
    RETURN_IF_ERROR(flip_slot_index(
        session.context_kaddr,
        offsetof(KernelCounterContext, active_hal_identity_slot),
        inactive));
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
