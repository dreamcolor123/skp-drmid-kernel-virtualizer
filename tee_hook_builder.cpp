#include "tee_hook_builder.h"

#include <cstddef>
#include <cstring>
#include <initializer_list>
#include <vector>

#include "kernel_module_kit_umbrella.h"

using namespace asmjit;
using namespace asmjit::a64;

namespace drmid {
namespace {

constexpr uint32_t kSiArgBytes = 24;
constexpr uint32_t kSiArgTypeOffset = 0;
constexpr uint32_t kSiArgFlagsOffset = 4;
constexpr uint32_t kSiArgPointerOffset = 8;
constexpr uint32_t kSiArgSizeOffset = 16;
constexpr uint32_t kSiArgInputBuffer = 1;
constexpr uint32_t kSiArgOutputBuffer = 2;
constexpr uint32_t kSiArgOutputObject = 4;
constexpr uint32_t kSiArgUserAddress = 1;
constexpr uint32_t kWidevineGetDeviceIdOperation = 9;
constexpr uint32_t kFallbackStateMask = 7;

constexpr int32_t kLocalInvokeContext = 0;
constexpr int32_t kLocalObject = 8;
constexpr int32_t kLocalOperation = 16;
constexpr int32_t kLocalArgs = 24;
constexpr int32_t kLocalResultPointer = 32;
constexpr int32_t kLocalReturn = 40;
constexpr int32_t kLocalRuntimeConfig = 48;
constexpr int32_t kLocalEdgeScratch = 64;
constexpr int32_t kLocalBytes = 144;

static_assert((kLocalBytes & 15) == 0);
static_assert(sizeof(TeeFirmwareIdentitySlot) == 88);

bool valid_firmware(const TeeFirmwareIdentity& firmware) {
    return firmware.generation != 0 && firmware.file_size >= 64 &&
           firmware.file_size <= 16U * 1024U * 1024U &&
           firmware.edge_bytes == kTeeFirmwareEdgeBytes;
}

void emit_atomic_increment(Assembler* a, uint64_t counter_kaddr) {
    aarch64_asm_mov_x(a, x9, counter_kaddr);
    aarch64_asm_mov_x(a, x10, 1);
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
    a->str(x10, ptr(sp, kLocalRuntimeConfig));
}

void emit_exact_arg_pattern(Assembler* a,
                            std::initializer_list<uint32_t> types,
                            Label match,
                            Label mismatch) {
    a->ldr(x13, ptr(sp, kLocalArgs));
    a->cbz(x13, mismatch);
    uint32_t index = 0;
    for (const uint32_t type : types) {
        const uint32_t offset = index * kSiArgBytes;
        a->ldr(w9, ptr(x13, offset + kSiArgTypeOffset));
        a->cmp(w9, type);
        a->b(CondCode::kNE, mismatch);
        if (type == kSiArgInputBuffer || type == kSiArgOutputBuffer) {
            a->ldrb(w10, ptr(x13, offset + kSiArgFlagsOffset));
            a->cmp(w10, kSiArgUserAddress);
            a->b(CondCode::kNE, mismatch);
        }
        ++index;
    }
    a->ldr(w9, ptr(x13, index * kSiArgBytes + kSiArgTypeOffset));
    a->cbz(w9, match);
    a->b(mismatch);
}

void emit_table_contains(Assembler* a,
                         uint64_t table_kaddr,
                         size_t limit,
                         GpX object,
                         Label found,
                         Label missing) {
    for (size_t index = 0; index < limit; ++index) {
        aarch64_asm_mov_x(
            a, x9, table_kaddr + index * sizeof(uint64_t));
        a->ldar(x10, ptr(x9));
        a->cmp(x10, object);
        a->b(CondCode::kEQ, found);
    }
    a->b(missing);
}

void emit_table_add(Assembler* a,
                    uint64_t context_kaddr,
                    uint64_t table_kaddr,
                    size_t limit,
                    GpX object,
                    size_t add_counter_offset,
                    Label done) {
    const Label added = a->newLabel();
    const Label duplicate = a->newLabel();
    for (size_t index = 0; index < limit; ++index) {
        const Label next = a->newLabel();
        aarch64_asm_mov_x(
            a, x9, table_kaddr + index * sizeof(uint64_t));
        a->ldar(x10, ptr(x9));
        a->cmp(x10, object);
        a->b(CondCode::kEQ, duplicate);
        a->cbnz(x10, next);
        aarch64_asm_mov_x(a, x11, 0);
        a->mov(x12, object);
        a->casal(x11, x12, ptr(x9));
        a->cbz(x11, added);
        a->cmp(x11, object);
        a->b(CondCode::kEQ, duplicate);
        a->bind(next);
    }
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, tee_state_full));
    a->b(done);
    a->bind(added);
    emit_counter_increment(a, context_kaddr, add_counter_offset);
    a->bind(duplicate);
    a->b(done);
}

void emit_table_clear_object(Assembler* a,
                             uint64_t context_kaddr,
                             uint64_t table_kaddr,
                             size_t limit,
                             GpX object) {
    for (size_t index = 0; index < limit; ++index) {
        const Label next = a->newLabel();
        aarch64_asm_mov_x(
            a, x9, table_kaddr + index * sizeof(uint64_t));
        a->ldar(x10, ptr(x9));
        a->cmp(x10, object);
        a->b(CondCode::kNE, next);
        a->mov(x11, object);
        aarch64_asm_mov_x(a, x12, 0);
        a->casal(x11, x12, ptr(x9));
        a->cmp(x11, object);
        a->b(CondCode::kNE, next);
        emit_counter_increment(
            a,
            context_kaddr,
            offsetof(KernelCounterContext, tee_address_clears));
        a->bind(next);
    }
}

void emit_fallback_transition(Assembler* a,
                              uint64_t context_kaddr,
                              GpX object,
                              uint32_t expected_state,
                              uint32_t next_state,
                              bool restart,
                              Label done) {
    const uint64_t table_kaddr = context_kaddr +
        offsetof(KernelCounterContext, tee_fallback_states);
    for (size_t index = 0; index < kTeeFallbackStateLimit; ++index) {
        const Label next = a->newLabel();
        const Label mismatch = a->newLabel();
        const Label conflict = a->newLabel();
        aarch64_asm_mov_x(
            a, x9, table_kaddr + index * sizeof(uint64_t));
        a->ldar(x10, ptr(x9));
        a->and_(x11, x10, UINT64_C(0xfffffffffffffff8));
        a->cmp(x11, object);
        a->b(CondCode::kNE, next);
        if (!restart) {
            a->and_(w12, w10, kFallbackStateMask);
            a->cmp(w12, expected_state);
            a->b(CondCode::kNE, mismatch);
        }
        a->mov(x14, x10);
        a->add(x12, object, next_state);
        a->casal(x10, x12, ptr(x9));
        a->cmp(x10, x14);
        a->b(CondCode::kNE, conflict);
        emit_counter_increment(
            a,
            context_kaddr,
            offsetof(KernelCounterContext, tee_fallback_transitions));
        a->b(done);
        a->bind(mismatch);
        a->mov(x14, x10);
        aarch64_asm_mov_x(a, x12, 0);
        a->casal(x10, x12, ptr(x9));
        a->cmp(x10, x14);
        a->b(CondCode::kNE, conflict);
        emit_counter_increment(
            a,
            context_kaddr,
            offsetof(KernelCounterContext, tee_fallback_resets));
        a->b(done);
        a->bind(conflict);
        emit_counter_increment(
            a,
            context_kaddr,
            offsetof(KernelCounterContext, tee_fallback_cas_drops));
        a->b(done);
        a->bind(next);
    }
    if (!restart) {
        a->b(done);
        return;
    }
    for (size_t index = 0; index < kTeeFallbackStateLimit; ++index) {
        const Label next = a->newLabel();
        aarch64_asm_mov_x(
            a, x9, table_kaddr + index * sizeof(uint64_t));
        aarch64_asm_mov_x(a, x10, 0);
        a->add(x12, object, next_state);
        a->casal(x10, x12, ptr(x9));
        a->cbnz(x10, next);
        emit_counter_increment(
            a,
            context_kaddr,
            offsetof(KernelCounterContext, tee_fallback_transitions));
        a->b(done);
        a->bind(next);
    }
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, tee_state_full));
    a->b(done);
}

void emit_fallback_consume_ready(Assembler* a,
                                 uint64_t context_kaddr,
                                 GpX object,
                                 Label matched,
                                 Label missing) {
    const uint64_t table_kaddr = context_kaddr +
        offsetof(KernelCounterContext, tee_fallback_states);
    for (size_t index = 0; index < kTeeFallbackStateLimit; ++index) {
        const Label next = a->newLabel();
        const Label state_invalid = a->newLabel();
        const Label conflict = a->newLabel();
        aarch64_asm_mov_x(
            a, x9, table_kaddr + index * sizeof(uint64_t));
        a->ldar(x10, ptr(x9));
        a->and_(x11, x10, UINT64_C(0xfffffffffffffff8));
        a->cmp(x11, object);
        a->b(CondCode::kNE, next);
        a->and_(w12, w10, kFallbackStateMask);
        a->cmp(w12, 4);
        a->b(CondCode::kNE, state_invalid);
        a->mov(x14, x10);
        aarch64_asm_mov_x(a, x12, 0);
        a->casal(x10, x12, ptr(x9));
        a->cmp(x10, x14);
        a->b(CondCode::kNE, conflict);
        emit_counter_increment(
            a,
            context_kaddr,
            offsetof(KernelCounterContext, tee_fallback_matches));
        a->b(matched);
        a->bind(state_invalid);
        a->mov(x14, x10);
        aarch64_asm_mov_x(a, x12, 0);
        a->casal(x10, x12, ptr(x9));
        a->cmp(x10, x14);
        a->b(CondCode::kNE, conflict);
        emit_counter_increment(
            a,
            context_kaddr,
            offsetof(KernelCounterContext, tee_fallback_resets));
        a->b(missing);
        a->bind(conflict);
        emit_counter_increment(
            a,
            context_kaddr,
            offsetof(KernelCounterContext, tee_fallback_cas_drops));
        a->b(missing);
        a->bind(next);
    }
    a->b(missing);
}

void emit_fallback_clear_object(Assembler* a,
                                uint64_t context_kaddr,
                                GpX object,
                                size_t counter_offset) {
    const uint64_t table_kaddr = context_kaddr +
        offsetof(KernelCounterContext, tee_fallback_states);
    for (size_t index = 0; index < kTeeFallbackStateLimit; ++index) {
        const Label next = a->newLabel();
        aarch64_asm_mov_x(
            a, x9, table_kaddr + index * sizeof(uint64_t));
        a->ldar(x10, ptr(x9));
        a->and_(x11, x10, UINT64_C(0xfffffffffffffff8));
        a->cmp(x11, object);
        a->b(CondCode::kNE, next);
        a->mov(x14, x10);
        aarch64_asm_mov_x(a, x12, 0);
        a->casal(x10, x12, ptr(x9));
        a->cmp(x10, x14);
        a->b(CondCode::kNE, next);
        emit_counter_increment(a, context_kaddr, counter_offset);
        a->bind(next);
    }
}

void emit_loader_identity_match(Assembler* a,
                                uint64_t context_kaddr,
                                KModErr& helper_error,
                                Label matched,
                                Label failed) {
    const uint64_t identity_kaddr = context_kaddr +
        offsetof(KernelCounterContext, tee_firmware_identity);
    aarch64_asm_mov_x(a, x9, identity_kaddr);
    a->ldr(x10, ptr(x9, offsetof(TeeFirmwareIdentitySlot, generation)));
    a->cbz(x10, failed);
    a->ldr(w10, ptr(x9, offsetof(TeeFirmwareIdentitySlot, edge_bytes)));
    a->cmp(w10, kTeeFirmwareEdgeBytes);
    a->b(CondCode::kNE, failed);

    a->ldr(x13, ptr(sp, kLocalArgs));
    a->ldr(x10, ptr(x13, kSiArgSizeOffset));
    a->ldr(x11, ptr(x9, offsetof(TeeFirmwareIdentitySlot, file_size)));
    a->cmp(x10, x11);
    a->b(CondCode::kNE, failed);
    a->ldr(x12, ptr(x13, kSiArgPointerOffset));
    a->cbz(x12, failed);

    a->add(x9, sp, kLocalEdgeScratch);
    kernel_module::export_symbol::copy_from_user(
        a, helper_error, x9, x12, kTeeFirmwareEdgeBytes);
    if (is_failed(helper_error)) return;
    const Label copy_fault = a->newLabel();
    a->cbnz(x0, copy_fault);

    a->ldr(x13, ptr(sp, kLocalArgs));
    a->ldr(x12, ptr(x13, kSiArgPointerOffset));
    a->ldr(x10, ptr(x13, kSiArgSizeOffset));
    a->add(x12, x12, x10);
    a->sub(x12, x12, kTeeFirmwareEdgeBytes);
    a->add(x9, sp, kLocalEdgeScratch + kTeeFirmwareEdgeBytes);
    kernel_module::export_symbol::copy_from_user(
        a, helper_error, x9, x12, kTeeFirmwareEdgeBytes);
    if (is_failed(helper_error)) return;
    a->cbnz(x0, copy_fault);

    for (uint32_t offset = 0; offset < kTeeFirmwareEdgeBytes; offset += 8) {
        a->ldr(x10, ptr(sp, kLocalEdgeScratch + offset));
        aarch64_asm_mov_x(
            a,
            x9,
            identity_kaddr + offsetof(TeeFirmwareIdentitySlot, prefix) +
                offset);
        a->ldr(x11, ptr(x9));
        a->cmp(x10, x11);
        a->b(CondCode::kNE, failed);
        a->ldr(
            x10,
            ptr(sp,
                kLocalEdgeScratch + kTeeFirmwareEdgeBytes + offset));
        aarch64_asm_mov_x(
            a,
            x9,
            identity_kaddr + offsetof(TeeFirmwareIdentitySlot, suffix) +
                offset);
        a->ldr(x11, ptr(x9));
        a->cmp(x10, x11);
        a->b(CondCode::kNE, failed);
    }
    a->b(matched);
    a->bind(copy_fault);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, tee_loader_identity_faults));
    a->b(failed);
}

KModErr build_global_invoke_handler(uint64_t context_kaddr,
                                    std::vector<uint8_t>& handler) {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    Assembler* a = asm_ctx.assembler();
    if (a == nullptr) return KModErr::ERR_MODULE_ASM;

    kernel_module::arm64_before_hook_start(a);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, tee_active_calls));
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, tee_invoke_calls));
    a->sub(sp, sp, kLocalBytes);
    a->str(x0, ptr(sp, kLocalInvokeContext));
    a->str(x1, ptr(sp, kLocalObject));
    a->str(x2, ptr(sp, kLocalOperation));
    a->str(x3, ptr(sp, kLocalArgs));
    a->str(x4, ptr(sp, kLocalResultPointer));
    kernel_module::arm64_emit_call_original(a);
    a->str(x0, ptr(sp, kLocalReturn));

    const Label done = a->newLabel();
    const Label result_rejected = a->newLabel();
    aarch64_asm_mov_x(
        a,
        x9,
        context_kaddr + offsetof(KernelCounterContext, tee_backend_state));
    a->ldar(w10, ptr(x9));
    a->cmp(w10, 1);
    a->b(CondCode::kNE, done);
    a->ldr(x9, ptr(sp, kLocalReturn));
    a->cbnz(x9, result_rejected);
    a->ldr(x10, ptr(sp, kLocalResultPointer));
    a->cbz(x10, result_rejected);
    a->ldr(w9, ptr(x10));
    a->cbnz(w9, result_rejected);

    a->ldr(x15, ptr(sp, kLocalObject));
    a->cmp(x15, 2);
    a->b(CondCode::kLO, done);
    a->tst(x15, kFallbackStateMask);
    a->b(CondCode::kNE, done);
    a->ldr(w16, ptr(sp, kLocalOperation));

    // Global op9: the caller identity is deliberately absent. Only a TA
    // object established by the loader/controller chain or the cached-loader
    // fallback sequence can reach replacement.
    const Label op9_pattern = a->newLabel();
    const Label not_op9 = a->newLabel();
    a->cmp(w16, kWidevineGetDeviceIdOperation);
    a->b(CondCode::kNE, not_op9);
    emit_exact_arg_pattern(
        a, {kSiArgOutputBuffer}, op9_pattern, done);
    a->bind(op9_pattern);
    {
        const Label known_ta = a->newLabel();
        const Label fallback_ready = a->newLabel();
        const Label fallback_promoted = a->newLabel();
        const Label not_widevine = a->newLabel();
        emit_table_contains(
            a,
            context_kaddr +
                offsetof(KernelCounterContext, tee_widevine_objects),
            kTeeWidevineObjectLimit,
            x15,
            known_ta,
            fallback_ready);
        a->bind(fallback_ready);
        emit_fallback_consume_ready(
            a, context_kaddr, x15, fallback_promoted, not_widevine);
        a->bind(fallback_promoted);
        emit_table_add(
            a,
            context_kaddr,
            context_kaddr +
                offsetof(KernelCounterContext, tee_widevine_objects),
            kTeeWidevineObjectLimit,
            x15,
            offsetof(KernelCounterContext, tee_ta_adds),
            known_ta);
        a->bind(not_widevine);
        emit_counter_increment(
            a,
            context_kaddr,
            offsetof(KernelCounterContext, tee_argument_rejects));
        a->b(done);
        a->bind(known_ta);
        emit_counter_increment(
            a, context_kaddr, offsetof(KernelCounterContext, tee_ta_hits));
        emit_counter_increment(
            a,
            context_kaddr,
            offsetof(KernelCounterContext, tee_op9_candidates));
        emit_capture_active_runtime_config(a, context_kaddr);
        a->ldr(x13, ptr(sp, kLocalArgs));
        a->ldr(x9, ptr(x13, kSiArgSizeOffset));
        a->cmp(x9, kWidevineDeviceUniqueIdBytes);
        a->b(CondCode::kNE, done);
        a->ldr(x10, ptr(sp, kLocalRuntimeConfig));
        a->ldr(w11, ptr(x10, offsetof(RuntimeConfigSlot, virtual_id_length)));
        a->cmp(w11, kWidevineDeviceUniqueIdBytes);
        a->b(CondCode::kNE, done);
        a->ldr(w11, ptr(x10, offsetof(RuntimeConfigSlot, replacement_mode)));
        const Label dry_run = a->newLabel();
        const Label write = a->newLabel();
        a->cbz(w11, dry_run);
        a->cmp(w11, static_cast<uint32_t>(ReplacementMode::kWriteTest));
        a->b(CondCode::kEQ, write);
        a->b(done);
        a->bind(dry_run);
        emit_counter_increment(
            a,
            context_kaddr,
            offsetof(KernelCounterContext, tee_op9_dry_run_hits));
        a->b(done);
        a->bind(write);
        a->ldr(x12, ptr(x13, kSiArgPointerOffset));
        a->cbz(x12, done);
        a->add(x11, x10, offsetof(RuntimeConfigSlot, virtual_id));
        KModErr helper_error = KModErr::OK;
        kernel_module::export_symbol::copy_to_user(
            a,
            helper_error,
            x12,
            x11,
            kWidevineDeviceUniqueIdBytes);
        if (is_failed(helper_error)) return helper_error;
        const Label write_fault = a->newLabel();
        a->cbnz(x0, write_fault);
        emit_counter_increment(
            a,
            context_kaddr,
            offsetof(KernelCounterContext, tee_op9_write_ok));
        a->b(done);
        a->bind(write_fault);
        emit_counter_increment(
            a,
            context_kaddr,
            offsetof(KernelCounterContext, tee_op9_write_faults));
        a->b(done);
    }

    a->bind(not_op9);
    // Primary classification: IAppLoader.loadFromBuffer([IB,OO]) whose input
    // matches the current Widevine MBN, followed by controller op2([OO]).
    const Label not_loader = a->newLabel();
    const Label loader_pattern = a->newLabel();
    a->cmp(w16, 0);
    a->b(CondCode::kNE, not_loader);
    emit_exact_arg_pattern(
        a,
        {kSiArgInputBuffer, kSiArgOutputObject},
        loader_pattern,
        not_loader);
    a->bind(loader_pattern);
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, tee_loader_candidates));
    {
        const Label identity_match = a->newLabel();
        KModErr helper_error = KModErr::OK;
        emit_loader_identity_match(
            a, context_kaddr, helper_error, identity_match, done);
        if (is_failed(helper_error)) return helper_error;
        a->bind(identity_match);
        emit_counter_increment(
            a,
            context_kaddr,
            offsetof(KernelCounterContext, tee_loader_identity_hits));
        a->ldr(x13, ptr(sp, kLocalArgs));
        a->ldr(x15,
               ptr(x13,
                   kSiArgBytes + kSiArgPointerOffset));
        a->cmp(x15, 2);
        a->b(CondCode::kLO, done);
        a->tst(x15, kFallbackStateMask);
        a->b(CondCode::kNE, done);
        emit_table_add(
            a,
            context_kaddr,
            context_kaddr +
                offsetof(KernelCounterContext, tee_controller_objects),
            kTeeControllerObjectLimit,
            x15,
            offsetof(KernelCounterContext, tee_controller_adds),
            done);
    }

    a->bind(not_loader);
    const Label not_controller = a->newLabel();
    const Label controller_pattern = a->newLabel();
    a->cmp(w16, 2);
    a->b(CondCode::kNE, not_controller);
    emit_exact_arg_pattern(
        a, {kSiArgOutputObject}, controller_pattern, not_controller);
    a->bind(controller_pattern);
    {
        const Label controller_found = a->newLabel();
        emit_table_contains(
            a,
            context_kaddr +
                offsetof(KernelCounterContext, tee_controller_objects),
            kTeeControllerObjectLimit,
            x15,
            controller_found,
            done);
        a->bind(controller_found);
        emit_counter_increment(
            a,
            context_kaddr,
            offsetof(KernelCounterContext, tee_controller_hits));
        a->ldr(x13, ptr(sp, kLocalArgs));
        a->ldr(x15, ptr(x13, kSiArgPointerOffset));
        a->cmp(x15, 2);
        a->b(CondCode::kLO, done);
        a->tst(x15, kFallbackStateMask);
        a->b(CondCode::kNE, done);
        emit_table_add(
            a,
            context_kaddr,
            context_kaddr +
                offsetof(KernelCounterContext, tee_widevine_objects),
            kTeeWidevineObjectLimit,
            x15,
            offsetof(KernelCounterContext, tee_ta_adds),
            done);
    }

    a->bind(not_controller);
    // Cached-loader fallback, observed on the verified Android 16 firmware.
    // Exact consecutive operation/shape states are stored in a lock-free,
    // fixed-capacity pointer table. It remains caller-global.
    const Label try_fallback_0 = a->newLabel();
    const Label try_fallback_19 = a->newLabel();
    const Label try_fallback_20 = a->newLabel();
    const Label fallback_reset = a->newLabel();
    const Label fallback_16_pattern = a->newLabel();
    const Label fallback_0_pattern = a->newLabel();
    const Label fallback_19_pattern = a->newLabel();
    const Label fallback_20_pattern = a->newLabel();
    a->cmp(w16, 16);
    a->b(CondCode::kNE, try_fallback_0);
    emit_exact_arg_pattern(
        a,
        {kSiArgInputBuffer, kSiArgOutputBuffer},
        fallback_16_pattern,
        fallback_reset);
    a->bind(fallback_16_pattern);
    emit_fallback_transition(a, context_kaddr, x15, 0, 1, true, done);

    a->bind(try_fallback_0);
    a->cmp(w16, 0);
    a->b(CondCode::kNE, try_fallback_19);
    emit_exact_arg_pattern(
        a,
        {kSiArgInputBuffer, kSiArgOutputBuffer},
        fallback_0_pattern,
        fallback_reset);
    a->bind(fallback_0_pattern);
    emit_fallback_transition(a, context_kaddr, x15, 1, 2, false, done);

    a->bind(try_fallback_19);
    a->cmp(w16, 19);
    a->b(CondCode::kNE, try_fallback_20);
    emit_exact_arg_pattern(
        a,
        {kSiArgInputBuffer,
         kSiArgInputBuffer,
         kSiArgInputBuffer,
         kSiArgOutputBuffer},
        fallback_19_pattern,
        fallback_reset);
    a->bind(fallback_19_pattern);
    emit_fallback_transition(a, context_kaddr, x15, 2, 3, false, done);

    a->bind(try_fallback_20);
    a->cmp(w16, 20);
    a->b(CondCode::kNE, fallback_reset);
    emit_exact_arg_pattern(
        a,
        {kSiArgInputBuffer,
         kSiArgOutputBuffer,
         kSiArgOutputBuffer,
         kSiArgOutputBuffer},
        fallback_20_pattern,
        fallback_reset);
    a->bind(fallback_20_pattern);
    emit_fallback_transition(a, context_kaddr, x15, 3, 4, false, done);

    a->bind(fallback_reset);
    emit_fallback_clear_object(
        a,
        context_kaddr,
        x15,
        offsetof(KernelCounterContext, tee_fallback_resets));
    a->b(done);

    a->bind(result_rejected);
    {
        const Label count_rejection = a->newLabel();
        a->ldr(x15, ptr(sp, kLocalObject));
        a->cmp(x15, 2);
        a->b(CondCode::kLO, count_rejection);
        a->tst(x15, kFallbackStateMask);
        a->b(CondCode::kNE, count_rejection);
        emit_fallback_clear_object(
            a,
            context_kaddr,
            x15,
            offsetof(KernelCounterContext, tee_fallback_resets));
        a->bind(count_rejection);
    }
    emit_counter_increment(
        a,
        context_kaddr,
        offsetof(KernelCounterContext, tee_result_rejects));
    a->bind(done);
    emit_atomic_decrement(
        a, context_kaddr + offsetof(KernelCounterContext, tee_active_calls));
    a->ldr(x0, ptr(sp, kLocalReturn));
    a->add(sp, sp, kLocalBytes);
    kernel_module::arm64_before_hook_end(a, false);

    if (asm_ctx.has_error()) return KModErr::ERR_MODULE_ASM;
    handler = aarch64_asm_to_bytes(a);
    return handler.empty() ? KModErr::ERR_MODULE_ASM : KModErr::OK;
}

KModErr build_global_free_handler(uint64_t context_kaddr,
                                  std::vector<uint8_t>& handler) {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    Assembler* a = asm_ctx.assembler();
    if (a == nullptr) return KModErr::ERR_MODULE_ASM;
    kernel_module::arm64_before_hook_start(a);
    emit_counter_increment(
        a, context_kaddr, offsetof(KernelCounterContext, tee_free_calls));
    a->mov(x15, x0);
    const Label done = a->newLabel();
    a->cmp(x15, 2);
    a->b(CondCode::kLO, done);
    a->tst(x15, kFallbackStateMask);
    a->b(CondCode::kNE, done);
    emit_table_clear_object(
        a,
        context_kaddr,
        context_kaddr +
            offsetof(KernelCounterContext, tee_controller_objects),
        kTeeControllerObjectLimit,
        x15);
    emit_table_clear_object(
        a,
        context_kaddr,
        context_kaddr +
            offsetof(KernelCounterContext, tee_widevine_objects),
        kTeeWidevineObjectLimit,
        x15);
    emit_fallback_clear_object(
        a,
        context_kaddr,
        x15,
        offsetof(KernelCounterContext, tee_address_clears));
    a->bind(done);
    kernel_module::arm64_before_hook_end(a, true);
    if (asm_ctx.has_error()) return KModErr::ERR_MODULE_ASM;
    handler = aarch64_asm_to_bytes(a);
    return handler.empty() ? KModErr::ERR_MODULE_ASM : KModErr::OK;
}

bool supported_invoke_prologue(const std::array<uint32_t, 4>& words) {
    return words[0] == 0xd503233fU && // paciasp
           words[1] == 0xd10343ffU && // sub sp,sp,#0xd0
           words[2] == 0xa9077bfdU &&
           words[3] == 0xa9086ffcU;
}

bool supported_free_prologue(const std::array<uint32_t, 4>& words) {
    return words[0] == 0xd503233fU && // paciasp
           words[1] == 0xa9bf7bfdU &&
           words[2] == 0x910003fdU;
}

KModErr set_tee_backend_state(const CounterHookSession& session,
                              uint32_t state) {
    return kernel_module::write_kernel_mem(
        session.context_kaddr +
            offsetof(KernelCounterContext, tee_backend_state),
        &state,
        static_cast<uint32_t>(sizeof(state)),
        kernel_module::KernMemProt::KMP_RW);
}

} // namespace

KModErr resolve_and_validate_tee_hooks(TeeHookResolution& resolution) {
    resolution = {};
    RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name(
        "si_object_do_invoke", resolution.invoke_kaddr));
    RETURN_IF_ERROR(kernel_module::kallsyms_lookup_name(
        "free_si_object", resolution.free_kaddr));
    if (resolution.invoke_kaddr == 0 || resolution.free_kaddr == 0 ||
        resolution.invoke_kaddr == resolution.free_kaddr) {
        resolution = {};
        return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    }
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(
        resolution.invoke_kaddr,
        resolution.invoke_prologue.data(),
        static_cast<uint32_t>(sizeof(resolution.invoke_prologue))));
    RETURN_IF_ERROR(kernel_module::read_kernel_mem(
        resolution.free_kaddr,
        resolution.free_prologue.data(),
        static_cast<uint32_t>(sizeof(resolution.free_prologue))));
    if (!supported_invoke_prologue(resolution.invoke_prologue) ||
        !supported_free_prologue(resolution.free_prologue)) {
        resolution = {};
        return KModErr::ERR_MODULE_FUNC_NOT_STANDARD;
    }
    return KModErr::OK;
}

KModErr install_global_tee_hooks(const TeeHookResolution& resolution,
                                 const TeeFirmwareIdentity& firmware,
                                 CounterHookSession& session) {
    if (session.context_kaddr == 0 || session.hook == nullptr ||
        session.tee_invoke_hook != nullptr ||
        session.tee_free_hook != nullptr || resolution.invoke_kaddr == 0 ||
        resolution.free_kaddr == 0 || !valid_firmware(firmware)) {
        return KModErr::ERR_MODULE_PARAM;
    }

    TeeFirmwareIdentitySlot kernel_identity{};
    kernel_identity.generation = firmware.generation;
    kernel_identity.file_size = firmware.file_size;
    kernel_identity.edge_bytes = firmware.edge_bytes;
    std::memcpy(kernel_identity.prefix,
                firmware.prefix.data(),
                firmware.prefix.size());
    std::memcpy(kernel_identity.suffix,
                firmware.suffix.data(),
                firmware.suffix.size());
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(
        session.context_kaddr +
            offsetof(KernelCounterContext, tee_firmware_identity),
        &kernel_identity,
        static_cast<uint32_t>(sizeof(kernel_identity)),
        kernel_module::KernMemProt::KMP_RW));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(
        session.context_kaddr +
            offsetof(KernelCounterContext, tee_invoke_target_kaddr),
        &resolution.invoke_kaddr,
        static_cast<uint32_t>(sizeof(resolution.invoke_kaddr)),
        kernel_module::KernMemProt::KMP_RW));
    RETURN_IF_ERROR(kernel_module::write_kernel_mem(
        session.context_kaddr +
            offsetof(KernelCounterContext, tee_free_target_kaddr),
        &resolution.free_kaddr,
        static_cast<uint32_t>(sizeof(resolution.free_kaddr)),
        kernel_module::KernMemProt::KMP_RW));

    std::vector<uint8_t> invoke_handler;
    std::vector<uint8_t> free_handler;
    RETURN_IF_ERROR(build_global_invoke_handler(
        session.context_kaddr, invoke_handler));
    RETURN_IF_ERROR(build_global_free_handler(
        session.context_kaddr, free_handler));

    kernel_module::HookHandle invoke_hook = nullptr;
    KModErr err = kernel_module::install_kernel_function_before_hook(
        resolution.invoke_kaddr, invoke_handler, &invoke_hook);
    if (is_failed(err)) return err;
    kernel_module::HookHandle free_hook = nullptr;
    err = kernel_module::install_kernel_function_before_hook(
        resolution.free_kaddr, free_handler, &free_hook);
    if (is_failed(err)) {
        kernel_module::uninstall_kernel_hook(invoke_hook);
        return err;
    }

    session.tee_invoke_target_kaddr = resolution.invoke_kaddr;
    session.tee_free_target_kaddr = resolution.free_kaddr;
    session.tee_invoke_hook = invoke_hook;
    session.tee_free_hook = free_hook;
    err = set_tee_backend_state(session, 1);
    if (is_failed(err)) {
        kernel_module::uninstall_kernel_hook(free_hook);
        kernel_module::uninstall_kernel_hook(invoke_hook);
        session.tee_invoke_target_kaddr = 0;
        session.tee_free_target_kaddr = 0;
        session.tee_invoke_hook = nullptr;
        session.tee_free_hook = nullptr;
        return err;
    }
    return KModErr::OK;
}

KModErr remove_global_tee_hooks(CounterHookSession& session) {
    if (session.context_kaddr == 0) return KModErr::ERR_MODULE_PARAM;
    RETURN_IF_ERROR(set_tee_backend_state(session, 0));
    if (session.tee_free_hook != nullptr) {
        RETURN_IF_ERROR(
            kernel_module::uninstall_kernel_hook(session.tee_free_hook));
        session.tee_free_hook = nullptr;
    }
    if (session.tee_invoke_hook != nullptr) {
        RETURN_IF_ERROR(
            kernel_module::uninstall_kernel_hook(session.tee_invoke_hook));
        session.tee_invoke_hook = nullptr;
    }
    session.tee_invoke_target_kaddr = 0;
    session.tee_free_target_kaddr = 0;
    return KModErr::OK;
}

} // namespace drmid
