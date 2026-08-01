#include "binder_ioctl_resolver.h"

#include <cstdint>
#include <cstdio>

#include "kernel_module_kit_umbrella.h"

using namespace asmjit;
using namespace asmjit::a64;

namespace drmid {
namespace {

bool is_kernel_pointer(uint64_t value) {
    return value != 0 && (value & 0x3U) == 0 && static_cast<int64_t>(value) < 0;
}

KModErr load_offsets(BinderKernelOffsets& offsets) {
    const std::string kernel_version = kernel_module::get_kernel_version();
    const bool kernel_66 = kernel_version.rfind("6.6.", 0) == 0;
    const bool kernel_612 = kernel_version.rfind("6.12.", 0) == 0;
    KModErr err = kernel_module::get_task_struct_files_offset(offsets.task_files);
    printf("[drmid612] offset task.files=%u result=%s\n",
           offsets.task_files, to_string(err).c_str());
    if (is_failed(err)) return err;

    err = kernel_module::get_file_struct_fdt_offset(offsets.files_fdt);
    printf("[drmid612] offset files.fdt=%u result=%s\n",
           offsets.files_fdt, to_string(err).c_str());
    if (is_failed(err)) return err;

    err = kernel_module::get_fdtable_fd_offset(offsets.fdtable_fd);
    printf("[drmid612] offset fdt.fd=%u result=%s\n",
           offsets.fdtable_fd, to_string(err).c_str());
    if (is_failed(err)) return err;

    err = kernel_module::get_file_f_op_offset(offsets.file_f_op);
    printf("[drmid612] offset file.f_op=%u result=%s\n",
           offsets.file_f_op, to_string(err).c_str());
    if (is_failed(err)) {
        if ((err == KModErr::ERR_MODULE_OFFSET_NOT_FOUND ||
             err == KModErr::ERR_MODULE_CREATE_EMPTY_FILE) &&
            kernel_612) {
            offsets.file_f_op = 0x10;
            printf("[drmid612] offset file.f_op=16 "
                   "source=device-6.12-live-profile\n");
        } else if ((err == KModErr::ERR_MODULE_OFFSET_NOT_FOUND ||
                    err == KModErr::ERR_MODULE_CREATE_EMPTY_FILE) &&
                   kernel_66) {
            // Captured on Linux 6.6.89 / SDK 4.5.4 and cross-validated by
            // file->f_op == binder_fops. The live symbol scan below remains
            // authoritative and corrects any future layout drift.
            offsets.file_f_op = 0xc0;
            printf("[drmid612] offset file.f_op=192 "
                   "source=classic-binder-6.6-live-profile\n");
        } else {
            return err;
        }
    }

    err = kernel_module::get_file_operations_unlocked_ioctl_offset(
        offsets.fops_unlocked_ioctl);
    printf("[drmid612] offset fops.unlocked_ioctl=%u result=%s\n",
           offsets.fops_unlocked_ioctl, to_string(err).c_str());
    if (is_failed(err)) {
        // SDK 4.5.4 does not yet expose this member offset on the captured
        // Android 16 / Linux 6.12 build. 0x50 comes from both the captured
        // rust_binder_fops relocation and the live classic binder_fops match.
        // The resolver still reads the target through the live f_op and the
        // caller requires an exact 16-byte classic/Rust profile before Hook.
        if ((err == KModErr::ERR_MODULE_OFFSET_NOT_FOUND ||
             err == KModErr::ERR_MODULE_CREATE_EMPTY_FILE) &&
            kernel_612) {
            offsets.fops_unlocked_ioctl = 0x50;
            printf("[drmid612] offset fops.unlocked_ioctl=80 "
                   "source=file_operations-6.12-profile\n");
        } else if ((err == KModErr::ERR_MODULE_OFFSET_NOT_FOUND ||
                    err == KModErr::ERR_MODULE_CREATE_EMPTY_FILE) &&
                   kernel_66) {
            offsets.fops_unlocked_ioctl = 0x48;
            printf("[drmid612] offset fops.unlocked_ioctl=72 "
                   "source=classic-binder-6.6-live-profile\n");
        } else {
            return err;
        }
    }
    return KModErr::OK;
}

KModErr resolve_file_from_current_fd(int fd,
                                     const BinderKernelOffsets& offsets,
                                     uint64_t& file_kaddr) {
    if (fd < 0 || fd > 4095) {
        return KModErr::ERR_MODULE_PARAM;
    }

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    Assembler* a = asm_ctx.assembler();
    if (a == nullptr) {
        return KModErr::ERR_MODULE_ASM;
    }

    const Label fail = a->newLabel();
    const Label done = a->newLabel();

    kernel_module::arm64_module_asm_func_start(a);

    // x9 = current
    kernel_module::export_symbol::get_current(a, x9);
    a->cbz(x9, fail);

    // x9 = current->files->fdt->fd
    a->ldr(x9, ptr(x9, offsets.task_files));
    a->cbz(x9, fail);
    a->ldr(x9, ptr(x9, offsets.files_fdt));
    a->cbz(x9, fail);
    a->ldr(x9, ptr(x9, offsets.fdtable_fd));
    a->cbz(x9, fail);

    // The FD remains open for the whole resolver call, so this current-task
    // lookup is stable without walking another process's fdtable.
    a->ldr(x9, ptr(x9, static_cast<int64_t>(fd) * 8));
    a->b(done);

    a->bind(fail);
    a->mov(x9, xzr);
    a->bind(done);
    kernel_module::arm64_module_asm_func_end(a, x9);

    if (asm_ctx.has_error()) {
        return KModErr::ERR_MODULE_ASM;
    }

    file_kaddr = 0;
    const KModErr execute_err = kernel_module::execute_kernel_asm_func(
        aarch64_asm_to_bytes(a), file_kaddr);
    printf("[drmid612] fd walk file=%p result=%s\n",
           reinterpret_cast<void*>(file_kaddr),
           to_string(execute_err).c_str());
    if (is_failed(execute_err)) return execute_err;
    return is_kernel_pointer(file_kaddr) ? KModErr::OK
                                         : KModErr::ERR_MODULE_NOT_KADDR;
}

BinderBackend classify_backend(const std::array<uint32_t, 4>& words) {
    // Classic binder_ioctl captured from Linux 6.6.89. The 0xd0-byte frame
    // and first two callee-save pairs differ from the existing 6.12 profile.
    // The SDK probe read the same 256-byte body three times from both the
    // binder_ioctl symbol and the live /dev/binder unlocked_ioctl target
    // (FNV-1a64 62e54bf3e7aa39bb).
    constexpr std::array<uint32_t, 4> kClassicBinder66Prologue = {
        0xd503233fU, // paciasp
        0xd10343ffU, // sub sp, sp, #0xd0
        0xa9077bfdU, // stp x29, x30, [sp, #0x70]
        0xa9086ffcU, // stp x28, x27, [sp, #0x80]
    };
    // Classic binder_ioctl from the running, SKP-patched PLZ110 6.12 kernel.
    // It was reached from the live /dev/binder FD and cross-matched against
    // kallsyms binder_fops/binder_ioctl.
    constexpr std::array<uint32_t, 4> kClassicBinder612Prologue = {
        0xd503233fU, // paciasp
        0xd10303ffU, // sub sp, sp, #0xc0
        0xa9067bfdU, // stp x29, x30, [sp, #0x60]
        0xa9076ffcU, // stp x28, x27, [sp, #0x70]
    };
    // rust_binder.ko @ 0x1d50c, aliases:
    // rust_binder_unlocked_ioctl / rust_binder_compat_ioctl
    constexpr std::array<uint32_t, 4> kRustBinder612Prologue = {
        0xd503233fU, // paciasp
        0xa9bf7bfdU, // stp x29, x30, [sp, #-16]!
        0x910003fdU, // mov x29, sp
        0xaa0003e8U, // mov x8, x0
    };
    if (words == kClassicBinder66Prologue) {
        return BinderBackend::kClassicBinder66;
    }
    if (words == kClassicBinder612Prologue) {
        return BinderBackend::kClassicBinder612;
    }
    if (words == kRustBinder612Prologue) {
        return BinderBackend::kRustBinder612;
    }
    return BinderBackend::kUnknown;
}

} // namespace

const char* binder_backend_name(BinderBackend backend) {
    switch (backend) {
        case BinderBackend::kClassicBinder66:
            return "classic_binder-6.6";
        case BinderBackend::kClassicBinder612:
            return "classic_binder-6.12";
        case BinderBackend::kRustBinder612:
            return "rust_binder-6.12";
        case BinderBackend::kUnknown:
        default:
            return "unknown";
    }
}

KModErr resolve_binder_ioctl_from_fd(int binder_fd, BinderIoctlResolution& out) {
    out = {};
    out.binder_fd = binder_fd;
    RETURN_IF_ERROR(load_offsets(out.offsets));
    RETURN_IF_ERROR(resolve_file_from_current_fd(
        binder_fd, out.offsets, out.file_kaddr));

    uint64_t binder_fops_symbol = 0;
    uint64_t binder_ioctl_symbol = 0;
    const KModErr fops_symbol_err = kernel_module::kallsyms_lookup_name(
        "binder_fops", binder_fops_symbol);
    const KModErr ioctl_symbol_err = kernel_module::kallsyms_lookup_name(
        "binder_ioctl", binder_ioctl_symbol);
    printf("[drmid612] symbol binder_fops=%p result=%s\n",
           reinterpret_cast<void*>(binder_fops_symbol),
           to_string(fops_symbol_err).c_str());
    printf("[drmid612] symbol binder_ioctl=%p result=%s\n",
           reinterpret_cast<void*>(binder_ioctl_symbol),
           to_string(ioctl_symbol_err).c_str());

    KModErr err = kernel_module::read_kernel_mem_atomic64(
        out.file_kaddr + out.offsets.file_f_op, out.fops_kaddr);
    printf("[drmid612] live fops=%p offset=%u result=%s\n",
           reinterpret_cast<void*>(out.fops_kaddr),
           out.offsets.file_f_op,
           to_string(err).c_str());
    if (is_failed(err)) return err;

    // Cross-validate the SDK-provided file.f_op offset. The current 6.12 SDK
    // finder can return a plausible but incorrect offset on this OEM layout.
    // The FD walk remains the source of the file object; kallsyms only supplies
    // an equality target for locating f_op inside that live object.
    if (is_ok(fops_symbol_err) && is_kernel_pointer(binder_fops_symbol) &&
        out.fops_kaddr != binder_fops_symbol) {
        bool found = false;
        for (uint32_t offset = 0; offset < 0x100; offset += 8) {
            uint64_t candidate = 0;
            err = kernel_module::read_kernel_mem_atomic64(
                out.file_kaddr + offset, candidate);
            if (is_failed(err)) return err;
            if (candidate == binder_fops_symbol) {
                out.offsets.file_f_op = offset;
                out.fops_kaddr = candidate;
                found = true;
                printf("[drmid612] corrected file.f_op=%u by binder_fops match\n",
                       offset);
                break;
            }
        }
        if (!found) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
    if (!is_kernel_pointer(out.fops_kaddr)) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    // Prefer an exact slot match against binder_ioctl when kallsyms is
    // available. This also corrects SDK 4.5.4's missing 6.12 fops offset.
    bool ioctl_slot_found = false;
    if (is_ok(ioctl_symbol_err) && is_kernel_pointer(binder_ioctl_symbol)) {
        for (uint32_t offset = 0; offset < 0x108; offset += 8) {
            uint64_t candidate = 0;
            err = kernel_module::read_kernel_mem_atomic64(
                out.fops_kaddr + offset, candidate);
            if (is_failed(err)) return err;
            if (candidate == binder_ioctl_symbol) {
                out.offsets.fops_unlocked_ioctl = offset;
                out.ioctl_kaddr = candidate;
                ioctl_slot_found = true;
                printf("[drmid612] corrected fops.unlocked_ioctl=%u "
                       "by binder_ioctl match\n", offset);
                break;
            }
        }
    }
    if (!ioctl_slot_found) {
        err = kernel_module::read_kernel_mem_atomic64(
            out.fops_kaddr + out.offsets.fops_unlocked_ioctl,
            out.ioctl_kaddr);
    } else {
        err = KModErr::OK;
    }
    printf("[drmid612] live unlocked_ioctl=%p result=%s\n",
           reinterpret_cast<void*>(out.ioctl_kaddr),
           to_string(err).c_str());
    if (is_failed(err)) return err;
    if (!is_kernel_pointer(out.ioctl_kaddr)) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    RETURN_IF_ERROR(kernel_module::read_kernel_mem(
        out.ioctl_kaddr,
        out.prologue.data(),
        static_cast<uint32_t>(sizeof(out.prologue))));
    out.backend = classify_backend(out.prologue);
    return KModErr::OK;
}

bool is_supported_ioctl_profile(const BinderIoctlResolution& resolution,
                                const std::string& kernel_version) {
    if (!is_kernel_pointer(resolution.ioctl_kaddr)) return false;
    if (kernel_version.rfind("6.6.", 0) == 0) {
        return resolution.backend == BinderBackend::kClassicBinder66;
    }
    if (kernel_version.rfind("6.12.", 0) == 0) {
        return resolution.backend == BinderBackend::kClassicBinder612 ||
               resolution.backend == BinderBackend::kRustBinder612;
    }
    return false;
}

} // namespace drmid
