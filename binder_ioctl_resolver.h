#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "module_err_def.h"

namespace drmid {

enum class BinderBackend {
    kUnknown,
    kClassicBinder66,
    kClassicBinder612,
    kRustBinder612,
};

struct BinderKernelOffsets {
    uint32_t task_files = 0;
    uint32_t files_fdt = 0;
    uint32_t fdtable_fd = 0;
    uint32_t file_f_op = 0;
    uint32_t fops_unlocked_ioctl = 0;
};

struct BinderIoctlResolution {
    int binder_fd = -1;
    uint64_t file_kaddr = 0;
    uint64_t fops_kaddr = 0;
    uint64_t ioctl_kaddr = 0;
    BinderKernelOffsets offsets{};
    std::array<uint32_t, 4> prologue{};
    BinderBackend backend = BinderBackend::kUnknown;
};

const char* binder_backend_name(BinderBackend backend);

// Resolve the actual unlocked_ioctl reached by the supplied, already-open
// /dev/binder FD. The path is current->files->fdt->fd[fd]->f_op and therefore
// works whether the device node is backed by classic or Rust Binder.
KModErr resolve_binder_ioctl_from_fd(int binder_fd, BinderIoctlResolution& out);

// Strictly couple the live prologue fingerprint to its kernel family. Linux
// 6.6 accepts only the captured classic Binder profile; Linux 6.12 retains its
// existing classic/Rust profiles. A cross-family fingerprint fails closed.
bool is_supported_ioctl_profile(const BinderIoctlResolution& resolution,
                                const std::string& kernel_version);

} // namespace drmid
