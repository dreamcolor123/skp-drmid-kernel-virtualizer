#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "module_err_def.h"

namespace drmid {

enum class BinderBackend : uint32_t {
    kUnknown = 0,
    kClassic = 1,
    kRust = 2,
};

enum class BinderOffsetSource : uint32_t {
    kUnknown = 0,
    kSdk = 1,
    kSymbolScan = 2,
};

enum BinderCapability : uint64_t {
    kCapabilityFdWalk = 1ULL << 0,
    kCapabilityFopsResolved = 1ULL << 1,
    kCapabilityIoctlResolved = 1ULL << 2,
    kCapabilitySymbolCrossValidated = 1ULL << 3,
    kCapabilityKernelTextTarget = 1ULL << 4,
    kCapabilitySemanticPrologue = 1ULL << 5,
    kCapabilityHookRelocatablePrefix = 1ULL << 6,
    kCapabilityBinderWriteRead = 1ULL << 7,
    kCapabilityTransactionStreams = 1ULL << 8,
    kCapabilityEqualLengthReplacement = 1ULL << 9,
};

enum BinderEntrySemantic : uint32_t {
    kEntryHasBti = 1U << 0,
    kEntryHasPac = 1U << 1,
    kEntryHasStackFrame = 1U << 2,
    kEntrySavesFrameLink = 1U << 3,
    kEntrySetsFramePointer = 1U << 4,
    kEntryRelocatablePrefix = 1U << 5,
    // The exported symbol is a short AArch64 veneer that branches to the
    // real Binder implementation.  The target prologue is classified before
    // the hook is installed; the bit is diagnostic only and does not alter
    // the frozen Kernel Context ABI.
    kEntryHasVeneer = 1U << 6,
    // The SDK 4.5.4 before-hook replaces exactly one 4-byte instruction.
    // These bits describe that actual hook-site instruction separately from
    // the real implementation prologue reached through a veneer.
    kEntryHookSiteBti = 1U << 7,
    kEntryHookSitePac = 1U << 8,
    kEntryHookSiteFrame = 1U << 9,
};

enum BinderSymbolValidation : uint32_t {
    kSymbolClassicFops = 1U << 0,
    kSymbolClassicIoctl = 1U << 1,
    kSymbolRustFops = 1U << 2,
    kSymbolRustIoctl = 1U << 3,
};

constexpr size_t kBinderEntryProbeBytes = 256;
constexpr size_t kBinderEntryProbeWords =
    kBinderEntryProbeBytes / sizeof(uint32_t);

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
    BinderOffsetSource file_f_op_source = BinderOffsetSource::kUnknown;
    BinderOffsetSource fops_unlocked_ioctl_source =
        BinderOffsetSource::kUnknown;
    std::array<uint32_t, kBinderEntryProbeWords> entry_words{};
    uint64_t entry_fingerprint = 0;
    uint64_t capabilities = 0;
    uint32_t entry_semantics = 0;
    uint32_t symbol_validations = 0;
    BinderBackend backend = BinderBackend::kUnknown;
};

struct BinderCapabilityStatus {
    std::string kernel_release;
    BinderBackend backend = BinderBackend::kUnknown;
    BinderOffsetSource file_f_op_source = BinderOffsetSource::kUnknown;
    BinderOffsetSource fops_unlocked_ioctl_source =
        BinderOffsetSource::kUnknown;
    uint64_t capabilities = 0;
    uint64_t entry_fingerprint = 0;
    uint32_t entry_semantics = 0;
    uint32_t symbol_validations = 0;
};

constexpr uint64_t kRequiredBinderCapabilities =
    kCapabilityFdWalk |
    kCapabilityFopsResolved |
    kCapabilityIoctlResolved |
    kCapabilitySymbolCrossValidated |
    kCapabilityKernelTextTarget |
    kCapabilitySemanticPrologue |
    kCapabilityHookRelocatablePrefix |
    kCapabilityBinderWriteRead |
    kCapabilityTransactionStreams |
    kCapabilityEqualLengthReplacement;

const char* binder_backend_name(BinderBackend backend);
const char* binder_offset_source_name(BinderOffsetSource source);
const char* binder_resolution_source_name(
    const BinderIoctlResolution& resolution);

// Accept Linux 6.x from 6.1 onward. The release string is only a minimum
// platform gate; the live Binder capabilities below are authoritative.
bool is_supported_linux_6_1_or_newer(const std::string& kernel_release);

// Resolve the actual unlocked_ioctl reached by the supplied, already-open
// /dev/binder FD. SDK offsets are checked against live Binder symbols and
// corrected with bounded scans when an OEM layout differs.
KModErr resolve_binder_ioctl_from_fd(int binder_fd, BinderIoctlResolution& out);

bool has_required_binder_capabilities(
    const BinderIoctlResolution& resolution);

// Private, CRC-protected diagnostics shared with WebUI without changing the
// frozen Control IPC v5 wire layout.
std::string default_binder_capability_path(const char* module_private_dir);
KModErr write_binder_capability_status(
    const char* path,
    const std::string& kernel_release,
    const BinderIoctlResolution& resolution);
KModErr read_binder_capability_status(
    const char* path,
    BinderCapabilityStatus& status);

} // namespace drmid
