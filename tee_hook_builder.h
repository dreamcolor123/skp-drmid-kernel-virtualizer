#pragma once

#include <array>
#include <cstdint>

#include "binder_hook_builder.h"
#include "tee_firmware_identity.h"

namespace drmid {

struct TeeHookResolution {
    uint64_t invoke_kaddr = 0;
    uint64_t free_kaddr = 0;
    std::array<uint32_t, 4> invoke_prologue{};
    std::array<uint32_t, 4> free_prologue{};
};

// Resolves exported si_core symbols and admits only the verified Android 16 /
// Linux 6.12 function profiles. No module-relative offset is used.
KModErr resolve_and_validate_tee_hooks(TeeHookResolution& resolution);

// Adds a caller-global SMCInvoke backend to an existing Binder session. The
// handler never reads UID/EUID, package, process or credential state.
KModErr install_global_tee_hooks(const TeeHookResolution& resolution,
                                 const TeeFirmwareIdentity& firmware,
                                 CounterHookSession& session);

// Disables the TEE backend, then removes free/invoke hooks in reverse order.
// The shared context remains retained under the Binder session grace policy.
KModErr remove_global_tee_hooks(CounterHookSession& session);

} // namespace drmid
