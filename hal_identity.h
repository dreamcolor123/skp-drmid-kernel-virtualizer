#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "binder_hook_builder.h"

namespace drmid {

struct HalProcessInfo {
    uint32_t tgid = 0;
    uint32_t uid = 0;
    std::string exe;
    std::string domain;
    std::string binder_path;
};

// Discovers only strictly verified Widevine HAL processes. An empty result is
// valid and means the kernel gate remains closed while the service starts.
KModErr discover_widevine_hal_identities(
    const char* proc_root,
    uint64_t generation,
    HalIdentityConfig& identities,
    std::vector<HalProcessInfo>* details = nullptr);

// Opens a pollable process-lifetime descriptor. Returns -1 with errno set on
// kernels where pidfd is absent or when the TGID already exited.
int open_hal_pidfd(uint32_t tgid);

} // namespace drmid
