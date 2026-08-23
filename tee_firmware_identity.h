#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "kernel_context.h"
#include "kernel_module_kit_umbrella.h"

namespace drmid {

constexpr uint64_t kTeeFirmwareMinimumBytes = 64;
constexpr uint64_t kTeeFirmwareMaximumBytes = 16U * 1024U * 1024U;

struct TeeFirmwareIdentity {
    uint64_t generation = 0;
    uint64_t file_size = 0;
    uint32_t edge_bytes = 0;
    std::array<uint8_t, kTeeFirmwareEdgeBytes> prefix{};
    std::array<uint8_t, kTeeFirmwareEdgeBytes> suffix{};
    std::string path;
};

// Reads a regular Widevine firmware image without following a final symlink.
// Only its size and fixed prefix/suffix are retained; identifier material is
// never read here.
KModErr read_tee_firmware_identity(const char* path,
                                   uint64_t generation,
                                   TeeFirmwareIdentity& identity);

KModErr discover_tee_firmware_identity(
    uint64_t generation,
    TeeFirmwareIdentity& identity,
    const std::vector<std::string>* candidate_override = nullptr);

} // namespace drmid
