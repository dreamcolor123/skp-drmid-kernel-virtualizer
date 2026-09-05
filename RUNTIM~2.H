#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "kernel_module_kit_umbrella.h"

namespace drmid {

constexpr size_t kSeedBytes = 32;
constexpr size_t kVirtualIdBytes = 32;
constexpr size_t kVirtualStreamBytes = 64;

struct RuntimeProfile {
    std::array<uint8_t, kVirtualStreamBytes> virtual_stream{};
    uint64_t seed_generation = 0;
    uint64_t profile_fingerprint = 0;
    bool seed_created = false;
};

// Runs SHA-256/HMAC/HKDF known-answer tests used by the profile generator.
bool runtime_crypto_self_test();
uint64_t virtual_id_fingerprint(const uint8_t* data, size_t size);

// Loads the module-isolated seed or creates it on first use, then derives one
// stable 64-byte stream in the fixed global-widevine-v1 domain.
KModErr load_or_create_runtime_profile(bool regenerate_seed,
                                       const char* module_private_dir,
                                       RuntimeProfile& profile);

} // namespace drmid
