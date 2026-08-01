#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "kernel_module_kit_umbrella.h"

namespace drmid {

constexpr size_t kSeedBytes = 32;
constexpr size_t kVirtualIdBytes = 32;
constexpr size_t kVirtualStreamBytes = 64;

enum class TargetRuleMode : uint32_t {
    kAll = 0,
    kExactEuid = 1,
    kExactPackage = 2,
};

struct RuntimeProfile {
    std::array<uint8_t, kVirtualStreamBytes> virtual_stream{};
    uint64_t seed_generation = 0;
    uint64_t profile_fingerprint = 0;
    TargetRuleMode rule_mode = TargetRuleMode::kAll;
    uint32_t target_euid = 0;
    bool seed_created = false;
};

// Runs SHA-256/HMAC/HKDF known-answer tests used by the profile generator.
bool runtime_crypto_self_test();
uint64_t virtual_id_fingerprint(const uint8_t* data, size_t size);

// Loads the module-isolated seed or creates it on first use, then derives a
// stable 64-byte stream bound to the selected UID or package rule.
KModErr load_or_create_runtime_profile(bool regenerate_seed,
                                       const char* module_private_dir,
                                       TargetRuleMode rule_mode,
                                       uint32_t target_euid,
                                       RuntimeProfile& profile);

KModErr load_or_create_runtime_profile(bool regenerate_seed,
                                       const char* module_private_dir,
                                       TargetRuleMode rule_mode,
                                       uint32_t target_euid,
                                       const char* package_name,
                                       RuntimeProfile& profile);

} // namespace drmid
