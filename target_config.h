#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "kernel_module_kit_umbrella.h"
#include "runtime_profile.h"

namespace drmid {

constexpr size_t kTargetPackageMaxBytes = 127;
constexpr size_t kTargetPackageLimit = 32;
constexpr size_t kTargetPackagesFormMaxBytes =
    kTargetPackageLimit * (kTargetPackageMaxBytes + 1);

struct TargetPackageResolution {
    std::string package_name;
    uint32_t resolved_euid = 0;
};

struct ResolvedTargetConfig {
    TargetRuleMode rule_mode = TargetRuleMode::kAll;
    uint64_t generation = 0;
    std::string profile_domain;
    std::vector<TargetPackageResolution> packages;
    std::vector<uint32_t> target_euids;
    size_t input_package_count = 0;
    size_t duplicate_package_count = 0;
    bool shared_uid = false;
    bool created = false;
    bool updated = false;
    bool migrated_v1 = false;

    // Compatibility summaries for existing diagnostic call sites. Multi-target
    // policy publication always uses target_euids rather than this first item.
    uint32_t target_euid = 0;
    std::string package_name;
    std::string display_name;
};

// Loads the v2 persistent target set, migrates an existing validated v1
// single-package record atomically, applies explicit environment overrides,
// and resolves the complete package set. Explicit changes are committed only
// after every package resolves to a non-zero UID.
KModErr load_or_resolve_target_config(const char* root_key,
                                      const char* module_private_dir,
                                      ResolvedTargetConfig& config);

// Read-only v2 snapshot used by WebUI status. Record-version or CRC mismatch is
// rejected rather than interpreted as an older layout.
KModErr read_target_config_snapshot(const char* module_private_dir,
                                    ResolvedTargetConfig& config);

} // namespace drmid
