#pragma once

#include <cstdint>
#include <string>

#include "binder_hook_builder.h"

namespace drmid {

constexpr uint64_t kRuntimeControlMagic = 0x38314c54434d5244ULL; // DRMCTL18
constexpr uint32_t kRuntimeControlVersion = 3;
constexpr uint32_t kRuntimeControlRecordBytes = 128;

// Reads and validates exactly one v3 global immutable control record.
KModErr read_runtime_control_file(const char* path,
                                  ReplacementConfig& config);
KModErr write_runtime_control_file(const char* path,
                                   const ReplacementConfig& config);

// One-time, strictly validated v2 -> v3 conversion. Legacy target fields are
// discarded while the active ID bytes, mode, generations and fingerprint are
// preserved exactly.
KModErr migrate_runtime_control_v2(const char* v3_path, bool& migrated);

std::string default_runtime_control_path(const char* module_private_dir);

} // namespace drmid
