#pragma once

#include <cstdint>
#include <string>

#include "binder_hook_builder.h"

namespace drmid {

constexpr uint64_t kRuntimeControlMagic = 0x36314c54434d5244ULL; // DRMCTL16
constexpr uint32_t kRuntimeControlVersion = 2;
constexpr uint32_t kRuntimeControlRecordBytes = 256;

// Reads and validates exactly one v2 immutable control record.
KModErr read_runtime_control_file(const char* path,
                                  ReplacementConfig& config);
KModErr write_runtime_control_file(const char* path,
                                   const ReplacementConfig& config);

// One-time, explicitly validated v1 -> v2 conversion. A v1 record is never
// consumed directly by the runtime publisher; conversion binds its ID/mode to
// the already resolved v2 target set and atomically writes a v2 record.
KModErr migrate_runtime_control_v1(const char* v2_path,
                                   const ReplacementConfig& target_template,
                                   bool& migrated);

std::string default_runtime_control_path(const char* module_private_dir);

} // namespace drmid
