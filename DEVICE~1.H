#pragma once

#include <cstdint>

#include "kernel_module_kit_umbrella.h"

namespace drmid {

// Captures only a SHA-256-derived 64-bit fingerprint of the original
// Widevine deviceUniqueId before this module installs its Binder Hook. Raw ID
// bytes are never persisted or logged. An existing validated record is kept.
KModErr capture_original_id_fingerprint_if_missing(
    const char* module_private_dir,
    uint64_t& fingerprint);

// Reads the validated private fingerprint record for WebUI status output.
KModErr read_original_id_fingerprint(const char* module_private_dir,
                                      uint64_t& fingerprint);

} // namespace drmid
