#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "kernel_module_kit_umbrella.h"

namespace drmid {

// The picker is deliberately bounded: the WebUI is a configuration surface,
// not a package database export.  The target rule itself remains capped at 32.
constexpr size_t kDeviceAppCatalogLimit = 512;

struct DeviceAppInfo {
    std::string package_name;
    uint32_t uid = 0;
    std::string label;
    // A small data URI is returned so the WebUI does not need a second public
    // route for icon bytes.  It is generated when PackageManager resources are
    // unavailable (the common early-boot case).
    std::string icon_data_uri;
    std::string icon_source = "generated";
    bool system = false;
    bool label_from_package_manager = false;
};

// Enumerate packages visible to the module's root context.  Package names and
// UIDs come from packages.list first (the same early-boot source used by the
// target resolver); the private PackageManager/resource helper is best-effort
// for locale-aware human labels.  A failure to resolve labels/icons never
// changes the package/UID result.
KModErr enumerate_device_apps(const char* root_key,
                              const char* module_private_dir,
                              std::vector<DeviceAppInfo>& apps,
                              bool& truncated);

} // namespace drmid
