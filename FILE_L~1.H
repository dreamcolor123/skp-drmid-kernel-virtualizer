#pragma once

#include <cstddef>
#include <sys/types.h>

namespace drmid {

struct DaemonLockHandle {
    int directory_fd = -1;
    int lock_fd = -1;
    dev_t device = 0;
    ino_t inode = 0;
};

bool is_seed_temp_orphan_name(const char* name);
size_t cleanup_seed_temp_orphans(const char* module_private_dir);

// One-release compatibility cleanup. Legacy public paths never control startup.
bool is_legacy_development_payload_name(const char* name);
size_t cleanup_legacy_development_payloads(const char* public_tmp_dir);
void cleanup_legacy_public_marker();
void cleanup_legacy_public_artifacts();
size_t cleanup_legacy_target_state_after_global_migration(
    const char* module_private_dir);
void cleanup_module_state_files(const char* module_private_dir);

bool acquire_daemon_lock(const char* module_private_dir,
                         DaemonLockHandle& handle);
bool write_daemon_lock_pid(const DaemonLockHandle& handle, pid_t pid);
bool daemon_lock_owner_alive(const char* module_private_dir, pid_t& pid);
void release_daemon_lock(DaemonLockHandle& handle);

} // namespace drmid
