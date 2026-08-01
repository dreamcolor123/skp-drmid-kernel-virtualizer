#include "file_lifecycle.h"

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <unistd.h>

namespace fs = std::filesystem;

volatile sig_atomic_t g_stop_requested = 0;

void stop_handler(int) {
    g_stop_requested = 1;
}

int main(int argc, char** argv) {
    if (argc < 3) return 64;
    const std::string operation(argv[1]);
    const char* directory = argv[2];
    fs::create_directories(directory);

    if (operation == "cleanup") {
        std::cout << drmid::cleanup_seed_temp_orphans(directory) << '\n';
        return 0;
    }
    if (operation == "cleanup-legacy") {
        std::cout << drmid::cleanup_legacy_development_payloads(directory) << '\n';
        return 0;
    }
    if (operation == "check") {
        pid_t pid = -1;
        if (drmid::daemon_lock_owner_alive(directory, pid)) {
            std::cout << "alive " << pid << '\n';
        } else {
            std::cout << "inactive\n";
        }
        return 0;
    }

    drmid::DaemonLockHandle lock;
    if (!drmid::acquire_daemon_lock(directory, lock)) {
        std::cout << "busy\n";
        return operation == "try" ? 0 : 2;
    }
    if (!drmid::write_daemon_lock_pid(lock, getpid())) {
        drmid::release_daemon_lock(lock);
        return 3;
    }

    if (operation == "try") {
        std::cout << "acquired\n";
        drmid::release_daemon_lock(lock);
        return 0;
    }
    if (operation == "normal") {
        drmid::release_daemon_lock(lock);
        return fs::exists(fs::path(directory) / "drmid_daemon_v1.lock") ? 4 : 0;
    }
    if (operation == "hold") {
        if (argc != 4) return 65;
        const auto milliseconds = std::chrono::milliseconds(
            std::strtoul(argv[3], nullptr, 10));
        std::cout << "locked\n" << std::flush;
        std::this_thread::sleep_for(milliseconds);
        drmid::release_daemon_lock(lock);
        return 0;
    }
    if (operation == "hold-term") {
        std::signal(SIGTERM, stop_handler);
        std::cout << "locked\n" << std::flush;
        while (!g_stop_requested) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        drmid::release_daemon_lock(lock);
        return 0;
    }

    drmid::release_daemon_lock(lock);
    return 66;
}
