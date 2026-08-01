#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

#include "control_ipc.h"
#include "kernel_module_kit_umbrella.h"

extern "C" int __skroot_module_main_18fdf393885363712349ef3de5411bd5(
    const char* root_key, const char* module_private_dir);

// Device-side development runner. The root key is read from stdin so it does
// not appear in argv or process listings.
int main() {
    // Development runs redirect output to a device file. Keep progress lines
    // immediately observable so the host can trigger MediaDrm only after the
    // Hook installation line has actually been emitted.
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    // The production module entry forks a detached daemon. The development
    // runner must stay attached so host-side tests can observe its lifecycle
    // and feed the root key only through stdin.
    setenv("DRMID_FOREGROUND", "1", 1);
    if (const char* operation_text = std::getenv("DRMID_IPC_CLIENT")) {
        if (std::getenv("DRMID_IPC_GET_ROOT") != nullptr) {
            std::string client_root_key;
            if (!std::getline(std::cin, client_root_key) ||
                client_root_key.empty()) {
                std::cerr << "missing root key on stdin\n";
                return 2;
            }
            const KModErr root_err =
                skroot_env::get_root(client_root_key.c_str());
            std::fill(client_root_key.begin(), client_root_key.end(), '\0');
            if (is_failed(root_err)) {
                std::cerr << "[drmid-runner] get_root result="
                          << to_string(root_err) << '\n';
                return 3;
            }
        }
        drmid::ControlIpcOperation operation;
        if (std::string(operation_text) == "status") {
            operation = drmid::ControlIpcOperation::kStatus;
        } else if (std::string(operation_text) == "apply") {
            operation = drmid::ControlIpcOperation::kApply;
        } else if (std::string(operation_text) == "stop") {
            operation = drmid::ControlIpcOperation::kStop;
        } else {
            std::cerr << "invalid DRMID_IPC_CLIENT operation\n";
            return 4;
        }
        const char* path = std::getenv("DRMID_CONTROL_SOCKET_PATH");
        const std::string fallback =
            "/data/local/tmp/drmid_probe_state/drmid_control_v2.sock";
        drmid::ControlIpcResponse response{};
        const KModErr err = drmid::send_control_ipc_request(
            path != nullptr && path[0] != '\0' ? path : fallback.c_str(),
            operation,
            response);
        if (is_failed(err)) {
            std::cerr << "[drmid-runner] IPC transport result="
                      << to_string(err) << '\n';
            return 5;
        }
        std::cout << drmid::control_response_json(response) << '\n';
        return response.result == 0 ? 0 : 6;
    }
    std::string root_key;
    if (!std::getline(std::cin, root_key) || root_key.empty()) {
        std::cerr << "missing root key on stdin\n";
        return 2;
    }
    if (const char* action = std::getenv("DRMID_MODULE_ACTION")) {
        KModErr action_err = KModErr::ERR_MODULE_PARAM;
        const std::string action_name(action);
        if (action_name == "run-once" || action_name == "install") {
            const char* zip_path = std::getenv("DRMID_MODULE_ZIP");
            std::string reason;
            if (zip_path != nullptr && zip_path[0] != '\0') {
                action_err = action_name == "run-once"
                                 ? skroot_env::install_module_dev_run_once(
                                       root_key.c_str(), zip_path, reason)
                                 : skroot_env::install_module(
                                       root_key.c_str(), zip_path, reason);
            }
            if (!reason.empty()) std::cout << reason << '\n';
        } else if (action_name == "webui") {
            int port = 0;
            action_err = skroot_env::features::web_ui::
                start_module_web_ui_server_async(
                    root_key.c_str(),
                    "drmidKern612Probe20260728Alpha01",
                    port);
            std::cout << "[drmid-runner] WebUI port=" << port << '\n';
            if (is_ok(action_err)) {
                if (const char* hold_text =
                        std::getenv("DRMID_WEBUI_HOLD_MS")) {
                    const unsigned long hold_ms =
                        std::strtoul(hold_text, nullptr, 10);
                    if (hold_ms <= 600000UL) {
                        usleep(static_cast<useconds_t>(hold_ms) * 1000U);
                    }
                }
            }
        } else if (action_name == "uninstall") {
            action_err = skroot_env::uninstall_module(
                root_key.c_str(),
                "drmidKern612Probe20260728Alpha01");
        } else if (action_name == "log") {
            std::string module_log;
            action_err = skroot_env::read_skroot_log(
                root_key.c_str(), module_log);
            std::cout << module_log;
            if (!module_log.empty() && module_log.back() != '\n') {
                std::cout << '\n';
            }
        } else if (action_name == "list") {
            std::vector<skroot_env::module_record> modules;
            action_err = skroot_env::get_all_modules_list(
                root_key.c_str(), modules);
            for (const auto& module : modules) {
                std::cout << module.desc.id32 << '\t' << module.desc.version
                          << '\t' << static_cast<uint32_t>(module.state)
                          << '\t' << (module.desc.web_ui ? "webui" : "-")
                          << '\n';
            }
        } else if (action_name == "env-state") {
            const auto state =
                skroot_env::get_skroot_environment_state(root_key.c_str());
            std::cout << "[drmid-runner] environment state="
                      << static_cast<uint32_t>(state) << '\n';
            action_err = KModErr::OK;
        }
        std::fill(root_key.begin(), root_key.end(), '\0');
        std::cout << "[drmid-runner] module action=" << action_name
                  << " result=" << to_string(action_err) << '\n';
        return is_ok(action_err) ? 0 : 7;
    }
    const char* private_dir = std::getenv("DRMID_MODULE_PRIVATE_DIR");
    return __skroot_module_main_18fdf393885363712349ef3de5411bd5(
        root_key.c_str(),
        private_dir != nullptr && private_dir[0] != '\0'
            ? private_dir
            : "/data/local/tmp/drmid_probe_state");
}
