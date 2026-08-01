#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>

#include "control_ipc.h"
#include "app_catalog.h"
#include "device_id_fingerprint.h"
#include "file_lifecycle.h"
#include "kernel_module_kit_umbrella.h"
#include "runtime_control.h"
#include "runtime_profile.h"
#include "target_config.h"

namespace {

constexpr size_t kWidevineIdBytes = 32;
constexpr size_t kSessionTokenBytes = 16;
constexpr size_t kSessionTokenHexBytes = kSessionTokenBytes * 2;
constexpr auto kSessionOpenGrace = std::chrono::seconds(15);
constexpr auto kSessionIdleTimeout = std::chrono::seconds(12);
constexpr auto kServerCloseDelay = std::chrono::milliseconds(80);
static_assert(drmid::kTargetPackageLimit == drmid::kRuntimeTargetLimit);
static_assert(kWidevineIdBytes == drmid::kVirtualIdBytes);

std::string json_escape(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);
    for (const unsigned char ch : value) {
        switch (ch) {
            case '\\': escaped += "\\\\"; break;
            case '"': escaped += "\\\""; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (ch >= 0x20) escaped.push_back(static_cast<char>(ch));
                break;
        }
    }
    return escaped;
}

std::string target_json_fields(const drmid::ResolvedTargetConfig& target) {
    std::string json;
    json += ",\"configured\":";
    json += target.rule_mode == drmid::TargetRuleMode::kAll
                ? "false"
                : "true";
    json += ",\"configured_package_count\":" +
            std::to_string(target.packages.size());
    json += ",\"configured_target_count\":" +
            std::to_string(target.target_euids.size());
    json += ",\"input_package_count\":" +
            std::to_string(target.input_package_count);
    json += ",\"duplicate_count\":" +
            std::to_string(target.duplicate_package_count);
    json += ",\"shared_uid\":";
    json += target.shared_uid ? "true" : "false";
    json += ",\"profile_domain\":\"" +
            json_escape(target.profile_domain) + "\"";
    json += ",\"package_status\":[";
    for (size_t index = 0; index < target.packages.size(); ++index) {
        if (index != 0) json.push_back(',');
        const auto& item = target.packages[index];
        json += "{\"package\":\"" + json_escape(item.package_name) +
                "\",\"uid\":" + std::to_string(item.resolved_euid) +
                ",\"status\":\"" +
                (item.resolved_euid == 0 ? "unresolved" : "resolved") +
                "\"}";
    }
    json += "]";
    json += ",\"unresolved_packages\":[";
    bool first = true;
    for (const auto& item : target.packages) {
        if (item.resolved_euid != 0) continue;
        if (!first) json.push_back(',');
        first = false;
        json += "\"" + json_escape(item.package_name) + "\"";
    }
    json += "]";
    return json;
}

std::string error_json(KModErr err,
                       const char* stage,
                       const drmid::ResolvedTargetConfig* target = nullptr) {
    std::string json = std::string("{\"result\":") +
                       std::to_string(to_num(err)) +
                       ",\"stage\":\"" + stage + "\"";
    if (target != nullptr) json += target_json_fields(*target);
    json += "}";
    return json;
}

std::string status_json(const drmid::ControlIpcResponse& response,
                        const drmid::ResolvedTargetConfig& target,
                        const char* module_private_dir) {
    std::string json = drmid::control_response_json(response);
    if (!json.empty() && json.back() == '}') json.pop_back();
    json += target_json_fields(target);
    uint64_t device_fingerprint = 0;
    const KModErr fingerprint_err = drmid::read_original_id_fingerprint(
        module_private_dir, device_fingerprint);
    if (is_ok(fingerprint_err) && device_fingerprint != 0) {
        char text[17]{};
        std::snprintf(text,
                      sizeof(text),
                      "%016" PRIx64,
                      device_fingerprint);
        json += ",\"device_fingerprint\":\"" + std::string(text) + "\"";
    } else {
        json += ",\"device_fingerprint\":\"\"";
    }
    json += "}";
    return json;
}

std::string apps_json(const std::vector<drmid::DeviceAppInfo>& apps,
                      bool truncated) {
    std::string json = "{\"result\":0,\"truncated\":";
    json += truncated ? "true" : "false";
    json += ",\"count\":" + std::to_string(apps.size()) +
            ",\"apps\":[";
    for (size_t index = 0; index < apps.size(); ++index) {
        if (index != 0) json.push_back(',');
        const auto& app = apps[index];
        json += "{\"package\":\"" + json_escape(app.package_name) +
                "\",\"uid\":" + std::to_string(app.uid) +
                ",\"label\":\"" + json_escape(app.label) +
                "\",\"icon\":\"" + json_escape(app.icon_data_uri) +
                "\",\"icon_source\":\"" +
                json_escape(app.icon_source) +
                "\",\"label_source\":\"" +
                (app.label_from_package_manager ? "package-manager" :
                                                   "package-fallback") +
                "\",\"system\":" + (app.system ? "true" : "false") +
                "}";
    }
    json += "]}";
    return json;
}

bool form_value(const std::string& body,
                const char* name,
                std::string& value,
                size_t max_bytes) {
    std::string buffer(max_bytes + 1, '\0');
    const int count = mg_get_var(body.data(),
                                 body.size(),
                                 name,
                                 buffer.data(),
                                 buffer.size());
    if (count < 0 || static_cast<size_t>(count) > max_bytes) {
        value.clear();
        return false;
    }
    value.assign(buffer.data(), static_cast<size_t>(count));
    return true;
}

int hex_nibble(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

bool read_full(int fd, uint8_t* buffer, size_t size) {
    size_t used = 0;
    while (used < size) {
        const ssize_t count = read(fd, buffer + used, size - used);
        if (count > 0) {
            used += static_cast<size_t>(count);
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

std::string new_session_token() {
    std::array<uint8_t, kSessionTokenBytes> bytes{};
    bool random_ok = false;
    const int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        random_ok = read_full(fd, bytes.data(), bytes.size());
        close(fd);
    }
    if (!random_ok) {
        const uint64_t now = static_cast<uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count());
        const uint64_t pid = static_cast<uint64_t>(getpid());
        for (size_t index = 0; index < bytes.size(); ++index) {
            const uint64_t mixed = now ^ (pid << 17) ^
                                   (static_cast<uint64_t>(index) *
                                    0x9e3779b97f4a7c15ULL);
            bytes[index] = static_cast<uint8_t>(mixed >> ((index % 8) * 8));
        }
    }
    static constexpr char kHex[] = "0123456789abcdef";
    std::string token;
    token.reserve(kSessionTokenHexBytes);
    for (const uint8_t byte : bytes) {
        token.push_back(kHex[byte >> 4]);
        token.push_back(kHex[byte & 0x0f]);
    }
    return token;
}

bool decode_virtual_id(const std::string& text,
                       std::array<uint8_t, drmid::kVirtualStreamBytes>& out) {
    out = {};
    if (text.size() != kWidevineIdBytes * 2) return false;
    for (size_t i = 0; i < kWidevineIdBytes; ++i) {
        const int high = hex_nibble(text[i * 2]);
        const int low = hex_nibble(text[i * 2 + 1]);
        if (high < 0 || low < 0) return false;
        out[i] = static_cast<uint8_t>((high << 4) | low);
    }
    return true;
}

bool active_targets_equal(const drmid::ControlIpcResponse& current,
                          const drmid::ResolvedTargetConfig& target) {
    if (current.target_count != target.target_euids.size() ||
        current.target_count > drmid::kRuntimeTargetLimit) {
        return false;
    }
    return std::equal(target.target_euids.begin(),
                      target.target_euids.end(),
                      current.target_euids);
}

class EnvironmentTargetScope {
public:
    explicit EnvironmentTargetScope(const std::string& packages) {
        setenv("DRMID_TARGET_PACKAGES", packages.c_str(), 1);
        unsetenv("DRMID_TARGET_PACKAGE");
        unsetenv("DRMID_TARGET_LABEL");
        unsetenv("DRMID_TARGET_UID");
    }

    ~EnvironmentTargetScope() {
        unsetenv("DRMID_TARGET_PACKAGES");
    }
};

class DrmidWebHandler : public kernel_module::WebUIHttpHandler {
public:
    void onPrepareCreate(const char* root_key,
                         const char* module_private_dir,
                         uint32_t port) override {
        std::lock_guard<std::mutex> guard(lock_);
        root_key_ = root_key != nullptr ? root_key : "";
        private_dir_ = module_private_dir != nullptr
                           ? module_private_dir
                           : "";
        control_path_ =
            drmid::default_runtime_control_path(private_dir_.c_str());
        socket_path_ =
            drmid::default_control_socket_path(private_dir_.c_str());
        printf("[drmid612] WebUI ready port=%u private_dir=%s\n",
               port,
               private_dir_.c_str());
    }

    void onServerCreated(CivetServer* server) override {
        {
            std::lock_guard<std::mutex> guard(lock_);
            server_ = server;
            session_token_.clear();
            session_open_ = false;
            session_last_activity_ = std::chrono::steady_clock::now();
            shutdown_requested_ = false;
            server_exiting_ = false;
        }
        if (!watchdog_started_.exchange(true)) {
            std::thread([this] { session_watchdog(); }).detach();
        }
    }

    ServerExitAction onBeforeServerExit() override {
        std::lock_guard<std::mutex> guard(lock_);
        session_open_ = false;
        session_token_.clear();
        server_exiting_ = true;
        return ServerExitAction::Exit;
    }

    bool handlePost(CivetServer*,
                    mg_connection* connection,
                    const std::string& path,
                    const std::string& body) override {
        if (path == "/api/session/open") return handle_session_open(connection);
        if (path == "/api/session/ping") {
            return handle_session_ping(connection, body);
        }
        if (path == "/api/session/close") {
            return handle_session_close(connection, body);
        }
        if (!authenticate_session(connection, body)) return true;
        if (path == "/api/status") return handle_status(connection);
        if (path == "/api/apps") return handle_apps(connection);
        if (path == "/api/apply") return handle_apply(connection, body);
        if (path == "/api/stop") return handle_stop(connection);
        kernel_module::webui::send_json(
            connection, 404, "{\"result\":-1,\"stage\":\"route\"}");
        return true;
    }

private:
    bool ready() const {
        return !root_key_.empty() && !private_dir_.empty() &&
               !control_path_.empty() && !socket_path_.empty();
    }

    bool authenticate_session(mg_connection* connection,
                              const std::string& body) {
        std::string token;
        if (!form_value(body, "session_token", token, kSessionTokenHexBytes)) {
            kernel_module::webui::send_json(
                connection, 401, "{\"result\":-1,\"stage\":\"session\"}");
            return false;
        }
        std::lock_guard<std::mutex> guard(lock_);
        if (!session_open_ || token != session_token_ || server_exiting_) {
            kernel_module::webui::send_json(
                connection, 401, "{\"result\":-1,\"stage\":\"session\"}");
            return false;
        }
        session_last_activity_ = std::chrono::steady_clock::now();
        return true;
    }

    bool handle_session_open(mg_connection* connection) {
        std::lock_guard<std::mutex> guard(lock_);
        if (!ready() || server_exiting_) {
            kernel_module::webui::send_json(
                connection, 503, "{\"result\":-1,\"stage\":\"server\"}");
            return true;
        }
        session_token_ = new_session_token();
        session_open_ = true;
        session_last_activity_ = std::chrono::steady_clock::now();
        shutdown_requested_ = false;
        kernel_module::webui::send_json(
            connection,
            200,
            std::string("{\"result\":0,\"session_token\":\"") +
                session_token_ +
                "\",\"heartbeat_ms\":" +
                std::to_string(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        kSessionIdleTimeout)
                        .count() /
                    3) +
                "}" );
        return true;
    }

    bool handle_session_ping(mg_connection* connection,
                             const std::string& body) {
        if (!authenticate_session(connection, body)) return true;
        kernel_module::webui::send_json(
            connection,
            200,
            std::string("{\"result\":0,\"heartbeat_ms\":") +
                std::to_string(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        kSessionIdleTimeout)
                        .count() /
                    3) +
                "}");
        return true;
    }

    bool handle_session_close(mg_connection* connection,
                              const std::string& body) {
        if (!authenticate_session(connection, body)) return true;
        {
            std::lock_guard<std::mutex> guard(lock_);
            session_open_ = false;
            session_token_.clear();
            request_server_close_locked();
        }
        kernel_module::webui::send_json(
            connection, 200, "{\"result\":0,\"closed\":true}");
        return true;
    }

    void request_server_close_locked() {
        if (shutdown_requested_ || server_ == nullptr || server_exiting_) {
            return;
        }
        shutdown_requested_ = true;
        CivetServer* server = server_;
        std::thread([server] {
            std::this_thread::sleep_for(kServerCloseDelay);
            if (server != nullptr) server->close();
        }).detach();
    }

    void session_watchdog() {
        for (;;) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            std::lock_guard<std::mutex> guard(lock_);
            if (server_ == nullptr || server_exiting_ ||
                shutdown_requested_) {
                continue;
            }
            const auto now = std::chrono::steady_clock::now();
            const auto idle = now - session_last_activity_;
            const auto limit = session_open_ ? kSessionIdleTimeout
                                             : kSessionOpenGrace;
            if (idle >= limit) request_server_close_locked();
        }
    }

    bool handle_status(mg_connection* connection) {
        std::lock_guard<std::mutex> guard(lock_);
        if (!ready()) {
            kernel_module::webui::send_json(
                connection,
                500,
                error_json(KModErr::ERR_MODULE_PARAM, "prepare"));
            return true;
        }
        drmid::ControlIpcResponse response{};
        KModErr err = drmid::send_control_ipc_request(
            socket_path_.c_str(),
            drmid::ControlIpcOperation::kStatus,
            response);
        if (is_failed(err)) {
            pid_t daemon_pid = -1;
            if (drmid::daemon_lock_owner_alive(
                    private_dir_.c_str(), daemon_pid)) {
                kernel_module::webui::send_json(
                    connection,
                    425,
                    "{\"result\":" + std::to_string(to_num(err)) +
                        ",\"stage\":\"daemon-starting\",\"daemon_pid\":" +
                        std::to_string(static_cast<long>(daemon_pid)) + "}");
            } else {
                kernel_module::webui::send_json(
                    connection, 503, error_json(err, "status-connect"));
            }
            return true;
        }
        drmid::ResolvedTargetConfig target;
        err = drmid::read_target_config_snapshot(
            private_dir_.c_str(), target);
        if (is_failed(err)) {
            kernel_module::webui::send_json(
                connection, 409, error_json(err, "target-status"));
            return true;
        }
        kernel_module::webui::send_json(
            connection,
            response.result == 0 ? 200 : 409,
            status_json(response, target, private_dir_.c_str()));
        return true;
    }

    bool handle_apps(mg_connection* connection) {
        std::lock_guard<std::mutex> guard(lock_);
        if (!ready()) {
            kernel_module::webui::send_json(
                connection,
                500,
                error_json(KModErr::ERR_MODULE_PARAM, "prepare"));
            return true;
        }
        std::vector<drmid::DeviceAppInfo> apps;
        bool truncated = false;
        const KModErr err = drmid::enumerate_device_apps(
            root_key_.c_str(), private_dir_.c_str(), apps, truncated);
        if (is_failed(err)) {
            kernel_module::webui::send_json(
                connection, 503, error_json(err, "apps-enumerate"));
            return true;
        }
        kernel_module::webui::send_json(
            connection, 200, apps_json(apps, truncated));
        return true;
    }

    bool handle_stop(mg_connection* connection) {
        std::lock_guard<std::mutex> guard(lock_);
        if (!ready()) {
            kernel_module::webui::send_json(
                connection,
                500,
                error_json(KModErr::ERR_MODULE_PARAM, "prepare"));
            return true;
        }
        drmid::ControlIpcResponse response{};
        const KModErr err = drmid::send_control_ipc_request(
            socket_path_.c_str(),
            drmid::ControlIpcOperation::kStop,
            response);
        kernel_module::webui::send_json(
            connection,
            is_failed(err) ? 503 : (response.result == 0 ? 200 : 409),
            is_failed(err) ? error_json(err, "stop-connect")
                           : drmid::control_response_json(response));
        return true;
    }

    bool handle_apply(mg_connection* connection, const std::string& body) {
        if (body.size() > 8192) {
            kernel_module::webui::send_json(
                connection,
                413,
                error_json(KModErr::ERR_MODULE_PARAM, "body-size"));
            return true;
        }
        std::string packages;
        std::string mode;
        std::string id_hex;
        std::string id_action;
        if (!form_value(body,
                        "packages",
                        packages,
                        drmid::kTargetPackagesFormMaxBytes) ||
            !form_value(body, "mode", mode, 8) ||
            !form_value(body, "id_hex", id_hex, kWidevineIdBytes * 2) ||
            !form_value(body, "id_action", id_action, 8)) {
            kernel_module::webui::send_json(
                connection,
                422,
                error_json(KModErr::ERR_MODULE_PARAM, "form"));
            return true;
        }
        if (packages.empty()) {
            kernel_module::webui::send_json(
                connection,
                422,
                error_json(KModErr::ERR_MODULE_PARAM, "packages-empty"));
            return true;
        }
        if ((mode != "dry" && mode != "write") ||
            (id_action != "keep" && id_action != "derive" &&
             id_action != "custom")) {
            kernel_module::webui::send_json(
                connection,
                422,
                error_json(KModErr::ERR_MODULE_PARAM, "mode-or-id-action"));
            return true;
        }

        std::lock_guard<std::mutex> guard(lock_);
        if (!ready()) {
            kernel_module::webui::send_json(
                connection,
                500,
                error_json(KModErr::ERR_MODULE_PARAM, "prepare"));
            return true;
        }

        drmid::ControlIpcResponse current{};
        KModErr err = drmid::send_control_ipc_request(
            socket_path_.c_str(),
            drmid::ControlIpcOperation::kStatus,
            current);
        if (is_failed(err) || current.result != 0) {
            kernel_module::webui::send_json(
                connection,
                503,
                is_failed(err) ? error_json(err, "status-connect")
                               : drmid::control_response_json(current));
            return true;
        }

        drmid::ResolvedTargetConfig target;
        {
            EnvironmentTargetScope target_scope(packages);
            err = drmid::load_or_resolve_target_config(
                root_key_.c_str(), private_dir_.c_str(), target);
        }
        if (is_failed(err)) {
            // No runtime record is written and no APPLY request is sent. The
            // active kernel slot therefore remains the previous generation.
            kernel_module::webui::send_json(
                connection, 422, error_json(err, "target", &target));
            return true;
        }

        drmid::RuntimeProfile profile;
        err = drmid::load_or_create_runtime_profile(
            false,
            private_dir_.c_str(),
            target.rule_mode,
            target.target_euid,
            target.profile_domain.empty()
                ? nullptr
                : target.profile_domain.c_str(),
            profile);
        if (is_failed(err)) {
            kernel_module::webui::send_json(
                connection, 500, error_json(err, "profile"));
            return true;
        }

        drmid::ReplacementConfig config;
        config.mode = mode == "write"
                          ? drmid::ReplacementMode::kWriteTest
                          : drmid::ReplacementMode::kDryRun;
        config.rule_mode = static_cast<uint32_t>(target.rule_mode);
        config.target_count = target.target_euids.size();
        if (config.target_count > drmid::kRuntimeTargetLimit) {
            kernel_module::webui::send_json(
                connection,
                422,
                error_json(KModErr::ERR_MODULE_PARAM, "target-count"));
            return true;
        }
        std::copy(target.target_euids.begin(),
                  target.target_euids.end(),
                  config.target_euids.begin());
        config.seed_generation = profile.seed_generation;
        config.virtual_id_length = kWidevineIdBytes;

        if (id_action == "keep") {
            drmid::ReplacementConfig persisted;
            err = drmid::read_runtime_control_file(
                control_path_.c_str(), persisted);
            if (is_failed(err) ||
                persisted.profile_fingerprint != current.profile_fingerprint) {
                kernel_module::webui::send_json(
                    connection,
                    409,
                    error_json(is_failed(err) ? err
                                              : KModErr::ERR_MODULE_STORAGE_TYPE,
                               "id-keep"));
                return true;
            }
            config.virtual_id = persisted.virtual_id;
            config.virtual_id_length = persisted.virtual_id_length;
            config.profile_fingerprint = persisted.profile_fingerprint;
            config.seed_generation = persisted.seed_generation;
        } else if (id_action == "derive") {
            config.virtual_id = profile.virtual_stream;
            config.profile_fingerprint = drmid::virtual_id_fingerprint(
                config.virtual_id.data(), config.virtual_id_length);
        } else if (decode_virtual_id(id_hex, config.virtual_id)) {
            config.profile_fingerprint = drmid::virtual_id_fingerprint(
                config.virtual_id.data(), config.virtual_id_length);
        } else {
            kernel_module::webui::send_json(
                connection,
                422,
                error_json(KModErr::ERR_MODULE_PARAM, "id-hex"));
            return true;
        }

        const bool no_op =
            !target.updated && active_targets_equal(current, target) &&
            current.rule_mode == config.rule_mode &&
            current.replacement_mode == static_cast<uint32_t>(config.mode) &&
            current.profile_fingerprint == config.profile_fingerprint &&
            current.virtual_id_length == config.virtual_id_length;
        if (no_op) {
            kernel_module::webui::send_json(
                connection,
                200,
                status_json(current, target, private_dir_.c_str()));
            return true;
        }

        const uint64_t base_generation =
            std::max(current.config_generation, target.generation);
        if (base_generation == std::numeric_limits<uint64_t>::max()) {
            kernel_module::webui::send_json(
                connection,
                409,
                error_json(KModErr::ERR_MODULE_PARAM, "generation"));
            return true;
        }
        config.config_generation = base_generation + 1;
        err = drmid::write_runtime_control_file(control_path_.c_str(), config);
        if (is_failed(err)) {
            kernel_module::webui::send_json(
                connection, 500, error_json(err, "persist"));
            return true;
        }

        drmid::ControlIpcResponse applied{};
        err = drmid::send_control_ipc_request(
            socket_path_.c_str(),
            drmid::ControlIpcOperation::kApply,
            applied);
        kernel_module::webui::send_json(
            connection,
            is_failed(err) ? 503 : (applied.result == 0 ? 200 : 409),
            is_failed(err) ? error_json(err, "apply-connect")
                           : status_json(
                                 applied, target, private_dir_.c_str()));
        return true;
    }

    std::mutex lock_;
    std::string root_key_;
    std::string private_dir_;
    std::string control_path_;
    std::string socket_path_;
    CivetServer* server_ = nullptr;
    std::string session_token_;
    std::chrono::steady_clock::time_point session_last_activity_{};
    bool session_open_ = false;
    bool shutdown_requested_ = false;
    bool server_exiting_ = false;
    std::atomic<bool> watchdog_started_{false};
};

} // namespace

SKROOT_MODULE_WEB_UI(DrmidWebHandler)
