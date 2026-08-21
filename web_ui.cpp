#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>

#include "control_ipc.h"
#include "device_id_fingerprint.h"
#include "file_lifecycle.h"
#include "kernel_module_kit_umbrella.h"
#include "runtime_control.h"
#include "runtime_profile.h"

namespace {

constexpr size_t kWidevineIdBytes = drmid::kWidevineDeviceUniqueIdBytes;
constexpr size_t kSessionTokenBytes = 16;
constexpr size_t kSessionTokenHexBytes = kSessionTokenBytes * 2;
constexpr auto kSessionOpenGrace = std::chrono::seconds(15);
constexpr auto kSessionIdleTimeout = std::chrono::seconds(12);
constexpr auto kServerCloseDelay = std::chrono::milliseconds(80);
static_assert(kWidevineIdBytes == drmid::kVirtualIdBytes);

std::string error_json(KModErr err, const char* stage) {
    return std::string("{\"result\":") + std::to_string(to_num(err)) +
           ",\"stage\":\"" + stage + "\"}";
}

std::string status_json(const drmid::ControlIpcResponse& response,
                        const char* module_private_dir) {
    std::string json = drmid::control_response_json(response);
    if (!json.empty() && json.back() == '}') json.pop_back();
    uint64_t device_fingerprint = 0;
    const KModErr fingerprint_err = drmid::read_original_id_fingerprint(
        module_private_dir, device_fingerprint);
    if (is_ok(fingerprint_err) && device_fingerprint != 0) {
        char text[17]{};
        std::snprintf(text, sizeof(text), "%016" PRIx64, device_fingerprint);
        json += ",\"device_fingerprint\":\"" + std::string(text) + "\"";
    } else {
        json += ",\"device_fingerprint\":\"\"";
    }
    json += "}";
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

bool fill_random_id(std::array<uint8_t, drmid::kVirtualStreamBytes>& out) {
    out = {};
    const int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    const bool ok = read_full(fd, out.data(), kWidevineIdBytes);
    close(fd);
    return ok;
}

std::string new_session_token() {
    std::array<uint8_t, kSessionTokenBytes> bytes{};
    const int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0 || !read_full(fd, bytes.data(), bytes.size())) {
        if (fd >= 0) close(fd);
        return {};
    }
    close(fd);
    static constexpr char kHex[] = "0123456789abcdef";
    std::string token;
    token.reserve(kSessionTokenHexBytes);
    for (const uint8_t byte : bytes) {
        token.push_back(kHex[byte >> 4]);
        token.push_back(kHex[byte & 0x0f]);
    }
    return token;
}

bool decode_virtual_id(
    const std::string& text,
    std::array<uint8_t, drmid::kVirtualStreamBytes>& out) {
    out = {};
    if (text.size() != kWidevineIdBytes * 2) return false;
    for (size_t index = 0; index < kWidevineIdBytes; ++index) {
        const int high = hex_nibble(text[index * 2]);
        const int low = hex_nibble(text[index * 2 + 1]);
        if (high < 0 || low < 0) return false;
        out[index] = static_cast<uint8_t>((high << 4) | low);
    }
    return true;
}

class DrmidWebHandler : public kernel_module::WebUIHttpHandler {
public:
    void onPrepareCreate(const char* root_key,
                         const char* module_private_dir,
                         uint32_t port) override {
        std::lock_guard<std::mutex> guard(lock_);
        (void)root_key;
        private_dir_ = module_private_dir != nullptr ? module_private_dir : "";
        control_path_ =
            drmid::default_runtime_control_path(private_dir_.c_str());
        socket_path_ =
            drmid::default_control_socket_path(private_dir_.c_str());
        printf("[drmid612] global HAL WebUI ready port=%u private_dir=%s\n",
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
        if (path == "/api/apply") return handle_apply(connection, body);
        if (path == "/api/stop") return handle_stop(connection);
        kernel_module::webui::send_json(
            connection, 404, "{\"result\":-1,\"stage\":\"route\"}");
        return true;
    }

private:
    bool ready() const {
        return !private_dir_.empty() && !control_path_.empty() &&
               !socket_path_.empty();
    }

    bool authenticate_session(mg_connection* connection,
                              const std::string& body) {
        std::string token;
        if (!form_value(body, "session_token", token,
                        kSessionTokenHexBytes)) {
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
        if (session_token_.size() != kSessionTokenHexBytes) {
            kernel_module::webui::send_json(
                connection, 500, "{\"result\":-1,\"stage\":\"random\"}");
            return true;
        }
        session_open_ = true;
        session_last_activity_ = std::chrono::steady_clock::now();
        shutdown_requested_ = false;
        kernel_module::webui::send_json(
            connection,
            200,
            std::string("{\"result\":0,\"session_token\":\"") +
                session_token_ + "\",\"heartbeat_ms\":4000}");
        return true;
    }

    bool handle_session_ping(mg_connection* connection,
                             const std::string& body) {
        if (!authenticate_session(connection, body)) return true;
        kernel_module::webui::send_json(
            connection, 200, "{\"result\":0,\"heartbeat_ms\":4000}");
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
        if (shutdown_requested_ || server_ == nullptr || server_exiting_) return;
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
            if (server_ == nullptr || server_exiting_ || shutdown_requested_) {
                continue;
            }
            const auto idle =
                std::chrono::steady_clock::now() - session_last_activity_;
            const auto limit = session_open_ ? kSessionIdleTimeout
                                             : kSessionOpenGrace;
            if (idle >= limit) request_server_close_locked();
        }
    }

    bool handle_status(mg_connection* connection) {
        std::lock_guard<std::mutex> guard(lock_);
        if (!ready()) {
            kernel_module::webui::send_json(
                connection, 500,
                error_json(KModErr::ERR_MODULE_PARAM, "prepare"));
            return true;
        }
        drmid::ControlIpcResponse response{};
        const KModErr err = drmid::send_control_ipc_request(
            socket_path_.c_str(), drmid::ControlIpcOperation::kStatus,
            response);
        if (is_failed(err)) {
            pid_t daemon_pid = -1;
            if (drmid::daemon_lock_owner_alive(private_dir_.c_str(),
                                                daemon_pid)) {
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
        kernel_module::webui::send_json(
            connection,
            response.result == 0 ? 200 : 409,
            status_json(response, private_dir_.c_str()));
        return true;
    }

    bool handle_stop(mg_connection* connection) {
        std::lock_guard<std::mutex> guard(lock_);
        drmid::ControlIpcResponse response{};
        const KModErr err = ready()
            ? drmid::send_control_ipc_request(
                  socket_path_.c_str(), drmid::ControlIpcOperation::kStop,
                  response)
            : KModErr::ERR_MODULE_PARAM;
        kernel_module::webui::send_json(
            connection,
            is_failed(err) ? 503 : (response.result == 0 ? 200 : 409),
            is_failed(err) ? error_json(err, "stop-connect")
                           : drmid::control_response_json(response));
        return true;
    }

    bool handle_apply(mg_connection* connection, const std::string& body) {
        if (body.size() > 4096) {
            kernel_module::webui::send_json(
                connection, 413,
                error_json(KModErr::ERR_MODULE_PARAM, "body-size"));
            return true;
        }
        std::string mode;
        std::string id_action;
        std::string id_hex;
        if (!form_value(body, "mode", mode, 8) ||
            !form_value(body, "id_action", id_action, 8) ||
            !form_value(body, "id_hex", id_hex, kWidevineIdBytes * 2) ||
            (mode != "dry" && mode != "write") ||
            (id_action != "keep" && id_action != "derive" &&
             id_action != "random" && id_action != "custom")) {
            kernel_module::webui::send_json(
                connection, 422,
                error_json(KModErr::ERR_MODULE_PARAM, "form"));
            return true;
        }

        std::lock_guard<std::mutex> guard(lock_);
        if (!ready()) {
            kernel_module::webui::send_json(
                connection, 500,
                error_json(KModErr::ERR_MODULE_PARAM, "prepare"));
            return true;
        }
        drmid::ControlIpcResponse current{};
        KModErr err = drmid::send_control_ipc_request(
            socket_path_.c_str(), drmid::ControlIpcOperation::kStatus,
            current);
        if (is_failed(err) || current.result != 0) {
            kernel_module::webui::send_json(
                connection, 503,
                is_failed(err) ? error_json(err, "status-connect")
                               : drmid::control_response_json(current));
            return true;
        }

        drmid::ReplacementConfig persisted{};
        err = drmid::read_runtime_control_file(
            control_path_.c_str(), persisted);
        if (is_failed(err)) {
            kernel_module::webui::send_json(
                connection, 409, error_json(err, "control-read"));
            return true;
        }
        drmid::ReplacementConfig config = persisted;
        config.mode = mode == "write" ? drmid::ReplacementMode::kWriteTest
                                      : drmid::ReplacementMode::kDryRun;
        config.virtual_id_length = kWidevineIdBytes;

        if (id_action == "derive") {
            drmid::RuntimeProfile profile;
            err = drmid::load_or_create_runtime_profile(
                false, private_dir_.c_str(), profile);
            if (is_failed(err)) {
                kernel_module::webui::send_json(
                    connection, 500, error_json(err, "profile"));
                return true;
            }
            config.virtual_id = profile.virtual_stream;
            config.seed_generation = profile.seed_generation;
        } else if (id_action == "random") {
            if (!fill_random_id(config.virtual_id)) {
                kernel_module::webui::send_json(
                    connection, 500,
                    error_json(KModErr::ERR_MODULE_STORAGE_READ, "random"));
                return true;
            }
        } else if (id_action == "custom") {
            if (!decode_virtual_id(id_hex, config.virtual_id)) {
                kernel_module::webui::send_json(
                    connection, 422,
                    error_json(KModErr::ERR_MODULE_PARAM, "id-hex"));
                return true;
            }
        }
        config.profile_fingerprint = drmid::virtual_id_fingerprint(
            config.virtual_id.data(), config.virtual_id_length);

        const bool no_op =
            current.replacement_mode == static_cast<uint32_t>(config.mode) &&
            current.profile_fingerprint == config.profile_fingerprint &&
            current.virtual_id_length == config.virtual_id_length;
        if (no_op) {
            kernel_module::webui::send_json(
                connection, 200,
                status_json(current, private_dir_.c_str()));
            return true;
        }
        if (current.config_generation ==
            std::numeric_limits<uint64_t>::max()) {
            kernel_module::webui::send_json(
                connection, 409,
                error_json(KModErr::ERR_MODULE_PARAM, "generation"));
            return true;
        }
        config.config_generation = current.config_generation + 1;
        err = drmid::write_runtime_control_file(
            control_path_.c_str(), config);
        if (is_failed(err)) {
            kernel_module::webui::send_json(
                connection, 500, error_json(err, "persist"));
            return true;
        }

        drmid::ControlIpcResponse applied{};
        err = drmid::send_control_ipc_request(
            socket_path_.c_str(), drmid::ControlIpcOperation::kApply, applied);
        kernel_module::webui::send_json(
            connection,
            is_failed(err) ? 503 : (applied.result == 0 ? 200 : 409),
            is_failed(err) ? error_json(err, "apply-connect")
                           : status_json(applied, private_dir_.c_str()));
        return true;
    }

    std::mutex lock_;
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
