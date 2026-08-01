#include <android/binder_auto_utils.h>
#include <android/binder_ibinder.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>

#include <aidl/android/hardware/drm/IDrmFactory.h>
#include <aidl/android/hardware/drm/IDrmPlugin.h>
#include <aidl/android/hardware/drm/BpDrmFactory.h>
#include <aidl/android/hardware/drm/BpDrmPlugin.h>
#include <aidl/android/hardware/drm/Uuid.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace {

constexpr char kWidevineService[] =
    "android.hardware.drm.IDrmFactory/widevine";
constexpr uint8_t kWidevineUuid[16] = {
    0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce,
    0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed,
};

using CheckServiceFn = AIBinder* (*)(const char*);

bool read_expected(std::vector<uint8_t>& expected) {
    expected.clear();
    const char* path = std::getenv("DRMID_EXPECTED_FILE");
    if (path == nullptr || path[0] == '\0') return true;
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    uint8_t buffer[65]{};
    size_t used = 0;
    while (used < sizeof(buffer)) {
        const ssize_t count = read(fd, buffer + used, sizeof(buffer) - used);
        if (count > 0) {
            used += static_cast<size_t>(count);
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    close(fd);
    if (used == 0 || used > 64) return false;
    expected.assign(buffer, buffer + used);
    return true;
}

int repeat_count() {
    const char* text = std::getenv("DRMID_REPEAT");
    if (text == nullptr) return 1;
    char* end = nullptr;
    const long value = std::strtol(text, &end, 10);
    return end != text && *end == '\0' && value >= 1 && value <= 1000
               ? static_cast<int>(value)
               : 1;
}

void print_status(const char* operation, const ::ndk::ScopedAStatus& status) {
    if (status.get() == nullptr) {
        std::printf("[aidl-probe] %s status=null\n", operation);
        return;
    }
    std::printf(
        "[aidl-probe] %s exception=%d service=%d transport=%d\n",
        operation,
        status.getExceptionCode(),
        status.getServiceSpecificError(),
        status.getStatus());
}

} // namespace

int main() {
    // The device acceptance fixture exports the expected ID as root/0600.
    // Snapshot it before dropping to the target application EUID; all later
    // comparisons use this in-memory copy.
    std::vector<uint8_t> expected;
    if (!read_expected(expected)) {
        std::printf("[aidl-probe] expected profile read failed\n");
        return 6;
    }

    if (const char* drop_text = std::getenv("DRMID_DROP_EUID")) {
        char* end = nullptr;
        const unsigned long value = std::strtoul(drop_text, &end, 10);
        if (end == drop_text || *end != '\0' || value > UINT32_MAX ||
            setuid(static_cast<uid_t>(value)) != 0) {
            std::printf("[aidl-probe] setuid failed errno=%d\n", errno);
            return 1;
        }
    }
    void* library = dlopen("libbinder_ndk.so", RTLD_NOW | RTLD_LOCAL);
    auto check_service = library == nullptr
                             ? nullptr
                             : reinterpret_cast<CheckServiceFn>(
                                   dlsym(library, "AServiceManager_checkService"));
    if (check_service == nullptr) {
        std::printf("[aidl-probe] service-manager symbol missing\n");
        if (library != nullptr) dlclose(library);
        return 2;
    }

    ::ndk::SpAIBinder factory_binder(check_service(kWidevineService));
    if (factory_binder.get() == nullptr) {
        std::printf("[aidl-probe] Widevine factory missing\n");
        dlclose(library);
        return 3;
    }
    auto factory =
        ::aidl::android::hardware::drm::IDrmFactory::fromBinder(factory_binder);
    if (!factory) {
        std::printf("[aidl-probe] factory proxy creation failed\n");
        dlclose(library);
        return 4;
    }

    ::aidl::android::hardware::drm::Uuid uuid;
    std::memcpy(uuid.uuid.data(), kWidevineUuid, sizeof(kWidevineUuid));
    std::shared_ptr<::aidl::android::hardware::drm::IDrmPlugin> plugin;
    auto factory_proxy = std::static_pointer_cast<
        ::aidl::android::hardware::drm::BpDrmFactory>(factory);
    const auto create = factory_proxy->BpDrmFactory::createDrmPlugin(
        uuid, "com.drmid.kernel.probe", &plugin);
    if (!create.isOk() || !plugin) {
        print_status("createDrmPlugin", create);
        dlclose(library);
        return 5;
    }

    const int repeats = repeat_count();
    auto plugin_proxy = std::static_pointer_cast<
        ::aidl::android::hardware::drm::BpDrmPlugin>(plugin);
    std::vector<uint8_t> first;
    bool stable = true;
    bool expected_match = !expected.empty();
    for (int index = 0; index < repeats; ++index) {
        std::vector<uint8_t> value;
        const auto status = plugin_proxy->BpDrmPlugin::getPropertyByteArray(
            "deviceUniqueId", &value);
        if (!status.isOk()) {
            print_status("getPropertyByteArray", status);
            stable = false;
            break;
        }
        if (index == 0) {
            first = value;
        } else if (value != first) {
            stable = false;
        }
        if (!expected.empty() && value != expected) expected_match = false;
    }

    if (const char* done_file = std::getenv("DRMID_DONE_FILE")) {
        const int fd = open(done_file,
                            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                            0644);
        std::printf("[aidl-probe] marker=%s errno=%d\n",
                    fd >= 0 ? "ok" : "error",
                    fd >= 0 ? 0 : errno);
        if (fd >= 0) close(fd);
    }
    std::printf(
        "[aidl-probe] create=yes deviceUniqueId length=%zu repeat=%d "
        "stable=%s expected_match=%s pid=%u euid=%u\n",
        first.size(),
        repeats,
        stable ? "yes" : "no",
        expected.empty() ? "unconfigured" : (expected_match ? "yes" : "no"),
        static_cast<unsigned>(getpid()),
        static_cast<unsigned>(geteuid()));
    plugin.reset();
    plugin_proxy.reset();
    factory_proxy.reset();
    factory.reset();
    dlclose(library);
    return stable && !first.empty() ? 0 : 7;
}
