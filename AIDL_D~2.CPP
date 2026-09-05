#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <android/binder_status.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr char kFactoryDescriptor[] = "android.hardware.drm.IDrmFactory";
constexpr char kPluginDescriptor[] = "android.hardware.drm.IDrmPlugin";
constexpr char kWidevineService[] =
    "android.hardware.drm.IDrmFactory/widevine";
// libbinder consumes this private flag to permit a vendor-stability proxy
// transaction; it is not forwarded as a Binder transaction flag.
constexpr binder_flags_t kPrivateVendor = 0x10000000U;
constexpr std::array<int8_t, 16> kWidevineUuid = {
    static_cast<int8_t>(0xed), static_cast<int8_t>(0xef),
    static_cast<int8_t>(0x8b), static_cast<int8_t>(0xa9),
    0x79, static_cast<int8_t>(0xd6), 0x4a, static_cast<int8_t>(0xce),
    static_cast<int8_t>(0xa3), static_cast<int8_t>(0xc8),
    0x27, static_cast<int8_t>(0xdc), static_cast<int8_t>(0xd5),
    0x1d, 0x21, static_cast<int8_t>(0xed),
};

void* binder_class_create(void*) { return nullptr; }
void binder_class_destroy(void*) {}
binder_status_t binder_class_transact(
    AIBinder*, transaction_code_t, const AParcel*, AParcel*) {
    return STATUS_UNKNOWN_TRANSACTION;
}

AIBinder_Class* factory_class() {
    static AIBinder_Class* value = AIBinder_Class_define(
        kFactoryDescriptor,
        binder_class_create,
        binder_class_destroy,
        binder_class_transact);
    return value;
}

AIBinder_Class* plugin_class() {
    static AIBinder_Class* value = AIBinder_Class_define(
        kPluginDescriptor,
        binder_class_create,
        binder_class_destroy,
        binder_class_transact);
    return value;
}

bool write_uuid(AParcel* parcel) {
    const int32_t start = AParcel_getDataPosition(parcel);
    if (start < 0 || AParcel_writeInt32(parcel, 0) != STATUS_OK ||
        AParcel_writeByteArray(
            parcel, kWidevineUuid.data(), kWidevineUuid.size()) != STATUS_OK) {
        return false;
    }
    const int32_t end = AParcel_getDataPosition(parcel);
    return end >= start && AParcel_setDataPosition(parcel, start) == STATUS_OK &&
           AParcel_writeInt32(parcel, end - start) == STATUS_OK &&
           AParcel_setDataPosition(parcel, end) == STATUS_OK;
}

bool read_status_ok(const AParcel* parcel, const char* operation) {
    AStatus* status = nullptr;
    const binder_status_t read = AParcel_readStatusHeader(parcel, &status);
    if (read != STATUS_OK || status == nullptr) {
        std::printf("[aidl-probe] %s status-header=%d\n", operation, read);
        if (status != nullptr) AStatus_delete(status);
        return false;
    }
    const bool ok = AStatus_isOk(status);
    if (!ok) {
        std::printf(
            "[aidl-probe] %s exception=%d service=%d transport=%d\n",
            operation,
            AStatus_getExceptionCode(status),
            AStatus_getServiceSpecificError(status),
            AStatus_getStatus(status));
    }
    AStatus_delete(status);
    return ok;
}

bool read_bytes_allocator(void* opaque, int32_t length, int8_t** out) {
    auto* value = static_cast<std::vector<uint8_t>*>(opaque);
    value->clear();
    if (length < 0 || length > 4096) return false;
    value->resize(static_cast<size_t>(length));
    *out = length == 0 ? nullptr : reinterpret_cast<int8_t*>(value->data());
    return true;
}

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

using CheckServiceFn = AIBinder* (*)(const char*);

} // namespace

int main() {
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

    AIBinder* factory = check_service(kWidevineService);
    if (factory == nullptr) {
        std::printf("[aidl-probe] Widevine factory missing\n");
        dlclose(library);
        return 3;
    }
    if (!AIBinder_associateClass(factory, factory_class())) {
        std::printf("[aidl-probe] factory class association failed\n");
        AIBinder_decStrong(factory);
        dlclose(library);
        return 4;
    }

    AParcel* input = nullptr;
    AParcel* output = nullptr;
    int create_stage = 1;
    binder_status_t transport = AIBinder_prepareTransaction(factory, &input);
    if (transport == STATUS_OK) create_stage = 2;
    if (transport == STATUS_OK && !write_uuid(input)) transport = STATUS_BAD_VALUE;
    if (transport == STATUS_OK) create_stage = 3;
    constexpr char kPackage[] = "com.drmid.kernel.probe";
    if (transport == STATUS_OK) {
        transport = AParcel_writeString(
            input, kPackage, static_cast<int32_t>(sizeof(kPackage) - 1));
    }
    if (transport == STATUS_OK) create_stage = 4;
    if (transport == STATUS_OK) {
        transport = AIBinder_transact(
            factory, 1, &input, &output, kPrivateVendor);
    }
    if (transport == STATUS_OK) create_stage = 5;
    if (transport != STATUS_OK || output == nullptr ||
        !read_status_ok(output, "createDrmPlugin")) {
        std::printf("[aidl-probe] create stage=%d transport=%d\n",
                    create_stage, transport);
        if (input != nullptr) AParcel_delete(input);
        if (output != nullptr) AParcel_delete(output);
        AIBinder_decStrong(factory);
        dlclose(library);
        return 5;
    }

    AIBinder* plugin = nullptr;
    transport = AParcel_readStrongBinder(output, &plugin);
    AParcel_delete(output);
    output = nullptr;
    AIBinder_decStrong(factory);
    if (transport != STATUS_OK || plugin == nullptr ||
        !AIBinder_associateClass(plugin, plugin_class())) {
        std::printf("[aidl-probe] plugin binder status=%d present=%s\n",
                    transport, plugin == nullptr ? "no" : "yes");
        if (plugin != nullptr) AIBinder_decStrong(plugin);
        dlclose(library);
        return 6;
    }

    std::vector<uint8_t> expected;
    if (!read_expected(expected)) {
        std::printf("[aidl-probe] expected profile read failed\n");
        AIBinder_decStrong(plugin);
        dlclose(library);
        return 7;
    }

    const int repeats = repeat_count();
    std::vector<uint8_t> first;
    bool stable = true;
    bool expected_match = !expected.empty();
    for (int index = 0; index < repeats; ++index) {
        input = nullptr;
        output = nullptr;
        transport = AIBinder_prepareTransaction(plugin, &input);
        constexpr char kProperty[] = "deviceUniqueId";
        if (transport == STATUS_OK) {
            transport = AParcel_writeString(
                input, kProperty, static_cast<int32_t>(sizeof(kProperty) - 1));
        }
        if (transport == STATUS_OK) {
            // IDrmPlugin.getPropertyByteArray is the eleventh declared method.
            transport = AIBinder_transact(
                plugin, 11, &input, &output, kPrivateVendor);
        }
        std::vector<uint8_t> value;
        if (transport != STATUS_OK || output == nullptr ||
            !read_status_ok(output, "getPropertyByteArray") ||
            AParcel_readByteArray(output, &value, read_bytes_allocator) !=
                STATUS_OK) {
            stable = false;
            if (input != nullptr) AParcel_delete(input);
            if (output != nullptr) AParcel_delete(output);
            break;
        }
        AParcel_delete(output);
        if (index == 0) {
            first = value;
        } else if (value != first) {
            stable = false;
        }
        if (!expected.empty() && value != expected) expected_match = false;
    }

    std::printf(
        "[aidl-probe] create=yes deviceUniqueId length=%zu repeat=%d "
        "stable=%s expected_match=%s euid=%u\n",
        first.size(),
        repeats,
        stable ? "yes" : "no",
        expected.empty() ? "unconfigured" : (expected_match ? "yes" : "no"),
        static_cast<unsigned>(geteuid()));
    AIBinder_decStrong(plugin);
    dlclose(library);
    return stable && !first.empty() ? 0 : 8;
}
