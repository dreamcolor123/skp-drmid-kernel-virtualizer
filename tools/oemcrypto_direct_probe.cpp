#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

using OemCryptoResult = std::uint32_t;
using InitializeFn = OemCryptoResult (*)();
using TerminateFn = OemCryptoResult (*)();
using GetDeviceIdFn = OemCryptoResult (*)(std::uint8_t*, std::size_t*);

template <typename Function>
Function load_symbol(void* library, const char* name) {
    dlerror();
    void* symbol = dlsym(library, name);
    return dlerror() == nullptr ? reinterpret_cast<Function>(symbol) : nullptr;
}

bool read_expected(std::array<std::uint8_t, 32>& expected,
                   bool& configured) {
    expected.fill(0);
    configured = false;
    const char* path = std::getenv("DRMID_EXPECTED_FILE");
    if (path == nullptr || path[0] == '\0') return true;
    const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    std::size_t used = 0;
    while (used < expected.size()) {
        const ssize_t count = read(
            fd, expected.data() + used, expected.size() - used);
        if (count > 0) {
            used += static_cast<std::size_t>(count);
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    std::uint8_t extra = 0;
    const ssize_t tail = read(fd, &extra, 1);
    close(fd);
    configured = used == expected.size() && tail == 0;
    if (!configured) expected.fill(0);
    return configured;
}

int requested_repeats() {
    const char* text = std::getenv("DRMID_REPEAT");
    if (text == nullptr || text[0] == '\0') return 2;
    char* end = nullptr;
    const long value = std::strtol(text, &end, 10);
    return end != text && *end == '\0' && value >= 1 && value <= 1000
               ? static_cast<int>(value)
               : 2;
}

}  // namespace

int main() {
    constexpr char kLibrary[] = "/vendor/lib64/liboemcrypto.so";
    // These aliases are verified against the PLZ110 Android 16 vendor image.
    // They must be re-derived before this probe is used with another build.
    constexpr char kInitialize[] = "_oecc01";
    constexpr char kTerminate[] = "_oecc02";
    constexpr char kGetDeviceId[] = "_oecc07";

    void* library = dlopen(kLibrary, RTLD_NOW | RTLD_LOCAL);
    if (library == nullptr) {
        std::printf("[oemcrypto-probe] dlopen=error detail=%s\n", dlerror());
        return 2;
    }

    const auto initialize = load_symbol<InitializeFn>(library, kInitialize);
    const auto terminate = load_symbol<TerminateFn>(library, kTerminate);
    const auto get_device_id = load_symbol<GetDeviceIdFn>(library, kGetDeviceId);
    if (initialize == nullptr || terminate == nullptr || get_device_id == nullptr) {
        std::printf("[oemcrypto-probe] symbols=missing init=%s get=%s term=%s\n",
                    initialize != nullptr ? "yes" : "no",
                    get_device_id != nullptr ? "yes" : "no",
                    terminate != nullptr ? "yes" : "no");
        dlclose(library);
        return 3;
    }

    std::array<std::uint8_t, 32> expected{};
    bool expected_configured = false;
    if (!read_expected(expected, expected_configured)) {
        std::printf("[oemcrypto-probe] expected profile read failed\n");
        dlclose(library);
        return 6;
    }

    const OemCryptoResult initialize_result = initialize();
    if (initialize_result != 0) {
        std::printf("[oemcrypto-probe] initialize=%u\n", initialize_result);
        dlclose(library);
        return 4;
    }

    std::array<std::uint8_t, 256> first{};
    std::array<std::uint8_t, 256> current{};
    std::size_t first_length = 0;
    OemCryptoResult first_result = 0xffffffffU;
    OemCryptoResult second_result = 0xffffffffU;
    const int repeats = requested_repeats();
    int completed = 0;
    bool stable = true;
    bool expected_match = expected_configured;
    for (int index = 0; index < repeats; ++index) {
        current.fill(0);
        std::size_t current_length = current.size();
        const OemCryptoResult result =
            get_device_id(current.data(), &current_length);
        if (index == 0) first_result = result;
        if (index == 1) second_result = result;
        if (result != 0 || current_length > current.size()) {
            stable = false;
            break;
        }
        if (index == 0) {
            first = current;
            first_length = current_length;
        } else if (first_length != current_length ||
                   std::memcmp(first.data(), current.data(), first_length) != 0) {
            stable = false;
        }
        if (expected_configured &&
            (current_length != expected.size() ||
             std::memcmp(current.data(), expected.data(), expected.size()) != 0)) {
            expected_match = false;
        }
        ++completed;
    }
    stable = stable && completed == repeats;
    if (repeats == 1) second_result = first_result;
    bool expectation_pass = true;
    if (const char* enforce = std::getenv("DRMID_EXPECT_MATCH")) {
        if (std::strcmp(enforce, "1") == 0 ||
            std::strcmp(enforce, "yes") == 0) {
            expectation_pass = expected_match;
        } else if (std::strcmp(enforce, "0") == 0 ||
                   std::strcmp(enforce, "no") == 0) {
            expectation_pass = !expected_match;
        }
    }

    // Deliberately do not print identifier bytes or a reversible representation.
    std::printf("[oemcrypto-probe] get1=%u get2=%u length=%zu stable=%s "
                "expected_match=%s expectation=%s repeat=%d completed=%d\n",
                first_result,
                second_result,
                first_result == 0 ? first_length : 0,
                stable ? "yes" : "no",
                expected_configured ? (expected_match ? "yes" : "no")
                                    : "unconfigured",
                expectation_pass ? "pass" : "fail",
                repeats,
                completed);

    std::memset(first.data(), 0, first.size());
    std::memset(current.data(), 0, current.size());
    expected.fill(0);
    first_length = 0;
    first_result = 0;
    second_result = 0;
    const OemCryptoResult terminate_result = terminate();
    std::printf("[oemcrypto-probe] terminate=%u\n", terminate_result);
    dlclose(library);
    return stable && expectation_pass && terminate_result == 0 ? 0 : 5;
}
