#include <media/NdkMediaDrm.h>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

bool read_expected(std::vector<uint8_t>& expected) {
    expected.clear();
    const char* path = getenv("DRMID_EXPECTED_FILE");
    if (path == nullptr || path[0] == '\0') {
        return true;
    }
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
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
    if (used == 0 || used > 64) {
        return false;
    }
    expected.assign(buffer, buffer + used);
    return true;
}

int requested_repeats() {
    const char* value = getenv("DRMID_REPEAT");
    if (value == nullptr) {
        return 1;
    }
    char* end = nullptr;
    const long parsed = strtol(value, &end, 10);
    return end != value && *end == '\0' && parsed >= 1 && parsed <= 1000
               ? static_cast<int>(parsed)
               : 1;
}

} // namespace

int main() {
    constexpr uint8_t kWidevineUuid[16] = {
        0xed, 0xef, 0x8b, 0xa9,
        0x79, 0xd6,
        0x4a, 0xce,
        0xa3, 0xc8,
        0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed,
    };

    AMediaDrm* drm = AMediaDrm_createByUUID(kWidevineUuid);
    if (drm == nullptr) {
        std::printf("[media-probe] create Widevine failed\n");
        return 2;
    }

    const char* security_level = nullptr;
    const media_status_t security_status = AMediaDrm_getPropertyString(
        drm, "securityLevel", &security_level);
    std::printf("[media-probe] securityLevel status=%d value=%s\n",
                static_cast<int>(security_status),
                security_status == AMEDIA_OK && security_level != nullptr
                    ? security_level
                    : "-");

    std::vector<uint8_t> expected;
    if (!read_expected(expected)) {
        std::printf("[media-probe] expected profile read failed\n");
        AMediaDrm_release(drm);
        return 4;
    }
    const int repeats = requested_repeats();
    std::vector<uint8_t> first;
    AMediaDrmByteArray value{};
    media_status_t status = AMEDIA_OK;
    bool stable = true;
    bool expected_match = !expected.empty();
    size_t observed_length = 0;
    for (int i = 0; i < repeats; ++i) {
        value = {};
        status = AMediaDrm_getPropertyByteArray(drm, "deviceUniqueId", &value);
        if (status != AMEDIA_OK || value.ptr == nullptr) {
            stable = false;
            break;
        }
        observed_length = value.length;
        if (i == 0) {
            first.assign(value.ptr, value.ptr + value.length);
        } else if (first.size() != value.length ||
                   std::memcmp(first.data(), value.ptr, value.length) != 0) {
            stable = false;
        }
        if (!expected.empty() &&
            (expected.size() != value.length ||
             std::memcmp(expected.data(), value.ptr, value.length) != 0)) {
            expected_match = false;
        }
    }
    const char* expected_text = expected.empty()
                                    ? "unconfigured"
                                    : (expected_match ? "yes" : "no");
    bool expectation_pass = true;
    if (const char* enforce = getenv("DRMID_EXPECT_MATCH")) {
        if (strcmp(enforce, "1") == 0 || strcmp(enforce, "yes") == 0) {
            expectation_pass = expected_match;
        } else if (strcmp(enforce, "0") == 0 || strcmp(enforce, "no") == 0) {
            expectation_pass = !expected_match;
        }
    }
    // Identifier bytes and their digest are never printed.
    std::printf("[media-probe] deviceUniqueId status=%d length=%zu repeat=%d "
                "stable=%s expected_match=%s expectation=%s euid=%u\n",
                static_cast<int>(status),
                status == AMEDIA_OK ? observed_length : 0U,
                repeats,
                stable ? "yes" : "no",
                expected_text,
                expectation_pass ? "pass" : "fail",
                static_cast<unsigned>(geteuid()));
    AMediaDrm_release(drm);
    return status == AMEDIA_OK && stable && expectation_pass ? 0 : 3;
}
