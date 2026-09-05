#include "runtime_profile.h"

#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace drmid {
namespace {

constexpr char kSeedFileName[] = "drmid_seed_record_v1.bin";
constexpr uint64_t kSeedMagic = 0x30354445534d5244ULL; // "DRMSED50"
constexpr uint32_t kSeedVersion = 1;

struct SeedRecord {
    uint64_t magic;
    uint32_t version;
    uint32_t seed_size;
    uint64_t generation;
    uint8_t seed[kSeedBytes];
    uint32_t crc32;
    uint32_t reserved;
};

static_assert(offsetof(SeedRecord, crc32) == 56);
static_assert(sizeof(SeedRecord) == 64);

constexpr uint32_t rotr(uint32_t value, uint32_t bits) {
    return (value >> bits) | (value << (32 - bits));
}

class Sha256 {
public:
    Sha256() { reset(); }

    void reset() {
        state_ = {
            0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
            0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
        };
        total_bytes_ = 0;
        buffered_ = 0;
        buffer_.fill(0);
    }

    void update(const void* input, size_t length) {
        const auto* data = static_cast<const uint8_t*>(input);
        total_bytes_ += length;
        while (length != 0) {
            const size_t take = std::min(length, buffer_.size() - buffered_);
            std::memcpy(buffer_.data() + buffered_, data, take);
            buffered_ += take;
            data += take;
            length -= take;
            if (buffered_ == buffer_.size()) {
                transform(buffer_.data());
                buffered_ = 0;
            }
        }
    }

    std::array<uint8_t, 32> finish() {
        const uint64_t total_bits = total_bytes_ * 8;
        buffer_[buffered_++] = 0x80;
        if (buffered_ > 56) {
            std::fill(buffer_.begin() + buffered_, buffer_.end(), 0);
            transform(buffer_.data());
            buffered_ = 0;
        }
        std::fill(buffer_.begin() + buffered_, buffer_.begin() + 56, 0);
        for (size_t i = 0; i < 8; ++i) {
            buffer_[63 - i] = static_cast<uint8_t>(total_bits >> (i * 8));
        }
        transform(buffer_.data());

        std::array<uint8_t, 32> digest{};
        for (size_t i = 0; i < state_.size(); ++i) {
            digest[i * 4 + 0] = static_cast<uint8_t>(state_[i] >> 24);
            digest[i * 4 + 1] = static_cast<uint8_t>(state_[i] >> 16);
            digest[i * 4 + 2] = static_cast<uint8_t>(state_[i] >> 8);
            digest[i * 4 + 3] = static_cast<uint8_t>(state_[i]);
        }
        return digest;
    }

private:
    void transform(const uint8_t block[64]) {
        static constexpr uint32_t k[64] = {
            0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
            0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
            0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
            0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
            0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
            0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
            0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
            0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
            0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
            0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
            0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
            0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
            0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
            0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
            0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
            0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
        };
        uint32_t w[64]{};
        for (size_t i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                   static_cast<uint32_t>(block[i * 4 + 3]);
        }
        for (size_t i = 16; i < 64; ++i) {
            const uint32_t s0 = rotr(w[i - 15], 7) ^
                                rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const uint32_t s1 = rotr(w[i - 2], 17) ^
                                rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = state_[0];
        uint32_t b = state_[1];
        uint32_t c = state_[2];
        uint32_t d = state_[3];
        uint32_t e = state_[4];
        uint32_t f = state_[5];
        uint32_t g = state_[6];
        uint32_t h = state_[7];
        for (size_t i = 0; i < 64; ++i) {
            const uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const uint32_t ch = (e & f) ^ ((~e) & g);
            const uint32_t t1 = h + s1 + ch + k[i] + w[i];
            const uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2 = s0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    std::array<uint32_t, 8> state_{};
    std::array<uint8_t, 64> buffer_{};
    uint64_t total_bytes_ = 0;
    size_t buffered_ = 0;
};

std::array<uint8_t, 32> sha256(const void* data, size_t size) {
    Sha256 hash;
    hash.update(data, size);
    return hash.finish();
}

std::array<uint8_t, 32> hmac_sha256(const uint8_t* key,
                                    size_t key_size,
                                    const uint8_t* data,
                                    size_t data_size) {
    std::array<uint8_t, 64> normalized{};
    if (key_size > normalized.size()) {
        const auto digest = sha256(key, key_size);
        std::copy(digest.begin(), digest.end(), normalized.begin());
    } else if (key_size != 0) {
        std::memcpy(normalized.data(), key, key_size);
    }
    std::array<uint8_t, 64> inner_pad{};
    std::array<uint8_t, 64> outer_pad{};
    for (size_t i = 0; i < normalized.size(); ++i) {
        inner_pad[i] = normalized[i] ^ 0x36;
        outer_pad[i] = normalized[i] ^ 0x5c;
    }
    Sha256 inner;
    inner.update(inner_pad.data(), inner_pad.size());
    inner.update(data, data_size);
    const auto inner_digest = inner.finish();
    Sha256 outer;
    outer.update(outer_pad.data(), outer_pad.size());
    outer.update(inner_digest.data(), inner_digest.size());
    return outer.finish();
}

bool hkdf_sha256(const uint8_t* ikm,
                 size_t ikm_size,
                 const uint8_t* salt,
                 size_t salt_size,
                 const uint8_t* info,
                 size_t info_size,
                 uint8_t* output,
                 size_t output_size) {
    if (output_size > 255 * 32) {
        return false;
    }
    const auto prk = hmac_sha256(salt, salt_size, ikm, ikm_size);
    std::array<uint8_t, 32> previous{};
    size_t previous_size = 0;
    size_t produced = 0;
    uint8_t counter = 1;
    while (produced < output_size) {
        std::vector<uint8_t> input;
        input.reserve(previous_size + info_size + 1);
        input.insert(input.end(), previous.begin(), previous.begin() + previous_size);
        input.insert(input.end(), info, info + info_size);
        input.push_back(counter++);
        previous = hmac_sha256(
            prk.data(), prk.size(), input.data(), input.size());
        previous_size = previous.size();
        const size_t take = std::min(previous.size(), output_size - produced);
        std::memcpy(output + produced, previous.data(), take);
        produced += take;
    }
    return true;
}

uint32_t crc32(const void* data, size_t size) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    uint32_t crc = 0xffffffffU;
    for (size_t i = 0; i < size; ++i) {
        crc ^= bytes[i];
        for (int bit = 0; bit < 8; ++bit) {
            const uint32_t mask = 0U - (crc & 1U);
            crc = (crc >> 1) ^ (0xedb88320U & mask);
        }
    }
    return ~crc;
}

bool fill_random(uint8_t* output, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        const ssize_t count = getrandom(output + offset, size - offset, 0);
        if (count > 0) {
            offset += static_cast<size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    if (offset == size) {
        return true;
    }
    const int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    offset = 0;
    while (offset < size) {
        const ssize_t count = read(fd, output + offset, size - offset);
        if (count > 0) {
            offset += static_cast<size_t>(count);
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            close(fd);
            return false;
        }
    }
    close(fd);
    return true;
}

bool validate_seed_record(const SeedRecord& record) {
    return record.magic == kSeedMagic && record.version == kSeedVersion &&
           record.seed_size == kSeedBytes && record.generation != 0 &&
           record.crc32 == crc32(&record, offsetof(SeedRecord, crc32));
}

std::string seed_path(const char* module_private_dir) {
    std::string path(module_private_dir);
    if (!path.empty() && path.back() != '/') {
        path.push_back('/');
    }
    path += kSeedFileName;
    return path;
}

KModErr read_seed_file(const std::string& path, SeedRecord& record) {
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return errno == ENOENT ? KModErr::ERR_MODULE_STORAGE_NOT_FOUND
                              : KModErr::ERR_MODULE_STORAGE_READ;
    }
    uint8_t raw[sizeof(record) + 1]{};
    size_t used = 0;
    while (used < sizeof(raw)) {
        const ssize_t count = read(fd, raw + used, sizeof(raw) - used);
        if (count > 0) {
            used += static_cast<size_t>(count);
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    close(fd);
    if (used != sizeof(record)) {
        return KModErr::ERR_MODULE_STORAGE_TYPE;
    }
    std::memcpy(&record, raw, sizeof(record));
    return KModErr::OK;
}

KModErr write_seed_file(const char* module_private_dir,
                        const std::string& path,
                        const SeedRecord& record) {
    if (mkdir(module_private_dir, 0700) != 0 && errno != EEXIST) {
        return KModErr::ERR_MODULE_CREATE_DIR;
    }
    const std::string temporary =
        path + ".tmp." + std::to_string(static_cast<unsigned long>(getpid()));
    const int fd = open(temporary.c_str(),
                        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                        0600);
    if (fd < 0) {
        return KModErr::ERR_MODULE_STORAGE_WRITE;
    }
    size_t written = 0;
    const auto* raw = reinterpret_cast<const uint8_t*>(&record);
    while (written < sizeof(record)) {
        const ssize_t count = write(fd, raw + written, sizeof(record) - written);
        if (count > 0) {
            written += static_cast<size_t>(count);
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            close(fd);
            unlink(temporary.c_str());
            return KModErr::ERR_MODULE_STORAGE_WRITE;
        }
    }
    const bool file_ok = fsync(fd) == 0;
    close(fd);
    if (!file_ok || rename(temporary.c_str(), path.c_str()) != 0) {
        unlink(temporary.c_str());
        return KModErr::ERR_MODULE_STORAGE_WRITE;
    }
    const int dir_fd = open(module_private_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }
    return KModErr::OK;
}

} // namespace

bool runtime_crypto_self_test() {
    static constexpr uint8_t kShaExpected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    const auto sha = sha256("abc", 3);
    if (!std::equal(sha.begin(), sha.end(), kShaExpected)) {
        return false;
    }

    // RFC 5869 test case 1.
    std::array<uint8_t, 22> ikm{};
    ikm.fill(0x0b);
    static constexpr uint8_t salt[13] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    };
    static constexpr uint8_t info[10] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
        0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
    };
    static constexpr uint8_t expected[42] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65,
    };
    std::array<uint8_t, sizeof(expected)> output{};
    return hkdf_sha256(ikm.data(), ikm.size(), salt, sizeof(salt),
                       info, sizeof(info), output.data(), output.size()) &&
           std::equal(output.begin(), output.end(), expected);
}

uint64_t virtual_id_fingerprint(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0) return 0;
    const auto digest = sha256(data, size);
    uint64_t value = 0;
    for (size_t i = 0; i < sizeof(value); ++i) {
        value |= static_cast<uint64_t>(digest[i]) << (i * 8);
    }
    return value;
}

KModErr load_or_create_runtime_profile(bool regenerate_seed,
                                       const char* module_private_dir,
                                       RuntimeProfile& profile) {
    profile = {};
    if (module_private_dir == nullptr || module_private_dir[0] == '\0') {
        return KModErr::ERR_MODULE_PARAM;
    }
    if (!runtime_crypto_self_test()) {
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }

    SeedRecord record{};
    const std::string path = seed_path(module_private_dir);
    const KModErr read_err = read_seed_file(path, record);
    bool create = regenerate_seed;
    if (is_ok(read_err)) {
        if (!validate_seed_record(record)) {
            return KModErr::ERR_MODULE_STORAGE_TYPE;
        }
    } else if (read_err == KModErr::ERR_MODULE_STORAGE_NOT_FOUND) {
        create = true;
    } else {
        return read_err;
    }

    if (create) {
        const uint64_t previous_generation =
            validate_seed_record(record) ? record.generation : 0;
        record = {};
        record.magic = kSeedMagic;
        record.version = kSeedVersion;
        record.seed_size = kSeedBytes;
        record.generation = previous_generation + 1;
        if (!fill_random(record.seed, sizeof(record.seed))) {
            return KModErr::ERR_MODULE_STORAGE_READ;
        }
        record.crc32 = crc32(&record, offsetof(SeedRecord, crc32));
        RETURN_IF_ERROR(write_seed_file(module_private_dir, path, record));
        SeedRecord verified{};
        RETURN_IF_ERROR(read_seed_file(path, verified));
        if (std::memcmp(&record, &verified, sizeof(record)) != 0 ||
            !validate_seed_record(verified)) {
            return KModErr::ERR_MODULE_STORAGE_READ;
        }
        profile.seed_created = true;
    }

    static constexpr uint8_t salt[] = {
        'S','K','P','-','D','R','M','I','D','-','S','A','L','T','-','v','1'
    };
    static constexpr char info[] = "global-widevine-v1";
    if (!hkdf_sha256(record.seed, sizeof(record.seed), salt, sizeof(salt),
                     reinterpret_cast<const uint8_t*>(info), sizeof(info) - 1,
                     profile.virtual_stream.data(),
                     profile.virtual_stream.size())) {
        return KModErr::ERR_MODULE_TEST_CHANNEL;
    }
    profile.profile_fingerprint = virtual_id_fingerprint(
        profile.virtual_stream.data(), kVirtualIdBytes);
    profile.seed_generation = record.generation;
    return KModErr::OK;
}

} // namespace drmid
