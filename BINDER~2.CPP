#include "binder_ioctl_resolver.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>

#include "kernel_module_kit_umbrella.h"

using namespace asmjit;
using namespace asmjit::a64;

namespace drmid {
namespace {

constexpr uint32_t kMaxStructureOffset = 0x4000;
constexpr uint32_t kMaxFileMemberScan = 0x200;
constexpr uint32_t kMaxFopsMemberScan = 0x200;
constexpr uint64_t kCapabilityRecordMagic =
    0x31325041434d5244ULL; // DRMCAP21
constexpr uint32_t kCapabilityRecordVersion = 1;

struct BinderCapabilityRecordV1 {
    uint64_t magic;
    uint32_t version;
    uint32_t record_size;
    uint64_t capabilities;
    uint64_t entry_fingerprint;
    uint32_t backend;
    uint32_t file_f_op_source;
    uint32_t fops_unlocked_ioctl_source;
    uint32_t symbol_validations;
    uint32_t entry_semantics;
    uint32_t reserved0;
    char kernel_release[64];
    char resolver_source[32];
    uint32_t crc32;
    uint32_t reserved1;
};

static_assert(sizeof(BinderCapabilityRecordV1) == 160);
static_assert(offsetof(BinderCapabilityRecordV1, crc32) == 152);
static_assert(sizeof(void*) == 8);

struct SymbolCandidate {
    const char* name;
    BinderBackend backend;
    uint32_t validation_bit;
    uint64_t address = 0;
    bool available = false;
};

bool is_kernel_pointer(uint64_t value) {
    return value != 0 && (value & 0x3U) == 0 &&
           static_cast<int64_t>(value) < 0;
}

bool valid_member_offset(uint32_t value, uint32_t limit) {
    return value <= limit && (value & 0x7U) == 0;
}

uint32_t crc32(const void* data, size_t size) {
    uint32_t value = 0xffffffffU;
    const auto* bytes = static_cast<const uint8_t*>(data);
    for (size_t index = 0; index < size; ++index) {
        value ^= bytes[index];
        for (int bit = 0; bit < 8; ++bit) {
            const uint32_t mask = 0U - (value & 1U);
            value = (value >> 1) ^ (0xedb88320U & mask);
        }
    }
    return value ^ 0xffffffffU;
}

uint64_t fnv1a64(const void* data, size_t size) {
    uint64_t value = 14695981039346656037ULL;
    const auto* bytes = static_cast<const uint8_t*>(data);
    for (size_t index = 0; index < size; ++index) {
        value ^= bytes[index];
        value *= 1099511628211ULL;
    }
    return value;
}

bool write_all(int fd, const void* data, size_t size) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    size_t written = 0;
    while (written < size) {
        const ssize_t count = write(fd, bytes + written, size - written);
        if (count > 0) {
            written += static_cast<size_t>(count);
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

bool read_all_exact(int fd, void* data, size_t size) {
    auto* bytes = static_cast<uint8_t*>(data);
    size_t used = 0;
    while (used < size) {
        const ssize_t count = read(fd, bytes + used, size - used);
        if (count > 0) {
            used += static_cast<size_t>(count);
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    uint8_t extra = 0;
    return read(fd, &extra, 1) == 0;
}

bool valid_kernel_release_text(const char* text, size_t capacity) {
    bool terminated = false;
    for (size_t index = 0; index < capacity; ++index) {
        const unsigned char ch = static_cast<unsigned char>(text[index]);
        if (ch == 0) {
            terminated = true;
            break;
        }
        if (!(ch == '.' || ch == '-' || ch == '_' || ch == '+' ||
              (ch >= '0' && ch <= '9') ||
              (ch >= 'A' && ch <= 'Z') ||
              (ch >= 'a' && ch <= 'z'))) {
            return false;
        }
    }
    return terminated && text[0] != '\0';
}

KModErr load_offsets(BinderKernelOffsets& offsets,
                     BinderOffsetSource& file_source,
                     BinderOffsetSource& ioctl_source) {
    offsets = {};
    file_source = BinderOffsetSource::kUnknown;
    ioctl_source = BinderOffsetSource::kUnknown;

    KModErr err = kernel_module::get_task_struct_files_offset(offsets.task_files);
    printf("[drmid612] offset task.files=%u result=%s\n",
           offsets.task_files, to_string(err).c_str());
    if (is_failed(err) ||
        !valid_member_offset(offsets.task_files, kMaxStructureOffset)) {
        return is_failed(err) ? err : KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }

    err = kernel_module::get_file_struct_fdt_offset(offsets.files_fdt);
    printf("[drmid612] offset files.fdt=%u result=%s\n",
           offsets.files_fdt, to_string(err).c_str());
    if (is_failed(err) ||
        !valid_member_offset(offsets.files_fdt, kMaxStructureOffset)) {
        return is_failed(err) ? err : KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }

    err = kernel_module::get_fdtable_fd_offset(offsets.fdtable_fd);
    printf("[drmid612] offset fdt.fd=%u result=%s\n",
           offsets.fdtable_fd, to_string(err).c_str());
    if (is_failed(err) ||
        !valid_member_offset(offsets.fdtable_fd, kMaxStructureOffset)) {
        return is_failed(err) ? err : KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }

    err = kernel_module::get_file_f_op_offset(offsets.file_f_op);
    printf("[drmid612] offset file.f_op=%u result=%s\n",
           offsets.file_f_op, to_string(err).c_str());
    if (is_ok(err) && valid_member_offset(offsets.file_f_op,
                                          kMaxFileMemberScan)) {
        file_source = BinderOffsetSource::kSdk;
    } else {
        offsets.file_f_op = 0;
    }

    err = kernel_module::get_file_operations_unlocked_ioctl_offset(
        offsets.fops_unlocked_ioctl);
    printf("[drmid612] offset fops.unlocked_ioctl=%u result=%s\n",
           offsets.fops_unlocked_ioctl, to_string(err).c_str());
    if (is_ok(err) && valid_member_offset(offsets.fops_unlocked_ioctl,
                                          kMaxFopsMemberScan)) {
        ioctl_source = BinderOffsetSource::kSdk;
    } else {
        offsets.fops_unlocked_ioctl = 0;
    }
    return KModErr::OK;
}

KModErr resolve_file_from_current_fd(int fd,
                                     const BinderKernelOffsets& offsets,
                                     uint64_t& file_kaddr) {
    if (fd < 0 || fd > 4095) return KModErr::ERR_MODULE_PARAM;

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    Assembler* a = asm_ctx.assembler();
    if (a == nullptr) return KModErr::ERR_MODULE_ASM;
    const Label fail = a->newLabel();
    const Label done = a->newLabel();
    kernel_module::arm64_module_asm_func_start(a);
    kernel_module::export_symbol::get_current(a, x9);
    a->cbz(x9, fail);
    a->ldr(x9, ptr(x9, offsets.task_files));
    a->cbz(x9, fail);
    a->ldr(x9, ptr(x9, offsets.files_fdt));
    a->cbz(x9, fail);
    a->ldr(x9, ptr(x9, offsets.fdtable_fd));
    a->cbz(x9, fail);
    a->ldr(x9, ptr(x9, static_cast<int64_t>(fd) * 8));
    a->b(done);
    a->bind(fail);
    a->mov(x9, xzr);
    a->bind(done);
    kernel_module::arm64_module_asm_func_end(a, x9);
    if (asm_ctx.has_error()) return KModErr::ERR_MODULE_ASM;

    file_kaddr = 0;
    const KModErr execute_err = kernel_module::execute_kernel_asm_func(
        aarch64_asm_to_bytes(a), file_kaddr);
    printf("[drmid612] fd walk file=%p result=%s\n",
           reinterpret_cast<void*>(file_kaddr),
           to_string(execute_err).c_str());
    if (is_failed(execute_err)) return execute_err;
    return is_kernel_pointer(file_kaddr) ? KModErr::OK
                                         : KModErr::ERR_MODULE_NOT_KADDR;
}

template <size_t N>
void resolve_symbols(std::array<SymbolCandidate, N>& symbols) {
    for (auto& symbol : symbols) {
        const KModErr err = kernel_module::kallsyms_lookup_name(
            symbol.name, symbol.address);
        symbol.available = is_ok(err) && is_kernel_pointer(symbol.address);
        printf("[drmid612] symbol %s=%p result=%s\n",
               symbol.name,
               reinterpret_cast<void*>(symbol.address),
               to_string(err).c_str());
    }
}

template <size_t N>
const SymbolCandidate* matching_symbol(
    uint64_t address,
    const std::array<SymbolCandidate, N>& symbols) {
    for (const auto& symbol : symbols) {
        if (symbol.available && symbol.address == address) return &symbol;
    }
    return nullptr;
}

template <size_t N>
bool any_symbol_available(const std::array<SymbolCandidate, N>& symbols) {
    return std::any_of(symbols.begin(), symbols.end(),
                       [](const SymbolCandidate& symbol) {
                           return symbol.available;
                       });
}

template <size_t N>
bool backend_symbol_available(
    const std::array<SymbolCandidate, N>& symbols,
    BinderBackend backend) {
    return std::any_of(symbols.begin(), symbols.end(),
                       [backend](const SymbolCandidate& symbol) {
                           return symbol.available &&
                                  symbol.backend == backend;
                       });
}

template <size_t N>
KModErr scan_pointer_member(uint64_t base,
                            uint32_t limit,
                            const std::array<SymbolCandidate, N>& symbols,
                            uint32_t& offset,
                            uint64_t& value,
                            const SymbolCandidate*& match) {
    match = nullptr;
    for (uint32_t candidate_offset = 0;
         candidate_offset <= limit;
         candidate_offset += sizeof(uint64_t)) {
        uint64_t candidate = 0;
        const KModErr err = kernel_module::read_kernel_mem_atomic64(
            base + candidate_offset, candidate);
        if (is_failed(err)) return err;
        if (const SymbolCandidate* symbol =
                matching_symbol(candidate, symbols)) {
            offset = candidate_offset;
            value = candidate;
            match = symbol;
            return KModErr::OK;
        }
    }
    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

bool is_bti(uint32_t word) {
    return word == 0xd503245fU || word == 0xd503249fU ||
           word == 0xd50324dfU;
}

bool is_pac_stack(uint32_t word) {
    return word == 0xd503233fU || word == 0xd503237fU;
}

bool decode_sub_sp_frame(uint32_t word, uint32_t& frame_bytes) {
    if ((word & 0xffc003ffU) != 0xd10003ffU) return false;
    const uint32_t immediate = (word >> 10) & 0xfffU;
    const uint32_t shift = (word >> 22) & 1U;
    if (shift != 0 || immediate < 16 || immediate > 4096 ||
        (immediate & 0xfU) != 0) {
        return false;
    }
    frame_bytes = immediate;
    return true;
}

bool is_store_pair_to_sp(uint32_t word) {
    // Frame-link saves in a Binder entry are the 64-bit STP form.  The
    // 32-bit W-register encoding shares the same masked opcode, so retain
    // the sf bit explicitly instead of treating an arbitrary W29/W30 pair as
    // a valid frame.
    return (word & 0x80000000U) != 0 &&
           (word & 0x3b400000U) == 0x29000000U &&
           ((word >> 5) & 0x1fU) == 31U;
}

bool is_frame_link_store(uint32_t word) {
    return is_store_pair_to_sp(word) && (word & 0x1fU) == 29U &&
           ((word >> 10) & 0x1fU) == 30U;
}

bool decode_preindex_frame_link(uint32_t word, uint32_t& frame_bytes) {
    if (!is_frame_link_store(word) ||
        (word & 0x01800000U) != 0x01800000U) {
        return false;
    }
    int32_t immediate = static_cast<int32_t>((word >> 15) & 0x7fU);
    if ((immediate & 0x40) != 0) immediate -= 0x80;
    immediate *= 8;
    if (immediate >= 0 || -immediate > 4096 ||
        ((-immediate) & 0xf) != 0) {
        return false;
    }
    frame_bytes = static_cast<uint32_t>(-immediate);
    return true;
}

bool is_mov_fp_sp(uint32_t word) {
    return word == 0x910003fdU;
}

bool is_pc_relative_or_control_flow(uint32_t word) {
    return (word & 0x7c000000U) == 0x14000000U ||
           (word & 0xff000010U) == 0x54000000U ||
           (word & 0x7e000000U) == 0x34000000U ||
           (word & 0x7e000000U) == 0x36000000U ||
           (word & 0x1f000000U) == 0x10000000U ||
           (word & 0x9f000000U) == 0x90000000U ||
           (word & 0x3b000000U) == 0x18000000U ||
           (word & 0xfe000000U) == 0xd6000000U;
}

bool address_in_core_text(uint64_t address);
bool classify_semantic_entry(
    const std::array<uint32_t, kBinderEntryProbeWords>& words,
    uint32_t& semantics);

bool classify_single_instruction_hook_site(uint32_t word,
                                           uint32_t& semantics) {
    // SKP SDK 4.5.4 replaces one instruction at the requested hook address
    // and replays it from arm64_emit_call_original().  Accept only
    // position-independent entry instructions whose meaning is unchanged at
    // the SDK trampoline.  In particular, a direct B at word zero is not
    // accepted merely because its destination has a plausible prologue.
    semantics = 0;
    if (is_bti(word)) {
        semantics = kEntryHookSiteBti;
        return true;
    }
    if (is_pac_stack(word)) {
        semantics = kEntryHookSitePac;
        return true;
    }
    uint32_t frame_bytes = 0;
    if (decode_sub_sp_frame(word, frame_bytes) ||
        decode_preindex_frame_link(word, frame_bytes)) {
        semantics = kEntryHookSiteFrame;
        return true;
    }
    return false;
}

bool decode_unconditional_branch(uint32_t word, int64_t& displacement) {
    // AArch64 B imm26.  Keep the displacement word-aligned and sign extend
    // before adding it to the symbol address.
    if ((word & 0x7c000000U) != 0x14000000U) return false;
    int64_t immediate = static_cast<int64_t>(word & 0x03ffffffU);
    if ((immediate & (1LL << 25)) != 0) immediate -= (1LL << 26);
    displacement = immediate << 2;
    return displacement != 0;
}

bool classify_veneer_target(
    uint64_t entry_address,
    const std::array<uint32_t, kBinderEntryProbeWords>& entry_words,
    uint32_t& semantics) {
    // Allow an optional BTI/PAC prefix before one direct, forward branch.  The
    // first instruction must itself be safe for the SDK's one-instruction
    // trampoline, so a veneer beginning directly with B remains fail-closed.
    // Both the Binder ioctl symbol and the branch destination must reside in
    // immutable core text.  SKP's logical uninstall can intentionally leave
    // a forward B at entry+4 which targets a disabled trampoline in allocated
    // executable memory.  Its bytes can resemble a valid function prologue,
    // so accepting a readable kernel pointer alone would allow Hook stacking
    // during the same boot.  The core-text requirement is the coexistence
    // gate that keeps such an occupied entry fail-closed.
    size_t branch_index = 0;
    if (is_bti(entry_words[branch_index])) ++branch_index;
    if (is_pac_stack(entry_words[branch_index])) ++branch_index;
    if (branch_index == 0 || branch_index >= 4) return false;
    uint32_t hook_site_semantics = 0;
    if (!classify_single_instruction_hook_site(entry_words[0],
                                                hook_site_semantics)) {
        return false;
    }
    int64_t displacement = 0;
    if (!decode_unconditional_branch(entry_words[branch_index],
                                    displacement) ||
        displacement <= 0) {
        return false;
    }
    const uint64_t branch_pc = entry_address + branch_index * sizeof(uint32_t);
    const uint64_t target = static_cast<uint64_t>(
        static_cast<int64_t>(branch_pc) + displacement);
    if (target <= entry_address || !is_kernel_pointer(target) ||
        !address_in_core_text(target)) {
        return false;
    }

    std::array<uint32_t, kBinderEntryProbeWords> target_words{};
    if (is_failed(kernel_module::read_kernel_mem(
            target,
            target_words.data(),
            static_cast<uint32_t>(kBinderEntryProbeBytes)))) {
        return false;
    }
    uint32_t target_semantics = 0;
    if (!classify_semantic_entry(target_words, target_semantics)) {
        return false;
    }
    semantics = target_semantics | hook_site_semantics | kEntryHasVeneer;
    return true;
}

bool classify_hookable_entry(
    uint64_t entry_address,
    const std::array<uint32_t, kBinderEntryProbeWords>& entry_words,
    uint32_t& semantics) {
    uint32_t entry_semantics = 0;
    if (classify_semantic_entry(entry_words, entry_semantics)) {
        uint32_t hook_site_semantics = 0;
        if (!classify_single_instruction_hook_site(entry_words[0],
                                                    hook_site_semantics)) {
            return false;
        }
        semantics = entry_semantics | hook_site_semantics;
        return true;
    }
    return classify_veneer_target(entry_address, entry_words, semantics);
}

bool classify_semantic_entry(
    const std::array<uint32_t, kBinderEntryProbeWords>& words,
    uint32_t& semantics) {
    semantics = 0;
    size_t index = 0;
    if (is_bti(words[index])) {
        semantics |= kEntryHasBti;
        ++index;
    }
    if (is_pac_stack(words[index])) {
        semantics |= kEntryHasPac;
        ++index;
    }
    if (index >= 4) return false;

    uint32_t frame_bytes = 0;
    if (decode_sub_sp_frame(words[index], frame_bytes)) {
        semantics |= kEntryHasStackFrame;
        ++index;
        bool frame_link = false;
        for (size_t cursor = index; cursor < std::min<size_t>(index + 3, 8);
             ++cursor) {
            if (is_frame_link_store(words[cursor])) {
                frame_link = true;
                break;
            }
        }
        if (!frame_link) return false;
        semantics |= kEntrySavesFrameLink;
    } else if (decode_preindex_frame_link(words[index], frame_bytes)) {
        semantics |= kEntryHasStackFrame | kEntrySavesFrameLink;
        ++index;
        if (index < 8 && is_mov_fp_sp(words[index])) {
            semantics |= kEntrySetsFramePointer;
        }
    } else {
        return false;
    }

    for (size_t cursor = 0; cursor < 4; ++cursor) {
        if (is_pc_relative_or_control_flow(words[cursor])) return false;
    }
    semantics |= kEntryRelocatablePrefix;
    return frame_bytes != 0;
}

bool address_in_core_text(uint64_t address) {
    constexpr std::array<std::pair<const char*, const char*>, 2> ranges = {{
        {"_stext", "_etext"},
        {"_text", "_etext"},
    }};
    for (const auto& names : ranges) {
        uint64_t begin = 0;
        uint64_t end = 0;
        if (is_ok(kernel_module::kallsyms_lookup_name(names.first, begin)) &&
            is_ok(kernel_module::kallsyms_lookup_name(names.second, end)) &&
            is_kernel_pointer(begin) && is_kernel_pointer(end) &&
            begin < end && address >= begin && address < end) {
            return true;
        }
    }
    return false;
}

bool compatible_symbol_backends(const SymbolCandidate* fops,
                                const SymbolCandidate* ioctl) {
    return fops == nullptr || ioctl == nullptr ||
           fops->backend == ioctl->backend;
}

// A live pointer obtained through an SDK offset is useful only when it can
// be tied back to a Binder symbol.  Keep this check separate from the bounded
// scans: it lets the normal SDK path remain the fast path while still making
// the symbol cross-check explicit.  A stale or OEM-shifted SDK offset simply
// falls through to the scan path below.
template <size_t N>
const SymbolCandidate* sdk_symbol_match(
    uint64_t address,
    const std::array<SymbolCandidate, N>& symbols) {
    if (!is_kernel_pointer(address)) return nullptr;
    return matching_symbol(address, symbols);
}

template <size_t N>
bool all_available_ioctl_symbols_are_text(
    const std::array<SymbolCandidate, N>& symbols) {
    // ioctl symbols are executable kernel entries.  Checking the complete
    // visible set prevents a data symbol/alias from becoming an implicit
    // authority merely because one live pointer happened to match.  The
    // binder_fops symbols are deliberately not passed here: they name
    // file_operations data objects, not text addresses.
    for (const auto& symbol : symbols) {
        if (!symbol.available) continue;
        if (!address_in_core_text(symbol.address)) return false;
    }
    // A kernel may export only the ioctl symbol (or only the fops symbol).
    // The resolver requires one cross-check overall, not one from each list.
    return true;
}

bool valid_record(const BinderCapabilityRecordV1& record) {
    return record.magic == kCapabilityRecordMagic &&
           record.version == kCapabilityRecordVersion &&
           record.record_size == sizeof(record) &&
           record.backend != static_cast<uint32_t>(BinderBackend::kUnknown) &&
           record.backend <= static_cast<uint32_t>(BinderBackend::kRust) &&
           record.file_f_op_source !=
               static_cast<uint32_t>(BinderOffsetSource::kUnknown) &&
           record.file_f_op_source <=
               static_cast<uint32_t>(BinderOffsetSource::kSymbolScan) &&
           record.fops_unlocked_ioctl_source !=
               static_cast<uint32_t>(BinderOffsetSource::kUnknown) &&
           record.fops_unlocked_ioctl_source <=
               static_cast<uint32_t>(BinderOffsetSource::kSymbolScan) &&
           record.entry_fingerprint != 0 &&
           (record.capabilities & kRequiredBinderCapabilities) ==
               kRequiredBinderCapabilities &&
           record.reserved0 == 0 && record.reserved1 == 0 &&
           valid_kernel_release_text(record.kernel_release,
                                     sizeof(record.kernel_release)) &&
           record.crc32 ==
               crc32(&record, offsetof(BinderCapabilityRecordV1, crc32));
}

} // namespace

const char* binder_backend_name(BinderBackend backend) {
    switch (backend) {
        case BinderBackend::kClassic:
            return "classic";
        case BinderBackend::kRust:
            return "rust";
        case BinderBackend::kUnknown:
        default:
            return "unknown";
    }
}

const char* binder_offset_source_name(BinderOffsetSource source) {
    switch (source) {
        case BinderOffsetSource::kSdk:
            return "sdk";
        case BinderOffsetSource::kSymbolScan:
            return "symbol-scan";
        case BinderOffsetSource::kUnknown:
        default:
            return "unknown";
    }
}

const char* binder_resolution_source_name(
    const BinderIoctlResolution& resolution) {
    if (resolution.file_f_op_source == BinderOffsetSource::kSymbolScan ||
        resolution.fops_unlocked_ioctl_source ==
            BinderOffsetSource::kSymbolScan) {
        return "fd+sdk+symbol-scan";
    }
    return "fd+sdk+symbol-check";
}

bool is_supported_linux_6_1_or_newer(const std::string& release) {
    size_t cursor = 0;
    auto parse_component = [&](uint32_t& value) {
        if (cursor >= release.size() || release[cursor] < '0' ||
            release[cursor] > '9') {
            return false;
        }
        value = 0;
        size_t digits = 0;
        while (cursor < release.size() && release[cursor] >= '0' &&
               release[cursor] <= '9') {
            if (++digits > 3) return false;
            value = value * 10U + static_cast<uint32_t>(release[cursor] - '0');
            ++cursor;
        }
        return true;
    };
    uint32_t major = 0;
    uint32_t minor = 0;
    if (!parse_component(major) || cursor >= release.size() ||
        release[cursor++] != '.' || !parse_component(minor)) {
        return false;
    }
    if (major != 6 || minor < 1) return false;

    // A third numeric component is optional ("6.1" is a valid uname
    // release), but once a dot is present it must be followed by digits.
    // This keeps malformed values such as "6.1.foo" and "6.1.0foo" out of
    // the platform gate while accepting normal vendor suffixes.
    if (cursor < release.size() && release[cursor] == '.') {
        do {
            ++cursor;
            uint32_t ignored = 0;
            if (!parse_component(ignored)) return false;
        } while (cursor < release.size() && release[cursor] == '.');
    }
    if (cursor < release.size()) {
        if (release[cursor] != '-' && release[cursor] != '+') return false;
        ++cursor;
        if (cursor >= release.size()) return false;
        for (; cursor < release.size(); ++cursor) {
            const char ch = release[cursor];
            if (!((ch >= '0' && ch <= '9') ||
                  (ch >= 'A' && ch <= 'Z') ||
                  (ch >= 'a' && ch <= 'z') || ch == '.' || ch == '_' ||
                  ch == '-' || ch == '+')) {
                return false;
            }
        }
    }
    return true;
}

KModErr resolve_binder_ioctl_from_fd(int binder_fd, BinderIoctlResolution& out) {
    out = {};
    out.binder_fd = binder_fd;
    RETURN_IF_ERROR(load_offsets(out.offsets,
                                 out.file_f_op_source,
                                 out.fops_unlocked_ioctl_source));
    RETURN_IF_ERROR(resolve_file_from_current_fd(
        binder_fd, out.offsets, out.file_kaddr));
    out.capabilities |= kCapabilityFdWalk;

    std::array<SymbolCandidate, 2> fops_symbols = {{
        {"binder_fops", BinderBackend::kClassic, kSymbolClassicFops},
        {"rust_binder_fops", BinderBackend::kRust, kSymbolRustFops},
    }};
    std::array<SymbolCandidate, 4> ioctl_symbols = {{
        {"binder_ioctl", BinderBackend::kClassic, kSymbolClassicIoctl},
        {"rust_binder_unlocked_ioctl", BinderBackend::kRust,
         kSymbolRustIoctl},
        {"rust_binder_ioctl", BinderBackend::kRust, kSymbolRustIoctl},
        {"rust_binder_compat_ioctl", BinderBackend::kRust,
         kSymbolRustIoctl},
    }};
    resolve_symbols(fops_symbols);
    resolve_symbols(ioctl_symbols);

    KModErr err = KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    if (out.file_f_op_source == BinderOffsetSource::kSdk) {
        err = kernel_module::read_kernel_mem_atomic64(
            out.file_kaddr + out.offsets.file_f_op, out.fops_kaddr);
        if (is_failed(err) || !is_kernel_pointer(out.fops_kaddr)) {
            out.fops_kaddr = 0;
        }
    }
    const SymbolCandidate* fops_match =
        sdk_symbol_match(out.fops_kaddr, fops_symbols);
    if (fops_match != nullptr) {
        out.symbol_validations |= fops_match->validation_bit;
    }
    uint32_t scanned_file_offset = 0;
    uint64_t scanned_fops = 0;
    if (fops_match == nullptr) {
        const KModErr fops_scan_err = any_symbol_available(fops_symbols)
            ? scan_pointer_member(out.file_kaddr,
                                  kMaxFileMemberScan,
                                  fops_symbols,
                                  scanned_file_offset,
                                  scanned_fops,
                                  fops_match)
            : KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        if (is_ok(fops_scan_err)) {
            out.offsets.file_f_op = scanned_file_offset;
            out.fops_kaddr = scanned_fops;
            out.file_f_op_source = BinderOffsetSource::kSymbolScan;
            out.symbol_validations |= fops_match->validation_bit;
        }
    }
    if (!is_kernel_pointer(out.fops_kaddr)) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
    out.capabilities |= kCapabilityFopsResolved;

    if (out.fops_unlocked_ioctl_source == BinderOffsetSource::kSdk) {
        err = kernel_module::read_kernel_mem_atomic64(
            out.fops_kaddr + out.offsets.fops_unlocked_ioctl,
            out.ioctl_kaddr);
        if (is_failed(err) || !is_kernel_pointer(out.ioctl_kaddr)) {
            out.ioctl_kaddr = 0;
        }
    }
    const SymbolCandidate* ioctl_match =
        sdk_symbol_match(out.ioctl_kaddr, ioctl_symbols);
    if (ioctl_match != nullptr) {
        out.symbol_validations |= ioctl_match->validation_bit;
    }
    uint32_t scanned_ioctl_offset = 0;
    uint64_t scanned_ioctl = 0;
    if (ioctl_match == nullptr) {
        const KModErr ioctl_scan_err = any_symbol_available(ioctl_symbols)
            ? scan_pointer_member(out.fops_kaddr,
                                  kMaxFopsMemberScan,
                                  ioctl_symbols,
                                  scanned_ioctl_offset,
                                  scanned_ioctl,
                                  ioctl_match)
            : KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        if (is_ok(ioctl_scan_err)) {
            out.offsets.fops_unlocked_ioctl = scanned_ioctl_offset;
            out.ioctl_kaddr = scanned_ioctl;
            out.fops_unlocked_ioctl_source = BinderOffsetSource::kSymbolScan;
            out.symbol_validations |= ioctl_match->validation_bit;
        }
    }
    if (!is_kernel_pointer(out.ioctl_kaddr)) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
    out.capabilities |= kCapabilityIoctlResolved;

    if (!compatible_symbol_backends(fops_match, ioctl_match)) {
        return KModErr::ERR_MODULE_FUNC_NOT_STANDARD;
    }
    if (ioctl_match != nullptr) {
        out.backend = ioctl_match->backend;
    } else if (fops_match != nullptr) {
        out.backend = fops_match->backend;
    }
    if (out.symbol_validations == 0 ||
        out.backend == BinderBackend::kUnknown) {
        return KModErr::ERR_MODULE_FUNC_NOT_STANDARD;
    }
    // If a backend-specific symbol is visible it is authoritative. Do not
    // accept an SDK offset that points at a different file_operations table
    // or ioctl entry merely because another Binder symbol happened to match.
    if ((backend_symbol_available(fops_symbols, out.backend) &&
         (fops_match == nullptr || fops_match->backend != out.backend)) ||
        (backend_symbol_available(ioctl_symbols, out.backend) &&
         (ioctl_match == nullptr || ioctl_match->backend != out.backend))) {
        return KModErr::ERR_MODULE_FUNC_NOT_STANDARD;
    }
    out.capabilities |= kCapabilitySymbolCrossValidated;

    if (!all_available_ioctl_symbols_are_text(ioctl_symbols) ||
        !address_in_core_text(out.ioctl_kaddr)) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }
    out.capabilities |= kCapabilityKernelTextTarget;

    RETURN_IF_ERROR(kernel_module::read_kernel_mem(
        out.ioctl_kaddr,
        out.entry_words.data(),
        static_cast<uint32_t>(kBinderEntryProbeBytes)));
    out.entry_fingerprint = fnv1a64(
        out.entry_words.data(), kBinderEntryProbeBytes);
    if (!classify_hookable_entry(out.ioctl_kaddr,
                                 out.entry_words,
                                 out.entry_semantics)) {
        printf("[drmid612] semantic entry rejected words=%08x %08x %08x %08x\n",
               out.entry_words[0], out.entry_words[1], out.entry_words[2],
               out.entry_words[3]);
        return KModErr::ERR_MODULE_FUNC_NOT_STANDARD;
    }
    out.capabilities |= kCapabilitySemanticPrologue |
                        kCapabilityHookRelocatablePrefix |
                        kCapabilityBinderWriteRead |
                        kCapabilityTransactionStreams |
                        kCapabilityEqualLengthReplacement;
    return KModErr::OK;
}

bool has_required_binder_capabilities(
    const BinderIoctlResolution& resolution) {
    return resolution.backend != BinderBackend::kUnknown &&
           is_kernel_pointer(resolution.file_kaddr) &&
           is_kernel_pointer(resolution.fops_kaddr) &&
           is_kernel_pointer(resolution.ioctl_kaddr) &&
           (resolution.capabilities & kRequiredBinderCapabilities) ==
               kRequiredBinderCapabilities;
}

std::string default_binder_capability_path(const char* module_private_dir) {
    if (module_private_dir == nullptr || module_private_dir[0] == '\0') {
        return {};
    }
    std::string path(module_private_dir);
    if (path.back() != '/') path.push_back('/');
    path += "drmid_binder_capability_v1.bin";
    return path;
}

KModErr write_binder_capability_status(
    const char* path,
    const std::string& kernel_release,
    const BinderIoctlResolution& resolution) {
    if (path == nullptr || path[0] == '\0' ||
        kernel_release.empty() || kernel_release.size() >= 64 ||
        !has_required_binder_capabilities(resolution)) {
        return KModErr::ERR_MODULE_PARAM;
    }
    BinderCapabilityRecordV1 record{};
    record.magic = kCapabilityRecordMagic;
    record.version = kCapabilityRecordVersion;
    record.record_size = sizeof(record);
    record.capabilities = resolution.capabilities;
    record.entry_fingerprint = resolution.entry_fingerprint;
    record.backend = static_cast<uint32_t>(resolution.backend);
    record.file_f_op_source =
        static_cast<uint32_t>(resolution.file_f_op_source);
    record.fops_unlocked_ioctl_source =
        static_cast<uint32_t>(resolution.fops_unlocked_ioctl_source);
    record.symbol_validations = resolution.symbol_validations;
    record.entry_semantics = resolution.entry_semantics;
    std::memcpy(record.kernel_release,
                kernel_release.data(),
                kernel_release.size());
    const char* source = binder_resolution_source_name(resolution);
    std::strncpy(record.resolver_source,
                 source,
                 sizeof(record.resolver_source) - 1);
    record.crc32 =
        crc32(&record, offsetof(BinderCapabilityRecordV1, crc32));

    const std::string temporary = std::string(path) + ".tmp";
    const int fd = open(temporary.c_str(),
                        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                        0600);
    if (fd < 0) return KModErr::ERR_MODULE_STORAGE_WRITE;
    const bool ok = write_all(fd, &record, sizeof(record)) &&
                    fchmod(fd, 0600) == 0 && fsync(fd) == 0;
    const bool closed = close(fd) == 0;
    if (!ok || !closed || rename(temporary.c_str(), path) != 0) {
        unlink(temporary.c_str());
        return KModErr::ERR_MODULE_STORAGE_WRITE;
    }
    std::string directory(path);
    const size_t slash = directory.find_last_of('/');
    directory = slash == std::string::npos ? "." : directory.substr(0, slash);
    const int directory_fd = open(directory.c_str(),
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                      O_NOFOLLOW);
    if (directory_fd >= 0) {
        fsync(directory_fd);
        close(directory_fd);
    }
    return KModErr::OK;
}

KModErr read_binder_capability_status(
    const char* path,
    BinderCapabilityStatus& status) {
    status = {};
    if (path == nullptr || path[0] == '\0') return KModErr::ERR_MODULE_PARAM;
    const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return errno == ENOENT ? KModErr::ERR_MODULE_STORAGE_NOT_FOUND
                              : KModErr::ERR_MODULE_STORAGE_READ;
    }
    struct stat info {};
    BinderCapabilityRecordV1 record{};
    const bool ok = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
                    read_all_exact(fd, &record, sizeof(record));
    close(fd);
    if (!ok) return KModErr::ERR_MODULE_STORAGE_READ;
    if (!valid_record(record)) return KModErr::ERR_MODULE_STORAGE_TYPE;

    status.kernel_release = record.kernel_release;
    status.backend = static_cast<BinderBackend>(record.backend);
    status.file_f_op_source =
        static_cast<BinderOffsetSource>(record.file_f_op_source);
    status.fops_unlocked_ioctl_source =
        static_cast<BinderOffsetSource>(record.fops_unlocked_ioctl_source);
    status.capabilities = record.capabilities;
    status.entry_fingerprint = record.entry_fingerprint;
    status.entry_semantics = record.entry_semantics;
    status.symbol_validations = record.symbol_validations;
    return KModErr::OK;
}

} // namespace drmid
