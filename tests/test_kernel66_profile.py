from __future__ import annotations

from pathlib import Path
import re
import struct
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]
FIXTURE_CAPTURE = ROOT / "tests" / "fixtures" / "kernel66_profile.txt"
WORKSPACE_CAPTURE = WORKSPACE / "artifacts" / "kernel66-sdk-probe-20260801" / "采集.txt"
CAPTURE = FIXTURE_CAPTURE if FIXTURE_CAPTURE.is_file() else WORKSPACE_CAPTURE
RESOLVER = (ROOT / "binder_ioctl_resolver.cpp").read_text(encoding="utf-8")
HEADER = (ROOT / "binder_ioctl_resolver.h").read_text(encoding="utf-8")
MODULE = (ROOT / "module_main.cpp").read_text(encoding="utf-8")

BTI_C = 0xD503245F
PACIASP = 0xD503233F
MOV_FP_SP = 0x910003FD
CLASSIC_66 = (0xD503233F, 0xD10343FF, 0xA9077BFD, 0xA9086FFC)
CLASSIC_612 = (0xD503233F, 0xD10303FF, 0xA9067BFD, 0xA9076FFC)
RUST_612 = (0xD503233F, 0xA9BF7BFD, 0x910003FD, 0xAA0003E8)


def fnv1a64(data: bytes) -> int:
    value = 14695981039346656037
    for byte in data:
        value ^= byte
        value = (value * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return value


def sub_sp(frame: int) -> int:
    return 0xD10003FF | (frame << 10)


def is_store_pair_sp(word: int) -> bool:
    return (
        (word & 0x80000000) != 0
        and (word & 0x3B400000) == 0x29000000
        and ((word >> 5) & 31) == 31
    )


def is_frame_link_store(word: int) -> bool:
    return is_store_pair_sp(word) and (word & 31) == 29 and ((word >> 10) & 31) == 30


def pc_relative_or_control(word: int) -> bool:
    return (
        (word & 0x7C000000) == 0x14000000
        or (word & 0xFF000010) == 0x54000000
        or (word & 0x7E000000) == 0x34000000
        or (word & 0x7E000000) == 0x36000000
        or (word & 0x1F000000) == 0x10000000
        or (word & 0x9F000000) == 0x90000000
        or (word & 0x3B000000) == 0x18000000
        or (word & 0xFE000000) == 0xD6000000
    )


def semantic_entry(words: tuple[int, ...]) -> bool:
    words = words + (0,) * (8 - len(words))
    index = 0
    if words[index] in {0xD503245F, 0xD503249F, 0xD50324DF}:
        index += 1
    if words[index] in {0xD503233F, 0xD503237F}:
        index += 1
    word = words[index]
    frame = 0
    if (word & 0xFFC003FF) == 0xD10003FF:
        frame = (word >> 10) & 0xFFF
        if frame < 16 or frame > 4096 or frame % 16:
            return False
        if not any(is_frame_link_store(x) for x in words[index + 1:index + 4]):
            return False
    elif is_frame_link_store(word) and (word & 0x01800000) == 0x01800000:
        immediate = (word >> 15) & 0x7F
        if immediate & 0x40:
            immediate -= 0x80
        frame = -immediate * 8
        if frame < 16 or frame > 4096 or frame % 16:
            return False
    else:
        return False
    return all(not pc_relative_or_control(x) for x in words[:4])


def supported_release(release: str) -> bool:
    match = re.match(r"^(\d{1,3})\.(\d{1,3})", release)
    if not match or int(match.group(1)) != 6 or int(match.group(2)) < 1:
        return False
    tail = release[match.end():]
    if not tail:
        return True
    if tail.startswith("."):
        components = tail.split("-")[0].split("+")[0].split(".")
        if any(not component.isdigit() or len(component) > 3
               for component in components[1:]):
            return False
        tail = tail[len(".".join(components)):]
    if tail:
        if tail[0] not in "-+" or len(tail) == 1:
            return False
        if not re.fullmatch(r"[-+A-Za-z0-9._]+", tail):
            return False
    return True


def capability_gate(*, pointers: bool = True, symbol_validation: bool = True,
                    fops_consistent: bool = True, ioctl_consistent: bool = True,
                    kernel_text: bool = True, semantic: bool = True,
                    relocatable: bool = True) -> bool:
    return all((pointers, symbol_validation, fops_consistent, ioctl_consistent,
                kernel_text, semantic, relocatable))


class UniversalBinderCapabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not CAPTURE.is_file():
            raise unittest.SkipTest("6.6 device capture is not part of the source repository")
        cls.capture = CAPTURE.read_text(encoding="utf-8")

    def test_captured_66_probe_remains_complete(self) -> None:
        self.assertIn("schema=skp-drmid-kernel66-sdk-probe-v1", self.capture)
        self.assertIn("kernel=6.6.89", self.capture)
        self.assertIn("probe_complete=yes symbol_code=1 live=1", self.capture)
        self.assertIn("code.live_matches_symbol_bytes=1", self.capture)

    def test_captured_66_body_is_accepted_by_semantic_classifier(self) -> None:
        chunks = []
        for offset in range(0, 256, 16):
            match = re.search(
                rf"code\.binder_ioctl_symbol\.{offset:04x}=([0-9a-f]{{32}})",
                self.capture,
            )
            self.assertIsNotNone(match)
            chunks.append(bytes.fromhex(match.group(1)))
        body = b"".join(chunks)
        self.assertEqual(fnv1a64(body), 0x62E54BF3E7AA39BB)
        words = struct.unpack_from("<8I", body)
        self.assertEqual(words[:4], CLASSIC_66)
        self.assertTrue(semantic_entry(words))

    def test_captured_612_classic_and_rust_are_accepted(self) -> None:
        self.assertTrue(semantic_entry(CLASSIC_612))
        self.assertTrue(semantic_entry(RUST_612))

    def test_synthetic_61_common_prologues_are_accepted(self) -> None:
        variants = (
            (PACIASP, sub_sp(0x80), 0xA9047BFD, 0xA90573FB),
            (BTI_C, PACIASP, sub_sp(0x100), 0xA9087BFD, 0xA90973FB),
            (sub_sp(0x40), 0xA9027BFD, 0xA90353F3, 0xAA0003F3),
            (PACIASP, 0xA9BF7BFD, MOV_FP_SP, 0xAA0003E8),
        )
        for words in variants:
            with self.subTest(words=tuple(hex(word) for word in words)):
                self.assertTrue(semantic_entry(words))

    def test_invalid_or_unrelocatable_entries_are_rejected(self) -> None:
        invalid = (
            (PACIASP, sub_sp(8), 0xA9017BFD, 0xAA0003E8),
            (PACIASP, sub_sp(0x80), 0xAA0003E8, 0xAA0103E9),
            (PACIASP, 0x14000000, 0xA9BF7BFD, MOV_FP_SP),
            (BTI_C, PACIASP, 0x10000000, 0xA9017BFD),
            (PACIASP, sub_sp(0x80), 0x29047BFD, 0xAA0003E8),
            (PACIASP, sub_sp(0x80), 0x90000000, 0xA9017BFD),
        )
        for words in invalid:
            with self.subTest(words=tuple(hex(word) for word in words)):
                self.assertFalse(semantic_entry(words))

    def test_capability_gate_rejects_each_resolution_failure(self) -> None:
        self.assertTrue(capability_gate())
        for failure in (
            "pointers", "symbol_validation", "fops_consistent",
            "ioctl_consistent", "kernel_text", "semantic", "relocatable",
        ):
            with self.subTest(failure=failure):
                self.assertFalse(capability_gate(**{failure: False}))

    def test_source_rejects_missing_symbols_and_non_binder_fops(self) -> None:
        for marker in (
            "out.symbol_validations == 0",
            "backend_symbol_available(fops_symbols, out.backend)",
            "backend_symbol_available(ioctl_symbols, out.backend)",
            "compatible_symbol_backends",
            "!address_in_core_text(out.ioctl_kaddr)",
            "!is_kernel_pointer(out.fops_kaddr)",
            "!is_kernel_pointer(out.ioctl_kaddr)",
        ):
            self.assertIn(marker, RESOLVER)

    def test_fops_data_symbol_is_not_mistaken_for_text(self) -> None:
        # binder_fops names a file_operations data object; only ioctl entry
        # symbols are required to lie in the executable kernel text range.
        self.assertIn("all_available_ioctl_symbols_are_text", RESOLVER)
        self.assertNotIn("all_available_ioctl_symbols_are_text(fops_symbols)", RESOLVER)

    def test_direct_binder_veneer_is_classified_via_target_prologue(self) -> None:
        # Some Android 16 builds expose binder_ioctl as PAC + direct B veneer;
        # the real frame prologue lives at the forward branch target.
        for marker in (
            "decode_unconditional_branch",
            "classify_veneer_target",
            "kEntryHasVeneer",
            "classify_single_instruction_hook_site",
            "classify_hookable_entry",
            "branch_index == 0",
            "displacement <= 0",
            "is_kernel_pointer(target)",
            "!address_in_core_text(target)",
            "read_kernel_mem(\n            target",
        ):
            self.assertIn(marker, RESOLVER + HEADER)

    def test_linux_gate_is_61_and_later_6x_only(self) -> None:
        for release in ("6.1.0", "6.6.89", "6.12.38", "6.99.1-oem"):
            self.assertTrue(supported_release(release))
        for release in (
            "5.15.0", "6.0.99", "7.0.0", "", "6.x.1", "6.1.foo",
            "6.1.0foo", "6.1.", "6.1-",
        ):
            self.assertFalse(supported_release(release))
        self.assertIn("is_supported_linux_6_1_or_newer", RESOLVER + HEADER + MODULE)
        for marker in (
            "#if defined(__aarch64__)", "!kArm64Build",
            "sizeof(void*) != 8", "sizeof(binder_uintptr_t) != 8",
        ):
            self.assertIn(marker, MODULE)

    def test_runtime_has_no_per_kernel_profile_matrix_or_fixed_fallback(self) -> None:
        production = RESOLVER + HEADER + MODULE
        for retired in (
            "kClassicBinder66", "kClassicBinder612", "kRustBinder612",
            'kernel_version.rfind("6.6.", 0)',
            'kernel_version.rfind("6.12.", 0)',
            "is_supported_ioctl_profile",
            "offsets.file_f_op = 0xc0",
            "offsets.fops_unlocked_ioctl = 0x48",
            "offsets.fops_unlocked_ioctl = 0x50",
        ):
            self.assertNotIn(retired, production)

    def test_dynamic_resolution_and_required_capabilities_are_guarded(self) -> None:
        production = RESOLVER + HEADER + MODULE
        for marker in (
            "BinderBackend::kClassic", "BinderBackend::kRust",
            "binder_fops", "rust_binder_fops", "binder_ioctl",
            "rust_binder_unlocked_ioctl", "scan_pointer_member",
            "classify_semantic_entry", "kBinderEntryProbeBytes = 256",
            "kRequiredBinderCapabilities", "has_required_binder_capabilities",
            "kCapabilitySymbolCrossValidated", "kCapabilityKernelTextTarget",
            "kCapabilityHookRelocatablePrefix",
        ):
            self.assertIn(marker, production)

    def test_private_capability_record_is_crc_and_size_guarded(self) -> None:
        for marker in (
            "DRMCAP21", "BinderCapabilityRecordV1", "record_size",
            "offsetof(BinderCapabilityRecordV1, crc32)",
            "O_NOFOLLOW", "fchmod(fd, 0600)",
            "drmid_binder_capability_v1.bin",
        ):
            self.assertIn(marker, RESOLVER + HEADER)


if __name__ == "__main__":
    unittest.main()
