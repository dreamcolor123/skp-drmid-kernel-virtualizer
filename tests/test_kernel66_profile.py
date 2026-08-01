from __future__ import annotations

from pathlib import Path
import re
import struct
import unittest


ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "tests" / "fixtures" / "kernel66_profile.txt"
RESOLVER = (ROOT / "binder_ioctl_resolver.cpp").read_text(encoding="utf-8")
HEADER = (ROOT / "binder_ioctl_resolver.h").read_text(encoding="utf-8")
MODULE = (ROOT / "module_main.cpp").read_text(encoding="utf-8")

CLASSIC_66 = (0xD503233F, 0xD10343FF, 0xA9077BFD, 0xA9086FFC)
CLASSIC_612 = (0xD503233F, 0xD10303FF, 0xA9067BFD, 0xA9076FFC)
RUST_612 = (0xD503233F, 0xA9BF7BFD, 0x910003FD, 0xAA0003E8)


def fnv1a64(data: bytes) -> int:
    value = 14695981039346656037
    for byte in data:
        value ^= byte
        value = (value * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return value


def classify(words: tuple[int, int, int, int]) -> str:
    if words == CLASSIC_66:
        return "classic66"
    if words == CLASSIC_612:
        return "classic612"
    if words == RUST_612:
        return "rust612"
    return "unknown"


def supported(kernel: str, backend: str) -> bool:
    if kernel.startswith("6.6."):
        return backend == "classic66"
    if kernel.startswith("6.12."):
        return backend in {"classic612", "rust612"}
    return False


class Kernel66ProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.capture = CAPTURE.read_text(encoding="utf-8")

    def test_single_probe_was_complete(self) -> None:
        self.assertIn("schema=skp-drmid-kernel66-sdk-probe-v1", self.capture)
        self.assertIn("kernel=6.6.89", self.capture)
        self.assertIn("probe_complete=yes symbol_code=1 live=1", self.capture)
        self.assertIn("code.live_matches_symbol_bytes=1", self.capture)
        self.assertIn("identity.euid_match=1", self.capture)
        self.assertIn("pid_match=1 tgid_match=1", self.capture)

    def test_captured_sdk_offsets_are_frozen(self) -> None:
        expected = {
            "task.files": 2144,
            "files.fdt": 32,
            "fdtable.fd": 8,
            "file.f_op": 192,
            "file_operations.unlocked_ioctl": 72,
            "task.pid": 1560,
            "task.tgid": 1564,
            "task.cred": 2080,
            "cred.uid": 8,
            "cred.euid": 24,
        }
        for name, value in expected.items():
            with self.subTest(name=name):
                match = re.search(
                    rf"offset\.{re.escape(name)}\.result=OK \(0\) value=(\d+)",
                    self.capture,
                )
                self.assertIsNotNone(match)
                self.assertEqual(int(match.group(1)), value)

    def test_symbol_and_live_targets_are_identical(self) -> None:
        symbol = re.search(
            r"symbol\.binder_ioctl\.result=OK \(0\) address=(0x[0-9a-f]+)",
            self.capture,
        )
        live = re.search(
            r"live\.unlocked_ioctl\.result=OK \(0\) value=(0x[0-9a-f]+)",
            self.capture,
        )
        self.assertIsNotNone(symbol)
        self.assertIsNotNone(live)
        self.assertEqual(symbol.group(1), live.group(1))
        self.assertIn("live.fops_matches_symbol=1", self.capture)
        self.assertIn("live.ioctl_matches_symbol=1", self.capture)

    def test_captured_256_byte_body_and_fingerprint(self) -> None:
        chunks = []
        for offset in range(0, 256, 16):
            match = re.search(
                rf"code\.binder_ioctl_symbol\.{offset:04x}=([0-9a-f]{{32}})",
                self.capture,
            )
            self.assertIsNotNone(match)
            chunks.append(bytes.fromhex(match.group(1)))
        body = b"".join(chunks)
        self.assertEqual(len(body), 256)
        self.assertEqual(fnv1a64(body), 0x62E54BF3E7AA39BB)
        self.assertEqual(struct.unpack_from("<4I", body), CLASSIC_66)

    def test_runtime_classifier_contains_exact_captured_prologue(self) -> None:
        for word in CLASSIC_66:
            self.assertIn(f"0x{word:08x}U", RESOLVER)
        self.assertIn("kClassicBinder66", HEADER)
        self.assertIn('return "classic_binder-6.6"', RESOLVER)

    def test_file_and_fops_fallbacks_match_live_capture(self) -> None:
        self.assertIn("offsets.file_f_op = 0xc0", RESOLVER)
        self.assertIn("offsets.fops_unlocked_ioctl = 0x48", RESOLVER)
        self.assertIn("offset < 0x100", RESOLVER)
        self.assertIn("offset < 0x108", RESOLVER)

    def test_kernel_backend_matrix_fails_closed(self) -> None:
        self.assertTrue(supported("6.6.89", classify(CLASSIC_66)))
        self.assertFalse(supported("6.6.89", classify(CLASSIC_612)))
        self.assertFalse(supported("6.6.89", classify(RUST_612)))
        self.assertTrue(supported("6.12.38", classify(CLASSIC_612)))
        self.assertTrue(supported("6.12.38", classify(RUST_612)))
        self.assertFalse(supported("6.12.38", classify(CLASSIC_66)))
        self.assertFalse(supported("6.1.0", classify(CLASSIC_66)))
        self.assertIn("is_supported_ioctl_profile", RESOLVER)
        self.assertIn("kernel_version.rfind(\"6.6.\", 0)", RESOLVER)
        self.assertIn("kernel_version.rfind(\"6.12.\", 0)", RESOLVER)

    def test_each_prologue_word_is_part_of_the_guard(self) -> None:
        for index in range(4):
            mutated = list(CLASSIC_66)
            mutated[index] ^= 1
            self.assertEqual(classify(tuple(mutated)), "unknown")

    def test_main_platform_gate_accepts_only_66_or_612(self) -> None:
        self.assertIn('kernel_version.rfind("6.6.", 0) == 0', MODULE)
        self.assertIn('kernel_version.rfind("6.12.", 0) == 0', MODULE)
        self.assertIn("strict kernel/backend profile guard", MODULE)
        self.assertNotIn("is_supported_612_ioctl_profile", MODULE)


if __name__ == "__main__":
    unittest.main()
