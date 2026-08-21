#!/usr/bin/env python3
"""Fixtures for the persistent seed and fixed global Widevine profile."""

from __future__ import annotations

import binascii
import hashlib
import hmac
from pathlib import Path
import struct
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "runtime_profile.cpp").read_text(encoding="utf-8")
HEADER = (ROOT / "runtime_profile.h").read_text(encoding="utf-8")
MAGIC = 0x30354445534D5244
SALT = b"SKP-DRMID-SALT-v1"
INFO = b"global-widevine-v1"


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        output += previous
        counter += 1
    return bytes(output[:length])


def seed_record(seed: bytes, generation: int) -> bytes:
    prefix = struct.pack("<QIIQ32s", MAGIC, 1, 32, generation, seed)
    return prefix + struct.pack("<II", binascii.crc32(prefix) & 0xFFFFFFFF, 0)


class RuntimeProfileTest(unittest.TestCase):
    def test_rfc5869_case_1(self) -> None:
        expected = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c"
            "5db02d56ecc4c5bf34007208d5b887185865"
        )
        self.assertEqual(
            hkdf(bytes([0x0B]) * 22, bytes(range(13)), bytes(range(0xF0, 0xFA)), 42),
            expected,
        )

    def test_seed_record_layout_and_crc(self) -> None:
        record = seed_record(bytes(range(32)), 7)
        self.assertEqual(len(record), 64)
        self.assertEqual(struct.unpack_from("<I", record, 56)[0], binascii.crc32(record[:56]) & 0xFFFFFFFF)
        damaged = bytearray(record)
        damaged[31] ^= 0x80
        self.assertNotEqual(struct.unpack_from("<I", damaged, 56)[0], binascii.crc32(damaged[:56]) & 0xFFFFFFFF)

    def test_global_profile_is_stable_for_same_seed(self) -> None:
        seed = bytes(range(32))
        first = hkdf(seed, SALT, INFO, 64)
        self.assertEqual(first, hkdf(seed, SALT, INFO, 64))
        self.assertEqual(len(first), 64)

    def test_seed_change_rotates_global_profile(self) -> None:
        self.assertNotEqual(hkdf(bytes(32), SALT, INFO, 64), hkdf(bytes([1]) * 32, SALT, INFO, 64))

    def test_domain_contains_no_package_uid_or_target_state(self) -> None:
        self.assertIn('"global-widevine-v1"', SOURCE)
        for retired in ("package_name", "target_euid", "TargetRuleMode", "profile_domain"):
            self.assertNotIn(retired, SOURCE + HEADER)

    def test_active_fingerprint_covers_first_32_bytes(self) -> None:
        self.assertIn("profile.virtual_stream.data(), kVirtualIdBytes", SOURCE)
        seed = bytes(range(32))
        stream = hkdf(seed, SALT, INFO, 64)
        self.assertNotEqual(hashlib.sha256(stream[:32]).digest(), hashlib.sha256(stream).digest())


if __name__ == "__main__":
    unittest.main()
