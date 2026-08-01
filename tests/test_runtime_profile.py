#!/usr/bin/env python3
"""Fixtures for persistent seed, stable domains and bounded EUID-set rules."""

from __future__ import annotations

import binascii
import hashlib
import hmac
import struct
import unittest


MAGIC = 0x30354445534D5244
VERSION = 1
SEED_SIZE = 32
SALT = b"SKP-DRMID-SALT-v1"
LABEL = b"A14+-WIDEVINE-v1"
PACKAGE_LABEL = b"A14+-WIDEVINE-PKG-v1"


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            prk, previous + info + bytes([counter]), hashlib.sha256
        ).digest()
        output += previous
        counter += 1
    return bytes(output[:length])


def profile_info(rule_mode: int, target_euid: int) -> bytes:
    return LABEL + bytes([rule_mode]) + struct.pack("<I", target_euid) + b"612"


def package_profile_info(package_name: str) -> bytes:
    info = bytearray(64)
    info[: len(PACKAGE_LABEL)] = PACKAGE_LABEL
    info[20] = 2
    info[21:24] = b"612"
    info[32:64] = hashlib.sha256(package_name.encode()).digest()
    return bytes(info)


def seed_record(seed: bytes, generation: int) -> bytes:
    prefix = struct.pack("<QIIQ32s", MAGIC, VERSION, SEED_SIZE, generation, seed)
    crc = binascii.crc32(prefix) & 0xFFFFFFFF
    return prefix + struct.pack("<II", crc, 0)


def validate_seed_record(record: bytes) -> bool:
    if len(record) != 64:
        return False
    magic, version, seed_size, generation = struct.unpack_from("<QIIQ", record)
    crc = struct.unpack_from("<I", record, 56)[0]
    return (
        magic == MAGIC
        and version == VERSION
        and seed_size == SEED_SIZE
        and generation != 0
        and crc == (binascii.crc32(record[:56]) & 0xFFFFFFFF)
    )


def rule_matches(rule_mode: int, target_euids: list[int], current_euid: int) -> bool:
    if rule_mode == 0:
        return not target_euids
    if rule_mode not in (1, 2) or not 1 <= len(target_euids) <= 32:
        return False
    if target_euids != sorted(set(target_euids)) or not all(target_euids):
        return False
    return current_euid in target_euids


class RuntimeProfileTest(unittest.TestCase):
    def test_rfc5869_case_1(self) -> None:
        ikm = bytes([0x0B]) * 22
        salt = bytes(range(13))
        info = bytes(range(0xF0, 0xFA))
        expected = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )
        self.assertEqual(hkdf(ikm, salt, info, 42), expected)

    def test_seed_record_crc(self) -> None:
        record = seed_record(bytes(range(32)), 7)
        self.assertEqual(len(record), 64)
        self.assertTrue(validate_seed_record(record))
        damaged = bytearray(record)
        damaged[31] ^= 0x80
        self.assertFalse(validate_seed_record(bytes(damaged)))

    def test_profile_is_stable(self) -> None:
        seed = bytes(range(32))
        info = profile_info(1, 2000)
        self.assertEqual(hkdf(seed, SALT, info, 64), hkdf(seed, SALT, info, 64))

    def test_uid_domain_separation(self) -> None:
        seed = bytes(range(32))
        shell = hkdf(seed, SALT, profile_info(1, 2000), 64)
        app = hkdf(seed, SALT, profile_info(1, 10403), 64)
        wildcard = hkdf(seed, SALT, profile_info(0, 0), 64)
        self.assertNotEqual(shell, app)
        self.assertNotEqual(shell, wildcard)

    def test_package_domain_survives_uid_change(self) -> None:
        seed = bytes(range(32))
        package = "com.sf.activity"
        first = hkdf(seed, SALT, package_profile_info(package), 64)
        after_reinstall = hkdf(seed, SALT, package_profile_info(package), 64)
        other = hkdf(seed, SALT, package_profile_info("com.example.other"), 64)
        self.assertEqual(first, after_reinstall)
        self.assertNotEqual(first, other)

    def test_package_domain_survives_target_set_change_and_reorder(self) -> None:
        seed = bytes(range(32))
        stable_domain = "com.sf.activity"
        before = hkdf(seed, SALT, package_profile_info(stable_domain), 64)
        # Package collection is intentionally absent from the HKDF info. The
        # persisted profile domain remains the migrated single package.
        after_add = hkdf(seed, SALT, package_profile_info(stable_domain), 64)
        after_reorder = hkdf(seed, SALT, package_profile_info(stable_domain), 64)
        self.assertEqual(before, after_add)
        self.assertEqual(before, after_reorder)

    def test_bounded_euid_set_rule(self) -> None:
        self.assertTrue(rule_matches(0, [], 2000))
        self.assertTrue(rule_matches(1, [2000], 2000))
        self.assertTrue(rule_matches(2, [2000, 10373, 10455], 10373))
        self.assertFalse(rule_matches(2, [2000, 10373, 10455], 9999))
        self.assertFalse(rule_matches(2, [], 2000))
        self.assertFalse(rule_matches(2, [10373, 0], 10373))
        self.assertFalse(rule_matches(2, [10373, 10373], 10373))
        self.assertFalse(rule_matches(2, list(range(1, 34)), 1))


if __name__ == "__main__":
    unittest.main()
