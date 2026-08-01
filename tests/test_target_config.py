#!/usr/bin/env python3
"""Fixtures for v2 multi-package target configuration and v1 migration."""

from __future__ import annotations

import binascii
import re
import struct
import unittest


V1_MAGIC = 0x37304746434D5244
V1_SIZE = 256
V2_MAGIC = 0x36314746434D5244
V2_VERSION = 2
V2_SIZE = 4544
FLAG_ENABLED = 1
LIMIT = 32
MODE_ALL = 0
MODE_EUID = 1
MODE_PACKAGE = 2
PACKAGE_RE = re.compile(r"^(?:[A-Za-z0-9_]+\.)+[A-Za-z0-9_]+$")


def c_string(value: str, capacity: int) -> bytes:
    raw = value.encode()
    if len(raw) >= capacity:
        raise ValueError(value)
    return raw + bytes(capacity - len(raw))


def normalize_packages(text: str) -> tuple[list[str], int, int]:
    source = [item.strip() for item in re.split(r"[,\r\n]", text) if item.strip()]
    if not source or any(not PACKAGE_RE.fullmatch(item) for item in source):
        raise ValueError("packages")
    unique = sorted(set(source))
    if len(unique) > LIMIT:
        raise ValueError("package count")
    return unique, len(source), len(source) - len(unique)


def v1_record(generation: int, package: str, uid: int) -> bytes:
    prefix = struct.pack(
        "<QIIQIIII128s64s16s",
        V1_MAGIC, 1, V1_SIZE, generation, MODE_PACKAGE, 0, uid,
        FLAG_ENABLED, c_string(package, 128), c_string("顺风速运", 64), bytes(16),
    )
    return prefix + struct.pack("<II", binascii.crc32(prefix) & 0xFFFFFFFF, 0)


def v2_record(
    generation: int,
    packages: list[str],
    resolved_uids: list[int],
    profile_domain: str,
    *,
    mode: int = MODE_PACKAGE,
    exact_uid: int = 0,
) -> bytes:
    if mode == MODE_PACKAGE:
        if not 1 <= len(packages) <= LIMIT or len(packages) != len(resolved_uids):
            raise ValueError("package count")
        if packages != sorted(set(packages)) or any(not PACKAGE_RE.fullmatch(x) for x in packages):
            raise ValueError("canonical packages")
        if any(uid <= 0 for uid in resolved_uids):
            raise ValueError("resolved uid")
        targets = sorted(set(resolved_uids))
    elif mode == MODE_EUID:
        packages, resolved_uids, profile_domain = [], [], ""
        targets = [exact_uid]
    else:
        packages, resolved_uids, profile_domain, targets = [], [], "", []
    package_blob = b"".join(c_string(item, 128) for item in packages)
    package_blob += bytes((LIMIT - len(packages)) * 128)
    resolved = resolved_uids + [0] * (LIMIT - len(resolved_uids))
    padded_targets = targets + [0] * (LIMIT - len(targets))
    prefix = struct.pack(
        "<QIIQIIII128s4096s32I32I16s",
        V2_MAGIC, V2_VERSION, V2_SIZE, generation, mode, len(packages),
        len(targets), FLAG_ENABLED, c_string(profile_domain, 128), package_blob,
        *resolved, *padded_targets, bytes(16),
    )
    assert len(prefix) == 4536
    return prefix + struct.pack("<II", binascii.crc32(prefix) & 0xFFFFFFFF, 0)


def unpack_v2(record: bytes) -> dict:
    if len(record) != V2_SIZE:
        raise ValueError("size")
    magic, version, size, generation, mode, package_count, target_count, flags = struct.unpack_from(
        "<QIIQIIII", record
    )
    profile = record[40:168].split(b"\0", 1)[0].decode()
    package_blob = record[168:4264]
    packages = [
        package_blob[i * 128:(i + 1) * 128].split(b"\0", 1)[0].decode()
        for i in range(package_count)
    ]
    resolved = list(struct.unpack_from("<32I", record, 4264))
    targets = list(struct.unpack_from("<32I", record, 4392))
    crc, tail = struct.unpack_from("<II", record, 4536)
    return locals()


def validate_v2(record: bytes) -> bool:
    try:
        value = unpack_v2(record)
    except (ValueError, struct.error, UnicodeDecodeError):
        return False
    if (
        value["magic"] != V2_MAGIC or value["version"] != V2_VERSION
        or value["size"] != V2_SIZE or value["generation"] == 0
        or value["mode"] not in (0, 1, 2) or not value["flags"] & FLAG_ENABLED
        or value["crc"] != (binascii.crc32(record[:4536]) & 0xFFFFFFFF)
        or value["tail"] != 0
    ):
        return False
    packages, resolved, targets = value["packages"], value["resolved"], value["targets"]
    if value["mode"] == MODE_PACKAGE:
        active_resolved = resolved[: value["package_count"]]
        active_targets = targets[: value["target_count"]]
        return (
            1 <= len(packages) <= LIMIT and packages == sorted(set(packages))
            and all(PACKAGE_RE.fullmatch(x) for x in packages)
            and PACKAGE_RE.fullmatch(value["profile"] or "") is not None
            and all(active_resolved) and active_targets == sorted(set(active_resolved))
            and not any(resolved[value["package_count"]:])
            and not any(targets[value["target_count"]:])
        )
    if value["mode"] == MODE_EUID:
        return not packages and value["target_count"] == 1 and targets[0] != 0
    return not packages and value["target_count"] == 0 and not any(targets)


def migrate_v1(record: bytes) -> bytes:
    if len(record) != V1_SIZE or struct.unpack_from("<Q", record)[0] != V1_MAGIC:
        raise ValueError("v1")
    generation = struct.unpack_from("<Q", record, 16)[0]
    package = record[40:168].split(b"\0", 1)[0].decode()
    uid = struct.unpack_from("<I", record, 32)[0]
    return v2_record(generation, [package], [uid], package)


class TargetConfigTest(unittest.TestCase):
    def test_fresh_install_bootstrap_has_no_package_dependency(self) -> None:
        bootstrap = v2_record(1, [], [], "", mode=MODE_ALL)
        self.assertTrue(validate_v2(bootstrap))
        parsed = unpack_v2(bootstrap)
        self.assertEqual(parsed["mode"], MODE_ALL)
        self.assertEqual(parsed["package_count"], 0)
        self.assertEqual(parsed["target_count"], 0)
        self.assertEqual(parsed["packages"], [])
        self.assertEqual(parsed["profile"], "")

        first = v2_record(
            2,
            ["com.example.first"],
            [10456],
            "com.example.first",
        )
        self.assertTrue(validate_v2(first))
        self.assertEqual(unpack_v2(first)["generation"], 2)

    def test_three_packages_are_sorted_and_uid_set_is_deduplicated(self) -> None:
        packages, source, duplicates = normalize_packages(
            "com.z.app, com.a.app\ncom.z.app\ncom.shared.app"
        )
        self.assertEqual((source, duplicates), (4, 1))
        record = v2_record(8, packages, [10001, 10002, 10001], "com.sf.activity")
        self.assertTrue(validate_v2(record))
        parsed = unpack_v2(record)
        self.assertEqual(parsed["targets"][: parsed["target_count"]], [10001, 10002])

    def test_boundaries_zero_one_32_33(self) -> None:
        with self.assertRaises(ValueError):
            normalize_packages("")
        one, *_ = normalize_packages("com.example.one")
        self.assertEqual(len(one), 1)
        names32 = [f"com.example.p{i}" for i in range(32)]
        canonical, *_ = normalize_packages("\n".join(names32))
        self.assertEqual(len(canonical), 32)
        with self.assertRaises(ValueError):
            normalize_packages("\n".join(names32 + ["com.example.extra"]))

    def test_reorder_and_duplicates_do_not_change_semantic_record(self) -> None:
        first, *_ = normalize_packages("com.b.app\ncom.a.app")
        second, _, duplicate_count = normalize_packages(
            "com.a.app,com.b.app,com.a.app"
        )
        self.assertEqual(first, second)
        self.assertEqual(duplicate_count, 1)
        self.assertEqual(
            v2_record(7, first, [10001, 10002], "com.sf.activity"),
            v2_record(7, second, [10001, 10002], "com.sf.activity"),
        )

    def test_v1_migration_preserves_generation_package_uid_and_domain(self) -> None:
        migrated = migrate_v1(v1_record(7, "com.sf.activity", 10373))
        self.assertTrue(validate_v2(migrated))
        parsed = unpack_v2(migrated)
        self.assertEqual(parsed["generation"], 7)
        self.assertEqual(parsed["packages"], ["com.sf.activity"])
        self.assertEqual(parsed["profile"], "com.sf.activity")
        self.assertEqual(parsed["targets"][0], 10373)

    def test_package_set_change_keeps_stable_profile_domain(self) -> None:
        old = v2_record(7, ["com.sf.activity"], [10373], "com.sf.activity")
        new = v2_record(
            8,
            ["com.example.second", "com.sf.activity"],
            [10455, 10373],
            unpack_v2(old)["profile"],
        )
        self.assertEqual(unpack_v2(old)["profile"], unpack_v2(new)["profile"])
        self.assertNotEqual(old, new)

    def test_corruption_and_zero_uid_fail_closed(self) -> None:
        record = bytearray(v2_record(1, ["com.sf.activity"], [10373], "com.sf.activity"))
        record[500] ^= 0x80
        self.assertFalse(validate_v2(bytes(record)))
        with self.assertRaises(ValueError):
            v2_record(1, ["com.sf.activity"], [0], "com.sf.activity")

    def test_unresolved_candidate_does_not_replace_previous_generation(self) -> None:
        active = v2_record(7, ["com.sf.activity"], [10373], "com.sf.activity")
        resolutions = {"com.sf.activity": 10373, "com.missing.app": 0}
        requested, *_ = normalize_packages("com.sf.activity\ncom.missing.app")
        resolved = [resolutions[name] for name in requested]
        publishable = all(resolved)
        self.assertFalse(publishable)
        self.assertEqual(unpack_v2(active)["generation"], 7)


if __name__ == "__main__":
    unittest.main()
