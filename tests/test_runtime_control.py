#!/usr/bin/env python3
"""Offline fixtures for ABI-14 multi-target double-buffer control records."""

from __future__ import annotations

import binascii
import ctypes
import importlib.util
import os
from pathlib import Path
import struct
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools" / "write_runtime_control.py"
SPEC = importlib.util.spec_from_file_location("runtime_control_writer", TOOLS)
assert SPEC and SPEC.loader
WRITER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WRITER)
V1_MAGIC = 0x38304C54434D5244


class RuntimeSlotLayout(ctypes.Structure):
    _fields_ = [
        ("config_generation", ctypes.c_uint64),
        ("seed_generation", ctypes.c_uint64),
        ("profile_fingerprint", ctypes.c_uint64),
        ("replacement_mode", ctypes.c_uint32),
        ("rule_mode", ctypes.c_uint32),
        ("target_count", ctypes.c_uint32),
        ("virtual_id_length", ctypes.c_uint32),
        ("target_euids", ctypes.c_uint32 * 32),
        ("virtual_id", ctypes.c_uint8 * 64),
    ]


class DoubleBufferModel:
    def __init__(self, generation: int, payload: bytes) -> None:
        self.active = 0
        self.slots = [(generation, payload), (generation, payload)]
        self.switches = 0

    def acquire(self) -> tuple[int, bytes]:
        generation, payload = self.slots[self.active]
        return generation, bytes(payload)

    def publish(self, generation: int, payload: bytes) -> bool:
        if generation <= self.slots[self.active][0]:
            return False
        inactive = self.active ^ 1
        self.slots[inactive] = (generation, bytes(payload))
        self.active = inactive
        self.switches += 1
        return True


def valid(record: bytes) -> bool:
    if len(record) != 256:
        return False
    fields = struct.unpack_from("<QIIQQQIIII32I64s", record)
    magic, version, size, generation, seed_generation, _ = fields[:6]
    mode, rule, count, length = fields[6:10]
    targets = fields[10:42]
    crc, tail = struct.unpack_from("<II", record, 248)
    active = targets[:count]
    return (
        magic == WRITER.MAGIC and version == 2 and size == 256
        and generation != 0 and seed_generation != 0 and mode in (0, 1)
        and rule in (0, 1, 2) and 1 <= length <= 64 and tail == 0
        and ((rule == 0 and count == 0) or (rule != 0 and 1 <= count <= 32))
        and list(active) == sorted(set(active)) and all(active)
        and not any(targets[count:])
        and crc == (binascii.crc32(record[:248]) & 0xFFFFFFFF)
    )


def v1_record(
    generation: int,
    seed_generation: int,
    fingerprint: int,
    mode: int,
    rule: int,
    target_uid: int,
    virtual_id: bytes,
) -> bytes:
    prefix = struct.pack(
        "<QIIQQQIIII64s",
        V1_MAGIC, 1, 128, generation, seed_generation, fingerprint,
        mode, rule, target_uid, len(virtual_id),
        virtual_id + bytes(64 - len(virtual_id)),
    )
    return prefix + struct.pack("<II", binascii.crc32(prefix) & 0xFFFFFFFF, 0)


def migrate_v1(record: bytes, targets: list[int]) -> bytes:
    fields = struct.unpack("<QIIQQQIIII64sII", record)
    magic, version, size = fields[:3]
    if magic != V1_MAGIC or version != 1 or size != 128:
        raise ValueError("v1 type")
    generation, seed_generation, fingerprint = fields[3:6]
    mode, rule, target_uid, length, virtual_id = fields[6:11]
    if rule != 0 and targets != [target_uid]:
        raise ValueError("target mismatch")
    return WRITER.build_record(
        generation, seed_generation, fingerprint, mode, rule,
        targets, virtual_id[:length],
    )


class RuntimeControlTest(unittest.TestCase):
    def test_kernel_slot_layout(self) -> None:
        self.assertEqual(ctypes.sizeof(RuntimeSlotLayout), 232)
        self.assertEqual(RuntimeSlotLayout.replacement_mode.offset, 24)
        self.assertEqual(RuntimeSlotLayout.target_euids.offset, 40)
        self.assertEqual(RuntimeSlotLayout.virtual_id.offset, 168)

    def test_record_layout_crc_and_three_targets(self) -> None:
        record = WRITER.build_record(
            8, 1, 0x1234, 1, 2, [10373, 10455, 10500], bytes(range(32))
        )
        self.assertEqual(len(record), 256)
        self.assertTrue(valid(record))
        self.assertEqual(struct.unpack_from("<I", record, 48)[0], 3)
        self.assertEqual(struct.unpack_from("<3I", record, 56), (10373, 10455, 10500))

    def test_writer_sorts_and_deduplicates_uids(self) -> None:
        record = WRITER.build_record(
            8, 1, 0x1234, 0, 2, [10500, 10373, 10500], bytes(range(32))
        )
        self.assertTrue(valid(record))
        self.assertEqual(struct.unpack_from("<I", record, 48)[0], 2)
        self.assertEqual(struct.unpack_from("<2I", record, 56), (10373, 10500))

    def test_target_boundaries_0_1_32_33(self) -> None:
        self.assertTrue(valid(WRITER.build_record(1, 1, 1, 0, 0, [], b"x")))
        self.assertTrue(valid(WRITER.build_record(1, 1, 1, 0, 2, [10001], b"x")))
        values = list(range(10001, 10033))
        self.assertTrue(valid(WRITER.build_record(1, 1, 1, 0, 2, values, b"x")))
        with self.assertRaises(ValueError):
            WRITER.build_record(1, 1, 1, 0, 2, values + [10033], b"x")
        with self.assertRaises(ValueError):
            WRITER.build_record(1, 1, 1, 0, 2, [], b"x")

    def test_corruption_and_zero_uid_fail_closed(self) -> None:
        record = bytearray(
            WRITER.build_record(2, 1, 0x1234, 1, 2, [10373], bytes(range(32)))
        )
        record[72] ^= 0x40
        self.assertFalse(valid(bytes(record)))
        with self.assertRaises(ValueError):
            WRITER.build_record(2, 1, 1, 1, 2, [0], b"x")

    def test_generation_and_slot_payload_can_differ(self) -> None:
        first = WRITER.build_record(2, 1, 1, 1, 2, [10373], bytes(range(32)))
        second = WRITER.build_record(
            3, 1, 1, 1, 2, [10373, 10455], bytes(range(32))
        )
        self.assertTrue(valid(first) and valid(second))
        self.assertNotEqual(first, second)

    def test_v1_migration_preserves_custom_id_mode_and_fingerprint(self) -> None:
        custom = bytes(reversed(range(32)))
        old = v1_record(7, 1, 0xA150911F32649CF3, 1, 2, 10373, custom)
        migrated = migrate_v1(old, [10373])
        self.assertTrue(valid(migrated))
        fields = struct.unpack("<QIIQQQIIII32I64sII", migrated)
        self.assertEqual(fields[3:6], (7, 1, 0xA150911F32649CF3))
        self.assertEqual(fields[6:10], (1, 2, 1, 32))
        self.assertEqual(fields[10], 10373)
        self.assertEqual(fields[42][:32], custom)

    def test_v1_migration_rejects_target_mismatch(self) -> None:
        old = v1_record(7, 1, 1, 0, 2, 10373, bytes(range(32)))
        with self.assertRaises(ValueError):
            migrate_v1(old, [10373, 10455])

    def test_atomic_publish_has_fixed_mode(self) -> None:
        tmp_root = "/dev/shm" if os.path.isdir("/dev/shm") else None
        with tempfile.TemporaryDirectory(dir=tmp_root) as directory:
            path = Path(directory) / "drmid_runtime_control_v2.bin"
            WRITER.publish(
                path,
                WRITER.build_record(2, 1, 1, 0, 2, [10373], bytes(range(32))),
            )
            self.assertEqual(path.stat().st_size, 256)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertTrue(valid(path.read_bytes()))

    def test_double_buffer_alternates_and_rejects_stale_generation(self) -> None:
        model = DoubleBufferModel(1, b"A" * 32)
        self.assertTrue(model.publish(2, b"B" * 32))
        self.assertEqual((model.active, model.switches), (1, 1))
        self.assertFalse(model.publish(2, b"C" * 32))
        self.assertTrue(model.publish(3, b"C" * 32))
        self.assertEqual((model.active, model.switches), (0, 2))

    def test_acquired_slot_stays_coherent_across_target_flip(self) -> None:
        model = DoubleBufferModel(1, b"one-target")
        acquired = model.acquire()
        self.assertTrue(model.publish(2, b"three-targets"))
        self.assertEqual(acquired, (1, b"one-target"))
        self.assertEqual(model.acquire(), (2, b"three-targets"))


if __name__ == "__main__":
    unittest.main()
