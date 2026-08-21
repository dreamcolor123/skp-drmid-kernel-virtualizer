#!/usr/bin/env python3
"""Fixtures for ABI-18 global runtime control and atomic double slots."""

from __future__ import annotations

import binascii
import ctypes
import importlib.util
import os
from pathlib import Path
import struct
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools" / "write_runtime_control.py"
SPEC = importlib.util.spec_from_file_location("runtime_control_writer", TOOLS)
assert SPEC and SPEC.loader
WRITER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WRITER)
V2_MAGIC = 0x36314C54434D5244


class RuntimeSlotLayout(ctypes.Structure):
    _fields_ = [
        ("config_generation", ctypes.c_uint64),
        ("seed_generation", ctypes.c_uint64),
        ("profile_fingerprint", ctypes.c_uint64),
        ("replacement_mode", ctypes.c_uint32),
        ("virtual_id_length", ctypes.c_uint32),
        ("virtual_id", ctypes.c_uint8 * 64),
    ]


def valid_v3(record: bytes) -> bool:
    if len(record) != 128:
        return False
    fields = struct.unpack("<QIIQQQII64sQII", record)
    magic, version, size, generation, seed_generation, fingerprint = fields[:6]
    mode, length, virtual_id, reserved, crc, tail = fields[6:]
    return (
        magic == WRITER.MAGIC
        and version == 3
        and size == 128
        and generation > 0
        and seed_generation > 0
        and fingerprint > 0
        and mode in (0, 1)
        and length == 32
        and not any(virtual_id[length:])
        and reserved == 0
        and tail == 0
        and crc == (binascii.crc32(record[:120]) & 0xFFFFFFFF)
    )


def build_v2(generation: int, seed_generation: int, fingerprint: int, mode: int, virtual_id: bytes) -> bytes:
    targets = [10373, 10455] + [0] * 30
    prefix = struct.pack(
        "<QIIQQQIIII32I64s",
        V2_MAGIC, 2, 256, generation, seed_generation, fingerprint,
        mode, 2, 2, len(virtual_id), *targets,
        virtual_id + bytes(64 - len(virtual_id)),
    )
    return prefix + struct.pack("<II", binascii.crc32(prefix) & 0xFFFFFFFF, 0)


def migrate_v2(record: bytes) -> bytes:
    fields = struct.unpack("<QIIQQQIIII32I64sII", record)
    if fields[0:3] != (V2_MAGIC, 2, 256):
        raise ValueError("v2 type")
    if fields[-2] != (binascii.crc32(record[:248]) & 0xFFFFFFFF):
        raise ValueError("v2 crc")
    generation, seed_generation, fingerprint = fields[3:6]
    mode, length = fields[6], fields[9]
    virtual_id = fields[42][:length]
    return WRITER.build_record(generation, seed_generation, fingerprint, mode, virtual_id)


class DoubleBuffer:
    def __init__(self, generation: int, payload: bytes):
        self.active = 0
        self.slots = [(generation, bytes(payload)), (generation, bytes(payload))]

    def acquire(self):
        return self.slots[self.active]

    def publish(self, generation: int, payload: bytes) -> bool:
        if generation <= self.acquire()[0]:
            return False
        inactive = self.active ^ 1
        self.slots[inactive] = (generation, bytes(payload))
        self.active = inactive
        return True


class RuntimeControlTest(unittest.TestCase):
    def test_kernel_slot_layout_is_global_96_bytes(self) -> None:
        self.assertEqual(ctypes.sizeof(RuntimeSlotLayout), 96)
        self.assertEqual(RuntimeSlotLayout.replacement_mode.offset, 24)
        self.assertEqual(RuntimeSlotLayout.virtual_id.offset, 32)

    def test_v3_record_layout_crc_and_global_payload(self) -> None:
        record = WRITER.build_record(8, 3, 0x1234, 1, bytes(range(32)))
        self.assertTrue(valid_v3(record))
        self.assertEqual(struct.unpack_from("<I", record, 44)[0], 32)
        self.assertEqual(record[48:80], bytes(range(32)))

    def test_writer_requires_exact_32_byte_id(self) -> None:
        for size in (0, 1, 31, 33, 64):
            with self.assertRaises(ValueError):
                WRITER.build_record(1, 1, 1, 0, bytes(size))

    def test_crc_corruption_fails_closed(self) -> None:
        record = bytearray(WRITER.build_record(2, 1, 1, 1, bytes(range(32))))
        record[60] ^= 0x40
        self.assertFalse(valid_v3(bytes(record)))

    def test_v2_migration_preserves_id_mode_generations_and_fingerprint(self) -> None:
        custom = bytes(reversed(range(32)))
        migrated = migrate_v2(build_v2(7, 2, 0xA150911F32649CF3, 1, custom))
        self.assertTrue(valid_v3(migrated))
        fields = struct.unpack("<QIIQQQII64sQII", migrated)
        self.assertEqual(fields[3:8], (7, 2, 0xA150911F32649CF3, 1, 32))
        self.assertEqual(fields[8][:32], custom)

    def test_v2_target_fields_do_not_enter_v3(self) -> None:
        old = build_v2(7, 2, 1, 0, bytes(range(32)))
        migrated = migrate_v2(old)
        self.assertEqual(len(migrated), 128)
        self.assertNotIn(struct.pack("<I", 10373), migrated[40:48])

    def test_atomic_publish_mode_and_permissions(self) -> None:
        tmp_root = "/dev/shm" if os.path.isdir("/dev/shm") else None
        with tempfile.TemporaryDirectory(dir=tmp_root) as directory:
            path = Path(directory) / "drmid_runtime_control_v3.bin"
            WRITER.publish(path, WRITER.build_record(2, 1, 1, 0, bytes(range(32))))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertTrue(valid_v3(path.read_bytes()))

    def test_double_slot_rejects_stale_generation(self) -> None:
        model = DoubleBuffer(1, b"A" * 32)
        self.assertTrue(model.publish(2, b"B" * 32))
        self.assertFalse(model.publish(2, b"C" * 32))
        self.assertTrue(model.publish(3, b"C" * 32))

    def test_acquired_slot_is_coherent_across_publish(self) -> None:
        model = DoubleBuffer(1, b"A" * 32)
        acquired = model.acquire()
        self.assertTrue(model.publish(2, b"B" * 32))
        self.assertEqual(acquired, (1, b"A" * 32))
        self.assertEqual(model.acquire(), (2, b"B" * 32))


if __name__ == "__main__":
    unittest.main()
