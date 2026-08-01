#!/usr/bin/env python3
"""Fixtures for the 0.2.1 per-thread synchronous Binder Pending model."""

from __future__ import annotations

from dataclasses import dataclass, field
import ctypes
import unittest


PENDING_SLOTS = 256
BUCKET_WAYS = 4
BUCKETS = PENDING_SLOTS // BUCKET_WAYS
MAX_DEPTH = 4
TF_ONE_WAY = 0x01


class EventLayout(ctypes.Structure):
    _fields_ = [
        ("sequence", ctypes.c_uint64),
        ("event_id", ctypes.c_uint64),
        ("task_kaddr", ctypes.c_uint64),
        ("target", ctypes.c_uint64),
        ("cookie", ctypes.c_uint64),
        ("data_size", ctypes.c_uint64),
        ("offsets_size", ctypes.c_uint64),
        ("buffer", ctypes.c_uint64),
        ("offsets", ctypes.c_uint64),
        ("correlated_request_id", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("tgid", ctypes.c_uint32),
        ("command", ctypes.c_uint32),
        ("code", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("sender_pid", ctypes.c_uint32),
        ("sender_euid", ctypes.c_uint32),
        ("kind", ctypes.c_uint32),
        ("parcel_token_kind", ctypes.c_uint32),
        ("parcel_token_offset", ctypes.c_uint32),
        ("parcel_prefix_size", ctypes.c_uint32),
        ("parcel_flags", ctypes.c_uint32),
        ("correlated_request_flags", ctypes.c_uint32),
        ("reply_prefix_size", ctypes.c_uint32),
        ("reply_status_code", ctypes.c_int32),
        ("reply_byte_array_length", ctypes.c_int32),
        ("reply_byte_array_offset", ctypes.c_uint32),
        ("reply_flags", ctypes.c_uint32),
        ("factory_uuid_offset", ctypes.c_uint32),
        ("plugin_handle", ctypes.c_uint32),
    ]


class PendingFrameLayout(ctypes.Structure):
    _fields_ = [
        ("request_event_id", ctypes.c_uint64),
        ("target", ctypes.c_uint64),
        ("data_size", ctypes.c_uint64),
        ("code", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("parcel_flags", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
    ]


class PendingSlotLayout(ctypes.Structure):
    _fields_ = [
        ("task_kaddr", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("tgid", ctypes.c_uint32),
        ("depth", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("frames", PendingFrameLayout * MAX_DEPTH),
    ]


@dataclass
class Frame:
    event_id: int
    target: int
    code: int
    flags: int
    data_size: int
    parcel_flags: int = 0


@dataclass
class Slot:
    task: int = 0
    pid: int = 0
    tgid: int = 0
    frames: list[Frame] = field(default_factory=list)


class PendingModel:
    def __init__(self) -> None:
        self.slots = [Slot() for _ in range(PENDING_SLOTS)]
        self.pushes = 0
        self.pops = 0
        self.misses = 0
        self.overflows = 0
        self.collisions = 0
        self.oneway = 0

    @staticmethod
    def bucket(task: int) -> int:
        return ((task >> 6) & (BUCKETS - 1)) * BUCKET_WAYS

    def push(self, task: int, pid: int, tgid: int, frame: Frame) -> bool:
        if frame.flags & TF_ONE_WAY:
            self.oneway += 1
            return False
        base = self.bucket(task)
        ways = self.slots[base : base + BUCKET_WAYS]
        slot = next((entry for entry in ways if entry.task == task), None)
        if slot is None:
            slot = next((entry for entry in ways if entry.task == 0), None)
            if slot is None:
                self.collisions += 1
                return False
            slot.task, slot.pid, slot.tgid = task, pid, tgid
        if len(slot.frames) >= MAX_DEPTH:
            self.overflows += 1
            return False
        slot.frames.append(frame)
        self.pushes += 1
        return True

    def pop(self, task: int) -> int:
        base = self.bucket(task)
        slot = next(
            (entry for entry in self.slots[base : base + BUCKET_WAYS] if entry.task == task),
            None,
        )
        if slot is None or not slot.frames:
            self.misses += 1
            return 0
        event_id = slot.frames.pop().event_id
        self.pops += 1
        if not slot.frames:
            slot.task = 0
        return event_id


class BinderPendingTest(unittest.TestCase):
    def test_layout_matches_kernel_abi(self) -> None:
        self.assertEqual(ctypes.sizeof(EventLayout), 160)
        self.assertEqual(EventLayout.correlated_request_id.offset, 72)
        self.assertEqual(EventLayout.kind.offset, 108)
        self.assertEqual(EventLayout.correlated_request_flags.offset, 128)
        self.assertEqual(EventLayout.reply_flags.offset, 148)
        self.assertEqual(EventLayout.factory_uuid_offset.offset, 152)
        self.assertEqual(EventLayout.plugin_handle.offset, 156)
        self.assertEqual(ctypes.sizeof(PendingFrameLayout), 40)
        self.assertEqual(ctypes.sizeof(PendingSlotLayout), 184)
        self.assertEqual(PendingSlotLayout.frames.offset, 24)

    def test_single_request_reply(self) -> None:
        model = PendingModel()
        request = Frame(17, 42, 9, 0x10, 128)
        self.assertTrue(model.push(0xFFFF_0000_1000, 10, 10, request))
        self.assertEqual(model.pop(0xFFFF_0000_1000), 17)
        self.assertEqual((model.pushes, model.pops, model.misses), (1, 1, 0))

    def test_nested_lifo(self) -> None:
        model = PendingModel()
        task = 0xFFFF_0000_2000
        for event_id in (1, 2, 3, 4):
            self.assertTrue(model.push(task, 20, 20, Frame(event_id, 1, 2, 0, 8)))
        self.assertEqual([model.pop(task) for _ in range(4)], [4, 3, 2, 1])

    def test_depth_overflow(self) -> None:
        model = PendingModel()
        task = 0xFFFF_0000_3000
        for event_id in range(MAX_DEPTH):
            self.assertTrue(model.push(task, 30, 30, Frame(event_id + 1, 0, 0, 0, 0)))
        self.assertFalse(model.push(task, 30, 30, Frame(99, 0, 0, 0, 0)))
        self.assertEqual(model.overflows, 1)

    def test_oneway_is_not_pending(self) -> None:
        model = PendingModel()
        self.assertFalse(model.push(0x1000, 1, 1, Frame(1, 0, 0, TF_ONE_WAY, 0)))
        self.assertEqual((model.oneway, model.pushes), (1, 0))

    def test_four_way_collision(self) -> None:
        model = PendingModel()
        # These task values share the same six-bit bucket after >> 6.
        tasks = [0x1000 + index * (BUCKETS << 6) for index in range(5)]
        for event_id, task in enumerate(tasks[:4], start=1):
            self.assertTrue(model.push(task, event_id, event_id, Frame(event_id, 0, 0, 0, 0)))
        self.assertFalse(model.push(tasks[4], 5, 5, Frame(5, 0, 0, 0, 0)))
        self.assertEqual(model.collisions, 1)

    def test_miss(self) -> None:
        model = PendingModel()
        self.assertEqual(model.pop(0xDEAD_0000), 0)
        self.assertEqual(model.misses, 1)


if __name__ == "__main__":
    unittest.main()
