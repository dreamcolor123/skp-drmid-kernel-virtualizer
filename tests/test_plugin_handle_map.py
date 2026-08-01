#!/usr/bin/env python3
"""Offline model for the four-way Widevine client handle table."""

from __future__ import annotations

from dataclasses import dataclass
import unittest


CAPACITY = 256
WAYS = 4
BUCKETS = CAPACITY // WAYS


@dataclass
class Slot:
    binder_file: int = 0
    tgid: int = 0
    handle: int = 0
    event_id: int = 0


class PluginMap:
    def __init__(self) -> None:
        self.slots = [Slot() for _ in range(CAPACITY)]
        self.active = 0
        self.inserts = 0
        self.reuses = 0
        self.collisions = 0
        self.releases = 0
        self.release_misses = 0

    @staticmethod
    def bucket(binder_file: int, tgid: int, handle: int) -> int:
        key = (binder_file >> 6) ^ tgid ^ handle
        return (key & (BUCKETS - 1)) * WAYS

    def register(self, binder_file: int, tgid: int, handle: int, event: int) -> bool:
        base = self.bucket(binder_file, tgid, handle)
        ways = self.slots[base : base + WAYS]
        exact = next(
            (s for s in ways if (s.binder_file, s.tgid, s.handle) ==
             (binder_file, tgid, handle)),
            None,
        )
        if exact is not None:
            exact.event_id = event
            self.reuses += 1
            return True
        empty = next((s for s in ways if s.binder_file == 0), None)
        if empty is None:
            self.collisions += 1
            return False
        empty.binder_file = binder_file
        empty.tgid = tgid
        empty.handle = handle
        empty.event_id = event
        self.inserts += 1
        self.active += 1
        return True

    def lookup(self, binder_file: int, tgid: int, handle: int) -> bool:
        base = self.bucket(binder_file, tgid, handle)
        return any(
            (s.binder_file, s.tgid, s.handle) == (binder_file, tgid, handle)
            for s in self.slots[base : base + WAYS]
        )

    def release(self, binder_file: int, tgid: int, handle: int) -> bool:
        base = self.bucket(binder_file, tgid, handle)
        for slot in self.slots[base : base + WAYS]:
            if (slot.binder_file, slot.tgid, slot.handle) == (
                binder_file,
                tgid,
                handle,
            ):
                slot.binder_file = 0
                self.active -= 1
                self.releases += 1
                return True
        self.release_misses += 1
        return False


class PluginHandleMapTest(unittest.TestCase):
    def test_register_lookup_release(self) -> None:
        model = PluginMap()
        self.assertTrue(model.register(0xFFFF00001000, 200, 5, 17))
        self.assertTrue(model.lookup(0xFFFF00001000, 200, 5))
        self.assertFalse(model.lookup(0xFFFF00001000, 201, 5))
        self.assertFalse(model.lookup(0xFFFF00002000, 200, 5))
        self.assertTrue(model.release(0xFFFF00001000, 200, 5))
        self.assertFalse(model.lookup(0xFFFF00001000, 200, 5))
        self.assertEqual((model.inserts, model.releases, model.active), (1, 1, 0))

    def test_duplicate_registration_reuses_slot(self) -> None:
        model = PluginMap()
        self.assertTrue(model.register(0x1000, 10, 7, 1))
        self.assertTrue(model.register(0x1000, 10, 7, 2))
        self.assertEqual((model.inserts, model.reuses, model.active), (1, 1, 1))

    def test_four_way_collision(self) -> None:
        model = PluginMap()
        # Keep the XOR bucket constant while varying all key components.
        keys = []
        for i in range(5):
            binder_file = 0x1000 + (i << 12)
            tgid = 100 + i
            handle = ((binder_file >> 6) ^ tgid) & (BUCKETS - 1)
            keys.append((binder_file, tgid, handle))
        target_bucket = PluginMap.bucket(*keys[0])
        # Adjust handles so every key lands in the first key's bucket.
        keys = [
            (bf, tg, h ^ ((PluginMap.bucket(bf, tg, h) // WAYS) ^
                          (target_bucket // WAYS)))
            for bf, tg, h in keys
        ]
        for index, key in enumerate(keys[:4]):
            self.assertTrue(model.register(*key, index + 1))
        self.assertFalse(model.register(*keys[4], 5))
        self.assertEqual(model.collisions, 1)

    def test_release_miss(self) -> None:
        model = PluginMap()
        self.assertFalse(model.release(0x1000, 10, 5))
        self.assertEqual(model.release_misses, 1)


if __name__ == "__main__":
    unittest.main()
