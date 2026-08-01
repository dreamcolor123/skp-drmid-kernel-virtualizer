#!/usr/bin/env python3
"""Offline model for the bounded LRU Widevine client handle table."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import unittest


CAPACITY = 256
WAYS = 8
BUCKETS = CAPACITY // WAYS
ROOT = Path(__file__).resolve().parents[1]
HOOK_SOURCE = (ROOT / "binder_hook_builder.cpp").read_text(encoding="utf-8")


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
        self.evictions = 0

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
            empty = min(ways, key=lambda s: s.event_id)
            self.collisions += 1
            self.evictions += 1
            # Reclamation replaces one active entry, so active remains
            # bounded at capacity instead of growing or rejecting the new
            # Widevine registration.
            active_delta = 0
        else:
            active_delta = 1
        empty.binder_file = binder_file
        empty.tgid = tgid
        empty.handle = handle
        empty.event_id = event
        self.inserts += 1
        self.active += active_delta
        return True

    def lookup(
        self,
        binder_file: int,
        tgid: int,
        handle: int,
        event: int | None = None,
    ) -> bool:
        base = self.bucket(binder_file, tgid, handle)
        for slot in self.slots[base : base + WAYS]:
            if (slot.binder_file, slot.tgid, slot.handle) == (
                binder_file,
                tgid,
                handle,
            ):
                if event is not None:
                    slot.event_id = event
                return True
        return False

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
    def test_emitter_uses_eight_way_addressing_for_all_plugin_operations(self) -> None:
        self.assertEqual(
            HOOK_SOURCE.count("a->lsl(x15, x15, kPluginBucketWayShift)"),
            3,
        )
        self.assertIn("kPluginBucketWays == 8", HOOK_SOURCE)
        self.assertIn("least-recently-used occupied slot", HOOK_SOURCE)
        self.assertIn("recovered collision/eviction events", HOOK_SOURCE)

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

    def same_bucket_keys(self, count: int) -> list[tuple[int, int, int]]:
        keys = []
        for i in range(count):
            binder_file = 0x1000 + (i << 12)
            tgid = 100 + i
            handle = ((binder_file >> 6) ^ tgid) & (BUCKETS - 1)
            keys.append((binder_file, tgid, handle))
        target_bucket = PluginMap.bucket(*keys[0])
        return [
            (bf, tg, h ^ ((PluginMap.bucket(bf, tg, h) // WAYS) ^
                          (target_bucket // WAYS)))
            for bf, tg, h in keys
        ]

    def test_eight_way_collision_reclaims_lru_instead_of_rejecting(self) -> None:
        model = PluginMap()
        # Keep the XOR bucket constant while varying all key components.
        keys = self.same_bucket_keys(WAYS + 1)
        for index, key in enumerate(keys[:WAYS]):
            self.assertTrue(model.register(*key, index + 1))
        self.assertTrue(model.register(*keys[WAYS], WAYS + 1))
        self.assertFalse(model.lookup(*keys[0]))
        self.assertTrue(model.lookup(*keys[WAYS]))
        self.assertEqual((model.collisions, model.evictions), (1, 1))
        self.assertEqual(model.active, WAYS)

    def test_lookup_refresh_protects_active_entry_from_stale_reclaim(self) -> None:
        model = PluginMap()
        keys = self.same_bucket_keys(WAYS + 1)
        for index, key in enumerate(keys[:WAYS]):
            self.assertTrue(model.register(*key, index + 1))
        self.assertTrue(model.lookup(*keys[0], event=1000))
        self.assertTrue(model.register(*keys[WAYS], 1001))
        self.assertTrue(model.lookup(*keys[0]))
        self.assertFalse(model.lookup(*keys[1]))

    def test_repeated_client_exit_without_release_never_rejects_new_plugin(self) -> None:
        model = PluginMap()
        keys = self.same_bucket_keys(128)
        for event, key in enumerate(keys, start=1):
            self.assertTrue(model.register(*key, event))
            self.assertTrue(model.lookup(*key, event=event))
        self.assertEqual(model.active, WAYS)
        self.assertEqual(model.evictions, len(keys) - WAYS)

    def test_release_miss(self) -> None:
        model = PluginMap()
        self.assertFalse(model.release(0x1000, 10, 5))
        self.assertEqual(model.release_misses, 1)


if __name__ == "__main__":
    unittest.main()
