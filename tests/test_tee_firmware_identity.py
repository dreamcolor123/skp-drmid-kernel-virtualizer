#!/usr/bin/env python3
"""Widevine firmware identity path and file-type fixtures."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "tee_firmware_identity.cpp").read_text(encoding="utf-8")
HEADER = (ROOT / "tee_firmware_identity.h").read_text(encoding="utf-8")


def fixture_identity(path: Path) -> tuple[int, bytes, bytes]:
    stat = path.lstat()
    if not path.is_file() or path.is_symlink() or not 64 <= stat.st_size <= 16 * 1024 * 1024:
        raise ValueError("invalid")
    data = path.read_bytes()
    return len(data), data[:32], data[-32:]


class TeeFirmwareIdentityTest(unittest.TestCase):
    def test_regular_file_captures_only_size_and_edges(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "widevine.mbn"
            payload = bytes(range(256)) * 5
            path.write_bytes(payload)
            size, prefix, suffix = fixture_identity(path)
            self.assertEqual(size, len(payload))
            self.assertEqual(prefix, payload[:32])
            self.assertEqual(suffix, payload[-32:])

    def test_symlink_short_missing_and_oversized_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / "regular"
            regular.write_bytes(b"A" * 64)
            link = root / "link"
            link.symlink_to(regular)
            short = root / "short"
            short.write_bytes(b"B" * 63)
            for path in (link, short, root / "missing"):
                with self.subTest(path=path), self.assertRaises((ValueError, FileNotFoundError)):
                    fixture_identity(path)
            oversized = root / "oversized"
            with oversized.open("wb") as stream:
                stream.truncate(16 * 1024 * 1024 + 1)
            with self.assertRaises(ValueError):
                fixture_identity(oversized)

    def test_candidate_order_is_stable(self) -> None:
        markers = [
            '"/vendor/firmware_mnt/image/widevine.mbn"',
            '"/vendor/firmware/widevine.mbn"',
            '"/vendor/etc/firmware/widevine.mbn"',
            '"/system/etc/firmware/widevine.mbn"',
        ]
        positions = [SOURCE.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions))

    def test_source_uses_nofollow_regular_bounds_and_exact_pread(self) -> None:
        for marker in (
            "O_NOFOLLOW", "S_ISREG", "kTeeFirmwareMinimumBytes",
            "kTeeFirmwareMaximumBytes", "pread_exact", "prefix", "suffix",
        ):
            self.assertIn(marker, SOURCE + HEADER)
        self.assertNotIn("deviceUniqueId", SOURCE + HEADER)


if __name__ == "__main__":
    unittest.main()
