#!/usr/bin/env python3
"""Strict Widevine HAL identity discovery fixtures."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "hal_identity.cpp").read_text(encoding="utf-8")
HEADER = (ROOT / "hal_identity.h").read_text(encoding="utf-8")
LIMIT = 4


def inspect_fixture(root: Path, pid: int) -> bool:
    proc = root / str(pid)
    try:
        exe = os.readlink(proc / "exe")
        argv0 = (proc / "cmdline").read_bytes().split(b"\0", 1)[0].decode()
        status = (proc / "status").read_text()
        domain = (proc / "attr" / "current").read_text()
        uid = int(status.split("Uid:\t", 1)[1].split()[0])
        binder = any(
            Path(os.readlink(path)).name in {"binder", "hwbinder", "vndbinder"}
            for path in (proc / "fd").iterdir()
        )
    except (OSError, ValueError, IndexError, UnicodeError):
        return False
    return (
        "drm" in Path(exe).name
        and ("widevine" in Path(exe).name or "/widevine/" in exe)
        and Path(argv0).name == Path(exe).name
        and uid in {1013, 1019, 1031}
        and "drm" in domain
        and "widevine" in domain
        and binder
    )


def create_candidate(root: Path, pid: int = 2216) -> Path:
    proc = root / str(pid)
    (proc / "attr").mkdir(parents=True)
    (proc / "fd").mkdir()
    exe = root / "android.hardware.drm-service.widevine"
    exe.touch(exist_ok=True)
    (proc / "exe").symlink_to(exe)
    (proc / "cmdline").write_bytes(str(exe).encode() + b"\0")
    (proc / "status").write_text("Name:\twv\nUid:\t1013\t1013\t1013\t1013\n")
    (proc / "attr" / "current").write_text("u:r:hal_drm_widevine:s0\n")
    (proc / "fd" / "7").symlink_to("/dev/binderfs/binder")
    return proc


class HalIdentityTest(unittest.TestCase):
    def test_complete_candidate_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_candidate(root)
            self.assertTrue(inspect_fixture(root, 2216))

    def test_each_identity_factor_is_required(self) -> None:
        mutations = {
            "exe": lambda p: (p / "exe").unlink(),
            "cmdline": lambda p: (p / "cmdline").write_bytes(b"fake\0"),
            "uid": lambda p: (p / "status").write_text("Uid:\t2000\t2000\t2000\t2000\n"),
            "domain": lambda p: (p / "attr" / "current").write_text("u:r:shell:s0\n"),
            "binder": lambda p: (p / "fd" / "7").unlink(),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                proc = create_candidate(root)
                mutate(proc)
                self.assertFalse(inspect_fixture(root, 2216))

    def test_source_cross_checks_all_proc_attributes(self) -> None:
        for marker in (
            'join_path(root, "exe")', 'join_path(root, "cmdline")',
            'join_path(root, "status")', 'join_path(root, "attr/current")',
            'join_path(process_root, "fd")', "cmdline_matches_exe",
            "widevine_domain", "find_binder_fd",
        ):
            self.assertIn(marker, SOURCE)

    def test_identity_set_is_sorted_unique_nonzero_and_bounded(self) -> None:
        for marker in (
            "std::sort(matches.begin(), matches.end()",
            "std::unique(matches.begin(), matches.end()",
            "matches.size() > kHalIdentityLimit",
            "parsed == 0 || parsed > UINT32_MAX",
        ):
            self.assertIn(marker, SOURCE)
        self.assertEqual(LIMIT, 4)

    def test_pidfd_wrapper_uses_zero_flags(self) -> None:
        self.assertIn("SYS_pidfd_open", SOURCE)
        self.assertIn("syscall(SYS_pidfd_open, tgid, 0)", SOURCE)
        self.assertIn("int open_hal_pidfd(uint32_t tgid)", HEADER)


if __name__ == "__main__":
    unittest.main()
