#!/usr/bin/env python3
"""Verify the pinned upstream SKRoot SDK and stage an ASCII-only NDK path."""

from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parent
UPSTREAM = ROOT / "third_party" / "SKRoot-linuxKernelRoot"
SDK_SOURCE = (
    UPSTREAM / "Pro(众测开放中)" / "src" / "testModule" /
    "kernel_module_kit"
)
SDK_CACHE = ROOT / ".sdk-cache" / "kernel_module_kit"
EXPECTED_COMMIT = "843b8ab32905e653d5959683cfca328883e9076c"
EXPECTED_SHA256 = "5b304a9d7e1c2d5d8aa2e7d2a95710d37b1f261e1a92ffe640737d747ed93f91"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    source_library = SDK_SOURCE / "lib" / "libkernel_module_kit_static.a"
    if not source_library.is_file():
        raise SystemExit(
            "SKRoot SDK submodule is missing; run: "
            "git submodule update --init --depth 1"
        )
    commit = subprocess.run(
        ["git", "-C", str(UPSTREAM), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if commit != EXPECTED_COMMIT:
        raise SystemExit(
            f"SKRoot SDK commit mismatch: expected={EXPECTED_COMMIT} "
            f"actual={commit}"
        )
    digest = sha256_file(source_library)
    if digest != EXPECTED_SHA256:
        raise SystemExit(
            f"SKRoot SDK 4.6.0 hash mismatch: expected={EXPECTED_SHA256} "
            f"actual={digest}"
        )

    cached_library = SDK_CACHE / "lib" / source_library.name
    cached_header = SDK_CACHE / "include" / "kernel_module_kit_umbrella.h"
    if (
        not cached_library.is_file() or
        sha256_file(cached_library) != EXPECTED_SHA256 or
        not cached_header.is_file()
    ):
        SDK_CACHE.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(SDK_SOURCE, SDK_CACHE, dirs_exist_ok=True)
    print(f"SKRoot SDK 4.6.0 ready: {EXPECTED_COMMIT[:12]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
