#!/usr/bin/env python3
"""Build the private, deterministic Android application-label helper JAR."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import zipfile


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "label_helper" / "DrmidAppLabels.java"
OUTPUT = ROOT / "label_helper" / "drmid_label_helper.jar"
BUILD_ROOT = ROOT / "obj" / "label_helper"


def windows_path(path: Path) -> str:
    if os.name == "nt":
        return str(path)
    completed = subprocess.run(
        ["wslpath", "-w", str(path)],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def java_tool(java_home: Path, name: str) -> tuple[Path, bool]:
    """Return the Java tool and whether it is a Windows executable."""
    candidates = (
        java_home / "bin" / f"{name}.exe",
        java_home / "bin" / name,
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate, candidate.suffix.lower() == ".exe"
    raise FileNotFoundError(
        f"label helper Java tool missing: {candidates[0]} or {candidates[1]}"
    )


def tool_argument(path: Path, windows_tool: bool) -> str:
    return windows_path(path) if windows_tool else str(path)


def build() -> Path:
    sdk_value = os.environ.get("ANDROID_SDK_ROOT")
    java_value = os.environ.get("JAVA_HOME")
    if not sdk_value or not java_value:
        raise RuntimeError("ANDROID_SDK_ROOT and JAVA_HOME must be set")
    sdk = Path(sdk_value)
    java_home = Path(java_value)
    build_tools = sdk / "build-tools" / "35.0.0"
    platform = sdk / "platforms" / "android-35" / "android.jar"
    javac, javac_is_windows = java_tool(java_home, "javac")
    java, java_is_windows = java_tool(java_home, "java")
    d8 = build_tools / "lib" / "d8.jar"
    for required in (SOURCE, platform, d8):
        if not required.is_file():
            raise FileNotFoundError(f"label helper build input missing: {required}")

    if BUILD_ROOT.exists():
        shutil.rmtree(BUILD_ROOT)
    classes = BUILD_ROOT / "classes"
    dex = BUILD_ROOT / "dex"
    classes.mkdir(parents=True)
    dex.mkdir(parents=True)

    subprocess.run(
        [
            str(javac),
            "-source", "8",
            "-target", "8",
            "-Xlint:-options",
            "-classpath", tool_argument(platform, javac_is_windows),
            "-d", tool_argument(classes, javac_is_windows),
            tool_argument(SOURCE, javac_is_windows),
        ],
        check=True,
    )
    subprocess.run(
        [
            str(java),
            "-cp", tool_argument(d8, java_is_windows),
            "com.android.tools.r8.D8",
            "--lib", tool_argument(platform, java_is_windows),
            "--output", tool_argument(dex, java_is_windows),
            tool_argument(classes / "DrmidAppLabels.class", java_is_windows),
        ],
        check=True,
    )

    dex_bytes = (dex / "classes.dex").read_bytes()
    info = zipfile.ZipInfo("classes.dex", date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    with zipfile.ZipFile(OUTPUT, "w", compresslevel=9) as archive:
        archive.writestr(info, dex_bytes)
    return OUTPUT


if __name__ == "__main__":
    print(build())
