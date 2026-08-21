#!/usr/bin/env python3
"""Atomically publish a DRMID ABI-18 global runtime control v3 record."""

from __future__ import annotations

import argparse
import binascii
import os
from pathlib import Path
import struct
import tempfile


MAGIC = 0x38314C54434D5244  # DRMCTL18
VERSION = 3
SIZE = 128
ID_BYTES = 32
PREFIX_FORMAT = "<QIIQQQII64sQ"
PREFIX_SIZE = struct.calcsize(PREFIX_FORMAT)
assert PREFIX_SIZE == 120


def build_record(
    generation: int,
    seed_generation: int,
    fingerprint: int,
    mode: int,
    virtual_id: bytes,
) -> bytes:
    if not 1 <= generation <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("generation")
    if not 1 <= seed_generation <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("seed_generation")
    if not 1 <= fingerprint <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("fingerprint")
    if mode not in (0, 1):
        raise ValueError("mode")
    if len(virtual_id) != ID_BYTES:
        raise ValueError("virtual_id length")
    prefix = struct.pack(
        PREFIX_FORMAT,
        MAGIC,
        VERSION,
        SIZE,
        generation,
        seed_generation,
        fingerprint,
        mode,
        len(virtual_id),
        virtual_id + bytes(64 - len(virtual_id)),
        0,
    )
    return prefix + struct.pack(
        "<II", binascii.crc32(prefix) & 0xFFFFFFFF, 0
    )


def publish(path: Path, record: bytes) -> None:
    if len(record) != SIZE:
        raise ValueError("record size")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(record)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def parse_hex(value: str) -> bytes:
    try:
        data = bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("invalid hex") from error
    if len(data) != ID_BYTES:
        raise argparse.ArgumentTypeError("hex ID must be exactly 32 bytes")
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--generation", type=int, required=True)
    parser.add_argument("--seed-generation", type=int, required=True)
    parser.add_argument(
        "--fingerprint", type=lambda value: int(value, 0), required=True
    )
    parser.add_argument("--mode", choices=("dry", "write"), required=True)
    parser.add_argument("--id-hex", type=parse_hex, required=True)
    args = parser.parse_args()
    record = build_record(
        args.generation,
        args.seed_generation,
        args.fingerprint,
        {"dry": 0, "write": 1}[args.mode],
        args.id_hex,
    )
    publish(args.path, record)
    print(
        f"published={args.path} bytes={len(record)} "
        f"generation={args.generation} scope=global"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
