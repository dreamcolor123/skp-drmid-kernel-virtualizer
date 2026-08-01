#!/usr/bin/env python3
"""Atomically publish a DRMID ABI-14 multi-target runtime policy record."""

from __future__ import annotations

import argparse
import binascii
import os
from pathlib import Path
import struct
import tempfile
from typing import Sequence


MAGIC = 0x36314C54434D5244  # DRMCTL16
VERSION = 2
SIZE = 256
TARGET_LIMIT = 32
PREFIX_FORMAT = "<QIIQQQIIII32I64s"
PREFIX_SIZE = struct.calcsize(PREFIX_FORMAT)
assert PREFIX_SIZE == 248


def normalize_target_uids(rule: int, target_uids: Sequence[int]) -> list[int]:
    values = sorted(set(target_uids))
    if any(not 1 <= value <= 0xFFFFFFFF for value in values):
        raise ValueError("target_uid")
    if rule == 0:
        if values:
            raise ValueError("all rule target_uids")
    elif not 1 <= len(values) <= TARGET_LIMIT:
        raise ValueError("target_uids count")
    return values


def build_record(
    generation: int,
    seed_generation: int,
    fingerprint: int,
    mode: int,
    rule: int,
    target_uids: Sequence[int],
    virtual_id: bytes,
) -> bytes:
    if not 1 <= generation <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("generation")
    if not 1 <= seed_generation <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("seed_generation")
    if not 0 <= fingerprint <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("fingerprint")
    if mode not in (0, 1) or rule not in (0, 1, 2):
        raise ValueError("mode/rule")
    if not 1 <= len(virtual_id) <= 64:
        raise ValueError("virtual_id length")
    targets = normalize_target_uids(rule, target_uids)
    padded_targets = targets + [0] * (TARGET_LIMIT - len(targets))
    prefix = struct.pack(
        PREFIX_FORMAT,
        MAGIC,
        VERSION,
        SIZE,
        generation,
        seed_generation,
        fingerprint,
        mode,
        rule,
        len(targets),
        len(virtual_id),
        *padded_targets,
        virtual_id + bytes(64 - len(virtual_id)),
    )
    crc = binascii.crc32(prefix) & 0xFFFFFFFF
    return prefix + struct.pack("<II", crc, 0)


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
    if not 1 <= len(data) <= 64:
        raise argparse.ArgumentTypeError("hex ID must be 1..64 bytes")
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--generation", type=int, required=True)
    parser.add_argument("--seed-generation", type=int, required=True)
    parser.add_argument("--fingerprint", type=lambda value: int(value, 0),
                        required=True)
    parser.add_argument("--mode", choices=("dry", "write"), required=True)
    parser.add_argument("--rule", choices=("all", "euid", "package"),
                        required=True)
    parser.add_argument("--target-uid", type=int, action="append", default=[])
    parser.add_argument("--id-hex", type=parse_hex, required=True)
    args = parser.parse_args()
    mode = {"dry": 0, "write": 1}[args.mode]
    rule = {"all": 0, "euid": 1, "package": 2}[args.rule]
    record = build_record(
        args.generation,
        args.seed_generation,
        args.fingerprint,
        mode,
        rule,
        args.target_uid,
        args.id_hex,
    )
    publish(args.path, record)
    print(
        f"published={args.path} bytes={len(record)} "
        f"generation={args.generation} targets={len(set(args.target_uid))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
