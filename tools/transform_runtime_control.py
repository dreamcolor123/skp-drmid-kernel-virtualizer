#!/usr/bin/env python3
"""Transform one validated DRMCTL18 v3 record on stdin without exposing ID bytes."""

from __future__ import annotations

import argparse
import binascii
import struct
import sys


MAGIC = 0x38314C54434D5244  # DRMCTL18
VERSION = 3
SIZE = 128
CRC_OFFSET = 120
GENERATION_OFFSET = 16
MODE_OFFSET = 40
LENGTH_OFFSET = 44
FINGERPRINT_OFFSET = 32
RESERVED_OFFSET = 112


def transform(record: bytes, mode: int) -> tuple[bytes, int]:
    if len(record) != SIZE:
        raise ValueError("record size")
    magic, version, record_size = struct.unpack_from("<QII", record, 0)
    generation = struct.unpack_from("<Q", record, GENERATION_OFFSET)[0]
    fingerprint = struct.unpack_from("<Q", record, FINGERPRINT_OFFSET)[0]
    current_mode = struct.unpack_from("<I", record, MODE_OFFSET)[0]
    length = struct.unpack_from("<I", record, LENGTH_OFFSET)[0]
    reserved = struct.unpack_from("<Q", record, RESERVED_OFFSET)[0]
    stored_crc, tail_reserved = struct.unpack_from("<II", record, CRC_OFFSET)
    actual_crc = binascii.crc32(record[:CRC_OFFSET]) & 0xFFFFFFFF
    if (
        magic != MAGIC
        or version != VERSION
        or record_size != SIZE
        or generation == 0
        or generation == 0xFFFFFFFFFFFFFFFF
        or fingerprint == 0
        or current_mode not in (0, 1)
        or length != 32
        or reserved != 0
        or tail_reserved != 0
        or stored_crc != actual_crc
    ):
        raise ValueError("record validation")
    transformed = bytearray(record)
    next_generation = generation + 1
    struct.pack_into("<Q", transformed, GENERATION_OFFSET, next_generation)
    struct.pack_into("<I", transformed, MODE_OFFSET, mode)
    struct.pack_into(
        "<I",
        transformed,
        CRC_OFFSET,
        binascii.crc32(transformed[:CRC_OFFSET]) & 0xFFFFFFFF,
    )
    return bytes(transformed), next_generation


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("dry", "write"), required=True)
    args = parser.parse_args()
    try:
        transformed, _ = transform(
            sys.stdin.buffer.read(), {"dry": 0, "write": 1}[args.mode]
        )
    except ValueError as error:
        print(f"transform rejected: {error}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(transformed)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
