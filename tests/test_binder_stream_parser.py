#!/usr/bin/env python3
"""Offline fixtures for the read-only top-level Binder stream walker."""

from __future__ import annotations

from dataclasses import dataclass
import struct
import unittest


IOC_WRITE = 1
IOC_READ = 2
MAX_BYTES = 64 * 1024
MAX_COMMANDS = 128


def ioc(direction: int, kind: str, number: int, size: int) -> int:
    return (
        (direction << 30)
        | (size << 16)
        | (ord(kind) << 8)
        | number
    )


def io(kind: str, number: int) -> int:
    return ioc(0, kind, number, 0)


def iow(kind: str, number: int, size: int) -> int:
    return ioc(IOC_WRITE, kind, number, size)


def ior(kind: str, number: int, size: int) -> int:
    return ioc(IOC_READ, kind, number, size)


BC_TRANSACTION = iow("c", 0, 64)
BC_REPLY = iow("c", 1, 64)
BC_ENTER_LOOPER = io("c", 12)
BC_TRANSACTION_SG = iow("c", 17, 72)
BC_REPLY_SG = iow("c", 18, 72)

BR_TRANSACTION = ior("r", 2, 64)
BR_TRANSACTION_SEC_CTX = ior("r", 2, 72)
BR_REPLY = ior("r", 3, 64)
BR_TRANSACTION_COMPLETE = io("r", 6)

BC_TRANSACTIONS = {
    BC_TRANSACTION,
    BC_REPLY,
    BC_TRANSACTION_SG,
    BC_REPLY_SG,
}
BR_TRANSACTIONS = {
    BR_TRANSACTION,
    BR_TRANSACTION_SEC_CTX,
    BR_REPLY,
}


def frame(command: int, fill: int = 0xA5) -> bytes:
    size = (command >> 16) & 0x3FFF
    return struct.pack("<I", command) + bytes([fill]) * size


@dataclass(frozen=True)
class Result:
    commands: int = 0
    transactions: int = 0
    boundary_error: bool = False
    capped: bool = False


def parse_stream(data: bytes, expected_type: str) -> Result:
    if not data:
        return Result()
    if len(data) > MAX_BYTES:
        return Result(capped=True)

    offset = 0
    commands = 0
    transactions = 0
    transaction_set = BC_TRANSACTIONS if expected_type == "c" else BR_TRANSACTIONS
    while offset < len(data):
        if commands >= MAX_COMMANDS:
            return Result(commands, transactions, capped=True)
        if len(data) - offset < 4:
            return Result(commands, transactions, boundary_error=True)
        command = struct.unpack_from("<I", data, offset)[0]
        if ((command >> 8) & 0xFF) != ord(expected_type):
            return Result(commands, transactions, boundary_error=True)
        total = 4 + ((command >> 16) & 0x3FFF)
        if total > len(data) - offset:
            return Result(commands, transactions, boundary_error=True)
        commands += 1
        transactions += command in transaction_set
        offset += total
    return Result(commands, transactions)


class BinderStreamParserTest(unittest.TestCase):
    def test_valid_bc_stream(self) -> None:
        data = (
            frame(BC_ENTER_LOOPER)
            + frame(BC_TRANSACTION)
            + frame(BC_TRANSACTION_SG)
            + frame(BC_REPLY)
            + frame(BC_REPLY_SG)
        )
        self.assertEqual(parse_stream(data, "c"), Result(5, 4))

    def test_valid_br_stream(self) -> None:
        data = (
            frame(BR_TRANSACTION_COMPLETE)
            + frame(BR_TRANSACTION)
            + frame(BR_TRANSACTION_SEC_CTX)
            + frame(BR_REPLY)
        )
        self.assertEqual(parse_stream(data, "r"), Result(4, 3))

    def test_short_command_word(self) -> None:
        self.assertTrue(parse_stream(b"\x01\x02\x03", "c").boundary_error)

    def test_short_payload(self) -> None:
        self.assertTrue(parse_stream(frame(BC_TRANSACTION)[:-1], "c").boundary_error)

    def test_wrong_stream_type(self) -> None:
        self.assertTrue(parse_stream(frame(BR_REPLY), "c").boundary_error)

    def test_byte_cap(self) -> None:
        result = parse_stream(bytes(MAX_BYTES + 1), "c")
        self.assertTrue(result.capped)
        self.assertEqual(result.commands, 0)

    def test_command_cap(self) -> None:
        result = parse_stream(frame(BC_ENTER_LOOPER) * (MAX_COMMANDS + 1), "c")
        self.assertTrue(result.capped)
        self.assertEqual(result.commands, MAX_COMMANDS)

    def test_empty_stream(self) -> None:
        self.assertEqual(parse_stream(b"", "r"), Result())


if __name__ == "__main__":
    unittest.main()
