#!/usr/bin/env python3
"""Offline fixtures for the bounded 0.3.0 DRM AIDL token scanner."""

from __future__ import annotations

import struct
import unittest


PREFIX_CAP = 256
DRM_FACTORY = "android.hardware.drm.IDrmFactory"
DRM_PLUGIN = "android.hardware.drm.IDrmPlugin"
DEVICE_UNIQUE_ID = "deviceUniqueId"
TEST_VIRTUAL_ID = b"SKP612-VIRTUAL-DRMID-TEST-000001"
WIDEVINE_UUID = bytes.fromhex("edef8ba979d64acea3c827dcd51d21ed")
BINDER_TYPE_HANDLE = 0x73682A85
SYSTEM_HEADER = struct.pack("<I", 0x53595354)  # raw bytes: TSYS


def align4(value: int) -> int:
    return (value + 3) & ~3


def string16(value: str) -> bytes:
    raw = struct.pack("<I", len(value)) + value.encode("utf-16le") + b"\x00\x00"
    return raw + bytes(align4(len(raw)) - len(raw))


def headered_string16(value: str, order: str = "header-first") -> bytes:
    encoded = string16(value)
    if order == "header-first":
        return SYSTEM_HEADER + encoded
    if order == "length-first":
        return encoded[:4] + SYSTEM_HEADER + encoded[4:]
    raise ValueError(order)


def parcel(token: str, property_name: str | None = None, token_offset: int = 4) -> bytes:
    data = bytearray(token_offset)
    data += string16(token)
    if property_name is not None:
        data += string16(property_name)
    return bytes(data)


def headered_parcel(
    token: str,
    property_name: str | None = None,
    order: str = "header-first",
    token_offset: int = 8,
) -> bytes:
    data = bytearray(token_offset)
    data += headered_string16(token, order)
    if property_name is not None:
        data += string16(property_name)
    return bytes(data)


def read_string16(data: bytes, offset: int, expected: str) -> bool:
    required = offset + 4 + (len(expected) + 1) * 2
    if required > len(data):
        return False
    length = struct.unpack_from("<I", data, offset)[0]
    if length != len(expected):
        return False
    raw = data[offset + 4 : offset + 4 + len(expected) * 2]
    terminator = data[offset + 4 + len(expected) * 2 : required]
    return raw == expected.encode("utf-16le") and terminator == b"\x00\x00"


def read_utf16_contents(data: bytes, offset: int, expected: str) -> bool:
    end = offset + (len(expected) + 1) * 2
    return end <= len(data) and data[offset : offset + len(expected) * 2] == expected.encode(
        "utf-16le"
    ) and data[offset + len(expected) * 2 : end] == b"\x00\x00"


def scan(data: bytes) -> tuple[str | None, int, bool]:
    data = data[:PREFIX_CAP]
    for token_offset in range(0, 33, 4):
        if read_string16(data, token_offset, DRM_FACTORY):
            return DRM_FACTORY, token_offset, False
        if read_utf16_contents(data, token_offset + 4, DRM_FACTORY):
            return DRM_FACTORY, token_offset, False
    for token_offset in range(0, 33, 4):
        plugin = read_string16(data, token_offset, DRM_PLUGIN) or read_utf16_contents(
            data, token_offset + 4, DRM_PLUGIN
        )
        if not plugin:
            continue
        property_offset = align4(token_offset + 4 + (len(DRM_PLUGIN) + 1) * 2)
        property_match = read_string16(data, property_offset, DEVICE_UNIQUE_ID)
        if not property_match:
            property_match = any(
                read_utf16_contents(data, offset, DEVICE_UNIQUE_ID)
                for offset in range(0, min(len(data), PREFIX_CAP), 4)
            )
        return (
            DRM_PLUGIN,
            token_offset,
            property_match,
        )
    return None, 0, False


def parse_reply(data: bytes) -> tuple[bool, int, int]:
    """Return (valid, byte-array length, content offset)."""
    if len(data) < 8:
        return False, 0, 0
    status, length = struct.unpack_from("<ii", data)
    if status != 0 or length < 1 or length > 64 or 8 + length > len(data):
        return False, length, 0
    # Mirror the kernel's second bounded copy by touching the exact range.
    self_contained = bytes(data[8 : 8 + length])
    return len(self_contained) == length, length, 8


def factory_create_parcel(token_offset: int = 12) -> bytes:
    data = bytearray(token_offset)
    data += string16(DRM_FACTORY)
    # Stable AIDL parcelable: parcelable-size, fixed-array length, 16 bytes.
    data += struct.pack("<ii", 24, 16) + WIDEVINE_UUID
    data += string16("com.example.drmid.fixture")
    return bytes(data)


def find_widevine_uuid(data: bytes, code: int) -> int:
    if code != 1:
        return 0
    token, token_offset, _ = scan(data)
    if token != DRM_FACTORY:
        return 0
    start = align4(token_offset + 4 + (len(DRM_FACTORY) + 1) * 2)
    for offset in range(start, start + 65, 4):
        if data[offset : offset + 16] == WIDEVINE_UUID:
            return offset
    return 0


def parse_factory_reply(data: bytes, offsets: bytes) -> int:
    if len(data) < 24 or len(offsets) != 8:
        return 0
    status = struct.unpack_from("<i", data)[0]
    offset = struct.unpack_from("<Q", offsets)[0]
    if status != 0 or offset & 3 or offset + 24 > len(data):
        return 0
    obj_type, _, handle, _ = struct.unpack_from("<IIQQ", data, offset)
    return handle & 0xFFFFFFFF if obj_type == BINDER_TYPE_HANDLE else 0


def replacement(reply: bytes, virtual_id: bytes, write: bool) -> tuple[bytes, str]:
    valid, length, offset = parse_reply(reply)
    if not valid or length != len(virtual_id):
        return reply, "mismatch"
    if not write:
        return reply, "dry-run"
    result = bytearray(reply)
    result[offset : offset + length] = virtual_id
    return bytes(result), "replaced"


class AidlParcelProbeTest(unittest.TestCase):
    def test_factory_token(self) -> None:
        self.assertEqual(scan(parcel(DRM_FACTORY)), (DRM_FACTORY, 4, False))

    def test_plugin_device_unique_id(self) -> None:
        data = parcel(DRM_PLUGIN, DEVICE_UNIQUE_ID)
        self.assertEqual(len(data), 108)
        self.assertEqual(scan(data), (DRM_PLUGIN, 4, True))

    def test_plugin_other_property(self) -> None:
        self.assertEqual(
            scan(parcel(DRM_PLUGIN, "securityLevel")),
            (DRM_PLUGIN, 4, False),
        )

    def test_supported_shifted_token_offset(self) -> None:
        self.assertEqual(
            scan(parcel(DRM_PLUGIN, DEVICE_UNIQUE_ID, token_offset=12)),
            (DRM_PLUGIN, 12, True),
        )

    def test_header_first_aidl_token(self) -> None:
        data = headered_parcel(DRM_PLUGIN, DEVICE_UNIQUE_ID, "header-first")
        self.assertEqual(scan(data), (DRM_PLUGIN, 12, True))

    def test_length_first_aidl_token(self) -> None:
        data = headered_parcel(DRM_PLUGIN, DEVICE_UNIQUE_ID, "length-first")
        self.assertEqual(scan(data), (DRM_PLUGIN, 12, True))

    def test_raw_descriptor_fallback(self) -> None:
        data = b"\0\0\0\0" + b"\x99\x88\x77\x66" + DRM_PLUGIN.encode(
            "utf-16le"
        ) + b"\0\0" + string16(DEVICE_UNIQUE_ID)
        self.assertEqual(scan(data), (DRM_PLUGIN, 4, True))

    def test_truncated_token(self) -> None:
        data = parcel(DRM_PLUGIN, DEVICE_UNIQUE_ID)[:60]
        self.assertEqual(scan(data), (None, 0, False))

    def test_unknown_token(self) -> None:
        self.assertEqual(
            scan(parcel("android.example.IFixture", "deviceUniqueId")),
            (None, 0, False),
        )

    def test_successful_device_reply(self) -> None:
        reply = struct.pack("<ii", 0, 32) + bytes(range(32))
        self.assertEqual(len(reply), 40)
        self.assertEqual(parse_reply(reply), (True, 32, 8))

    def test_reply_status_failure(self) -> None:
        self.assertEqual(parse_reply(struct.pack("<ii", 1, 32) + bytes(32)),
                         (False, 32, 0))

    def test_reply_length_bounds(self) -> None:
        self.assertEqual(parse_reply(struct.pack("<ii", 0, 0)),
                         (False, 0, 0))
        self.assertEqual(parse_reply(struct.pack("<ii", 0, 65) + bytes(65)),
                         (False, 65, 0))

    def test_reply_truncated_content(self) -> None:
        self.assertEqual(parse_reply(struct.pack("<ii", 0, 32) + bytes(31)),
                         (False, 32, 0))

    def test_replacement_dry_run(self) -> None:
        original = struct.pack("<ii", 0, 32) + bytes(range(32))
        result, state = replacement(original, TEST_VIRTUAL_ID, False)
        self.assertEqual((result, state), (original, "dry-run"))

    def test_replacement_write(self) -> None:
        original = struct.pack("<ii", 0, 32) + bytes(range(32))
        result, state = replacement(original, TEST_VIRTUAL_ID, True)
        self.assertEqual(state, "replaced")
        self.assertEqual(result[:8], original[:8])
        self.assertEqual(result[8:], TEST_VIRTUAL_ID)

    def test_replacement_length_mismatch(self) -> None:
        original = struct.pack("<ii", 0, 31) + bytes(range(31))
        result, state = replacement(original, TEST_VIRTUAL_ID, True)
        self.assertEqual((result, state), (original, "mismatch"))

    def test_widevine_factory_request_uuid(self) -> None:
        data = factory_create_parcel()
        self.assertEqual(find_widevine_uuid(data, 1), 92)
        self.assertEqual(find_widevine_uuid(data, 2), 0)

    def test_other_factory_uuid_is_not_widevine(self) -> None:
        data = bytearray(factory_create_parcel())
        data[92] ^= 0x80
        self.assertEqual(find_widevine_uuid(bytes(data), 1), 0)

    def test_factory_reply_handle(self) -> None:
        obj = struct.pack("<IIQQ", BINDER_TYPE_HANDLE, 0, 5, 0)
        reply = struct.pack("<ii", 0, 0) + obj
        self.assertEqual(len(reply), 32)
        self.assertEqual(parse_factory_reply(reply, struct.pack("<Q", 8)), 5)

    def test_factory_reply_rejects_wrong_object(self) -> None:
        obj = struct.pack("<IIQQ", 0x73622A85, 0, 5, 0)
        reply = struct.pack("<ii", 0, 0) + obj
        self.assertEqual(parse_factory_reply(reply, struct.pack("<Q", 8)), 0)

    def test_factory_reply_offset_four(self) -> None:
        obj = struct.pack("<IIQQ", BINDER_TYPE_HANDLE, 0, 7, 0)
        reply = struct.pack("<i", 0) + obj + b"\0\0\0\0"
        self.assertEqual(parse_factory_reply(reply, struct.pack("<Q", 4)), 7)


if __name__ == "__main__":
    unittest.main()
