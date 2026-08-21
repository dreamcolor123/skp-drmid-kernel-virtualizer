#!/usr/bin/env python3
"""Fixtures for the HAL-side IDrmPlugin/deviceUniqueId correlation parser."""

from __future__ import annotations

import struct
import unittest


PREFIX_CAP = 256
DRM_PLUGIN = "android.hardware.drm.IDrmPlugin"
DEVICE_UNIQUE_ID = "deviceUniqueId"
GET_PROPERTY_BYTE_ARRAY = 11
TEST_ID = b"SKP612-VIRTUAL-DRMID-TEST-000001"
SYSTEM_HEADER = struct.pack("<I", 0x53595354)


def align4(value: int) -> int:
    return (value + 3) & ~3


def string16(value: str) -> bytes:
    raw = struct.pack("<I", len(value)) + value.encode("utf-16le") + b"\0\0"
    return raw + bytes(align4(len(raw)) - len(raw))


def parcel(property_name: str, token_offset: int = 4, headered: bool = False) -> bytes:
    data = bytearray(token_offset)
    encoded = string16(DRM_PLUGIN)
    if headered:
        encoded = encoded[:4] + SYSTEM_HEADER + encoded[4:]
    data += encoded
    data += string16(property_name)
    return bytes(data)


def string16_at(data: bytes, offset: int, value: str) -> bool:
    end = offset + 4 + (len(value) + 1) * 2
    return (
        end <= len(data)
        and struct.unpack_from("<I", data, offset)[0] == len(value)
        and data[offset + 4 : offset + 4 + len(value) * 2]
        == value.encode("utf-16le")
        and data[end - 2 : end] == b"\0\0"
    )


def contents_at(data: bytes, offset: int, value: str, utf16: bool) -> bool:
    encoded = value.encode("utf-16le" if utf16 else "ascii")
    terminator = b"\0\0" if utf16 else b"\0"
    return data[offset : offset + len(encoded) + len(terminator)] == encoded + terminator


def matched_request(data: bytes, code: int) -> bool:
    if code != GET_PROPERTY_BYTE_ARRAY:
        return False
    data = data[:PREFIX_CAP]
    plugin_forms: list[tuple[int, int]] = []
    for offset in range(0, 33, 4):
        if string16_at(data, offset, DRM_PLUGIN):
            plugin_forms.append((offset, 0))
        if (
            offset + 8 <= len(data)
            and struct.unpack_from("<I", data, offset)[0] == len(DRM_PLUGIN)
            and data[offset + 4 : offset + 8] == SYSTEM_HEADER
            and contents_at(data, offset + 8, DRM_PLUGIN, True)
        ):
            plugin_forms.append((offset, 4))
        if contents_at(data, offset + 4, DRM_PLUGIN, True):
            plugin_forms.append((offset, 0))
    if not plugin_forms:
        return False
    for token_offset, header_extra in plugin_forms:
        property_offset = align4(
            token_offset + 4 + (len(DRM_PLUGIN) + 1) * 2
        ) + header_extra
        if string16_at(data, property_offset, DEVICE_UNIQUE_ID):
            return True
    return any(
        contents_at(data, offset, DEVICE_UNIQUE_ID, utf16)
        for utf16 in (True, False)
        for offset in range(0, 65, 4)
    )


def replace_reply(reply: bytes, virtual_id: bytes, write: bool) -> tuple[bytes, str]:
    if len(reply) < 8:
        return reply, "invalid"
    status, length = struct.unpack_from("<ii", reply)
    if status != 0 or length != 32 or len(reply) < 8 + length:
        return reply, "invalid"
    if len(virtual_id) != length:
        return reply, "mismatch"
    if not write:
        return reply, "dry-run"
    changed = bytearray(reply)
    changed[8:40] = virtual_id
    return bytes(changed), "replaced"


class AidlParcelProbeTest(unittest.TestCase):
    def test_exact_method_interface_and_property_match(self) -> None:
        self.assertTrue(matched_request(parcel(DEVICE_UNIQUE_ID), 11))

    def test_wrong_method_is_rejected(self) -> None:
        for code in (0, 1, 10, 12, 0xFFFFFF):
            self.assertFalse(matched_request(parcel(DEVICE_UNIQUE_ID), code))

    def test_other_property_and_interface_are_rejected(self) -> None:
        self.assertFalse(matched_request(parcel("securityLevel"), 11))
        other = parcel(DEVICE_UNIQUE_ID).replace(
            DRM_PLUGIN.encode("utf-16le"), b"x" * (len(DRM_PLUGIN) * 2)
        )
        self.assertFalse(matched_request(other, 11))

    def test_shifted_and_headered_descriptor_forms(self) -> None:
        self.assertTrue(matched_request(parcel(DEVICE_UNIQUE_ID, 12), 11))
        self.assertTrue(matched_request(parcel(DEVICE_UNIQUE_ID, 12, True), 11))

    def test_truncated_request_is_rejected(self) -> None:
        self.assertFalse(matched_request(parcel(DEVICE_UNIQUE_ID)[:70], 11))

    def test_dry_run_preserves_reply(self) -> None:
        original = struct.pack("<ii", 0, 32) + bytes(range(32))
        self.assertEqual(replace_reply(original, TEST_ID, False), (original, "dry-run"))

    def test_write_replaces_only_array_content(self) -> None:
        original = struct.pack("<ii", 0, 32) + bytes(range(32))
        result, state = replace_reply(original, TEST_ID, True)
        self.assertEqual(state, "replaced")
        self.assertEqual(result[:8], original[:8])
        self.assertEqual(result[8:40], TEST_ID)

    def test_status_length_and_bounds_fail_closed(self) -> None:
        cases = (
            struct.pack("<ii", 1, 32) + bytes(32),
            struct.pack("<ii", 0, 31) + bytes(31),
            struct.pack("<ii", 0, 32) + bytes(31),
        )
        for reply in cases:
            self.assertEqual(replace_reply(reply, TEST_ID, True)[0], reply)


if __name__ == "__main__":
    unittest.main()
