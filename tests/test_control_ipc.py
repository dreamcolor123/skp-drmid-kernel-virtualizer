#!/usr/bin/env python3
"""Offline fixtures for control protocol v2 and multi-package WebUI."""

from __future__ import annotations

import binascii
from pathlib import Path
import struct
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONTROL = (ROOT / "control_ipc.cpp").read_text(encoding="utf-8")
IPC_MAGIC = 0x36314350494D5244
IPC_VERSION = 2
REQUEST_FORMAT = "<QIIQII"
RESPONSE_FORMAT = "<QIi11Q5I32I3I"


def request(operation: int, request_id: int = 0x1122334455667788) -> bytes:
    prefix = struct.pack("<QIIQ", IPC_MAGIC, IPC_VERSION, operation, request_id)
    crc = binascii.crc32(prefix) & 0xFFFFFFFF
    return struct.pack(
        REQUEST_FORMAT, IPC_MAGIC, IPC_VERSION, operation, request_id, crc, 0
    )


def valid_request(data: bytes) -> bool:
    if len(data) != 32:
        return False
    magic, version, operation, _, crc, reserved = struct.unpack(REQUEST_FORMAT, data)
    return (
        magic == IPC_MAGIC and version == IPC_VERSION and 1 <= operation <= 3
        and reserved == 0 and crc == (binascii.crc32(data[:24]) & 0xFFFFFFFF)
    )


def response() -> bytes:
    targets = [10373, 10455, 10500] + [0] * 29
    fields = [
        IPC_MAGIC, IPC_VERSION, 0,
        0x1122334455667788, 3141, 0, 8, 2, 0xA07FC413AF94A3ED,
        7, 1, 200, 100, 100,
        1, 1, 2, 3, 32,
        *targets,
        0, 0, 0,
    ]
    raw = bytearray(struct.pack(RESPONSE_FORMAT, *fields))
    struct.pack_into("<I", raw, 252, binascii.crc32(raw[:252]) & 0xFFFFFFFF)
    return bytes(raw)


class ControlIpcTest(unittest.TestCase):
    def test_production_control_socket_blocks_instead_of_periodic_wakeup(self):
        self.assertIn(
            "const int poll_timeout_ms = max_runtime_ms == 0 ? -1 : kPollMs",
            CONTROL,
        )
        self.assertIn("poll(&descriptor, 1, poll_timeout_ms)", CONTROL)
        self.assertNotIn("poll(&descriptor, 1, kPollMs)", CONTROL)

    def test_request_is_fixed_32_bytes(self) -> None:
        self.assertEqual(struct.calcsize(REQUEST_FORMAT), 32)
        self.assertEqual(len(request(1)), 32)

    def test_request_crc_version_and_operations(self) -> None:
        for operation in (1, 2, 3):
            self.assertTrue(valid_request(request(operation)))
        self.assertFalse(valid_request(request(0)))
        old = bytearray(request(1))
        struct.pack_into("<I", old, 8, 1)
        self.assertFalse(valid_request(bytes(old)))

    def test_request_corruption_fails_closed(self) -> None:
        raw = bytearray(request(2))
        raw[18] ^= 0x80
        self.assertFalse(valid_request(bytes(raw)))

    def test_response_is_fixed_264_bytes_with_crc(self) -> None:
        raw = response()
        self.assertEqual(struct.calcsize(RESPONSE_FORMAT), 264)
        self.assertEqual(len(raw), 264)
        self.assertEqual(
            struct.unpack_from("<I", raw, 252)[0],
            binascii.crc32(raw[:252]) & 0xFFFFFFFF,
        )
        self.assertEqual(raw[256:264], bytes(8))

    def test_response_contains_target_count_and_euids(self) -> None:
        fields = struct.unpack(RESPONSE_FORMAT, response())
        self.assertEqual(fields[6], 8)  # config generation
        self.assertEqual(fields[8], 0xA07FC413AF94A3ED)
        self.assertEqual(fields[14:19], (1, 1, 2, 3, 32))
        self.assertEqual(fields[19:22], (10373, 10455, 10500))

    def test_socket_path_respects_linux_sun_path_limit(self) -> None:
        private_dir = "/data/adb/skroot/modules/drmidKern612"
        path = private_dir + "/drmid_control_v2.sock"
        self.assertLess(len(path.encode()), 108)

    def test_webui_routes_and_assets_are_bundled(self) -> None:
        source = (ROOT / "web_ui.cpp").read_text(encoding="utf-8")
        page = (ROOT / "webroot" / "index.html").read_text(encoding="utf-8")
        package = (ROOT / "package.py").read_text(encoding="utf-8")
        for route in (
            "/api/status", "/api/apply", "/api/stop",
            "/api/apps",
            "/api/session/open", "/api/session/ping", "/api/session/close",
        ):
            self.assertIn(route, source)
            self.assertIn(route, page)
        self.assertIn("DRMID_TARGET_PACKAGES", source)
        for marker in (
            "package_status", "unresolved_packages", "duplicate_count",
            "shared_uid", "target_count",
        ):
            self.assertIn(marker, source)
            self.assertIn(marker, page)
        self.assertIn('WEBROOT.rglob("*")', package)

    def test_webui_session_closes_on_hidden_page_and_has_timeout_fallback(self) -> None:
        source = (ROOT / "web_ui.cpp").read_text(encoding="utf-8")
        page = (ROOT / "webroot" / "index.html").read_text(encoding="utf-8")
        for marker in (
            "session_watchdog", "kSessionOpenGrace", "kSessionIdleTimeout",
            "server->close()", "session_token", "onServerCreated",
            "onBeforeServerExit",
        ):
            self.assertIn(marker, source)
        for marker in (
            "visibilitychange", "pagehide", "beforeunload", "sendBeacon",
            "/api/session/ping", "/api/session/close", "sessionClosed",
        ):
            self.assertIn(marker, page)

    def test_webui_api_requests_carry_session_token(self) -> None:
        page = (ROOT / "webroot" / "index.html").read_text(encoding="utf-8")
        self.assertIn("params.set('session_token',sessionToken)", page)
        self.assertIn("api('/api/session/open','',false)", page)
        self.assertIn("sessionToken=s.session_token", page)

    def test_apply_order_is_resolve_persist_then_publish(self) -> None:
        source = (ROOT / "web_ui.cpp").read_text(encoding="utf-8")
        resolve = source.index("load_or_resolve_target_config")
        persist = source.index("write_runtime_control_file", resolve)
        publish = source.index("ControlIpcOperation::kApply", persist)
        self.assertLess(resolve, persist)
        self.assertLess(persist, publish)
        self.assertIn("active kernel slot therefore remains", source)

    def test_daemon_restores_v2_control_and_uses_v2_socket(self) -> None:
        source = (ROOT / "module_main.cpp").read_text(encoding="utf-8")
        lifecycle = (ROOT / "file_lifecycle.cpp").read_text(encoding="utf-8")
        control = (ROOT / "control_ipc.cpp").read_text(encoding="utf-8")
        self.assertIn("startup control migrated v1-to-v2", source)
        self.assertIn("startup control rebound to resolved target", source)
        self.assertIn("run_control_socket_server", source)
        self.assertIn("drmid_runtime_control_v2.bin", lifecycle)
        self.assertIn("drmid_target_config_v2.bin", lifecycle)
        self.assertIn("drmid_control_v2.sock", control)

    def test_package_lookup_has_early_boot_local_source(self) -> None:
        source = (ROOT / "target_config.cpp").read_text(encoding="utf-8")
        self.assertIn("/data/system/packages.list", source)
        self.assertLess(
            source.index("resolve_package_uid_from_packages_list"),
            source.index("cmd package list packages -U"),
        )
        self.assertIn("complete target generation", source)

    def test_fresh_start_bootstraps_without_a_package_name(self) -> None:
        target = (ROOT / "target_config.cpp").read_text(encoding="utf-8")
        module = (ROOT / "module_main.cpp").read_text(encoding="utf-8")
        webui = (ROOT / "web_ui.cpp").read_text(encoding="utf-8")
        page = (ROOT / "webroot" / "index.html").read_text(encoding="utf-8")
        self.assertNotIn("kDefaultPackage", target + webui)
        self.assertIn(
            "desired.rule_mode = static_cast<uint32_t>(TargetRuleMode::kAll)",
            target,
        )
        self.assertIn("unconfigured bootstrap: no target package", module)
        self.assertIn("config.mode = drmid::ReplacementMode::kDryRun", module)
        self.assertIn("config.target_count = 0", module)
        self.assertIn('error_json(KModErr::ERR_MODULE_PARAM, "packages-empty")', webui)
        self.assertNotIn(">com.sf.activity</textarea>", page)


if __name__ == "__main__":
    unittest.main()
