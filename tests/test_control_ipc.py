#!/usr/bin/env python3
"""Fixtures for Binder-global Control IPC v5 and HAL lifecycle."""

from __future__ import annotations

import binascii
import ctypes
from pathlib import Path
import struct
import unittest


ROOT = Path(__file__).resolve().parents[1]
HEADER = (ROOT / "control_ipc.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "control_ipc.cpp").read_text(encoding="utf-8")
WEB = (ROOT / "web_ui.cpp").read_text(encoding="utf-8")
HTML = (ROOT / "webroot" / "index.html").read_text(encoding="utf-8")
MODULE = (ROOT / "module_main.cpp").read_text(encoding="utf-8")
MAGIC = 0x30324350494D5244


class ResponseLayout(ctypes.Structure):
    _fields_ = [
        ("magic", ctypes.c_uint64), ("version", ctypes.c_uint32),
        ("result", ctypes.c_int32), ("request_id", ctypes.c_uint64),
        ("daemon_pid", ctypes.c_uint64), ("active_calls", ctypes.c_uint64),
        ("generation", ctypes.c_uint64), ("seed_generation", ctypes.c_uint64),
        ("fingerprint", ctypes.c_uint64), ("switches", ctypes.c_uint64),
        ("rejections", ctypes.c_uint64), ("server_requests", ctypes.c_uint64),
        ("correlated", ctypes.c_uint64), ("candidates", ctypes.c_uint64),
        ("dry_hits", ctypes.c_uint64), ("write_ok", ctypes.c_uint64),
        ("write_faults", ctypes.c_uint64), ("hal_generation", ctypes.c_uint64),
        ("hal_switches", ctypes.c_uint64), ("hal_gate_hits", ctypes.c_uint64),
        ("active_slot", ctypes.c_uint32), ("mode", ctypes.c_uint32),
        ("length", ctypes.c_uint32), ("hal_state", ctypes.c_uint32),
        ("hal_count", ctypes.c_uint32), ("hal_tgids", ctypes.c_uint32 * 4),
        ("monitor_backend", ctypes.c_uint32),
        ("monitor_wakeups", ctypes.c_uint32),
        ("crc32", ctypes.c_uint32),
    ]


def request(operation: int, request_id: int = 7) -> bytes:
    prefix = struct.pack("<QIIQ", MAGIC, 5, operation, request_id)
    return prefix + struct.pack("<II", binascii.crc32(prefix) & 0xFFFFFFFF, 0)


class ControlIpcTest(unittest.TestCase):
    def test_request_is_fixed_32_bytes_and_crc_versioned(self) -> None:
        for operation in (1, 2, 3):
            data = request(operation)
            self.assertEqual(len(data), 32)
            self.assertEqual(struct.unpack_from("<I", data, 24)[0], binascii.crc32(data[:24]) & 0xFFFFFFFF)
        self.assertIn("kControlIpcVersion = 5", HEADER)
        self.assertIn("DRMIPC20", HEADER)

    def test_request_corruption_fails_closed(self) -> None:
        data = bytearray(request(1))
        data[12] ^= 1
        self.assertNotEqual(struct.unpack_from("<I", data, 24)[0], binascii.crc32(data[:24]) & 0xFFFFFFFF)

    def test_response_is_fixed_200_bytes_without_retired_tee_telemetry(self) -> None:
        self.assertEqual(ctypes.sizeof(ResponseLayout), 200)
        self.assertEqual(ResponseLayout.hal_tgids.offset, 172)
        self.assertEqual(ResponseLayout.monitor_backend.offset, 188)
        self.assertEqual(ResponseLayout.crc32.offset, 196)
        self.assertIn("static_assert(sizeof(ControlIpcResponse) == 200)", HEADER)
        for retired in ("tee_backend_state", "tee_firmware", "tee_op9"):
            self.assertNotIn(retired, HEADER + SOURCE)

    def test_protocol_contains_no_package_uid_or_rule_fields(self) -> None:
        for retired in ("target_count", "target_euids", "rule_mode", "package_status", "shared_uid"):
            self.assertNotIn(retired, HEADER + SOURCE + WEB)

    def test_daemon_uses_v3_record_and_v5_socket(self) -> None:
        self.assertIn('path += "drmid_control_v5.sock"', SOURCE)
        self.assertIn("migrate_runtime_control_v2", MODULE)
        self.assertIn("drmid_runtime_control_v3.bin", (ROOT / "runtime_control.cpp").read_text(encoding="utf-8"))

    def test_apply_reads_persisted_record_then_publishes_inactive_slot(self) -> None:
        start = SOURCE.index("ControlIpcOperation::kApply")
        read = SOURCE.index("read_runtime_control_file", start)
        publish = SOURCE.index("publish_runtime_config", read)
        self.assertLess(read, publish)
        web_start = WEB.index("bool handle_apply")
        persist = WEB.index("write_runtime_control_file", web_start)
        ipc = WEB.index("ControlIpcOperation::kApply", persist)
        self.assertLess(persist, ipc)

    def test_stable_pidfd_backend_blocks_without_periodic_scan(self) -> None:
        for marker in (
            "lifecycle_timeout_ms = -1",
            "descriptors.push_back({pidfd, POLLIN, 0})",
            "HalMonitorBackend::kPidfd",
            "descriptors.data(), descriptors.size(), poll_timeout_ms",
        ):
            self.assertIn(marker, SOURCE)
        self.assertNotIn("usleep(3000", SOURCE)
        self.assertNotIn("usleep(5000", SOURCE)

    def test_exit_clears_identity_before_rediscovery(self) -> None:
        event = SOURCE.index("if (pidfd_event)")
        clear = SOURCE.index("clear_monitored_identities", event)
        discover = SOURCE.index("rediscover_hal_identities", clear)
        self.assertLess(clear, discover)
        self.assertIn("hal_identity_restarts", SOURCE)

    def test_missing_hal_uses_bounded_backoff_and_fallback_is_low_frequency(self) -> None:
        for marker in (
            "kHalRediscoveryInitialMs = 50",
            "kHalRediscoveryMaximumMs = 2000",
            "kHalProcFallbackPollMs = 5000",
            "monitor.retry_ms * 2U",
        ):
            self.assertIn(marker, SOURCE)

    def test_webui_routes_are_global_and_session_authenticated(self) -> None:
        for route in ("/api/status", "/api/apply", "/api/stop", "/api/session/open", "/api/session/close"):
            self.assertIn(route, WEB + HTML)
        self.assertNotIn("/api/apps", WEB + HTML)
        self.assertIn("session_token", WEB + HTML)

    def test_hidden_page_closes_session_and_server(self) -> None:
        for marker in (
            "visibilitychange", "pagehide", "sendBeacon", "request_server_close_locked",
            "kSessionIdleTimeout", "后台已退出，请重新从管理器打开",
            "window.addEventListener('blur'", "document.addEventListener('freeze'",
        ):
            self.assertIn(marker, WEB + HTML)

    def test_status_json_exposes_hal_and_replacement_counters(self) -> None:
        for marker in (
            "hal_identity_generation", "hal_monitor_backend",
            "server_request_hits", "correlated_reply_candidates",
            "write_ok", "hal_tgids", "hal-outbound-binder-global",
        ):
            self.assertIn(marker, SOURCE)


if __name__ == "__main__":
    unittest.main()
