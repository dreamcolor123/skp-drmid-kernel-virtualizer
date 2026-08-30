#!/usr/bin/env python3
"""WebUI regression fixtures for global HAL mode and foreground sessions."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "webroot" / "index.html").read_text(encoding="utf-8")
WEB_CPP = (ROOT / "web_ui.cpp").read_text(encoding="utf-8")
RESOLVER = (ROOT / "binder_ioctl_resolver.cpp").read_text(encoding="utf-8")


class WebUiStateSyncTest(unittest.TestCase):
    def test_no_application_picker_package_or_uid_configuration_remains(self) -> None:
        for retired in ("/api/apps", "选择应用", "package_status", "target_euid", "sharedUid"):
            self.assertNotIn(retired, HTML)
        self.assertIn("一个 ID，全局生效", HTML)
        self.assertIn("Java MediaDrm 与 NDK AMediaDrm", HTML)

    def test_virtualization_mode_is_a_single_off_on_switch(self) -> None:
        self.assertIn('id="modeToggle" type="checkbox" role="switch"', HTML)
        self.assertIn('id="modeChoice">DRM ID虚拟化</b>', HTML)
        self.assertIn('aria-label="DRM ID虚拟化开关"', HTML)
        self.assertIn("当前状态：已关闭", HTML)
        self.assertIn("当前状态：已开启", HTML)
        self.assertIn("全局替换 Widevine HAL Binder 回复中的 32 字节 deviceUniqueId。", HTML)
        self.assertIn("$('modeChoice').textContent='DRM ID虚拟化'", HTML)
        self.assertNotIn("$('modeChoice').textContent=on?", HTML)
        self.assertIn("checked?'write':'dry'", HTML)
        self.assertIn(".switchcopy{min-width:0}", HTML)
        self.assertNotIn('name="mode"', HTML)
        self.assertLess(HTML.index("<h2>运行模式</h2>"), HTML.index("<h2>运行状态</h2>"))

    def test_id_sources_are_fixed_random_and_custom_only(self) -> None:
        for action in ("derive", "random", "custom"):
            self.assertIn(f'name="idAction" value="{action}"', HTML)
        self.assertNotIn('name="idAction" value="keep"', HTML)
        for label in ("固定值", "随机值", "自定义"):
            self.assertIn(label, HTML)
        self.assertIn("return x?x.value:'keep'", HTML)
        self.assertIn("不选择时保持当前 ID", HTML)

    def test_applied_id_source_is_cleared_to_prevent_accidental_rotation(self) -> None:
        self.assertIn("document.querySelectorAll('input[name=\"idAction\"]')", HTML)
        self.assertIn("x.checked=false", HTML)

    def test_custom_id_requires_exactly_64_hex_characters(self) -> None:
        self.assertIn('maxlength="64"', HTML)
        self.assertIn("/^[0-9a-fA-F]{64}$/", HTML)
        self.assertIn("需要恰好 64 个十六进制字符", HTML)
        self.assertIn(".field[hidden]{display:none}", HTML)

    def test_apply_disabled_until_session_and_valid_form(self) -> None:
        self.assertIn('id="applyBtn" class="btn primary" type="button" disabled', HTML)
        self.assertIn("!token||busy", HTML)
        self.assertIn("setAttribute('aria-disabled'", HTML)
        self.assertIn("请先填写 64 位十六进制自定义 ID", HTML)

    def test_mode_toggle_does_not_disable_apply_or_get_overwritten_by_stale_status(self) -> None:
        self.assertIn("formDirty=false", HTML)
        self.assertIn("function markDirty(){formDirty=true;syncControls()}", HTML)
        self.assertIn("if(!formDirty&&!busy)$('modeToggle').checked=s.mode===1", HTML)
        self.assertIn("$('modeToggle').addEventListener('change',markDirty)", HTML)

    def test_status_restores_mode_without_exposing_id_bytes(self) -> None:
        self.assertIn("$('modeToggle').checked=s.mode===1", HTML)
        self.assertIn("s.fingerprint", HTML)
        self.assertIn("s.device_fingerprint", HTML)
        self.assertNotIn("virtual_id_hex", HTML)
        self.assertNotIn("original_id_hex", HTML)

    def test_hal_lifecycle_and_request_counters_are_visible(self) -> None:
        for marker in (
            "hal_identity_generation", "hal_monitor_backend",
            "hal_monitor_wakeups", "server_request_hits", "write_ok",
            "pidfd 事件驱动", "HAL 出站 Binder（全局）",
        ):
            self.assertIn(marker, HTML)
        for retired in ("tee_backend_state", "tee_op9_candidates", "TEE 直连", "TEE 对象"):
            self.assertNotIn(retired, HTML)

    def test_binder_capability_diagnostics_are_visible_without_ipc_change(self) -> None:
        for marker in (
            "kernel_release", "binder_driver_backend",
            "binder_resolution_source", "binder_capabilities",
            "binder_entry_fingerprint", "drmid_binder_capability_v1.bin",
            "内核版本", "Binder 驱动", "解析来源", "能力标志", "入口指纹",
        ):
            self.assertIn(marker, HTML + WEB_CPP + RESOLVER)

    def test_stop_confirmation_stays_in_foreground_page(self) -> None:
        self.assertNotIn("confirm(", HTML)
        self.assertIn("stopArmedUntil", HTML)
        self.assertIn("再次点击确认停止", HTML)
        self.assertIn("5 秒内再次点击确认停止", HTML)

    def test_hidden_or_closed_page_ends_session_and_port(self) -> None:
        for marker in (
            "visibilitychange", "pagehide", "beforeunload", "sendBeacon",
            "window.addEventListener('blur'", "document.addEventListener('freeze'",
            "/api/session/close", "当前 WebUI 会话和监听端口会自动结束",
        ):
            self.assertIn(marker, HTML)
        self.assertIn("hidden-during-open", HTML)

    def test_page_exit_is_terminal_and_replaces_the_entire_webui(self) -> None:
        for marker in (
            'id="sessionEnded"', "后台已退出，请重新从管理器打开",
            "body.session-ended>:not(#sessionEnded):not(script)",
            "document.body.classList.add('session-ended')",
            "此页面不会自动重新连接", "window.addEventListener('pageshow'",
        ):
            self.assertIn(marker, HTML)
        self.assertEqual(HTML.count("terminal=false"), 1)

    def test_close_during_async_open_still_closes_the_new_session(self) -> None:
        self.assertIn("if(terminal||document.visibilityState!=='visible')", HTML)
        self.assertIn("closeSession(terminalReason||'hidden-during-open')", HTML)
        self.assertIn("dispatchSessionClose(sessionToken,terminalReason)", HTML)
        self.assertIn("queued=navigator.sendBeacon", HTML)
        self.assertIn("if(!queued)", HTML)

    def test_session_heartbeat_only_runs_while_visible(self) -> None:
        self.assertIn("document.visibilityState!=='visible'", HTML)
        self.assertIn("/api/session/ping", HTML)
        self.assertIn("clearInterval(heartbeat)", HTML)
        self.assertIn("closeSession('heartbeat-lost')", HTML)

    def test_mobile_layout_and_dark_mode_are_present(self) -> None:
        self.assertIn("@media(max-width:650px)", HTML)
        self.assertIn("grid-template-columns:minmax(0,1fr)", HTML)
        self.assertIn(".card{min-width:0", HTML)
        self.assertIn("@media(prefers-color-scheme:dark)", HTML)
        self.assertIn("env(safe-area-inset-bottom)", HTML)

    def test_release_identity_is_visible(self) -> None:
        self.assertIn("1.4.0 · 斓梦语", HTML)

    def test_inline_javascript_has_valid_syntax(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is required")
        script = HTML.split("<script>", 1)[1].split("</script>", 1)[0]
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
            handle.write(script)
            handle.flush()
            subprocess.run([node, "--check", handle.name], check=True, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
