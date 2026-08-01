from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "webroot" / "index.html").read_text(encoding="utf-8")


class WebUiStateSyncTest(unittest.TestCase):
    def test_first_start_has_no_prefilled_device_specific_package(self):
        self.assertNotIn(">com.sf.activity</textarea>", HTML)
        self.assertIn('placeholder="请从设备选择应用，或输入包名"', HTML)
        self.assertIn("选择应用，一次启用", HTML)
        self.assertIn("s.configured===false", HTML)
        self.assertIn("尚未选择应用", HTML)

    def test_primary_workflow_precedes_advanced_diagnostics(self):
        self.assertLess(HTML.index("第 1 步"), HTML.index("高级设置"))
        self.assertLess(HTML.index("高级设置"), HTML.index("诊断信息"))
        self.assertIn('class="advanced"', HTML)
        self.assertIn('class="diagnostics"', HTML)

    def test_dry_run_is_fail_closed_markup_default(self):
        self.assertLess(HTML.index('<option value="dry">'),
                        HTML.index('<option value="write">'))

    def test_apply_is_disabled_until_status_initializes_form(self):
        self.assertIn('id="apply" class="sr-only" type="submit" disabled', HTML)
        self.assertIn('id="applyAction" class="btn primary" type="button" disabled', HTML)
        self.assertIn("if(!formInitialized)return", HTML)
        self.assertIn("!formInitialized||!dirty||!packages.length", HTML)

    def test_status_restores_mode_and_complete_package_list(self):
        self.assertIn("function syncConfig(s)", HTML)
        self.assertIn("s.package_status.map(x=>x.package).join('\\n')", HTML)
        self.assertIn("if(syncForm||!formInitialized)syncConfig(s)", HTML)
        self.assertIn("render(s,true)", HTML)
        self.assertIn("s.package_status.map(x=>x.package).join('\\n'):''", HTML)

    def test_first_setup_prepares_write_mode_without_changing_backend_default(self):
        self.assertIn("s.configured===false?true:s.mode===1", HTML)
        self.assertIn("$('mode').value=$('effectToggle').checked?'write':'dry'", HTML)
        self.assertIn("启用并应用", HTML)

    def test_first_setup_explicitly_selects_derived_id(self):
        self.assertIn(
            "$('idAction').value=s.configured===false?'derive':'keep'", HTML
        )
        self.assertIn("使用自动生成 ID", HTML)

    def test_dirty_state_controls_single_sticky_apply_action(self):
        self.assertIn("function configSignature()", HTML)
        self.assertIn("configSignature()!==baselineSignature", HTML)
        self.assertIn("$('configForm').requestSubmit()", HTML)
        self.assertIn('id="actionBar" class="action-bar"', HTML)

    def test_multi_package_input_dedup_boundary_and_shared_uid_notice(self):
        self.assertIn('name="packages" maxlength="4096"', HTML)
        self.assertIn("unique.length>32", HTML)
        self.assertIn("new Set(tokens)", HTML)
        self.assertIn("sharedUidWarn", HTML)
        self.assertIn("package_status", HTML)

    def test_existing_id_is_kept_until_user_selects_custom_or_derive(self):
        self.assertIn('name="id_action" type="hidden" value="keep"', HTML)
        self.assertIn("$('idAction').value='custom'", HTML)
        self.assertIn("$('idAction').value='derive'", HTML)
        self.assertIn("s.configured===false?'derive':'keep'", HTML)

    def test_original_and_active_virtual_fingerprints_are_separate(self):
        for marker in (
            'id="deviceFingerprintShort"', 'id="virtualFingerprintShort"',
            'id="deviceFingerprint"', 'id="virtualFingerprint"',
            "s.device_fingerprint||'待采集'",
            "enabled?(s.fingerprint||'—'):'未启用'",
        ):
            self.assertIn(marker, HTML)

    def test_titles_and_descriptions_have_no_sentence_full_stop(self):
        self.assertNotIn("。", HTML)

    def test_stop_confirmation_does_not_hide_the_foreground_page(self):
        self.assertNotIn("confirm(", HTML)
        self.assertIn("stopArmedUntil", HTML)
        self.assertIn("再次点击确认停止", HTML)
        self.assertIn("5 秒内再次点击确认停止", HTML)

    def test_apple_visual_tokens_and_no_decorative_gradient_or_card_shadow(self):
        for marker in ("--blue: #0066cc", "--ink: #1d1d1f",
                       "--parchment: #f5f5f7", "SF Pro Display",
                       "border-radius: 9999px"):
            self.assertIn(marker, HTML)
        self.assertNotIn("linear-gradient", HTML)
        self.assertNotIn("radial-gradient", HTML)
        self.assertNotIn("box-shadow", HTML)

    def test_foreground_session_constraint_is_visible_before_interaction(self):
        self.assertIn("操作期间请保持页面在前台", HTML)
        self.assertIn("visibilitychange", HTML)
        self.assertIn("请从管理器模块页重新打开", HTML)


if __name__ == "__main__":
    unittest.main()
