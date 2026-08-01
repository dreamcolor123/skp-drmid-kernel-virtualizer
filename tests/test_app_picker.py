from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "webroot" / "index.html").read_text(encoding="utf-8")
WEB_UI = (ROOT / "web_ui.cpp").read_text(encoding="utf-8")
CATALOG_H = (ROOT / "app_catalog.h").read_text(encoding="utf-8")
CATALOG_CPP = (ROOT / "app_catalog.cpp").read_text(encoding="utf-8")
ANDROID_MK = (ROOT / "jni" / "Android.mk").read_text(encoding="utf-8")
LABEL_HELPER = (ROOT / "label_helper" / "DrmidAppLabels.java").read_text(
    encoding="utf-8"
)


class AppPickerFixtureTest(unittest.TestCase):
    def test_picker_controls_and_device_route_exist(self):
        for marker in (
            'id="pickApps"', 'id="appPickerMask"', 'id="appSearch"',
            'id="appFilter"', 'id="selectVisibleApps"',
            'id="clearSelectedApps"', 'id="confirmAppPicker"',
            "/api/apps",
        ):
            self.assertIn(marker, HTML)
        self.assertIn("if (path == \"/api/apps\")", WEB_UI)
        self.assertIn("enumerate_device_apps", WEB_UI)

    def test_picker_preserves_manual_semantics_until_apply(self):
        self.assertIn("应用已选好，点击下方按钮即可生效", HTML)
        self.assertIn("使用所选应用", HTML)
        self.assertIn("$('packages').value=[...pickerSelected].sort().join('\\n')", HTML)
        self.assertIn("api('/api/apply',body)", HTML)

    def test_picker_is_bounded_and_deduplicated_by_package(self):
        self.assertIn("pickerSelected=new Set(currentPackageTokens())", HTML)
        self.assertIn("pickerSelected.size>=32", HTML)
        self.assertIn("kDeviceAppCatalogLimit = 512", CATALOG_H)
        self.assertIn("if (apps.size() >= kDeviceAppCatalogLimit)", CATALOG_CPP)

    def test_app_records_include_label_icon_uid_and_system_state(self):
        for marker in (
            '\\"package\\"', '\\"uid\\"', '\\"label\\"', '\\"icon\\"',
            '\\"icon_source\\"', '\\"label_source\\"', '\\"system\\"',
            "package_fallback_label", "generated_icon", "extract_png_from_apk",
            "apk-resource", "data:image/png;base64",
        ):
            self.assertIn(marker, WEB_UI + CATALOG_CPP)
        self.assertIn("/data/system/packages.list", CATALOG_CPP)
        self.assertNotIn("cmd package dump", CATALOG_CPP)

    def test_labels_follow_current_android_locale(self):
        for marker in (
            "drmid_label_helper.jar", "/system/bin/app_process",
            "DrmidAppLabels", "base64_decode", "valid_utf8_label",
            "module_private_dir",
        ):
            self.assertIn(marker, CATALOG_CPP + CATALOG_H)
        for marker in (
            "IPackageManager$Stub", "getInstalledApplications",
            "Resources.getSystem()", "getLocales().toLanguageTags()",
            "addAssetPath", "splitSourceDirs", "Base64.NO_WRAP",
            '"#locale\\t"',
        ):
            self.assertIn(marker, LABEL_HELPER)

    def test_label_helper_output_is_bounded_and_private(self):
        package_source = (ROOT / "package.py").read_text(encoding="utf-8")
        self.assertIn("kLabelHelperMaxBytes = 1024 * 1024", CATALOG_CPP)
        self.assertIn("kLabelHelperMaxFileBytes = 128 * 1024", CATALOG_CPP)
        self.assertIn("S_ISREG", CATALOG_CPP)
        self.assertIn('"drmid_label_helper.jar"', package_source)
        self.assertIn('helper.namelist() != ["classes.dex"]', package_source)

    def test_new_source_is_built_into_webui_payload(self):
        self.assertIn("../app_catalog.cpp", ANDROID_MK)
        version = re.search(r'SKROOT_MODULE_VERSION\("([^\"]+)"\)',
                            (ROOT / "module_main.cpp").read_text())
        self.assertEqual(version.group(1), "1.1.2")


if __name__ == "__main__":
    unittest.main()
