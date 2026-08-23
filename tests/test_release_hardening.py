#!/usr/bin/env python3
"""Release guards for the 1.3.0-rc1 caller-global candidate."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SDK = ROOT.parent / "kernel_module_kit" / "lib" / "libkernel_module_kit_static.a"
VERSION = "1.3.0-rc1"
ZIP = ROOT / "dist" / f"module_drmid_kernel_virtualizer-{VERSION}-arm64-run-once.zip"
SDK_SHA256 = "9144ddc36c7ebe2bd524bc38d279c82c14d0f162cc195fcbe98f19882eab71d2"


class ReleaseHardeningTest(unittest.TestCase):
    def require_file(self, path: Path, label: str) -> None:
        if not path.is_file():
            self.skipTest(f"{label} is generated locally and is not tracked")

    def test_module_package_and_webui_versions_match(self) -> None:
        module = (ROOT / "module_main.cpp").read_text(encoding="utf-8")
        package = (ROOT / "package.py").read_text(encoding="utf-8")
        html = (ROOT / "webroot" / "index.html").read_text(encoding="utf-8")
        self.assertEqual(re.search(r'SKROOT_MODULE_VERSION\("([^"]+)"\)', module).group(1), VERSION)
        self.assertEqual(re.search(r'^VERSION = "([^"]+)"$', package, re.M).group(1), VERSION)
        self.assertIn(VERSION, html)

    def test_webui_uses_simplified_mode_and_id_source_model(self) -> None:
        html = (ROOT / "webroot" / "index.html").read_text(encoding="utf-8")
        for marker in (
            'id="modeChoice">DRM ID虚拟化</b>',
            'aria-label="DRM ID虚拟化开关"',
            "当前状态：已关闭", "当前状态：已开启",
            "固定值", "随机值", "自定义",
        ):
            self.assertIn(marker, html)
        for retired in (
            'name="mode"', 'name="idAction" value="keep"',
            "<b>Dry-run</b>", "<b>全局写入</b>", "<b>恢复派生</b>",
        ):
            self.assertNotIn(retired, html)

    def test_formal_identity_and_sdk_454_are_pinned(self) -> None:
        module = (ROOT / "module_main.cpp").read_text(encoding="utf-8")
        self.assertIn('SKROOT_MODULE_NAME("虚拟化DRM ID")', module)
        self.assertIn('SKROOT_MODULE_AUTHOR("斓梦语")', module)
        self.require_file(SDK, "SKP SDK static library")
        self.assertEqual(hashlib.sha256(SDK.read_bytes()).hexdigest(), SDK_SHA256)

    def test_retired_multi_application_sources_are_absent(self) -> None:
        for name in (
            "app_catalog.cpp", "app_catalog.h", "target_config.cpp",
            "target_config.h", "build_label_helper.py",
        ):
            self.assertFalse((ROOT / name).exists(), name)
        self.assertFalse((ROOT / "label_helper" / "drmid_label_helper.jar").exists())

    def test_android_makefile_does_not_build_retired_components(self) -> None:
        makefile = (ROOT / "jni" / "Android.mk").read_text(encoding="utf-8")
        for retired in ("app_catalog.cpp", "target_config.cpp", "drmid_multi_target_probe"):
            self.assertNotIn(retired, makefile)
        self.assertIn("../hal_identity.cpp", makefile)

    def test_packager_guards_hal_backend_lifecycle_and_global_webui(self) -> None:
        source = (ROOT / "package.py").read_text(encoding="utf-8")
        for marker in (
            "HAL Binder backend", "kCounterContextAbi = 19",
            "kGetPropertyByteArrayTransactionCode = 11",
            "HAL identity lifecycle", "pidfd_open", "clear_monitored_identities",
            "retired application hot path", "retired application WebUI",
            "state convergence", "cleanup_legacy_target_state_after_global_migration",
        ):
            self.assertIn(marker, source)

    def test_packager_guards_run_before_archive_write(self) -> None:
        source = (ROOT / "package.py").read_text(encoding="utf-8")
        main = source.index("def main()")
        inputs = source.index("verify_release_inputs()", main)
        payloads = source.index("verify_built_payloads()", main)
        archive = source.index("build_archive()", main)
        verify = source.index("verify_archive_members()", archive)
        self.assertLess(inputs, archive)
        self.assertLess(payloads, archive)
        self.assertGreater(verify, archive)

    def test_runner_has_no_skp_environment_mutation_path(self) -> None:
        runner = (ROOT / "runner_main.cpp").read_text(encoding="utf-8")
        for marker in (
            "install_skroot_environment", "uninstall_skroot_environment",
            'action_name == "env-install"', 'std::getenv("DRMID_ROOT_CMD")',
        ):
            self.assertNotIn(marker, runner)

    def test_production_sources_have_no_public_id_export(self) -> None:
        production = "\n".join(
            path.read_text(encoding="utf-8")
            for pattern in ("*.cpp", "*.h")
            for path in ROOT.glob(pattern)
        )
        for marker in (
            "DRMID_EXPORT_EXPECTED", "DRMID_EXPORT_EXPECTED_READABLE",
            "export_expected_profile", "fchmod(fd, 0644)",
        ):
            self.assertNotIn(marker, production)

    def test_archive_members_are_exact_and_private(self) -> None:
        self.require_file(ZIP, "release ZIP")
        self.assertTrue(ZIP.is_file())
        with zipfile.ZipFile(ZIP) as archive:
            self.assertEqual(
                set(archive.namelist()),
                {
                    "libmodule_drmid_kernel_virtualizer.so",
                    "webroot/drmid_daemon",
                    "webroot/index.html",
                },
            )
            self.assertTrue(all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in archive.infolist()))
            self.assertFalse(any("label_helper" in name or name.startswith("data/local/tmp") for name in archive.namelist()))

    def test_archive_build_is_reproducible(self) -> None:
        self.require_file(SDK, "SKP SDK static library")
        for payload in (
            ROOT / "libs" / "arm64-v8a" / "libmodule_drmid_kernel_virtualizer.so",
            ROOT / "libs" / "arm64-v8a" / "drmid_probe_runner",
        ):
            self.require_file(payload, "built ARM64 payload")
        first = subprocess.run(["python3", "package.py"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.splitlines()[-1]
        second = subprocess.run(["python3", "package.py"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.splitlines()[-1]
        self.assertEqual(first, second)
        self.assertEqual(first, hashlib.sha256(ZIP.read_bytes()).hexdigest())

    def test_binaries_contain_current_identity_and_backend(self) -> None:
        for payload in (
            ROOT / "libs" / "arm64-v8a" / "libmodule_drmid_kernel_virtualizer.so",
            ROOT / "libs" / "arm64-v8a" / "drmid_probe_runner",
        ):
            self.require_file(payload, "built ARM64 payload")
            data = payload.read_bytes()
            for marker in (VERSION.encode(), "虚拟化DRM ID".encode(), b"hal-binder+widevine-smcinvoke-global", b"drmid_control_v4.sock"):
                self.assertIn(marker, data)

    def test_kernel_66_and_612_strict_profiles_remain_guarded(self) -> None:
        resolver = (ROOT / "binder_ioctl_resolver.cpp").read_text(encoding="utf-8")
        module = (ROOT / "module_main.cpp").read_text(encoding="utf-8")
        for marker in ("kClassicBinder66", "classic_binder-6.6", 'kernel_version.rfind("6.6.", 0)', 'kernel_version.rfind("6.12.", 0)', "is_supported_ioctl_profile"):
            self.assertIn(marker, resolver + module)


if __name__ == "__main__":
    unittest.main()
