import hashlib
from pathlib import Path
import re
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SDK_STATIC = ROOT.parent / "kernel_module_kit" / "lib" / "libkernel_module_kit_static.a"
EXPECTED_VERSION = "1.1.2"
EXPECTED_DISPLAY_NAME = "虚拟化DRM ID"
EXPECTED_AUTHOR = "斓梦语"
EXPECTED_SDK_SHA256 = "9144ddc36c7ebe2bd524bc38d279c82c14d0f162cc195fcbe98f19882eab71d2"
RC21_ZIP = ROOT / "dist" / (
    "module_drmid_kernel_virtualizer-0.9.0-rc21-arm64-run-once.zip"
)
RC22_ZIP = ROOT / "dist" / (
    "module_drmid_kernel_virtualizer-0.9.0-rc22-arm64-run-once.zip"
)
RC23_ZIP = ROOT / "dist" / (
    "module_drmid_kernel_virtualizer-0.9.0-rc23-arm64-run-once.zip"
)
RC24_ZIP = ROOT / "dist" / (
    "module_drmid_kernel_virtualizer-0.9.0-rc24-arm64-run-once.zip"
)
RC25_ZIP = ROOT / "dist" / (
    "module_drmid_kernel_virtualizer-0.9.0-rc25-arm64-run-once.zip"
)
RC26_ZIP = ROOT / "dist" / (
    "module_drmid_kernel_virtualizer-0.9.0-rc26-arm64-run-once.zip"
)
RC27_ZIP = ROOT / "dist" / (
    "module_drmid_kernel_virtualizer-0.9.0-rc27-arm64-run-once.zip"
)
RELEASE_ZIP = ROOT / "dist" / (
    "module_drmid_kernel_virtualizer-1.0.0-arm64-run-once.zip"
)
KERNEL66_RC1_ZIP = ROOT / "dist" / (
    "module_drmid_kernel_virtualizer-1.1.0-rc1-arm64-run-once.zip"
)
KERNEL66_RELEASE_ZIP = ROOT / "dist" / (
    "module_drmid_kernel_virtualizer-1.1.0-arm64-run-once.zip"
)
RESTART_RECLAIM_RC1_ZIP = ROOT / "dist" / (
    "module_drmid_kernel_virtualizer-1.1.1-rc1-arm64-run-once.zip"
)
RELEASE_112_ZIP = ROOT / "dist" / (
    "module_drmid_kernel_virtualizer-1.1.2-arm64-run-once.zip"
)
NATIVECHECK_NONINTERFERENCE_MARKERS = (
    b"persist.sys.spoof",
    b"persist.sys.pihooks",
    b"persist.sys.pixelprops",
    b"libauditpatch.so",
    b"logd plt hook success",
    b"u:r:priv_app:s0:c512,c768",
    b"__system_property_set",
    b"logcat -b events",
    b"auditd:I",
)


class ReleaseHardeningTest(unittest.TestCase):
    def test_module_and_package_versions_match(self):
        module_source = (ROOT / "module_main.cpp").read_text(encoding="utf-8")
        package_source = (ROOT / "package.py").read_text(encoding="utf-8")
        module_version = re.search(
            r'SKROOT_MODULE_VERSION\("([^"]+)"\)', module_source
        )
        package_version = re.search(r'^VERSION = "([^"]+)"$', package_source, re.M)
        self.assertIsNotNone(module_version)
        self.assertIsNotNone(package_version)
        self.assertEqual(module_version.group(1), EXPECTED_VERSION)
        self.assertEqual(package_version.group(1), EXPECTED_VERSION)

    def test_formal_module_identity_matches_release(self):
        module_source = (ROOT / "module_main.cpp").read_text(encoding="utf-8")
        package_source = (ROOT / "package.py").read_text(encoding="utf-8")
        self.assertIn(
            f'SKROOT_MODULE_NAME("{EXPECTED_DISPLAY_NAME}")', module_source
        )
        self.assertIn(
            f'SKROOT_MODULE_AUTHOR("{EXPECTED_AUTHOR}")', module_source
        )
        self.assertIn(f'DISPLAY_NAME = "{EXPECTED_DISPLAY_NAME}"', package_source)
        self.assertIn(f'AUTHOR = "{EXPECTED_AUTHOR}"', package_source)

    def test_sdk_454_baseline_is_pinned(self):
        if not SDK_STATIC.is_file():
            self.skipTest("SKP SDK static library is not part of the source repository")
        digest = hashlib.sha256(SDK_STATIC.read_bytes()).hexdigest()
        self.assertEqual(digest, EXPECTED_SDK_SHA256)

    def test_runner_excludes_environment_mutation_and_root_command_hooks(self):
        source = (ROOT / "runner_main.cpp").read_text(encoding="utf-8")
        forbidden = (
            "install_skroot_environment",
            "uninstall_skroot_environment",
            'action_name == "env-install"',
            'std::getenv("DRMID_ROOT_CMD")',
        )
        for marker in forbidden:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, source)

    def test_packager_runs_release_guard_before_writing_zip(self):
        source = (ROOT / "package.py").read_text(encoding="utf-8")
        guard_call = source.index("    verify_release_inputs()")
        payload_guard_call = source.index("    verify_built_payloads()")
        archive_guard_call = source.index("    verify_archive_members()")
        zip_open = source.index('    with zipfile.ZipFile(ZIP, "w"')
        self.assertLess(guard_call, zip_open)
        self.assertLess(payload_guard_call, zip_open)
        self.assertGreater(archive_guard_call, zip_open)

    def test_packager_rejects_stale_or_unhardened_binaries(self):
        source = (ROOT / "package.py").read_text(encoding="utf-8")
        self.assertIn('expected_version = VERSION.encode("ascii")', source)
        self.assertIn('stale_candidate_prefix = expected_version + b"-rc"', source)
        self.assertIn("stale release-candidate build", source)
        self.assertIn('b"env-install"', source)
        self.assertIn('b"DRMID_ROOT_CMD"', source)
        self.assertIn('b"DRMID_EXPORT_EXPECTED"', source)
        self.assertIn('b"DRMID_EXPORT_EXPECTED_READABLE"', source)
        for marker in NATIVECHECK_NONINTERFERENCE_MARKERS:
            with self.subTest(marker=marker):
                self.assertIn(marker.decode("ascii"), source)

    def test_rc21_payload_excludes_nativecheck_false_positive_inputs(self):
        candidates = tuple(candidate for candidate in (
            RC21_ZIP, RC22_ZIP, RC23_ZIP, RC24_ZIP, RC25_ZIP,
            RC26_ZIP, RC27_ZIP, RELEASE_ZIP,
            KERNEL66_RC1_ZIP, KERNEL66_RELEASE_ZIP,
            RESTART_RECLAIM_RC1_ZIP, RELEASE_112_ZIP,
        ) if candidate.is_file())
        if not candidates:
            self.skipTest("historical release ZIPs are not part of the source repository")
        for candidate in candidates:
            with zipfile.ZipFile(candidate) as archive:
                members = {
                    name: archive.read(name)
                    for name in archive.namelist()
                }
            for name, payload in members.items():
                for marker in NATIVECHECK_NONINTERFERENCE_MARKERS:
                    with self.subTest(
                        candidate=candidate.name, name=name, marker=marker
                    ):
                        self.assertNotIn(marker, payload)

    def test_packager_guards_exact_legacy_payload_cleanup(self):
        source = (ROOT / "package.py").read_text(encoding="utf-8")
        for marker in (
            "EXPECTED_LEGACY_DEVELOPMENT_PAYLOADS",
            "missing_payloads",
            "missing_primitives",
            "AT_SYMLINK_NOFOLLOW",
            "unlinkat(owned_fd, entry->d_name, 0)",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)

    def test_packager_guards_adaptive_startup_and_rejects_fixed_delay(self):
        source = (ROOT / "package.py").read_text(encoding="utf-8")
        for marker in (
            "required_startup_markers",
            "wait_for_adaptive_startup_readiness",
            "startup_observations_quiet",
            "forbidden_fixed_delay",
            "kDefaultPostBootDelayMs",
            "DRMID_POST_BOOT_DELAY_MS",
        ):
            self.assertIn(marker, source)

    def test_packager_guards_unconfigured_first_start(self):
        source = (ROOT / "package.py").read_text(encoding="utf-8")
        for marker in (
            "required_bootstrap",
            "first-start bootstrap guard failed",
            "kDefaultPackage",
            "pre-filled-com.sf.activity",
            '"packages-empty"',
        ):
            self.assertIn(marker, source)

    def test_packager_guards_webui_version_and_foreground_safe_stop(self):
        source = (ROOT / "package.py").read_text(encoding="utf-8")
        for marker in (
            "WebUI release version does not match package version",
            "WebUI foreground-safe STOP guard failed",
            "required_stop_flow",
            '"confirm(" in webui_html',
        ):
            self.assertIn(marker, source)

    def test_packager_guards_shadow_stack_and_bounded_locks(self):
        source = (ROOT / "package.py").read_text(encoding="utf-8")
        for marker in (
            "required_hook_lock",
            "Binder lock hardening guard failed",
            "CONFIG_SHADOW_CALL_STACK",
            "kMapLockTryCount = 8",
            "pending_lock_drops",
            "plugin_lock_drops",
            "emit_pending_lock_acquire(a, context_kaddr, x18)",
            "hook_lock_executable_source",
            "platform_register_uses",
            're.findall(r"\\b[wx]18\\b"',
        ):
            self.assertIn(marker, source)

    def test_packager_guards_binder_map_restart_reclamation(self):
        source = (ROOT / "package.py").read_text(encoding="utf-8")
        for marker in (
            "kPendingBucketWays = 8",
            "kPendingBucketWayShift = 3",
            "task_struct address can be reused",
            "Reclaim the oldest entry in the bounded bucket",
            "kPluginBucketWays = 8",
            "kPluginBucketWayShift = 3",
            "least-recently-used occupied slot",
            "recovered collision/eviction events",
        ):
            self.assertIn(marker, source)
        for marker in (
            "required_reclaim_diagnostics",
            "Binder map reclaim diagnostics guard failed",
            "miss/overflow/reclaim/oneway=",
            "map insert/reuse/reclaim/active=",
            "Binder parser hook installed context=%p abi=%",
        ):
            self.assertIn(marker, source)

    def test_packager_guards_linux66_strict_profile(self):
        source = (ROOT / "package.py").read_text(encoding="utf-8")
        for marker in (
            "required_kernel66_profile",
            "Linux 6.6 strict profile guard failed",
            "kClassicBinder66",
            "classic_binder-6.6",
            "0xd10343ffU",
            "offsets.file_f_op = 0xc0",
            "offsets.fops_unlocked_ioctl = 0x48",
            "62e54bf3e7aa39bb",
            "is_supported_ioctl_profile",
            "is_supported_612_ioctl_profile",
        ):
            self.assertIn(marker, source)

    def test_production_payload_excludes_public_expected_export(self):
        production_source = "\n".join(
            path.read_text(encoding="utf-8")
            for pattern in ("*.cpp", "*.h")
            for path in sorted(ROOT.glob(pattern))
        )
        for marker in (
            "DRMID_EXPORT_EXPECTED",
            "DRMID_EXPORT_EXPECTED_READABLE",
            "export_expected_profile",
            "fchmod(fd, 0644)",
        ):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, production_source)

    def test_archive_members_are_exact_and_private(self):
        source = (ROOT / "package.py").read_text(encoding="utf-8")
        for member in (
            '"libmodule_drmid_kernel_virtualizer.so"',
            '"drmid_label_helper.jar"',
            '"webroot/drmid_daemon"',
            '"webroot/index.html"',
        ):
            self.assertIn(member, source)
        self.assertIn('name.startswith("data/local/tmp/")', source)


if __name__ == "__main__":
    unittest.main()
