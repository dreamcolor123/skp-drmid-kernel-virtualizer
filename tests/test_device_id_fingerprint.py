from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "device_id_fingerprint.cpp").read_text(encoding="utf-8")
HEADER = (ROOT / "device_id_fingerprint.h").read_text(encoding="utf-8")
MODULE = (ROOT / "module_main.cpp").read_text(encoding="utf-8")
WEB_UI = (ROOT / "web_ui.cpp").read_text(encoding="utf-8")
ANDROID_MK = (ROOT / "jni" / "Android.mk").read_text(encoding="utf-8")
LIFECYCLE = (ROOT / "file_lifecycle.cpp").read_text(encoding="utf-8")
RUNTIME_PROFILE = (ROOT / "runtime_profile.cpp").read_text(encoding="utf-8")


class DeviceIdFingerprintTest(unittest.TestCase):
    def test_original_id_is_fingerprinted_before_hook_install(self):
        capture = MODULE.index("capture_original_id_fingerprint_if_missing")
        install = MODULE.index("install_readonly_parser_hook", capture)
        self.assertLess(capture, install)
        self.assertIn('AMediaDrm_getPropertyByteArray(drm, "deviceUniqueId"', SOURCE)
        self.assertIn("value.length == kWidevineIdBytes", SOURCE)
        self.assertIn("virtual_id_fingerprint(value.ptr, value.length)", SOURCE)

    def test_only_fingerprint_record_is_persisted_privately(self):
        self.assertIn("struct OriginalFingerprintRecord", SOURCE)
        self.assertIn("uint64_t fingerprint", SOURCE)
        self.assertNotIn("uint8_t original_id", SOURCE)
        for marker in (
            "O_DIRECTORY", "O_NOFOLLOW", "S_ISREG", "0600", "fsync(fd)",
            "renameat", "crc32", "drmid_original_fingerprint_v1.bin",
        ):
            self.assertIn(marker, SOURCE)

    def test_capture_source_is_linked_and_cleaned_with_module_state(self):
        self.assertIn("../device_id_fingerprint.cpp", ANDROID_MK)
        self.assertIn("-lmediandk", ANDROID_MK)
        self.assertIn("device_id_fingerprint.h", MODULE)
        self.assertIn("drmid_original_fingerprint_v1.bin", LIFECYCLE)
        self.assertIn("drmid_original_fingerprint_v1.bin.tmp", LIFECYCLE)

    def test_webui_status_exposes_fingerprint_without_changing_ipc_abi(self):
        self.assertIn("read_original_id_fingerprint", HEADER + WEB_UI)
        self.assertIn('\\"device_fingerprint\\"', WEB_UI)
        self.assertIn("module_private_dir", WEB_UI)

    def test_virtual_fingerprint_covers_the_active_32_byte_id(self):
        self.assertIn(
            "profile.virtual_stream.data(), kVirtualIdBytes", RUNTIME_PROFILE
        )
        self.assertIn(
            "config.virtual_id.data(), config.virtual_id_length", WEB_UI
        )
        self.assertIn("actual_fingerprint", MODULE)
        self.assertIn("persisted.profile_fingerprint", MODULE)


if __name__ == "__main__":
    unittest.main()
