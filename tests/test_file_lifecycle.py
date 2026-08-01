import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
LEGACY_DEVELOPMENT_PAYLOADS = (
    "drmid-0.9.0-rc10.zip",
    "drmid-0.9.0-rc12.zip",
    "drmid_aidl_probe",
    "drmid_probe_runner",
    "drmid_rc13.zip",
    "drmid_rc13_runner",
    "drmid_rc14.zip",
    "drmid_rc14_runner",
)


class FileLifecycleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("g++")
        if compiler is None:
            raise unittest.SkipTest("g++ is required for the POSIX lifecycle fixture")
        cls.build_dir = tempfile.TemporaryDirectory(prefix="drmid-lifecycle-build-")
        cls.harness = Path(cls.build_dir.name) / "file_lifecycle_harness"
        subprocess.run(
            [
                compiler,
                "-std=c++20",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pthread",
                "-I",
                str(ROOT),
                str(ROOT / "file_lifecycle.cpp"),
                str(ROOT / "tests" / "file_lifecycle_harness.cpp"),
                "-o",
                str(cls.harness),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.build_dir.cleanup()

    def run_harness(self, operation, directory, *args):
        return subprocess.run(
            [str(self.harness), operation, str(directory), *map(str, args)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def start_holder(self, directory, milliseconds=30000, operation="hold"):
        command = [str(self.harness), operation, str(directory)]
        if operation == "hold":
            command.append(str(milliseconds))
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(process.stdout.readline().strip(), "locked")
        return process

    def test_seed_orphans_require_exact_decimal_regular_file(self):
        with tempfile.TemporaryDirectory(prefix="drmid-orphans-") as temporary:
            root = Path(temporary)
            removable = (
                "drmid_seed_record_v1.bin.tmp.123",
                "drmid_seed_record_v1.bin.tmp.00042",
            )
            retained_files = (
                "drmid_seed_record_v1.bin.tmp.",
                "drmid_seed_record_v1.bin.tmp.pid",
                "drmid_seed_record_v1.bin.tmp.12x",
                "other.tmp.123",
            )
            for name in removable + retained_files:
                (root / name).write_text("fixture", encoding="utf-8")
            retained_directory = root / "drmid_seed_record_v1.bin.tmp.777"
            retained_directory.mkdir()
            retained_symlink = root / "drmid_seed_record_v1.bin.tmp.888"
            retained_symlink.symlink_to(root / removable[0])

            result = self.run_harness("cleanup", root)
            self.assertEqual(result.stdout.strip(), "2")
            for name in removable:
                self.assertFalse((root / name).exists())
            for name in retained_files:
                self.assertTrue((root / name).is_file())
            self.assertTrue(retained_directory.is_dir())
            self.assertTrue(retained_symlink.is_symlink())

    def test_completed_seed_temp_fault_preserves_formal_seed(self):
        with tempfile.TemporaryDirectory(prefix="drmid-seed-fault-") as temporary:
            root = Path(temporary)
            seed = root / "drmid_seed_record_v1.bin"
            orphan = root / "drmid_seed_record_v1.bin.tmp.4242"
            seed.write_bytes(b"valid-seed-record" * 4)
            original = seed.read_bytes()
            orphan.write_bytes(b"completed-temp-record" * 4)
            result = self.run_harness("cleanup", root)
            self.assertEqual(result.stdout.strip(), "1")
            self.assertFalse(orphan.exists())
            self.assertEqual(seed.read_bytes(), original)

    def test_legacy_development_payloads_are_exact_and_cleanup_is_idempotent(self):
        with tempfile.TemporaryDirectory(prefix="drmid-legacy-payloads-") as temporary:
            root = Path(temporary)
            for name in LEGACY_DEVELOPMENT_PAYLOADS:
                (root / name).write_text("historical fixture", encoding="utf-8")

            first = self.run_harness("cleanup-legacy", root)
            self.assertEqual(first.stdout.strip(), str(len(LEGACY_DEVELOPMENT_PAYLOADS)))
            for name in LEGACY_DEVELOPMENT_PAYLOADS:
                self.assertFalse((root / name).exists())

            second = self.run_harness("cleanup-legacy", root)
            self.assertEqual(second.stdout.strip(), "0")

    def test_legacy_cleanup_retains_near_names_directories_and_symlinks(self):
        with tempfile.TemporaryDirectory(prefix="drmid-legacy-safety-") as temporary:
            root = Path(temporary)
            near_names = (
                "drmid-0.9.0-rc10.zip.bak",
                "DRMID-0.9.0-rc12.zip",
                "drmid_aidl_probe2",
                "prefix_drmid_probe_runner",
                "drmid_rc13",
                "drmid_rc13_runner.tmp",
                "drmid_rc14.zip.old",
                "drmid_rc14_runner/child",
            )
            for name in near_names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("retained fixture", encoding="utf-8")

            exact_directory = root / "drmid_rc13.zip"
            exact_directory.mkdir()
            protected_target = root / "protected-target"
            protected_target.write_text("keep", encoding="utf-8")
            exact_symlink = root / "drmid_rc14.zip"
            exact_symlink.symlink_to(protected_target)

            result = self.run_harness("cleanup-legacy", root)
            self.assertEqual(result.stdout.strip(), "0")
            for name in near_names:
                self.assertTrue((root / name).is_file())
            self.assertTrue(exact_directory.is_dir())
            self.assertTrue(exact_symlink.is_symlink())
            self.assertEqual(protected_target.read_text(encoding="utf-8"), "keep")

    def test_normal_lock_exit_removes_path(self):
        with tempfile.TemporaryDirectory(prefix="drmid-lock-normal-") as temporary:
            self.run_harness("normal", temporary)
            self.assertFalse((Path(temporary) / "drmid_daemon_v1.lock").exists())

    def test_concurrent_instance_cannot_break_owner_lock(self):
        with tempfile.TemporaryDirectory(prefix="drmid-lock-busy-") as temporary:
            holder = self.start_holder(temporary, 1000)
            try:
                contender = self.run_harness("try", temporary)
                self.assertEqual(contender.stdout.strip(), "busy")
                self.assertTrue(
                    (Path(temporary) / "drmid_daemon_v1.lock").is_file()
                )
            finally:
                holder.wait(timeout=5)
                holder.stdout.close()
                holder.stderr.close()
            self.assertEqual(holder.returncode, 0)
            self.assertFalse((Path(temporary) / "drmid_daemon_v1.lock").exists())

    def test_webui_probe_distinguishes_live_owner_and_stale_lock(self):
        with tempfile.TemporaryDirectory(prefix="drmid-lock-probe-") as temporary:
            holder = self.start_holder(temporary, 1000)
            try:
                probe = self.run_harness("check", temporary)
                state, pid = probe.stdout.strip().split()
                self.assertEqual(state, "alive")
                self.assertEqual(int(pid), holder.pid)
            finally:
                holder.kill()
                holder.wait(timeout=5)
                holder.stdout.close()
                holder.stderr.close()
            stale = self.run_harness("check", temporary)
            self.assertEqual(stale.stdout.strip(), "inactive")

    def test_killed_owner_is_recovered_and_next_exit_cleans_lock(self):
        with tempfile.TemporaryDirectory(prefix="drmid-lock-kill-") as temporary:
            lock_path = Path(temporary) / "drmid_daemon_v1.lock"
            holder = self.start_holder(temporary)
            holder.kill()
            holder.wait(timeout=5)
            holder.stdout.close()
            holder.stderr.close()
            self.assertTrue(lock_path.is_file())
            stale_pid = lock_path.read_text(encoding="utf-8")
            self.run_harness("normal", temporary)
            self.assertTrue(stale_pid.strip().isdigit())
            self.assertFalse(lock_path.exists())

    def test_sigterm_normal_path_removes_lock(self):
        with tempfile.TemporaryDirectory(prefix="drmid-lock-term-") as temporary:
            lock_path = Path(temporary) / "drmid_daemon_v1.lock"
            holder = self.start_holder(temporary, operation="hold-term")
            holder.terminate()
            holder.wait(timeout=5)
            holder.stdout.close()
            holder.stderr.close()
            self.assertEqual(holder.returncode, 0)
            self.assertFalse(lock_path.exists())

    def test_inode_replacement_is_not_removed_by_old_owner(self):
        with tempfile.TemporaryDirectory(prefix="drmid-lock-inode-") as temporary:
            root = Path(temporary)
            lock_path = root / "drmid_daemon_v1.lock"
            old_path = root / "drmid_daemon_v1.lock.old"
            holder = self.start_holder(root, 1000)
            try:
                original_inode = lock_path.stat().st_ino
                os.rename(lock_path, old_path)
                lock_path.write_text("replacement\n", encoding="utf-8")
                self.assertNotEqual(lock_path.stat().st_ino, original_inode)
            finally:
                holder.wait(timeout=5)
                holder.stdout.close()
                holder.stderr.close()
            self.assertEqual(holder.returncode, 0)
            self.assertEqual(lock_path.read_text(encoding="utf-8"), "replacement\n")

    def test_source_wires_cleanup_at_start_boot_cleanup_and_uninstall(self):
        module = (ROOT / "module_main.cpp").read_text(encoding="utf-8")
        lifecycle = (ROOT / "file_lifecycle.cpp").read_text(encoding="utf-8")
        self.assertIn("cleanup_seed_temp_orphans(module_private_dir)", module)
        self.assertGreaterEqual(
            module.count("cleanup_module_state_files(module_private_dir)"), 2
        )
        self.assertIn("cleanup_legacy_public_artifacts()", module)
        self.assertIn("cleanup_seed_temp_orphans(module_private_dir);", lifecycle)
        self.assertIn("cleanup_legacy_public_artifacts();", lifecycle)

    def test_legacy_payload_cleanup_uses_bounded_safe_directory_operations(self):
        lifecycle = (ROOT / "file_lifecycle.cpp").read_text(encoding="utf-8")
        for name in LEGACY_DEVELOPMENT_PAYLOADS:
            with self.subTest(name=name):
                self.assertEqual(lifecycle.count(f'"{name}"'), 1)
        for primitive in (
            "O_DIRECTORY",
            "O_NOFOLLOW",
            "AT_SYMLINK_NOFOLLOW",
            "S_ISREG",
            "unlinkat(owned_fd, entry->d_name, 0)",
            "std::strcmp(name, expected) == 0",
        ):
            with self.subTest(primitive=primitive):
                self.assertIn(primitive, lifecycle)

    def test_legacy_public_marker_is_cleanup_only_not_boot_control(self):
        module = (ROOT / "module_main.cpp").read_text(encoding="utf-8")
        lifecycle = (ROOT / "file_lifecycle.cpp").read_text(encoding="utf-8")
        self.assertNotIn("drmid_disable_boot_cleanup", module)
        self.assertIn("/data/local/tmp/drmid_disable_boot_cleanup", lifecycle)
        self.assertIn("cleanup_legacy_public_artifacts", module)
        self.assertNotIn("access(kBootCleanupMarker", module)


if __name__ == "__main__":
    unittest.main()
