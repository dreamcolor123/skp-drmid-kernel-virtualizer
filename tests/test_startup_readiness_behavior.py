from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class StartupReadinessBehaviorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("g++")
        if compiler is None:
            raise unittest.SkipTest("g++ is required for the readiness fixture")
        cls.build_dir = tempfile.TemporaryDirectory(prefix="drmid-ready-build-")
        cls.harness = Path(cls.build_dir.name) / "startup_readiness_harness"
        subprocess.run(
            [
                compiler,
                "-std=c++20",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(ROOT / "tests" / "host_stubs"),
                "-I",
                str(ROOT),
                str(ROOT / "startup_readiness.cpp"),
                str(ROOT / "tests" / "startup_readiness_harness.cpp"),
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

    def run_harness(self, operation):
        return subprocess.run(
            [str(self.harness), operation],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()

    def test_all_base_services_are_required(self):
        self.assertEqual(self.run_harness("ready"), "1")
        self.assertEqual(self.run_harness("missing-service"), "0")

    def test_low_cpu_same_identity_and_count_is_quiet(self):
        self.assertEqual(self.run_harness("quiet"), "1")

    def test_busy_cpu_process_churn_and_identity_change_reset_window(self):
        for operation in ("busy", "process-churn", "identity-change"):
            with self.subTest(operation=operation):
                self.assertEqual(self.run_harness(operation), "0")

    def test_policy_defaults_and_out_of_range_fallbacks(self):
        expected = "250 3000 45000 500"
        self.assertEqual(self.run_harness("policy-default"), expected)
        self.assertEqual(self.run_harness("policy-bounded"), expected)


if __name__ == "__main__":
    unittest.main()
