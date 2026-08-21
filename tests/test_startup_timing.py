from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "module_main.cpp").read_text(encoding="utf-8")
READINESS = (ROOT / "startup_readiness.cpp").read_text(encoding="utf-8")
READINESS_H = (ROOT / "startup_readiness.h").read_text(encoding="utf-8")
WEB_UI = (ROOT / "web_ui.cpp").read_text(encoding="utf-8")
HTML = (ROOT / "webroot" / "index.html").read_text(encoding="utf-8")


class StartupTimingFixtureTest(unittest.TestCase):
    def test_fixed_45_second_sleep_is_removed(self):
        self.assertNotIn("kDefaultPostBootDelayMs", SOURCE)
        self.assertNotIn("DRMID_POST_BOOT_DELAY_MS", SOURCE)
        self.assertIn("wait_for_adaptive_startup_readiness", SOURCE)

    def test_three_minute_value_remains_only_the_boot_wait_timeout(self):
        self.assertIn("kDefaultBootWaitTimeoutMs = 180000", SOURCE)
        self.assertNotIn("deadline_ms = 180000", READINESS + READINESS_H)

    def test_adaptive_gate_has_short_stability_window_and_legacy_ceiling(self):
        self.assertIn("uint32_t poll_ms = 250", READINESS_H)
        self.assertIn("uint32_t stable_ms = 3000", READINESS_H)
        self.assertIn("uint32_t deadline_ms = 45000", READINESS_H)
        self.assertIn("deadline_fallback", SOURCE + READINESS + READINESS_H)

    def test_readiness_uses_services_process_identity_and_bounded_cpu(self):
        for marker in (
            '"init.svc.bootanim", "stopped"',
            '"dev.bootcomplete", "1"',
            '"sys.user.0.ce_available", "true"',
            '"init.svc.servicemanager", "running"',
            '"init.svc.mediadrm", "running"',
            '"init.svc.drm64", "running"',
            'name == "system_server"',
            'name == "surfaceflinger"',
            "start_time_ticks",
            "process_count",
            "max_cpu_permille",
        ):
            self.assertIn(marker, READINESS + READINESS_H)

    def test_diagnostic_readiness_overrides_are_bounded(self):
        for marker in (
            "DRMID_READY_POLL_MS",
            "DRMID_READY_STABLE_MS",
            "DRMID_READY_DEADLINE_MS",
            "DRMID_READY_CPU_PERMILLE",
            "bounded_environment_u32",
        ):
            self.assertIn(marker, READINESS)

    def test_readiness_chain_waits_for_boot_then_discovers_hal(self):
        boot = SOURCE.index('"sys.boot_completed"')
        adaptive = SOURCE.index("wait_for_adaptive_startup_readiness", boot)
        hal = SOURCE.index("discover_widevine_hal_identities", adaptive)
        self.assertLess(boot, adaptive)
        self.assertLess(adaptive, hal)
        self.assertNotIn("load_or_resolve_target_config", SOURCE)
        self.assertNotIn("kDefaultTargetWaitTimeoutMs", SOURCE)

    def test_webui_distinguishes_starting_daemon_from_missing_daemon(self):
        self.assertIn("daemon_lock_owner_alive", WEB_UI)
        self.assertIn('\\"stage\\":\\"daemon-starting\\"', WEB_UI)
        self.assertIn("守护进程已启动，等待稳定切入", HTML)
        self.assertIn("守护进程未连接", HTML)

    def test_parent_marks_detached_daemon_running_before_return(self):
        spawn = SOURCE.index("exec daemon spawned pid")
        running = SOURCE.index("ModuleRunState::Running", spawn)
        returned = SOURCE.index("return 0;", running)
        self.assertLess(spawn, running)
        self.assertLess(running, returned)


if __name__ == "__main__":
    unittest.main()
