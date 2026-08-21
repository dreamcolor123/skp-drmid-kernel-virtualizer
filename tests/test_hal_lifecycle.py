#!/usr/bin/env python3
"""State-model fixtures for fail-closed HAL exit and hot rediscovery."""

from dataclasses import dataclass
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "control_ipc.cpp").read_text(encoding="utf-8")


@dataclass
class Monitor:
    identities: tuple[int, ...] = ()
    identity_generation: int = 1
    config_generation: int = 7
    backend: str = "waiting"
    retry_ms: int = 50
    restarts: int = 0

    def adopt(self, identities: tuple[int, ...], pidfd: bool = True) -> None:
        assert len(identities) <= 4 and all(identities)
        assert identities == tuple(sorted(set(identities)))
        if identities != self.identities:
            self.identity_generation += 1
            self.identities = identities
        self.backend = "pidfd" if pidfd else "procfs"
        self.retry_ms = 50

    def exit(self) -> None:
        if self.identities:
            self.identity_generation += 1
            self.identities = ()
            self.restarts += 1
        self.backend = "waiting"
        self.retry_ms = 50

    def miss(self) -> None:
        self.retry_ms = min(self.retry_ms * 2, 2000)


class HalLifecycleTest(unittest.TestCase):
    def test_exit_publishes_empty_before_new_identity(self) -> None:
        monitor = Monitor((2216,), 3, 9, "pidfd")
        monitor.exit()
        self.assertEqual((monitor.identities, monitor.identity_generation), ((), 4))
        monitor.adopt((3300,))
        self.assertEqual((monitor.identities, monitor.identity_generation), ((3300,), 5))

    def test_hal_restart_does_not_rotate_runtime_configuration(self) -> None:
        monitor = Monitor((2216,), 3, 9, "pidfd")
        monitor.exit()
        monitor.adopt((3300,))
        self.assertEqual(monitor.config_generation, 9)
        self.assertEqual(monitor.restarts, 1)

    def test_missing_backoff_is_bounded(self) -> None:
        monitor = Monitor()
        observed = []
        for _ in range(8):
            observed.append(monitor.retry_ms)
            monitor.miss()
        self.assertEqual(observed, [50, 100, 200, 400, 800, 1600, 2000, 2000])

    def test_stable_pidfd_backend_has_no_timer(self) -> None:
        self.assertIn("int lifecycle_timeout_ms = -1", SOURCE)
        self.assertIn("HalMonitorBackend::kPidfd", SOURCE)
        self.assertIn("descriptors.push_back({pidfd, POLLIN, 0})", SOURCE)

    def test_source_clears_on_pidfd_event_and_on_shutdown(self) -> None:
        event = SOURCE.index("if (pidfd_event)")
        self.assertIn("clear_monitored_identities", SOURCE[event:])
        shutdown = SOURCE.rindex("const KModErr clear_err = clear_monitored_identities")
        self.assertGreater(shutdown, event)

    def test_procfs_discovery_error_clears_stale_identity(self) -> None:
        failure = SOURCE.index("if (is_failed(discover_err))")
        clear = SOURCE.index("clear_monitored_identities", failure)
        retry = SOURCE.index("hal_monitor.retry_ms", clear)
        self.assertLess(clear, retry)

    def test_procfs_fallback_is_explicit_and_low_frequency(self) -> None:
        self.assertIn("kHalProcFallbackPollMs = 5000", SOURCE)
        self.assertIn('"procfs-fallback"', SOURCE)
        self.assertIn("hal_monitor_backend", SOURCE)
        self.assertIn("hal_monitor_wakeups", SOURCE)


if __name__ == "__main__":
    unittest.main()
