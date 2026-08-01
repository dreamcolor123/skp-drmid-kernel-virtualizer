#!/usr/bin/env python3
"""Regression fixtures for Binder-hook shadow-stack and lock liveness."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
BUILDER = (ROOT / "binder_hook_builder.cpp").read_text(encoding="utf-8")
CONTEXT = (ROOT / "kernel_context.h").read_text(encoding="utf-8")
TRY_COUNT = 8


def without_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"//.*", "", source)


class BoundedTryLock:
    def __init__(self) -> None:
        self.state = 0
        self.drops = 0

    def acquire(self) -> bool:
        for _ in range(TRY_COUNT):
            if self.state == 0:
                self.state = 1
                return True
        self.drops += 1
        return False

    def release(self) -> None:
        self.state = 0


class HookLockSafetyTest(unittest.TestCase):
    def test_generated_handler_never_uses_platform_x18(self) -> None:
        executable_source = without_comments(BUILDER)
        self.assertNotRegex(executable_source, r"\bx18\b")
        self.assertNotRegex(executable_source, r"\bw18\b")
        self.assertIn("CONFIG_SHADOW_CALL_STACK", BUILDER)

    def test_lock_acquisition_is_bounded_and_fail_open(self) -> None:
        for marker in (
            "kMapLockTryCount = 8",
            "emit_bounded_lock_acquire",
            "a->ldaxr(x12, ptr(x9))",
            "a->stxr(w13, x10, ptr(x9))",
            "a->clrex(15)",
            "a->subs(w11, w11, 1)",
            "a->b(failure)",
            "a->stlr(xzr, ptr(x9))",
        ):
            self.assertIn(marker, BUILDER)
        for legacy in (
            "pending_lock_next",
            "pending_lock_serving",
            "plugin_lock_next",
            "plugin_lock_serving",
        ):
            self.assertNotIn(legacy, BUILDER + CONTEXT)

    def test_stuck_owner_drops_correlation_instead_of_waiting(self) -> None:
        lock = BoundedTryLock()
        lock.state = 1
        self.assertFalse(lock.acquire())
        self.assertEqual(lock.state, 1)
        self.assertEqual(lock.drops, 1)

    def test_normal_owner_releases_and_next_caller_progresses(self) -> None:
        lock = BoundedTryLock()
        self.assertTrue(lock.acquire())
        self.assertEqual(lock.state, 1)
        lock.release()
        self.assertTrue(lock.acquire())
        self.assertEqual(lock.drops, 0)

    def test_context_versions_new_lock_semantics_without_layout_growth(self) -> None:
        for marker in (
            "kCounterContextAbi = 16",
            "pending_lock_state",
            "pending_lock_drops",
            "plugin_lock_state",
            "plugin_lock_drops",
            "sizeof(KernelCounterContext) == 97704",
        ):
            self.assertIn(marker, CONTEXT)


if __name__ == "__main__":
    unittest.main()
