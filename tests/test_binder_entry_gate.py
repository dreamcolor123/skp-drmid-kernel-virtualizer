#!/usr/bin/env python3
"""Fixtures for the installer/Widevine-HAL binder_ioctl entry gate."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
HOOK = (ROOT / "binder_hook_builder.cpp").read_text(encoding="utf-8")
CONTEXT = (ROOT / "kernel_context.h").read_text(encoding="utf-8")


def valid_identities(values: tuple[int, ...]) -> bool:
    return len(values) <= 4 and all(values) and list(values) == sorted(set(values))


def should_track(tgid: int, installer_tgid: int, identities: tuple[int, ...]) -> bool:
    return tgid == installer_tgid or (valid_identities(identities) and tgid in identities)


class BinderEntryGateTest(unittest.TestCase):
    def test_only_installer_and_active_hal_tgids_are_tracked(self) -> None:
        identities = (2216, 2401)
        self.assertTrue(should_track(4000, 4000, identities))
        self.assertTrue(should_track(2216, 4000, identities))
        self.assertFalse(should_track(10373, 4000, identities))
        self.assertFalse(should_track(1000, 4000, identities))

    def test_empty_or_invalid_identity_set_fails_closed(self) -> None:
        for values in ((), (0,), (2, 1), (1, 1), (1, 2, 3, 4, 5)):
            self.assertFalse(should_track(2216, 4000, values))

    def test_identity_flip_removes_old_pid_without_hook_reinstall(self) -> None:
        self.assertTrue(should_track(2216, 4000, (2216,)))
        self.assertFalse(should_track(2216, 4000, (3300,)))
        self.assertTrue(should_track(3300, 4000, (3300,)))

    def test_gate_precedes_counters_stack_and_user_copy(self) -> None:
        builder = HOOK[HOOK.index("KModErr build_readonly_parser_handler") :]
        gate = builder.index("emit_hal_identity_gate(")
        bypass = builder.index("kernel_module::arm64_emit_call_original(a);")
        counter = builder.index("offsetof(KernelCounterContext, active_calls)")
        stack = builder.index("a->sub(sp, sp, kLocalBytes)")
        self.assertLess(gate, bypass)
        self.assertLess(bypass, counter)
        self.assertLess(bypass, stack)

    def test_gate_uses_acquire_slot_and_fixed_four_way_bound(self) -> None:
        for marker in (
            "a->ldar(w13, ptr(x12))",
            "for (uint32_t index = 0; index < kHalIdentityLimit; ++index)",
            "offsetof(HalIdentitySet, tgids)",
            "kCounterContextAbi = 20",
            "kHalIdentityLimit = 4",
        ):
            self.assertIn(marker, HOOK + CONTEXT)
        for retired in ("kAndroidAppUidStart", "cred_euid", "target_euids"):
            self.assertNotIn(retired, HOOK)


if __name__ == "__main__":
    unittest.main()
