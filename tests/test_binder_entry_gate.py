#!/usr/bin/env python3
"""Fixtures for the low-cost binder_ioctl entry gate."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
HOOK = (ROOT / "binder_hook_builder.cpp").read_text(encoding="utf-8")
CONTEXT = (ROOT / "kernel_context.h").read_text(encoding="utf-8")
ANDROID_APP_UID_START = 10000


def should_track(
    *,
    tgid: int,
    euid: int,
    installer_tgid: int,
    targets: tuple[int, ...],
) -> bool:
    return (
        tgid == installer_tgid
        or euid in targets
        or euid >= ANDROID_APP_UID_START
    )


class BinderEntryGateTest(unittest.TestCase):
    def test_core_service_uids_take_fast_bypass(self) -> None:
        for euid in (0, 1000, 1001, 1013, 1041, 2000, 9999):
            with self.subTest(euid=euid):
                self.assertFalse(
                    should_track(
                        tgid=5000,
                        euid=euid,
                        installer_tgid=4000,
                        targets=(10324, 10360),
                    )
                )

    def test_installer_selftest_and_selected_low_uid_remain_tracked(self) -> None:
        self.assertTrue(
            should_track(
                tgid=4000,
                euid=0,
                installer_tgid=4000,
                targets=(10324,),
            )
        )
        self.assertTrue(
            should_track(
                tgid=5000,
                euid=1000,
                installer_tgid=4000,
                targets=(1000, 10324),
            )
        )

    def test_all_android_application_uids_preserve_hot_add_tracking(self) -> None:
        for euid in (10000, 10324, 19999, 99000, 1010324):
            with self.subTest(euid=euid):
                self.assertTrue(
                    should_track(
                        tgid=5000,
                        euid=euid,
                        installer_tgid=4000,
                        targets=(),
                    )
                )

    def test_gate_precedes_every_global_counter_copy_and_stack_frame(self) -> None:
        builder = HOOK[HOOK.index("KModErr build_readonly_parser_handler") :]
        gate = builder.index("emit_package_uid_or_target_gate(")
        bypass_call = builder.index("kernel_module::arm64_emit_call_original(a);")
        active_counter = builder.index("offsetof(KernelCounterContext, active_calls)")
        stack_frame = builder.index("a->sub(sp, sp, kLocalBytes)")
        header_copy = builder.index("sizeof(binder_write_read)")
        self.assertLess(gate, bypass_call)
        self.assertLess(bypass_call, active_counter)
        self.assertLess(bypass_call, stack_frame)
        self.assertLess(bypass_call, header_copy)
        self.assertIn("without touching counters", HOOK)

    def test_gate_is_bounded_and_context_semantics_are_versioned(self) -> None:
        self.assertIn("kAndroidAppUidStart = 10000", HOOK)
        self.assertIn(
            "aarch64_asm_mov_w(a, w12, kAndroidAppUidStart)", HOOK
        )
        self.assertIn("a->cmp(w11, w12)", HOOK)
        self.assertNotIn("a->cmp(w11, kAndroidAppUidStart)", HOOK)
        self.assertIn(
            "for (uint32_t index = 0; index < kRuntimeTargetLimit; ++index)",
            HOOK,
        )
        self.assertIn("a->b(CondCode::kLO, app_uid_check)", HOOK)
        self.assertIn("kCounterContextAbi = 17", CONTEXT)
        self.assertIn("sizeof(KernelCounterContext) == 97704", CONTEXT)


if __name__ == "__main__":
    unittest.main()
