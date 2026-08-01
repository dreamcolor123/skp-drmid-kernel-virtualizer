"""Static/layout fixtures for ABI-14 bounded multi-EUID matching."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONTEXT = (ROOT / "kernel_context.h").read_text(encoding="utf-8")
BUILDER = (ROOT / "binder_hook_builder.cpp").read_text(encoding="utf-8")


def bounded_match(targets: list[int], euid: int) -> tuple[bool, int]:
    if not 1 <= len(targets) <= 32:
        return False, 0
    comparisons = 0
    for target in targets:
        comparisons += 1
        if target == 0:
            return False, comparisons
        if target == euid:
            return True, comparisons
    return False, comparisons


class MultiTargetAbiTest(unittest.TestCase):
    def test_context_abi_and_layout_are_explicit(self) -> None:
        for marker in (
            "kCounterContextAbi = 16",
            "kRuntimeTargetLimit = 32",
            "sizeof(RuntimeConfigSlot) == 232",
            "offsetof(RuntimeConfigSlot, target_euids) == 40",
            "offsetof(RuntimeConfigSlot, virtual_id) == 168",
            "offsetof(KernelCounterContext, config_slots) == 97240",
            "sizeof(KernelCounterContext) == 97704",
        ):
            self.assertIn(marker, CONTEXT)

    def test_hot_path_is_compile_time_bounded_after_candidate_guards(self) -> None:
        candidate = BUILDER.index("replacement_candidates")
        target_count = BUILDER.index("RuntimeConfigSlot, target_count", candidate)
        bounded_loop = BUILDER.index("index < kRuntimeTargetLimit", target_count)
        self.assertLess(candidate, target_count)
        self.assertLess(target_count, bounded_loop)
        self.assertIn("a->cbz(w13, rule_miss)", BUILDER)
        self.assertIn("a->b(CondCode::kEQ, rule_match)", BUILDER)

    def test_inactive_slot_write_precedes_release_publish(self) -> None:
        publish = BUILDER.index("KModErr publish_runtime_config")
        write = BUILDER.index("write_kernel_mem", publish)
        stlr = BUILDER.index("flip_runtime_config_slot", write)
        self.assertLess(write, stlr)
        self.assertIn("a->stlr(w10, ptr(x9))", BUILDER)

    def test_three_targets_and_100_non_targets(self) -> None:
        targets = [10373, 10455, 10500]
        for target in targets:
            for _ in range(100):
                matched, comparisons = bounded_match(targets, target)
                self.assertTrue(matched)
                self.assertLessEqual(comparisons, 32)
        for euid in range(20000, 20100):
            matched, comparisons = bounded_match(targets, euid)
            self.assertFalse(matched)
            self.assertEqual(comparisons, 3)

    def test_maximum_non_target_cost_is_32_comparisons(self) -> None:
        targets = list(range(10001, 10033))
        matched, comparisons = bounded_match(targets, 99999)
        self.assertFalse(matched)
        self.assertEqual(comparisons, 32)


if __name__ == "__main__":
    unittest.main()
