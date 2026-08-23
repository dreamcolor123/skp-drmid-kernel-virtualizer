#!/usr/bin/env python3
"""Caller-global SMCInvoke classification and bounded-state fixtures."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "tee_hook_builder.cpp").read_text(encoding="utf-8")
HEADER = (ROOT / "tee_hook_builder.h").read_text(encoding="utf-8")
CONTEXT = (ROOT / "kernel_context.h").read_text(encoding="utf-8")
MODULE = (ROOT / "module_main.cpp").read_text(encoding="utf-8")


class TeeModel:
    def __init__(self) -> None:
        self.controllers: list[int] = []
        self.objects: list[int] = []
        self.fallback: dict[int, int] = {}

    @staticmethod
    def pattern(args: tuple[int, ...], expected: tuple[int, ...]) -> bool:
        return args == expected

    def add(self, table: list[int], value: int, limit: int) -> bool:
        if value in table:
            return True
        if len(table) == limit:
            return False
        table.append(value)
        return True

    def loader(self, firmware_match: bool, output: int) -> bool:
        return firmware_match and self.add(self.controllers, output, 16)

    def controller(self, owner: int, output: int) -> bool:
        return owner in self.controllers and self.add(self.objects, output, 32)

    def sequence(self, owner: int, op: int, args: tuple[int, ...]) -> None:
        transitions = {
            (16, (1, 2), None): 1,
            (0, (1, 2), 1): 2,
            (19, (1, 1, 1, 2), 2): 3,
            (20, (1, 2, 2, 2), 3): 4,
        }
        current = self.fallback.get(owner)
        next_state = transitions.get((op, args, current))
        if op == 16 and args == (1, 2):
            next_state = 1
        if next_state is not None:
            if owner in self.fallback or len(self.fallback) < 16:
                self.fallback[owner] = next_state
        elif owner in self.fallback:
            self.fallback.pop(owner)

    def op9(self, owner: int, length: int) -> bool:
        if self.fallback.get(owner) == 4:
            self.fallback.pop(owner)
            self.add(self.objects, owner, 32)
        return owner in self.objects and length == 32

    def free(self, owner: int) -> None:
        self.controllers = [x for x in self.controllers if x != owner]
        self.objects = [x for x in self.objects if x != owner]
        self.fallback.pop(owner, None)


class TeeGlobalBackendTest(unittest.TestCase):
    def test_primary_loader_controller_ta_chain_is_global(self) -> None:
        model = TeeModel()
        self.assertTrue(model.loader(True, 0x1000))
        self.assertTrue(model.controller(0x1000, 0x2000))
        for caller in (1000, 10000, 20000, 99999):
            del caller
            self.assertTrue(model.op9(0x2000, 32))

    def test_qms_same_shape_is_not_a_candidate(self) -> None:
        model = TeeModel()
        self.assertFalse(model.op9(0x9000, 32))
        self.assertFalse(model.loader(False, 0x9000))
        self.assertFalse(model.op9(0x9000, 32))

    def test_cached_loader_fallback_sequence_promotes_on_first_op9(self) -> None:
        model = TeeModel()
        owner = 0x3000
        for op, args in ((16, (1, 2)), (0, (1, 2)),
                         (19, (1, 1, 1, 2)), (20, (1, 2, 2, 2))):
            model.sequence(owner, op, args)
        self.assertTrue(model.op9(owner, 32))
        self.assertIn(owner, model.objects)
        self.assertTrue(model.op9(owner, 32))

    def test_fallback_sequence_is_consecutive_and_fail_closed(self) -> None:
        model = TeeModel()
        owner = 0x3800
        model.sequence(owner, 16, (1, 2))
        model.sequence(owner, 7, (2,))
        model.sequence(owner, 0, (1, 2))
        model.sequence(owner, 19, (1, 1, 1, 2))
        model.sequence(owner, 20, (1, 2, 2, 2))
        self.assertFalse(model.op9(owner, 32))

    def test_free_clears_address_before_reuse(self) -> None:
        model = TeeModel()
        model.loader(True, 0x1000)
        model.controller(0x1000, 0x2000)
        self.assertTrue(model.op9(0x2000, 32))
        model.free(0x2000)
        self.assertFalse(model.op9(0x2000, 32))

    def test_table_boundaries_and_lengths(self) -> None:
        model = TeeModel()
        for index in range(16):
            self.assertTrue(model.loader(True, 0x1000 + index * 8))
        self.assertFalse(model.loader(True, 0x5000))
        for index in range(32):
            self.assertTrue(model.add(model.objects, 0x8000 + index * 8, 32))
        self.assertFalse(model.add(model.objects, 0xA000, 32))
        for length in (31, 33):
            self.assertFalse(model.op9(0x8000, length))
        self.assertTrue(model.op9(0x8000, 32))

    def test_source_has_no_caller_scope_filter(self) -> None:
        for marker in (
            "target_euids", "cred_euid", "sender_euid",
            "get_task_struct_tgid_offset", "get_task_struct_cred_offset",
            "emit_hal_identity_gate",
        ):
            self.assertNotIn(marker, SOURCE)
        self.assertIn("caller-global", HEADER + SOURCE)
        self.assertIn("euid-filter=absent", MODULE)

    def test_hot_state_is_fixed_lock_free_and_no_dynamic_kernel_allocation(self) -> None:
        for marker in (
            "kTeeControllerObjectLimit = 16",
            "kTeeWidevineObjectLimit = 32",
            "kTeeFallbackStateLimit = 16",
            "a->casal", "emit_table_contains", "emit_fallback_consume_ready",
        ):
            self.assertIn(marker, CONTEXT + SOURCE)
        for marker in ("kmalloc", "kzalloc", "GFP_KERNEL"):
            self.assertNotIn(marker, SOURCE)

    def test_symbol_profile_and_reverse_uninstall_are_guarded(self) -> None:
        for marker in (
            '"si_object_do_invoke"', '"free_si_object"',
            "0xd503233fU", "0xd10343ffU",
            "session.tee_free_hook", "session.tee_invoke_hook",
        ):
            self.assertIn(marker, SOURCE)
        remove = SOURCE.index("KModErr remove_global_tee_hooks")
        free = SOURCE.index("uninstall_kernel_hook(session.tee_free_hook)", remove)
        invoke = SOURCE.index("uninstall_kernel_hook(session.tee_invoke_hook)", free)
        self.assertLess(free, invoke)

    def test_generated_tee_handlers_do_not_use_x18(self) -> None:
        executable = re.sub(r"/\*.*?\*/", "", SOURCE, flags=re.S)
        executable = re.sub(r"//.*", "", executable)
        self.assertNotRegex(executable, r"\b[wx]18\b")


if __name__ == "__main__":
    unittest.main()
