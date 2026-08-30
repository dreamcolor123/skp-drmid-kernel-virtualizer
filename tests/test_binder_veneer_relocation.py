"""Offline model for the SDK 4.5.4 one-instruction Binder veneer gate."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RESOLVER = (ROOT / "binder_ioctl_resolver.cpp").read_text(encoding="utf-8")
HEADER = (ROOT / "binder_ioctl_resolver.h").read_text(encoding="utf-8")

BTI_C = 0xD503245F
PACIASP = 0xD503233F
SUB_SP_0X80 = 0xD10203FF
STP_FP_LR = 0xA9047BFD
NOP = 0xD503201F


def encode_b(branch_pc: int, target: int) -> int:
    delta = target - branch_pc
    if delta % 4:
        raise ValueError("unaligned branch target")
    immediate = delta // 4
    if not -(1 << 25) <= immediate < (1 << 25):
        raise ValueError("branch target outside imm26 range")
    return 0x14000000 | (immediate & 0x03FFFFFF)


def decode_b(word: int) -> int | None:
    if (word & 0x7C000000) != 0x14000000:
        return None
    immediate = word & 0x03FFFFFF
    if immediate & (1 << 25):
        immediate -= 1 << 26
    displacement = immediate << 2
    return displacement if displacement else None


def kernel_pointer(value: int) -> bool:
    return value != 0 and value % 4 == 0 and (value & (1 << 63)) != 0


def target_semantic(words: tuple[int, ...] | None) -> bool:
    if words is None:
        return False
    words = words + (0,) * (4 - len(words))
    return (
        words[0] in (PACIASP, SUB_SP_0X80)
        and SUB_SP_0X80 in words[:3]
        and STP_FP_LR in words[:4]
    )


def hookable_veneer(entry: int,
                     words: tuple[int, ...],
                     target_words: tuple[int, ...] | None,
                     *,
                     target_in_core_text: bool = True) -> bool:
    words = words + (0,) * (4 - len(words))
    index = 0
    if words[index] in (BTI_C, 0xD503249F, 0xD50324DF):
        index += 1
    if words[index] in (PACIASP, 0xD503237F):
        index += 1
    # The SDK overwrites word zero.  A direct-B first word would require
    # explicit PC-relative relocation support and therefore stays closed.
    if index == 0 or index >= 4:
        return False
    if words[0] not in (BTI_C, 0xD503249F, 0xD50324DF,
                        PACIASP, 0xD503237F):
        return False
    displacement = decode_b(words[index])
    if displacement is None or displacement <= 0:
        return False
    branch_pc = entry + index * 4
    target = (branch_pc + displacement) & 0xFFFFFFFFFFFFFFFF
    return (
        target > entry
        and kernel_pointer(target)
        and target_in_core_text
        and target_semantic(target_words)
    )


class BinderVeneerRelocationTests(unittest.TestCase):
    ENTRY = 0xFFFFFFE920000000
    TARGET = ENTRY + 0x12000
    TARGET_PROLOGUE = (PACIASP, SUB_SP_0X80, STP_FP_LR, NOP)

    def test_pac_then_forward_branch_is_hookable(self) -> None:
        words = (PACIASP, encode_b(self.ENTRY + 4, self.TARGET), NOP, NOP)
        self.assertTrue(hookable_veneer(self.ENTRY, words, self.TARGET_PROLOGUE))

    def test_bti_pac_then_forward_branch_is_hookable(self) -> None:
        words = (
            BTI_C,
            PACIASP,
            encode_b(self.ENTRY + 8, self.TARGET),
            NOP,
        )
        self.assertTrue(hookable_veneer(self.ENTRY, words, self.TARGET_PROLOGUE))

    def test_direct_branch_at_overwritten_word_is_rejected(self) -> None:
        words = (encode_b(self.ENTRY, self.TARGET), NOP, NOP, NOP)
        self.assertFalse(hookable_veneer(self.ENTRY, words, self.TARGET_PROLOGUE))

    def test_backward_branch_is_rejected(self) -> None:
        words = (PACIASP, encode_b(self.ENTRY + 4, self.ENTRY - 0x1000), NOP, NOP)
        self.assertFalse(hookable_veneer(self.ENTRY, words, self.TARGET_PROLOGUE))

    def test_non_kernel_target_is_rejected(self) -> None:
        boundary_entry = 0xFFFFFFFFFFFFF000
        wrapped_target = boundary_entry + 0x2000
        words = (
            PACIASP,
            encode_b(boundary_entry + 4, wrapped_target),
            NOP,
            NOP,
        )
        self.assertFalse(
            hookable_veneer(boundary_entry, words, self.TARGET_PROLOGUE)
        )

    def test_failed_target_read_is_rejected(self) -> None:
        words = (PACIASP, encode_b(self.ENTRY + 4, self.TARGET), NOP, NOP)
        self.assertFalse(hookable_veneer(self.ENTRY, words, None))

    def test_invalid_target_prologue_is_rejected(self) -> None:
        words = (PACIASP, encode_b(self.ENTRY + 4, self.TARGET), NOP, NOP)
        self.assertFalse(hookable_veneer(self.ENTRY, words, (NOP,) * 4))

    def test_allocated_sdk_trampoline_target_is_rejected(self) -> None:
        words = (PACIASP, encode_b(self.ENTRY + 4, self.TARGET), NOP, NOP)
        self.assertFalse(
            hookable_veneer(
                self.ENTRY,
                words,
                self.TARGET_PROLOGUE,
                target_in_core_text=False,
            )
        )

    def test_source_has_separate_hook_site_and_target_gates(self) -> None:
        production = RESOLVER + HEADER
        for marker in (
            "classify_single_instruction_hook_site",
            "classify_hookable_entry",
            "branch_index == 0",
            "!address_in_core_text(target)",
            "kEntryHookSiteBti",
            "kEntryHookSitePac",
            "kEntryHookSiteFrame",
            "one-instruction",
        ):
            self.assertIn(marker, production)


if __name__ == "__main__":
    unittest.main()
