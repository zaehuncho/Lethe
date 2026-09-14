"""Differential coverage for bounded 32/64-bit SHLD and SHRD lifting."""

from __future__ import annotations

import random

import pytest


pytest.importorskip("iced_x86")
pytest.importorskip("keystone")
pytest.importorskip("unicorn")

from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # noqa: E402
from lifter import oracle  # noqa: E402
from lifter import x64_lifter as lifter  # noqa: E402


_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_ALL_FLAGS = ("CF", "PF", "ZF", "SF", "OF")
_SHIFT_FLAGS = ("CF", "PF", "ZF", "SF")


def _asm(source: str) -> bytes:
    encoded, _ = _KS.asm(source, addr=oracle.BASE)
    return bytes(encoded)


def _init(**registers: int) -> list[int]:
    values = [0] * 16
    for name, value in registers.items():
        values[lifter.GPR_NAMES.index(name)] = value
    return values


@pytest.mark.parametrize(
    ("source", "initial"),
    (
        (
            "shld rax, rbx, 1",
            _init(rax=0x8000000000000000, rbx=0x0000000000000001),
        ),
        (
            "shrd rax, rbx, 1",
            _init(rax=0x0000000000000000, rbx=0x0000000000000001),
        ),
        (
            "shld eax, ebx, 1",
            _init(rax=0xDEADBEEF80000000, rbx=0x0000000000000001),
        ),
        (
            "shrd eax, ebx, 1",
            _init(rax=0xDEADBEEF00000001, rbx=0x0000000000000001),
        ),
    ),
)
def test_count_one_matches_all_defined_flags(source: str, initial: list[int]) -> None:
    oracle.check(_asm(source), init=initial, flags=_ALL_FLAGS)


@pytest.mark.parametrize(
    "source",
    (
        "cmp r14, r15; shld eax, ebx, 0",
        "cmp r14, r15; shrd eax, ebx, 32",
        "cmp r14, r15; shld rax, rbx, 64",
        "cmp r14, r15; shrd rax, rbx, cl",
    ),
)
def test_zero_masked_count_preserves_flags_and_32bit_write_rules(source: str) -> None:
    oracle.check(
        _asm(source),
        init=_init(
            rax=0xDEADBEEF11223344,
            rbx=0x9988776655443322,
            rcx=0x40,
            r14=1,
            r15=2,
        ),
        flags=_ALL_FLAGS,
    )


@pytest.mark.parametrize(
    ("source", "initial", "memory"),
    (
        (
            "shld dword ptr [rdi+4], eax, 13",
            _init(rax=0xAABBCCDD, rdi=oracle.MEM_BASE),
            bytes.fromhex("00112233 44556677 8899aabb ccddeeff"),
        ),
        (
            "shrd qword ptr [rdi], rdi, cl",
            _init(rcx=7, rdi=oracle.MEM_BASE),
            bytes.fromhex("efcdab8967452301 8877665544332211"),
        ),
    ),
)
def test_memory_destinations_preserve_evaluation_order(
    source: str, initial: list[int], memory: bytes
) -> None:
    oracle.check(
        _asm(source),
        init=initial,
        flags=_SHIFT_FLAGS,
        mem=memory,
    )


def test_randomized_register_double_shifts_match_unicorn() -> None:
    rng = random.Random(0x5A1D_5A1D)
    registers = {
        32: (("eax", "ebx"), ("r8d", "r9d"), ("ecx", "edx")),
        64: (("rax", "rbx"), ("r8", "r9"), ("rcx", "rdx")),
    }
    for width, pairs in registers.items():
        for _ in range(120):
            mnemonic = rng.choice(("shld", "shrd"))
            destination, source = rng.choice(pairs)
            count = rng.choice((0, 1, 2, width - 1, width, width + 1, 255))
            initial = [rng.getrandbits(64) for _ in range(16)]
            masked = count & (width - 1)
            flags = _ALL_FLAGS if masked in (0, 1) else _SHIFT_FLAGS
            oracle.check(
                _asm(f"{mnemonic} {destination}, {source}, {count}"),
                init=initial,
                flags=flags,
            )


def test_randomized_cl_double_shifts_match_unicorn() -> None:
    rng = random.Random(0xC1_5A1D)
    for width, destination, source in (
        (32, "eax", "ebx"),
        (64, "rax", "rbx"),
        (32, "ecx", "edx"),
        (64, "rcx", "rdx"),
    ):
        for _ in range(80):
            mnemonic = rng.choice(("shld", "shrd"))
            initial = [rng.getrandbits(64) for _ in range(16)]
            masked = initial[lifter.GPR_NAMES.index("rcx")] & (width - 1)
            flags = _ALL_FLAGS if masked in (0, 1) else _SHIFT_FLAGS
            oracle.check(
                _asm(f"{mnemonic} {destination}, {source}, cl"),
                init=initial,
                flags=flags,
            )


@pytest.mark.parametrize(
    ("source", "reason"),
    (
        ("shld ax, bx, 1", "32/64-bit"),
        ("shrd word ptr [rdi], ax, cl", "32/64-bit"),
        ("lock shld dword ptr [rdi], eax, 1", "undecodable"),
        ("shrd qword ptr [rip], rax, 1", "RIP-relative"),
    ),
)
def test_unmodeled_double_shift_forms_fail_closed(source: str, reason: str) -> None:
    with pytest.raises(lifter.LiftUnsupported, match=reason):
        lifter.lift_function(_asm(source), base=oracle.BASE)


@pytest.mark.parametrize(
    "source",
    (
        "div bl",
        "div bx",
        "div ebx",
        "div rbx",
        "idiv bl",
        "idiv bx",
        "idiv ebx",
        "idiv rbx",
        "div qword ptr [rcx]",
        "idiv qword ptr [rcx]",
    ),
)
def test_division_still_requires_architectural_divide_error(source: str) -> None:
    with pytest.raises(lifter.LiftUnsupported, match="architectural #DE"):
        lifter.lift_function(_asm(source), base=oracle.BASE)
