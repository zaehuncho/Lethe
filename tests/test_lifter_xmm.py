"""Cut 12: legacy register-only XMM moves and bitwise XOR."""
from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lifter"))
sys.path.insert(0, str(ROOT / "daedalus"))

pytest.importorskip("iced_x86")
pytest.importorskip("keystone")
pytest.importorskip("unicorn")

import oracle  # noqa: E402
import x64_lifter as lifter  # noqa: E402
from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # noqa: E402


_KS = Ks(KS_ARCH_X86, KS_MODE_64)


def _asm(source: str) -> bytes:
    encoded, _ = _KS.asm(source, addr=oracle.BASE)
    return bytes(encoded)


def _gprs(**values: int) -> list[int]:
    result = [0] * 16
    for name, value in values.items():
        result[lifter.GPR_NAMES.index(name)] = value
    return result


def _xmms(**values: int) -> list[int]:
    result = [0] * 16
    for name, value in values.items():
        result[lifter.XMM_NAMES.index(name)] = value
    return result


@pytest.mark.parametrize(
    "instruction",
    [
        "movaps xmm0, xmm15",
        "movups xmm15, xmm0",
        "movdqa xmm7, xmm8",
        "movdqu xmm8, xmm7",
    ],
)
def test_full_register_moves_match_unicorn(instruction: str) -> None:
    initial = [
        ((index + 1) << 120) | (0x0102030405060708 * (index + 1))
        for index in range(16)
    ]
    oracle.check_xmm(_asm(instruction), xmm_init=initial)


@pytest.mark.parametrize("instruction", ["pxor", "xorps", "xorpd"])
def test_register_xor_matches_unicorn_and_self_xor_clears(
    instruction: str,
) -> None:
    initial = _xmms(
        xmm0=0xFFEEDDCCBBAA99887766554433221100,
        xmm15=0x0123456789ABCDEFFEDCBA9876543210,
    )
    oracle.check_xmm(
        _asm(f"{instruction} xmm0, xmm15; {instruction} xmm15, xmm15"),
        xmm_init=initial,
    )


def test_xmm_operations_preserve_nonzero_integer_flags() -> None:
    initial = _gprs(rax=1, rbx=2)
    xmm_init = _xmms(
        xmm0=0xFFEEDDCCBBAA99887766554433221100,
        xmm1=0x0123456789ABCDEFFEDCBA9876543210,
    )
    oracle.check_xmm(
        _asm("cmp rax, rbx; pxor xmm0, xmm1; movaps xmm1, xmm0"),
        init=initial,
        xmm_init=xmm_init,
    )


@pytest.mark.parametrize(
    ("instruction", "gprs", "xmms"),
    [
        (
            "movd xmm0, eax",
            _gprs(rax=0xFFEEDDCC89ABCDEF),
            _xmms(xmm0=(1 << 128) - 1),
        ),
        (
            "movd r15d, xmm14",
            _gprs(r15=(1 << 64) - 1),
            _xmms(xmm14=0xFFEEDDCCBBAA99887766554489ABCDEF),
        ),
        (
            "movq xmm15, rax",
            _gprs(rax=0xFFEEDDCC89ABCDEF),
            _xmms(xmm15=(1 << 128) - 1),
        ),
        (
            "movq r15, xmm14",
            _gprs(r15=0x1111111111111111),
            _xmms(xmm14=0xFFEEDDCCBBAA99887766554433221100),
        ),
        (
            "movq xmm0, xmm15",
            _gprs(),
            _xmms(
                xmm0=(1 << 128) - 1,
                xmm15=0xFFEEDDCCBBAA99887766554433221100,
            ),
        ),
    ],
)
def test_movd_movq_zeroing_and_gpr_widths_match_unicorn(
    instruction: str, gprs: list[int], xmms: list[int]
) -> None:
    oracle.check_xmm(_asm(instruction), init=gprs, xmm_init=xmms)


def test_deterministic_register_sequence_fuzz_matches_unicorn() -> None:
    rng = random.Random(0x584D4D12)
    moves = ("movaps", "movups", "movdqa", "movdqu")
    xors = ("pxor", "xorps", "xorpd")
    for _ in range(128):
        lines = []
        for _ in range(rng.randint(1, 12)):
            destination = rng.randrange(16)
            source = rng.randrange(16)
            operation = rng.choice(moves + xors)
            lines.append(f"{operation} xmm{destination}, xmm{source}")
        initial = [rng.getrandbits(128) for _ in range(16)]
        oracle.check_xmm(_asm("; ".join(lines)), xmm_init=initial)


@pytest.mark.parametrize(
    "instruction",
    [
        "movd xmm0, dword ptr [rax]",
        "movd dword ptr [rax], xmm0",
        "movq xmm0, qword ptr [rax]",
        "movq qword ptr [rax], xmm0",
        "movaps xmm0, xmmword ptr [rax]",
        "movups xmmword ptr [rax], xmm0",
        "movdqa xmm0, xmmword ptr [rax]",
        "movdqu xmmword ptr [rax], xmm0",
        "pxor xmm0, xmmword ptr [rax]",
        "xorps xmm0, xmmword ptr [rax]",
        "xorpd xmm0, xmmword ptr [rax]",
    ],
)
def test_xmm_memory_operands_fail_closed(instruction: str) -> None:
    with pytest.raises(lifter.LiftUnsupported, match="register-only"):
        lifter.lift_function(_asm(instruction))


@pytest.mark.parametrize(
    "instruction",
    [
        "vmovaps xmm0, xmm1",
        "vmovdqa xmm0, xmm1",
        "vpxor xmm0, xmm1, xmm2",
        "vxorps xmm0, xmm1, xmm2",
        "vmovaps ymm0, ymm1",
    ],
)
def test_vex_and_ymm_forms_fail_closed(instruction: str) -> None:
    with pytest.raises(lifter.LiftUnsupported):
        lifter.lift_function(_asm(instruction))


@pytest.mark.parametrize(
    "code",
    [
        bytes.fromhex("62f17c4828c1"),  # vmovaps zmm0,zmm1
        bytes.fromhex("62f17548efc2"),  # vpxord zmm0,zmm1,zmm2
    ],
)
def test_evex_and_zmm_forms_fail_closed(code: bytes) -> None:
    with pytest.raises(lifter.LiftUnsupported):
        lifter.lift_function(code)


@pytest.mark.parametrize(
    "instruction",
    [
        "addps xmm0, xmm1",
        "addsd xmm0, xmm1",
        "mulss xmm0, xmm1",
        "divpd xmm0, xmm1",
    ],
)
def test_simd_fp_arithmetic_fails_closed(instruction: str) -> None:
    with pytest.raises(lifter.LiftUnsupported):
        lifter.lift_function(_asm(instruction))
