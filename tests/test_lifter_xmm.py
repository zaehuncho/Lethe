"""Legacy XMM register operations and exact unaligned memory transfers."""
from __future__ import annotations

import random
import struct
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
import daedalus_asm  # noqa: E402
from daedalus_ref import DaedalusError, RefVM  # noqa: E402
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
        "movaps xmm0, xmmword ptr [rax]",
        "movaps xmmword ptr [rax], xmm0",
        "movdqa xmm0, xmmword ptr [rax]",
        "movdqa xmmword ptr [rax], xmm0",
        "pxor xmm0, xmmword ptr [rax]",
        "xorps xmm0, xmmword ptr [rax]",
        "xorpd xmm0, xmmword ptr [rax]",
    ],
)
def test_unmodeled_xmm_memory_operands_fail_closed(instruction: str) -> None:
    with pytest.raises(lifter.LiftUnsupported):
        lifter.lift_function(_asm(instruction))


@pytest.mark.parametrize(
    "instruction",
    [
        "movd xmm0, dword ptr [rax + 3]",
        "movd dword ptr [rax + 7], xmm15",
        "movq xmm15, qword ptr [rax + 5]",
        "movq qword ptr [rax + 9], xmm0",
        "movups xmm0, xmmword ptr [rax + 1]",
        "movups xmmword ptr [rax + 3], xmm15",
        "movdqu xmm15, xmmword ptr [rax + 5]",
        "movdqu xmmword ptr [rax + 7], xmm0",
    ],
)
def test_exact_memory_transfer_forms_match_unicorn(instruction: str) -> None:
    memory = bytearray((index * 29 + 7) & 0xFF for index in range(256))
    oracle.check_xmm(
        _asm(instruction),
        init=_gprs(rax=oracle.MEM_BASE),
        xmm_init=_xmms(
            xmm0=0x00112233445566778899AABBCCDDEEFF,
            xmm15=0xFFEEDDCCBBAA99887766554433221100,
        ),
        mem=memory,
    )


@pytest.mark.parametrize("mnemonic", ["movups", "movdqu"])
@pytest.mark.parametrize("store", [False, True], ids=["load", "store"])
def test_randomized_unaligned_128_bit_transfers_match_unicorn(
    mnemonic: str, store: bool
) -> None:
    rng = random.Random(0x584D4D1300 + store + (mnemonic == "movdqu") * 2)
    for _ in range(96):
        offset = rng.randrange(1, 224)
        destination = rng.randrange(16)
        source = rng.randrange(16)
        memory = bytearray(rng.getrandbits(8) for _ in range(256))
        xmms = [rng.getrandbits(128) for _ in range(16)]
        if store:
            instruction = (
                f"{mnemonic} xmmword ptr [rax + {offset}], xmm{source}"
            )
        else:
            instruction = (
                f"{mnemonic} xmm{destination}, xmmword ptr [rax + {offset}]"
            )
        oracle.check_xmm(
            _asm(instruction),
            init=_gprs(rax=oracle.MEM_BASE),
            xmm_init=xmms,
            mem=memory,
        )


def test_unaligned_128_store_uses_one_atomic_vm_store_operation() -> None:
    code = _asm("movdqu xmmword ptr [rax + 1], xmm15")
    assembly = lifter.lift_function(code)
    assert assembly.count("store128") == 1

    blob = daedalus_asm.assemble(assembly)
    data_size = struct.unpack_from("<H", blob, 0)[0]
    memory = bytes.fromhex("a5" * 16)
    vm = RefVM(
        blob[2 + data_size:],
        blob[2:2 + data_size],
        mem=memory,
        mem_base=oracle.MEM_BASE,
    )
    vm.locals[0:8] = oracle.MEM_BASE.to_bytes(8, "little")
    xmm = 0x00112233445566778899AABBCCDDEEFF
    offset = lifter.XMM_OFF[lifter.Register.XMM15]
    vm.locals[offset:offset + 16] = xmm.to_bytes(16, "little")
    with pytest.raises(DaedalusError, match="mem OOB"):
        vm.run()
    assert bytes(vm.mem) == memory


@pytest.mark.parametrize("mnemonic,width", [("movd", 4), ("movq", 8)])
@pytest.mark.parametrize("store", [False, True], ids=["load", "store"])
def test_randomized_scalar_xmm_memory_transfers_match_unicorn(
    mnemonic: str, width: int, store: bool
) -> None:
    rng = random.Random(0x584D4D1340 + width + store)
    for _ in range(96):
        base_offset = rng.randrange(0, 32)
        index = rng.randrange(0, 32)
        displacement = rng.randrange(0, 32)
        address = base_offset + index * 4 + displacement
        memory = bytearray(rng.getrandbits(8) for _ in range(256))
        xmms = [rng.getrandbits(128) for _ in range(16)]
        xmm = rng.randrange(16)
        pointer = "dword" if width == 4 else "qword"
        if store:
            instruction = (
                f"{mnemonic} {pointer} ptr [rax + rcx*4 + {displacement}], "
                f"xmm{xmm}"
            )
        else:
            instruction = (
                f"{mnemonic} xmm{xmm}, {pointer} ptr "
                f"[rax + rcx*4 + {displacement}]"
            )
        oracle.check_xmm(
            _asm(instruction),
            init=_gprs(rax=oracle.MEM_BASE + base_offset, rcx=index),
            xmm_init=xmms,
            mem=memory,
        )
        assert address + width <= len(memory)


@pytest.mark.parametrize(
    "instruction",
    [
        "movd xmm0, dword ptr fs:[rax]",
        "movq qword ptr gs:[rax], xmm0",
        "movups xmm0, xmmword ptr fs:[rax]",
        "movdqu xmmword ptr gs:[rax], xmm0",
    ],
)
def test_segment_overridden_xmm_memory_transfers_fail_closed(
    instruction: str,
) -> None:
    with pytest.raises(lifter.LiftUnsupported, match="segment-overridden"):
        lifter.lift_function(_asm(instruction))


@pytest.mark.parametrize(
    "code",
    [
        bytes.fromhex("67660f6e00"),  # movd xmm0,dword ptr [eax]
        bytes.fromhex("67f30f7e00"),  # movq xmm0,qword ptr [eax]
        bytes.fromhex("670f1000"),    # movups xmm0,xmmword ptr [eax]
        bytes.fromhex("67f30f6f00"),  # movdqu xmm0,xmmword ptr [eax]
    ],
)
def test_address_size_overridden_xmm_memory_fails_closed(code: bytes) -> None:
    with pytest.raises(lifter.LiftUnsupported, match="64-bit GPR"):
        lifter.lift_function(code)


@pytest.mark.parametrize("mnemonic", ["movups", "movdqu"])
def test_rip_relative_unaligned_transfer_rebases_through_image_base(
    mnemonic: str,
) -> None:
    code_rva = 0x1000
    data_rva = 0x3000
    runtime_image_base = 0x180000000
    probe = _asm(f"{mnemonic} xmm7, xmmword ptr [rip]")
    displacement = data_rva - (code_rva + len(probe))
    encoded, _ = _KS.asm(
        f"{mnemonic} xmm7, xmmword ptr [rip + {displacement}]",
        addr=code_rva,
    )
    code = bytes(encoded)
    data = bytes.fromhex("00112233445566778899aabbccddeeff")
    sections = (
        oracle._OracleSection(
            ".text", code_rva, len(code), code, 0x60000020
        ),
        oracle._OracleSection(
            ".data", data_rva, len(data), data, 0xC0000040
        ),
    )
    oracle.check_xmm(
        code,
        xmm_init=_xmms(xmm7=(1 << 128) - 1),
        mem=data,
        mem_base=runtime_image_base + data_rva,
        lift_base=code_rva,
        image_base=runtime_image_base,
        code_base=runtime_image_base + code_rva,
        image_sections=sections,
        selected_extents=((code_rva, len(code)),),
    )


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
