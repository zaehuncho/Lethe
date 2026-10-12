"""Legacy XMM register operations and exact 128-bit memory transfers."""
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
_XMM_XORS = ("pxor", "xorps", "xorpd")
_XMM_ANDS = ("pand", "andps", "andpd")
_XMM_AND_NOTS = ("pandn", "andnps", "andnpd")
_XMM_ORS = ("por", "orps", "orpd")
_XMM_LOGICAL = _XMM_XORS + _XMM_ANDS + _XMM_AND_NOTS + _XMM_ORS
_XMM_HALF_MEMORY = ("movlps", "movlpd", "movhps", "movhpd")
_XMM_HALF_REGISTER = ("movhlps", "movlhps")
_XMM_BYTE_SHIFTS = ("pslldq", "psrldq")


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


def _int32_pair_as_double_bits(low: int, high: int) -> int:
    """Independent exact binary64 expectation, not a copy of the VM algorithm."""
    return int.from_bytes(struct.pack("<dd", float(low), float(high)), "little")


@pytest.mark.parametrize("destination,source", [(0, 15), (15, 0), (7, 7)])
@pytest.mark.parametrize("low,high", [
    (0, 0), (1, -1), (-1, 1), (-(1 << 31), (1 << 31) - 1),
    ((1 << 30) + 1, -(1 << 30) - 1), (16777217, -16777217),
    (0x12345678, -0x12345678), (-2147483647, 2147483646),
])
def test_cvtdq2pd_exact_signed_lanes_and_self_alias(destination, source, low, high):
    xmms = [((index + 1) << 112) | 0xA5A5A5A5A5A5A5A5 for index in range(16)]
    xmms[source] = (0xFFEEDDCCBBAA9988 << 64) | ((high & 0xFFFFFFFF) << 32) | (low & 0xFFFFFFFF)
    regs = [(index + 1) * 0x1020304050607 for index in range(16)]
    native, lifted = oracle.check_xmm(
        _asm(f"cvtdq2pd xmm{destination}, xmm{source}"), init=regs, xmm_init=xmms)
    assert native[2][destination] == lifted[2][destination] == _int32_pair_as_double_bits(low, high)
    assert native[0] == lifted[0] == regs
    assert all(lifted[2][index] == value for index, value in enumerate(xmms)
               if index != destination)


@pytest.mark.parametrize("pattern", range(32))
def test_cvtdq2pd_keeps_all_incoming_integer_flags(pattern):
    names = ("CF", "PF", "ZF", "SF", "OF")
    expected = {name: (pattern >> ordinal) & 1 for ordinal, name in enumerate(names)}
    mask = sum(value << oracle.FLAG_BIT[name] for name, value in expected.items())
    native, lifted = oracle.check_xmm(
        _asm("cvtdq2pd xmm15, xmm15"),
        xmm_init=_xmms(xmm15=0x7FFFFFFF80000000), initial_flags=mask)
    assert native[1] == lifted[1] == expected
    assert lifted[2][15] == _int32_pair_as_double_bits(-(1 << 31), (1 << 31) - 1)


@pytest.mark.parametrize("exponent", range(32))
def test_cvtdq2pd_every_normalization_boundary(exponent):
    for magnitude in ((1 << exponent) - 1, 1 << exponent, (1 << exponent) + 1):
        for low in (magnitude, -magnitude):
            if not -(1 << 31) <= low < (1 << 31):
                continue
            high = -low - 1
            source = ((high & 0xFFFFFFFF) << 32) | (low & 0xFFFFFFFF)
            native, lifted = oracle.check_xmm(
                _asm("cvtdq2pd xmm15, xmm15"), xmm_init=_xmms(xmm15=source))
            assert native[2][15] == lifted[2][15] == _int32_pair_as_double_bits(low, high)


@pytest.mark.parametrize("offset", [0, 1, 3, 7, 8])
def test_cvtdq2pd_m64_has_no_128_bit_alignment_or_overread(offset):
    memory = bytes([0xA5] * offset) + struct.pack("<ii", -(1 << 31), 16777217)
    native, lifted = oracle.check_xmm(
        _asm(f"cvtdq2pd xmm15, qword ptr [rax+{offset}]"),
        init=_gprs(rax=oracle.MEM_BASE), xmm_init=_xmms(xmm15=(1 << 128) - 1), mem=memory)
    assert native[2][15] == lifted[2][15] == _int32_pair_as_double_bits(-(1 << 31), 16777217)


def test_cvtdq2pd_seeded_random_register_and_memory_forms():
    rng = random.Random(0xC7D03264)
    for index in range(128):
        low = rng.randrange(-(1 << 31), 1 << 31)
        high = rng.randrange(-(1 << 31), 1 << 31)
        xmms = [rng.getrandbits(128) for _ in range(16)]
        destination, source = rng.randrange(16), rng.randrange(16)
        offset = rng.randrange(16)
        if index % 2:
            xmms[source] = (rng.getrandbits(64) << 64) | ((high & 0xFFFFFFFF) << 32) | (low & 0xFFFFFFFF)
            instruction, memory = f"cvtdq2pd xmm{destination}, xmm{source}", None
        else:
            instruction = f"cvtdq2pd xmm{destination}, qword ptr [rax+{offset}]"
            memory = bytes(rng.getrandbits(8) for _ in range(offset)) + struct.pack("<ii", low, high)
        native, lifted = oracle.check_xmm(
            _asm(instruction), init=_gprs(rax=oracle.MEM_BASE), xmm_init=xmms, mem=memory)
        assert native[2][destination] == lifted[2][destination] == _int32_pair_as_double_bits(low, high)


def test_cvtdq2pd_faulting_m64_read_precedes_any_destination_write():
    assembly = lifter.lift_function(_asm("cvtdq2pd xmm15, qword ptr [rax]"))
    assert "load128" not in assembly
    blob = daedalus_asm.assemble(assembly)
    size = struct.unpack_from("<H", blob)[0]
    vm = RefVM(blob[2 + size:], blob[2:2 + size],
               mem=bytes(7), mem_base=oracle.MEM_BASE)
    vm.locals[:8] = oracle.MEM_BASE.to_bytes(8, "little")
    offset = lifter.XMM_OFF[lifter.Register.XMM15]
    sentinel = bytes.fromhex("00112233445566778899aabbccddeeff")
    vm.locals[offset:offset + 16] = sentinel
    with pytest.raises(DaedalusError):
        vm.run()
    assert vm.locals[offset:offset + 16] == sentinel


@pytest.mark.parametrize("image_base", [0, 0x180000000])
def test_cvtdq2pd_rip_relative_m64_rebases_and_keeps_exact_width(image_base):
    code_rva, data_rva = 0x1000, 0x3000
    probe = _asm("cvtdq2pd xmm15, qword ptr [rip]")
    displacement = data_rva - code_rva - len(probe)
    code = bytes(_KS.asm(f"cvtdq2pd xmm15, qword ptr [rip+{displacement}]", addr=code_rva)[0])
    data = struct.pack("<ii", -16777217, (1 << 31) - 1)
    sections = (
        oracle._OracleSection(".text", code_rva, len(code), code, 0x60000020),
        oracle._OracleSection(".data", data_rva, len(data), data, 0xC0000040),
    )
    native, lifted = oracle.check_xmm(
        code, mem=data, mem_base=image_base + data_rva, lift_base=code_rva,
        image_base=image_base, code_base=image_base + code_rva,
        image_sections=sections, selected_extents=((code_rva, len(code)),))
    assert native[2][15] == lifted[2][15] == _int32_pair_as_double_bits(-16777217, (1 << 31) - 1)


@pytest.mark.parametrize("instruction", [
    "vcvtdq2pd xmm0, xmm1", "vcvtdq2pd ymm0, xmm1",
    "cvtdq2pd xmm0, qword ptr gs:[rax]", "cvtdq2pd xmm0, qword ptr [eax]",
    "cvtsi2sd xmm0, rax", "cvtdq2ps xmm0, xmm1", "addsd xmm0, xmm1",
])
def test_cvtdq2pd_does_not_admit_unmodeled_encodings_or_rounded_fp(instruction):
    with pytest.raises(lifter.LiftUnsupported):
        lifter.lift_function(_asm(instruction))


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


@pytest.mark.parametrize("mnemonic", _XMM_LOGICAL)
def test_register_logical_matches_unicorn(mnemonic: str) -> None:
    initial = _xmms(
        xmm0=0xFFEEDDCCBBAA99887766554433221100,
        xmm15=0x0123456789ABCDEFFEDCBA9876543210,
    )
    oracle.check_xmm(
        _asm(f"{mnemonic} xmm0, xmm15"),
        xmm_init=initial,
    )


@pytest.mark.parametrize("mnemonic", _XMM_XORS + _XMM_AND_NOTS)
def test_self_xor_and_and_not_clear(
    mnemonic: str,
) -> None:
    initial = _xmms(
        xmm0=0xFFEEDDCCBBAA99887766554433221100,
        xmm15=0x0123456789ABCDEFFEDCBA9876543210,
    )
    oracle.check_xmm(
        _asm(f"{mnemonic} xmm0, xmm15; {mnemonic} xmm15, xmm15"),
        xmm_init=initial,
    )


@pytest.mark.parametrize("mnemonic", _XMM_LOGICAL)
def test_xmm_logical_operations_preserve_nonzero_integer_flags(
    mnemonic: str,
) -> None:
    initial = _gprs(rax=1, rbx=2)
    xmm_init = _xmms(
        xmm0=0xFFEEDDCCBBAA99887766554433221100,
        xmm1=0x0123456789ABCDEFFEDCBA9876543210,
    )
    oracle.check_xmm(
        _asm(f"cmp rax, rbx; {mnemonic} xmm0, xmm1"),
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


@pytest.mark.parametrize(
    "instruction",
    [
        "movss xmm0, xmm15",
        "movsd xmm0, xmm15",
        "movss xmm15, xmm15",
        "movsd xmm15, xmm15",
    ],
)
def test_legacy_scalar_float_register_moves_match_unicorn(
    instruction: str,
) -> None:
    oracle.check_xmm(
        _asm(instruction),
        xmm_init=_xmms(
            xmm0=0xFFEEDDCCBBAA99887766554433221100,
            xmm15=0x0123456789ABCDEFFEDCBA9876543210,
        ),
    )


@pytest.mark.parametrize(
    "instruction",
    [
        "movss xmm0, dword ptr [rax + 3]",
        "movss dword ptr [rax + 7], xmm15",
        "movsd xmm15, qword ptr [rax + 5]",
        "movsd qword ptr [rax + 9], xmm0",
    ],
)
def test_legacy_scalar_float_memory_moves_match_unicorn(
    instruction: str,
) -> None:
    memory = bytearray((index * 41 + 13) & 0xFF for index in range(96))
    oracle.check_xmm(
        _asm(instruction),
        init=_gprs(rax=oracle.MEM_BASE),
        xmm_init=_xmms(
            xmm0=0xFFEEDDCCBBAA99887766554433221100,
            xmm15=0x0123456789ABCDEFFEDCBA9876543210,
        ),
        mem=memory,
    )


@pytest.mark.parametrize(("mnemonic", "width"), [("movss", 4), ("movsd", 8)])
def test_randomized_scalar_float_moves_match_unicorn(
    mnemonic: str,
    width: int,
) -> None:
    rng = random.Random(0x584D4D1600 + width)
    pointer = "dword" if width == 4 else "qword"
    for _ in range(64):
        destination = rng.randrange(16)
        source = rng.randrange(16)
        offset = rng.randrange(0, 224)
        memory = bytearray(rng.getrandbits(8) for _ in range(256))
        xmms = [rng.getrandbits(128) for _ in range(16)]
        operation = rng.randrange(3)
        if operation == 0:
            instruction = f"{mnemonic} xmm{destination}, xmm{source}"
        elif operation == 1:
            instruction = (
                f"{mnemonic} xmm{destination}, {pointer} ptr [rax + {offset}]"
            )
        else:
            instruction = (
                f"{mnemonic} {pointer} ptr [rax + {offset}], xmm{source}"
            )
        oracle.check_xmm(
            _asm(f"cmp r10, r11; {instruction}"),
            init=_gprs(rax=oracle.MEM_BASE, r10=1, r11=2),
            xmm_init=xmms,
            mem=memory,
        )


@pytest.mark.parametrize(
    "instruction",
    [
        "movhlps xmm0, xmm15",
        "movlhps xmm0, xmm15",
        "movhlps xmm15, xmm15",
        "movlhps xmm15, xmm15",
    ],
)
def test_legacy_half_lane_register_moves_match_unicorn(
    instruction: str,
) -> None:
    oracle.check_xmm(
        _asm(f"cmp r10, r11; {instruction}"),
        init=_gprs(r10=1, r11=2),
        xmm_init=_xmms(
            xmm0=0xFFEEDDCCBBAA99887766554433221100,
            xmm15=0x0123456789ABCDEFFEDCBA9876543210,
        ),
    )


@pytest.mark.parametrize(
    "instruction",
    [
        "movlps xmm0, qword ptr [rax + 3]",
        "movlps qword ptr [rax + 7], xmm15",
        "movlpd xmm15, qword ptr [rax + 5]",
        "movlpd qword ptr [rax + 9], xmm0",
        "movhps xmm0, qword ptr [rax + 11]",
        "movhps qword ptr [rax + 13], xmm15",
        "movhpd xmm15, qword ptr [rax + 15]",
        "movhpd qword ptr [rax + 17], xmm0",
    ],
)
def test_legacy_half_lane_memory_moves_match_unicorn(
    instruction: str,
) -> None:
    memory = bytearray((index * 43 + 19) & 0xFF for index in range(96))
    oracle.check_xmm(
        _asm(f"cmp r10, r11; {instruction}"),
        init=_gprs(rax=oracle.MEM_BASE, r10=1, r11=2),
        xmm_init=_xmms(
            xmm0=0xFFEEDDCCBBAA99887766554433221100,
            xmm15=0x0123456789ABCDEFFEDCBA9876543210,
        ),
        mem=memory,
    )


@pytest.mark.parametrize("mnemonic", _XMM_HALF_REGISTER)
def test_randomized_half_lane_register_moves_match_unicorn(
    mnemonic: str,
) -> None:
    rng = random.Random(0x584D4D1700 + _XMM_HALF_REGISTER.index(mnemonic))
    for _ in range(64):
        destination = rng.randrange(16)
        source = rng.randrange(16)
        xmms = [rng.getrandbits(128) for _ in range(16)]
        oracle.check_xmm(
            _asm(
                f"cmp r10, r11; {mnemonic} xmm{destination}, xmm{source}"
            ),
            init=_gprs(
                r10=rng.getrandbits(64),
                r11=rng.getrandbits(64),
            ),
            xmm_init=xmms,
        )


@pytest.mark.parametrize("mnemonic", _XMM_HALF_MEMORY)
@pytest.mark.parametrize("store", [False, True], ids=["load", "store"])
def test_randomized_half_lane_memory_moves_match_unicorn(
    mnemonic: str,
    store: bool,
) -> None:
    rng = random.Random(
        0x584D4D1740 + _XMM_HALF_MEMORY.index(mnemonic) * 2 + store
    )
    for _ in range(64):
        offset = rng.randrange(0, 248)
        xmm = rng.randrange(16)
        memory = bytearray(rng.getrandbits(8) for _ in range(256))
        xmms = [rng.getrandbits(128) for _ in range(16)]
        if store:
            instruction = f"{mnemonic} qword ptr [rax + {offset}], xmm{xmm}"
        else:
            instruction = f"{mnemonic} xmm{xmm}, qword ptr [rax + {offset}]"
        oracle.check_xmm(
            _asm(f"cmp r10, r11; {instruction}"),
            init=_gprs(
                rax=oracle.MEM_BASE,
                r10=rng.getrandbits(64),
                r11=rng.getrandbits(64),
            ),
            xmm_init=xmms,
            mem=memory,
        )


@pytest.mark.parametrize("mnemonic", _XMM_BYTE_SHIFTS)
@pytest.mark.parametrize("count", [0, 1, 7, 8, 9, 15, 16, 17, 255])
def test_legacy_xmm_byte_shift_boundaries_match_unicorn(
    mnemonic: str,
    count: int,
) -> None:
    oracle.check_xmm(
        _asm(f"cmp r10, r11; {mnemonic} xmm15, {count}"),
        init=_gprs(r10=1, r11=2),
        xmm_init=_xmms(xmm15=0xFFEEDDCCBBAA99887766554433221100),
    )


@pytest.mark.parametrize("mnemonic", _XMM_BYTE_SHIFTS)
def test_randomized_legacy_xmm_byte_shifts_match_unicorn(
    mnemonic: str,
) -> None:
    rng = random.Random(0x584D4D1780 + _XMM_BYTE_SHIFTS.index(mnemonic))
    for _ in range(128):
        destination = rng.randrange(16)
        count = rng.randrange(256)
        xmms = [rng.getrandbits(128) for _ in range(16)]
        oracle.check_xmm(
            _asm(f"cmp r10, r11; {mnemonic} xmm{destination}, {count}"),
            init=_gprs(
                r10=rng.getrandbits(64),
                r11=rng.getrandbits(64),
            ),
            xmm_init=xmms,
        )


def test_deterministic_register_sequence_fuzz_matches_unicorn() -> None:
    rng = random.Random(0x584D4D12)
    moves = ("movaps", "movups", "movdqa", "movdqu")
    for _ in range(128):
        lines = []
        for _ in range(rng.randint(1, 12)):
            destination = rng.randrange(16)
            source = rng.randrange(16)
            operation = rng.choice(moves + _XMM_LOGICAL)
            lines.append(f"{operation} xmm{destination}, xmm{source}")
        initial = [rng.getrandbits(128) for _ in range(16)]
        oracle.check_xmm(_asm("; ".join(lines)), xmm_init=initial)


@pytest.mark.parametrize("mnemonic", _XMM_LOGICAL)
def test_aligned_logical_memory_sources_match_unicorn(
    mnemonic: str,
) -> None:
    memory = bytearray((index * 37 + 11) & 0xFF for index in range(96))
    oracle.check_xmm(
        _asm(f"cmp r10, r11; {mnemonic} xmm7, xmmword ptr [rax + 32]"),
        init=_gprs(rax=oracle.MEM_BASE, r10=1, r11=2),
        xmm_init=_xmms(
            xmm0=0x00112233445566778899AABBCCDDEEFF,
            xmm7=0xFFEEDDCCBBAA99887766554433221100,
            xmm15=0xA55AA55AA55AA55A5AA55AA55AA55AA5,
        ),
        mem=memory,
    )


@pytest.mark.parametrize("mnemonic", _XMM_LOGICAL)
def test_randomized_aligned_logical_memory_sources_match_unicorn(
    mnemonic: str,
) -> None:
    seed = 0x584D4D1500 + _XMM_LOGICAL.index(mnemonic)
    rng = random.Random(seed)
    for _ in range(64):
        offset = rng.randrange(0, 15) * 16
        destination = rng.randrange(16)
        memory = bytearray(rng.getrandbits(8) for _ in range(256))
        xmms = [rng.getrandbits(128) for _ in range(16)]
        oracle.check_xmm(
            _asm(
                f"cmp r10, r11; {mnemonic} xmm{destination}, "
                f"xmmword ptr [rax + {offset}]"
            ),
            init=_gprs(
                rax=oracle.MEM_BASE,
                r10=rng.getrandbits(64),
                r11=rng.getrandbits(64),
            ),
            xmm_init=xmms,
            mem=memory,
        )


@pytest.mark.parametrize("mnemonic", _XMM_LOGICAL)
def test_unaligned_logical_memory_source_fault_preserves_architectural_state(
    mnemonic: str,
) -> None:
    assembly = lifter.lift_function(
        _asm(f"{mnemonic} xmm15, xmmword ptr [rax + 1]")
    )
    assert assembly.count("load128a") == 1

    blob = daedalus_asm.assemble(assembly)
    data_size = struct.unpack_from("<H", blob, 0)[0]
    memory = bytearray.fromhex("a5" * 32)
    vm = RefVM(
        blob[2 + data_size:],
        blob[2:2 + data_size],
        mem=memory,
        mem_base=oracle.MEM_BASE,
    )
    vm.locals[0:8] = oracle.MEM_BASE.to_bytes(8, "little")
    xmm_offset = lifter.XMM_OFF[lifter.Register.XMM15]
    original_xmm = 0x00112233445566778899AABBCCDDEEFF
    vm.locals[xmm_offset:xmm_offset + 16] = original_xmm.to_bytes(16, "little")
    original_flags = {
        lifter.CF: 1,
        lifter.PF: 1,
        lifter.ZF: 0,
        lifter.SF: 1,
        lifter.OF: 1,
    }
    for offset, value in original_flags.items():
        vm.locals[offset:offset + 8] = value.to_bytes(8, "little")

    with pytest.raises(DaedalusError, match="aligned 128-bit load is unaligned"):
        vm.run()

    assert bytes(vm.mem) == bytes.fromhex("a5" * 32)
    assert int.from_bytes(vm.locals[0:8], "little") == oracle.MEM_BASE
    assert int.from_bytes(
        vm.locals[xmm_offset:xmm_offset + 16], "little"
    ) == original_xmm
    assert {
        offset: int.from_bytes(vm.locals[offset:offset + 8], "little")
        for offset in original_flags
    } == original_flags


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
        "movaps xmm0, xmmword ptr [rax]",
        "movaps xmmword ptr [rax + 16], xmm15",
        "movdqa xmm15, xmmword ptr [rax + 32]",
        "movdqa xmmword ptr [rax + 48], xmm0",
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


@pytest.mark.parametrize("mnemonic", ["movaps", "movdqa"])
@pytest.mark.parametrize("store", [False, True], ids=["load", "store"])
def test_randomized_aligned_128_bit_transfers_match_unicorn(
    mnemonic: str, store: bool
) -> None:
    rng = random.Random(0x584D4D1380 + store + (mnemonic == "movdqa") * 2)
    for _ in range(96):
        offset = rng.randrange(0, 15) * 16
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


@pytest.mark.parametrize("mnemonic", ["movaps", "movdqa"])
@pytest.mark.parametrize("store", [False, True], ids=["load", "store"])
def test_aligned_128_transfer_uses_fault_preserving_vm_operation(
    mnemonic: str, store: bool
) -> None:
    instruction = (
        f"{mnemonic} xmmword ptr [rax + 1], xmm15"
        if store else f"{mnemonic} xmm15, xmmword ptr [rax + 1]"
    )
    assembly = lifter.lift_function(_asm(instruction))
    expected = "store128a" if store else "load128a"
    assert assembly.count(expected) == 1

    blob = daedalus_asm.assemble(assembly)
    data_size = struct.unpack_from("<H", blob, 0)[0]
    memory = bytearray.fromhex("a5" * 32)
    vm = RefVM(
        blob[2 + data_size:],
        blob[2:2 + data_size],
        mem=memory,
        mem_base=oracle.MEM_BASE,
    )
    vm.locals[0:8] = oracle.MEM_BASE.to_bytes(8, "little")
    xmm_offset = lifter.XMM_OFF[lifter.Register.XMM15]
    original_xmm = 0x00112233445566778899AABBCCDDEEFF
    vm.locals[xmm_offset:xmm_offset + 16] = original_xmm.to_bytes(16, "little")
    with pytest.raises(DaedalusError, match="aligned 128-bit .* is unaligned"):
        vm.run()
    assert bytes(vm.mem) == bytes.fromhex("a5" * 32)
    assert int.from_bytes(
        vm.locals[xmm_offset:xmm_offset + 16], "little"
    ) == original_xmm


@pytest.mark.parametrize("store", [False, True], ids=["load", "store"])
def test_reference_aligned128_fault_preserves_operand_stack(store: bool) -> None:
    address = oracle.MEM_BASE + 1
    lines = [".code", f"push_imm64 0x{address:X}"]
    expected_stack = [address]
    if store:
        low = 0x1122334455667788
        high = 0x99AABBCCDDEEFF00
        lines.extend([f"push_imm64 0x{low:X}", f"push_imm64 0x{high:X}"])
        expected_stack.extend([low, high])
    lines.extend(["store128a" if store else "load128a", "push_imm8 0", "halt"])
    blob = daedalus_asm.assemble("\n".join(lines))
    data_size = struct.unpack_from("<H", blob, 0)[0]
    memory = bytearray.fromhex("a5" * 32)
    vm = RefVM(
        blob[2 + data_size:],
        blob[2:2 + data_size],
        mem=memory,
        mem_base=oracle.MEM_BASE,
    )
    with pytest.raises(DaedalusError, match="aligned 128-bit .* is unaligned"):
        vm.run()
    assert vm.stack == expected_stack
    assert vm.pc == sum(9 for _ in expected_stack)
    assert bytes(vm.mem) == bytes.fromhex("a5" * 32)


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
        "movaps xmm0, xmmword ptr fs:[rax]",
        "movdqa xmmword ptr gs:[rax], xmm0",
        "movss xmm0, dword ptr fs:[rax]",
        "movsd qword ptr gs:[rax], xmm0",
        "movlps xmm0, qword ptr fs:[rax]",
        "movlpd qword ptr gs:[rax], xmm0",
        "movhps xmm0, qword ptr fs:[rax]",
        "movhpd qword ptr gs:[rax], xmm0",
    ],
)
def test_segment_overridden_xmm_memory_transfers_fail_closed(
    instruction: str,
) -> None:
    with pytest.raises(lifter.LiftUnsupported, match="segment-overridden"):
        lifter.lift_function(_asm(instruction))


@pytest.mark.parametrize("mnemonic", _XMM_LOGICAL)
def test_segment_overridden_xmm_logical_sources_fail_closed(
    mnemonic: str,
) -> None:
    with pytest.raises(lifter.LiftUnsupported, match="segment-overridden"):
        lifter.lift_function(
            _asm(f"{mnemonic} xmm0, xmmword ptr fs:[rax]")
        )


@pytest.mark.parametrize(
    "code",
    [
        bytes.fromhex("67660f6e00"),  # movd xmm0,dword ptr [eax]
        bytes.fromhex("67f30f7e00"),  # movq xmm0,qword ptr [eax]
        bytes.fromhex("670f1000"),    # movups xmm0,xmmword ptr [eax]
        bytes.fromhex("67f30f6f00"),  # movdqu xmm0,xmmword ptr [eax]
        bytes.fromhex("670f2800"),    # movaps xmm0,xmmword ptr [eax]
        bytes.fromhex("67660f6f00"),  # movdqa xmm0,xmmword ptr [eax]
        bytes.fromhex("67f30f1000"),  # movss xmm0,dword ptr [eax]
        bytes.fromhex("67f20f1000"),  # movsd xmm0,qword ptr [eax]
        bytes.fromhex("670f1200"),    # movlps xmm0,qword ptr [eax]
        bytes.fromhex("67660f1200"),  # movlpd xmm0,qword ptr [eax]
        bytes.fromhex("670f1600"),    # movhps xmm0,qword ptr [eax]
        bytes.fromhex("67660f1600"),  # movhpd xmm0,qword ptr [eax]
        bytes.fromhex("67660fef00"),  # pxor xmm0,xmmword ptr [eax]
        bytes.fromhex("670f5700"),    # xorps xmm0,xmmword ptr [eax]
        bytes.fromhex("67660f5700"),  # xorpd xmm0,xmmword ptr [eax]
        bytes.fromhex("67660fdb00"),  # pand xmm0,xmmword ptr [eax]
        bytes.fromhex("670f5400"),    # andps xmm0,xmmword ptr [eax]
        bytes.fromhex("67660f5400"),  # andpd xmm0,xmmword ptr [eax]
        bytes.fromhex("67660fdf00"),  # pandn xmm0,xmmword ptr [eax]
        bytes.fromhex("670f5500"),    # andnps xmm0,xmmword ptr [eax]
        bytes.fromhex("67660f5500"),  # andnpd xmm0,xmmword ptr [eax]
        bytes.fromhex("67660feb00"),  # por xmm0,xmmword ptr [eax]
        bytes.fromhex("670f5600"),    # orps xmm0,xmmword ptr [eax]
        bytes.fromhex("67660f5600"),  # orpd xmm0,xmmword ptr [eax]
    ],
)
def test_address_size_overridden_xmm_memory_fails_closed(code: bytes) -> None:
    with pytest.raises(lifter.LiftUnsupported, match="64-bit GPR"):
        lifter.lift_function(code)


@pytest.mark.parametrize("mnemonic", ["movaps", "movdqa", "movups", "movdqu"])
def test_rip_relative_128_bit_transfer_rebases_through_image_base(
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


@pytest.mark.parametrize("mnemonic", _XMM_LOGICAL)
def test_rip_relative_logical_source_rebases_through_image_base(
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


@pytest.mark.parametrize(("mnemonic", "width"), [("movss", 4), ("movsd", 8)])
def test_rip_relative_scalar_float_load_rebases_through_image_base(
    mnemonic: str,
    width: int,
) -> None:
    code_rva = 0x1000
    data_rva = 0x3000
    runtime_image_base = 0x180000000
    pointer = "dword" if width == 4 else "qword"
    probe = _asm(f"{mnemonic} xmm7, {pointer} ptr [rip]")
    displacement = data_rva - (code_rva + len(probe))
    encoded, _ = _KS.asm(
        f"{mnemonic} xmm7, {pointer} ptr [rip + {displacement}]",
        addr=code_rva,
    )
    code = bytes(encoded)
    data = bytes.fromhex("0011223344556677")[:width]
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


@pytest.mark.parametrize("mnemonic", _XMM_HALF_MEMORY)
@pytest.mark.parametrize("store", [False, True], ids=["load", "store"])
def test_rip_relative_half_lane_transfer_rebases_through_image_base(
    mnemonic: str,
    store: bool,
) -> None:
    code_rva = 0x1000
    data_rva = 0x3000
    runtime_image_base = 0x180000000
    operand = (
        f"qword ptr [rip], xmm7"
        if store else "xmm7, qword ptr [rip]"
    )
    probe = _asm(f"{mnemonic} {operand}")
    displacement = data_rva - (code_rva + len(probe))
    operand = (
        f"qword ptr [rip + {displacement}], xmm7"
        if store else f"xmm7, qword ptr [rip + {displacement}]"
    )
    encoded, _ = _KS.asm(f"{mnemonic} {operand}", addr=code_rva)
    code = bytes(encoded)
    data = bytes.fromhex("0011223344556677")
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
        xmm_init=_xmms(xmm7=0xFFEEDDCCBBAA99887766554433221100),
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
        "vpand xmm0, xmm1, xmm2",
        "vpandn xmm0, xmm1, xmm2",
        "vpor xmm0, xmm1, xmm2",
        "vandps xmm0, xmm1, xmm2",
        "vandnps xmm0, xmm1, xmm2",
        "vorps xmm0, xmm1, xmm2",
        "vmovss xmm0, xmm1, xmm2",
        "vmovsd xmm0, xmm1, xmm2",
        "vmovlps xmm0, xmm1, qword ptr [rax]",
        "vmovhps xmm0, xmm1, qword ptr [rax]",
        "vmovlpd xmm0, xmm1, qword ptr [rax]",
        "vmovhpd xmm0, xmm1, qword ptr [rax]",
        "vpslldq xmm0, xmm1, 4",
        "vpsrldq xmm0, xmm1, 4",
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
