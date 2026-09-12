"""Differential coverage for the bounded Cut 11 scalar expansion."""
from __future__ import annotations

import pytest


pytest.importorskip("iced_x86")
pytest.importorskip("keystone")
pytest.importorskip("unicorn")

from iced_x86 import Decoder  # noqa: E402
from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # noqa: E402
from lifter import oracle  # noqa: E402
from lifter import x64_lifter as L  # noqa: E402


_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_FLAGS = ("CF", "PF", "ZF", "SF", "OF")
_MEM = bytes((index * 37 + 0x5A) & 0xFF for index in range(256))


def _asm(source: str, *, address: int = oracle.BASE) -> bytes:
    encoded, _ = _KS.asm(source, addr=address)
    return bytes(encoded)


def _init(**registers: int) -> list[int]:
    values = [0] * 16
    for name, value in registers.items():
        values[L.GPR_NAMES.index(name)] = value
    return values


def _rip_instruction(source: str, *, instruction_rva: int, target_rva: int) -> bytes:
    probe = _asm(source.format(mem="[rip]"), address=instruction_rva)
    displacement = target_rva - (instruction_rva + len(probe))
    sign = "+" if displacement >= 0 else "-"
    result = _asm(
        source.format(mem=f"[rip {sign} 0x{abs(displacement):X}]"),
        address=instruction_rva,
    )
    decoded = next(iter(Decoder(64, result, ip=instruction_rva)))
    assert decoded.ip_rel_memory_address == target_rva
    return result


@pytest.mark.parametrize(
    ("subregister", "parent"),
    (("ah", "rax"), ("ch", "rcx"), ("dh", "rdx"), ("bh", "rbx")),
)
def test_high8_read_write_and_arithmetic_match_unicorn(
    subregister: str,
    parent: str,
) -> None:
    destination = "dl" if subregister != "dh" else "cl"
    source = f"mov {subregister}, 0xA5; mov {destination}, {subregister}; add {subregister}, 0x7F"
    oracle.check(
        _asm(source),
        init=_init(**{parent: 0x1122334455667788}),
        flags=_FLAGS,
    )


@pytest.mark.parametrize(
    "source",
    (
        "mul ah",
        "imul ah",
        "cmp rax, rbx; setb bh",
        "xchg ah, bl",
    ),
)
def test_high8_aliases_work_across_existing_scalar_routes(source: str) -> None:
    oracle.check(
        _asm(source),
        init=_init(rax=0x112233445566817F, rbx=0x887766554433225A),
        flags=("CF", "OF") if source.endswith("ah") else (),
    )


@pytest.mark.parametrize(
    ("instruction", "value"),
    (
        ("cbw", 0x80),
        ("cbw", 0x7F),
        ("cwde", 0x8001),
        ("cwde", 0x7FFF),
        ("cdqe", 0x80000001),
        ("cdqe", 0x7FFFFFFF),
        ("cwd", 0x8001),
        ("cwd", 0x7FFF),
        ("cdq", 0x80000001),
        ("cdq", 0x7FFFFFFF),
        ("cqo", 0x8000000000000001),
        ("cqo", 0x7FFFFFFFFFFFFFFF),
    ),
)
def test_sign_extension_forms_match_and_preserve_flags(
    instruction: str,
    value: int,
) -> None:
    oracle.check(
        _asm(f"cmp r14, r15; {instruction}"),
        init=_init(
            rax=value,
            rdx=0x1122334455667788,
            r14=1,
            r15=2,
        ),
        flags=_FLAGS,
    )


@pytest.mark.parametrize(
    ("source", "rax", "rbx"),
    (
        ("imul ax, bx", 10, 20),
        ("imul ax, bx", -3000, 3000),
        ("imul ax, bx", -0x8000, -1),
        ("imul ax, bx, 7", 0x1234, -500),
        ("imul ax, bx, 100", 0x1234, 1000),
    ),
)
def test_imul16_result_and_overflow_match_unicorn(
    source: str,
    rax: int,
    rbx: int,
) -> None:
    oracle.check(
        _asm(source),
        init=_init(rax=rax & 0xFFFF, rbx=rbx & 0xFFFF),
        flags=("CF", "OF"),
    )


def _shift_flags(operation: str, width: int, count: int) -> tuple[str, ...]:
    masked = count & 31
    if masked == 0:
        return _FLAGS
    if operation in ("rol", "ror"):
        flags = ["CF", "PF", "ZF", "SF"]
        if masked == 1:
            flags.append("OF")
        return tuple(flags)
    flags = ["PF", "ZF", "SF"]
    if masked <= width:
        flags.append("CF")
    if masked == 1:
        flags.append("OF")
    return tuple(flags)


@pytest.mark.parametrize("operation", ("shl", "shr", "sar", "rol", "ror"))
@pytest.mark.parametrize(("width", "register"), ((8, "bl"), (16, "bx")))
@pytest.mark.parametrize("count", (0, 1, 8, 16, 32, 63, 64))
@pytest.mark.parametrize("count_source", ("immediate", "cl"))
def test_narrow_register_count_boundaries_match_unicorn(
    operation: str,
    width: int,
    register: str,
    count: int,
    count_source: str,
) -> None:
    operand = str(count) if count_source == "immediate" else "cl"
    oracle.check(
        _asm(f"cmp r14, r15; {operation} {register}, {operand}"),
        init=_init(
            rbx=0x1122334455669681,
            rcx=count,
            r14=1,
            r15=2,
        ),
        flags=_shift_flags(operation, width, count),
    )


@pytest.mark.parametrize("operation", ("shl", "shr", "sar", "rol", "ror"))
def test_immediate_zero_count_keeps_32bit_parent_zero_extension(
    operation: str,
) -> None:
    oracle.check(
        _asm(f"cmp r14, r15; {operation} eax, 0"),
        init=_init(rax=0xFFFFFFFF12345678, r14=1, r15=2),
        flags=_FLAGS,
    )


@pytest.mark.parametrize(
    ("operation", "size", "width", "count"),
    (
        ("shl", "byte", 8, 8),
        ("shr", "word", 16, 16),
        ("sar", "byte", 8, 63),
        ("rol", "word", 16, 16),
        ("ror", "byte", 8, 32),
        ("shl", "word", 16, 64),
    ),
)
@pytest.mark.parametrize("count_source", ("immediate", "cl"))
def test_memory_rmw_shift_rotate_boundaries_match_unicorn(
    operation: str,
    size: str,
    width: int,
    count: int,
    count_source: str,
) -> None:
    operand = str(count) if count_source == "immediate" else "cl"
    oracle.check(
        _asm(f"cmp r14, r15; {operation} {size} ptr [rbx+16], {operand}"),
        init=_init(rbx=oracle.MEM_BASE, rcx=count, r14=1, r15=2),
        flags=_shift_flags(operation, width, count),
        mem=_MEM,
    )


@pytest.mark.parametrize("mnemonic", ("bt", "bts", "btr", "btc"))
@pytest.mark.parametrize(
    ("register", "index", "value"),
    (
        ("ax", "15", 0x8001),
        ("eax", "63", 0x80000001),
        ("rax", "rcx", 0x8000000200008001),
    ),
)
def test_register_bit_tests_match_unicorn(
    mnemonic: str,
    register: str,
    index: str,
    value: int,
) -> None:
    oracle.check(
        _asm(f"{mnemonic} {register}, {index}"),
        init=_init(rax=value, rcx=63),
        flags=("CF",),
    )


@pytest.mark.parametrize(
    "source",
    (
        "bt qword ptr [rbx], rcx",
        "bts dword ptr [rbx], ecx",
        "btr word ptr [rbx], 7",
        "btc qword ptr [rbx], 45",
    ),
)
def test_memory_bit_strings_remain_fail_closed(source: str) -> None:
    with pytest.raises(L.LiftUnsupported, match="register"):
        L.lift_function(_asm(source), base=oracle.BASE)


def test_existing_rip_relative_data_route_remains_differentially_exact() -> None:
    code_rva = 0x1000
    data_rva = 0x4000
    code = _rip_instruction(
        "mov rax, qword ptr {mem}",
        instruction_rva=code_rva,
        target_rva=data_rva,
    )
    data = (0x8877665544332211).to_bytes(8, "little")
    oracle.check_rip_data(
        code,
        data,
        code_rva=code_rva,
        data_rva=data_rva,
        runtime_image_base=0x000001A000000000,
        flags=(),
    )


def test_existing_xmm_and_double_shift_routes_remain_differentially_exact() -> None:
    oracle.check_xmm(
        _asm("movdqu xmm1, xmm0; pxor xmm1, xmm2"),
        xmm_init=[0x00112233445566778899AABBCCDDEEFF, 0,
                  0xFFEEDDCCBBAA99887766554433221100] + [0] * 13,
        flags=(),
    )
    oracle.check(
        _asm("shld rax, rbx, 13; shrd rcx, rdx, cl"),
        init=_init(
            rax=0x0123456789ABCDEF,
            rbx=0xFEDCBA9876543210,
            rcx=7,
            rdx=0xA5A5A5A55A5A5A5A,
        ),
        flags=("CF", "PF", "ZF", "SF"),
    )


def test_default_lift_keeps_full_flag_emission() -> None:
    assembly = L.lift_function(_asm("add rax, rbx"), base=oracle.BASE)
    for offset in (L.CF, L.PF, L.ZF, L.SF, L.OF):
        assert f"local_addr {offset}" in assembly
