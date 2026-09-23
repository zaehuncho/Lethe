"""Differential coverage for Cut 11 lifter improvements.

Covers:
- High-8 sub-registers (AH, BH, CH, DH) preservation and arithmetic.
- Sign extension (CBW, CWDE, CDQE, CWD, CDQ, CQO).
- 8-bit and 16-bit shifts and rotates (SHL, SHR, SAR, ROL, ROR) with imm and CL.
- 16-bit IMUL (2-operand and 3-operand) with exact CF/OF overflow behaviour.
- Memory destination shifts and rotates (RMW forms).
- Bit-test primitives (BT, BTS, BTR, BTC) on register and memory targets.
- Backward liveness dead-flag elimination bytecode compaction and correctness.
"""
from __future__ import annotations

import random
import struct

import pytest

pytest.importorskip("iced_x86")
pytest.importorskip("keystone")
pytest.importorskip("unicorn")

from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # noqa: E402
from lifter import oracle  # noqa: E402
from lifter import x64_lifter as L  # noqa: E402


_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_FLAGS = ("CF", "PF", "ZF", "SF", "OF")
_MEM = bytes((index * 37 + 0x5A) & 0xFF for index in range(512))


def _asm(source: str) -> bytes:
    encoded, _ = _KS.asm(source, addr=oracle.BASE)
    return bytes(encoded)


def _init(**registers: int) -> list[int]:
    values = [0] * 16
    for name, value in registers.items():
        values[L.GPR_NAMES.index(name)] = value
    return values


# =====================================================================
# 1. High-8 Sub-Registers (AH, BH, CH, DH)
# =====================================================================

@pytest.mark.parametrize(
    "subreg,parent",
    (
        ("ah", "rax"),
        ("ch", "rcx"),
        ("dh", "rdx"),
        ("bh", "rbx"),
    ),
)
def test_high8_write_preserves_parent_low_and_high_bits(subreg: str, parent: str) -> None:
    # Set parent to distinct bytes across all 64 bits: 0x1122334455667788
    # Bits 8..15 is 0x77. Writing 0xAA to subreg should turn it into 0x112233445566AA88.
    code = _asm(f"mov {subreg}, 0xAA")
    oracle.check(
        code,
        init=_init(**{parent: 0x1122334455667788}),
        flags=(),
    )


@pytest.mark.parametrize(
    "subreg,parent",
    (
        ("ah", "rax"),
        ("ch", "rcx"),
        ("dh", "rdx"),
        ("bh", "rbx"),
    ),
)
def test_high8_read_extracts_correct_byte(subreg: str, parent: str) -> None:
    # High-8 cannot be encoded with REX prefix, so use legacy register (e.g. rsi/rdi without REX, or mem or parent)
    code = _asm(f"mov dl, {subreg}") if parent != "rdx" else _asm(f"mov cl, {subreg}")
    oracle.check(
        code,
        init=_init(**{parent: 0x1122334455667788}),
        flags=(),
    )


@pytest.mark.parametrize("subreg", ("ah", "ch", "dh", "bh"))
def test_high8_arithmetic_updates_flags_and_register(subreg: str) -> None:
    code = _asm(f"add {subreg}, 0x90")
    oracle.check(
        code,
        init=_init(rax=0x0000000000008000, rcx=0x0000000000008000,
                   rdx=0x0000000000008000, rbx=0x0000000000008000),
        flags=_FLAGS,
    )


# =====================================================================
# 2. Sign Extension (CBW, CWDE, CDQE, CWD, CDQ, CQO)
# =====================================================================

@pytest.mark.parametrize(
    "instr,val_rax,expected_flags",
    (
        ("cbw", 0x7F, ()),
        ("cbw", 0x80, ()),
        ("cbw", 0xFF, ()),
        ("cwde", 0x7FFF, ()),
        ("cwde", 0x8000, ()),
        ("cwde", 0xFFFF, ()),
        ("cdqe", 0x7FFFFFFF, ()),
        ("cdqe", 0x80000000, ()),
        ("cdqe", 0xFFFFFFFF, ()),
    ),
)
def test_sign_extend_accumulator_forms(instr: str, val_rax: int, expected_flags: tuple) -> None:
    code = _asm(f"cmp r8, r8; {instr}")
    oracle.check(
        code,
        init=_init(rax=val_rax, r8=1),
        flags=_FLAGS,
    )


@pytest.mark.parametrize(
    "instr,val_rax",
    (
        ("cwd", 0x0000),
        ("cwd", 0x7FFF),
        ("cwd", 0x8000),
        ("cwd", 0xFFFF),
        ("cdq", 0x00000000),
        ("cdq", 0x7FFFFFFF),
        ("cdq", 0x80000000),
        ("cdq", 0xFFFFFFFF),
        ("cqo", 0x0000000000000000),
        ("cqo", 0x7FFFFFFFFFFFFFFF),
        ("cqo", 0x8000000000000000),
        ("cqo", 0xFFFFFFFFFFFFFFFF),
    ),
)
def test_sign_extend_dx_ax_forms(instr: str, val_rax: int) -> None:
    code = _asm(f"cmp r8, r8; {instr}")
    oracle.check(
        code,
        init=_init(rax=val_rax, rdx=0x1234567890ABCDEF, r8=1),
        flags=_FLAGS,
    )


# =====================================================================
# 3. 8-bit and 16-bit Shifts & Rotates
# =====================================================================

@pytest.mark.parametrize("op", ("shl", "shr", "sar", "rol", "ror"))
@pytest.mark.parametrize("count", (1, 4, 7, 8, 15, 31))
def test_narrow_8bit_shifts_immediate(op: str, count: int) -> None:
    code = _asm(f"cmp r14, r15; {op} al, {count}")
    oracle.check(
        code,
        init=_init(rax=0x96, r14=1, r15=2),
        flags=("CF", "ZF", "SF"),
    )


@pytest.mark.parametrize("op", ("shl", "shr", "sar", "rol", "ror"))
@pytest.mark.parametrize("count", (1, 4, 15, 16, 31))
def test_narrow_16bit_shifts_immediate(op: str, count: int) -> None:
    code = _asm(f"cmp r14, r15; {op} ax, {count}")
    oracle.check(
        code,
        init=_init(rax=0x8042, r14=1, r15=2),
        flags=("CF", "ZF", "SF"),
    )


@pytest.mark.parametrize("op", ("shl", "shr", "sar", "rol", "ror"))
@pytest.mark.parametrize("cl_val", (0, 1, 5, 17, 33))
def test_narrow_shifts_cl(op: str, cl_val: int) -> None:
    code = _asm(f"cmp r14, r15; {op} ax, cl")
    oracle.check(
        code,
        init=_init(rax=0x9ABC, rcx=cl_val, r14=1, r15=2),
        flags=_FLAGS if cl_val == 0 else ("CF", "ZF", "SF"),
    )


# =====================================================================
# 4. 16-bit IMUL
# =====================================================================

@pytest.mark.parametrize(
    "ax,bx",
    (
        (10, 20),           # positive, no overflow
        (-5, 12),           # negative, no overflow
        (1000, 2000),       # positive, overflow
        (-3000, 3000),      # negative, overflow
        (0x7FFF, 2),        # boundary overflow
        (-0x8000, 1),       # boundary no overflow
        (-0x8000, -1),      # boundary overflow
    ),
)
def test_imul_16bit_2operand(ax: int, bx: int) -> None:
    code = _asm("imul ax, bx")
    oracle.check(
        code,
        init=_init(rax=ax & 0xFFFF, rbx=bx & 0xFFFF),
        flags=("CF", "OF"),
    )


@pytest.mark.parametrize(
    "bx,imm",
    (
        (10, 5),            # small imm8
        (1000, 100),        # imm16, overflow
        (-500, 2),          # negative, no overflow
        (0x4000, 4),        # overflow
    ),
)
def test_imul_16bit_3operand(bx: int, imm: int) -> None:
    code = _asm(f"imul ax, bx, {imm}")
    oracle.check(
        code,
        init=_init(rax=0x1234, rbx=bx & 0xFFFF),
        flags=("CF", "OF"),
    )


# =====================================================================
# 5. Memory Destination Shifts & Rotates (RMW Forms)
# =====================================================================

@pytest.mark.parametrize(
    "op,size,count",
    (
        ("shl", "byte", 1),
        ("shl", "byte", 4),
        ("shr", "word", 3),
        ("sar", "dword", 5),
        ("rol", "qword", 2),
        ("ror", "byte", 3),
        ("shl", "dword", "cl"),
        ("sar", "word", "cl"),
        ("rol", "byte", "cl"),
    ),
)
def test_rmw_memory_shifts_and_rotates(op: str, size: str, count) -> None:
    instr = f"{op} {size} ptr [rbx+16], {count}"
    code = _asm(f"cmp r14, r15; {instr}")
    flags = ("CF", "ZF", "SF")
    oracle.check(
        code,
        init=_init(rbx=oracle.MEM_BASE, rcx=3, r14=1, r15=2),
        flags=flags,
        mem=_MEM,
    )


# =====================================================================
# 6. Bit-Test Primitives (BT, BTS, BTR, BTC)
# =====================================================================

@pytest.mark.parametrize("mnemonic", ("bt", "bts", "btr", "btc"))
@pytest.mark.parametrize("width,reg,bit_idx", (
    ("word", "ax", 0),
    ("word", "ax", 7),
    ("word", "ax", 15),
    ("dword", "eax", 0),
    ("dword", "eax", 17),
    ("dword", "eax", 31),
    ("qword", "rax", 0),
    ("qword", "rax", 33),
    ("qword", "rax", 63),
))
def test_bittest_register_immediate(mnemonic: str, width: str, reg: str, bit_idx: int) -> None:
    code = _asm(f"cmp r14, r15; {mnemonic} {reg}, {bit_idx}")
    oracle.check(
        code,
        init=_init(rax=0x8000000200008001, r14=1, r15=2),
        flags=("CF",),
    )


@pytest.mark.parametrize("mnemonic", ("bt", "bts", "btr", "btc"))
@pytest.mark.parametrize("width,reg,idx_reg", (
    ("word", "ax", "cx"),
    ("dword", "eax", "ecx"),
    ("qword", "rax", "rcx"),
))
def test_bittest_register_with_reg_index(mnemonic: str, width: str, reg: str, idx_reg: str) -> None:
    code = _asm(f"cmp r14, r15; {mnemonic} {reg}, {idx_reg}")
    oracle.check(
        code,
        init=_init(rax=0xAAAAAAAAAAAAAAAA, rcx=5, r14=1, r15=2),
        flags=("CF",),
    )


@pytest.mark.parametrize("mnemonic", ("bt", "bts", "btr", "btc"))
@pytest.mark.parametrize("size,bit_idx", (
    ("word", 7),
    ("word", 12),
    ("dword", 20),
    ("qword", 45),
))
def test_bittest_memory_immediate(mnemonic: str, size: str, bit_idx: int) -> None:
    code = _asm(f"cmp r14, r15; {mnemonic} {size} ptr [rbx+24], {bit_idx}")
    oracle.check(
        code,
        init=_init(rbx=oracle.MEM_BASE, r14=1, r15=2),
        flags=("CF",),
        mem=_MEM,
    )


# =====================================================================
# 7. Backward Liveness Dead-Flag Elimination
# =====================================================================

def test_dead_flag_elimination_reduces_bytecode_size() -> None:
    # In this sequence, the first three arithmetic instructions compute flags
    # that are overwritten by the final CMP without ever being consumed.
    source = """
    add rax, rbx
    sub rcx, rdx
    xor r8, r9
    cmp r10, r11
    """
    raw_x64 = _asm(source)

    asm_unopt = L.lift_function(raw_x64, base=oracle.BASE, optimize_flags=False)
    asm_opt = L.lift_function(raw_x64, base=oracle.BASE, optimize_flags=True)

    # The optimized version must omit flag calculations for the dead instructions
    assert len(asm_opt) < len(asm_unopt), (
        f"Expected size reduction: unopt={len(asm_unopt)} opt={len(asm_opt)}"
    )

    # Differential correctness: both must execute with exact parity
    init = _init(
        rax=10, rbx=20, rcx=50, rdx=30,
        r8=0xFF, r9=0x0F, r10=100, r11=100,
    )
    oracle.check(raw_x64, init=init, flags=_FLAGS)


def test_dead_flag_elimination_preserves_live_flags_before_branch() -> None:
    # Here, SUB flags ARE consumed by JZ, so they must be kept live!
    source = """
    mov r8, 0
    sub rax, rbx
    jz skip
    mov r8, 1
skip:
    add r8, 2
    """
    raw_x64 = _asm(source)

    init_eq = _init(rax=10, rbx=10)
    oracle.check(raw_x64, init=init_eq, flags=())

    init_ne = _init(rax=10, rbx=20)
    oracle.check(raw_x64, init=init_ne, flags=())
