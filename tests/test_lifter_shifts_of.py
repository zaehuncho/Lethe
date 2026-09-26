"""Overflow-flag (OF) coverage for 1-bit shifts/rotates + SHLD/SHRD (T4).

OF is architecturally defined ONLY for a 1-bit shift/rotate. A recon pass found
the lifter mis-computed OF for shl/shr/rol/ror by 1 (imm=1 and CL count==1): it
hard-wired OF to 0 (shl/shr) or never wrote it (rol/ror). SAR-by-1 was already
correct (OF=0). These oracle-backed tests pin the fixed semantics against
Unicorn, and add SHLD/SHRD double-shift coverage with correct count==1 OF.
"""
import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lifter"))
sys.path.insert(0, str(ROOT / "daedalus"))

pytest.importorskip("iced_x86")
pytest.importorskip("unicorn")
pytest.importorskip("keystone")

import x64_lifter as L  # noqa: E402
import oracle  # noqa: E402
from keystone import Ks, KS_ARCH_X86, KS_MODE_64  # noqa: E402

_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_ALL = ("CF", "PF", "ZF", "SF", "OF")


def asm(src: str) -> bytes:
    code, _ = _KS.asm(src, addr=oracle.BASE)
    return bytes(code)


def _init(**regs):
    out = [0] * 16
    for name, val in regs.items():
        out[L.GPR_NAMES.index(name)] = val
    return out


# --- shl/shr/sar by 1: OF now defined ("value changed sign") ---------------
# Values chosen so OF lands on both 0 and 1 for each operation.
@pytest.mark.parametrize("dst,bits", [("rax", 64), ("eax", 32)])
@pytest.mark.parametrize("value", [
    0x0,
    0x1,
    (1 << 62),                       # shl: bit[w-2] set, bit[w-1] clear -> OF=1
    (1 << 63),                       # top bit set
    (3 << 62),                       # top two bits set -> shl OF=0
    0x7FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0x5555555555555555,
    0xAAAAAAAAAAAAAAAA,
])
def test_shl_shr_sar_by_one_defines_of(dst, bits, value):
    mask = (1 << bits) - 1
    for op in ("shl", "shr", "sar"):
        oracle.check(asm(f"{op} {dst}, 1"), init=_init(rax=value & mask),
                     flags=_ALL)


@pytest.mark.parametrize("op", ["shl", "shr", "sar"])
@pytest.mark.parametrize("value", [1 << 62, 1 << 63, 3 << 62, 0x8000000000000001, 0])
def test_shift_by_one_cl_count_one_defines_of(op, value):
    # CL == 1 must produce the SAME defined OF as the imm=1 form.
    oracle.check(asm(f"{op} rax, cl"), init=_init(rax=value, rcx=1), flags=_ALL)
    oracle.check(asm(f"{op} eax, cl"),
                 init=_init(rax=value & 0xFFFFFFFF, rcx=1), flags=_ALL)


# --- rol/ror by 1: OF now defined (rotates touch only CF and OF) ------------
@pytest.mark.parametrize("op", ["rol", "ror"])
@pytest.mark.parametrize("value", [
    0x1, 1 << 63, 0x8000000000000001, 0x4000000000000000,
    0xAAAAAAAAAAAAAAAA, 0x7FFFFFFFFFFFFFFF, 0xC000000000000000,
])
def test_rotate_by_one_defines_of(op, value):
    oracle.check(asm(f"{op} rax, 1"), init=_init(rax=value), flags=("CF", "OF"))
    oracle.check(asm(f"{op} eax, 1"),
                 init=_init(rax=value & 0xFFFFFFFF), flags=("CF", "OF"))
    # CL == 1 form
    oracle.check(asm(f"{op} rax, cl"), init=_init(rax=value, rcx=1),
                 flags=("CF", "OF"))
    oracle.check(asm(f"{op} eax, cl"),
                 init=_init(rax=value & 0xFFFFFFFF, rcx=1), flags=("CF", "OF"))


# --- 8/16-bit 1-bit shifts also get a defined OF ---------------------------
@pytest.mark.parametrize("dst", ["al", "ax"])
@pytest.mark.parametrize("op", ["shl", "shr", "sar"])
def test_narrow_shift_by_one_defines_of(dst, op):
    for value in (0x40, 0x80, 0xC0, 0x01, 0x00, 0x7F, 0xFF):
        oracle.check(asm(f"{op} {dst}, 1"),
                     init=_init(rax=0x1122334455660000 | value), flags=_ALL)


def test_of_is_not_wrongly_forced_when_liveness_keeps_it():
    # An OF-consumer after a 1-bit shift must observe the corrected OF.
    src = ("shl rax, 1; jo took; mov rbx, 10; jmp done; "
           "took: mov rbx, 20; done: nop")
    oracle.check(asm(src), init=_init(rax=1 << 62), flags=())   # OF=1 -> take
    oracle.check(asm(src), init=_init(rax=3 << 62), flags=())   # OF=0 -> skip


def test_fuzz_shift_rotate_by_one_of():
    rng = random.Random(0x0F0FBEEF)
    for _ in range(400):
        width_dst = rng.choice(["rax", "rbx", "rsi", "eax", "ebx", "esi",
                                "r8", "r9", "r8d", "r9d"])
        op = rng.choice(["shl", "shr", "sar", "rol", "ror"])
        form = rng.choice(["imm", "cl"])
        src = f"{op} {width_dst}, 1" if form == "imm" else f"{op} {width_dst}, cl"
        init = [rng.getrandbits(64) for _ in range(16)]
        init[L.GPR_NAMES.index("rcx")] = 1     # CL == 1 for the cl form
        flags = ("CF", "OF") if op in ("rol", "ror") else _ALL
        oracle.check(asm(src), init=init, flags=flags)


# ---------------------------------------------------------------------------
# SHLD / SHRD (double-precision shifts)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("op", ["shld", "shrd"])
@pytest.mark.parametrize("dst,src,bits", [
    ("rax", "rbx", 64), ("eax", "ebx", 32),
])
def test_shld_shrd_imm_count_one_defines_of(op, dst, src, bits):
    mask = (1 << bits) - 1
    for dv, sv in ((1 << 63, 1 << 63), (1 << 62, 0), (0, 1 << 63),
                   (0x8000000000000001, 0x7FFFFFFFFFFFFFFF),
                   (0xAAAAAAAAAAAAAAAA, 0x5555555555555555), (0, 0)):
        oracle.check(asm(f"{op} {dst}, {src}, 1"),
                     init=_init(rax=dv & mask, rbx=sv & mask), flags=_ALL)


@pytest.mark.parametrize("op", ["shld", "shrd"])
@pytest.mark.parametrize("dst,src,bits", [("rax", "rbx", 64), ("eax", "ebx", 32)])
@pytest.mark.parametrize("count", [1, 2, 5, 7, 16, 31])
def test_shld_shrd_imm_various_counts(op, dst, src, bits, count):
    if count >= bits:
        pytest.skip("count must be < operand width")
    mask = (1 << bits) - 1
    dv, sv = 0x123456789ABCDEF0 & mask, 0xFEDCBA9876543210 & mask
    # OF is defined only for count==1; check it there, otherwise leave undefined.
    flags = _ALL if count == 1 else ("CF", "PF", "ZF", "SF")
    oracle.check(asm(f"{op} {dst}, {src}, {count}"),
                 init=_init(rax=dv, rbx=sv), flags=flags)


@pytest.mark.parametrize("op", ["shld", "shrd"])
@pytest.mark.parametrize("dst,src,bits", [("rax", "rbx", 64), ("eax", "ebx", 32)])
@pytest.mark.parametrize("count", [0, 1, 3, 8, 31])
def test_shld_shrd_cl_forms(op, dst, src, bits, count):
    if count >= bits:
        pytest.skip("count must be < operand width")
    mask = (1 << bits) - 1
    dv, sv = 0xC0FFEE1234567890 & mask, 0x0F1E2D3C4B5A6978 & mask
    # count==0 is a full no-op; OF only defined at count==1.
    if count == 0:
        flags = _ALL
    elif count == 1:
        flags = _ALL
    else:
        flags = ("CF", "PF", "ZF", "SF")
    oracle.check(asm(f"{op} {dst}, {src}, cl"),
                 init=_init(rax=dv, rbx=sv, rcx=count), flags=flags)


def test_shld_shrd_cl_zero_count_preserves_all_flags():
    # A prior op sets known flags; a CL double-shift with masked count 0 must
    # leave dst AND every flag unchanged.
    oracle.check(asm("sub rax, rbx; shld rdx, rsi, cl"),
                 init=_init(rax=5, rbx=9, rdx=0xABCD, rsi=0x1234, rcx=0),
                 flags=_ALL)


def test_fuzz_shld_shrd():
    rng = random.Random(0x5D5D5D)
    regs64 = ["rax", "rbx", "rdx", "rsi", "rdi", "r8", "r9", "r10"]
    regs32 = ["eax", "ebx", "edx", "esi", "edi", "r8d", "r9d", "r10d"]
    for _ in range(400):
        op = rng.choice(["shld", "shrd"])
        is64 = rng.random() < 0.5
        pool, bits = (regs64, 64) if is64 else (regs32, 32)
        dst = rng.choice(pool)
        src = rng.choice([r for r in pool if r != dst])
        if rng.random() < 0.5:
            count = 1 if rng.random() < 0.5 else rng.randint(0, bits - 1)
            insn = f"{op} {dst}, {src}, {count}"
            use_cl = False
        else:
            count = 1 if rng.random() < 0.5 else rng.randint(0, bits - 1)
            insn = f"{op} {dst}, {src}, cl"
            use_cl = True
        init = [rng.getrandbits(64) for _ in range(16)]
        if use_cl:
            init[L.GPR_NAMES.index("rcx")] = count
        # OF is undefined unless the masked count is exactly 1.
        flags = _ALL if count == 1 else ("CF", "PF", "ZF", "SF")
        oracle.check(asm(insn), init=init, flags=flags)


@pytest.mark.parametrize("src", [
    "shld word ptr [rbx], ax, 1",   # memory destination
    "shld qword ptr [rbx], rax, cl",  # memory destination (CL)
    "shld ax, bx, 1",               # 16-bit form
    "shrd ax, bx, cl",              # 16-bit form (CL)
])
def test_shld_shrd_unsupported_forms_fail_closed(src):
    with pytest.raises(L.LiftUnsupported):
        L.lift_function(asm(src), base=oracle.BASE)
