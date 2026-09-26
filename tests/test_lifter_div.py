"""DIV / IDIV coverage for the x64 lifter (T4).

8/16/32-bit unsigned and signed division: exact quotient/remainder into the
implicit AL/AH, AX/DX, EAX/EDX pairs (AX is the 8-bit dividend). Result flags are
architecturally undefined, so they are asserted with flags=() (no comparison).

Divide-by-zero AND quotient overflow (e.g. IDIV INT_MIN / -1) must deliver a
#DE: Unicorn raises, and the RefVM returns a nonzero HALT while committing NO
register. 64-bit DIV/IDIV stay out of scope (LiftUnsupported).
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


def asm(src: str) -> bytes:
    code, _ = _KS.asm(src, addr=oracle.BASE)
    return bytes(code)


def _init(**regs):
    out = [0] * 16
    for name, val in regs.items():
        out[L.GPR_NAMES.index(name)] = val
    return out


# --- directed unsigned DIV -------------------------------------------------
@pytest.mark.parametrize("insn,init", [
    # 8-bit: AX / r8 -> AL=quot, AH=rem (upper RAX preserved)
    ("div bl", _init(rax=0x1122334455660000 | 255, rbx=2)),        # 255/2 = 127 r1
    ("div cl", _init(rax=0x11223344556600FF, rcx=0x10)),           # 255/16
    ("div bl", _init(rax=0xAABBCCDDEEFF0000, rbx=1)),              # /1 (quotient=0)
    # 16-bit: DX:AX / r16 -> AX=quot, DX=rem
    ("div bx", _init(rax=0x11223344_0000FFFF, rdx=0xAABBCCDD_00000000, rbx=2)),
    ("div cx", _init(rax=0xFFFFFFFF_0000FFFF, rdx=0xFFFFFFFF_00000001, rcx=3)),
    # 32-bit: EDX:EAX / r32 -> EAX=quot, EDX=rem (both zero-extend)
    ("div ebx", _init(rax=0x00000000, rdx=0x00000001, rbx=2)),     # 2^32 / 2
    ("div ecx", _init(rax=0xFFFFFFFF, rdx=0x00001234, rcx=0x12345)),
    ("div ebx", _init(rax=0xDEADBEEF, rdx=0x00000000, rbx=0x1000)),
])
def test_div_unsigned_exact(insn, init):
    oracle.check(asm(insn), init=init, flags=())


# --- directed signed IDIV --------------------------------------------------
@pytest.mark.parametrize("insn,init", [
    # 8-bit signed: AX / r8
    ("idiv bl", _init(rax=0x11223344556600F9, rbx=2)),      # -7 / 2 = -3 r -1
    ("idiv bl", _init(rax=0x1122334455660007, rbx=0xFE)),   # 7 / -2 = -3 r 1
    ("idiv cl", _init(rax=0x11223344556600F9, rcx=0xFE)),   # -7 / -2 = 3 r -1
    ("idiv bl", _init(rax=0x0000000000000080, rbx=0x7F)),   # 128 / 127
    # 16-bit signed: DX:AX
    ("idiv bx", _init(rax=0x0000FFF9, rdx=0x0000FFFF, rbx=2)),      # -7/2
    ("idiv cx", _init(rax=0x00000007, rdx=0x00000000, rcx=0xFFFE)),  # 7/-2
    # 32-bit signed: EDX:EAX
    ("idiv ebx", _init(rax=0xFFFFFFF9, rdx=0xFFFFFFFF, rbx=2)),      # -7/2
    ("idiv ecx", _init(rax=0x00000007, rdx=0x00000000, rcx=0xFFFFFFFE)),  # 7/-2
    ("idiv ebx", _init(rax=0x80000000, rdx=0xFFFFFFFF, rbx=2)),      # INT_MIN/2 (ok)
    ("idiv ebx", _init(rax=0x7FFFFFFF, rdx=0x00000000, rbx=3)),
])
def test_idiv_signed_exact(insn, init):
    oracle.check(asm(insn), init=init, flags=())


# --- memory divisor (matches the MUL/IMUL memory-source convention) --------
# mem layout: [0]=3 (i8), [1]=0xFE(-2 i8), [2..3]=5 (i16), [4..5]=0xFFFE(-2 i16),
#             [8..11]=7 (i32), [12..15]=0xFFFFFFFE(-2 i32)
_DIV_MEM = bytes.fromhex(
    "03" "fe" "0500" "feff" "0000" "07000000" "feffffff"
) + bytes(32)


@pytest.mark.parametrize("insn,init", [
    ("div byte ptr [rsi]", _init(rax=0x1122334455660064, rsi=oracle.MEM_BASE)),   # 100/3
    ("idiv byte ptr [rsi+1]", _init(rax=0x112233445566FFF9, rsi=oracle.MEM_BASE)),  # -7/-2
    ("div word ptr [rsi+2]", _init(rax=0x000003E8, rdx=0x00000000, rsi=oracle.MEM_BASE)),  # 1000/5
    ("idiv word ptr [rsi+4]", _init(rax=0x0000FC18, rdx=0x0000FFFF, rsi=oracle.MEM_BASE)),  # -1000/-2
    ("div dword ptr [rsi+8]", _init(rax=0x000F4240, rdx=0x00000000, rsi=oracle.MEM_BASE)),  # 1e6/7
    ("idiv dword ptr [rsi+12]", _init(rax=0xFFF0BDC0, rdx=0xFFFFFFFF, rsi=oracle.MEM_BASE)),  # -1e6/-2
])
def test_div_memory_divisor(insn, init):
    oracle.check(asm(insn), init=init, flags=(), mem=_DIV_MEM)


# --- fault contract: divide-by-zero ---------------------------------------
@pytest.mark.parametrize("insn", [
    "div bl", "idiv bl", "div bx", "idiv bx", "div ebx", "idiv ebx",
])
def test_divide_by_zero_faults(insn):
    # divisor register left at 0 -> #DE in both engines, no register committed.
    oracle.check_fault(asm(insn), init=_init(rax=0x1234567812345678,
                                             rdx=0x9ABCDEF09ABCDEF0, rbx=0))


# --- fault contract: quotient overflow ------------------------------------
@pytest.mark.parametrize("insn,init", [
    # unsigned: quotient too large for the destination width
    ("div bl", _init(rax=0x000000000000FFFF, rbx=1)),              # 65535/1
    ("div bx", _init(rax=0x0000FFFF, rdx=0x0000FFFF, rbx=1)),
    ("div ebx", _init(rax=0x00000000, rdx=0xFFFFFFFF, rbx=1)),
    # signed: INT_MIN / -1 overflows for every width
    ("idiv bl", _init(rax=0x000000000000FF80, rbx=0xFF)),          # -128 / -1
    ("idiv bx", _init(rax=0x00008000, rdx=0x0000FFFF, rbx=0xFFFF)),  # -32768 / -1
    ("idiv ebx", _init(rax=0x80000000, rdx=0xFFFFFFFF, rbx=0xFFFFFFFF)),  # INT_MIN/-1
])
def test_quotient_overflow_faults(insn, init):
    oracle.check_fault(asm(insn), init=init)


# --- out-of-scope / fail-closed -------------------------------------------
@pytest.mark.parametrize("insn", ["div rbx", "idiv rbx", "div rcx", "idiv rcx"])
def test_div64_is_out_of_scope(insn):
    with pytest.raises(L.LiftUnsupported, match="architectural #DE"):
        L.lift_function(asm(insn), base=oracle.BASE)


@pytest.mark.parametrize("encoding", [
    "f6f3",      # lock is illegal here, so build lock div via raw bytes:
])
def test_lock_prefixed_divide_is_rejected(encoding):
    # F0 (LOCK) + F6 /6 (div bl) — LOCK on a non-memory RMW is invalid but must
    # fail closed rather than lift.
    with pytest.raises(L.LiftUnsupported):
        L.lift_function(bytes.fromhex("f0" + encoding), base=oracle.BASE)


# --- fuzz: unified non-fault + fault differential --------------------------
def _to_signed(value, bits):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _div_faults(signed_op, width, rax, rdx, divisor_reg_val):
    vu = divisor_reg_val & ((1 << width) - 1)
    precision = 2 * width
    if width == 8:
        du = rax & 0xFFFF
    elif width == 16:
        du = ((rdx & 0xFFFF) << 16) | (rax & 0xFFFF)
    else:
        du = ((rdx & 0xFFFFFFFF) << 32) | (rax & 0xFFFFFFFF)
    if not signed_op:
        if vu == 0:
            return True
        return (du // vu) >= (1 << width)
    v = _to_signed(vu, width)
    d = _to_signed(du, precision)
    if v == 0:
        return True
    q = abs(d) // abs(v)
    if (d < 0) != (v < 0):
        q = -q
    return not (-(1 << (width - 1)) <= q <= (1 << (width - 1)) - 1)


def test_fuzz_div_idiv_all_widths():
    rng = random.Random(0xD1D1DE)
    plans = [
        (8, "bl"), (8, "cl"), (8, "sil"),
        (16, "bx"), (16, "cx"), (16, "si"),
        (32, "ebx"), (32, "ecx"), (32, "esi"),
    ]
    divisor_index = {"bl": "rbx", "cl": "rcx", "sil": "rsi",
                     "bx": "rbx", "cx": "rcx", "si": "rsi",
                     "ebx": "rbx", "ecx": "rcx", "esi": "rsi"}
    faults = 0
    non_faults = 0
    for _ in range(1200):
        width, divisor_reg = rng.choice(plans)
        signed_op = rng.random() < 0.5
        mnemonic = "idiv" if signed_op else "div"
        init = [rng.getrandbits(64) for _ in range(16)]
        # bias toward small divisors so overflow / clean division both appear
        parent = divisor_index[divisor_reg]
        if rng.random() < 0.25:
            init[L.GPR_NAMES.index(parent)] = rng.choice([0, 1, 2, 0xFF, 0xFFFF])
        rax = init[L.GPR_NAMES.index("rax")]
        rdx = init[L.GPR_NAMES.index("rdx")]
        divisor_val = init[L.GPR_NAMES.index(parent)]
        src = f"{mnemonic} {divisor_reg}"
        if _div_faults(signed_op, width, rax, rdx, divisor_val):
            oracle.check_fault(asm(src), init=init)
            faults += 1
        else:
            oracle.check(asm(src), init=init, flags=())
            non_faults += 1
    # sanity: the corpus actually exercises both paths
    assert faults > 0 and non_faults > 0
