"""x64 lifter (cut 1): differential tests vs Unicorn (directed + fuzz) + bail-outs."""
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
    order = L.GPR_NAMES
    out = [0] * 16
    for name, val in regs.items():
        out[order.index(name)] = val
    return out


def test_mov_imm():
    oracle.check(asm("mov rax, 0x1234; mov rbx, 0xFF"), flags=())


def test_add_and_carry():
    oracle.check(asm("add rax, rbx"), init=_init(rax=10, rbx=5))
    oracle.check(asm("add rax, 1"), init=_init(rax=0xFFFFFFFFFFFFFFFF))  # CF+ZF


def test_sub_and_cmp():
    oracle.check(asm("sub rax, rbx"), init=_init(rax=5, rbx=9))
    oracle.check(asm("cmp rax, rbx"), init=_init(rax=5, rbx=9))


def test_logical():
    for op in ("and", "or", "xor"):
        oracle.check(asm(f"{op} rax, rbx"), init=_init(rax=0xF0F0, rbx=0x0FF0))
    oracle.check(asm("test rax, rax"), init=_init(rax=0))


def test_inc_dec_neg_not():
    oracle.check(asm("inc rax"), init=_init(rax=0x7FFFFFFFFFFFFFFF))  # OF overflow
    oracle.check(asm("dec rax"), init=_init(rax=0))                    # -> -1
    oracle.check(asm("neg rax"), init=_init(rax=5))
    oracle.check(asm("not rax"), init=_init(rax=0x1234), flags=())


def test_shift_by_one():
    oracle.check(asm("shl rax, 1"), init=_init(rax=0x8000000000000001),
                 flags=("CF", "ZF", "SF"))
    oracle.check(asm("shr rax, 1"), init=_init(rax=3), flags=("CF", "ZF", "SF"))


def test_branch_taken_and_not():
    src = ("cmp rax, rbx; jl less; mov rcx, 100; jmp done; "
           "less: mov rcx, 200; done: nop")
    oracle.check(asm(src), init=_init(rax=1, rbx=9), flags=())   # rax<rbx -> take
    oracle.check(asm(src), init=_init(rax=9, rbx=1), flags=())   # rax>rbx -> skip


def test_fuzz_alu():
    rng = random.Random(0xC0FFEE)
    ops = ["add", "sub", "and", "or", "xor"]
    dsts = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi"]
    for _ in range(300):
        lines = []
        for _ in range(rng.randint(1, 6)):
            op, dst = rng.choice(ops), rng.choice(dsts)
            if rng.random() < 0.5:
                src = rng.choice(dsts)
            else:
                src = str(rng.randint(-(2 ** 31), 2 ** 31 - 1))
            lines.append(f"{op} {dst}, {src}")
        init = [rng.getrandbits(64) for _ in range(16)]
        oracle.check(asm("; ".join(lines)), init=init)


# ---------------------------------------------------------------------------
# 32-bit register operands (cut 2)
# ---------------------------------------------------------------------------
def test_mov32_zero_extends_upper():
    # Writing a 32-bit register must ZERO the upper 32 bits of the parent.
    oracle.check(asm("mov eax, 5"),
                 init=_init(rax=0xFFFFFFFFFFFFFFFF), flags=())
    oracle.check(asm("mov ecx, edx"),
                 init=_init(rcx=0xDEADBEEFCAFEBABE, rdx=0x1122334499887766),
                 flags=())
    # reg->reg copy: only low 32 of edx survive, upper of rcx cleared.
    oracle.check(asm("mov r8d, r9d"),
                 init=_init(r8=0xAAAAAAAAAAAAAAAA, r9=0x123456789ABCDEF0),
                 flags=())


def test_add32_carry_zero_and_zero_extend():
    # 0xFFFFFFFF + 1 -> 0 (32-bit), CF=1, ZF=1, SF=0, OF=0; upper zeroed.
    oracle.check(asm("add eax, 1"),
                 init=_init(rax=0x1234567800000000 | 0xFFFFFFFF))
    # source register's upper bits must be ignored (low-32 read).
    oracle.check(asm("add eax, ebx"),
                 init=_init(rax=0xDEADBEEF_FFFFFFFF, rbx=0x12345678_00000001))
    # no carry, no overflow.
    oracle.check(asm("add eax, ebx"), init=_init(rax=10, rbx=5))


def test_add32_signed_overflow():
    # 0x7FFFFFFF + 1 -> 0x80000000: OF=1, SF=1, ZF=0, CF=0.
    oracle.check(asm("add eax, 1"), init=_init(rax=0x7FFFFFFF))
    oracle.check(asm("add ecx, ecx"), init=_init(rcx=0x40000000))  # OF at bit31


def test_sub32_and_cmp32():
    # borrow: 5 - 9 -> CF=1, SF=1, OF=0.
    oracle.check(asm("sub eax, ebx"), init=_init(rax=5, rbx=9))
    # signed overflow on subtraction: INT32_MIN - 1.
    oracle.check(asm("sub eax, 1"), init=_init(rax=0x80000000))
    # cmp does NOT write back: dirty upper bits of rax must survive, and the
    # low-32 comparison still sets flags correctly.
    oracle.check(asm("cmp eax, ebx"),
                 init=_init(rax=0x99999999_00000005, rbx=9))
    oracle.check(asm("cmp eax, eax"), init=_init(rax=0x7FFFFFFF))  # ZF=1


def test_logical32():
    for op in ("and", "or", "xor"):
        oracle.check(asm(f"{op} eax, ebx"),
                     init=_init(rax=0xF0F0F0F0, rbx=0x0FF00FF0))
    # xor eax, eax zeroes the whole 64-bit parent and sets ZF.
    oracle.check(asm("xor eax, eax"), init=_init(rax=0xFFFFFFFFFFFFFFFF))
    # test sets SF from bit 31, clears CF/OF.
    oracle.check(asm("test eax, eax"), init=_init(rax=0x80000000))
    oracle.check(asm("test eax, ebx"), init=_init(rax=0, rbx=123))  # ZF=1


def test_inc_dec32():
    # inc overflow: 0x7FFFFFFF -> 0x80000000 (OF=1, SF=1), CF preserved.
    oracle.check(asm("inc eax"), init=_init(rax=0x7FFFFFFF))
    # dec 0 -> 0xFFFFFFFF: SF=1, ZF=0, upper zeroed to 0x00000000FFFFFFFF.
    oracle.check(asm("dec eax"), init=_init(rax=0x1111111100000000))
    # inc to zero: 0xFFFFFFFF -> 0 sets ZF (inc does not touch CF).
    oracle.check(asm("inc ecx"), init=_init(rcx=0xFFFFFFFF))


def test_shift32():
    # shl eax, 1: MSB shifted out -> CF=1, result low, upper zeroed.
    oracle.check(asm("shl eax, 1"), init=_init(rax=0x80000001),
                 flags=("CF", "ZF", "SF"))
    # shl by 4: CF = bit (32-4)=bit28 of source.
    oracle.check(asm("shl eax, 4"), init=_init(rax=0x1FFFFFFF),
                 flags=("CF", "ZF", "SF"))
    # shr eax, 1: LSB -> CF; logical, so SF=0.
    oracle.check(asm("shr eax, 1"), init=_init(rax=3),
                 flags=("CF", "ZF", "SF"))
    # shr that zeros the result -> ZF=1.
    oracle.check(asm("shr edx, 1"), init=_init(rdx=1),
                 flags=("CF", "ZF", "SF"))
    # shl with dirty upper parent bits: result must still zero-extend.
    oracle.check(asm("shl eax, 8"), init=_init(rax=0xFFFFFFFF_00ABCDEF),
                 flags=("CF", "ZF", "SF"))


def test_neg_not32():
    # neg 5 -> 0xFFFFFFFB (upper zeroed): CF=1, SF=1, OF=0.
    oracle.check(asm("neg eax"), init=_init(rax=5))
    # neg INT32_MIN overflows: OF=1, CF=1, SF=1.
    oracle.check(asm("neg eax"), init=_init(rax=0x80000000))
    # neg 0 -> 0: CF=0, ZF=1.
    oracle.check(asm("neg ecx"), init=_init(rcx=0))
    # not affects no flags but zero-extends.
    oracle.check(asm("not eax"), init=_init(rax=0x1234FFFF_0000FFFF), flags=())


def test_branch32_flags():
    # branch driven by a 32-bit compare.
    src = ("cmp eax, ebx; jl less; mov ecx, 100; jmp done; "
           "less: mov ecx, 200; done: nop")
    oracle.check(asm(src), init=_init(rax=1, rbx=9), flags=())
    oracle.check(asm(src), init=_init(rax=9, rbx=1), flags=())
    # unsigned branch: jb keys off CF from a 32-bit sub.
    src2 = ("cmp eax, ebx; jb below; mov ecx, 1; jmp end; "
            "below: mov ecx, 2; end: nop")
    oracle.check(asm(src2), init=_init(rax=1, rbx=0xFFFFFFFF), flags=())


def test_mixed_width_sequence():
    # 32- and 64-bit ops interleaved on the same register file.
    src = ("mov eax, 0x10; add rax, 0x100; add eax, 0x1; mov ebx, eax")
    oracle.check(asm(src), init=_init(rax=0xFFFFFFFF00000000))


def test_fuzz_alu32():
    rng = random.Random(0x32B17)
    ops = ["add", "sub", "and", "or", "xor"]
    dsts = ["eax", "ebx", "ecx", "edx", "esi", "edi", "r8d", "r10d", "r14d"]
    for _ in range(300):
        lines = []
        for _ in range(rng.randint(1, 6)):
            op, dst = rng.choice(ops), rng.choice(dsts)
            if rng.random() < 0.5:
                src = rng.choice(dsts)
            else:
                src = str(rng.randint(-(2 ** 31), 2 ** 31 - 1))
            lines.append(f"{op} {dst}, {src}")
        init = [rng.getrandbits(64) for _ in range(16)]
        # last op is add/sub/and/or/xor -> all four flags are defined.
        oracle.check(asm("; ".join(lines)), init=init)


def test_fuzz_mixed_width():
    # interleave 32-bit and 64-bit ALU ops; the LAST op fixes the checked flags.
    rng = random.Random(0x5EED32)
    ops = ["add", "sub", "and", "or", "xor"]
    dsts64 = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r9", "r11"]
    dsts32 = ["eax", "ebx", "ecx", "edx", "esi", "edi", "r9d", "r11d"]
    for _ in range(300):
        lines = []
        for _ in range(rng.randint(1, 6)):
            op = rng.choice(ops)
            if rng.random() < 0.5:
                dst, pool = rng.choice(dsts32), dsts32
            else:
                dst, pool = rng.choice(dsts64), dsts64
            if rng.random() < 0.5:
                src = rng.choice(pool)      # same-width register
            else:
                src = str(rng.randint(-(2 ** 31), 2 ** 31 - 1))
            lines.append(f"{op} {dst}, {src}")
        init = [rng.getrandbits(64) for _ in range(16)]
        oracle.check(asm("; ".join(lines)), init=init)


# ---------------------------------------------------------------------------
# lea / imul / sar / rol / ror / shift-by-CL (cut 3)
# ---------------------------------------------------------------------------
def test_lea_addressing():
    # base + index*scale + disp; lea computes the address only (no deref, no flags)
    oracle.check(asm("lea rax, [rbx+rcx*4+8]"),
                 init=_init(rbx=0x1000, rcx=7), flags=())
    oracle.check(asm("lea rax, [rbx-4]"), init=_init(rbx=0x1000), flags=())
    oracle.check(asm("lea rax, [rcx*8+16]"), init=_init(rcx=3), flags=())
    oracle.check(asm("lea rdx, [rdx+rdx*1]"), init=_init(rdx=0x777), flags=())
    # negative displacement wraps mod 2^64
    oracle.check(asm("lea rax, [rbx-0x100]"), init=_init(rbx=0x80), flags=())
    # index == base register is fine (read twice)
    oracle.check(asm("lea rsi, [rdi+rdi*8]"), init=_init(rdi=0x123), flags=())


def test_lea32_truncates():
    # a 32-bit destination truncates the effective address to 32 bits (zero-ext)
    oracle.check(asm("lea eax, [rbx+rcx*2]"),
                 init=_init(rbx=0xFFFFFFFE, rcx=5), flags=())
    # dirty upper parent bits must be cleared by the 32-bit write, and the
    # 64-bit address must wrap into 32 bits before that write.
    oracle.check(asm("lea eax, [rbx+8]"),
                 init=_init(rax=0xDEADBEEF00000000, rbx=0x1_FFFFFFF9), flags=())


def test_imul_64():
    # no overflow: small product
    oracle.check(asm("imul rax, rbx"), init=_init(rax=3, rbx=5), flags=("CF", "OF"))
    # overflow: 2^32 * 2^32 = 2^64 does not fit signed-64
    oracle.check(asm("imul rax, rbx"),
                 init=_init(rax=0x100000000, rbx=0x100000000), flags=("CF", "OF"))
    # -1 * -1 = 1 fits -> no overflow
    oracle.check(asm("imul rax, rbx"),
                 init=_init(rax=(1 << 64) - 1, rbx=(1 << 64) - 1), flags=("CF", "OF"))
    # INT64_MIN * 2 overflows; INT64_MIN * 1 does not
    oracle.check(asm("imul rax, rbx"),
                 init=_init(rax=1 << 63, rbx=2), flags=("CF", "OF"))
    oracle.check(asm("imul rax, rbx"),
                 init=_init(rax=1 << 63, rbx=1), flags=("CF", "OF"))
    # 2-operand-with-immediate (iced normalizes it to a 3-operand form)
    oracle.check(asm("imul rax, 5"),
                 init=_init(rax=0x1999999999999999), flags=("CF", "OF"))
    # 3-operand form dst = src * imm
    oracle.check(asm("imul rax, rbx, 7"),
                 init=_init(rbx=0x2492492492492492), flags=("CF", "OF"))


def test_imul_32():
    # overflow at 32-bit width: 2^16 * 2^16 = 2^32
    oracle.check(asm("imul eax, ebx"),
                 init=_init(rax=0x10000, rbx=0x10000), flags=("CF", "OF"))
    oracle.check(asm("imul eax, ebx"), init=_init(rax=3, rbx=5), flags=("CF", "OF"))
    # (-1)*(-1)=1 at 32-bit -> no overflow; upper parent bits ignored + zero-ext
    oracle.check(asm("imul ecx, ecx"),
                 init=_init(rcx=0x1234_FFFFFFFF), flags=("CF", "OF"))
    oracle.check(asm("imul eax, ebx, 3"),
                 init=_init(rbx=0x30000000), flags=("CF", "OF"))
    # negative immediate is sign-extended before the multiply
    oracle.check(asm("imul eax, ebx, -2"),
                 init=_init(rbx=0x40000000), flags=("CF", "OF"))


@pytest.mark.parametrize(
    ("source", "initial"),
    [
        ("mul al", _init(rax=0x11223344556677FF)),
        ("imul al", _init(rax=0x1122334455667780)),
        ("mul bl", _init(rax=0x11223344556677FF, rbx=2)),
        ("imul cl", _init(rax=0x11223344556677F0, rcx=0xFE)),
        ("mul bx", _init(rax=0x112233445566FFFF, rbx=0xFFFF,
                         rdx=0xAABBCCDDEEFF0011)),
        ("imul dx", _init(rax=0x1122334455668000, rdx=0xAABBCCDDEEEE0002)),
        ("mul ebx", _init(rax=0xFFFFFFFF, rbx=0xFFFFFFFF,
                          rdx=0xFFFFFFFFFFFFFFFF)),
        ("imul edx", _init(rax=0x80000000, rdx=2)),
        ("mul rbx", _init(rax=0xFFFFFFFFFFFFFFFF, rbx=0xFFFFFFFFFFFFFFFF,
                          rdx=7)),
        ("imul rdx", _init(rax=0x8000000000000000, rdx=2)),
    ],
)
def test_one_operand_mul_imul_implicit_products(source, initial):
    # PF/ZF/SF are architecturally undefined; CF/OF exactly report whether the
    # upper half is zero (MUL) or a sign-extension of the lower half (IMUL).
    oracle.check(asm(source), init=initial, flags=("CF", "OF"))


@pytest.mark.parametrize(
    "source",
    [
        "mul byte ptr [rcx]",
        "imul word ptr [rcx+2]",
        "mul dword ptr [rcx+4]",
        "imul qword ptr [rcx+8]",
    ],
)
def test_one_operand_mul_imul_memory_sources(source):
    memory = bytes.fromhex(
        "fe00feff ffffffff feffffffffffffff 1122334455667788"
    )
    oracle.check(
        asm(source),
        init=_init(rax=0x80000000FFFFFFFF, rcx=oracle.MEM_BASE,
                   rdx=0xAABBCCDDEEFF0011),
        flags=("CF", "OF"),
        mem=memory,
    )


def test_implicit_output_register_is_evaluated_as_memory_base_before_writeback():
    memory = (0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    oracle.check(
        asm("mul qword ptr [rdx]"),
        init=_init(rax=0xFFFFFFFFFFFFFFF0, rdx=oracle.MEM_BASE),
        flags=("CF", "OF"),
        mem=memory,
    )


def test_fuzz_one_operand_mul_imul():
    rng = random.Random(0x4D554C31)
    registers = {
        8: ("bl", "cl", "dl", "sil", "r8b"),
        16: ("bx", "cx", "dx", "si", "r8w"),
        32: ("ebx", "ecx", "edx", "esi", "r8d"),
        64: ("rbx", "rcx", "rdx", "rsi", "r8"),
    }
    for width, sources in registers.items():
        for signed in (False, True):
            mnemonic = "imul" if signed else "mul"
            for _ in range(50):
                initial = [rng.getrandbits(64) for _ in range(16)]
                source = rng.choice(sources)
                oracle.check(
                    asm(f"{mnemonic} {source}"),
                    init=initial,
                    flags=("CF", "OF"),
                )


@pytest.mark.parametrize("source", ["div rcx", "idiv rcx"])
def test_division_fault_contract_remains_explicitly_rejected(source):
    with pytest.raises(L.LiftUnsupported, match="architectural #DE"):
        L.lift_function(asm(source), base=oracle.BASE)


@pytest.mark.parametrize("encoding", ["f048f7e3", "f048f7eb"])
def test_lock_prefixed_one_operand_multiply_is_rejected(encoding):
    with pytest.raises(L.LiftUnsupported):
        L.lift_function(bytes.fromhex(encoding), base=oracle.BASE)


def test_sar():
    # sign fill on a negative value; CF = last bit shifted out
    oracle.check(asm("sar rax, 4"), init=_init(rax=0x8000000000000001),
                 flags=("CF", "ZF", "SF"))
    # count 1 -> OF is defined (0) for sar
    oracle.check(asm("sar rax, 1"), init=_init(rax=0xFFFFFFFFFFFFFFFF),
                 flags=("CF", "ZF", "SF", "OF"))
    oracle.check(asm("sar rax, 63"), init=_init(rax=0x8000000000000000),
                 flags=("CF", "ZF", "SF"))
    # positive value shifts in zeros
    oracle.check(asm("sar rax, 8"), init=_init(rax=0x7F00), flags=("CF", "ZF", "SF"))


def test_sar32():
    oracle.check(asm("sar eax, 4"), init=_init(rax=0x80000000),
                 flags=("CF", "ZF", "SF"))
    oracle.check(asm("sar eax, 31"), init=_init(rax=0x40000000),
                 flags=("CF", "ZF", "SF"))
    # count 0: the value is written (zero-extends the parent), flags unchanged
    oracle.check(asm("sar eax, 0"), init=_init(rax=0xDEADBEEF_0000ABCD), flags=())
    # dirty upper parent bits cleared by the 32-bit write
    oracle.check(asm("sar eax, 2"), init=_init(rax=0xFFFFFFFF_80000010),
                 flags=("CF", "ZF", "SF"))


def test_rol_ror():
    oracle.check(asm("rol rax, 4"), init=_init(rax=0xF000000000000001), flags=("CF",))
    oracle.check(asm("ror rax, 4"), init=_init(rax=0x1), flags=("CF",))
    oracle.check(asm("rol rax, 60"), init=_init(rax=0x123456789ABCDEF), flags=("CF",))
    # wraparound near the width boundary
    oracle.check(asm("ror rax, 63"), init=_init(rax=0x2), flags=("CF",))


def test_rol_ror32():
    oracle.check(asm("rol eax, 1"), init=_init(rax=0x80000001), flags=("CF",))
    oracle.check(asm("ror eax, 3"), init=_init(rax=0x5), flags=("CF",))
    # count 0: value written (zero-extend), CF unchanged
    oracle.check(asm("rol eax, 0"), init=_init(rax=0xAAAAAAAA_12345678), flags=())
    oracle.check(asm("ror eax, 8"), init=_init(rax=0xFFFFFFFF_000000FF), flags=("CF",))


def test_shift_by_cl():
    oracle.check(asm("shl eax, cl"), init=_init(rax=0x00ABCDEF, rcx=8),
                 flags=("CF", "ZF", "SF"))
    oracle.check(asm("shr rax, cl"), init=_init(rax=0xFF00, rcx=4),
                 flags=("CF", "ZF", "SF"))
    oracle.check(asm("sar eax, cl"), init=_init(rax=0x80000000, rcx=4),
                 flags=("CF", "ZF", "SF"))
    oracle.check(asm("shl rax, cl"), init=_init(rax=1, rcx=63),
                 flags=("CF", "ZF", "SF"))
    oracle.check(asm("rol eax, cl"), init=_init(rax=0x80000001, rcx=1), flags=("CF",))
    oracle.check(asm("ror rax, cl"), init=_init(rax=0x1, rcx=4), flags=("CF",))


def test_shift_by_cl_zero_count():
    # CL masked count == 0: the destination is still written (a 32-bit op
    # zero-extends the parent) but every flag is left unchanged.
    oracle.check(asm("shl eax, cl"), init=_init(rax=0xFFFFFFFF_00001234, rcx=32),
                 flags=())
    oracle.check(asm("sar eax, cl"), init=_init(rax=0xFFFFFFFF_80000000, rcx=0),
                 flags=())
    oracle.check(asm("shr eax, cl"), init=_init(rax=0xFFFFFFFF_0000ABCD, rcx=64),
                 flags=())
    oracle.check(asm("rol rax, cl"), init=_init(rax=0xDEADBEEFCAFEBABE, rcx=64),
                 flags=())
    # 64-bit CL==0 leaves the value untouched too
    oracle.check(asm("shl rax, cl"), init=_init(rax=0x1122334455667788, rcx=0),
                 flags=())


def test_cl_zero_count_preserves_flags():
    # A prior op sets known flags; a CL shift whose masked count is 0 must leave
    # ALL of them unchanged (the destination edx is still written / zero-extended).
    oracle.check(asm("sub rax, rbx; shl edx, cl"),
                 init=_init(rax=5, rbx=9, rdx=0xAB, rcx=32),
                 flags=("CF", "ZF", "SF", "OF"))


def test_fuzz_imul():
    rng = random.Random(0x1EE7)
    regs64 = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10",
              "r11", "r12", "r13", "r14", "r15"]
    regs32 = ["eax", "ebx", "ecx", "edx", "esi", "edi", "r8d", "r9d", "r10d"]
    for _ in range(400):
        pool = regs64 if rng.random() < 0.5 else regs32
        d, s = rng.choice(pool), rng.choice(pool)
        form = rng.randint(0, 2)
        if form == 0:
            src = f"imul {d}, {s}"
        elif form == 1:
            src = f"imul {d}, {rng.randint(-(2 ** 31), 2 ** 31 - 1)}"
        else:
            src = f"imul {d}, {s}, {rng.randint(-(2 ** 31), 2 ** 31 - 1)}"
        init = [rng.getrandbits(64) for _ in range(16)]
        # SF/ZF/AF/PF are UNDEFINED for imul -> check only CF and OF.
        oracle.check(asm(src), init=init, flags=("CF", "OF"))


def test_fuzz_sar_and_shift_cl():
    rng = random.Random(0x5A12)
    regs64 = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9"]
    regs32 = ["eax", "ebx", "ecx", "edx", "esi", "edi", "r8d", "r9d"]
    for _ in range(400):
        d = rng.choice(regs64 if rng.random() < 0.5 else regs32)
        r = rng.random()
        if r < 0.34:
            src = f"sar {d}, {rng.randint(0, 40)}"     # imm (incl. 0 and > width)
        elif r < 0.5:
            src = f"sar {d}, cl"
        else:
            src = f"{rng.choice(['shl', 'shr'])} {d}, cl"
        init = [rng.getrandbits(64) for _ in range(16)]
        # A CL count may mask to 0 (flags unchanged) but CF/ZF/SF stay consistent
        # with Unicorn. OF is undefined for count != 1, so it is NOT checked.
        oracle.check(asm(src), init=init, flags=("CF", "ZF", "SF"))


def test_fuzz_rotate():
    rng = random.Random(0x0201)
    regs64 = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9"]
    regs32 = ["eax", "ebx", "ecx", "edx", "esi", "edi", "r8d", "r9d"]
    for _ in range(400):
        d = rng.choice(regs64 if rng.random() < 0.5 else regs32)
        op = rng.choice(["rol", "ror"])
        src = (f"{op} {d}, cl" if rng.random() < 0.5
               else f"{op} {d}, {rng.randint(0, 40)}")
        init = [rng.getrandbits(64) for _ in range(16)]
        # only CF is defined for a rotate by an arbitrary count
        oracle.check(asm(src), init=init, flags=("CF",))


def test_fuzz_lea():
    rng = random.Random(0x1EA0)
    regs64 = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9",
              "r10", "r11", "r12", "r13", "r14", "r15"]
    idx_pool = [r for r in regs64 if r != "rsp"]      # rsp cannot be an index
    dsts = regs64 + ["eax", "ebx", "ecx", "edx", "esi", "edi", "r8d", "r9d"]
    for _ in range(400):
        b = rng.choice(regs64 + [None])
        ix = rng.choice(idx_pool + [None])
        if b is None and ix is None:
            b = rng.choice(regs64)   # pure-disp assembles RIP-relative -> skip
        scale = rng.choice([1, 2, 4, 8])
        disp = rng.randint(-(2 ** 31), 2 ** 31 - 1)
        parts = []
        if b:
            parts.append(b)
        if ix:
            parts.append(f"{ix}*{scale}")
        parts.append(str(disp))
        mem = "+".join(parts).replace("+-", "-")
        src = f"lea {rng.choice(dsts)}, [{mem}]"
        init = [rng.getrandbits(64) for _ in range(16)]
        oracle.check(asm(src), init=init, flags=())


# ---------------------------------------------------------------------------
# memory operands (cut 4): load / store / ALU-with-memory-source
# ---------------------------------------------------------------------------
_MEM = bytes((i * 37 + 11) & 0xFF for i in range(256))


def test_mem_load_64_and_addressing():
    oracle.check(asm("mov rax, [rbx]"),
                 init=_init(rbx=oracle.MEM_BASE), flags=(), mem=_MEM)
    oracle.check(asm("mov rax, [rbx+16]"),
                 init=_init(rbx=oracle.MEM_BASE), flags=(), mem=_MEM)
    oracle.check(asm("mov rax, [rbx+rcx*4]"),
                 init=_init(rbx=oracle.MEM_BASE, rcx=3), flags=(), mem=_MEM)


def test_mem_load_32_zero_extends():
    oracle.check(asm("mov eax, [rbx+4]"),
                 init=_init(rax=0xFFFFFFFFFFFFFFFF, rbx=oracle.MEM_BASE),
                 flags=(), mem=_MEM)


def test_mem_store_64_and_32():
    oracle.check(asm("mov [rbx], rax"),
                 init=_init(rbx=oracle.MEM_BASE, rax=0xCAFEBABEDEADBEEF),
                 flags=(), mem=_MEM)
    oracle.check(asm("mov [rbx+8], eax"),
                 init=_init(rbx=oracle.MEM_BASE, rax=0x11223344AABBCCDD),
                 flags=(), mem=_MEM)


def test_alu_with_memory_source():
    for op in ("add", "sub", "and", "or", "xor"):
        oracle.check(asm(f"{op} rax, [rbx]"),
                     init=_init(rax=0x0F0F0F0F0F0F0F0F, rbx=oracle.MEM_BASE),
                     mem=_MEM)
    oracle.check(asm("cmp rax, [rbx]"),
                 init=_init(rax=0x0102030405060708, rbx=oracle.MEM_BASE),
                 mem=_MEM)
    oracle.check(asm("add eax, [rbx+4]"),
                 init=_init(rax=100, rbx=oracle.MEM_BASE), mem=_MEM)


def test_imul_with_memory_source():
    oracle.check(asm("imul rax, [rbx]"),
                 init=_init(rax=7, rbx=oracle.MEM_BASE),
                 flags=("CF", "OF"), mem=_MEM)


def test_mem_load_store_roundtrip():
    oracle.check(asm("mov rax, [rbx]; mov [rbx+32], rax"),
                 init=_init(rbx=oracle.MEM_BASE), flags=(), mem=_MEM)


def test_fuzz_mem_ops():
    rng = random.Random(0x4D454D)
    ops = ["add", "sub", "and", "or", "xor", "mov"]
    regs = ["rax", "rcx", "rdx", "rsi", "rdi"]
    for _ in range(200):
        lines = []
        for _ in range(rng.randint(1, 4)):
            op = rng.choice(ops)
            disp = rng.randrange(0, 200, 8)         # 8 bytes stays within 256
            reg = rng.choice(regs)
            if op == "mov" and rng.random() < 0.5:
                lines.append(f"mov [rbx+{disp}], {reg}")     # store
            else:
                lines.append(f"{op} {reg}, [rbx+{disp}]")    # load / ALU source
        init = [rng.getrandbits(64) for _ in range(16)]
        init[L.GPR_NAMES.index("rbx")] = oracle.MEM_BASE
        # mov never sets flags and every ALU here defines all four, so the final
        # flag state is identical in both engines.
        oracle.check(asm("; ".join(lines)), init=init, mem=_MEM)


@pytest.mark.parametrize("src", [
    "call rax",             # call
    "ret 8",                # callee stack cleanup cannot use the common thunk
    "movsb",                # string op
    # unsupported one-operand multiply encodings stay fail-closed
    "mul qword ptr fs:[rbx]",  # segment-overridden source
    # lea forms outside the faithful subset
    "lea rax, [rip+0x10]",  # RIP-relative lea
    "lea eax, [rip+8]",     # RIP-relative lea (32-bit dest)
    "lea rax, [ebx+ecx]",   # 32-bit-addressed lea (mod-2^32, not modeled)
    "lea rax, fs:[rbx]",    # segment-overridden lea
    # memory forms still outside the faithful subset
    "mov rax, fs:[rbx]",    # segment-overridden load
    # Atomic memory exchange and LOCK-prefixed RMW are not synthesized.
    "xchg [rbx], eax",
    "lock add dword ptr [rbx], 1",
])
def test_bailouts(src):
    with pytest.raises(L.LiftUnsupported):
        L.lift_function(asm(src), base=oracle.BASE)
