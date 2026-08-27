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


@pytest.mark.parametrize("src", [
    "mov rax, [rbx]",       # memory source (64-bit)
    "mov [rbx], rax",       # memory dest (64-bit)
    "call rax",             # call
    "sar rax, 1",           # arithmetic shift (no VM op)
    "rol rax, 3",           # rotate
    "imul rax, rbx",        # multiply
    "movsb",                # string op
    # -- cut 2 supports 32-bit REGISTER operands, but these 32-bit forms must
    #    still bail (out of the register/immediate subset) --
    "mov eax, [rbx]",       # 32-bit memory source
    "mov [rbx], eax",       # 32-bit memory dest
    "sar eax, 1",           # 32-bit arithmetic shift (no VM op)
    "rol eax, 3",           # 32-bit rotate
    "ror eax, 2",           # 32-bit rotate
    "imul eax, ebx",        # 32-bit multiply
    "shl eax, cl",          # shift by CL (variable count)
    "shr eax, cl",          # shift by CL (variable count)
    # -- 8/16-bit sub-registers remain unsupported at any width --
    "mov al, 5",            # 8-bit sub-register
    "mov ax, 5",            # 16-bit sub-register
    "add al, bl",           # 8-bit ALU
    "add ax, bx",           # 16-bit ALU
    "movzx rax, al",        # zero-extend move
    "movsx eax, bl",        # sign-extend move
])
def test_bailouts(src):
    with pytest.raises(L.LiftUnsupported):
        L.lift_function(asm(src), base=oracle.BASE)
