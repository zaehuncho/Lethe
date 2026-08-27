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


@pytest.mark.parametrize("src", [
    "mov rax, [rbx]",       # memory source
    "mov [rbx], rax",       # memory dest
    "call rax",             # call
    "mov eax, 5",           # 32-bit sub-register (cut 1 is 64-bit only)
    "sar rax, 1",           # arithmetic shift (no VM op)
    "rol rax, 3",           # rotate
    "imul rax, rbx",        # multiply
    "movsb",                # string op
])
def test_bailouts(src):
    with pytest.raises(L.LiftUnsupported):
        L.lift_function(asm(src), base=oracle.BASE)
