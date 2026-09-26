"""RIP-relative lea / load / store coverage (T4).

RIP-relative operands are decoded to an RVA-based target and made ASLR-correct at
runtime by adding the live IMAGE_BASE local. These oracle-backed tests validate
the lift at image base 0 AND at nonzero (relocated) bases: Unicorn executes the
code at `image_base + rva` while the VM lifts at the RVA with IMAGE_BASE set, and
both must agree on registers and (for load/store) memory.
"""
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
from iced_x86 import Decoder  # noqa: E402
from keystone import Ks, KS_ARCH_X86, KS_MODE_64  # noqa: E402

_KS = Ks(KS_ARCH_X86, KS_MODE_64)
# image base 0 (preferred/no ASLR) and two relocated bases (page-aligned).
_IMAGE_BASES = (0, 0x140000000, 0x00007FF640000000)


def asm(src: str) -> bytes:
    code, _ = _KS.asm(src, addr=oracle.BASE)
    return bytes(code)


def _init(**regs):
    out = [0] * 16
    for name, val in regs.items():
        out[L.GPR_NAMES.index(name)] = val
    return out


def _target_rva(code: bytes) -> int:
    """The RVA the RIP-relative operand resolves to when decoded at BASE."""
    instr = next(iter(Decoder(64, code, ip=oracle.BASE)))
    assert instr.is_ip_rel_memory_operand
    return instr.memory_displacement


# --- lea (address-only; no dereference, so no mapped memory required) -------
@pytest.mark.parametrize("src", [
    "lea rax, [rip+0x4000]",
    "lea rax, [rip-0x100]",
    "lea rcx, [rip+0x123456]",
    "lea rdx, [rip+0]",
])
def test_rip_lea_64(src):
    code = asm(src)
    for image_base in _IMAGE_BASES:
        oracle.check(code, init=_init(rax=0xDEAD, rcx=0xBEEF, rdx=0xF00D),
                     flags=(), runtime_image_base=image_base)


@pytest.mark.parametrize("src", [
    "lea eax, [rip+0x4000]",
    "lea ecx, [rip-0x100]",
    "lea r8d, [rip+0x2222]",
])
def test_rip_lea_32_truncates(src):
    code = asm(src)
    for image_base in _IMAGE_BASES:
        # dirty upper parent bits must be cleared by the 32-bit write.
        oracle.check(code, init=_init(rax=0xFFFFFFFFFFFFFFFF,
                                      rcx=0xAAAAAAAAAAAAAAAA,
                                      r8=0x1234567800000000),
                     flags=(), runtime_image_base=image_base)


# --- load ------------------------------------------------------------------
_PAYLOAD = (0xCAFED00DDEADBEEF).to_bytes(8, "little") + \
    bytes(range(0x40, 0x40 + 56))


@pytest.mark.parametrize("src,dirty", [
    ("mov rax, [rip+0x4000]", 0x1111111111111111),
    ("mov eax, [rip+0x4000]", 0xFFFFFFFFFFFFFFFF),   # 32-bit load zero-extends
    ("movzx ecx, byte ptr [rip+0x4000]", 0),
    ("movsx rdx, word ptr [rip+0x4000]", 0),
])
def test_rip_load(src, dirty):
    code = asm(src)
    target = _target_rva(code)
    for image_base in _IMAGE_BASES:
        oracle.check(code, init=_init(rax=dirty, rcx=dirty, rdx=dirty),
                     flags=(), mem=_PAYLOAD, mem_base=image_base + target,
                     runtime_image_base=image_base)


# --- store -----------------------------------------------------------------
@pytest.mark.parametrize("src,init", [
    ("mov [rip+0x4000], rax", _init(rax=0x0123456789ABCDEF)),
    ("mov [rip+0x4000], eax", _init(rax=0x1122334455667788)),
    ("mov word ptr [rip+0x4000], cx", _init(rcx=0xBEEF)),
    ("mov byte ptr [rip+0x4000], dl", _init(rdx=0xA5)),
])
def test_rip_store(src, init):
    code = asm(src)
    target = _target_rva(code)
    for image_base in _IMAGE_BASES:
        oracle.check(code, init=init, flags=(),
                     mem=bytes(64), mem_base=image_base + target,
                     runtime_image_base=image_base)


# --- ALU with a RIP-relative memory source (folds through the same path) ----
def test_rip_alu_memory_source():
    code = asm("add rax, [rip+0x4000]")
    target = _target_rva(code)
    for image_base in _IMAGE_BASES:
        oracle.check(code, init=_init(rax=0x0F0F0F0F0F0F0F0F),
                     mem=_PAYLOAD, mem_base=image_base + target,
                     runtime_image_base=image_base)


def test_rip_relative_still_bails_with_segment_override():
    # fs:[rip+...] must remain a fail-closed bailout.
    with pytest.raises(L.LiftUnsupported):
        L.lift_function(asm("mov rax, fs:[rip+0x10]"), base=oracle.BASE)
