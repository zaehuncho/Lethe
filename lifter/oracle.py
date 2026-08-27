"""Differential oracle for the x64 lifter.

Ground truth = Unicorn executing the original x64. Candidate = the Daedalus
reference interpreter executing the lifted bytecode. The 16 GPRs (and the
requested flags) must match exactly, or the lift is wrong. This is the ONLY thing
that makes the lifter trustworthy -- a mis-lift that changes behaviour would brick
a packed app, so nothing lands without an oracle pass.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "daedalus"))
sys.path.insert(0, str(ROOT / "lifter"))

import daedalus_asm  # noqa: E402
from daedalus_ref import RefVM  # noqa: E402
import x64_lifter as L  # noqa: E402

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
    UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    UC_X86_REG_EFLAGS)

MASK64 = (1 << 64) - 1
BASE = 0x1000
STACK = 0x200000
MEM_BASE = 0x400000       # writable region backing lifted memory operands
MEM_SIZE = 0x1000

_UC_REGS = [UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
            UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
            UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
            UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15]
FLAG_BIT = {"CF": 0, "ZF": 6, "SF": 7, "OF": 11}
_FLAG_LOCAL = {"CF": L.CF, "ZF": L.ZF, "SF": L.SF, "OF": L.OF}


def _default_init():
    return [0] * 16


def run_unicorn(code: bytes, init, mem=None):
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(BASE, 0x1000)
    mu.mem_map(STACK - 0x1000, 0x2000)
    if mem is not None:
        mu.mem_map(MEM_BASE, MEM_SIZE)
        mu.mem_write(MEM_BASE, bytes(mem))
    mu.mem_write(BASE, code)
    mu.reg_write(UC_X86_REG_EFLAGS, 0x2)   # minimal: CF/ZF/SF/OF = 0
    for reg, val in zip(_UC_REGS, init):
        mu.reg_write(reg, val & MASK64)
    mu.emu_start(BASE, BASE + len(code))
    regs = [mu.reg_read(reg) & MASK64 for reg in _UC_REGS]
    ef = mu.reg_read(UC_X86_REG_EFLAGS)
    flags = {f: (ef >> b) & 1 for f, b in FLAG_BIT.items()}
    out_mem = bytes(mu.mem_read(MEM_BASE, len(mem))) if mem is not None else None
    return regs, flags, out_mem


def run_daedalus(code: bytes, init, mem=None):
    blob = daedalus_asm.assemble(L.lift_function(code, base=BASE))
    ds = struct.unpack_from("<H", blob, 0)[0]
    data, prog = blob[2:2 + ds], blob[2 + ds:]
    vm = RefVM(prog, data, args=[],
               mem=(bytes(mem) if mem is not None else None), mem_base=MEM_BASE)
    for i in range(16):
        vm.locals[i * 8:i * 8 + 8] = (init[i] & MASK64).to_bytes(8, "little")
    vm.run()
    regs = [int.from_bytes(vm.locals[i * 8:i * 8 + 8], "little") for i in range(16)]
    flags = {f: int.from_bytes(vm.locals[off:off + 8], "little")
             for f, off in _FLAG_LOCAL.items()}
    out_mem = bytes(vm.mem) if mem is not None else None
    return regs, flags, out_mem


def check(code: bytes, init=None, flags=("CF", "ZF", "SF", "OF"), mem=None):
    """Assert the lifted bytecode matches Unicorn on regs, the given flags, and
    (when `mem` initial bytes are given) the final memory region. Raises
    AssertionError on any mismatch."""
    init = list(init) if init is not None else _default_init()
    ur, uf, um = run_unicorn(code, init, mem)
    dr, df, dm = run_daedalus(code, init, mem)
    for i in range(16):
        assert ur[i] == dr[i], (
            f"reg {L.GPR_NAMES[i]} mismatch: unicorn=0x{ur[i]:016X} "
            f"daedalus=0x{dr[i]:016X}")
    for f in flags:
        assert uf[f] == df[f], f"flag {f} mismatch: unicorn={uf[f]} daedalus={df[f]}"
    if mem is not None:
        assert um == dm, (f"memory mismatch:\n  unicorn ={um.hex()}\n"
                          f"  daedalus={dm.hex()}")
    return (ur, uf), (dr, df)
