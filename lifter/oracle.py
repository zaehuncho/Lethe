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
FLAG_BIT = {"CF": 0, "PF": 2, "ZF": 6, "SF": 7, "OF": 11}
_FLAG_LOCAL = {"CF": L.CF, "PF": L.PF, "ZF": L.ZF, "SF": L.SF, "OF": L.OF}


def _default_init():
    return [0] * 16


def run_unicorn(code: bytes, init, mem=None, mem_base=MEM_BASE, code_base=BASE):
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    code_page = code_base & ~0xFFF
    code_size = ((code_base - code_page + max(len(code), 1) + 0xFFF) & ~0xFFF)
    mu.mem_map(code_page, code_size)
    mu.mem_map(STACK - 0x1000, 0x2000)
    if mem is not None:
        stack_lo = STACK - 0x1000
        stack_hi = STACK + 0x1000
        if not (stack_lo <= mem_base and mem_base + len(mem) <= stack_hi):
            map_base = mem_base & ~0xFFF
            map_end = (mem_base + max(len(mem), 1) + 0xFFF) & ~0xFFF
            mu.mem_map(map_base, map_end - map_base)
        mu.mem_write(mem_base, bytes(mem))
    mu.mem_write(code_base, code)
    mu.reg_write(UC_X86_REG_EFLAGS, 0x2)   # minimal: modeled arithmetic flags = 0
    for reg, val in zip(_UC_REGS, init):
        mu.reg_write(reg, val & MASK64)
    mu.emu_start(code_base, code_base + len(code))
    regs = [mu.reg_read(reg) & MASK64 for reg in _UC_REGS]
    ef = mu.reg_read(UC_X86_REG_EFLAGS)
    flags = {f: (ef >> b) & 1 for f, b in FLAG_BIT.items()}
    out_mem = bytes(mu.mem_read(mem_base, len(mem))) if mem is not None else None
    return regs, flags, out_mem


def run_daedalus(code: bytes, init, mem=None, mem_base=MEM_BASE,
                  lift_base=BASE, image_base=0):
    blob = daedalus_asm.assemble(L.lift_function(code, base=lift_base))
    ds = struct.unpack_from("<H", blob, 0)[0]
    data, prog = blob[2:2 + ds], blob[2 + ds:]
    vm = RefVM(prog, data, args=[],
               mem=(bytes(mem) if mem is not None else None), mem_base=mem_base)
    for i in range(16):
        vm.locals[i * 8:i * 8 + 8] = (init[i] & MASK64).to_bytes(8, "little")
    vm.locals[L.IMAGE_BASE:L.IMAGE_BASE + 8] = (
        image_base & MASK64
    ).to_bytes(8, "little")
    vm.run()
    regs = [int.from_bytes(vm.locals[i * 8:i * 8 + 8], "little") for i in range(16)]
    flags = {f: int.from_bytes(vm.locals[off:off + 8], "little")
             for f, off in _FLAG_LOCAL.items()}
    out_mem = bytes(vm.mem) if mem is not None else None
    return regs, flags, out_mem


def check(code: bytes, init=None, flags=("CF", "PF", "ZF", "SF", "OF"), mem=None,
          mem_base=MEM_BASE, *, code_rva=BASE, runtime_image_base=0):
    """Assert the lifted bytecode matches Unicorn on regs, the given flags, and
    (when `mem` initial bytes are given) the final memory region. Raises
    AssertionError on any mismatch.

    `code_rva` / `runtime_image_base` place the code at a specific RVA under a
    specific (possibly ASLR-relocated) image base: Unicorn executes at
    `runtime_image_base + code_rva` while the VM lifts at `code_rva` with the
    IMAGE_BASE local set to `runtime_image_base`. The defaults reproduce the
    original preferred-base behaviour exactly."""
    init = list(init) if init is not None else _default_init()
    code_base = (runtime_image_base + code_rva) & MASK64
    ur, uf, um = run_unicorn(code, init, mem, mem_base, code_base=code_base)
    dr, df, dm = run_daedalus(code, init, mem, mem_base,
                              lift_base=code_rva, image_base=runtime_image_base)
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


def check_function(code: bytes, init=None,
                   flags=("CF", "PF", "ZF", "SF", "OF"), *,
                   code_rva=BASE, runtime_image_base=0):
    """Differential-check a complete ABI-balanced function ending in RET.

    Unicorn executes the outer RET into a synthetic sentinel just beyond the
    function. The VM deliberately leaves that outer return for its native thunk,
    so the oracle normalizes Unicorn's final RSP by that single boundary pop.
    Internal CALL/RET stack traffic and the entire backing stack image still
    compare byte-for-byte.
    """
    init = list(init) if init is not None else _default_init()
    entry_rsp = init[L.GPR_NAMES.index("rsp")] & MASK64
    stack_base = STACK - 0x1000
    stack = bytearray(0x2000)
    if not stack_base <= entry_rsp <= stack_base + len(stack) - 8:
        raise ValueError("function oracle requires RSP inside its mapped stack")
    code_va = runtime_image_base + code_rva
    struct.pack_into("<Q", stack, entry_rsp - stack_base, code_va + len(code))

    ur, uf, um = run_unicorn(
        code, init, stack, stack_base, code_base=code_va
    )
    if ur[L.GPR_NAMES.index("rsp")] != entry_rsp + 8:
        raise AssertionError(
            "x64 function did not return with one balanced outer RET pop: "
            f"entry=0x{entry_rsp:016X} final=0x{ur[L.GPR_NAMES.index('rsp')]:016X}"
        )
    ur[L.GPR_NAMES.index("rsp")] = entry_rsp
    dr, df, dm = run_daedalus(
        code, init, stack, stack_base,
        lift_base=code_rva, image_base=runtime_image_base,
    )
    for i in range(16):
        assert ur[i] == dr[i], (
            f"reg {L.GPR_NAMES[i]} mismatch: unicorn=0x{ur[i]:016X} "
            f"daedalus=0x{dr[i]:016X}")
    for flag in flags:
        assert uf[flag] == df[flag], (
            f"flag {flag} mismatch: unicorn={uf[flag]} daedalus={df[flag]}"
        )
    assert um == dm, f"stack mismatch:\n  unicorn ={um.hex()}\n  daedalus={dm.hex()}"
    return (ur, uf), (dr, df)


def run_daedalus_capture(code: bytes, init, mem=None, mem_base=MEM_BASE,
                         lift_base=BASE, image_base=0):
    """Like run_daedalus but returns (halt_value, regs). Used to assert the fault
    contract: a faulting lift HALTs nonzero and commits no register."""
    blob = daedalus_asm.assemble(L.lift_function(code, base=lift_base))
    ds = struct.unpack_from("<H", blob, 0)[0]
    data, prog = blob[2:2 + ds], blob[2 + ds:]
    vm = RefVM(prog, data, args=[],
               mem=(bytes(mem) if mem is not None else None), mem_base=mem_base)
    for i in range(16):
        vm.locals[i * 8:i * 8 + 8] = (init[i] & MASK64).to_bytes(8, "little")
    vm.locals[L.IMAGE_BASE:L.IMAGE_BASE + 8] = (
        image_base & MASK64
    ).to_bytes(8, "little")
    halt = vm.run()
    regs = [int.from_bytes(vm.locals[i * 8:i * 8 + 8], "little") for i in range(16)]
    return halt, regs


def check_fault(code: bytes, init=None, mem=None, mem_base=MEM_BASE, *,
                code_rva=BASE, runtime_image_base=0):
    """Assert BOTH engines fault on `code`: Unicorn raises a CPU exception (a #DE)
    and the RefVM returns a nonzero HALT while committing NO register (every GPR
    equals its initial value). Returns the RefVM HALT value."""
    from unicorn import UcError

    init = list(init) if init is not None else _default_init()
    code_base = (runtime_image_base + code_rva) & MASK64
    try:
        run_unicorn(code, init, mem, mem_base, code_base=code_base)
    except UcError:
        pass
    else:
        raise AssertionError("unicorn did not fault as expected")

    halt, regs = run_daedalus_capture(
        code, init, mem, mem_base,
        lift_base=code_rva, image_base=runtime_image_base,
    )
    assert halt != 0, f"RefVM did not fault: HALT returned {halt}"
    for i in range(16):
        assert regs[i] == (init[i] & MASK64), (
            f"faulting lift committed reg {L.GPR_NAMES[i]}: "
            f"init=0x{init[i] & MASK64:016X} final=0x{regs[i]:016X}")
    return halt
