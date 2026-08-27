#!/usr/bin/env python3
"""
daedalus_ref.py -- Reference interpreter + basic-block decomposition for the
Daedalus VM ISA.

This is the Python oracle for the SP5 differential harness: the assembler /
rolling codec is only trusted when the reference interpreter produces the
IDENTICAL result running the plaintext bytecode and running the
rolling-encrypted bytecode (see tests/test_rolling_bytecode.py). It is also the
build-time simulator the rolling encoder uses to reason about control flow.

Scope: the PURE ISA subset (stack / arithmetic / comparison / control flow /
locals+data addressing and locals/data memory ops). The domain-specific native
ops (n_sha256, n_hkdf, n_scatter_init, n_call_ptr, ...) are NOT modeled here --
they call into stub crypto / Win32 and have no meaning outside the loaded image.
A program that dispatches a native op raises NativeOpUnsupported; the rolling
*codec* round-trip (daedalus_rolling.decode == plaintext) is proven separately on
the real native-using programs, where it does not need to execute them.

Decode metadata (byte -> mnemonic/width/kind) is imported from daedalus_disasm so
there is exactly one source of truth for the wire format.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

# Single source of truth for the wire format.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from daedalus_disasm import OPCODE_TABLE  # noqa: E402  byte -> (mnemonic, width, kind)

MASK64 = (1 << 64) - 1
MAX_INSTR_LEN = 9  # push_imm64 = opcode + 8 operand bytes

# Opcodes that terminate a basic block (control leaves this instruction to a
# target and/or the next instruction becomes a new block leader).
_BRANCH = {'jmp', 'jz', 'jnz', 'call', 'ret', 'halt'}
_HAS_TARGET = {'jmp', 'jz', 'jnz', 'call'}

DVM_STACK_SIZE = 64
DVM_LOCAL_SIZE = 1024
DVM_RET_STACK_SIZE = 32

# Synthetic, stable base addresses handed out by local_addr / data_addr so the
# interpreter can model memory ops without a real address space.
_LOCAL_BASE = 0x0001_0000
_DATA_BASE = 0x0002_0000


class DaedalusError(Exception):
    """Structural VM fault (mirrors daedalus_vm_exec returning -1)."""


class NativeOpUnsupported(DaedalusError):
    """A native n_* op was dispatched; not modeled by the reference VM."""


def iter_instructions(code: bytes, optable=None):
    """Yield (offset, mnemonic, width, kind, operand) over a code stream.

    `optable` maps opcode byte -> (mnemonic, width, kind); defaults to the
    canonical table. Pass a shuffled table to decode per-build-renumbered
    (wire) bytecode -- boundaries/leaders are identical to canonical, but the
    branch-op identification needs the right table.

    Raises DaedalusError on an unknown opcode or a truncated operand -- the same
    conditions under which the C interpreter returns -1.
    """
    if optable is None:
        optable = OPCODE_TABLE
    pc = 0
    n = len(code)
    while pc < n:
        opc = code[pc]
        if opc not in optable:
            raise DaedalusError(f"unknown opcode 0x{opc:02X} at 0x{pc:04X}")
        mnemonic, width, kind = optable[opc]
        if pc + 1 + width > n:
            raise DaedalusError(f"truncated {mnemonic} at 0x{pc:04X}")
        operand = None
        if width == 1:
            operand = code[pc + 1]
        elif width == 2:
            operand = struct.unpack_from('<H', code, pc + 1)[0]
        elif width == 4:
            operand = struct.unpack_from('<I', code, pc + 1)[0]
        elif width == 8:
            operand = struct.unpack_from('<Q', code, pc + 1)[0]
        yield pc, mnemonic, width, kind, operand
        pc += 1 + width


def instruction_offsets(code: bytes):
    """Return the sorted list of valid instruction start offsets in `code`."""
    return [off for (off, _m, _w, _k, _o) in iter_instructions(code)]


def compute_leaders(code: bytes, optable=None) -> list[int]:
    """Basic-block leaders: offset 0, every branch target, and every offset
    immediately following a block-terminating instruction.

    Leaders are the resync points for the rolling codec: the accumulator is
    reseeded from (seed, leader_offset) at each leader, so a block's encryption
    is a function of the seed, its leader offset, and its own plaintext bytes --
    path-independent, hence always decodable regardless of which control-flow
    path reached it at runtime. `optable` (see iter_instructions) selects the
    canonical or a shuffled decode table.
    """
    leaders = {0}
    valid = set()
    for off, mnemonic, width, kind, operand in iter_instructions(code, optable):
        valid.add(off)
        nxt = off + 1 + width
        if mnemonic in _BRANCH:
            if nxt < len(code):
                leaders.add(nxt)          # instruction after a branch
        if mnemonic in _HAS_TARGET and operand is not None:
            leaders.add(operand)          # branch/call target
    # A target that is not a real instruction boundary is a malformed program;
    # surface it rather than silently keying a mid-instruction offset.
    for L in leaders:
        if L != len(code) and L not in valid and L != 0:
            raise DaedalusError(f"leader 0x{L:04X} is not an instruction boundary")
    return sorted(leaders)


# --------------------------------------------------------------------------
# Reference interpreter (pure ISA subset)
# --------------------------------------------------------------------------
class RefVM:
    """Faithful stack-machine interpreter for the pure Daedalus ISA subset.

    Mirrors daedalus_vm.c semantics: 64-bit little-endian values, sp = next free
    slot, structural faults -> DaedalusError (the C -1). Native ops are refused.
    Memory ops are honored only for addresses inside the synthetic locals/data
    windows handed out by local_addr / data_addr.
    """

    def __init__(self, code: bytes, data: bytes, args=None,
                 decoder=None):
        self.code = code
        self.data = bytes(data)
        self.args = list(args or [])
        self.stack: list[int] = []
        self.ret_stack: list[int] = []
        self.locals = bytearray(DVM_LOCAL_SIZE)
        self.pc = 0
        # `decoder`, when supplied, is a RollingDecoder-like object exposing
        # fetch(pc) -> (mnemonic, width, kind, operand, plain_bytes). When None
        # the interpreter decodes plaintext `code` directly.
        self.decoder = decoder
        self.trace: list[int] = []   # dispatched pc sequence (for diffing)

    # ---- stack helpers (fault on under/overflow, like the C) -------------
    def _push(self, v):
        if len(self.stack) >= DVM_STACK_SIZE:
            raise DaedalusError("stack overflow")
        self.stack.append(v & MASK64)

    def _pop(self):
        if not self.stack:
            raise DaedalusError("stack underflow")
        return self.stack.pop()

    def _mem_ref(self, addr, size):
        """Resolve a synthetic address to (buffer, index) or fault."""
        if _LOCAL_BASE <= addr < _LOCAL_BASE + DVM_LOCAL_SIZE:
            off = addr - _LOCAL_BASE
            if off + size > DVM_LOCAL_SIZE:
                raise DaedalusError("local OOB")
            return self.locals, off
        if _DATA_BASE <= addr < _DATA_BASE + len(self.data):
            off = addr - _DATA_BASE
            if off + size > len(self.data):
                raise DaedalusError("data OOB")
            return self.data, off
        raise DaedalusError(f"unmodeled memory address 0x{addr:X}")

    def _fetch(self):
        if self.decoder is not None:
            return self.decoder.fetch(self.pc)
        for off, mnemonic, width, kind, operand in iter_instructions(
                self.code[self.pc:self.pc + MAX_INSTR_LEN]):
            plain = self.code[self.pc:self.pc + 1 + width]
            return mnemonic, width, kind, operand, plain
        raise DaedalusError("fetch past end")

    def run(self, max_steps=1_000_000):
        """Execute to halt; return the HALT value. Faults raise DaedalusError."""
        steps = 0
        while True:
            steps += 1
            if steps > max_steps:
                raise DaedalusError("step limit (possible infinite loop)")
            if self.pc >= len(self.code):
                raise DaedalusError("ran past code without halt")
            mnemonic, width, kind, operand, _plain = self._fetch()
            self.trace.append(self.pc)
            nxt = self.pc + 1 + width
            m = mnemonic

            if m == 'halt':
                return int(self._pop() & MASK64)
            elif m == 'nop':
                pass
            elif m in ('push_imm8', 'push_imm16', 'push_imm32', 'push_imm64'):
                self._push(operand)
            elif m == 'pop':
                self._pop()
            elif m == 'dup':
                v = self._pop(); self._push(v); self._push(v)
            elif m == 'swap':
                b = self._pop(); a = self._pop(); self._push(b); self._push(a)
            elif m in ('add', 'sub', 'xor', 'and', 'or', 'shl', 'shr', 'mul'):
                b = self._pop(); a = self._pop()
                if m == 'add': r = a + b
                elif m == 'sub': r = a - b
                elif m == 'xor': r = a ^ b
                elif m == 'and': r = a & b
                elif m == 'or': r = a | b
                elif m == 'shl': r = a << (b & 63)
                elif m == 'shr': r = a >> (b & 63)
                else: r = a * b
                self._push(r)
            elif m in ('div', 'mod'):
                b = self._pop(); a = self._pop()
                if b == 0:
                    raise DaedalusError("div/mod by zero")
                self._push(a // b if m == 'div' else a % b)
            elif m == 'neg':
                self._push((-self._pop()) & MASK64)
            elif m == 'not':
                self._push((~self._pop()) & MASK64)
            elif m in ('cmp_eq', 'cmp_lt', 'cmp_gt', 'cmp_ge', 'cmp_ne'):
                b = self._pop(); a = self._pop()
                if m == 'cmp_eq': r = a == b
                elif m == 'cmp_lt': r = a < b
                elif m == 'cmp_gt': r = a > b
                elif m == 'cmp_ge': r = a >= b
                else: r = a != b
                self._push(1 if r else 0)
            elif m in ('load8', 'load16', 'load32', 'load64'):
                size = {'load8': 1, 'load16': 2, 'load32': 4, 'load64': 8}[m]
                addr = self._pop()
                buf, idx = self._mem_ref(addr, size)
                self._push(int.from_bytes(buf[idx:idx + size], 'little'))
            elif m in ('store8', 'store16', 'store32', 'store64'):
                size = {'store8': 1, 'store16': 2, 'store32': 4, 'store64': 8}[m]
                val = self._pop(); addr = self._pop()
                buf, idx = self._mem_ref(addr, size)
                if not isinstance(buf, bytearray):
                    raise DaedalusError("store into read-only data")
                buf[idx:idx + size] = (val & ((1 << (8 * size)) - 1)).to_bytes(size, 'little')
            elif m == 'push_arg':
                if operand >= len(self.args):
                    raise DaedalusError("arg index OOB")
                self._push(self.args[operand])
            elif m == 'local_addr':
                if operand >= DVM_LOCAL_SIZE:
                    raise DaedalusError("local_addr OOB")
                self._push(_LOCAL_BASE + operand)
            elif m == 'data_addr':
                if operand >= len(self.data):
                    raise DaedalusError("data_addr OOB")
                self._push(_DATA_BASE + operand)
            elif m == 'rot3':
                # [c b a] top=a -> [a c b] top=b  (mirror daedalus_vm.c ROT3)
                a = self._pop(); b = self._pop(); c = self._pop()
                self._push(a); self._push(c); self._push(b)
            elif m == 'pick':
                n = operand
                if n >= len(self.stack):
                    raise DaedalusError("pick OOB")
                self._push(self.stack[len(self.stack) - 1 - n])
            elif m == 'jmp':
                self.pc = operand
                continue
            elif m == 'jz':
                cond = self._pop()
                self.pc = operand if cond == 0 else nxt
                continue
            elif m == 'jnz':
                cond = self._pop()
                self.pc = operand if cond != 0 else nxt
                continue
            elif m == 'call':
                if len(self.ret_stack) >= DVM_RET_STACK_SIZE:
                    raise DaedalusError("ret stack overflow")
                self.ret_stack.append(nxt)
                self.pc = operand
                continue
            elif m == 'ret':
                if not self.ret_stack:
                    raise DaedalusError("ret stack underflow")
                self.pc = self.ret_stack.pop()
                continue
            elif m.startswith('n_'):
                raise NativeOpUnsupported(m)
            else:
                raise DaedalusError(f"unhandled opcode '{m}'")

            self.pc = nxt


def run_plaintext(blob: bytes, args=None):
    """Assemble-then-run convenience: split a [u16 ds][data][code] blob and
    interpret it in plaintext. Returns (halt_value, trace)."""
    ds = struct.unpack_from('<H', blob, 0)[0]
    data = blob[2:2 + ds]
    code = blob[2 + ds:]
    vm = RefVM(code, data, args)
    val = vm.run()
    return val, vm.trace
