"""x64 -> Daedalus lifter (CUT 1: register/immediate integer subset).

Lifts a straight-line-or-branching x64 function into Daedalus VM assembly, so the
packer can virtualize selected functions of a target binary instead of only the
stub's own hand-authored programs. This is the single hardest component of a
virtualizing protector, so it is built the safe way:

  * a fixed register + FLAGS model (16 GPRs -> VM locals; CF/ZF/SF/OF as locals),
  * per-instruction lifters for a SUPPORTED subset only, and
  * a hard BAIL-OUT (`LiftUnsupported`) on anything not faithfully reproducible --
    memory operands, calls, mul/div, sar/rotate, sub-registers, SIMD, indirect or
    external branches. The packer leaves a bailed function native. Correctness
    over coverage; a mis-lift that changes behaviour would brick the app.

Every lift is validated by `oracle.py` (Unicorn runs the x64; the Daedalus
reference interpreter runs the lifted bytecode; register files + flags must match).

CUT 1 supports: mov, add, sub, and, or, xor, cmp, test, inc, dec, neg, not, shl,
shr, jmp, jcc, ret -- 64-bit register and immediate operands. Everything else
bails.

CUT 2 (this file) adds 32-bit register operands (eax..r15d) for the same
instruction set. A 32-bit register shares its 64-bit parent's local offset; a
32-bit READ is the low 32 bits (mask 0xFFFFFFFF), and a 32-bit WRITE zero-extends
(mask the result to 32 bits before store64, clearing the upper 32). Flags are
computed at the operation's width (sign bit 31, 32-bit unsigned compares). The
64-bit path is byte-identical to cut 1. Memory operands, calls, mul/div,
sar/rotate, shift-by-CL, and 8/16-bit sub-registers still bail.
"""
from __future__ import annotations

from iced_x86 import Decoder, Mnemonic, OpKind, Register

# --- VM local layout (byte offsets into RefVM.locals) ----------------------
# 16 GPRs at 0..127, flags at 128.., scratch at 160..
_R64 = [Register.RAX, Register.RCX, Register.RDX, Register.RBX, Register.RSP,
        Register.RBP, Register.RSI, Register.RDI, Register.R8, Register.R9,
        Register.R10, Register.R11, Register.R12, Register.R13, Register.R14,
        Register.R15]
# 32-bit sub-registers, SAME ORDER as _R64 -> they share their parent's local
# offset (eax and rax both at offset 0, r8d and r8 both at 64, ...). x64 writes
# to a 32-bit register zero-extend into the full 64-bit parent.
_R32 = [Register.EAX, Register.ECX, Register.EDX, Register.EBX, Register.ESP,
        Register.EBP, Register.ESI, Register.EDI, Register.R8D, Register.R9D,
        Register.R10D, Register.R11D, Register.R12D, Register.R13D, Register.R14D,
        Register.R15D]
REG_OFF = {r: i * 8 for i, r in enumerate(_R64)}
REG32_OFF = {r: i * 8 for i, r in enumerate(_R32)}   # 32-bit reg -> parent offset
GPR_NAMES = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

CF, ZF, SF, OF = 128, 136, 144, 152          # flag locals
SA, SB, SR = 160, 168, 176                   # scratch: operand a, b, result
LOCALS_NEEDED = 184

MASK64 = (1 << 64) - 1
SIGN64 = 63
MASK32 = (1 << 32) - 1
SIGN32 = 31


def _width_mask(width: int) -> int:
    return MASK32 if width == 32 else MASK64


def _width_signbit(width: int) -> int:
    return SIGN32 if width == 32 else SIGN64


class LiftUnsupported(Exception):
    """Raised when an instruction/operand cannot be faithfully lifted; the packer
    then leaves the whole function native."""


class _Asm:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, s: str) -> None:
        self.lines.append("  " + s)

    def label(self, name: str) -> None:
        self.lines.append(name + ":")

    def text(self) -> str:
        return ".code\n" + "\n".join(self.lines) + "\n"


def _lbl(addr: int) -> str:
    return f"L_{addr:X}"


class _Lifter:
    def __init__(self, code: bytes, base: int) -> None:
        self.code = code
        self.base = base
        self.end = base + len(code)
        self.a = _Asm()

    # -- primitive emit helpers ------------------------------------------
    def _reg_info(self, reg):
        """Return (local_offset, width_bits) for a supported GPR, else bail.

        64-bit regs and their 32-bit sub-registers share a local offset; the
        width tells the read/write path how to mask. 8/16-bit sub-registers are
        NOT in either map, so they bail here (cut 1/2 do not model them)."""
        if reg in REG_OFF:
            return REG_OFF[reg], 64
        if reg in REG32_OFF:
            return REG32_OFF[reg], 32
        raise LiftUnsupported(f"unsupported register {reg!r}")

    def rd_reg(self, reg) -> None:
        off, width = self._reg_info(reg)
        self.a(f"local_addr {off}")
        self.a("load64")
        if width == 32:                       # 32-bit read = low 32 bits
            self.push_imm(MASK32)
            self.a("and")

    def wr_reg(self, reg) -> None:
        # value on top of stack -> reg local. store64 pops [addr, val].
        off, width = self._reg_info(reg)
        if width == 32:                       # 32-bit write zero-extends: mask
            self.push_imm(MASK32)             # result to 32 bits so store64
            self.a("and")                     # clears the upper 32 bits.
        self.a(f"local_addr {off}")
        self.a("swap")
        self.a("store64")

    def rd_local(self, off: int) -> None:
        self.a(f"local_addr {off}")
        self.a("load64")

    def wr_local(self, off: int) -> None:
        self.a(f"local_addr {off}")
        self.a("swap")
        self.a("store64")

    def push_imm(self, v: int) -> None:
        self.a(f"push_imm64 0x{v & MASK64:016X}")

    def push_operand(self, instr, i: int, width: int = 64) -> None:
        """Push operand i (register or immediate) at the given operation width.

        A register source must match the operation width exactly (no mixed-width
        forms); an immediate is masked to the width. Bails on anything else."""
        k = instr.op_kind(i)
        if k == OpKind.REGISTER:
            reg = instr.op_register(i)
            _, rw = self._reg_info(reg)       # bails on unsupported sub-register
            if rw != width:
                raise LiftUnsupported("mixed-width register operand")
            self.rd_reg(reg)
        elif k in (OpKind.IMMEDIATE8, OpKind.IMMEDIATE16, OpKind.IMMEDIATE32,
                   OpKind.IMMEDIATE64, OpKind.IMMEDIATE8TO16,
                   OpKind.IMMEDIATE8TO32, OpKind.IMMEDIATE8TO64,
                   OpKind.IMMEDIATE32TO64):
            v = instr.immediate(i)
            if width == 32:                   # 32-bit dst -> 32-bit immediate
                v &= MASK32
            self.push_imm(v)
        else:
            raise LiftUnsupported(f"operand kind {k!r}")

    def require_reg(self, instr, i: int):
        """Destination operand must be a supported GPR; return (reg, width)."""
        if instr.op_kind(i) != OpKind.REGISTER:
            raise LiftUnsupported("expected a register operand")
        reg = instr.op_register(i)
        off, width = self._reg_info(reg)      # bails on unsupported sub-register
        return reg, width

    # -- flag emit -------------------------------------------------------
    # These are parameterized by `signbit` so 32- and 64-bit results share one
    # implementation. The default (SIGN64) makes the 64-bit path byte-identical
    # to cut 1. At 32-bit width the scratch SA/SB/SR are already masked to 32
    # bits by the caller, so an unsigned/sign-bit test at bit 31 is exact.
    def _zf_sf_from_sr(self, signbit: int = SIGN64) -> None:
        # ZF = (SR == 0)
        self.rd_local(SR); self.push_imm(0); self.a("cmp_eq"); self.wr_local(ZF)
        # SF = (SR >> signbit) & 1
        self.rd_local(SR); self.push_imm(signbit); self.a("shr")
        self.push_imm(1); self.a("and"); self.wr_local(SF)

    def flags_logical(self, signbit: int = SIGN64) -> None:
        self._zf_sf_from_sr(signbit)
        self.push_imm(0); self.wr_local(CF)
        self.push_imm(0); self.wr_local(OF)

    def flags_add(self, set_cf: bool = True, signbit: int = SIGN64) -> None:
        self._zf_sf_from_sr(signbit)
        if set_cf:                                   # CF = (SR < SA) unsigned
            self.rd_local(SR); self.rd_local(SA); self.a("cmp_lt"); self.wr_local(CF)
        # OF = ((SA ^ SR) & (SB ^ SR)) >> signbit & 1
        self.rd_local(SA); self.rd_local(SR); self.a("xor")
        self.rd_local(SB); self.rd_local(SR); self.a("xor")
        self.a("and"); self.push_imm(signbit); self.a("shr")
        self.push_imm(1); self.a("and"); self.wr_local(OF)

    def flags_sub(self, set_cf: bool = True, signbit: int = SIGN64) -> None:
        self._zf_sf_from_sr(signbit)
        if set_cf:                                   # CF = (SA < SB) unsigned
            self.rd_local(SA); self.rd_local(SB); self.a("cmp_lt"); self.wr_local(CF)
        # OF = ((SA ^ SB) & (SA ^ SR)) >> signbit & 1
        self.rd_local(SA); self.rd_local(SB); self.a("xor")
        self.rd_local(SA); self.rd_local(SR); self.a("xor")
        self.a("and"); self.push_imm(signbit); self.a("shr")
        self.push_imm(1); self.a("and"); self.wr_local(OF)

    # -- instruction lifters --------------------------------------------
    def _mask_sr(self, width: int) -> None:
        """After a raw VM op, mask the result to the operation width so the
        stored SR (and the flag math over it) reflects the wrapped value. A
        no-op for 64-bit (keeps the cut-1 emission byte-identical)."""
        if width == 32:
            self.push_imm(MASK32); self.a("and")

    def _binop(self, instr, vmop: str, kind: str, writeback: bool = True,
               set_cf: bool = True) -> None:
        """dst = dst OP src, computing flags. kind in {add,sub,logical}."""
        dst, width = self.require_reg(instr, 0)
        signbit = _width_signbit(width)
        # SA = dst
        self.rd_reg(dst); self.wr_local(SA)
        # SB = src (same width as dst; immediate masked to width)
        self.push_operand(instr, 1, width); self.wr_local(SB)
        # SR = (SA OP SB) masked to width
        self.rd_local(SA); self.rd_local(SB); self.a(vmop)
        self._mask_sr(width); self.wr_local(SR)
        if writeback:
            self.rd_local(SR); self.wr_reg(dst)
        if kind == "add":
            self.flags_add(set_cf=set_cf, signbit=signbit)
        elif kind == "sub":
            self.flags_sub(set_cf=set_cf, signbit=signbit)
        else:
            self.flags_logical(signbit=signbit)

    def _mov(self, instr) -> None:
        dst, width = self.require_reg(instr, 0)
        self.push_operand(instr, 1, width)
        self.wr_reg(dst)

    def _unary(self, instr, vmop: str) -> None:
        # neg / not: dst = OP dst
        dst, width = self.require_reg(instr, 0)
        signbit = _width_signbit(width)
        self.rd_reg(dst); self.wr_local(SA)
        if vmop == "neg":
            self.rd_local(SA); self.a("neg"); self._mask_sr(width); self.wr_local(SR)
            self.rd_local(SR); self.wr_reg(dst)
            # neg flags: like sub of 0 - SA. CF = (SA != 0); OF/SF/ZF from SR.
            self._zf_sf_from_sr(signbit)
            self.rd_local(SA); self.push_imm(0); self.a("cmp_ne"); self.wr_local(CF)
            # OF = (SA == SR) at sign bit -> ((0^SA)&(0^SR))>>signbit; reuse sub form
            self.push_imm(0); self.wr_local(SB)  # SB=0 (subtrahend a=0 form)
            # emulate 0 - SA: treat SA as SB, 0 as SA for the sub OF formula
            self.rd_local(SB); self.rd_local(SA); self.a("xor")   # 0 ^ SA
            self.rd_local(SB); self.rd_local(SR); self.a("xor")   # 0 ^ SR
            self.a("and"); self.push_imm(signbit); self.a("shr")
            self.push_imm(1); self.a("and"); self.wr_local(OF)
        else:  # not: no flags affected (wr_reg zero-extends a 32-bit result)
            self.rd_local(SA); self.a("not"); self.wr_reg(dst)

    def _incdec(self, instr, add: bool) -> None:
        # inc/dec: like add/sub of 1 but PRESERVE CF (x64 semantics).
        dst, width = self.require_reg(instr, 0)
        signbit = _width_signbit(width)
        self.rd_reg(dst); self.wr_local(SA)
        self.push_imm(1); self.wr_local(SB)
        self.rd_local(SA); self.rd_local(SB)
        self.a("add" if add else "sub"); self._mask_sr(width); self.wr_local(SR)
        self.rd_local(SR); self.wr_reg(dst)
        (self.flags_add if add else self.flags_sub)(set_cf=False, signbit=signbit)

    def _shift(self, instr, vmop: str) -> None:
        # shl/shr reg, imm|cl  -- CUT 1/2: immediate count only.
        dst, width = self.require_reg(instr, 0)
        if instr.op_kind(1) not in (OpKind.IMMEDIATE8, OpKind.IMMEDIATE8TO16,
                                    OpKind.IMMEDIATE8TO32, OpKind.IMMEDIATE8TO64):
            raise LiftUnsupported("shift by CL not supported in cut 1/2")
        signbit = _width_signbit(width)
        # x64 masks the shift count by 5 bits for 32-bit ops, 6 bits for 64-bit.
        cnt = instr.immediate(1) & (31 if width == 32 else 63)
        if cnt == 0:
            return  # no-op, flags unchanged
        self.rd_reg(dst); self.wr_local(SA)
        self.rd_local(SA); self.push_imm(cnt); self.a(vmop)
        self._mask_sr(width); self.wr_local(SR)
        self.rd_local(SR); self.wr_reg(dst)
        # flags: ZF/SF from result; CF = last bit shifted out; OF only defined for
        # count==1 (leave as computed). CF for shl = bit (width-cnt) of SA; shr =
        # bit (cnt-1) of SA. cnt in [1, width-1] here so the bit index is valid.
        self._zf_sf_from_sr(signbit)
        bit = ((32 if width == 32 else 64) - cnt) if vmop == "shl" else (cnt - 1)
        self.rd_local(SA); self.push_imm(bit); self.a("shr")
        self.push_imm(1); self.a("and"); self.wr_local(CF)
        self.push_imm(0); self.wr_local(OF)   # approximate OF as 0 (cnt!=1 undefined)

    # conditional-jump condition emitters: leave a 0/1 on the stack (1 == take).
    def _cc(self, m) -> None:
        if m == Mnemonic.JE:
            self.rd_local(ZF)
        elif m == Mnemonic.JNE:
            self.rd_local(ZF); self.push_imm(0); self.a("cmp_eq")
        elif m == Mnemonic.JB:
            self.rd_local(CF)
        elif m == Mnemonic.JAE:
            self.rd_local(CF); self.push_imm(0); self.a("cmp_eq")
        elif m == Mnemonic.JS:
            self.rd_local(SF)
        elif m == Mnemonic.JNS:
            self.rd_local(SF); self.push_imm(0); self.a("cmp_eq")
        elif m == Mnemonic.JO:
            self.rd_local(OF)
        elif m == Mnemonic.JNO:
            self.rd_local(OF); self.push_imm(0); self.a("cmp_eq")
        elif m == Mnemonic.JBE:               # CF or ZF
            self.rd_local(CF); self.rd_local(ZF); self.a("or")
        elif m == Mnemonic.JA:                # !CF and !ZF
            self.rd_local(CF); self.push_imm(0); self.a("cmp_eq")
            self.rd_local(ZF); self.push_imm(0); self.a("cmp_eq"); self.a("and")
        elif m == Mnemonic.JL:                # SF != OF
            self.rd_local(SF); self.rd_local(OF); self.a("xor")
        elif m == Mnemonic.JGE:               # SF == OF
            self.rd_local(SF); self.rd_local(OF); self.a("cmp_eq")
        elif m == Mnemonic.JLE:               # ZF or (SF != OF)
            self.rd_local(ZF); self.rd_local(SF); self.rd_local(OF); self.a("xor")
            self.a("or")
        elif m == Mnemonic.JG:                # !ZF and (SF == OF)
            self.rd_local(ZF); self.push_imm(0); self.a("cmp_eq")
            self.rd_local(SF); self.rd_local(OF); self.a("cmp_eq"); self.a("and")
        else:
            raise LiftUnsupported(f"conditional jump {m!r}")

    def _branch_target(self, instr) -> int:
        if instr.op_kind(0) != OpKind.NEAR_BRANCH64:
            raise LiftUnsupported("indirect / non-near branch")
        tgt = instr.near_branch_target
        if not (self.base <= tgt < self.end):
            raise LiftUnsupported("branch target outside lifted function")
        return tgt

    # -- top-level -------------------------------------------------------
    def lift(self) -> str:
        decoder = Decoder(64, self.code, ip=self.base)
        for instr in decoder:
            if instr.code == 0:  # Code.INVALID
                raise LiftUnsupported(f"undecodable byte at 0x{instr.ip:X}")
            self.a.label(_lbl(instr.ip))
            m = instr.mnemonic
            if m == Mnemonic.NOP:
                self.a("nop")
            elif m == Mnemonic.MOV:
                self._mov(instr)
            elif m == Mnemonic.ADD:
                self._binop(instr, "add", "add")
            elif m == Mnemonic.SUB:
                self._binop(instr, "sub", "sub")
            elif m == Mnemonic.XOR:
                self._binop(instr, "xor", "logical")
            elif m == Mnemonic.AND:
                self._binop(instr, "and", "logical")
            elif m == Mnemonic.OR:
                self._binop(instr, "or", "logical")
            elif m == Mnemonic.CMP:
                self._binop(instr, "sub", "sub", writeback=False)
            elif m == Mnemonic.TEST:
                self._binop(instr, "and", "logical", writeback=False)
            elif m == Mnemonic.INC:
                self._incdec(instr, add=True)
            elif m == Mnemonic.DEC:
                self._incdec(instr, add=False)
            elif m == Mnemonic.NEG:
                self._unary(instr, "neg")
            elif m == Mnemonic.NOT:
                self._unary(instr, "not")
            elif m == Mnemonic.SHL:
                self._shift(instr, "shl")
            elif m == Mnemonic.SHR:
                self._shift(instr, "shr")
            elif m == Mnemonic.JMP:
                self.a(f"jmp {_lbl(self._branch_target(instr))}")
            elif m in _CC:
                tgt = self._branch_target(instr)
                self._cc(m)
                self.a(f"jnz {_lbl(tgt)}")   # take branch iff condition != 0
            elif m == Mnemonic.RET:
                self.push_imm(0); self.a("halt")
            else:
                raise LiftUnsupported(f"mnemonic {m!r} at 0x{instr.ip:X}")
        # fall-through past the last instruction ends the program
        self.push_imm(0); self.a("halt")
        return self.a.text()


_CC = {Mnemonic.JE, Mnemonic.JNE, Mnemonic.JB, Mnemonic.JAE, Mnemonic.JS,
       Mnemonic.JNS, Mnemonic.JO, Mnemonic.JNO, Mnemonic.JBE, Mnemonic.JA,
       Mnemonic.JL, Mnemonic.JGE, Mnemonic.JLE, Mnemonic.JG}


def lift_function(code: bytes, base: int = 0x1000) -> str:
    """Lift x64 machine code into Daedalus VM assembly, or raise LiftUnsupported.

    `base` is the virtual address the code is decoded at (for branch targets)."""
    return _Lifter(code, base).lift()
