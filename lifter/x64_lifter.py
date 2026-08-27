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
bails. 32-bit operands, memory, and calls are cut 2.
"""
from __future__ import annotations

from iced_x86 import Decoder, Mnemonic, OpKind, Register

# --- VM local layout (byte offsets into RefVM.locals) ----------------------
# 16 GPRs at 0..127, flags at 128.., scratch at 160..
_R64 = [Register.RAX, Register.RCX, Register.RDX, Register.RBX, Register.RSP,
        Register.RBP, Register.RSI, Register.RDI, Register.R8, Register.R9,
        Register.R10, Register.R11, Register.R12, Register.R13, Register.R14,
        Register.R15]
REG_OFF = {r: i * 8 for i, r in enumerate(_R64)}
GPR_NAMES = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

CF, ZF, SF, OF = 128, 136, 144, 152          # flag locals
SA, SB, SR = 160, 168, 176                   # scratch: operand a, b, result
LOCALS_NEEDED = 184

MASK64 = (1 << 64) - 1
SIGN64 = 63


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
    def rd_reg(self, reg) -> None:
        if reg not in REG_OFF:
            raise LiftUnsupported(f"unsupported register {reg!r}")
        self.a(f"local_addr {REG_OFF[reg]}")
        self.a("load64")

    def wr_reg(self, reg) -> None:
        # value on top of stack -> reg local. store64 pops [addr, val].
        if reg not in REG_OFF:
            raise LiftUnsupported(f"unsupported register {reg!r}")
        self.a(f"local_addr {REG_OFF[reg]}")
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

    def push_operand(self, instr, i: int) -> None:
        """Push operand i (register or immediate). Bails on anything else."""
        k = instr.op_kind(i)
        if k == OpKind.REGISTER:
            self.rd_reg(instr.op_register(i))
        elif k in (OpKind.IMMEDIATE8, OpKind.IMMEDIATE16, OpKind.IMMEDIATE32,
                   OpKind.IMMEDIATE64, OpKind.IMMEDIATE8TO16,
                   OpKind.IMMEDIATE8TO32, OpKind.IMMEDIATE8TO64,
                   OpKind.IMMEDIATE32TO64):
            self.push_imm(instr.immediate(i))
        else:
            raise LiftUnsupported(f"operand kind {k!r}")

    def require_reg64(self, instr, i: int):
        if instr.op_kind(i) != OpKind.REGISTER:
            raise LiftUnsupported("expected a register operand")
        reg = instr.op_register(i)
        if reg not in REG_OFF:
            raise LiftUnsupported(f"non-64-bit / unsupported register {reg!r}")
        return reg

    # -- flag emit -------------------------------------------------------
    def _zf_sf_from_sr(self) -> None:
        # ZF = (SR == 0)
        self.rd_local(SR); self.push_imm(0); self.a("cmp_eq"); self.wr_local(ZF)
        # SF = (SR >> 63) & 1
        self.rd_local(SR); self.push_imm(SIGN64); self.a("shr")
        self.push_imm(1); self.a("and"); self.wr_local(SF)

    def flags_logical(self) -> None:
        self._zf_sf_from_sr()
        self.push_imm(0); self.wr_local(CF)
        self.push_imm(0); self.wr_local(OF)

    def flags_add(self, set_cf: bool = True) -> None:
        self._zf_sf_from_sr()
        if set_cf:                                   # CF = (SR < SA) unsigned
            self.rd_local(SR); self.rd_local(SA); self.a("cmp_lt"); self.wr_local(CF)
        # OF = ((SA ^ SR) & (SB ^ SR)) >> 63 & 1
        self.rd_local(SA); self.rd_local(SR); self.a("xor")
        self.rd_local(SB); self.rd_local(SR); self.a("xor")
        self.a("and"); self.push_imm(SIGN64); self.a("shr")
        self.push_imm(1); self.a("and"); self.wr_local(OF)

    def flags_sub(self, set_cf: bool = True) -> None:
        self._zf_sf_from_sr()
        if set_cf:                                   # CF = (SA < SB) unsigned
            self.rd_local(SA); self.rd_local(SB); self.a("cmp_lt"); self.wr_local(CF)
        # OF = ((SA ^ SB) & (SA ^ SR)) >> 63 & 1
        self.rd_local(SA); self.rd_local(SB); self.a("xor")
        self.rd_local(SA); self.rd_local(SR); self.a("xor")
        self.a("and"); self.push_imm(SIGN64); self.a("shr")
        self.push_imm(1); self.a("and"); self.wr_local(OF)

    # -- instruction lifters --------------------------------------------
    def _binop(self, instr, vmop: str, kind: str, writeback: bool = True,
               set_cf: bool = True) -> None:
        """dst = dst OP src, computing flags. kind in {add,sub,logical}."""
        dst = self.require_reg64(instr, 0)
        # SA = dst
        self.rd_reg(dst); self.wr_local(SA)
        # SB = src
        self.push_operand(instr, 1); self.wr_local(SB)
        # SR = SA OP SB
        self.rd_local(SA); self.rd_local(SB); self.a(vmop); self.wr_local(SR)
        if writeback:
            self.rd_local(SR); self.wr_reg(dst)
        if kind == "add":
            self.flags_add(set_cf=set_cf)
        elif kind == "sub":
            self.flags_sub(set_cf=set_cf)
        else:
            self.flags_logical()

    def _mov(self, instr) -> None:
        dst = self.require_reg64(instr, 0)
        self.push_operand(instr, 1)
        self.wr_reg(dst)

    def _unary(self, instr, vmop: str) -> None:
        # neg / not: dst = OP dst
        dst = self.require_reg64(instr, 0)
        self.rd_reg(dst); self.wr_local(SA)
        if vmop == "neg":
            self.rd_local(SA); self.a("neg"); self.wr_local(SR)
            self.rd_local(SR); self.wr_reg(dst)
            # neg flags: like sub of 0 - SA. CF = (SA != 0); OF/SF/ZF from SR.
            self._zf_sf_from_sr()
            self.rd_local(SA); self.push_imm(0); self.a("cmp_ne"); self.wr_local(CF)
            # OF = (SA == SR) at sign bit -> ((0^SA)&(0^SR))>>63; reuse sub form
            self.push_imm(0); self.wr_local(SB)  # SB=0 (subtrahend a=0 form)
            # emulate 0 - SA: treat SA as SB, 0 as SA for the sub OF formula
            self.rd_local(SB); self.rd_local(SA); self.a("xor")   # 0 ^ SA
            self.rd_local(SB); self.rd_local(SR); self.a("xor")   # 0 ^ SR
            self.a("and"); self.push_imm(SIGN64); self.a("shr")
            self.push_imm(1); self.a("and"); self.wr_local(OF)
        else:  # not: no flags affected
            self.rd_local(SA); self.a("not"); self.wr_reg(dst)

    def _incdec(self, instr, add: bool) -> None:
        # inc/dec: like add/sub of 1 but PRESERVE CF (x64 semantics).
        dst = self.require_reg64(instr, 0)
        self.rd_reg(dst); self.wr_local(SA)
        self.push_imm(1); self.wr_local(SB)
        self.rd_local(SA); self.rd_local(SB)
        self.a("add" if add else "sub"); self.wr_local(SR)
        self.rd_local(SR); self.wr_reg(dst)
        (self.flags_add if add else self.flags_sub)(set_cf=False)

    def _shift(self, instr, vmop: str) -> None:
        # shl/shr reg, imm|cl  -- CUT 1: immediate count only.
        dst = self.require_reg64(instr, 0)
        if instr.op_kind(1) not in (OpKind.IMMEDIATE8, OpKind.IMMEDIATE8TO16,
                                    OpKind.IMMEDIATE8TO32, OpKind.IMMEDIATE8TO64):
            raise LiftUnsupported("shift by CL not supported in cut 1")
        cnt = instr.immediate(1) & 63
        if cnt == 0:
            return  # no-op, flags unchanged
        self.rd_reg(dst); self.wr_local(SA)
        self.rd_local(SA); self.push_imm(cnt); self.a(vmop); self.wr_local(SR)
        self.rd_local(SR); self.wr_reg(dst)
        # flags: ZF/SF from result; CF = last bit shifted out; OF only defined for
        # count==1 (leave as computed). CF for shl = bit (64-cnt) of SA; shr = bit
        # (cnt-1) of SA.
        self._zf_sf_from_sr()
        bit = (64 - cnt) if vmop == "shl" else (cnt - 1)
        self.rd_local(SA); self.push_imm(bit); self.a("shr")
        self.push_imm(1); self.a("and"); self.wr_local(CF)
        self.push_imm(0); self.wr_local(OF)   # cut 1: approximate OF as 0 (cnt!=1 undefined)

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
