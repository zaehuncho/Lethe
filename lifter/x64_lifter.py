"""x64 -> Daedalus lifter for a fail-closed scalar integer subset.

Lifts a straight-line-or-branching x64 function into Daedalus VM assembly, so the
packer can virtualize selected functions of a target binary instead of only the
stub's own hand-authored programs. This is the single hardest component of a
virtualizing protector, so it is built the safe way:

  * a fixed register + FLAGS model (16 GPRs -> VM locals; CF/PF/ZF/SF/OF),
  * per-instruction lifters for a SUPPORTED subset only, and
  * a hard BAIL-OUT (`LiftUnsupported`) on anything not faithfully reproducible.
    The packer leaves a bailed function native. Correctness over coverage; a
    mis-lift that changes behaviour would brick the app.

Every lift is validated by `oracle.py` (Unicorn runs the x64; the Daedalus
reference interpreter runs the lifted bytecode; register files + flags must match).

The current scalar surface includes 8/16/32/64-bit low GPR reads and writes,
common arithmetic/logical operations, strict scalar memory sources, address
arithmetic, shifts/rotates and SHLD/SHRD at 32/64 bits, one-/two-/three-operand
IMUL, one-operand MUL, MOVZX/MOVSX/
MOVSXD, SETcc/CMOVcc, register XCHG, BSWAP, ADC, and SBB. High-8 aliases,
scalar memory destinations, immediate stores, parity conditions, and balanced
PUSH/POP/LEAVE stack frames are covered. Direct non-recursive calls to proven
instruction boundaries inside the same selected extent preserve architectural
stack effects and use shadow-validated VM returns. Atomic XCHG/LOCK forms,
SIMD, external/indirect/recursive calls, and unmodeled widths remain explicit
whole-function bailouts.
"""
from __future__ import annotations

from dataclasses import dataclass

from iced_x86 import Decoder, FlowControl, MemorySizeExt, Mnemonic, OpKind, Register

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
_R16 = [Register.AX, Register.CX, Register.DX, Register.BX, Register.SP,
        Register.BP, Register.SI, Register.DI, Register.R8W, Register.R9W,
        Register.R10W, Register.R11W, Register.R12W, Register.R13W, Register.R14W,
        Register.R15W]
_R8 = [Register.AL, Register.CL, Register.DL, Register.BL, Register.SPL,
       Register.BPL, Register.SIL, Register.DIL, Register.R8L, Register.R9L,
       Register.R10L, Register.R11L, Register.R12L, Register.R13L, Register.R14L,
       Register.R15L]
_HIGH8 = {Register.AH, Register.CH, Register.DH, Register.BH}
REG_OFF = {r: i * 8 for i, r in enumerate(_R64)}
REG32_OFF = {r: i * 8 for i, r in enumerate(_R32)}   # 32-bit reg -> parent offset
REG16_OFF = {r: i * 8 for i, r in enumerate(_R16)}
REG8_OFF = {r: i * 8 for i, r in enumerate(_R8)}
GPR_NAMES = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

CF, ZF, SF, OF = 128, 136, 144, 152          # legacy flag locals
SA, SB, SR = 160, 168, 176                   # scratch: operand a, b, result
# extra scratch for the wide (64x64->128) multiply used by imul overflow synthesis
T0, T1, T2, T3, T4, T5 = 184, 192, 200, 208, 216, 224
PF = 232                                      # parity flag (even low-byte parity)
CALL_DEPTH = 240                              # active internal CALL frames
CALL_RET_BASE = 248                           # 32 x architectural return RIP
CALL_STACK_CAPACITY = 32
IMAGE_BASE = CALL_RET_BASE + CALL_STACK_CAPACITY * 8
LOCALS_NEEDED = IMAGE_BASE + 8

MASK64 = (1 << 64) - 1
SIGN64 = 63
MASK32 = (1 << 32) - 1
SIGN32 = 31
MASK16 = (1 << 16) - 1
SIGN16 = 15
MASK8 = (1 << 8) - 1
SIGN8 = 7


def _width_mask(width: int) -> int:
    try:
        return {8: MASK8, 16: MASK16, 32: MASK32, 64: MASK64}[width]
    except KeyError as exc:
        raise LiftUnsupported(f"unsupported integer width {width}") from exc


def _width_signbit(width: int) -> int:
    try:
        return {8: SIGN8, 16: SIGN16, 32: SIGN32, 64: SIGN64}[width]
    except KeyError as exc:
        raise LiftUnsupported(f"unsupported integer width {width}") from exc


class LiftUnsupported(Exception):
    """Raised when an instruction/operand cannot be faithfully lifted; the packer
    then leaves the whole function native."""


@dataclass(frozen=True)
class InternalCallAnalysis:
    """Context-sensitive return classification for one selected extent.

    Daedalus has a separate return stack, while the lifted x64 register model
    must still reproduce CALL's physical stack write and RET's RSP movement.
    A RET therefore needs one static role: either an internal return or the
    selected function's outer return (which the native entry thunk performs).
    """

    internal_call_rvas: tuple[int, ...]
    internal_return_rvas: tuple[int, ...]
    top_level_return_rvas: tuple[int, ...]
    max_call_depth: int


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
        self._lblctr = 0

    def _new_label(self) -> str:
        """A unique intra-instruction label (for CL-shift zero-count guards).
        Prefixed so it never collides with the `L_<ip>` instruction labels."""
        self._lblctr += 1
        return f"g{self._lblctr}"

    # -- primitive emit helpers ------------------------------------------
    def _reg_info(self, reg):
        """Return (local_offset, width_bits) for a supported GPR, else bail.

        Every low sub-register shares its parent's 64-bit local. High-8 aliases
        remain rejected because their encoding depends on the absence of REX."""
        if reg in REG_OFF:
            return REG_OFF[reg], 64
        if reg in REG32_OFF:
            return REG32_OFF[reg], 32
        if reg in REG16_OFF:
            return REG16_OFF[reg], 16
        if reg in REG8_OFF:
            return REG8_OFF[reg], 8
        if reg in _HIGH8:
            raise LiftUnsupported(f"high-8 register {reg!r} is not supported")
        raise LiftUnsupported(f"unsupported register {reg!r}")

    def rd_reg(self, reg) -> None:
        off, width = self._reg_info(reg)
        self.a(f"local_addr {off}")
        self.a("load64")
        if width < 64:
            self.push_imm(_width_mask(width))
            self.a("and")

    def wr_reg(self, reg) -> None:
        # value on top of stack -> reg local. store64 pops [addr, val].
        off, width = self._reg_info(reg)
        mask = _width_mask(width)
        if width == 32:                       # 32-bit writes zero-extend
            self.push_imm(mask)
            self.a("and")
        elif width < 32:                      # 8/16-bit writes preserve parent
            self.push_imm(mask); self.a("and")
            self.a(f"local_addr {off}"); self.a("load64")
            self.push_imm((~mask) & MASK64); self.a("and")
            self.a("or")
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

    def _memory_width(self, instr) -> int:
        try:
            size = int(MemorySizeExt.size(instr.memory_size))
        except (TypeError, ValueError) as exc:
            raise LiftUnsupported("memory operand has no scalar width") from exc
        width = size * 8
        if width not in (8, 16, 32, 64):
            raise LiftUnsupported(f"unsupported memory width {width}")
        return width

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
            if width < 64:
                v &= _width_mask(width)
            self.push_imm(v)
        elif k == OpKind.MEMORY:
            # memory source: effective address -> load at the operation width.
            if self._memory_width(instr) != width:
                raise LiftUnsupported("memory operand width mismatch")
            self._emit_effective_address(instr)
            self.a(f"load{width}")
        else:
            raise LiftUnsupported(f"operand kind {k!r}")

    def require_reg(self, instr, i: int):
        """Destination operand must be a supported GPR; return (reg, width)."""
        if instr.op_kind(i) != OpKind.REGISTER:
            raise LiftUnsupported("expected a register operand")
        reg = instr.op_register(i)
        off, width = self._reg_info(reg)      # bails on unsupported sub-register
        return reg, width

    def _read_rmw_destination(self, instr):
        """Read operand zero into SA and preserve its destination geometry.

        Returns ``(register_or_none, width)``. For a memory destination the
        effective address is captured in T5 before any source evaluation, so a
        later store uses the exact address selected by the source instruction.
        LOCK-prefixed forms remain rejected because VM load/operate/store is not
        an atomic bus transaction.
        """
        kind = instr.op_kind(0)
        if kind == OpKind.REGISTER:
            dst, width = self.require_reg(instr, 0)
            self.rd_reg(dst); self.wr_local(SA)
            return dst, width
        if kind == OpKind.MEMORY:
            if instr.has_lock_prefix:
                raise LiftUnsupported("LOCK-prefixed memory RMW is not atomic in the VM")
            width = self._memory_width(instr)
            self._emit_effective_address(instr); self.wr_local(T5)
            self.rd_local(T5); self.a(f"load{width}"); self.wr_local(SA)
            return None, width
        raise LiftUnsupported("expected a register or memory destination")

    def _write_rmw_destination(self, dst, width: int) -> None:
        """Write SR to the destination captured by _read_rmw_destination."""
        if dst is not None:
            self.rd_local(SR); self.wr_reg(dst)
            return
        self.rd_local(T5); self.rd_local(SR); self.a(f"store{width}")

    # -- flag emit -------------------------------------------------------
    # These are parameterized by `signbit` so 32- and 64-bit results share one
    # implementation. The default (SIGN64) makes the 64-bit path byte-identical
    # to cut 1. At 32-bit width the scratch SA/SB/SR are already masked to 32
    # bits by the caller, so an unsigned/sign-bit test at bit 31 is exact.
    def _pf_from_sr(self) -> None:
        # PF is one for even parity in the low result byte. XOR-fold to one bit.
        self.rd_local(SR); self.push_imm(0xFF); self.a("and"); self.wr_local(T5)
        for shift in (4, 2, 1):
            self.rd_local(T5); self.rd_local(T5); self.push_imm(shift); self.a("shr")
            self.a("xor"); self.wr_local(T5)
        self.rd_local(T5); self.push_imm(1); self.a("and")
        self.push_imm(0); self.a("cmp_eq"); self.wr_local(PF)

    def _zf_sf_from_sr(self, signbit: int = SIGN64) -> None:
        # ZF = (SR == 0)
        self.rd_local(SR); self.push_imm(0); self.a("cmp_eq"); self.wr_local(ZF)
        # SF = (SR >> signbit) & 1
        self.rd_local(SR); self.push_imm(signbit); self.a("shr")
        self.push_imm(1); self.a("and"); self.wr_local(SF)
        self._pf_from_sr()

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
        if width < 64:
            self.push_imm(_width_mask(width)); self.a("and")

    def _binop(self, instr, vmop: str, kind: str, writeback: bool = True,
               set_cf: bool = True) -> None:
        """dst = dst OP src, computing flags. kind in {add,sub,logical}."""
        dst, width = self._read_rmw_destination(instr)
        signbit = _width_signbit(width)
        # SB = src (same width as dst; immediate masked to width)
        self.push_operand(instr, 1, width); self.wr_local(SB)
        # SR = (SA OP SB) masked to width
        self.rd_local(SA); self.rd_local(SB); self.a(vmop)
        self._mask_sr(width); self.wr_local(SR)
        if writeback:
            self._write_rmw_destination(dst, width)
        if kind == "add":
            self.flags_add(set_cf=set_cf, signbit=signbit)
        elif kind == "sub":
            self.flags_sub(set_cf=set_cf, signbit=signbit)
        else:
            self.flags_logical(signbit=signbit)

    def _mov(self, instr) -> None:
        if instr.op_kind(0) == OpKind.MEMORY:
            # store{w} pops [addr, val]. The decoded memory width makes register
            # and immediate stores unambiguous; push_operand validates both.
            width = self._memory_width(instr)
            self._emit_effective_address(instr)      # -> [addr]
            self.push_operand(instr, 1, width)        # -> [addr, val]
            self.a(f"store{width}")
            return
        dst, width = self.require_reg(instr, 0)
        self.push_operand(instr, 1, width)            # reg / imm / memory source
        self.wr_reg(dst)

    def _push(self, instr) -> None:
        if instr.op_count != 1:
            raise LiftUnsupported("push requires one operand")
        # x64 PUSH evaluates its source using the pre-decrement RSP. Operand
        # immediates are decoded by iced as sign-extended-to-64 forms.
        self.push_operand(instr, 0, 64); self.wr_local(SA)
        self.rd_reg(Register.RSP); self.push_imm(8); self.a("sub")
        self.wr_reg(Register.RSP)
        self.rd_reg(Register.RSP); self.rd_local(SA); self.a("store64")

    def _pop(self, instr) -> None:
        if instr.op_count != 1:
            raise LiftUnsupported("pop requires one operand")
        kind = instr.op_kind(0)
        if kind == OpKind.REGISTER:
            dst, width = self.require_reg(instr, 0)
            if width != 64:
                raise LiftUnsupported("only 64-bit pop registers are modeled")
        elif kind == OpKind.MEMORY:
            dst = None
            if self._memory_width(instr) != 64:
                raise LiftUnsupported("only 64-bit pop memory is modeled")
        else:
            raise LiftUnsupported("pop destination must be a register or memory")

        self.rd_reg(Register.RSP); self.a("load64"); self.wr_local(SA)
        self.rd_reg(Register.RSP); self.push_imm(8); self.a("add")
        self.wr_reg(Register.RSP)
        if dst is not None:
            # POP RSP writes the popped value after the architectural increment.
            self.rd_local(SA); self.wr_reg(dst)
        else:
            # Intel computes a POP memory effective address after incrementing RSP.
            self._emit_effective_address(instr)
            self.rd_local(SA); self.a("store64")

    def _leave(self, instr) -> None:
        if instr.op_count:
            raise LiftUnsupported("leave with explicit operands is not modeled")
        self.rd_reg(Register.RBP); self.wr_reg(Register.RSP)
        self.rd_reg(Register.RSP); self.a("load64"); self.wr_local(SA)
        self.rd_reg(Register.RSP); self.push_imm(8); self.a("add")
        self.wr_reg(Register.RSP)
        self.rd_local(SA); self.wr_reg(Register.RBP)

    def _extension_source_width(self, instr) -> int:
        kind = instr.op_kind(1)
        if kind == OpKind.REGISTER:
            _off, width = self._reg_info(instr.op_register(1))
            return width
        if kind == OpKind.MEMORY:
            return self._memory_width(instr)
        raise LiftUnsupported("extension source must be a register or memory")

    def _push_sign_extended(self, source_width: int) -> None:
        """Sign-extend the stack top from source_width to 64 bits."""
        source_mask = _width_mask(source_width)
        self.push_imm(source_mask); self.a("and"); self.wr_local(T0)
        self.rd_local(T0)
        self.rd_local(T0); self.push_imm(source_width - 1); self.a("shr")
        self.push_imm(1); self.a("and"); self.a("neg")
        self.push_imm((~source_mask) & MASK64); self.a("and")
        self.a("or")

    def _extend_move(self, instr, *, signed: bool, movsxd: bool = False) -> None:
        dst, dst_width = self.require_reg(instr, 0)
        source_width = self._extension_source_width(instr)
        if movsxd:
            if dst_width != 64 or source_width != 32:
                raise LiftUnsupported("movsxd requires a 64-bit destination and 32-bit source")
        elif source_width not in (8, 16) or dst_width <= source_width:
            raise LiftUnsupported("invalid movzx/movsx operand widths")
        self.push_operand(instr, 1, source_width)
        if signed:
            self._push_sign_extended(source_width)
        self.wr_reg(dst)

    def _setcc(self, instr, mnemonic) -> None:
        if instr.op_count != 1:
            raise LiftUnsupported("setcc requires one destination")
        kind = instr.op_kind(0)
        if kind == OpKind.REGISTER:
            dst, width = self.require_reg(instr, 0)
            if width != 8:
                raise LiftUnsupported("setcc register destination must be low-8")
            self._cc(mnemonic)
            self.wr_reg(dst)
            return
        if kind == OpKind.MEMORY:
            if self._memory_width(instr) != 8:
                raise LiftUnsupported("setcc memory destination must be one byte")
            self._emit_effective_address(instr)
            self._cc(mnemonic)
            self.a("store8")
            return
        raise LiftUnsupported("setcc destination must be low-8 register or memory")

    def _cmovcc(self, instr, mnemonic) -> None:
        dst, width = self.require_reg(instr, 0)
        if width not in (16, 32, 64):
            raise LiftUnsupported("cmovcc destination must be 16, 32, or 64 bits")
        self.rd_reg(dst); self.wr_local(SA)
        # Intel loads a memory source before testing the condition, so faults
        # and accesses are not hidden by a false predicate.
        self.push_operand(instr, 1, width); self.wr_local(SB)
        use_old = self._new_label()
        write = self._new_label()
        self._cc(mnemonic); self.a(f"jz {use_old}")
        self.rd_local(SB); self.a(f"jmp {write}")
        self.a.label(use_old); self.rd_local(SA)
        self.a.label(write); self.wr_reg(dst)

    def _xchg(self, instr) -> None:
        if instr.op_kind(0) != OpKind.REGISTER or instr.op_kind(1) != OpKind.REGISTER:
            raise LiftUnsupported("xchg memory forms require atomic semantics")
        left, width = self.require_reg(instr, 0)
        right, right_width = self.require_reg(instr, 1)
        if right_width != width:
            raise LiftUnsupported("xchg operands have different widths")
        self.rd_reg(left); self.wr_local(SA)
        self.rd_reg(right); self.wr_local(SB)
        self.rd_local(SB); self.wr_reg(left)
        self.rd_local(SA); self.wr_reg(right)

    def _bswap(self, instr) -> None:
        dst, width = self.require_reg(instr, 0)
        if width not in (32, 64):
            raise LiftUnsupported("bswap supports only 32-bit or 64-bit registers")
        self.rd_reg(dst); self.wr_local(SA)
        self.push_imm(0)
        byte_count = width // 8
        for source_byte in range(byte_count):
            self.rd_local(SA)
            if source_byte:
                self.push_imm(source_byte * 8); self.a("shr")
            self.push_imm(0xFF); self.a("and")
            destination_shift = (byte_count - 1 - source_byte) * 8
            if destination_shift:
                self.push_imm(destination_shift); self.a("shl")
            self.a("or")
        self.wr_reg(dst)

    def _adc_sbb(self, instr, *, subtract: bool) -> None:
        dst, width = self._read_rmw_destination(instr)
        signbit = _width_signbit(width)
        self.push_operand(instr, 1, width); self.wr_local(SB)
        self.rd_local(CF); self.push_imm(1); self.a("and"); self.wr_local(T0)

        self.rd_local(SA); self.rd_local(SB)
        self.a("sub" if subtract else "add")
        self._mask_sr(width); self.wr_local(T1)
        self.rd_local(T1); self.rd_local(T0)
        self.a("sub" if subtract else "add")
        self._mask_sr(width); self.wr_local(SR)
        self._write_rmw_destination(dst, width)

        if subtract:
            self.flags_sub(set_cf=False, signbit=signbit)
            self.rd_local(SA); self.rd_local(SB); self.a("cmp_lt"); self.wr_local(T2)
            self.rd_local(T1); self.rd_local(T0); self.a("cmp_lt")
        else:
            self.flags_add(set_cf=False, signbit=signbit)
            self.rd_local(T1); self.rd_local(SA); self.a("cmp_lt"); self.wr_local(T2)
            self.rd_local(SR); self.rd_local(T1); self.a("cmp_lt")
        self.rd_local(T2); self.a("or"); self.wr_local(CF)

    def _unary(self, instr, vmop: str) -> None:
        # neg / not: dst = OP dst
        dst, width = self._read_rmw_destination(instr)
        signbit = _width_signbit(width)
        if vmop == "neg":
            self.rd_local(SA); self.a("neg"); self._mask_sr(width); self.wr_local(SR)
            self._write_rmw_destination(dst, width)
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
        else:  # not: no flags affected
            self.rd_local(SA); self.a("not"); self._mask_sr(width); self.wr_local(SR)
            self._write_rmw_destination(dst, width)

    def _incdec(self, instr, add: bool) -> None:
        # inc/dec: like add/sub of 1 but PRESERVE CF (x64 semantics).
        dst, width = self._read_rmw_destination(instr)
        signbit = _width_signbit(width)
        self.push_imm(1); self.wr_local(SB)
        self.rd_local(SA); self.rd_local(SB)
        self.a("add" if add else "sub"); self._mask_sr(width); self.wr_local(SR)
        self._write_rmw_destination(dst, width)
        (self.flags_add if add else self.flags_sub)(set_cf=False, signbit=signbit)

    def _shift(self, instr, vmop: str) -> None:
        # shl/shr reg, imm|cl.
        dst, width = self.require_reg(instr, 0)
        if width < 32:
            raise LiftUnsupported("8/16-bit shifts are not yet modeled")
        if (instr.op_kind(1) == OpKind.REGISTER
                and instr.op_register(1) == Register.CL):
            self._shift_cl(dst, width, vmop)   # dynamic (CL) count -- cut 3
            return
        if instr.op_kind(1) not in (OpKind.IMMEDIATE8, OpKind.IMMEDIATE8TO16,
                                    OpKind.IMMEDIATE8TO32, OpKind.IMMEDIATE8TO64):
            raise LiftUnsupported("shift by non-immediate/CL not supported")
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

    def _read_cl_count(self, width: int) -> None:
        """SB = CL & (width-1). CL is the low 8 bits of rcx; since width-1 <= 63
        this equals (rcx & 0xFF) & (width-1)."""
        self.rd_local(REG_OFF[Register.RCX]); self.push_imm(width - 1)
        self.a("and"); self.wr_local(SB)

    def _shift_cl(self, dst, width: int, vmop: str) -> None:
        # shl/shr reg, CL -- dynamic count masked by (width-1). The VM shl/shr
        # take the count off the stack, so a dynamic count is a direct fit.
        signbit = _width_signbit(width)
        self._read_cl_count(width)                 # SB = cnt
        # Value is written unconditionally: x86 writes the destination even when
        # the masked count is 0, so a 32-bit shift zero-extends the parent no
        # matter the count (cnt==0 -> shift by 0 -> the low bits, zero-extended).
        self.rd_reg(dst); self.wr_local(SA)
        self.rd_local(SA); self.rd_local(SB); self.a(vmop)
        self._mask_sr(width); self.wr_local(SR)
        self.rd_local(SR); self.wr_reg(dst)
        # Flags are unchanged when cnt==0; guard the flag writes behind jz.
        skip = self._new_label()
        self.rd_local(SB); self.a(f"jz {skip}")
        self._zf_sf_from_sr(signbit)
        # CF = last bit shifted out: shl -> bit (width-cnt) of x; shr -> bit
        # (cnt-1) of x. In this branch cnt in [1, width-1] so the index is valid.
        self.rd_local(SA)
        if vmop == "shl":
            self.push_imm(width); self.rd_local(SB); self.a("sub")
        else:
            self.rd_local(SB); self.push_imm(1); self.a("sub")
        self.a("shr"); self.push_imm(1); self.a("and"); self.wr_local(CF)
        self.push_imm(0); self.wr_local(OF)        # OF defined only for cnt==1
        self.a.label(skip)

    def _shift_count(self, instr, operand_index: int = 1):
        """Classify a shift/rotate count operand: return ('imm', masked_cnt) or
        ('cl', None), or bail. `width` masking is applied by the caller."""
        k1 = instr.op_kind(operand_index)
        if (k1 == OpKind.REGISTER
                and instr.op_register(operand_index) == Register.CL):
            return "cl", None
        if k1 in (OpKind.IMMEDIATE8, OpKind.IMMEDIATE8TO16,
                  OpKind.IMMEDIATE8TO32, OpKind.IMMEDIATE8TO64):
            return "imm", instr.immediate(operand_index)
        raise LiftUnsupported("shift/rotate count must be an immediate or CL")

    def _double_shift(self, instr, *, left: bool) -> None:
        """Lift 32/64-bit SHLD or SHRD, including their defined flags.

        The source and destination are captured before any writeback so aliases,
        CL counts, and memory effective-address registers retain x64 evaluation
        order. Counts are masked architecturally. A zero count still performs a
        32-bit register write (therefore zero-extending its parent), but preserves
        all flags. OF is written only for count one; it is undefined otherwise.
        """
        if instr.op_count != 3:
            raise LiftUnsupported(
                "double shift requires destination, source, and count"
            )
        dst, width = self._read_rmw_destination(instr)
        if width not in (32, 64):
            raise LiftUnsupported("SHLD/SHRD support 32/64-bit destinations only")
        self.push_operand(instr, 1, width); self.wr_local(T0)

        count_kind, raw_count = self._shift_count(instr, 2)
        immediate = count_kind == "imm"
        count = (raw_count & (width - 1)) if immediate else None
        if not immediate:
            self._read_cl_count(width)

        def push_count() -> None:
            self.push_imm(count) if immediate else self.rd_local(SB)

        def emit_nonzero_result() -> None:
            if left:
                self.rd_local(SA); push_count(); self.a("shl")
                self.rd_local(T0); self.push_imm(width); push_count()
                self.a("sub"); self.a("shr"); self.a("or")
            else:
                self.rd_local(SA); push_count(); self.a("shr")
                self.rd_local(T0); self.push_imm(width); push_count()
                self.a("sub"); self.a("shl"); self.a("or")
            self._mask_sr(width); self.wr_local(SR)

        if immediate:
            if count == 0:
                self.rd_local(SA); self.wr_local(SR)
            else:
                emit_nonzero_result()
        else:
            zero = self._new_label()
            ready = self._new_label()
            self.rd_local(SB); self.a(f"jz {zero}")
            emit_nonzero_result()
            self.a(f"jmp {ready}")
            self.a.label(zero)
            self.rd_local(SA); self.wr_local(SR)
            self.a.label(ready)

        self._write_rmw_destination(dst, width)

        def emit_defined_flags() -> None:
            self._zf_sf_from_sr(_width_signbit(width))
            self.rd_local(SA)
            if left:
                self.push_imm(width); push_count(); self.a("sub")
            else:
                push_count(); self.push_imm(1); self.a("sub")
            self.a("shr"); self.push_imm(1); self.a("and"); self.wr_local(CF)

            def emit_of() -> None:
                if left:
                    self.rd_local(SR); self.push_imm(width - 1); self.a("shr")
                    self.push_imm(1); self.a("and"); self.rd_local(CF); self.a("xor")
                else:
                    self.rd_local(SA); self.push_imm(width - 1); self.a("shr")
                    self.rd_local(SR); self.push_imm(width - 1); self.a("shr")
                    self.a("xor"); self.push_imm(1); self.a("and")
                self.wr_local(OF)

            if immediate:
                if count == 1:
                    emit_of()
            else:
                not_one = self._new_label()
                self.rd_local(SB); self.push_imm(1); self.a("cmp_eq")
                self.a(f"jz {not_one}")
                emit_of()
                self.a.label(not_one)

        if immediate:
            if count != 0:
                emit_defined_flags()
        else:
            unchanged = self._new_label()
            self.rd_local(SB); self.a(f"jz {unchanged}")
            emit_defined_flags()
            self.a.label(unchanged)

    def _sar(self, instr) -> None:
        # sar reg, imm|cl -- arithmetic shift right (no VM sar; synthesized).
        dst, width = self.require_reg(instr, 0)
        if width < 32:
            raise LiftUnsupported("8/16-bit sar is not yet modeled")
        signbit = _width_signbit(width)
        mask = width - 1
        mask_val = _width_mask(width)
        src, raw = self._shift_count(instr)
        is_imm = src == "imm"
        cnt = (raw & mask) if is_imm else None
        if not is_imm:
            self._read_cl_count(width)              # SB = cnt

        def push_cnt():
            self.push_imm(cnt) if is_imm else self.rd_local(SB)

        # Value (count-0 safe, written unconditionally so 32-bit sar zero-extends):
        #   SR = (x >> n) | (sign_all & fill_mask)
        #   sign_all = 0 - sign(x)  (all-ones if x negative)
        #   fill_mask = ~(MASK >> n) & MASK  (top n bits; 0 when n==0)
        self.rd_reg(dst); self.wr_local(SA)
        self.rd_local(SA); push_cnt(); self.a("shr")               # x >> n
        self.rd_local(SA); self.push_imm(signbit); self.a("shr")
        self.push_imm(1); self.a("and"); self.a("neg")             # sign_all
        self.push_imm(mask_val); push_cnt(); self.a("shr")
        self.a("not"); self.push_imm(mask_val); self.a("and")      # fill_mask
        self.a("and")                                              # sign_all & fill
        self.a("or")                                               # | (x>>n)
        self._mask_sr(width); self.wr_local(SR)
        self.rd_local(SR); self.wr_reg(dst)

        # Flags: unchanged when n==0; else ZF/SF from result, CF = bit(n-1), OF=0.
        def emit_flags():
            self._zf_sf_from_sr(signbit)
            self.rd_local(SA)
            if is_imm:
                self.push_imm(cnt - 1)
            else:
                self.rd_local(SB); self.push_imm(1); self.a("sub")
            self.a("shr"); self.push_imm(1); self.a("and"); self.wr_local(CF)
            self.push_imm(0); self.wr_local(OF)

        if is_imm:
            if cnt != 0:
                emit_flags()
        else:
            skip = self._new_label()
            self.rd_local(SB); self.a(f"jz {skip}")
            emit_flags()
            self.a.label(skip)

    def _rotate(self, instr, direction: str) -> None:
        # rol/ror reg, imm|cl -- synthesized from shl/shr/or (no VM rotate op).
        dst, width = self.require_reg(instr, 0)
        if width < 32:
            raise LiftUnsupported("8/16-bit rotates are not yet modeled")
        mask = width - 1
        src, raw = self._shift_count(instr)
        is_imm = src == "imm"
        cnt = (raw & mask) if is_imm else None
        if not is_imm:
            self._read_cl_count(width)              # SB = cnt

        def push_cnt():
            self.push_imm(cnt) if is_imm else self.rd_local(SB)

        self.rd_reg(dst); self.wr_local(SA)
        # Value is count-0 safe thanks to the VM masking the shift count by 63:
        # at n==0 the (width-n) shift becomes a shift by `width`, which the VM
        # reduces so the two halves recombine to x. Written unconditionally so a
        # 32-bit rotate zero-extends the parent regardless of the count.
        if direction == "rol":                     # (x << n) | (x >> (width-n))
            self.rd_local(SA); push_cnt(); self.a("shl")
            self.rd_local(SA); self.push_imm(width); push_cnt(); self.a("sub")
            self.a("shr"); self.a("or")
        else:                                       # ror: (x >> n) | (x << (width-n))
            self.rd_local(SA); push_cnt(); self.a("shr")
            self.rd_local(SA); self.push_imm(width); push_cnt(); self.a("sub")
            self.a("shl"); self.a("or")
        self._mask_sr(width); self.wr_local(SR)
        self.rd_local(SR); self.wr_reg(dst)

        # Only CF is affected (ZF/SF untouched; OF defined only for count==1 and
        # left unwritten). Unchanged when cnt==0.
        def emit_cf():
            if direction == "rol":                 # CF = LSB of result
                self.rd_local(SR); self.push_imm(1); self.a("and"); self.wr_local(CF)
            else:                                  # ror: CF = MSB of result
                self.rd_local(SR); self.push_imm(width - 1); self.a("shr")
                self.push_imm(1); self.a("and"); self.wr_local(CF)

        if is_imm:
            if cnt != 0:
                emit_cf()
        else:
            skip = self._new_label()
            self.rd_local(SB); self.a(f"jz {skip}")
            emit_cf()
            self.a.label(skip)

    def _emit_effective_address(self, instr) -> None:
        """Push the effective address of the instruction's memory operand.
        Used by memory load (push_operand) and store (_mov). Bails on
        RIP-relative, segment overrides, or a non-64-bit base/index (32-bit
        addressing computes mod 2^32, which our 64-bit arithmetic would not
        reproduce)."""
        if instr.is_ip_rel_memory_operand:
            raise LiftUnsupported("RIP-relative memory operand")
        if instr.segment_prefix != Register.NONE:
            raise LiftUnsupported("segment-overridden memory operand")
        base = instr.memory_base
        index = instr.memory_index
        scale = instr.memory_index_scale
        disp = instr.memory_displacement & MASK64
        if base != Register.NONE and base not in REG_OFF:
            raise LiftUnsupported("memory base is not a supported 64-bit GPR")
        if index != Register.NONE and index not in REG_OFF:
            raise LiftUnsupported("memory index is not a supported 64-bit GPR")
        self.push_imm(disp)
        if base != Register.NONE:
            self.rd_reg(base); self.a("add")
        if index != Register.NONE:
            self.rd_reg(index); self.push_imm(scale & MASK64)
            self.a("mul"); self.a("add")

    def _lea(self, instr) -> None:
        # lea reg, [base + index*scale + disp] -- computes the effective address
        # only (NO dereference). No flags.
        dst, width = self.require_reg(instr, 0)
        if instr.op_kind(1) != OpKind.MEMORY:
            raise LiftUnsupported("lea without a memory operand")
        if instr.is_ip_rel_memory_operand:
            raise LiftUnsupported("lea RIP-relative memory")
        if instr.segment_prefix != Register.NONE:
            raise LiftUnsupported("lea with a segment override")
        base = instr.memory_base
        index = instr.memory_index
        scale = instr.memory_index_scale
        disp = instr.memory_displacement & MASK64
        # Require 64-bit base/index (or none): a 32-bit-addressed lea computes the
        # address mod 2^32, which our 64-bit arithmetic would not reproduce.
        if base != Register.NONE and base not in REG_OFF:
            raise LiftUnsupported("lea base is not a supported 64-bit GPR")
        if index != Register.NONE and index not in REG_OFF:
            raise LiftUnsupported("lea index is not a supported 64-bit GPR")
        # addr = disp + base + index*scale (mod 2^64). For a 32-bit destination
        # wr_reg masks to 32 bits (zero-extending the parent) -- exactly the x86
        # truncation of the 64-bit effective address.
        self.push_imm(disp)
        if base != Register.NONE:
            self.rd_reg(base); self.a("add")
        if index != Register.NONE:
            self.rd_reg(index); self.push_imm(scale & MASK64)
            self.a("mul"); self.a("add")
        self.wr_reg(dst)

    def _implicit_mul_registers(self, width: int):
        try:
            return {
                8: (Register.AL, Register.AX, None),
                16: (Register.AX, Register.AX, Register.DX),
                32: (Register.EAX, Register.EAX, Register.EDX),
                64: (Register.RAX, Register.RAX, Register.RDX),
            }[width]
        except KeyError as exc:
            raise LiftUnsupported(
                f"unsupported one-operand multiply width {width}"
            ) from exc

    def _one_operand_width(self, instr) -> int:
        if instr.op_count != 1:
            raise LiftUnsupported("one-operand multiply requires one source")
        if instr.has_lock_prefix:
            raise LiftUnsupported("LOCK-prefixed multiply is not supported")
        kind = instr.op_kind(0)
        if kind == OpKind.REGISTER:
            _off, width = self._reg_info(instr.op_register(0))
            return width
        if kind == OpKind.MEMORY:
            return self._memory_width(instr)
        raise LiftUnsupported("multiply source must be a register or memory")

    def _push_unsigned_high_64(self) -> None:
        """Push the exact high word of the unsigned SA*SB 128-bit product."""
        self.rd_local(SA); self.push_imm(0xFFFFFFFF); self.a("and"); self.wr_local(T0)
        self.rd_local(SA); self.push_imm(32); self.a("shr"); self.wr_local(T1)
        self.rd_local(SB); self.push_imm(0xFFFFFFFF); self.a("and"); self.wr_local(T2)
        self.rd_local(SB); self.push_imm(32); self.a("shr"); self.wr_local(T3)
        # cross = (aL*bL >> 32) + (aH*bL & mask) + (aL*bH & mask)
        self.rd_local(T0); self.rd_local(T2); self.a("mul")
        self.push_imm(32); self.a("shr")
        self.rd_local(T1); self.rd_local(T2); self.a("mul")
        self.push_imm(0xFFFFFFFF); self.a("and"); self.a("add")
        self.rd_local(T0); self.rd_local(T3); self.a("mul")
        self.push_imm(0xFFFFFFFF); self.a("and"); self.a("add")
        self.wr_local(T4)
        # high = aH*bH + (aH*bL >> 32) + (aL*bH >> 32) + (cross >> 32)
        self.rd_local(T1); self.rd_local(T3); self.a("mul")
        self.rd_local(T1); self.rd_local(T2); self.a("mul")
        self.push_imm(32); self.a("shr"); self.a("add")
        self.rd_local(T0); self.rd_local(T3); self.a("mul")
        self.push_imm(32); self.a("shr"); self.a("add")
        self.rd_local(T4); self.push_imm(32); self.a("shr"); self.a("add")

    def _push_signed_high_64(self) -> None:
        """Push the exact high word of the signed SA*SB 128-bit product."""
        self._push_unsigned_high_64(); self.wr_local(T5)
        self.rd_local(T5)
        self.rd_local(SA); self.push_imm(63); self.a("shr"); self.push_imm(1)
        self.a("and"); self.rd_local(SB); self.a("mul"); self.a("sub")
        self.rd_local(SB); self.push_imm(63); self.a("shr"); self.push_imm(1)
        self.a("and"); self.rd_local(SA); self.a("mul"); self.a("sub")

    def _implicit_mul(self, instr, *, signed: bool) -> None:
        """Lift one-operand MUL/IMUL with exact implicit accumulator outputs."""
        width = self._one_operand_width(instr)
        source_acc, low_dst, high_dst = self._implicit_mul_registers(width)
        self.rd_reg(source_acc); self.wr_local(SA)
        self.push_operand(instr, 0, width); self.wr_local(SB)

        self.rd_local(SA); self.rd_local(SB); self.a("mul")
        self._mask_sr(width); self.wr_local(SR)

        if width == 64:
            if signed:
                self._push_signed_high_64()
            else:
                self._push_unsigned_high_64()
            self.wr_local(T5)
        else:
            self.rd_local(SA)
            if signed:
                self._push_sign_extended(width)
            self.rd_local(SB)
            if signed:
                self._push_sign_extended(width)
            self.a("mul"); self.wr_local(T4)
            self.rd_local(T4); self.push_imm(width); self.a("shr")
            self.push_imm(_width_mask(width)); self.a("and"); self.wr_local(T5)

        if high_dst is None:
            self.rd_local(T5); self.push_imm(8); self.a("shl")
            self.rd_local(SR); self.a("or"); self.wr_reg(low_dst)
        else:
            self.rd_local(SR); self.wr_reg(low_dst)
            self.rd_local(T5); self.wr_reg(high_dst)

        if signed:
            if width == 64:
                self.rd_local(SR); self.push_imm(63); self.a("shr")
                self.push_imm(1); self.a("and"); self.a("neg")
                self.rd_local(T5); self.a("cmp_ne")
            else:
                self.rd_local(SR); self._push_sign_extended(width)
                self.rd_local(T4); self.a("cmp_ne")
        else:
            self.rd_local(T5); self.push_imm(0); self.a("cmp_ne")
        self._store_cf_of()

    def _imul(self, instr) -> None:
        # 2-op `imul r, r/imm` and 3-op `imul r, r/imm, imm`. dst = low `width`
        # bits of the signed product (VM mul gives the correct low bits).
        if instr.op_count == 1:
            self._implicit_mul(instr, signed=True)
            return
        dst, width = self.require_reg(instr, 0)
        if width < 32:
            raise LiftUnsupported("8/16-bit imul overflow is not yet modeled")
        n = instr.op_count
        if n == 2:                          # dst = op0 * op1
            self.push_operand(instr, 0, width); self.wr_local(SA)
            self.push_operand(instr, 1, width); self.wr_local(SB)
        elif n == 3:                        # dst = op1 * op2  (iced normalizes
            self.push_operand(instr, 1, width); self.wr_local(SA)   # `imul r,imm`
            self.push_operand(instr, 2, width); self.wr_local(SB)   # to 3 operands)
        else:
            raise LiftUnsupported("imul requires one, two, or three operands")
        # low result
        self.rd_local(SA); self.rd_local(SB); self.a("mul")
        self._mask_sr(width); self.wr_local(SR)
        self.rd_local(SR); self.wr_reg(dst)
        # CF = OF = 1 iff the full signed product does not fit in `width` bits.
        # SF/ZF/AF/PF are left UNDEFINED by Intel -- not written/checked.
        if width == 32:
            self._imul_of_32()
        else:
            self._imul_of_64()

    def _push_sext32(self, off: int) -> None:
        """Push the sign-extension to 64 bits of the 32-bit value at local `off`
        (which the caller has already masked to its low 32 bits)."""
        self.rd_local(off)                                  # x (top 32 zero)
        self.rd_local(off); self.push_imm(SIGN32); self.a("shr")
        self.push_imm(1); self.a("and"); self.a("neg")      # 0 or 0xFFFF..FFFF
        self.push_imm(32); self.a("shl")                    # fill high 32 (or 0)
        self.a("or")                                        # x | fill = sext(x)

    def _store_cf_of(self) -> None:
        """Top of stack holds the overflow bit -> CF and OF."""
        self.a("dup"); self.wr_local(CF); self.wr_local(OF)

    def _imul_of_32(self) -> None:
        # Sign-extend both 32-bit factors to 64 bits, take the exact 64-bit
        # product, and compare its sign-extended low 32 bits to the full product.
        self._push_sext32(SA); self._push_sext32(SB); self.a("mul")  # true product
        self.wr_local(T0)
        self._push_sext32(SR); self.rd_local(T0); self.a("cmp_ne")   # overflow?
        self._store_cf_of()

    def _imul_of_64(self) -> None:
        self._push_signed_high_64()
        # overflow iff signed hi != sign-extension of lo  (0 - (lo >> 63))
        self.rd_local(SR); self.push_imm(63); self.a("shr"); self.push_imm(1)
        self.a("and"); self.a("neg")
        self.a("cmp_ne")
        self._store_cf_of()

    # conditional-jump condition emitters: leave a 0/1 on the stack (1 == take).
    def _cc(self, m) -> None:
        condition = _CONDITION.get(m)
        if condition == "e":
            self.rd_local(ZF)
        elif condition == "ne":
            self.rd_local(ZF); self.push_imm(0); self.a("cmp_eq")
        elif condition == "b":
            self.rd_local(CF)
        elif condition == "ae":
            self.rd_local(CF); self.push_imm(0); self.a("cmp_eq")
        elif condition == "s":
            self.rd_local(SF)
        elif condition == "ns":
            self.rd_local(SF); self.push_imm(0); self.a("cmp_eq")
        elif condition == "o":
            self.rd_local(OF)
        elif condition == "no":
            self.rd_local(OF); self.push_imm(0); self.a("cmp_eq")
        elif condition == "p":
            self.rd_local(PF)
        elif condition == "np":
            self.rd_local(PF); self.push_imm(0); self.a("cmp_eq")
        elif condition == "be":               # CF or ZF
            self.rd_local(CF); self.rd_local(ZF); self.a("or")
        elif condition == "a":                # !CF and !ZF
            self.rd_local(CF); self.push_imm(0); self.a("cmp_eq")
            self.rd_local(ZF); self.push_imm(0); self.a("cmp_eq"); self.a("and")
        elif condition == "l":                # SF != OF
            self.rd_local(SF); self.rd_local(OF); self.a("xor")
        elif condition == "ge":               # SF == OF
            self.rd_local(SF); self.rd_local(OF); self.a("cmp_eq")
        elif condition == "le":               # ZF or (SF != OF)
            self.rd_local(ZF); self.rd_local(SF); self.rd_local(OF); self.a("xor")
            self.a("or")
        elif condition == "g":                # !ZF and (SF == OF)
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

    def _call(self, instr) -> None:
        """Emit a direct in-extent x64 CALL plus Daedalus control transfer."""
        target = self._branch_target(instr)
        return_ip = instr.ip + instr.len
        depth_ok = self._new_label()

        # The plan decodes at RVAs. The native bridge imports the loader-
        # relocated module base, keeping the physical return slot ASLR-correct.
        self.rd_local(IMAGE_BASE); self.push_imm(return_ip); self.a("add")
        self.wr_local(T5)

        # Keep a VM-local architectural shadow stack. DVM CALL owns bytecode
        # control flow; this stack lets internal RET validate the real x64 slot.
        self.rd_local(CALL_DEPTH); self.push_imm(CALL_STACK_CAPACITY)
        self.a("cmp_lt"); self.a(f"jnz {depth_ok}")
        self.push_imm(1); self.a("halt")
        self.a.label(depth_ok)
        self.a(f"local_addr {CALL_RET_BASE}")
        self.rd_local(CALL_DEPTH); self.push_imm(8); self.a("mul"); self.a("add")
        self.rd_local(T5); self.a("store64")
        self.rd_local(CALL_DEPTH); self.push_imm(1); self.a("add")
        self.wr_local(CALL_DEPTH)

        # Architectural CALL uses the pre-call RSP, writes the absolute next
        # RIP at [RSP-8], and leaves flags untouched.
        self.rd_reg(Register.RSP); self.push_imm(8); self.a("sub")
        self.wr_reg(Register.RSP)
        self.rd_reg(Register.RSP); self.rd_local(T5); self.a("store64")
        self.a(f"call {_lbl(target)}")

    def _internal_ret(self) -> None:
        """Validate/pop one architectural frame, then return in the VM."""
        depth_ok = self._new_label()
        address_ok = self._new_label()

        self.rd_local(CALL_DEPTH); self.push_imm(0); self.a("cmp_ne")
        self.a(f"jnz {depth_ok}")
        self.push_imm(1); self.a("halt")
        self.a.label(depth_ok)
        self.rd_local(CALL_DEPTH); self.push_imm(1); self.a("sub")
        self.wr_local(CALL_DEPTH)
        self.a(f"local_addr {CALL_RET_BASE}")
        self.rd_local(CALL_DEPTH); self.push_imm(8); self.a("mul"); self.a("add")
        self.a("load64"); self.wr_local(T5)

        # A rewritten physical return slot would make native RET branch outside
        # the proven VM graph. Reject it transactionally instead of misrouting.
        self.rd_reg(Register.RSP); self.a("load64")
        self.rd_local(T5); self.a("cmp_eq"); self.a(f"jnz {address_ok}")
        self.push_imm(1); self.a("halt")
        self.a.label(address_ok)
        self.rd_reg(Register.RSP); self.push_imm(8); self.a("add")
        self.wr_reg(Register.RSP)
        self.a("ret")

    def _top_level_ret(self) -> None:
        """Leave the physical caller return for the generated native thunk."""
        depth_ok = self._new_label()
        self.rd_local(CALL_DEPTH); self.push_imm(0); self.a("cmp_eq")
        self.a(f"jnz {depth_ok}")
        self.push_imm(1); self.a("halt")
        self.a.label(depth_ok)
        self.push_imm(0); self.a("halt")

    # -- top-level -------------------------------------------------------
    def lift(self) -> str:
        instructions = _decode_exact(self.code, self.base)
        call_analysis = _analyze_internal_calls(instructions, self.base, self.end)
        internal_returns = frozenset(call_analysis.internal_return_rvas)
        top_level_returns = frozenset(call_analysis.top_level_return_rvas)
        for instr in instructions:
            self.a.label(_lbl(instr.ip))
            m = instr.mnemonic
            if m == Mnemonic.NOP:
                self.a("nop")
            elif m == Mnemonic.MOV:
                self._mov(instr)
            elif m == Mnemonic.MOVZX:
                self._extend_move(instr, signed=False)
            elif m == Mnemonic.MOVSX:
                self._extend_move(instr, signed=True)
            elif m == Mnemonic.MOVSXD:
                self._extend_move(instr, signed=True, movsxd=True)
            elif m == Mnemonic.PUSH:
                self._push(instr)
            elif m == Mnemonic.POP:
                self._pop(instr)
            elif m == Mnemonic.LEAVE:
                self._leave(instr)
            elif m == Mnemonic.ADD:
                self._binop(instr, "add", "add")
            elif m == Mnemonic.ADC:
                self._adc_sbb(instr, subtract=False)
            elif m == Mnemonic.SUB:
                self._binop(instr, "sub", "sub")
            elif m == Mnemonic.SBB:
                self._adc_sbb(instr, subtract=True)
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
            elif m == Mnemonic.SHLD:
                self._double_shift(instr, left=True)
            elif m == Mnemonic.SHRD:
                self._double_shift(instr, left=False)
            elif m == Mnemonic.SAR:
                self._sar(instr)
            elif m == Mnemonic.ROL:
                self._rotate(instr, "rol")
            elif m == Mnemonic.ROR:
                self._rotate(instr, "ror")
            elif m == Mnemonic.LEA:
                self._lea(instr)
            elif m == Mnemonic.MUL:
                self._implicit_mul(instr, signed=False)
            elif m == Mnemonic.IMUL:
                self._imul(instr)
            elif m in (Mnemonic.DIV, Mnemonic.IDIV):
                raise LiftUnsupported(
                    "DIV/IDIV require architectural #DE divide-fault delivery, "
                    "which the VM/native thunk contract cannot reproduce"
                )
            elif m == Mnemonic.XCHG:
                self._xchg(instr)
            elif m == Mnemonic.BSWAP:
                self._bswap(instr)
            elif m in _SETCC:
                self._setcc(instr, m)
            elif m in _CMOVCC:
                self._cmovcc(instr, m)
            elif m == Mnemonic.CALL:
                self._call(instr)
            elif m == Mnemonic.JMP:
                self.a(f"jmp {_lbl(self._branch_target(instr))}")
            elif m in _CC:
                tgt = self._branch_target(instr)
                self._cc(m)
                self.a(f"jnz {_lbl(tgt)}")   # take branch iff condition != 0
            elif m == Mnemonic.RET:
                if instr.op_count:
                    raise LiftUnsupported("ret imm16 stack cleanup is not modeled")
                if instr.ip in internal_returns:
                    self._internal_ret()
                elif instr.ip in top_level_returns:
                    self._top_level_ret()
                else:
                    raise LiftUnsupported(f"unclassified RET at 0x{instr.ip:X}")
            else:
                raise LiftUnsupported(f"mnemonic {m!r} at 0x{instr.ip:X}")
        # fall-through past the last instruction ends the program
        self.push_imm(0); self.a("halt")
        return self.a.text()


_CONDITION_GROUPS = {
    "e": (Mnemonic.JE, Mnemonic.SETE, Mnemonic.CMOVE),
    "ne": (Mnemonic.JNE, Mnemonic.SETNE, Mnemonic.CMOVNE),
    "b": (Mnemonic.JB, Mnemonic.SETB, Mnemonic.CMOVB),
    "ae": (Mnemonic.JAE, Mnemonic.SETAE, Mnemonic.CMOVAE),
    "s": (Mnemonic.JS, Mnemonic.SETS, Mnemonic.CMOVS),
    "ns": (Mnemonic.JNS, Mnemonic.SETNS, Mnemonic.CMOVNS),
    "o": (Mnemonic.JO, Mnemonic.SETO, Mnemonic.CMOVO),
    "no": (Mnemonic.JNO, Mnemonic.SETNO, Mnemonic.CMOVNO),
    "p": (Mnemonic.JP, Mnemonic.SETP, Mnemonic.CMOVP),
    "np": (Mnemonic.JNP, Mnemonic.SETNP, Mnemonic.CMOVNP),
    "be": (Mnemonic.JBE, Mnemonic.SETBE, Mnemonic.CMOVBE),
    "a": (Mnemonic.JA, Mnemonic.SETA, Mnemonic.CMOVA),
    "l": (Mnemonic.JL, Mnemonic.SETL, Mnemonic.CMOVL),
    "ge": (Mnemonic.JGE, Mnemonic.SETGE, Mnemonic.CMOVGE),
    "le": (Mnemonic.JLE, Mnemonic.SETLE, Mnemonic.CMOVLE),
    "g": (Mnemonic.JG, Mnemonic.SETG, Mnemonic.CMOVG),
}
_CONDITION = {
    mnemonic: condition
    for condition, mnemonics in _CONDITION_GROUPS.items()
    for mnemonic in mnemonics
}
_CC = {mnemonics[0] for mnemonics in _CONDITION_GROUPS.values()}
_SETCC = {mnemonics[1] for mnemonics in _CONDITION_GROUPS.values()}
_CMOVCC = {mnemonics[2] for mnemonics in _CONDITION_GROUPS.values()}


def _decode_exact(code: bytes, base: int):
    instructions = tuple(Decoder(64, code, ip=base))
    if not instructions:
        raise LiftUnsupported("lifted function is empty")
    cursor = base
    for instruction in instructions:
        if instruction.ip != cursor or instruction.code == 0 or instruction.len <= 0:
            raise LiftUnsupported(f"undecodable byte at 0x{cursor:X}")
        cursor += instruction.len
    if cursor != base + len(code):
        raise LiftUnsupported(
            f"decoder consumed 0x{cursor - base:X} bytes, expected 0x{len(code):X}"
        )
    return instructions


def _analyze_internal_calls(instructions, base: int, end: int) -> InternalCallAnalysis:
    """Prove finite in-extent CALL/RET contexts and classify every RET."""
    instruction_by_ip = {instruction.ip: instruction for instruction in instructions}
    starts = frozenset(instruction_by_ip)
    calls = []

    def direct_target(instruction, kind: str) -> int:
        if instruction.op_kind(0) != OpKind.NEAR_BRANCH64:
            raise LiftUnsupported(f"indirect / non-near {kind} at 0x{instruction.ip:X}")
        target = instruction.near_branch_target
        if not (base <= target < end):
            raise LiftUnsupported(f"{kind} target outside lifted function at 0x{instruction.ip:X}")
        if target not in starts:
            raise LiftUnsupported(
                f"{kind} target 0x{target:X} is not an instruction boundary"
            )
        return target

    # Reject unsupported call shapes even when their bytes are unreachable.
    for instruction in instructions:
        if instruction.mnemonic == Mnemonic.CALL:
            direct_target(instruction, "call")
            calls.append(instruction.ip)

    # State includes the exact architectural/VM return context. Loops fold on
    # repeated states; recursion is rejected before it can make this unbounded.
    pending = [(base, (), (base,))]
    visited = set()
    return_modes: dict[int, set[str]] = {}
    max_depth = 0
    while pending:
        ip, return_stack, call_entries = pending.pop()
        state = (ip, return_stack, call_entries)
        if state in visited:
            continue
        visited.add(state)
        if len(visited) > 100_000:
            raise LiftUnsupported("internal call analysis exceeded its state bound")
        if ip == end:
            if return_stack:
                raise LiftUnsupported("internal call can fall through without RET")
            continue
        instruction = instruction_by_ip.get(ip)
        if instruction is None:
            raise LiftUnsupported(f"control flow reaches non-instruction 0x{ip:X}")
        next_ip = instruction.ip + instruction.len
        mnemonic = instruction.mnemonic

        if mnemonic == Mnemonic.CALL:
            target = direct_target(instruction, "call")
            if target in call_entries:
                raise LiftUnsupported(
                    f"recursive internal call to 0x{target:X} is not supported"
                )
            if len(return_stack) >= CALL_STACK_CAPACITY:
                raise LiftUnsupported(
                    f"internal call depth exceeds {CALL_STACK_CAPACITY} frames"
                )
            nested_returns = return_stack + (next_ip,)
            max_depth = max(max_depth, len(nested_returns))
            pending.append((target, nested_returns, call_entries + (target,)))
        elif mnemonic == Mnemonic.RET:
            if instruction.op_count:
                raise LiftUnsupported("ret imm16 stack cleanup is not modeled")
            mode = "internal" if return_stack else "top-level"
            return_modes.setdefault(ip, set()).add(mode)
            if return_stack:
                pending.append((return_stack[-1], return_stack[:-1], call_entries[:-1]))
        elif mnemonic == Mnemonic.JMP:
            pending.append((direct_target(instruction, "branch"), return_stack, call_entries))
        elif mnemonic in _CC:
            pending.append((direct_target(instruction, "branch"), return_stack, call_entries))
            pending.append((next_ip, return_stack, call_entries))
        elif instruction.flow_control == FlowControl.NEXT:
            pending.append((next_ip, return_stack, call_entries))
        else:
            raise LiftUnsupported(
                f"unsupported control flow at 0x{instruction.ip:X}"
            )

    all_returns = {item.ip for item in instructions if item.mnemonic == Mnemonic.RET}
    missing = sorted(all_returns - return_modes.keys())
    if missing:
        raise LiftUnsupported(f"unreachable RET at 0x{missing[0]:X} has no sound role")
    ambiguous = sorted(ip for ip, modes in return_modes.items() if len(modes) != 1)
    if ambiguous:
        raise LiftUnsupported(
            f"RET at 0x{ambiguous[0]:X} is both internal and top-level"
        )
    return InternalCallAnalysis(
        internal_call_rvas=tuple(calls),
        internal_return_rvas=tuple(
            sorted(ip for ip, modes in return_modes.items() if "internal" in modes)
        ),
        top_level_return_rvas=tuple(
            sorted(ip for ip, modes in return_modes.items() if "top-level" in modes)
        ),
        max_call_depth=max_depth,
    )


def analyze_internal_calls(code: bytes, base: int = 0x1000) -> InternalCallAnalysis:
    """Return the proven direct internal-call topology or raise LiftUnsupported."""
    instructions = _decode_exact(code, base)
    return _analyze_internal_calls(instructions, base, base + len(code))


def lift_function(code: bytes, base: int = 0x1000) -> str:
    """Lift x64 machine code into Daedalus VM assembly, or raise LiftUnsupported.

    `base` is the virtual address the code is decoded at (for branch targets)."""
    return _Lifter(code, base).lift()
