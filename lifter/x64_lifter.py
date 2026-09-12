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
arithmetic, shifts/rotates at 8/16/32/64 bits, SHLD/SHRD at 32/64 bits,
one-/two-/three-operand IMUL, one-operand MUL, MOVZX/MOVSX/
MOVSXD, SETcc/CMOVcc, register XCHG, BSWAP, ADC, and SBB. High-8 aliases,
scalar memory destinations, immediate stores, parity conditions, and balanced
PUSH/POP/LEAVE stack frames are covered. Direct non-recursive calls to proven
instruction boundaries inside the same selected extent preserve architectural
stack effects and use shadow-validated VM returns. Legacy register-only XMM
moves and bitwise XOR operate on a captured 16-register, two-lane state.
Register-target BT/BTS/BTR/BTC are supported; memory bit strings remain closed.
Floating-point arithmetic, XMM memory operands, VEX/EVEX encodings, atomic
XCHG/LOCK forms, external/indirect/recursive calls, and unmodeled widths remain
explicit whole-function bailouts.
"""
from __future__ import annotations

from dataclasses import dataclass

from iced_x86 import (
    Decoder,
    EncodingKind,
    FlowControl,
    InstructionInfoFactory,
    MemorySizeExt,
    Mnemonic,
    OpAccess,
    OpKind,
    Register,
)

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
_HIGH8_OFF = {
    Register.AH: 0,
    Register.CH: 8,
    Register.DH: 16,
    Register.BH: 24,
}
REG_OFF = {r: i * 8 for i, r in enumerate(_R64)}
REG32_OFF = {r: i * 8 for i, r in enumerate(_R32)}   # 32-bit reg -> parent offset
REG16_OFF = {r: i * 8 for i, r in enumerate(_R16)}
REG8_OFF = {r: i * 8 for i, r in enumerate(_R8)}
GPR_NAMES = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
_XMM = [
    Register.XMM0, Register.XMM1, Register.XMM2, Register.XMM3,
    Register.XMM4, Register.XMM5, Register.XMM6, Register.XMM7,
    Register.XMM8, Register.XMM9, Register.XMM10, Register.XMM11,
    Register.XMM12, Register.XMM13, Register.XMM14, Register.XMM15,
]
XMM_NAMES = [f"xmm{i}" for i in range(16)]

CF, ZF, SF, OF = 128, 136, 144, 152          # legacy flag locals
SA, SB, SR = 160, 168, 176                   # scratch: operand a, b, result
# extra scratch for the wide (64x64->128) multiply used by imul overflow synthesis
T0, T1, T2, T3, T4, T5 = 184, 192, 200, 208, 216, 224
PF = 232                                      # parity flag (even low-byte parity)
CALL_DEPTH = 240                              # active internal CALL frames
CALL_RET_BASE = 248                           # 32 x architectural return RIP
CALL_STACK_CAPACITY = 32
IMAGE_BASE = CALL_RET_BASE + CALL_STACK_CAPACITY * 8
XMM_BASE = IMAGE_BASE + 8
XMM_LANE_SIZE = 16
XMM_OFF = {register: XMM_BASE + i * XMM_LANE_SIZE for i, register in enumerate(_XMM)}
LOCALS_NEEDED = XMM_BASE + len(_XMM) * XMM_LANE_SIZE
_XMM_MOVES = {
    Mnemonic.MOVAPS: "movaps",
    Mnemonic.MOVUPS: "movups",
    Mnemonic.MOVDQA: "movdqa",
    Mnemonic.MOVDQU: "movdqu",
}
_XMM_XORS = {
    Mnemonic.PXOR: "pxor",
    Mnemonic.XORPS: "xorps",
    Mnemonic.XORPD: "xorpd",
}

MASK64 = (1 << 64) - 1
SIGN64 = 63
MASK32 = (1 << 32) - 1
SIGN32 = 31
MASK16 = (1 << 16) - 1
SIGN16 = 15
MASK8 = (1 << 8) - 1
SIGN8 = 7
_RVA_LIMIT = 1 << 32
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000


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


def _require_rip_memory_base(instruction) -> None:
    """Reject address-size-overridden EIP-relative forms before rebasing."""
    if instruction.memory_base == Register.RIP:
        return
    if instruction.memory_base == Register.EIP:
        raise LiftUnsupported(
            f"address-size-overridden EIP-relative memory operand at "
            f"0x{instruction.ip:X}"
        )
    raise LiftUnsupported(
        f"IP-relative memory operand at 0x{instruction.ip:X} is not RIP-relative"
    )


@dataclass(frozen=True)
class RipRelativeReference:
    """One decoded RIP-relative reference expressed entirely in RVAs."""

    instruction_rva: int
    target_rva: int
    size: int
    access: str
    address_only: bool

    def to_dict(self) -> dict[str, int | str | bool]:
        return {
            "instruction_rva": self.instruction_rva,
            "target_rva": self.target_rva,
            "size": self.size,
            "access": self.access,
            "address_only": self.address_only,
        }


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

        Every sub-register shares its parent's 64-bit local. Legacy high-8
        aliases address bits 8..15 of RAX, RCX, RDX, and RBX."""
        if reg in REG_OFF:
            return REG_OFF[reg], 64
        if reg in REG32_OFF:
            return REG32_OFF[reg], 32
        if reg in REG16_OFF:
            return REG16_OFF[reg], 16
        if reg in REG8_OFF:
            return REG8_OFF[reg], 8
        if reg in _HIGH8_OFF:
            return _HIGH8_OFF[reg], 8
        raise LiftUnsupported(f"unsupported register {reg!r}")

    def rd_reg(self, reg) -> None:
        if reg in _HIGH8_OFF:
            self.a(f"local_addr {_HIGH8_OFF[reg]}")
            self.a("load64")
            self.push_imm(8); self.a("shr")
            self.push_imm(MASK8); self.a("and")
            return
        off, width = self._reg_info(reg)
        self.a(f"local_addr {off}")
        self.a("load64")
        if width < 64:
            self.push_imm(_width_mask(width))
            self.a("and")

    def wr_reg(self, reg) -> None:
        # value on top of stack -> reg local. store64 pops [addr, val].
        if reg in _HIGH8_OFF:
            off = _HIGH8_OFF[reg]
            self.push_imm(MASK8); self.a("and")
            self.push_imm(8); self.a("shl")
            self.a(f"local_addr {off}"); self.a("load64")
            self.push_imm((~(MASK8 << 8)) & MASK64); self.a("and")
            self.a("or")
            self.a(f"local_addr {off}")
            self.a("swap")
            self.a("store64")
            return
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

    def _require_legacy_registers(self, instr, mnemonic: str):
        if instr.encoding != EncodingKind.LEGACY:
            raise LiftUnsupported(f"{mnemonic} VEX/EVEX encoding is not supported")
        if instr.op_count != 2 or any(
                instr.op_kind(index) != OpKind.REGISTER for index in (0, 1)):
            raise LiftUnsupported(f"{mnemonic} requires register-only operands")
        return instr.op_register(0), instr.op_register(1)

    def _xmm_offset(self, register) -> int:
        try:
            return XMM_OFF[register]
        except KeyError as exc:
            raise LiftUnsupported(f"expected an XMM0-XMM15 register, got {register!r}") from exc

    def _read_xmm(self, register) -> None:
        offset = self._xmm_offset(register)
        self.rd_local(offset); self.wr_local(T0)
        self.rd_local(offset + 8); self.wr_local(T1)

    def _write_xmm_from_temps(self, register) -> None:
        offset = self._xmm_offset(register)
        self.rd_local(T0); self.wr_local(offset)
        self.rd_local(T1); self.wr_local(offset + 8)

    def _xmm_move(self, instr, mnemonic: str) -> None:
        destination, source = self._require_legacy_registers(instr, mnemonic)
        self._xmm_offset(destination)
        self._xmm_offset(source)
        self._read_xmm(source)
        self._write_xmm_from_temps(destination)

    def _xmm_logical(self, instr, mnemonic: str) -> None:
        destination, source = self._require_legacy_registers(instr, mnemonic)
        destination_offset = self._xmm_offset(destination)
        source_offset = self._xmm_offset(source)
        self.rd_local(destination_offset); self.rd_local(source_offset); self.a("xor")
        self.wr_local(T0)
        self.rd_local(destination_offset + 8); self.rd_local(source_offset + 8)
        self.a("xor"); self.wr_local(T1)
        self._write_xmm_from_temps(destination)

    def _movd_movq(self, instr, *, width: int) -> None:
        mnemonic = "movd" if width == 32 else "movq"
        destination, source = self._require_legacy_registers(instr, mnemonic)
        destination_is_xmm = destination in XMM_OFF
        source_is_xmm = source in XMM_OFF
        if destination_is_xmm:
            if source_is_xmm:
                if width != 64:
                    raise LiftUnsupported("movd does not support an XMM register source")
                self.rd_local(self._xmm_offset(source)); self.wr_local(T0)
            else:
                _source_offset, source_width = self._reg_info(source)
                if source_width != width:
                    raise LiftUnsupported(f"{mnemonic} GPR source width mismatch")
                self.rd_reg(source); self.wr_local(T0)
            self.push_imm(0); self.wr_local(T1)
            self._write_xmm_from_temps(destination)
            return
        if not source_is_xmm:
            raise LiftUnsupported(f"{mnemonic} requires one XMM register operand")
        _destination_offset, destination_width = self._reg_info(destination)
        if destination_width != width:
            raise LiftUnsupported(f"{mnemonic} GPR destination width mismatch")
        self.rd_local(self._xmm_offset(source)); self.wr_reg(destination)

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
        # shl/shr reg|mem, imm|cl.
        dst, width = self._read_rmw_destination(instr)
        if (instr.op_kind(1) == OpKind.REGISTER
                and instr.op_register(1) == Register.CL):
            self._shift_cl(dst, width, vmop)
            return
        if instr.op_kind(1) not in (OpKind.IMMEDIATE8, OpKind.IMMEDIATE8TO16,
                                    OpKind.IMMEDIATE8TO32, OpKind.IMMEDIATE8TO64):
            raise LiftUnsupported("shift by non-immediate/CL not supported")
        signbit = _width_signbit(width)
        # x64 masks counts to five bits for 8/16/32-bit operands and six bits
        # only for 64-bit operands. It does not reduce narrow shifts modulo the
        # operand width.
        cnt = instr.immediate(1) & (63 if width == 64 else 31)
        if cnt == 0:
            # A zero-count 32-bit register form still performs the architectural
            # zero-extension of the parent. Narrow registers and memory are
            # already byte-for-byte identical, so no write is necessary.
            if dst is not None and width == 32:
                self.rd_local(SA); self.wr_local(SR)
                self._write_rmw_destination(dst, width)
            return  # no-op, flags unchanged
        self.rd_local(SA); self.push_imm(cnt); self.a(vmop)
        self._mask_sr(width); self.wr_local(SR)
        self._write_rmw_destination(dst, width)

        self._zf_sf_from_sr(signbit)
        if cnt <= width:
            bit = (width - cnt) if vmop == "shl" else (cnt - 1)
            self.rd_local(SA); self.push_imm(bit); self.a("shr")
            self.push_imm(1); self.a("and"); self.wr_local(CF)
        else:
            # CF is architecturally undefined past the operand width. Keep the
            # implementation deterministic without deriving an invalid index.
            self.push_imm(0); self.wr_local(CF)
        if cnt == 1:
            if vmop == "shl":
                self.rd_local(SR); self.push_imm(signbit); self.a("shr")
                self.push_imm(1); self.a("and"); self.rd_local(CF); self.a("xor")
            else:
                self.rd_local(SA); self.push_imm(signbit); self.a("shr")
                self.push_imm(1); self.a("and")
            self.wr_local(OF)

    def _read_cl_count(self, width: int) -> None:
        """SB = CL & the architectural 5-bit/6-bit count mask."""
        self.rd_local(REG_OFF[Register.RCX])
        self.push_imm(63 if width == 64 else 31)
        self.a("and"); self.wr_local(SB)

    def _shift_cl(self, dst, width: int, vmop: str) -> None:
        signbit = _width_signbit(width)
        self._read_cl_count(width)                 # SB = cnt
        self.rd_local(SA); self.rd_local(SB); self.a(vmop)
        self._mask_sr(width); self.wr_local(SR)
        if dst is not None and width == 32:
            self._write_rmw_destination(dst, width)
        else:
            skip_write = self._new_label()
            self.rd_local(SB); self.a(f"jz {skip_write}")
            self._write_rmw_destination(dst, width)
            self.a.label(skip_write)
        # Flags are unchanged when cnt==0; guard the flag writes behind jz.
        skip = self._new_label()
        self.rd_local(SB); self.a(f"jz {skip}")
        self._zf_sf_from_sr(signbit)
        # For counts beyond a narrow operand width CF is undefined. The shift
        # index below still produces the deterministic zero used by immediate
        # forms without introducing a separate dynamic branch.
        self.rd_local(SA)
        if vmop == "shl":
            self.push_imm(width); self.rd_local(SB); self.a("sub")
        else:
            self.rd_local(SB); self.push_imm(1); self.a("sub")
        self.a("shr"); self.push_imm(1); self.a("and"); self.wr_local(CF)
        not_one = self._new_label()
        self.rd_local(SB); self.push_imm(1); self.a("cmp_eq")
        self.a(f"jz {not_one}")
        if vmop == "shl":
            self.rd_local(SR); self.push_imm(signbit); self.a("shr")
            self.push_imm(1); self.a("and"); self.rd_local(CF); self.a("xor")
        else:
            self.rd_local(SA); self.push_imm(signbit); self.a("shr")
            self.push_imm(1); self.a("and")
        self.wr_local(OF)
        self.a.label(not_one)
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
        # sar reg|mem, imm|cl -- arithmetic shift right synthesized from VM ops.
        dst, width = self._read_rmw_destination(instr)
        signbit = _width_signbit(width)
        count_mask = 63 if width == 64 else 31
        mask_val = _width_mask(width)
        src, raw = self._shift_count(instr)
        is_imm = src == "imm"
        cnt = (raw & count_mask) if is_imm else None
        if not is_imm:
            self._read_cl_count(width)              # SB = cnt

        def push_cnt():
            self.push_imm(cnt) if is_imm else self.rd_local(SB)

        # Value (count-0 safe):
        #   SR = (x >> n) | (sign_all & fill_mask)
        #   sign_all = 0 - sign(x)  (all-ones if x negative)
        #   fill_mask = ~(MASK >> n) & MASK  (top n bits; 0 when n==0)
        self.rd_local(SA); push_cnt(); self.a("shr")               # x >> n
        self.rd_local(SA); self.push_imm(signbit); self.a("shr")
        self.push_imm(1); self.a("and"); self.a("neg")             # sign_all
        self.push_imm(mask_val); push_cnt(); self.a("shr")
        self.a("not"); self.push_imm(mask_val); self.a("and")      # fill_mask
        self.a("and")                                              # sign_all & fill
        self.a("or")                                               # | (x>>n)
        self._mask_sr(width); self.wr_local(SR)
        if is_imm:
            if cnt == 0:
                if dst is not None and width == 32:
                    self._write_rmw_destination(dst, width)
                return
            self._write_rmw_destination(dst, width)
        else:
            if dst is not None and width == 32:
                self._write_rmw_destination(dst, width)
            else:
                skip_write = self._new_label()
                self.rd_local(SB); self.a(f"jz {skip_write}")
                self._write_rmw_destination(dst, width)
                self.a.label(skip_write)

        # Flags: unchanged when n==0; else ZF/SF from result, CF = bit(n-1), OF=0.
        def emit_flags():
            self._zf_sf_from_sr(signbit)
            self.rd_local(SA)
            if is_imm:
                self.push_imm(min(cnt - 1, signbit))
            else:
                self.rd_local(SB); self.push_imm(1); self.a("sub"); self.wr_local(T0)
                clamp = self._new_label()
                ready = self._new_label()
                self.push_imm(signbit); self.rd_local(T0); self.a("cmp_lt")
                self.a(f"jnz {clamp}")
                self.rd_local(T0); self.a(f"jmp {ready}")
                self.a.label(clamp)
                self.push_imm(signbit)
                self.a.label(ready)
            self.a("shr"); self.push_imm(1); self.a("and"); self.wr_local(CF)
            if is_imm:
                if cnt == 1:
                    self.push_imm(0); self.wr_local(OF)
            else:
                not_one = self._new_label()
                self.rd_local(SB); self.push_imm(1); self.a("cmp_eq")
                self.a(f"jz {not_one}")
                self.push_imm(0); self.wr_local(OF)
                self.a.label(not_one)

        if is_imm:
            if cnt != 0:
                emit_flags()
        else:
            skip = self._new_label()
            self.rd_local(SB); self.a(f"jz {skip}")
            emit_flags()
            self.a.label(skip)

    def _rotate(self, instr, direction: str) -> None:
        # rol/ror reg|mem, imm|cl -- count-mask, then reduce modulo width.
        dst, width = self._read_rmw_destination(instr)
        count_mask = 63 if width == 64 else 31
        src, raw = self._shift_count(instr)
        is_imm = src == "imm"
        cnt = (raw & count_mask) if is_imm else None
        if not is_imm:
            self._read_cl_count(width)              # SB = cnt

        rotate_mask = width - 1
        if is_imm:
            rotate_count = cnt & rotate_mask
        else:
            self.rd_local(SB); self.push_imm(rotate_mask); self.a("and")
            self.wr_local(T0)

        def push_count():
            self.push_imm(rotate_count) if is_imm else self.rd_local(T0)

        if direction == "rol":                     # (x << n) | (x >> (width-n))
            self.rd_local(SA); push_count(); self.a("shl")
            self.rd_local(SA); self.push_imm(width); push_count(); self.a("sub")
            self.a("shr"); self.a("or")
        else:                                       # ror: (x >> n) | (x << (width-n))
            self.rd_local(SA); push_count(); self.a("shr")
            self.rd_local(SA); self.push_imm(width); push_count(); self.a("sub")
            self.a("shl"); self.a("or")
        self._mask_sr(width); self.wr_local(SR)

        if is_imm:
            if cnt == 0:
                if dst is not None and width == 32:
                    self._write_rmw_destination(dst, width)
                return
            self._write_rmw_destination(dst, width)
        else:
            if dst is not None and width == 32:
                self._write_rmw_destination(dst, width)
            else:
                skip_write = self._new_label()
                self.rd_local(SB); self.a(f"jz {skip_write}")
                self._write_rmw_destination(dst, width)
                self.a.label(skip_write)

        # Only CF is affected (ZF/SF untouched; OF defined only for count==1 and
        # left unwritten). Unchanged when cnt==0.
        def emit_cf():
            if direction == "rol":                 # CF = LSB of result
                self.rd_local(SR); self.push_imm(1); self.a("and"); self.wr_local(CF)
            else:                                  # ror: CF = MSB of result
                self.rd_local(SR); self.push_imm(width - 1); self.a("shr")
                self.push_imm(1); self.a("and"); self.wr_local(CF)

            if is_imm:
                if cnt == 1:
                    self._rotate_of(direction, width)
            else:
                not_one = self._new_label()
                self.rd_local(SB); self.push_imm(1); self.a("cmp_eq")
                self.a(f"jz {not_one}")
                self._rotate_of(direction, width)
                self.a.label(not_one)

        if is_imm:
            if cnt != 0:
                emit_cf()
        else:
            skip = self._new_label()
            self.rd_local(SB); self.a(f"jz {skip}")
            emit_cf()
            self.a.label(skip)

    def _rotate_of(self, direction: str, width: int) -> None:
        """Write the architecturally defined rotate overflow flag (count one)."""
        if direction == "rol":
            self.rd_local(SR); self.push_imm(width - 1); self.a("shr")
            self.push_imm(1); self.a("and"); self.rd_local(CF); self.a("xor")
        else:
            self.rd_local(SR); self.push_imm(width - 1); self.a("shr")
            self.rd_local(SR); self.push_imm(width - 2); self.a("shr")
            self.a("xor"); self.push_imm(1); self.a("and")
        self.wr_local(OF)

    def _emit_effective_address(self, instr) -> None:
        """Push the effective address of the instruction's memory operand.
        Used by memory load (push_operand) and store (_mov). RIP-relative
        operands are decoded at their source RVA and rebased through the
        runtime image-base local. Other forms bail on segment overrides or a
        non-64-bit base/index (32-bit addressing computes mod 2^32, which our
        64-bit arithmetic would not reproduce)."""
        if instr.segment_prefix != Register.NONE:
            raise LiftUnsupported("segment-overridden memory operand")
        if instr.is_ip_rel_memory_operand:
            _require_rip_memory_base(instr)
            self.rd_local(IMAGE_BASE)
            self.push_imm(instr.ip_rel_memory_address)
            self.a("add")
            return
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
        if instr.segment_prefix != Register.NONE:
            raise LiftUnsupported("lea with a segment override")
        if instr.is_ip_rel_memory_operand:
            _require_rip_memory_base(instr)
            self.rd_local(IMAGE_BASE)
            self.push_imm(instr.ip_rel_memory_address)
            self.a("add")
            self.wr_reg(dst)
            return
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
        if width not in (16, 32, 64):
            raise LiftUnsupported(f"unsupported imul width {width}")
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
        if width == 16:
            self._imul_of_16()
        elif width == 32:
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

    def _imul_of_16(self) -> None:
        self.rd_local(SA); self._push_sign_extended(16)
        self.rd_local(SB); self._push_sign_extended(16)
        self.a("mul"); self.wr_local(T1)
        self.rd_local(SR); self._push_sign_extended(16)
        self.rd_local(T1); self.a("cmp_ne")
        self._store_cf_of()

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

    def _cbw(self) -> None:
        self.rd_reg(Register.AL)
        self._push_sign_extended(8)
        self.push_imm(MASK16); self.a("and")
        self.wr_reg(Register.AX)

    def _cwde(self) -> None:
        self.rd_reg(Register.AX)
        self._push_sign_extended(16)
        self.push_imm(MASK32); self.a("and")
        self.wr_reg(Register.EAX)

    def _cdqe(self) -> None:
        self.rd_reg(Register.EAX)
        self._push_sign_extended(32)
        self.wr_reg(Register.RAX)

    def _cwd(self) -> None:
        self.rd_reg(Register.AX)
        self.push_imm(SIGN16); self.a("shr")
        self.push_imm(1); self.a("and"); self.a("neg")
        self.push_imm(MASK16); self.a("and")
        self.wr_reg(Register.DX)

    def _cdq(self) -> None:
        self.rd_reg(Register.EAX)
        self.push_imm(SIGN32); self.a("shr")
        self.push_imm(1); self.a("and"); self.a("neg")
        self.push_imm(MASK32); self.a("and")
        self.wr_reg(Register.EDX)

    def _cqo(self) -> None:
        self.rd_reg(Register.RAX)
        self.push_imm(SIGN64); self.a("shr")
        self.push_imm(1); self.a("and"); self.a("neg")
        self.wr_reg(Register.RDX)

    def _bittest_register(self, instr, mnemonic) -> None:
        """Lift register-target BT/BTS/BTR/BTC; memory bit strings stay closed."""
        dst, width = self.require_reg(instr, 0)
        if width not in (16, 32, 64):
            raise LiftUnsupported("bit test requires a 16/32/64-bit register target")
        self.rd_reg(dst); self.wr_local(SA)

        kind = instr.op_kind(1)
        bit_mask = width - 1
        if kind in (
            OpKind.IMMEDIATE8,
            OpKind.IMMEDIATE8TO16,
            OpKind.IMMEDIATE8TO32,
            OpKind.IMMEDIATE8TO64,
        ):
            bit_index = instr.immediate(1) & bit_mask
            immediate = True
        elif kind == OpKind.REGISTER:
            index = instr.op_register(1)
            _offset, index_width = self._reg_info(index)
            if index_width != width:
                raise LiftUnsupported("bit-test register index width mismatch")
            self.rd_reg(index); self.push_imm(bit_mask); self.a("and")
            self.wr_local(T0)
            immediate = False
        else:
            raise LiftUnsupported("bit-test index must be an immediate or register")

        def push_bit() -> None:
            self.push_imm(bit_index) if immediate else self.rd_local(T0)

        self.rd_local(SA); push_bit(); self.a("shr")
        self.push_imm(1); self.a("and"); self.wr_local(CF)
        if mnemonic == Mnemonic.BT:
            return

        self.push_imm(1); push_bit(); self.a("shl"); self.wr_local(T1)
        self.rd_local(SA)
        if mnemonic == Mnemonic.BTS:
            self.rd_local(T1); self.a("or")
        elif mnemonic == Mnemonic.BTR:
            self.rd_local(T1); self.a("not"); self.a("and")
        elif mnemonic == Mnemonic.BTC:
            self.rd_local(T1); self.a("xor")
        else:
            raise LiftUnsupported(f"unsupported bit-test mnemonic {mnemonic!r}")
        self._mask_sr(width); self.wr_local(SR)
        self._write_rmw_destination(dst, width)

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
            elif m == Mnemonic.CBW:
                self._cbw()
            elif m == Mnemonic.CWDE:
                self._cwde()
            elif m == Mnemonic.CDQE:
                self._cdqe()
            elif m == Mnemonic.CWD:
                self._cwd()
            elif m == Mnemonic.CDQ:
                self._cdq()
            elif m == Mnemonic.CQO:
                self._cqo()
            elif m in (Mnemonic.BT, Mnemonic.BTS, Mnemonic.BTR, Mnemonic.BTC):
                self._bittest_register(instr, m)
            elif m == Mnemonic.MOVD:
                self._movd_movq(instr, width=32)
            elif m == Mnemonic.MOVQ:
                self._movd_movq(instr, width=64)
            elif m in _XMM_MOVES:
                self._xmm_move(instr, _XMM_MOVES[m])
            elif m in _XMM_XORS:
                self._xmm_logical(instr, _XMM_XORS[m])
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


def _rip_access(instruction, operand: int) -> tuple[str, bool]:
    access = InstructionInfoFactory().info(instruction).op_access(operand)
    if access in (OpAccess.READ, OpAccess.COND_READ):
        return "read", False
    if access in (OpAccess.WRITE, OpAccess.COND_WRITE):
        return "write", False
    if access in (OpAccess.READ_WRITE, OpAccess.READ_COND_WRITE):
        return "read_write", False
    if access == OpAccess.NO_MEM_ACCESS and instruction.mnemonic == Mnemonic.LEA:
        return "address", True
    raise LiftUnsupported(
        f"unmodeled RIP-relative operand access at 0x{instruction.ip:X}"
    )


def analyze_rip_relative_references(
    code: bytes, base: int = 0x1000
) -> tuple[RipRelativeReference, ...]:
    """Decode RIP-relative references as RVAs, without granting memory access."""
    instructions = _decode_exact(code, base)
    references = []
    for instruction in instructions:
        if not instruction.is_ip_rel_memory_operand:
            continue
        _require_rip_memory_base(instruction)
        if not 0 <= instruction.ip < _RVA_LIMIT:
            raise LiftUnsupported("RIP-relative source address is not a 32-bit RVA")
        target = int(instruction.ip_rel_memory_address)
        if not 0 <= target < _RVA_LIMIT:
            raise LiftUnsupported(
                f"RIP-relative target at 0x{instruction.ip:X} is not a 32-bit RVA"
            )
        operands = [
            index
            for index in range(instruction.op_count)
            if instruction.op_kind(index) == OpKind.MEMORY
        ]
        if len(operands) != 1:
            raise LiftUnsupported(
                f"RIP-relative instruction at 0x{instruction.ip:X} does not have "
                "one explicit memory operand"
            )
        access, address_only = _rip_access(instruction, operands[0])
        if address_only:
            size = 1
        else:
            try:
                size = int(MemorySizeExt.size(instruction.memory_size))
            except (TypeError, ValueError) as exc:
                raise LiftUnsupported(
                    f"RIP-relative memory operand at 0x{instruction.ip:X} "
                    "has no byte width"
                ) from exc
            if size <= 0:
                raise LiftUnsupported(
                    f"RIP-relative memory operand at 0x{instruction.ip:X} "
                    "has no byte width"
                )
        if target + size > _RVA_LIMIT:
            raise LiftUnsupported(
                f"RIP-relative span at 0x{instruction.ip:X} exceeds the 32-bit RVA space"
            )
        references.append(
            RipRelativeReference(
                instruction_rva=int(instruction.ip),
                target_rva=target,
                size=size,
                access=access,
                address_only=address_only,
            )
        )
    return tuple(references)


def validate_rip_relative_references(
    code: bytes,
    base: int = 0x1000,
    *,
    image_sections=None,
    selected_extents=(),
) -> tuple[RipRelativeReference, ...]:
    """Prove every RIP reference is bounded mapped non-code image data."""
    references = analyze_rip_relative_references(code, base)
    if not references:
        return ()
    if image_sections is None:
        raise LiftUnsupported(
            "RIP-relative references require mapped image-section geometry"
        )
    try:
        raw_sections = sorted(tuple(image_sections), key=lambda item: int(item.rva))
    except (AttributeError, TypeError, ValueError) as exc:
        raise LiftUnsupported("invalid mapped image-section geometry") from exc
    sections = []
    previous_end = 0
    for section in raw_sections:
        try:
            section_rva = int(section.rva)
            mapped_size = max(int(section.virtual_size), len(bytes(section.raw)))
            characteristics = int(section.characteristics)
            name = str(section.name)
        except (AttributeError, TypeError, ValueError) as exc:
            raise LiftUnsupported("invalid mapped image-section geometry") from exc
        section_end = section_rva + mapped_size
        if (
            section_rva <= 0
            or mapped_size <= 0
            or section_end > _RVA_LIMIT
            or section_rva < previous_end
        ):
            raise LiftUnsupported("invalid or overlapping mapped image sections")
        sections.append(
            (section_rva, section_end, characteristics, name)
        )
        previous_end = section_end
    extents = tuple(selected_extents)
    for reference in references:
        target_end = reference.target_rva + reference.size
        owner = next(
            (
                section
                for section in sections
                if section[0] <= reference.target_rva and target_end <= section[1]
            ),
            None,
        )
        if owner is None:
            raise LiftUnsupported(
                f"RIP-relative reference at 0x{reference.instruction_rva:X} "
                f"targets an unmapped/header/cross-section span at "
                f"RVA 0x{reference.target_rva:X}+0x{reference.size:X}"
            )
        for extent in extents:
            try:
                extent_rva, extent_size = int(extent[0]), int(extent[1])
            except (IndexError, TypeError, ValueError) as exc:
                raise LiftUnsupported(
                    "invalid selected-function extent geometry"
                ) from exc
            extent_end = extent_rva + extent_size
            if (
                extent_rva <= 0
                or extent_size <= 0
                or extent_end > _RVA_LIMIT
            ):
                raise LiftUnsupported("invalid selected-function extent geometry")
            if extent_rva < target_end and reference.target_rva < extent_end:
                raise LiftUnsupported(
                    f"RIP-relative reference at 0x{reference.instruction_rva:X} "
                    f"to RVA 0x{reference.target_rva:X} overlaps selected "
                    f"extent RVA 0x{extent_rva:X}+0x{extent_size:X}"
                )
        characteristics = owner[2]
        owner_name = owner[3]
        if characteristics & IMAGE_SCN_MEM_DISCARDABLE:
            raise LiftUnsupported(
                f"RIP-relative reference at 0x{reference.instruction_rva:X} "
                f"targets discardable section {owner_name!r} at "
                f"RVA 0x{reference.target_rva:X}"
            )
        if characteristics & IMAGE_SCN_MEM_EXECUTE:
            kind = (
                "address-taken executable code"
                if reference.address_only
                else "executable bytes"
            )
            raise LiftUnsupported(
                f"RIP-relative reference at 0x{reference.instruction_rva:X} "
                f"targets {kind} at RVA 0x{reference.target_rva:X} "
                f"in section {owner_name!r}"
            )
        if reference.access in ("read", "read_write") and not (
            characteristics & IMAGE_SCN_MEM_READ
        ):
            raise LiftUnsupported(
                f"RIP-relative read at 0x{reference.instruction_rva:X} targets "
                f"RVA 0x{reference.target_rva:X} in non-readable section "
                f"{owner_name!r}"
            )
        if reference.access in ("write", "read_write") and not (
            characteristics & IMAGE_SCN_MEM_WRITE
        ):
            raise LiftUnsupported(
                f"RIP-relative write at 0x{reference.instruction_rva:X} targets "
                f"RVA 0x{reference.target_rva:X} in non-writable section "
                f"{owner_name!r}"
            )
    return references


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


def lift_function(
    code: bytes,
    base: int = 0x1000,
    *,
    image_sections=None,
    selected_extents=(),
) -> str:
    """Lift x64 machine code into Daedalus VM assembly, or raise LiftUnsupported.

    ``base`` is a source RVA. RIP-relative references require mapped section
    geometry and are emitted as ``runtime IMAGE_BASE + decoded target RVA``.
    """
    validate_rip_relative_references(
        code,
        base,
        image_sections=image_sections,
        selected_extents=selected_extents,
    )
    return _Lifter(code, base).lift()
