"""Lifter coverage for the extent/call-graph capabilities ed25519Verify needs.

Three new supported shapes, each fail-closed and oracle-proven:

* **Direct near call bridged to a native first-party callee** -- a
  ``call rel32`` whose target is a proven function entry OUTSIDE the selected
  extent is bridged through the Win64 trampoline to ``image_base + target_rva``
  (the callee is left native), instead of being rejected as out-of-extent.
* **Control-Flow-Guard dispatched indirect call** -- the MSVC
  ``mov rax, <target>; call qword ptr [__guard_dispatch_icall_fptr]`` idiom is
  bridged with the real target taken from RAX, rather than mis-read as a plain
  import call (which would jump to the dispatch thunk with RAX unmarshalled).
* **Multi-fragment (multi-range) function** -- a function the linker split into
  a hot body plus a contiguous cold return tail lifts as one body with the
  cross-fragment ``jcc`` resolved, including the cold return path.

The register marshalling, slot/target resolution and cross-fragment branch are
differential-checked against Unicorn (ground truth) vs the Daedalus reference
interpreter -- the same oracle discipline as every other lifter cut.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("iced_x86")
pytest.importorskip("keystone")
pytest.importorskip("unicorn")

from iced_x86 import Decoder, Mnemonic  # noqa: E402
from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lifter"))
sys.path.insert(0, str(ROOT / "daedalus"))

import daedalus_asm  # noqa: E402
import daedalus_ref  # noqa: E402
import oracle  # noqa: E402
import x64_lifter as lifter  # noqa: E402

_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_CODE_RVA = 0x1000


class _Section:
    def __init__(self, name, rva, virtual_size, raw, characteristics):
        self.name = name
        self.rva = rva
        self.virtual_size = virtual_size
        self.raw = raw
        self.characteristics = characteristics


def _asm(source: str, rva: int = _CODE_RVA) -> bytes:
    encoded, _ = _KS.asm(source, addr=rva)
    return bytes(encoded)


def _rip_call(code: bytes):
    return next(
        ins for ins in Decoder(64, code, ip=_CODE_RVA)
        if ins.mnemonic == Mnemonic.CALL and ins.is_ip_rel_memory_operand
    )


def _call_to_slot(source_template: str, slot_rva: int) -> bytes:
    call = _rip_call(_asm(source_template.format(disp=0)))
    disp = slot_rva - (call.ip + call.len)
    literal = hex(disp) if disp >= 0 else "-" + hex(-disp)
    encoded = _asm(source_template.format(disp=literal))
    assert _rip_call(encoded).ip_rel_memory_address == slot_rva
    return encoded


# --------------------------------------------------------------------------
# 1. Direct near call bridged to a native first-party callee.
# --------------------------------------------------------------------------
def _rdata_sections(code: bytes):
    return (
        _Section(".text", _CODE_RVA, len(code), code, 0x60000020),
        _Section(".rdata", 0x4000, 0x1000, b"\x00" * 0x1000, lifter.IMAGE_SCN_MEM_READ),
    )


def test_direct_native_call_lifts_to_bridge_at_image_base_plus_rva() -> None:
    target_rva = 0x2000
    code = _asm(f"sub rsp,0x28; call 0x{target_rva:X}; add rsp,0x28; ret")
    vasm = lifter.lift_function(
        code, base=_CODE_RVA, image_sections=_rdata_sections(code),
        selected_extents=((_CODE_RVA, len(code)),),
        native_call_targets=frozenset({target_rva}),
    )
    assert vasm.count("n_call_ptr") == 1
    # func_ptr = runtime image base + the target RVA (no slot dereference).
    assert f"local_addr {lifter.IMAGE_BASE}" in vasm
    assert f"push_imm64 0x{target_rva:016X}" in vasm
    assert "load64\n  n_call_ptr" not in vasm  # direct address, not a slot load
    assert daedalus_asm.assemble(vasm)


def test_direct_call_not_whitelisted_stays_native() -> None:
    # An out-of-extent direct call whose target is NOT a proven native entry
    # must fail closed rather than silently bridge to an unproven address.
    code = _asm("sub rsp,0x28; call 0x2000; add rsp,0x28; ret")
    with pytest.raises(lifter.LiftUnsupported, match="outside lifted function"):
        lifter.lift_function(
            code, base=_CODE_RVA, image_sections=_rdata_sections(code),
            selected_extents=((_CODE_RVA, len(code)),),
        )


def test_direct_native_call_marshalling_matches_unicorn(monkeypatch=None) -> None:
    import unicorn
    from unicorn import x86_const as ux

    image_base = 0x1_4000_0000
    mem_base = image_base + 0x1_0000
    mem_size = 0x4000
    out_off = 0x20
    out_va = mem_base + out_off
    entry_rsp = mem_base + 0x3000
    code_va = image_base + _CODE_RVA
    callee_rva = 0x2_0000
    callee_va = image_base + callee_rva
    sentinel_va = image_base + 0x3_0000
    a, b, c = 0x11, 0x2222, 0x33333333

    def fingerprint(x, y, z):
        return (x ^ (y << 16) ^ (z << 32)) & ((1 << 64) - 1)

    def out_value(x, y, z):
        return (x + y + z) & ((1 << 64) - 1)

    code = _asm(f"sub rsp,0x28; call 0x{callee_rva:X}; add rsp,0x28; ret")
    sections = _rdata_sections(code)
    program = daedalus_asm.assemble(lifter.lift_function(
        code, base=_CODE_RVA, image_sections=sections,
        selected_extents=((_CODE_RVA, len(code)),),
        native_call_targets=frozenset({callee_rva}),
    ))

    callee = _asm(
        "mov rax, rcx; mov r10, rdx; shl r10, 16; xor rax, r10; "
        "mov r10, r8; shl r10, 32; xor rax, r10; "
        "mov r11, rcx; add r11, rdx; add r11, r8; mov [r9], r11; ret",
        rva=callee_va,
    )
    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    mu.mem_map(code_va & ~0xFFF, 0x1000)
    mu.mem_map(callee_va & ~0xFFF, 0x1000)
    mu.mem_map(mem_base, mem_size)
    mu.mem_write(code_va, code)
    mu.mem_write(callee_va, callee)
    mu.mem_write(entry_rsp, sentinel_va.to_bytes(8, "little"))
    mu.reg_write(ux.UC_X86_REG_RCX, a)
    mu.reg_write(ux.UC_X86_REG_RDX, b)
    mu.reg_write(ux.UC_X86_REG_R8, c)
    mu.reg_write(ux.UC_X86_REG_R9, out_va)
    mu.reg_write(ux.UC_X86_REG_RSP, entry_rsp)
    mu.emu_start(code_va, sentinel_va)
    unicorn_rax = mu.reg_read(ux.UC_X86_REG_RAX)
    unicorn_out = int.from_bytes(bytes(mu.mem_read(out_va, 8)), "little")
    assert unicorn_rax == fingerprint(a, b, c)
    assert unicorn_out == out_value(a, b, c)

    captured = {}

    def mock_callee(vm, func_ptr, argc, argv):
        captured["func_ptr"] = func_ptr
        captured["argv"] = list(argv)
        x, y, z, out_ptr = argv[0], argv[1], argv[2], argv[3]
        buf, idx = vm._mem_ref(out_ptr, 8)
        buf[idx:idx + 8] = out_value(x, y, z).to_bytes(8, "little")
        return fingerprint(x, y, z)

    ds = int.from_bytes(program[:2], "little")
    data, code_bytes = program[2:2 + ds], program[2 + ds:]
    mem = bytearray(mem_size)
    vm = daedalus_ref.RefVM(code_bytes, data, mem=mem, mem_base=mem_base,
                            native_call_hook=mock_callee)

    def _set(reg, val):
        off = lifter.GPR_NAMES.index(reg) * 8
        vm.locals[off:off + 8] = val.to_bytes(8, "little")

    _set("rcx", a); _set("rdx", b); _set("r8", c)
    _set("r9", out_va); _set("rsp", entry_rsp)
    vm.locals[lifter.IMAGE_BASE:lifter.IMAGE_BASE + 8] = image_base.to_bytes(8, "little")
    assert vm.run() == 0

    ref_rax = int.from_bytes(
        vm.locals[lifter.GPR_NAMES.index("rax") * 8:
                  lifter.GPR_NAMES.index("rax") * 8 + 8], "little")
    ref_out = int.from_bytes(vm.mem[out_off:out_off + 8], "little")
    # func_ptr is the DIRECT image-base + target RVA (not a slot value).
    assert captured["func_ptr"] == callee_va
    assert captured["argv"][:4] == [a, b, c, out_va]
    assert ref_rax == unicorn_rax
    assert ref_out == unicorn_out


# --------------------------------------------------------------------------
# 2. Control-Flow-Guard dispatched indirect call (target in RAX).
# --------------------------------------------------------------------------
_GUARD_SLOT_RVA = 0x4008


def test_cfg_dispatch_call_bridges_via_rax_not_slot_load() -> None:
    code = _call_to_slot(
        "sub rsp,0x28; call qword ptr [rip+{disp}]; add rsp,0x28; ret",
        slot_rva=_GUARD_SLOT_RVA,
    )
    # Without the guard RVA it is an ordinary import bridge (slot load64).
    as_import = lifter.lift_function(
        code, base=_CODE_RVA, image_sections=_rdata_sections(code),
        selected_extents=((_CODE_RVA, len(code)),),
    )
    assert "load64" in as_import  # slot dereference
    # With the guard RVA it becomes a dispatch bridge: func_ptr = RAX.
    as_cfg = lifter.lift_function(
        code, base=_CODE_RVA, image_sections=_rdata_sections(code),
        selected_extents=((_CODE_RVA, len(code)),),
        guard_cf_dispatch_rva=_GUARD_SLOT_RVA,
    )
    assert as_cfg.count("n_call_ptr") == 1
    # Both forms load the four outgoing stack args; only the import form does an
    # EXTRA load64 to dereference the slot. The dispatch form reads RAX instead,
    # so it has exactly one fewer load64 and never touches the slot RVA.
    assert as_import.count("load64") == as_cfg.count("load64") + 1
    assert f"push_imm64 0x{_GUARD_SLOT_RVA:016X}" not in as_cfg
    assert daedalus_asm.assemble(as_cfg)


def test_cfg_dispatch_marshalling_and_target_match_unicorn() -> None:
    import unicorn
    from unicorn import x86_const as ux

    image_base = 0x1_4000_0000
    mem_base = image_base + 0x1_0000
    mem_size = 0x4000
    slot_off = 0x8
    out_off = 0x40
    out_va = mem_base + out_off
    slot_rva = (mem_base + slot_off) - image_base
    entry_rsp = mem_base + 0x3000
    code_va = image_base + _CODE_RVA
    thunk_va = image_base + 0x2_0000     # the `jmp rax` dispatch thunk
    callee_va = image_base + 0x2_1000    # the real CFG target (held in RAX)
    sentinel_va = image_base + 0x3_0000
    a, b, c = 0x5, 0x60, 0x700

    def fingerprint(x, y, z):
        return (x + (y << 8) + (z << 20)) & ((1 << 64) - 1)

    def out_value(x, y, z):
        return (x ^ y ^ z) & ((1 << 64) - 1)

    code = _call_to_slot(
        "sub rsp,0x28; call qword ptr [rip+{disp}]; add rsp,0x28; ret",
        slot_rva=slot_rva,
    )
    sections = (
        _Section(".text", _CODE_RVA, len(code), code, 0x60000020),
        _Section(".rdata", 0x10000, 0x4000, b"\x00" * 0x4000, lifter.IMAGE_SCN_MEM_READ),
    )
    program = daedalus_asm.assemble(lifter.lift_function(
        code, base=_CODE_RVA, image_sections=sections,
        selected_extents=((_CODE_RVA, len(code)),),
        guard_cf_dispatch_rva=slot_rva,
    ))

    thunk = _asm("jmp rax", rva=thunk_va)          # CFG dispatch thunk
    callee = _asm(
        "mov rax, rcx; shl rax, 0; add rax, rcx; "  # rax = 2*rcx placeholder
        "mov rax, rcx; mov r10, rdx; shl r10, 8; add rax, r10; "
        "mov r10, r8; shl r10, 20; add rax, r10; "   # rax = fingerprint
        "mov r11, rcx; xor r11, rdx; xor r11, r8; mov [r9], r11; ret",
        rva=callee_va,
    )
    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    mu.mem_map(code_va & ~0xFFF, 0x1000)
    mu.mem_map(thunk_va & ~0xFFF, 0x1000)
    mu.mem_map(callee_va & ~0xFFF, 0x1000)
    mu.mem_map(mem_base, mem_size)
    mu.mem_write(code_va, code)
    mu.mem_write(thunk_va, thunk)
    mu.mem_write(callee_va, callee)
    mu.mem_write(mem_base + slot_off, thunk_va.to_bytes(8, "little"))
    mu.mem_write(entry_rsp, sentinel_va.to_bytes(8, "little"))
    mu.reg_write(ux.UC_X86_REG_RAX, callee_va)     # CFG target in RAX
    mu.reg_write(ux.UC_X86_REG_RCX, a)
    mu.reg_write(ux.UC_X86_REG_RDX, b)
    mu.reg_write(ux.UC_X86_REG_R8, c)
    mu.reg_write(ux.UC_X86_REG_R9, out_va)
    mu.reg_write(ux.UC_X86_REG_RSP, entry_rsp)
    mu.emu_start(code_va, sentinel_va)
    unicorn_rax = mu.reg_read(ux.UC_X86_REG_RAX)
    unicorn_out = int.from_bytes(bytes(mu.mem_read(out_va, 8)), "little")
    assert unicorn_rax == fingerprint(a, b, c)
    assert unicorn_out == out_value(a, b, c)

    captured = {}

    def mock_callee(vm, func_ptr, argc, argv):
        captured["func_ptr"] = func_ptr
        x, y, z, out_ptr = argv[0], argv[1], argv[2], argv[3]
        buf, idx = vm._mem_ref(out_ptr, 8)
        buf[idx:idx + 8] = out_value(x, y, z).to_bytes(8, "little")
        return fingerprint(x, y, z)

    ds = int.from_bytes(program[:2], "little")
    data, code_bytes = program[2:2 + ds], program[2 + ds:]
    mem = bytearray(mem_size)
    vm = daedalus_ref.RefVM(code_bytes, data, mem=mem, mem_base=mem_base,
                            native_call_hook=mock_callee)

    def _set(reg, val):
        off = lifter.GPR_NAMES.index(reg) * 8
        vm.locals[off:off + 8] = val.to_bytes(8, "little")

    _set("rax", callee_va)                          # target the bridge forwards
    _set("rcx", a); _set("rdx", b); _set("r8", c)
    _set("r9", out_va); _set("rsp", entry_rsp)
    vm.locals[lifter.IMAGE_BASE:lifter.IMAGE_BASE + 8] = image_base.to_bytes(8, "little")
    assert vm.run() == 0

    ref_rax = int.from_bytes(
        vm.locals[lifter.GPR_NAMES.index("rax") * 8:
                  lifter.GPR_NAMES.index("rax") * 8 + 8], "little")
    ref_out = int.from_bytes(vm.mem[out_off:out_off + 8], "little")
    # The bridge forwarded RAX (the CFG target), never the dispatch thunk slot.
    assert captured["func_ptr"] == callee_va
    assert ref_rax == unicorn_rax
    assert ref_out == unicorn_out


# --------------------------------------------------------------------------
# 3. Multi-fragment function: hot body + contiguous cold return tail with a
#    cross-fragment jcc. Both the taken (cold) and fall-through paths must
#    match Unicorn exactly.
# --------------------------------------------------------------------------
_MULTI_FRAGMENT = (
    "push rbp; "
    "cmp rcx, 0x20; "
    "jne cold; "                 # cross-fragment branch to the cold tail
    "mov rax, 1; "               # hot path: return 1
    "pop rbp; ret; "
    "cold: xor eax, eax; "       # cold return-false tail
    "pop rbp; ret"
)


@pytest.mark.parametrize("rcx", [0x20, 0x00, 0x40])
def test_cold_epilogue_multifragment_matches_unicorn(rcx: int) -> None:
    code = _asm(_MULTI_FRAGMENT)
    init = [0] * 16
    init[lifter.GPR_NAMES.index("rcx")] = rcx
    init[lifter.GPR_NAMES.index("rsp")] = oracle.STACK - 0x400
    oracle.check_function(code, init)
