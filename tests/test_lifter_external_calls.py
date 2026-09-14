"""Lifter-level coverage for the external-call ABI bridge (Cut: import calls).

These tests need only iced-x86 + keystone (no MSVC): they prove that the
standard MSVC ``call qword ptr [rip+disp32]`` import form lifts to the Win64
native-call bridge and assembles, that the internal-call analysis treats it as
an external transfer (never an in-extent frame), and that every other call
shape and every unmapped/executable slot still fails closed. End-to-end
execution correctness is proven separately by the native runtime differential
test.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


pytest.importorskip("iced_x86")
pytest.importorskip("keystone")

from iced_x86 import Decoder, Mnemonic  # noqa: E402
from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lifter"))
sys.path.insert(0, str(ROOT / "daedalus"))

import daedalus_asm  # noqa: E402
import x64_lifter as lifter  # noqa: E402


_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_CODE_RVA = 0x1000
_SLOT_RVA = 0x4000


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


def _call_to_slot(source_template: str, slot_rva: int = _SLOT_RVA) -> bytes:
    """Assemble a body whose RIP-relative call resolves to ``slot_rva``."""
    call = _rip_call(_asm(source_template.format(disp=0)))
    disp = slot_rva - (call.ip + call.len)
    literal = hex(disp) if disp >= 0 else "-" + hex(-disp)
    encoded = _asm(source_template.format(disp=literal))
    assert _rip_call(encoded).ip_rel_memory_address == slot_rva
    return encoded


def _data_sections(code: bytes, *, characteristics=lifter.IMAGE_SCN_MEM_READ):
    return (
        _Section(".text", _CODE_RVA, len(code), code, 0x60000020),
        _Section(".rdata", 0x4000, 0x1000, b"\x00" * 0x1000, characteristics),
    )


def _lift(code: bytes, sections=None):
    if sections is None:
        sections = _data_sections(code)
    return lifter.lift_function(
        code,
        base=_CODE_RVA,
        image_sections=sections,
        selected_extents=((_CODE_RVA, len(code)),),
    )


_IMPORT_CALLER = (
    "sub rsp, 0x38; mov [rsp+0x20], rsi; mov [rsp+0x28], rdi; "
    "call qword ptr [rip+{disp}]; add rsp, 0x38; ret"
)


def test_import_call_lifts_to_native_bridge_and_assembles() -> None:
    code = _call_to_slot(_IMPORT_CALLER)
    vasm = _lift(code)
    # The bridge marshals the four register args, four outgoing stack slots, a
    # fixed argc of 8, and the slot-resolved pointer, then dispatches n_call_ptr
    # and commits RAX.
    assert "n_call_ptr" in vasm
    assert vasm.count("n_call_ptr") == 1
    # slot address = runtime image base local + decoded slot RVA.
    assert f"local_addr {lifter.IMAGE_BASE}" in vasm
    assert f"push_imm64 0x{_SLOT_RVA:016X}" in vasm
    # The bytecode is well-formed for the assembler and the wire format.
    blob = daedalus_asm.assemble(vasm)
    assert blob


def test_import_call_is_external_not_internal() -> None:
    code = _call_to_slot(_IMPORT_CALLER)
    analysis = lifter.analyze_internal_calls(code, _CODE_RVA)
    assert analysis.internal_call_rvas == ()
    assert analysis.internal_return_rvas == ()
    assert len(analysis.top_level_return_rvas) == 1
    assert analysis.max_call_depth == 0


def test_internal_and_import_calls_coexist() -> None:
    # A direct in-extent call to a helper plus an external import call.
    code = _call_to_slot(
        "jmp entry; "
        "helper: add rax, rcx; ret; "
        "entry: call helper; call qword ptr [rip+{disp}]; ret"
    )
    analysis = lifter.analyze_internal_calls(code, _CODE_RVA)
    assert len(analysis.internal_call_rvas) == 1      # only the helper call
    assert len(analysis.internal_return_rvas) == 1    # helper's ret
    assert len(analysis.top_level_return_rvas) == 1   # the entry's ret
    vasm = _lift(code)
    assert "n_call_ptr" in vasm
    assert daedalus_asm.assemble(vasm)


@pytest.mark.parametrize(
    ("source", "reason"),
    (
        ("call rax; ret", "indirect / non-near call"),
        ("call qword ptr [rax]; ret", "indirect / non-near call"),
        ("call qword ptr [rax+0x10]; ret", "indirect / non-near call"),
        ("call qword ptr [rbx+rcx*8]; ret", "indirect / non-near call"),
    ),
)
def test_non_rip_indirect_calls_stay_native(source: str, reason: str) -> None:
    code = _asm(source)
    with pytest.raises(lifter.LiftUnsupported, match=reason):
        _lift(code)


def test_import_call_without_section_geometry_fails_closed() -> None:
    code = _call_to_slot(_IMPORT_CALLER)
    with pytest.raises(lifter.LiftUnsupported, match="mapped image-section"):
        lifter.lift_function(code, base=_CODE_RVA)


def test_import_slot_in_executable_section_fails_closed() -> None:
    code = _call_to_slot(_IMPORT_CALLER)
    executable = (
        _Section(".text", _CODE_RVA, 0x8000, code + b"\x00" * 0x8000,
                 0x60000020),
    )
    with pytest.raises(lifter.LiftUnsupported, match="executable"):
        _lift(code, sections=executable)


def test_import_call_arg_marshalling_matches_unicorn_callout() -> None:
    """Oracle-modeled proof of the argument marshalling and slot resolution.

    Unicorn executes the real caller and a real callee stub reached through the
    RIP-relative slot; the reference VM runs the lifted bytecode with a Python
    mock callee that consumes the marshalled ``argv`` identically. The return
    value and the callee's output-parameter memory must match. This isolates the
    parts of the call-out that CAN be modeled in Python (register marshalling,
    slot dereference, output-pointer write, return value) without a native
    toolchain; execution of a real Win64 frame is proven by the native test.
    """
    unicorn = pytest.importorskip("unicorn")
    from unicorn import x86_const as ux  # noqa: E402

    daedalus_ref = __import__("daedalus_ref")

    image_base = 0x1_4000_0000
    mem_base = image_base + 0x1_0000          # above image base -> positive RVAs
    mem_size = 0x4000
    slot_off = 0x10
    out_off = 0x20
    slot_rva = (mem_base + slot_off) - image_base
    out_va = mem_base + out_off
    entry_rsp = mem_base + 0x3000
    code_va = image_base + _CODE_RVA
    callee_va = image_base + 0x2_0000
    sentinel_va = image_base + 0x3_0000

    a, b, c = 0x11, 0x2222, 0x33333333

    def fingerprint(x, y, z):
        return (x ^ (y << 16) ^ (z << 32)) & ((1 << 64) - 1)

    def out_value(x, y, z):
        return (x + y + z) & ((1 << 64) - 1)

    # Caller: reserve shadow space, call through the slot, unwind, return.
    code = _call_to_slot(
        "sub rsp, 0x28; call qword ptr [rip+{disp}]; add rsp, 0x28; ret",
        slot_rva=slot_rva,
    )
    sections = (
        _Section(".text", _CODE_RVA, len(code), code, 0x60000020),
        _Section(".rdata", 0x10000, 0x4000, b"\x00" * 0x4000,
                 lifter.IMAGE_SCN_MEM_READ),
    )
    program = daedalus_asm.assemble(
        lifter.lift_function(
            code, base=_CODE_RVA, image_sections=sections,
            selected_extents=((_CODE_RVA, len(code)),),
        )
    )

    # ---- ground truth: Unicorn executes the real caller + callee stub ----
    callee = _asm(
        "mov rax, rcx; mov r10, rdx; shl r10, 16; xor rax, r10; "
        "mov r10, r8; shl r10, 32; xor rax, r10; "        # rax = fingerprint
        "mov r11, rcx; add r11, rdx; add r11, r8; mov [r9], r11; "  # *out
        "ret",
        rva=callee_va,
    )
    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    mu.mem_map(code_va & ~0xFFF, 0x1000)
    mu.mem_map(callee_va & ~0xFFF, 0x1000)
    mu.mem_map(mem_base, mem_size)
    mu.mem_write(code_va, code)
    mu.mem_write(callee_va, callee)
    mu.mem_write(mem_base + slot_off, callee_va.to_bytes(8, "little"))
    mu.mem_write(entry_rsp, sentinel_va.to_bytes(8, "little"))  # caller's return
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

    # ---- candidate: the reference VM runs the lift with a mock callee ----
    captured = {}

    def mock_callee(vm, func_ptr, argc, argv):
        captured["func_ptr"] = func_ptr
        captured["argc"] = argc
        captured["argv"] = list(argv)
        x, y, z, out_ptr = argv[0], argv[1], argv[2], argv[3]
        buf, idx = vm._mem_ref(out_ptr, 8)
        buf[idx:idx + 8] = out_value(x, y, z).to_bytes(8, "little")
        return fingerprint(x, y, z)

    ds = int.from_bytes(program[:2], "little")
    data, code_bytes = program[2:2 + ds], program[2 + ds:]
    mem = bytearray(mem_size)
    mem[slot_off:slot_off + 8] = callee_va.to_bytes(8, "little")
    vm = daedalus_ref.RefVM(
        code_bytes, data, mem=mem, mem_base=mem_base,
        native_call_hook=mock_callee,
    )

    def _set(reg_name, value):
        off = lifter.GPR_NAMES.index(reg_name) * 8
        vm.locals[off:off + 8] = value.to_bytes(8, "little")

    _set("rcx", a)
    _set("rdx", b)
    _set("r8", c)
    _set("r9", out_va)
    _set("rsp", entry_rsp)
    vm.locals[lifter.IMAGE_BASE:lifter.IMAGE_BASE + 8] = (
        image_base.to_bytes(8, "little")
    )
    assert vm.run() == 0

    ref_rax = int.from_bytes(
        vm.locals[lifter.GPR_NAMES.index("rax") * 8:
                  lifter.GPR_NAMES.index("rax") * 8 + 8], "little"
    )
    ref_out = int.from_bytes(vm.mem[out_off:out_off + 8], "little")

    # The bridge marshalled the four register args and resolved the slot.
    assert captured["argc"] == 8
    assert captured["argv"][:4] == [a, b, c, out_va]
    assert captured["func_ptr"] == callee_va
    # And the modeled call-out agrees with the real Unicorn execution.
    assert ref_rax == unicorn_rax
    assert ref_out == unicorn_out


def test_import_slot_in_selected_extent_fails_closed() -> None:
    # A slot RVA that falls inside the selected function extent must be rejected
    # (it would collide with virtualized code rather than name import data).
    code = _call_to_slot(_IMPORT_CALLER, slot_rva=_CODE_RVA + 4)
    sections = (
        _Section(".text", _CODE_RVA, 0x8000, code + b"\x00" * 0x8000,
                 lifter.IMAGE_SCN_MEM_READ),
    )
    with pytest.raises(lifter.LiftUnsupported, match="overlaps selected"):
        _lift(code, sections=sections)
