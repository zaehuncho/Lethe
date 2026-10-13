"""A proven materialized native CALL writes the source architectural slot.

The imported EXE/DLL alias fixture exercises the same behavior with the real
runtime.  These small tests pin all three emitter routes and the proof gate.
The bridge callee's own physical [RSP] still contains its trampoline return.
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

K = Ks(KS_ARCH_X86, KS_MODE_64)
BASE = 0x1000
SLOT = 0x4000
TARGET = 0x2000


class Section:
    def __init__(self, name, rva, raw, characteristics):
        self.name = name
        self.rva = rva
        self.virtual_size = len(raw)
        self.raw = raw
        self.characteristics = characteristics


def asm(source):
    encoded, _ = K.asm(source, addr=BASE)
    return bytes(encoded)


def body(kind, depth=0x28):
    if kind == "direct":
        return asm(f"sub rsp,0x{depth:x}; call 0x{TARGET:x}; add rsp,0x{depth:x}; ret")
    source = f"sub rsp,0x{depth:x}; call qword ptr [rip+{{disp}}]; add rsp,0x{depth:x}; ret"
    probe = asm(source.format(disp=0))
    call = next(i for i in Decoder(64, probe, ip=BASE) if i.mnemonic == Mnemonic.CALL)
    displacement = SLOT - (call.ip + call.len)
    result = asm(source.format(disp=hex(displacement)))
    assert next(i for i in Decoder(64, result, ip=BASE)
                if i.mnemonic == Mnemonic.CALL).ip_rel_memory_address == SLOT
    return result


def sections(code):
    return (
        Section(".text", BASE, code, 0x60000020),
        Section(".rdata", SLOT, b"\0" * 0x1000, lifter.IMAGE_SCN_MEM_READ),
    )


def lift(code, kind, spans):
    return lifter.lift_function(
        code, base=BASE, image_sections=sections(code),
        selected_extents=((BASE, len(code)),),
        native_call_targets={TARGET} if kind == "direct" else frozenset(),
        guard_cf_dispatch_rva=SLOT if kind == "guard" else None,
        native_call_stack_bytes=spans,
    )


def expected_slot_write(call):
    return "\n".join((
        f"  local_addr {lifter.REG_OFF[lifter.Register.RSP]}",
        "  load64",
        "  push_imm64 0x0000000000000008",
        "  sub",
        f"  local_addr {lifter.IMAGE_BASE}",
        "  load64",
        f"  push_imm64 0x{call.ip + call.len:016X}",
        "  add",
        "  store64",
    ))


@pytest.mark.parametrize("kind", ["import", "guard", "direct"])
@pytest.mark.parametrize("depth,span", [(0x28, 8), (0x1F8, 472)])
def test_proven_native_call_writes_loader_relocated_next_ip(kind, depth, span):
    code = body(kind, depth)
    call = next(i for i in Decoder(64, code, ip=BASE) if i.mnemonic == Mnemonic.CALL)
    spans = {}
    maximum = lifter.validate_materialized_stack_window(
        code, base=BASE, window_size=512,
        native_call_targets={TARGET} if kind == "direct" else frozenset(),
        native_call_stack_bytes=spans,
    )
    assert maximum == depth and spans == {call.ip: span}
    assert -(depth + 8) >= -512  # slot is inside the reserved source window
    vasm = lift(code, kind, spans)
    assert vasm.count(expected_slot_write(call)) == 1
    assert vasm.index(expected_slot_write(call)) < vasm.index("n_call_frame_span")
    assert vasm.count("n_call_frame_span") == 1
    assert daedalus_asm.assemble(vasm)


@pytest.mark.parametrize("kind", ["import", "guard", "direct"])
def test_legacy_diagnostic_native_bridge_does_not_claim_stack_slot(kind):
    code = body(kind)
    call = next(i for i in Decoder(64, code, ip=BASE) if i.mnemonic == Mnemonic.CALL)
    vasm = lift(code, kind, None)
    assert "n_call_frame_span" not in vasm
    assert vasm.count("n_call_frame") == 1
    assert expected_slot_write(call) not in vasm


@pytest.mark.parametrize("spans", [{}, {0x1004: 0}, {0x1004: 480}, {0x1004: True}])
def test_native_source_slot_requires_aligned_proven_span(spans):
    code = body("direct")
    with pytest.raises(lifter.LiftUnsupported, match="unproven Win64 native CALL return slot"):
        lift(code, "direct", spans)


@pytest.mark.parametrize("depth,reason", [(0x18, "unproven Win64 native outgoing frame"),
                                          (0x200, "exceeds 512-byte window")])
def test_native_source_slot_rejects_insufficient_or_unaligned_frame(depth, reason):
    code = body("direct", depth)
    with pytest.raises(lifter.LiftUnsupported, match=reason):
        lifter.validate_materialized_stack_window(
            code, base=BASE, window_size=512,
            native_call_targets={TARGET}, native_call_stack_bytes={},
        )



def test_first_external_call_invalidates_previous_pointer_spill_in_return_slot():
    # The first architectural CALL overwrites [RSP-8].  A second CALL may
    # pass that now-code pointer in RCX; treating the pre-call RSP spill as
    # still live would incorrectly claim a source-stack-pointer escape.
    code = asm(
        "sub rsp,0x28; mov [rsp-8],rsp; call 0x2000; "
        "mov rcx,[rsp-8]; call 0x2000; add rsp,0x28; ret"
    )
    calls = [i for i in Decoder(64, code, ip=BASE) if i.mnemonic == Mnemonic.CALL]
    assert len(calls) == 2
    spans = {}
    assert lifter.validate_materialized_stack_window(
        code, base=BASE, window_size=512,
        native_call_targets={TARGET}, native_call_stack_bytes=spans,
    ) == 0x28
    assert spans == {call.ip: 8 for call in calls}
    vasm = lift(code, "direct", spans)
    assert all(vasm.count(expected_slot_write(call)) == 1 for call in calls)