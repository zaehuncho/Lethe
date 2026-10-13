"""Retained PDATA call admission versus low-level diagnostic bridge behavior.

The direct bridge can match scalar fixtures in a diagnostic interpreter, but
that does not prove physical return-slot identity for a materialized program.
Discovery and planning therefore reject this exact caller by default.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("iced_x86")
pytest.importorskip("keystone")
pytest.importorskip("unicorn")

from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "lifter"))
sys.path.insert(0, str(ROOT / "daedalus"))

import daedalus_asm  # noqa: E402
import daedalus_ref  # noqa: E402
import x64_lifter as lifter  # noqa: E402
from lifter import function_discovery as discovery  # noqa: E402

import unicorn  # noqa: E402
from unicorn import x86_const as ux  # noqa: E402

_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_EXEC = 0x60000020
_IMAGE_BASE = 0x140000000

CALLER_RVA = 0x1000
CALLEE_RVA = 0x1200
# F(a, b) = G(a, b) + 1, where G(a, b) = a + b, reached ONLY through the bridged
# direct call.  A shadow-space reservation frames the Win64 call.
_CALLER_SRC = (
    "sub rsp, 0x28; "
    "call 0x{callee:X}; "
    "add rax, 1; "
    "add rsp, 0x28; "
    "ret"
).format(callee=CALLEE_RVA)
_CALLEE_SRC = "lea rax, [rcx + rdx]; ret"


def _asm(source: str, rva: int) -> bytes:
    encoded, _count = _KS.asm(source, addr=rva)
    return bytes(encoded)


def _parsed(functions):
    ordered = sorted(functions, key=lambda item: item[0])
    section_start = ordered[0][0]
    section_end = max(rva + len(code) for rva, code in ordered)
    raw = bytearray(b"\xCC" * (section_end - section_start))
    records = []
    for rva, code in ordered:
        raw[rva - section_start:rva - section_start + len(code)] = code
        records.append(SimpleNamespace(
            begin_rva=rva, end_rva=rva + len(code),
            unwind_info_rva=0x3000, unwind_flags=0,
        ))
    return SimpleNamespace(
        path="fixture.dll", image_base=_IMAGE_BASE, size_of_image=0x5000,
        sections=[SimpleNamespace(
            name=".text", rva=section_start, virtual_size=len(raw),
            raw=bytes(raw), characteristics=_EXEC,
        )],
        pdata_rva=0x3000, pdata_count=len(records),
        runtime_functions=tuple(records),
    )


def _candidate(report, rva):
    return next(item for item in report.candidates if item.rva == rva)


def test_direct_retained_pdata_call_is_not_selectable_via_discovery():
    caller = _asm(_CALLER_SRC, CALLER_RVA)
    callee = _asm(_CALLEE_SRC, CALLEE_RVA)
    parsed = _parsed([(CALLER_RVA, caller), (CALLEE_RVA, callee)])

    report = discovery.discover_functions(parsed, exports=())
    caller_c = _candidate(report, CALLER_RVA)
    callee_c = _candidate(report, CALLEE_RVA)

    # A matching PDATA entry proves an extent, not the physical CALL frame.
    assert caller_c.liftable is False
    assert "retained PDATA native CALL lacks physical return-slot" in caller_c.rejection_reason
    assert caller_c.direct_control_proof_status == "passed"
    assert caller_c.exact_extent is True
    assert caller_c.extent_kind == "runtime_function"
    assert caller_c.unwind_flags == 0
    # This never becomes an admitted internal or native call.
    assert caller_c.internal_direct_call_count == 0
    assert callee_c.liftable is True

    # Only the independently liftable callee may appear in starter selection.
    selected = {entry["rva"] for entry in report.starter_selection_manifest()["functions"]}
    assert CALLER_RVA not in selected and CALLEE_RVA in selected


def test_direct_internal_call_bailed_before_wiring():
    # Fail-closed baseline: with NO native_call_targets (the pre-Cut-17 discovery
    # behaviour) the identical extent bails on the out-of-extent call.
    caller = _asm(_CALLER_SRC, CALLER_RVA)
    callee = _asm(_CALLEE_SRC, CALLEE_RVA)
    parsed = _parsed([(CALLER_RVA, caller), (CALLEE_RVA, callee)])
    sections = discovery._validate_image(parsed)
    runtime = discovery._runtime_ranges(parsed, sections)
    extents = discovery._build_extents(
        parsed, sections, runtime, (), (), discovery.DEFAULT_LEAF_CAP)
    caller_extent = next(e for e in extents if e.rva == CALLER_RVA)

    liftable, reason, _first, _refs = discovery._lift_status(caller_extent, sections)
    assert liftable is False
    assert "call target outside lifted function" in reason


def test_unproven_direct_call_still_bails():
    # A direct call to an address that is NOT a proven pdata BeginAddress must
    # still fail closed even with the wiring active.
    caller = _asm(
        "sub rsp, 0x28; call 0x{t:X}; add rsp, 0x28; ret".format(t=0x1800),
        CALLER_RVA,
    )
    callee = _asm(_CALLEE_SRC, CALLEE_RVA)   # real pdata entry, but NOT the target
    parsed = _parsed([(CALLER_RVA, caller), (CALLEE_RVA, callee)])
    report = discovery.discover_functions(parsed, exports=())
    caller_c = _candidate(report, CALLER_RVA)
    assert caller_c.liftable is False
    assert "call target outside lifted function" in caller_c.rejection_reason


def _run_callee_native(argv):
    """Ground-truth: execute G's real bytes in Unicorn at its image VA."""
    callee = _asm(_CALLEE_SRC, CALLEE_RVA)
    callee_va = _IMAGE_BASE + CALLEE_RVA
    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    page = callee_va & ~0xFFF
    mu.mem_map(page, 0x1000)
    stack = 0x50000000
    mu.mem_map(stack & ~0xFFF, 0x2000)
    mu.mem_write(callee_va, callee)
    ret_sentinel = callee_va + 0x800
    rsp = stack + 0x800
    mu.mem_write(rsp, struct.pack("<Q", ret_sentinel))
    for reg, val in zip(
        (ux.UC_X86_REG_RCX, ux.UC_X86_REG_RDX, ux.UC_X86_REG_R8, ux.UC_X86_REG_R9),
        (argv + [0, 0, 0, 0])[:4],
    ):
        mu.reg_write(reg, val & ((1 << 64) - 1))
    mu.reg_write(ux.UC_X86_REG_RSP, rsp)
    mu.emu_start(callee_va, ret_sentinel)
    return mu.reg_read(ux.UC_X86_REG_RAX) & ((1 << 64) - 1)


@pytest.mark.parametrize("a,b", [(0, 0), (1, 2), (0x100, 0x37), (0xFFFFFFFF, 1),
                                 (0x123456789A, 0xF)])
def test_bridged_caller_dual_runs_byte_identical_to_native(a: int, b: int) -> None:
    caller = _asm(_CALLER_SRC, CALLER_RVA)
    callee = _asm(_CALLEE_SRC, CALLEE_RVA)
    caller_va = _IMAGE_BASE + CALLER_RVA
    callee_va = _IMAGE_BASE + CALLEE_RVA
    mask = (1 << 64) - 1

    # ---- native ground truth: both functions mapped, call runs inline. -------
    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    page = (caller_va & ~0xFFF)
    mu.mem_map(page, 0x2000)
    stack = 0x50000000
    mu.mem_map(stack & ~0xFFF, 0x4000)
    mu.mem_write(caller_va, caller)
    mu.mem_write(callee_va, callee)
    ret_sentinel = page + 0x1800
    rsp = stack + 0x2000
    mu.mem_write(rsp, struct.pack("<Q", ret_sentinel))
    mu.reg_write(ux.UC_X86_REG_RCX, a & mask)
    mu.reg_write(ux.UC_X86_REG_RDX, b & mask)
    mu.reg_write(ux.UC_X86_REG_RSP, rsp)
    mu.emu_start(caller_va, ret_sentinel)
    native_rax = mu.reg_read(ux.UC_X86_REG_RAX) & mask

    # ---- lifted: caller virtualized, callee bridged to native (Unicorn). -----
    parsed = _parsed([(CALLER_RVA, caller), (CALLEE_RVA, callee)])
    sections = discovery._validate_image(parsed)
    runtime = discovery._runtime_ranges(parsed, sections)
    native_call_targets = frozenset(
        item.begin for item in runtime
        if not (CALLER_RVA <= item.begin < CALLER_RVA + len(caller))
    )
    assert CALLEE_RVA in native_call_targets
    vasm = lifter.lift_function(
        caller, base=CALLER_RVA, image_sections=sections,
        selected_extents=((CALLER_RVA, len(caller)),),
        source_extent_size=len(caller),
        native_call_targets=native_call_targets,
    )
    assert vasm.count("n_call_frame") == 1
    program = daedalus_asm.assemble(vasm)

    captured = {}

    def bridge(vm, func_ptr, argc, argv):
        captured["func_ptr"] = func_ptr
        return _run_callee_native(list(argv[:4]))

    ds = int.from_bytes(program[:2], "little")
    data, code_bytes = program[2:2 + ds], program[2 + ds:]
    # Back the caller stack frame so the Win64 marshalling's [RSP+0x20..0x38]
    # reads resolve (the callee ignores those surplus slots).
    stack_base = 0x50000000
    stack_mem = bytearray(0x4000)
    vm = daedalus_ref.RefVM(
        code_bytes, data, native_frame_hook=bridge,
        mem=stack_mem, mem_base=stack_base)

    def _set(reg, val):
        off = lifter.GPR_NAMES.index(reg) * 8
        vm.locals[off:off + 8] = (val & mask).to_bytes(8, "little")

    _set("rcx", a)
    _set("rdx", b)
    _set("rsp", 0x50002000)
    vm.locals[lifter.IMAGE_BASE:lifter.IMAGE_BASE + 8] = _IMAGE_BASE.to_bytes(8, "little")
    assert vm.run() == 0

    lifted_rax = int.from_bytes(
        vm.locals[lifter.GPR_NAMES.index("rax") * 8:
                  lifter.GPR_NAMES.index("rax") * 8 + 8], "little")

    assert captured["func_ptr"] == callee_va       # bridged to image_base + RVA
    assert lifted_rax == native_rax == ((a + b + 1) & mask)
