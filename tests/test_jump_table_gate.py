"""Directed tests for the compiler jump-table (data-in-code) gate.

Compiler ``switch`` jump tables live as data inside a function's ``pdata``
extent. A naive linear sweep mis-decodes the table bytes and used to poison the
whole-image direct-control gate, blocking selective virtualization of an entire
DLL. These tests exercise:

* :mod:`lifter.jump_table` -- recognition, precise delimitation, and the
  conservative bail on anything it cannot prove;
* :mod:`lifter.function_discovery` -- per-function isolation so a table (or an
  unprovable data-in-code function) makes only that one function unselectable
  while the rest of the image stays analyzable;
* :mod:`lifter.direct_control_flow` -- the strict packing proof decodes a
  switch function without choking, yet still rejects an unprovable extent.

The fixtures are position-independent MSVC-shaped switches built here, so the
tests are self-contained; the installed crown-jewel DLLs are exercised
separately by the real end-to-end pack test.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "lifter"))

pytest.importorskip("iced_x86")

from lifter import direct_control_flow as flow  # noqa: E402
from lifter import function_discovery as fd  # noqa: E402
from lifter import jump_table as jt  # noqa: E402

_EXEC = 0x60000020


def _build_switch(base: int = 0x2000, ncases: int = 4, invalid_low: int = 0x1E):
    """A PIC MSVC-style single-level dword-table switch that faults on a sweep.

    ``cmp ecx,N; ja default; lea rdx,[0]; mov eax,[rdx+rcx*4+TBL]; add rax,rdx;
    jmp rax`` followed by the case bodies, the default body, and the trailing
    dword offset table. Padding steers the first case body to an RVA whose low
    byte is an invalid 64-bit opcode, so the table's first dword faults a linear
    decode exactly the way a real compiler table does.
    """
    parts: list[bytes] = []
    parts.append(bytes([0x83, 0xF9, ncases - 1]))          # cmp ecx, N
    parts.append(bytes([0x0F, 0x87, 0, 0, 0, 0]))          # ja default (rel32)
    parts.append(bytes([0x48, 0x8D, 0x15, 0, 0, 0, 0]))    # lea rdx,[rip+..]=0
    parts.append(bytes([0x8B, 0x84, 0x8A, 0, 0, 0, 0]))    # mov eax,[rdx+rcx*4+TBL]
    parts.append(bytes([0x48, 0x01, 0xD0]))                # add rax, rdx
    parts.append(bytes([0xFF, 0xE0]))                      # jmp rax

    dispatch_end = base + sum(len(p) for p in parts)
    pad = (invalid_low - (dispatch_end & 0xFF)) & 0xFF
    parts.append(bytes([0xCC]) * pad)

    cases = []
    for index in range(ncases):
        cases.append(base + sum(len(p) for p in parts))
        parts.append(bytes([0xB8, 0x10 + index, 0, 0, 0, 0xC3]))  # mov eax,i; ret
    default_rva = base + sum(len(p) for p in parts)
    parts.append(bytes([0x31, 0xC0, 0xC3]))                # xor eax,eax; ret

    cursor = base + sum(len(p) for p in parts)
    while cursor % 4:
        parts.append(bytes([0xCC]))
        cursor += 1
    tbl = base + sum(len(p) for p in parts)
    for case in cases:
        parts.append(struct.pack("<I", case))

    blob = bytearray(b"".join(parts))
    end = base + len(blob)
    # Patch the deferred rel32 / disp32 fields now that the layout is known.
    blob[5:9] = struct.pack("<i", default_rva - (base + 9))     # ja default
    blob[12:16] = struct.pack("<i", 0 - (base + 16))            # lea rdx,[0]
    blob[19:23] = struct.pack("<I", tbl)                        # mov disp = TBL
    assert cases[0] & 0xFF == invalid_low
    return bytes(blob), base, end, tbl, tuple(cases), default_rva


def _clean(base: int, value: int = 0x1234) -> bytes:
    return bytes([0xB8]) + struct.pack("<I", value) + bytes([0xC3])  # mov eax,i; ret


def _unresolved(base: int) -> bytes:
    # A valid prologue, then a lone invalid 64-bit opcode with no table
    # reference -- the sweep faults and there is nothing to prove.
    return bytes([0x48, 0x89, 0x5C, 0x24, 0x08, 0x06, 0xC3, 0xCC])


# --------------------------------------------------------------------------- #
# lifter.jump_table
# --------------------------------------------------------------------------- #
def test_switch_table_is_recognized_and_delimited() -> None:
    blob, base, end, tbl, cases, _default = _build_switch()
    body = jt.decode_function_body(blob, base, end)
    assert body.data_ranges == ((tbl, end),)
    assert body.has_data_in_code
    assert body.has_indirect_dispatch
    assert set(body.switch_target_rvas) == set(cases)
    # No table byte survives as a decoded instruction.
    assert all(instr.ip < tbl for instr in body.instructions)
    # The table interior is not an instruction start.
    assert tbl not in body.instruction_starts


def test_clean_function_uses_fast_path() -> None:
    base = 0x1000
    code = _clean(base)
    body = jt.decode_function_body(code, base, base + len(code))
    assert body.data_ranges == ()
    assert not body.has_data_in_code
    assert not body.has_indirect_dispatch


def test_unprovable_data_in_code_bails() -> None:
    base = 0x1000
    code = _unresolved(base)
    with pytest.raises(jt.JumpTableUnresolved):
        jt.decode_function_body(code, base, base + len(code))


def test_length_mismatch_is_rejected() -> None:
    with pytest.raises(jt.JumpTableError):
        jt.decode_function_body(b"\xC3", 0x1000, 0x1004)


# --------------------------------------------------------------------------- #
# fixtures for the two gates
# --------------------------------------------------------------------------- #
def _section(rva: int, raw: bytes, name: str = ".text"):
    return SimpleNamespace(
        name=name, rva=rva, virtual_size=len(raw), raw=raw,
        characteristics=_EXEC,
    )


def _dcf_parsed(functions):
    """A minimal ParsedPE for direct_control_flow (single .text section)."""
    ordered = sorted(functions)
    start = ordered[0][0]
    end = max(rva + len(code) for rva, code in ordered)
    raw = bytearray(b"\xCC" * (end - start))
    records = []
    for rva, code in ordered:
        raw[rva - start:rva - start + len(code)] = code
        records.append(SimpleNamespace(
            begin_rva=rva, end_rva=rva + len(code),
            unwind_info_rva=0x30000, unwind_flags=0,
        ))
    return SimpleNamespace(
        sections=[_section(start, bytes(raw))],
        runtime_functions=tuple(records),
    )


def _fd_parsed(functions, *, image_base=0x180000000):
    ordered = sorted(functions)
    start = ordered[0][0]
    text_end = max(rva + len(code) for rva, code in ordered)
    raw = bytearray(b"\xCC" * (text_end - start))
    records = []
    for rva, code in ordered:
        raw[rva - start:rva - start + len(code)] = code
        records.append(SimpleNamespace(
            begin_rva=rva, end_rva=rva + len(code),
            unwind_info_rva=0x30000, unwind_flags=0,
        ))
    pdata_rva = 0x40000
    size_of_image = 0x80000
    return SimpleNamespace(
        image_base=image_base,
        size_of_image=size_of_image,
        sections=[_section(start, bytes(raw))],
        runtime_functions=tuple(records),
        pdata_count=len(records),
        pdata_rva=pdata_rva,
        path="",
    )


def _spec(name, rva, code):
    return SimpleNamespace(name=name, rva=rva, size=len(code))


# --------------------------------------------------------------------------- #
# lifter.function_discovery -- whole-image isolation
# --------------------------------------------------------------------------- #
def test_discovery_not_poisoned_by_switch_table() -> None:
    switch, sbase, send, _tbl, _cases, _default = _build_switch(base=0x2000)
    clean_rva = 0x1000
    clean = _clean(clean_rva)
    parsed = _fd_parsed([(clean_rva, clean), (sbase, switch)])
    report = fd.discover_functions(parsed, exports=())

    assert report.direct_control_analysis_status == "passed"
    assert report.direct_control_analysis_error is None
    by_rva = {c.rva: c for c in report.candidates}
    # The clean leaf is now selectable (not poisoned by the switch table).
    assert by_rva[clean_rva].direct_control_proof_status == "passed"
    assert by_rva[clean_rva].liftable
    # The switch function decodes (table excised) and is not poisoned either;
    # it is simply not liftable because of its indirect dispatch.
    assert by_rva[sbase].direct_control_proof_status == "passed"
    assert not by_rva[sbase].liftable


def test_discovery_isolates_unprovable_function() -> None:
    bad_rva = 0x2000
    bad = _unresolved(bad_rva)
    clean_rva = 0x1000
    clean = _clean(clean_rva)
    parsed = _fd_parsed([(clean_rva, clean), (bad_rva, bad)])
    report = fd.discover_functions(parsed, exports=())

    # Whole image is NOT poisoned.
    assert report.direct_control_analysis_status == "passed"
    by_rva = {c.rva: c for c in report.candidates}
    assert by_rva[clean_rva].direct_control_proof_status == "passed"
    assert by_rva[clean_rva].liftable
    # Only the unprovable function is rejected (bailed to native).
    assert by_rva[bad_rva].direct_control_proof_status == "rejected"
    assert "unresolved data-in-code" in by_rva[bad_rva].direct_control_rejection_reason


# --------------------------------------------------------------------------- #
# lifter.direct_control_flow -- strict packing proof
# --------------------------------------------------------------------------- #
def test_strict_gate_decodes_switch_function() -> None:
    switch, sbase, send, _tbl, _cases, _default = _build_switch(base=0x2000)
    clean_rva = 0x1000
    clean = _clean(clean_rva)
    parsed = _dcf_parsed([(clean_rva, clean), (sbase, switch)])
    # Selecting the clean leaf must succeed even though the image contains a
    # switch function with an inline jump table.
    proof = flow.analyze_direct_control_flow(
        parsed, [_spec("clean", clean_rva, clean)], production=False,
    )
    assert any(f.rva == clean_rva for f in proof.selected_functions)


def test_strict_gate_still_rejects_unprovable_extent() -> None:
    bad_rva = 0x2000
    bad = _unresolved(bad_rva)
    clean_rva = 0x1000
    clean = _clean(clean_rva)
    parsed = _dcf_parsed([(clean_rva, clean), (bad_rva, bad)])
    with pytest.raises(flow.DirectControlFlowError, match="undecodable"):
        flow.analyze_direct_control_flow(
            parsed, [_spec("clean", clean_rva, clean)], production=False,
        )


# --------------------------------------------------------------------------- #
# lifter.direct_control_flow -- chain-group isolation (strict-gate unblock)
#
# A compiler split a switch/dispatch into a primary pdata record (the indexing
# instruction) plus a contiguous CHAININFO fragment carrying the jump table.
# The fragment does NOT decode in isolation (no in-extent table reference), so
# it used to poison the whole-image strict proof and block the DLL. The pass
# now isolates the whole contiguous chain group (decoded and proven as one
# extent) instead, while never allowing an isolated function to be selected.
# --------------------------------------------------------------------------- #
_DISPATCH_LEN = 28  # cmp+ja+lea+mov+add+jmp = 3+6+7+7+3+2


def _split_switch(base: int = 0x2000):
    """A PIC MSVC switch split at the dispatch/table boundary.

    Returns ``(primary_code, fragment_code, base, end, split)`` where the
    primary holds the ``cmp/ja/lea/mov[*4+TBL]/jmp`` dispatch and the fragment
    holds the case bodies plus the trailing dword table. The fragment alone has
    no in-extent scaled-index reference (that lives in the primary), so it does
    not decode standalone -- exactly like the real SecurityCore/AutomationCore/
    RemotePlayCore cold-fragment jump tables.
    """
    blob, sbase, send, _tbl, _cases, _default = _build_switch(base=base)
    split = base + _DISPATCH_LEN
    return blob[:_DISPATCH_LEN], blob[_DISPATCH_LEN:], base, send, split


def _dcf_parsed_chained(functions):
    """A minimal ParsedPE whose records carry unwind flags + chain primaries.

    ``functions`` items are ``(rva, code, unwind_flags, chain_primary_rva)``.
    """
    ordered = sorted(functions, key=lambda item: item[0])
    start = ordered[0][0]
    end = max(rva + len(code) for rva, code, _f, _c in ordered)
    raw = bytearray(b"\xCC" * (end - start))
    records = []
    for rva, code, unwind_flags, chain_primary in ordered:
        raw[rva - start:rva - start + len(code)] = code
        records.append(SimpleNamespace(
            begin_rva=rva, end_rva=rva + len(code),
            unwind_info_rva=0x30000, unwind_flags=unwind_flags,
            chain_primary_rva=chain_primary,
        ))
    return SimpleNamespace(
        sections=[_section(start, bytes(raw))],
        runtime_functions=tuple(records),
    )


def test_split_chain_fragment_is_unresolvable_alone_but_group_decodes() -> None:
    primary, fragment, base, end, split = _split_switch()
    # The fragment alone cannot be proven (no in-extent table reference).
    with pytest.raises(jt.JumpTableUnresolved):
        jt.decode_function_body(fragment, split, end)
    # The whole contiguous chain group resolves the table from the primary's
    # in-group dispatch reference (the same trusted machinery).
    body = jt.decode_function_body(primary + fragment, base, end)
    assert body.has_data_in_code and body.has_indirect_dispatch


def test_strict_gate_isolates_split_chain_group() -> None:
    primary, fragment, base, end, split = _split_switch(base=0x2000)
    clean_rva = 0x1000
    clean = _clean(clean_rva)
    parsed = _dcf_parsed_chained([
        (clean_rva, clean, 0, 0),
        (base, primary, 0, 0),            # primary dispatch record
        (split, fragment, 0x4, base),     # CHAININFO fragment carrying the table
    ])
    # Selecting the clean leaf now SUCCEEDS: the split chain group no longer
    # poisons the whole-image proof -- it is isolated whole.
    proof = flow.analyze_direct_control_flow(
        parsed, [_spec("clean", clean_rva, clean)], production=False,
    )
    assert any(f.rva == clean_rva for f in proof.selected_functions)
    assert len(proof.isolated_runtime_functions) == 1
    isolated = proof.isolated_runtime_functions[0]
    assert isolated.begin_rva == base
    assert isolated.end_rva == end
    assert isolated.chain_primary_rva == base
    assert isolated.fragment_count == 2


def test_strict_gate_refuses_to_select_an_isolated_fragment() -> None:
    # The differential-oracle contract: an isolated (un-decodable) function must
    # be provably EXCLUDED from selection, never silently quarantined. Selecting
    # the table-bearing fragment therefore hard-fails rather than isolating it.
    primary, fragment, base, end, split = _split_switch(base=0x2000)
    clean_rva = 0x1000
    clean = _clean(clean_rva)
    parsed = _dcf_parsed_chained([
        (clean_rva, clean, 0, 0),
        (base, primary, 0, 0),
        (split, fragment, 0x4, base),
    ])
    with pytest.raises(flow.DirectControlFlowError, match="cannot isolate"):
        flow.analyze_direct_control_flow(
            parsed, [_spec("frag", split, fragment)], production=False,
        )
