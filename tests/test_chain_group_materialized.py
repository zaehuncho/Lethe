"""Materialized Windows EXE/DLL parity for complete CHAININFO groups.

Both binaries are generated afresh.  A single existing unwind record is split
into a contiguous primary and a real CHAININFO fragment in independent copies;
no product, tracked prebuilt, or installed binary is used by these tests.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

import pefile
import pytest

from lifter import direct_control_flow, function_discovery, virtualization_plan
from packer import assemble, orchestrator, pe_analyze, report, virtualize
from tests import test_native_virtualization_runtime as native_fixture


_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def built_runtime():
    if os.name != "nt" or not shutil.which("cmake") or not native_fixture._visual_studio_available():
        pytest.skip("Windows and the Visual Studio x64 toolchain are required")
    work = Path(tempfile.mkdtemp(prefix=".chain_group_e2e_", dir=_ROOT)).resolve()
    assert work.parent == _ROOT.resolve() and work.name.startswith(".chain_group_e2e_")
    try:
        candidate = (os.environ.get("LETHE_CHAIN_GROUP_CANDIDATE_PATH")
                     or os.environ.get(native_fixture._STUB_PATH_ENV))
        if candidate:
            from tools.promote_stub import validate_candidate_bundle
            stub = Path(candidate).resolve()
            verified = validate_candidate_bundle(stub, stub.with_suffix(".manifest.json"))
            head = subprocess.check_output(["git", "rev-parse", "HEAD"],
                                           cwd=_ROOT, text=True).strip()
            assert verified["source_commit"] == head
            assert not subprocess.check_output(["git", "status", "--porcelain"],
                                               cwd=_ROOT).strip()
            allow_override = False
        else:
            stub = native_fixture._build_stub(work)
            allow_override = True
        yield work, stub, allow_override
    finally:
        assert work.parent == _ROOT.resolve() and work.name.startswith(".chain_group_e2e_")
        shutil.rmtree(work)


def _run(kind: str, source: Path, host: Path | None) -> subprocess.CompletedProcess[bytes]:
    argv = [str(source)] if kind == "exe" else [str(host), str(source)]
    return subprocess.run(argv, capture_output=True, timeout=30, check=False)


def _mutate_chain(source: Path, target: Path, kind: str) -> tuple[int, int, int]:
    """Split an assembled function at an instruction boundary, preserving raw bytes."""
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    parsed = pe_analyze.analyze_pe(str(source))
    image = assemble._StubImage(source.read_bytes())
    name = "vm_native_helper" if kind == "exe" else "vm_dll_leaf"
    begin = image.find_export_rva(name)
    assert begin is not None
    original, = (item for item in parsed.runtime_functions if item.begin_rva == begin)
    assert original.unwind_flags == original.chain_primary_rva == 0
    body = image.read_at_rva(begin, original.end_rva - begin)
    if kind == "exe":
        assert body == bytes.fromhex("B82800000083C002C3")
        split, end = begin + 5, begin + 9
    else:
        assert body == bytes.fromhex("4883EC08B82900000083C0014883C408C3CCCC")
        split, end = begin + 12, begin + 17
    assert begin < split < end <= original.end_rva

    raw = bytearray(source.read_bytes())
    pe = pefile.PE(data=bytes(raw))
    pdata = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".pdata")
    rdata = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".rdata")
    exception = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    assert exception.VirtualAddress == parsed.pdata_rva
    assert exception.Size == 12 * len(parsed.runtime_functions)

    # Reserve a 16-byte aligned, zero-filled tail in the existing file-backed
    # read-only section.  Expand VirtualSize only within its raw allocation.
    offset = (rdata.Misc_VirtualSize + 15) & ~15
    assert offset + 16 <= rdata.SizeOfRawData
    chain_rva = rdata.VirtualAddress + offset
    chain_file = rdata.PointerToRawData + offset
    assert raw[chain_file:chain_file + 16] == bytes(16)
    raw[chain_file:chain_file + 16] = (
        b"\x21\0\0\0" + struct.pack(
            "<III", begin, split, original.unwind_info_rva))
    struct.pack_into("<I", raw, rdata.get_file_offset() + 8, offset + 16)

    rows = []
    for item in parsed.runtime_functions:
        if item.begin_rva == begin:
            rows.append((begin, split, original.unwind_info_rva))
            rows.append((split, end, chain_rva))
        else:
            rows.append((item.begin_rva, item.end_rva, item.unwind_info_rva))
    assert len(rows) == len(parsed.runtime_functions) + 1
    packed_rows = b"".join(struct.pack("<III", *item) for item in rows)
    table_offset = pe.get_offset_from_rva(parsed.pdata_rva)
    assert table_offset == pdata.PointerToRawData
    assert len(packed_rows) <= pdata.SizeOfRawData
    assert raw[table_offset + exception.Size:table_offset + len(packed_rows)] == (
        bytes(len(packed_rows) - exception.Size))
    raw[table_offset:table_offset + len(packed_rows)] = packed_rows
    struct.pack_into("<I", raw, exception.get_file_offset() + 4, len(packed_rows))
    struct.pack_into("<I", raw, pdata.get_file_offset() + 8,
                     max(pdata.Misc_VirtualSize, len(packed_rows)))
    changed_pe = pefile.PE(data=bytes(raw))
    struct.pack_into("<I", raw,
                     changed_pe.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum"),
                     changed_pe.generate_checksum())
    target.write_bytes(raw)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash

    changed = pe_analyze.analyze_pe(str(target))
    members = [item for item in changed.runtime_functions
               if item.begin_rva in (begin, split)]
    assert [(item.begin_rva, item.end_rva, item.unwind_flags,
             item.chain_primary_rva) for item in members] == [
        (begin, split, 0, 0), (split, end, 4, begin)]
    discovery = function_discovery.discover_functions(changed)
    candidate, = (item for item in discovery.candidates if item.rva == begin)
    assert candidate.extent_kind == "runtime_function_group"
    assert candidate.size == end - begin and candidate.liftable
    assert all(item.rva != split for item in discovery.candidates)
    return begin, split, end


@pytest.mark.parametrize("kind", ("exe", "dll"))
def test_complete_chain_group_materializes_and_runs(kind: str, built_runtime, monkeypatch):
    work, stub, allow_override = built_runtime
    case = work / kind
    case.mkdir()
    if kind == "exe":
        source = native_fixture._build_fixture(case)
        host = None
        expected = b"vm-answer=42\r\n"
    else:
        source, host = native_fixture._build_dll_fixture(case)
        expected = b"dll-answer=42\r\n"
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    chained = case / ("chained.exe" if kind == "exe" else "chained.dll")
    begin, split, end = _mutate_chain(source, chained, kind)
    before = _run(kind, source, host)
    modified_unpacked = _run(kind, chained, host)
    assert (before.returncode, before.stdout, before.stderr) == (
        modified_unpacked.returncode, modified_unpacked.stdout,
        modified_unpacked.stderr) == (0, expected, b"")

    parsed = pe_analyze.analyze_pe(str(chained))
    spec = virtualization_plan.FunctionSpec(
        "vm_native_helper" if kind == "exe" else "vm_dll_leaf",
        begin, end - begin)
    proof = direct_control_flow.analyze_direct_control_flow(
        parsed, (spec,), production=False)
    gaps = tuple(orchestrator.VirtualizationGapAcknowledgement(
        item.rva, item.size, "generated chain fixture executable gap")
        for item in proof.coverage_gaps)
    packed_path = case / ("chained.packed.exe" if kind == "exe"
                          else "chained.packed.dll")
    observed = {}
    original_materialize = virtualize.materialize_selected_functions

    def capture(*args, **kwargs):
        value = original_materialize(*args, **kwargs)
        observed["value"] = value
        return value

    monkeypatch.setattr(virtualize, "materialize_selected_functions", capture)
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION", "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")
    outcome = orchestrator.pack_file(str(chained), orchestrator.PackOptions(
        output_path=str(packed_path), is_dll=(kind == "dll"),
        stub_path=str(stub),
        virtualization_specs=(orchestrator.VirtualizationSpec(
            spec.name, begin, end - begin),),
        virtualization_gap_acknowledgements=gaps,
        acknowledge_unproven_indirect_targets=True,
        _allow_unverified_stub_for_tests=allow_override,
    ))
    assert outcome.ok, outcome.error
    materialized = observed["value"]
    assert len(materialized.manifest.functions) == 1
    assert [item.begin_rva for item in materialized.manifest.exception_table.removed] == [
        begin, split]
    assert len(materialized.manifest.exception_table.generated) == 1
    assert report.validate_packed(str(packed_path)).ok
    after = _run(kind, packed_path, host)
    assert (after.returncode, after.stdout, after.stderr) == (0, expected, b"")
    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash


@pytest.mark.skipif(os.name != "nt", reason="native Windows loader only")
def test_address_taken_chain_group_rejects_before_output(built_runtime, monkeypatch):
    """The old exported DIR64 entry pointer remains an explicit negative."""
    work, stub, allow_override = built_runtime
    case = work / "address-taken-negative"
    case.mkdir()
    source, host = native_fixture._build_dll_fixture(
        case, address_taken_entry=True)
    assert _run("dll", source, host).returncode == 0
    chained = case / "chained-address-taken.dll"
    begin, _split, end = _mutate_chain(source, chained, "dll")
    original = _run("dll", chained, host)
    assert (original.returncode, original.stdout, original.stderr) == (
        0, b"dll-answer=42\r\n", b"")
    parsed = pe_analyze.analyze_pe(str(chained))
    spec = virtualization_plan.FunctionSpec("vm_dll_leaf", begin, end - begin)
    with pytest.raises(direct_control_flow.DirectControlFlowError,
                       match="known source reference: DIR64 address"):
        direct_control_flow.analyze_direct_control_flow(
            parsed, (spec,), production=False)
    output = case / "must-not-exist.dll"
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION", "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")
    outcome = orchestrator.pack_file(str(chained), orchestrator.PackOptions(
        output_path=str(output), is_dll=True, stub_path=str(stub),
        virtualization_specs=(orchestrator.VirtualizationSpec(
            spec.name, begin, end - begin),),
        acknowledge_unproven_indirect_targets=True,
        _allow_unverified_stub_for_tests=allow_override,
    ))
    assert not outcome.ok and "known source reference: DIR64 address" in outcome.error
    assert not output.exists()
