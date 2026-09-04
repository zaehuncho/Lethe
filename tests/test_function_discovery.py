"""Read-only function discovery and lift-coverage reporting tests."""
from __future__ import annotations

import json
import struct
from types import SimpleNamespace

import pytest


pytest.importorskip("iced_x86")
pytest.importorskip("keystone")

from keystone import KS_ARCH_X86, KS_MODE_64, Ks
from lifter import function_discovery as discovery


_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_EXEC = 0x60000020
_READ = 0x40000040


def _asm(source: str, rva: int) -> bytes:
    encoded, _count = _KS.asm(source, addr=rva)
    return bytes(encoded)


def _parsed(functions, *, start=None, end=None, path="fixture.exe"):
    ordered = sorted(functions, key=lambda item: item[0])
    section_start = ordered[0][0] if start is None else start
    section_end = max(rva + len(code) for rva, code, _flags in ordered) if end is None else end
    raw = bytearray(b"\xCC" * (section_end - section_start))
    records = []
    for rva, code, flags in ordered:
        raw[rva - section_start:rva - section_start + len(code)] = code
        records.append(SimpleNamespace(
            begin_rva=rva,
            end_rva=rva + len(code),
            unwind_info_rva=0x3000,
            unwind_flags=flags,
        ))
    return SimpleNamespace(
        path=path,
        image_base=0x140000000,
        size_of_image=0x5000,
        sections=[SimpleNamespace(
            name=".text", rva=section_start, virtual_size=len(raw), raw=bytes(raw),
            characteristics=_EXEC,
        )],
        pdata_rva=0x3000 if records else 0,
        pdata_count=len(records),
        runtime_functions=tuple(records),
    )


def test_exact_runtime_candidates_report_lift_rejection_and_handler_flags():
    good = _asm("mov eax, 7; ret", 0x1000)
    unsupported = _asm("addsd xmm0, xmm1; nop; nop; ret", 0x1100)
    handler = _asm("mov eax, 9; ret", 0x1200)
    parsed = _parsed([
        (0x1000, good, 0),
        (0x1100, unsupported, 0),
        (0x1200, handler, 1),
    ])

    report = discovery.discover_functions(
        parsed,
        exports=(discovery.ExportSymbol("good", 1, 0x1000),),
    )

    assert [item.name for item in report.candidates] == [
        "good", "sub_00001100", "sub_00001200",
    ]
    assert report.candidates[0].source == "export+pdata"
    assert report.candidates[0].exact_extent is True
    assert report.candidates[0].liftable is True
    rejected = report.candidates[1]
    assert rejected.liftable is False
    assert "mnemonic" in rejected.rejection_reason
    assert rejected.first_unsupported_instruction.rva == 0x1100
    assert "addsd" in rejected.first_unsupported_instruction.text
    assert "addsd" in rejected.rejection_reason
    assert report.candidates[2].unwind_flag_names == ("EHANDLER",)
    assert "EHANDLER" in report.candidates[2].rejection_reason
    assert all(item.indirect_target_closure_proven is False for item in report.candidates)


def test_export_without_pdata_is_bounded_plain_ret_heuristic():
    code = _asm("mov eax, 3; ret", 0x1000)
    parsed = _parsed([(0x1000, code, 0)])
    parsed.runtime_functions = ()
    parsed.pdata_rva = 0
    parsed.pdata_count = 0

    report = discovery.discover_functions(
        parsed,
        exports=(discovery.ExportSymbol("leaf", 1, 0x1000),),
    )
    candidate = report.candidates[0]

    assert candidate.extent_kind == "heuristic_plain_ret"
    assert candidate.heuristic is True
    assert candidate.exact_extent is False
    assert candidate.size == len(code)
    assert candidate.liftable is True
    assert report.starter_selection_manifest()["functions"] == []


def test_internal_call_coverage_reports_count_and_proven_depth():
    code = _asm(
        "jmp entry; inner: add rax, rdx; ret; "
        "outer: call inner; ret; entry: call outer; ret",
        0x1000,
    )
    report = discovery.discover_functions(
        _parsed([(0x1000, code, 0)]), exports=()
    )
    candidate = report.candidates[0]

    assert candidate.liftable is True
    assert candidate.internal_direct_call_count == 2
    assert candidate.max_internal_call_depth == 2
    encoded = candidate.to_dict()
    assert encoded["internal_direct_call_count"] == 2
    assert encoded["max_internal_call_depth"] == 2
    assert "CALLS" in discovery.render_table(report)


def test_export_heuristic_refuses_control_flow_and_reports_unresolved_extent():
    code = _asm("jmp 0x1010", 0x1000) + b"\xCC" * 0x20
    parsed = _parsed([(0x1000, code, 0)])
    parsed.runtime_functions = ()
    parsed.pdata_rva = 0
    parsed.pdata_count = 0

    report = discovery.discover_functions(
        parsed,
        exports=(discovery.ExportSymbol("not_leaf", 1, 0x1000),),
    )
    candidate = report.candidates[0]

    assert candidate.extent_kind == "unresolved"
    assert candidate.size == 0
    assert candidate.direct_control_proof_status == "not_run"
    assert "control transfer" in candidate.rejection_reason


def test_map_symbols_bind_only_exact_runtime_ranges():
    code = _asm("mov eax, 1; ret", 0x1000)
    parsed = _parsed([(0x1000, code, 0)])
    map_text = """
 Publics by Value              Rva+Base               Lib:Object
 0001:00000000       exact_symbol              0000000140001000 f   sample.obj
"""

    report = discovery.discover_functions(parsed, exports=(), map_text=map_text)
    assert report.candidates[0].name == "exact_symbol"
    assert report.candidates[0].source == "map+pdata"

    interior = map_text.replace("140001000", "140001001")
    with pytest.raises(discovery.FunctionDiscoveryError, match="points inside"):
        discovery.discover_functions(parsed, exports=(), map_text=interior)


def test_map_malformed_and_ambiguous_symbols_fail_closed():
    code = _asm("mov eax, 1; ret", 0x1000)
    parsed = _parsed([(0x1000, code, 0)])
    malformed = """
 Publics by Value              Rva+Base               Lib:Object
 0001:00000000       missing_rva
"""
    with pytest.raises(discovery.FunctionDiscoveryError, match="malformed"):
        discovery.discover_functions(parsed, exports=(), map_text=malformed)

    ambiguous = """
 Publics by Value              Rva+Base               Lib:Object
 0001:00000000       first                     0000000140001000 f   a.obj
 0001:00000000       second                    0000000140001000 f   b.obj
"""
    with pytest.raises(discovery.FunctionDiscoveryError, match="ambiguous"):
        discovery.discover_functions(parsed, exports=(), map_text=ambiguous)


def test_direct_interior_reference_is_reported_per_candidate():
    source = _asm("call 0x1101; ret", 0x1000)
    target = _asm("nop; mov eax, 1; ret", 0x1100)
    parsed = _parsed([(0x1000, source, 0), (0x1100, target, 0)])

    report = discovery.discover_functions(
        parsed,
        exports=(discovery.ExportSymbol("target", 1, 0x1100),),
    )
    candidate = next(item for item in report.candidates if item.name == "target")

    assert candidate.direct_control_proof_status == "rejected"
    assert "enters candidate interior" in candidate.direct_control_rejection_reason
    assert candidate.direct_reference_gate_passed is False


def test_json_table_and_starter_selection_are_deterministic():
    good = _asm("mov eax, 7; ret", 0x1000)
    handler = _asm("mov eax, 9; ret", 0x1100)
    parsed = _parsed([(0x1000, good, 0), (0x1100, handler, 2)])
    report = discovery.discover_functions(parsed, exports=())

    assert report.to_json() == report.to_json()
    encoded = json.loads(report.to_json())
    assert encoded["schema"] == discovery.REPORT_SCHEMA
    assert encoded["version"] == discovery.REPORT_VERSION
    assert "executable_coverage_gaps" in encoded["candidates"][0]
    selection = report.starter_selection_manifest()
    assert selection["schema"] == discovery.SELECTION_SCHEMA
    assert selection["functions"] == [
        {"name": "sub_00001000", "rva": 0x1000, "size": len(good)}
    ]
    table = discovery.render_table(report)
    assert "RVA" in table and "sub_00001000" in table
    assert "indirect closure: unproven" in table


def test_candidate_overlap_and_export_aliases_fail_closed():
    code = _asm("mov eax, 1; ret", 0x1000)
    parsed = _parsed([(0x1000, code, 0)], end=0x1100)
    parsed.runtime_functions = ()
    parsed.pdata_rva = 0
    parsed.pdata_count = 0
    exports = (
        discovery.ExportSymbol("first", 1, 0x1000),
        discovery.ExportSymbol("second", 2, 0x1001),
    )
    with pytest.raises(discovery.FunctionDiscoveryError, match="overlap"):
        discovery.discover_functions(parsed, exports=exports)

    aliases = (
        discovery.ExportSymbol("first", 1, 0x1000),
        discovery.ExportSymbol("second", 2, 0x1000),
    )
    with pytest.raises(discovery.FunctionDiscoveryError, match="ambiguous"):
        discovery.discover_functions(parsed, exports=aliases)


def test_strict_pe_export_parser_reads_named_runtime_entry(tmp_path):
    image = bytearray(0x200)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", image, 0x84, 0x8664)
    struct.pack_into("<H", image, 0x84 + 16, 0xF0)
    optional = 0x84 + 20
    struct.pack_into("<H", image, optional, 0x20B)
    struct.pack_into("<I", image, optional + 0x6C, 16)
    struct.pack_into("<II", image, optional + 0x70, 0x2000, 0x100)
    path = tmp_path / "exports.dll"
    path.write_bytes(image)

    edata = bytearray(0x100)
    struct.pack_into(
        "<IIHHIIIIIII", edata, 0,
        0, 0, 0, 0, 0x2080, 1, 1, 1, 0x2040, 0x2050, 0x2060,
    )
    struct.pack_into("<I", edata, 0x40, 0x1000)
    struct.pack_into("<I", edata, 0x50, 0x2070)
    struct.pack_into("<H", edata, 0x60, 0)
    edata[0x70:0x75] = b"leaf\0"
    edata[0x80:0x88] = b"testdll\0"
    code = _asm("mov eax, 1; ret", 0x1000)
    parsed = SimpleNamespace(
        path=str(path), image_base=0x140000000, size_of_image=0x5000,
        sections=[
            SimpleNamespace(name=".text", rva=0x1000, virtual_size=len(code),
                            raw=code, characteristics=_EXEC),
            SimpleNamespace(name=".edata", rva=0x2000, virtual_size=len(edata),
                            raw=bytes(edata), characteristics=_READ),
        ],
        pdata_rva=0x3000, pdata_count=1,
        runtime_functions=(SimpleNamespace(
            begin_rva=0x1000, end_rva=0x1000 + len(code),
            unwind_info_rva=0x3000, unwind_flags=0,
        ),),
    )

    assert discovery.parse_pe_exports(parsed) == (
        discovery.ExportSymbol("leaf", 1, 0x1000),
    )
