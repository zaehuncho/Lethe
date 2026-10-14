"""Genuine MASM/LINK/DIA-bound static inventories; no fixture is executed."""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess

import pytest
from iced_x86 import OpAccess, Register

from lifter import direct_control_flow as flow, pdb_coverage as coverage
from lifter import guard_slot_references as refs
from packer import pe_analyze


_ASM = r"""OPTION CASEMAP:NONE
.const
ALIGN 8
PUBLIC cf_check_slot, cf_dispatch_slot
cf_check_slot QWORD OFFSET cf_check_nop
cf_dispatch_slot QWORD OFFSET cf_nop
xfg_check_slot QWORD OFFSET cf_check_nop
xfg_dispatch_slot QWORD OFFSET cf_nop
xfg_table_slot QWORD OFFSET cf_nop
gfids DWORD IMAGEREL probe
EXTRA
ALIGN 8
PUBLIC _load_config_used
_load_config_used LABEL BYTE
 DD 320
 DB 84 DUP(0)
 DQ 0
 DB 16 DUP(0)
 DQ OFFSET cf_check_slot
 DQ OFFSET cf_dispatch_slot
 DQ OFFSET gfids
 DQ 1
 DD 500h
 DB 12 DUP(0)
 DQ 0,0,0,0
 DB 88 DUP(0)
 DQ OFFSET xfg_check_slot
 DQ OFFSET xfg_dispatch_slot
 DQ OFFSET xfg_table_slot
 DQ 0,0
.code
PUBLIC probe
probe PROC FRAME
 .endprolog
 ret
probe ENDP
PUBLIC source_body
source_body PROC FRAME
 .endprolog
 BODY
 ret
source_body ENDP
cf_check_nop PROC FRAME
 .endprolog
 ret
cf_check_nop ENDP
cf_nop PROC FRAME
 .endprolog
 jmp rax
cf_nop ENDP
END
"""


@pytest.fixture(scope="module")
def native_case(tmp_path_factory):
    """Build real PE/RSDS/PDBs and call the production proof/binding APIs."""
    root = tmp_path_factory.mktemp("gr")
    installations = sorted(Path(os.environ.get("ProgramFiles", r"C:\Program Files")).glob(
        "Microsoft Visual Studio/2022/*/VC/Tools/MSVC/*/bin/Hostx64/x64"))
    tool = installations[-1] if installations else Path("missing")
    helper = Path(os.environ.get("LETHE_GUARD_TEST_DIA_HELPER", "missing"))
    dia = Path(os.environ.get("LETHE_GUARD_TEST_MSDIA", "missing"))
    required = (tool/"ml64.exe", tool/"link.exe", helper, dia)
    if os.name != "nt" or not all(p.is_file() for p in required):
        if os.environ.get("LETHE_GUARD_REFERENCE_REQUIRE_NATIVE") == "1":
            pytest.fail("mandatory real MASM/LINK/DIA fixture inputs are absent")
        pytest.skip("real Windows MASM/LINK/DIA inputs are not configured")
    cache = {}

    def build(body="call qword ptr [cf_dispatch_slot]", extra=""):
        key = (body, extra)
        if key in cache:
            parsed, binding = cache[key]
            return copy.deepcopy(parsed), binding
        folder = root/sha256(repr(key).encode()).hexdigest()[:12]
        folder.mkdir()
        source, obj, image = (folder/n for n in ("f.asm", "f.obj", "f.exe"))
        source.write_text(_ASM.replace("BODY", body).replace("EXTRA", extra), encoding="ascii")
        commands = ([str(tool/"ml64.exe"), "/nologo", "/c", "/Zi", "/Fo"+str(obj), str(source)],
                    [str(tool/"link.exe"), "/nologo", "/MACHINE:X64", "/NODEFAULTLIB", "/ENTRY:probe",
                     "/SUBSYSTEM:CONSOLE", "/DYNAMICBASE", "/NXCOMPAT", "/GUARD:CF", "/DEBUG",
                     "/DEBUGTYPE:CV", "/OPT:NOREF", "/OPT:NOICF", "/INCREMENTAL:NO",
                     "/OUT:"+str(image), "/PDB:"+str(image.with_suffix(".pdb")), str(obj)])
        for command in commands:
            done = subprocess.run(command, cwd=folder, capture_output=True, timeout=60, check=False)
            assert done.returncode == 0, (command, done.stdout, done.stderr)
        parsed = pe_analyze.analyze_pe(str(image))
        selected = (flow.SelectedFunctionRange("probe", 0x1000, 1),)
        proof = coverage.prove_pdb_executable_coverage(parsed, image, image.with_suffix(".pdb"),
                                                       helper, dia, selected)
        binding = coverage.bind_pdb_commit_proof(parsed, proof, selected)
        coverage.validate_pdb_commit_binding(parsed, selected, binding)
        cache[key] = (copy.deepcopy(parsed), binding)
        return parsed, binding
    return build


def collect(parsed, binding):
    evidence = refs.PdbInputFiles(
        Path(parsed.path).with_suffix(".pdb"),
        Path(os.environ["LETHE_GUARD_TEST_DIA_HELPER"]),
        Path(os.environ["LETHE_GUARD_TEST_MSDIA"]))
    return refs.collect_guard_slot_references(parsed, binding, pdb_inputs=evidence)


def matching(inventory, kind="cf_dispatch"):
    return [r for r in inventory.references if any(t.kind == kind for t in r.targets)]


def test_actual_binding_positive_is_frozen_and_has_no_admission(native_case):
    parsed, binding = native_case()
    before = copy.deepcopy(parsed)
    got = collect(parsed, binding)
    assert parsed == before
    assert got.identity.image_sha256 == binding.image_sha256
    assert got.identity.rsds_age > 0 and got.unique_instruction_count > 0
    assert len(matching(got)) == 1 and matching(got)[0].kind == "canonical_memory_CALL"
    assert got.xfg_fields_present and not got.xfg_enabled
    assert {s.kind for s in got.slots} == {"cf_check", "cf_dispatch", "xfg_check", "xfg_dispatch", "xfg_table"}
    with pytest.raises(FrozenInstanceError):
        got.guard_flags = 0
    encoded = got.canonical_bytes()
    assert encoded == collect(parsed, binding).canonical_bytes()
    assert json.loads(encoded)["identity"]["binding_sha256"] == binding.binding_sha256
    assert not any(hasattr(got, name) for name in ("admitted", "production_ready", "closure_proven"))
    assert {u.reason for u in got.unresolved} >= {"unknown_computed_reference_routes",
        "external_host_and_callback_routes", "resident_runtime_target_domains", "runtime_page_and_slot_lifetime"}
    markers = {"unknown_computed_reference_routes", "external_host_and_callback_routes",
               "resident_runtime_target_domains", "runtime_page_and_slot_lifetime"}
    assert all(u.count == 1 and u.example_rvas == () for u in got.unresolved if u.reason in markers)
    assert all(rva > 0 for u in got.unresolved for rva in u.example_rvas)


@pytest.mark.parametrize("value", [None, {}, [], True, "binding"])
def test_arbitrary_serialized_or_structural_binding_never_accepted(value):
    with pytest.raises(refs.GuardReferenceError, match="exact ParsedPE"):
        refs.collect_guard_slot_references(value, value, pdb_inputs=None)


@pytest.mark.parametrize("field", ["image_sha256", "pdb_sha256", "helper_sha256", "msdia_sha256",
                                    "source_parsed_sha256", "binding_sha256", "supplemental_ranges"])
def test_changed_binding_is_actually_replayed(native_case, field):
    parsed, bound = native_case()
    changed = replace(bound, **{field: ((1,2),) if field == "supplemental_ranges" else "f"*64})
    with pytest.raises(refs.GuardReferenceError, match="source|binding"):
        collect(parsed, changed)


@pytest.mark.parametrize("field,value", [("pdb_sha256", "A"*64), ("helper_sha256", "x"*64),
                                         ("msdia_sha256", True), ("binding_sha256", "0")])
def test_malformed_hashes_reject_before_authority(native_case, field, value):
    parsed, bound = native_case()
    with pytest.raises(refs.GuardReferenceError, match="canonical"):
        collect(parsed, replace(bound, **{field:value}))


@pytest.mark.parametrize("field", ["pdb_sha256", "helper_sha256", "msdia_sha256"])
def test_self_rehashed_external_identity_forgery_rejects_actual_files(native_case, field):
    parsed, bound = native_case()
    changed = replace(bound, **{field:"f"*64})
    changed = replace(changed, binding_sha256=coverage._binding_sha256(changed))
    with pytest.raises(refs.GuardReferenceError, match="external"):
        collect(parsed, changed)


def test_actual_wrong_PDB_with_matching_rehashed_digest_still_rejects(native_case):
    parsed, bound = native_case()
    other, _ = native_case("nop")
    other_pdb = Path(other.path).with_suffix(".pdb")
    changed = replace(bound,pdb_sha256=sha256(other_pdb.read_bytes()).hexdigest())
    changed = replace(changed,binding_sha256=coverage._binding_sha256(changed))
    evidence = refs.PdbInputFiles(other_pdb,Path(os.environ["LETHE_GUARD_TEST_DIA_HELPER"]),
                                  Path(os.environ["LETHE_GUARD_TEST_MSDIA"]))
    with pytest.raises(refs.GuardReferenceError, match="GUID/age"):
        refs.collect_guard_slot_references(parsed,changed,pdb_inputs=evidence)


def test_missing_external_evidence_has_no_legacy_fallback(native_case):
    parsed,bound=native_case()
    with pytest.raises(TypeError,match="pdb_inputs"):
        refs.collect_guard_slot_references(parsed,bound)
    with pytest.raises(refs.GuardReferenceError,match="PdbInputFiles"):
        refs.collect_guard_slot_references(parsed,bound,pdb_inputs={})


def test_collector_rebuilds_real_external_coverage_and_entire_binding(native_case,monkeypatch):
    parsed,bound=native_case()
    original=coverage.prove_pdb_executable_coverage
    called=[]
    def observe(*args,**kwargs):
        called.append(args)
        return original(*args,**kwargs)
    monkeypatch.setattr(coverage,"prove_pdb_executable_coverage",observe)
    got=collect(parsed,bound)
    assert len(called)==1 and got.identity.binding_sha256==bound.binding_sha256


def test_literal_work_limit_is_fail_closed(native_case,monkeypatch):
    parsed,bound=native_case()
    monkeypatch.setattr(refs,"_MAX_LITERAL_SEARCH_WORK",1)
    with pytest.raises(refs.GuardReferenceError,match="literal scan work"):
        collect(parsed,bound)


def test_input_size_limit_is_checked_before_helper_replay(native_case,monkeypatch):
    parsed,bound=native_case()
    monkeypatch.setattr(refs,"_MAX_INPUT_TOTAL",1)
    with pytest.raises(refs.GuardReferenceError,match="size bounds"):
        collect(parsed,bound)


def test_absolute_addr32_crossing_remains_unresolved(native_case):
    got=collect(*native_case("DB 067h,048h,0A1h\n DD 0FFFFFFFCh"))
    assert any(u.reason=="address_size_span_boundary" for u in got.unresolved)


@pytest.mark.parametrize("mutation", ["slot_rva", "slot_overlap", "guard_flags", "section_bytes", "runtime", "writable"])
def test_parsed_metadata_cannot_be_rebound_away_from_real_PE(native_case, mutation):
    parsed, bound = native_case()
    if mutation == "slot_rva":parsed.load_config = replace(parsed.load_config, guard_cf_dispatch_function_pointer_rva=1)
    if mutation == "slot_overlap":parsed.load_config = replace(parsed.load_config, guard_xfg_check_function_pointer_rva=parsed.load_config.guard_cf_dispatch_function_pointer_rva)
    if mutation == "guard_flags":parsed.load_config = replace(parsed.load_config, guard_flags=0)
    if mutation == "section_bytes":parsed.sections[0].raw = b"\x90"+parsed.sections[0].raw[1:]
    if mutation == "runtime":parsed.runtime_functions = parsed.runtime_functions[:-1]
    if mutation == "writable":parsed.sections[1].characteristics |= 0x80000000
    # Even recomputing caller-visible digests cannot replace exact-file metadata.
    changed = replace(bound, source_parsed_sha256=coverage.parsed_source_sha256(parsed))
    changed = replace(changed, binding_sha256=coverage._binding_sha256(changed))
    with pytest.raises(refs.GuardReferenceError, match="snapshot"):
        collect(parsed, changed)


@pytest.mark.parametrize("body,access,width", [
    ("mov rax,qword ptr [cf_dispatch_slot]",OpAccess.READ,8),
    ("mov qword ptr [cf_dispatch_slot],rax",OpAccess.WRITE,8),
    ("lock xadd qword ptr [cf_dispatch_slot],rax",OpAccess.READ_WRITE,8),
    ("movdqu xmm0,xmmword ptr [cf_dispatch_slot-1]",OpAccess.READ,16),
])
def test_full_memory_span_and_access_not_only_start_equality(native_case, body, access, width):
    got = collect(*native_case(body))
    row = matching(got)[0]
    assert row.access == access and row.width == width
    if width == 16:
        assert {t.kind for t in row.targets} >= {"cf_check", "cf_dispatch", "xfg_check"}


@pytest.mark.parametrize("body", ["rep movsq", "rep stosq", "push rax\n pop rax", "call qword ptr [cf_dispatch_slot]"])
def test_implicit_string_stack_and_CALL_domains_are_retained(native_case, body):
    got = collect(*native_case(body))
    assert any(u.reason == "base_index_or_implicit_memory" and u.count for u in got.unresolved)
    if "rep" in body:
        assert any(u.reason == "variable_or_unknown_memory_extent" for u in got.unresolved)


@pytest.mark.parametrize("segment", ["fs", "gs"])
def test_FS_GS_base_domain_is_not_flat_source_reference(native_case, segment):
    got = collect(*native_case(f"mov rax,{segment}:[60h]"))
    assert not matching(got)
    assert any(u.reason == "FS_GS_segment_base" for u in got.unresolved)


@pytest.mark.parametrize("segment", ["fs", "gs"])
def test_FS_GS_relative_slot_shape_keeps_existing_proof_rejection(native_case, segment):
    with pytest.raises(coverage.PdbCoverageError, match="unbounded source reference"):
        native_case(f"mov rax,{segment}:[cf_dispatch_slot]")


def test_EIP_relative_at_actual_high_image_VA_does_not_become_local_RVA(native_case):
    with pytest.raises(coverage.PdbCoverageError, match="address-size-relative"):
        native_case("DB 067h,048h,08bh,005h\n DD 0")


@pytest.mark.parametrize("body,kind", [("lea rax,cf_dispatch_slot+1","address_take_LEA"),
    ("mov rax,OFFSET cf_dispatch_slot+1","immediate_VA_candidate"),
    ("mov eax,IMAGEREL cf_dispatch_slot+1","immediate_RVA_candidate")])
def test_LEA_immediate_and_interior_candidates_remain_distinct(native_case, body, kind):
    got = collect(*native_case(body))
    assert any(r.kind == kind and any(t.kind == "cf_dispatch" and t.target_offset == 1 for t in r.targets)
               for r in got.references)


def test_DIR64_and_unaligned_raw_data_interior_literals_are_candidates(native_case):
    got = collect(*native_case("nop", "DB 0A5h\n literal_pointer QWORD OFFSET cf_dispatch_slot+1\n scalar DWORD IMAGEREL cf_dispatch_slot+2"))
    assert any(d.encoding == "DIR64_VA" and any(t.kind=="cf_dispatch" and t.target_offset==1 for t in d.targets) for d in got.data_references)
    assert any(d.encoding == "RVA32_candidate" and any(t.kind=="cf_dispatch" and t.target_offset==2 for t in d.targets) for d in got.data_references)


@pytest.mark.parametrize("register", ["rdx", "r9"])
def test_exact_alias_preserves_original_call_geometry_without_waiver(native_case, register):
    got = collect(*native_case(f"mov {register},qword ptr [cf_dispatch_slot]\n call {register}"))
    assert len(got.aliases)==1
    alias=got.aliases[0]
    assert alias.slot_kind=="cf_dispatch" and alias.call_rva==alias.load_rva+7
    assert alias.call_end_rva==alias.call_rva+len(alias.call_bytes)
    assert alias.register == (Register.RDX if register=="rdx" else Register.R9)


@pytest.mark.parametrize("body", ["mov rdx,[cf_dispatch_slot]\n nop\n call rdx",
                                 "mov rdx,[cf_dispatch_slot]\n call r9",
                                 "mov edx,dword ptr [cf_dispatch_slot]\n call rdx"])
def test_noncanonical_aliases_not_silently_normalized(native_case, body):
    assert collect(*native_case(body)).aliases == ()


def test_incoming_direct_reference_to_alias_CALL_interior_is_retained(native_case):
    got = collect(*native_case("jnz alias_call\n mov rdx,[cf_dispatch_slot]\nalias_call:\n call rdx"))
    assert len(got.aliases)==1 and got.aliases[0].known_interior_reference_rvas


def test_check_XFG_and_fallback_references_are_separate(native_case):
    got = collect(*native_case("mov rax,[cf_check_slot]\n mov rax,[xfg_dispatch_slot]\n jmp cf_nop"))
    assert matching(got,"cf_check") and matching(got,"xfg_dispatch")
    assert any(r.kind=="direct_transfer" and any(t.kind=="cf_dispatch_initial_target" for t in r.targets) for r in got.references)


@pytest.mark.parametrize("filename,rva,size,expected", [("VisionCore.dll",0x2bf0,103,231),
                                                       ("OrionNative.exe",0xa890,40,58542)])
def test_exact_product_read_only_inventory_parity(filename,rva,size,expected):
    product=os.environ.get("LETHE_GUARD_REFERENCE_PRODUCT_ROOT")
    pdbroot=os.environ.get("LETHE_GUARD_REFERENCE_PDB_ROOT")
    if not product or not pdbroot:
        pytest.skip("explicit read-only exact-product/PDB roots are not configured")
    image=Path(product)/filename;pdb=Path(pdbroot)/image.with_suffix(".pdb").name
    parsed=pe_analyze.analyze_pe(str(image));selected=(flow.SelectedFunctionRange("inventory",rva,size),)
    proof=coverage.prove_pdb_executable_coverage(parsed,image,pdb,Path(os.environ["LETHE_GUARD_TEST_DIA_HELPER"]),Path(os.environ["LETHE_GUARD_TEST_MSDIA"]),selected)
    bound=coverage.bind_pdb_commit_proof(parsed,proof,selected)
    before=sha256(image.read_bytes()).hexdigest()
    got=refs.collect_guard_slot_references(parsed,bound,pdb_inputs=refs.PdbInputFiles(pdb,Path(os.environ["LETHE_GUARD_TEST_DIA_HELPER"]),Path(os.environ["LETHE_GUARD_TEST_MSDIA"])))
    assert len(got.indirect_instruction_rvas)==expected and len(got.aliases)==2
    assert len(matching(got))==(10 if filename.endswith("dll") else 53)
    assert sha256(image.read_bytes()).hexdigest()==before

