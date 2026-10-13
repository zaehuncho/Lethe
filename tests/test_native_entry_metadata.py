"""Mandatory materialized EXE/DLL export-interior rejection and entry controls."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from lifter import direct_control_flow, function_discovery, virtualization_plan
from packer import assemble, orchestrator, pe_analyze
from tests import test_native_known_references as known
from tests import test_native_virtualization_runtime as runtime


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str], cwd: Path) -> dict:
    process = subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL,
                             capture_output=True, timeout=180)
    return {
        "command": command,
        "stdout": process.stdout.decode("utf-8", errors="replace"),
        "stderr": process.stderr.decode("utf-8", errors="replace"),
        "exit_status": process.returncode,
    }


def _build(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    build = tmp_path / "build"
    source.mkdir()
    c = known._C
    c = c.replace(
        "extern int vm_probe(void);",
        "extern unsigned char __ImageBase;\n"
        "typedef unsigned int (__cdecl *AliasFn)(void);\n"
        "__declspec(dllimport) AliasFn __stdcall GetProcAddress(void*,const char*);\n"
        "extern int vm_probe(void);",
    )
    assert "unsigned int n=native_probe();" in c
    c = c.replace(
        "unsigned int n=native_probe();",
        'AliasFn alias=GetProcAddress(&__ImageBase,"probe_alias");'
        "unsigned int n=alias?alias():999U;",
    )
    (source / "fixture.c").write_text(c, encoding="utf-8")
    (source / "host.cpp").write_text(known._HOST, encoding="utf-8")
    cmake = [
        "cmake_minimum_required(VERSION 3.20)",
        "project(export_entry_metadata C CXX ASM_MASM)",
        "add_executable(reference_host host.cpp)",
    ]
    for mode in ("entry", "interior"):
        alias = "probe_alias LABEL NEAR\n"
        assembly = (
            "OPTION CASEMAP:NONE\nPUBLIC vm_probe\nPUBLIC probe_alias\n"
            "PUBLIC native_probe\nPUBLIC reference_slot\n.data\n"
            "reference_slot QWORD vm_probe\n.code\n"
            "vm_probe PROC FRAME\n .endprolog\n"
            + (alias if mode == "entry" else "") + " nop\n"
            + (alias if mode == "interior" else "")
            + " mov eax,42\n ret\nvm_probe ENDP\n"
            "native_probe PROC FRAME\n .endprolog\n xor eax,eax\n ret\n"
            "native_probe ENDP\nEND\n"
        )
        (source / f"{mode}.asm").write_text(assembly, encoding="utf-8")
        for role in ("exe", "dll"):
            target = f"{mode}_{role}"
            cmake += [
                ("add_executable" if role == "exe" else "add_library")
                + f"({target}" + (" SHARED" if role == "dll" else "")
                + f" fixture.c {mode}.asm)",
                f"target_compile_options({target} PRIVATE "
                "$<$<COMPILE_LANGUAGE:C>:/W4;/WX;/O2;/GS->)",
                f"target_compile_definitions({target} PRIVATE EXPECTED=42"
                + (" BUILD_DLL=1)" if role == "dll" else ")"),
                f"target_link_options({target} PRIVATE /INCREMENTAL:NO "
                "/OPT:NOICF /DYNAMICBASE /NXCOMPAT /CETCOMPAT:NO "
                "/NODEFAULTLIB /EXPORT:probe_alias /EXPORT:reference_slot,DATA "
                + ("/ENTRY:fixture_entry /SUBSYSTEM:CONSOLE)" if role == "exe"
                   else "/ENTRY:DllMain /MANIFEST:NO)"),
                f"target_link_libraries({target} PRIVATE kernel32.lib)",
            ]
    (source / "CMakeLists.txt").write_text("\n".join(cmake) + "\n", encoding="utf-8")
    for command in (
        ["cmake", "-S", str(source), "-B", str(build),
         "-G", "Visual Studio 17 2022", "-A", "x64"],
        ["cmake", "--build", str(build), "--config", "Release"],
    ):
        result = _run(command, tmp_path)
        assert result["exit_status"] == 0, result
    return build / "Release"


@pytest.mark.skipif(os.name != "nt" or os.environ.get(runtime._RUN_GATE) != "1",
                    reason="opt-in Windows native materialized acceptance")
def test_materialized_export_entry_metadata_exe_and_dll(tmp_path, monkeypatch):
    release = _build(tmp_path)
    strict = os.environ.get("LETHE_STRICT_REFERENCE_STUB_PATH")
    stub = Path(strict) if strict else runtime._candidate_stub_or_build(tmp_path)
    pinned = {str(stub): _sha256(stub)}
    if strict:
        manifest = stub.with_suffix(".manifest.json")
        pinned[str(manifest)] = _sha256(manifest)
    monkeypatch.setenv(runtime._VIRTUALIZATION_GATE, "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")
    records = []
    for mode in ("entry", "interior"):
        for role in ("exe", "dll"):
            original = release / f"{mode}_{role}.{role}"
            host = release / "reference_host.exe"
            original_sha256 = _sha256(original)
            original_command = ([str(host), str(original)] if role == "dll"
                                else [str(original)])
            before = _run(original_command, tmp_path)
            assert before == {
                "command": original_command,
                "stdout": "KNOWN_REFERENCE result=42 observed=42 passed=true\n",
                "stderr": "",
                "exit_status": 0,
            }
            parsed = pe_analyze.analyze_pe(str(original))
            image = assemble._StubImage(original.read_bytes())
            alias = image.find_export_rva("probe_alias")
            selected_rva = alias - (mode == "interior")
            matching = [item for item in parsed.runtime_functions
                        if item.begin_rva == selected_rva]
            assert len(matching) == 1 and matching[0].end_rva == selected_rva + 7
            spec = virtualization_plan.FunctionSpec("vm_probe", selected_rva, 7)
            # Explicit advisory exports cannot conceal a real on-disk EAT
            # target when discovery computes its direct-reference gate.
            if mode == "interior":
                report = function_discovery.discover_functions(parsed, exports=())
                candidate = next(item for item in report.candidates
                                 if item.rva == selected_rva)
                assert candidate.direct_control_proof_status == "rejected"
                assert "PE export" in candidate.direct_control_rejection_reason
                assert not candidate.direct_reference_gate_passed
            assert pe_analyze._slice_at_rva(parsed.sections, selected_rva, 7,
                what="generated entry-alias fixture") == bytes.fromhex("90b82a000000c3")
            assert [(item.name, item.rva) for item in
                    function_discovery.parse_pe_exports(parsed)
                    if item.name == "probe_alias"] == [("probe_alias", alias)]
            gaps = direct_control_flow._compute_coverage_gaps(
                direct_control_flow._normalize_sections(parsed),
                tuple((item.begin_rva, item.end_rva)
                      for item in parsed.runtime_functions))
            output = tmp_path / f"packed-{original.name}"
            options = orchestrator.PackOptions(
                output_path=str(output), is_dll=role == "dll",
                stub_path=str(stub),
                virtualization_specs=(orchestrator.VirtualizationSpec(
                    spec.name, spec.rva, spec.size),),
                virtualization_gap_acknowledgements=tuple(
                    orchestrator.VirtualizationGapAcknowledgement(
                        item.rva, item.size, "Exact generated entry-alias fixture gap")
                    for item in gaps),
                acknowledge_unproven_indirect_targets=True,
                _allow_unverified_stub_for_tests=not bool(strict),
            )
            packed = orchestrator.pack_file(str(original), options)
            row = {"mode": mode, "role": role,
                   "original_sha256": original_sha256,
                   "original": before, "pack_ok": packed.ok,
                   "pack_error": packed.error,
                   "unverified_override": options._allow_unverified_stub_for_tests}
            records.append(row)
            (tmp_path / "entry-metadata-receipt.json").write_text(
                json.dumps({"candidate_pins": pinned, "records": records}, indent=2),
                encoding="utf-8")
            if mode == "entry":
                assert packed.ok, packed.error
                after = _run(([str(host), str(output)] if role == "dll"
                              else [str(output)]), tmp_path)
                row["packed"] = after
                assert after["exit_status"] == 0 and not after["stderr"]
                assert after["stdout"] == before["stdout"]
            else:
                assert not packed.ok and "known source reference: PE export" in packed.error
                assert not output.exists()
            assert _sha256(original) == original_sha256
    assert len(records) == 4
    assert {path: _sha256(Path(path)) for path in pinned} == pinned
    (tmp_path / "entry-metadata-receipt.json").write_text(
        json.dumps({"candidate_pins": pinned, "records": records}, indent=2),
        encoding="utf-8")
