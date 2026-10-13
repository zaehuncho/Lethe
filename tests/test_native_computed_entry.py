"""Materialized EXE/DLL regression for a computed interior indirect call."""
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


_KINDS = ("lea_exact", "lea_derived", "lea_branch",
          "dir64_exact", "dir64_derived")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _execute(command: list[str], cwd: Path) -> dict:
    process = subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL,
                             capture_output=True, timeout=180)
    return {
        "command": command,
        "exit_status": process.returncode,
        "stdout": process.stdout.decode("utf-8", "replace"),
        "stderr": process.stderr.decode("utf-8", "replace"),
    }


def _build(work: Path) -> Path:
    source = work / "source"
    build = work / "build"
    source.mkdir()
    c_source = known._C.replace(
        "extern int vm_probe(void);",
        "extern unsigned char __ImageBase;\n"
        "__declspec(dllimport) void* __stdcall GetProcAddress(void*,const char*);\n"
        "extern int vm_probe(void);",
    ).replace("extern unsigned int native_probe(void);",
              "extern unsigned int native_probe(void*);")
    assert "unsigned int n=native_probe();" in c_source
    c_source = c_source.replace(
        "unsigned int n=native_probe();",
        "\n#ifdef BRANCH_MODE\n"
        "unsigned char* alias=(unsigned char*)GetProcAddress(&__ImageBase,\"vm_probe\");\n"
        "unsigned int n=native_probe(alias?alias+1:0);\n"
        "#else\nunsigned int n=native_probe(0);\n#endif\n",
    )
    (source / "fixture.c").write_text(c_source, encoding="utf-8")
    (source / "host.cpp").write_text(known._HOST, encoding="utf-8")
    cmake = ["cmake_minimum_required(VERSION 3.20)",
             "project(computed_entry C CXX ASM_MASM)",
             "add_executable(reference_host host.cpp)"]
    for kind in _KINDS:
        address = (" mov rax,rcx\n jmp computed_call\n lea rax,vm_probe\ncomputed_call:\n"
                   if kind == "lea_branch" else
                   (" lea rax,vm_probe\n" if kind.startswith("lea")
                    else " mov rax,qword ptr [reference_slot]\n"))
        arithmetic = " inc rax\n" if kind.endswith("derived") else ""
        slot = "native_probe" if kind.startswith("lea") else "vm_probe"
        assembly = (
            "OPTION CASEMAP:NONE\nPUBLIC vm_probe\nPUBLIC native_probe\n"
            "PUBLIC reference_slot\n.data\nreference_slot QWORD " + slot +
            "\n.code\nvm_probe PROC FRAME\n .endprolog\n nop\n"
            " mov eax,42\n ret\nvm_probe ENDP\n"
            "native_probe PROC FRAME\n sub rsp,28h\n .allocstack 28h\n"
            " .endprolog\n" + address + arithmetic +
            " call rax\n add rsp,28h\n ret\nnative_probe ENDP\nEND\n"
        )
        (source / f"{kind}.asm").write_text(assembly, encoding="utf-8")
        for role in ("exe", "dll"):
            target = f"{kind}_{role}"
            cmake += [
                ("add_executable" if role == "exe" else "add_library") +
                f"({target}" + (" SHARED" if role == "dll" else "") +
                f" fixture.c {kind}.asm)",
                f"target_compile_options({target} PRIVATE "
                "$<$<COMPILE_LANGUAGE:C>:/W4;/WX;/O2;/GS->)",
                f"target_compile_definitions({target} PRIVATE EXPECTED=42" +
                (" BRANCH_MODE=1" if kind == "lea_branch" else "") +
                (" BUILD_DLL=1)" if role == "dll" else ")"),
                f"target_link_options({target} PRIVATE /INCREMENTAL:NO "
                "/OPT:NOICF /DYNAMICBASE /NXCOMPAT /CETCOMPAT:NO "
                "/NODEFAULTLIB /EXPORT:vm_probe /EXPORT:reference_slot,DATA " +
                ("/ENTRY:fixture_entry /SUBSYSTEM:CONSOLE)" if role == "exe"
                 else "/ENTRY:DllMain /MANIFEST:NO)"),
                f"target_link_libraries({target} PRIVATE kernel32.lib)",
            ]
    (source / "CMakeLists.txt").write_text("\n".join(cmake) + "\n", encoding="utf-8")
    for command in (["cmake", "-S", str(source), "-B", str(build),
                     "-G", "Visual Studio 17 2022", "-A", "x64"],
                    ["cmake", "--build", str(build), "--config", "Release"]):
        result = _execute(command, work)
        assert result["exit_status"] == 0, result
    return build / "Release"


@pytest.mark.skipif(os.name != "nt" or os.environ.get(runtime._RUN_GATE) != "1",
                    reason="opt-in Windows native materialized acceptance")
def test_computed_entry_exe_and_dll_fail_closed_with_exact_call_control(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    release = _build(tmp_path)
    strict = os.environ.get("LETHE_STRICT_REFERENCE_STUB_PATH")
    stub = Path(strict) if strict else runtime._candidate_stub_or_build(tmp_path)
    pins = {str(stub): _sha(stub)}
    if strict:
        manifest = stub.with_suffix(".manifest.json")
        pins[str(manifest)] = _sha(manifest)
    monkeypatch.setenv(runtime._VIRTUALIZATION_GATE, "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")
    records = []
    for kind in _KINDS:
        for role in ("exe", "dll"):
            original = release / f"{kind}_{role}.{role}"
            host = release / "reference_host.exe"
            original_hash = _sha(original)
            baseline = _execute([str(host), str(original)] if role == "dll"
                                else [str(original)], tmp_path)
            assert baseline["exit_status"] == 0 and baseline["stderr"] == ""
            assert baseline["stdout"] == (
                "KNOWN_REFERENCE result=42 observed=42 passed=true\n")
            parsed = pe_analyze.analyze_pe(str(original))
            rva = assemble._StubImage(original.read_bytes()).find_export_rva("vm_probe")
            row, = (item for item in parsed.runtime_functions if item.begin_rva == rva)
            spec = virtualization_plan.FunctionSpec("vm_probe", rva, row.end_rva - rva)
            assert spec.size == 7
            assert pe_analyze._slice_at_rva(parsed.sections, rva, 7, what="fixture") == (
                bytes.fromhex("90b82a000000c3"))
            # Preflight, read-only discovery, and materialization must agree
            # about this source-reference admission decision.
            report = function_discovery.discover_functions(parsed)
            candidate, = (item for item in report.candidates if item.rva == rva)
            expect_positive = kind == "lea_exact"
            assert (candidate.direct_control_proof_status == "passed") == expect_positive, (
                kind, role, candidate.direct_control_rejection_reason)
            if expect_positive:
                proof = direct_control_flow.analyze_direct_control_flow(
                    parsed, (spec,), production=False)
                assert proof.indirect_target_closure_proven is False
            else:
                with pytest.raises(direct_control_flow.DirectControlFlowError,
                                   match="known source reference"):
                    direct_control_flow.analyze_direct_control_flow(
                        parsed, (spec,), production=False)
            gaps = direct_control_flow._compute_coverage_gaps(
                direct_control_flow._normalize_sections(parsed),
                tuple((item.begin_rva, item.end_rva)
                      for item in parsed.runtime_functions))
            output = tmp_path / f"packed-{original.name}"
            options = orchestrator.PackOptions(
                output_path=str(output), is_dll=role == "dll", stub_path=str(stub),
                virtualization_specs=(orchestrator.VirtualizationSpec(
                    spec.name, spec.rva, spec.size),),
                virtualization_gap_acknowledgements=tuple(
                    orchestrator.VirtualizationGapAcknowledgement(
                        item.rva, item.size,
                        "Exact generated computed-entry fixture gap")
                    for item in gaps),
                acknowledge_unproven_indirect_targets=True,
                _allow_unverified_stub_for_tests=not bool(strict),
            )
            packed = orchestrator.pack_file(str(original), options)
            record = {"kind": kind, "role": role, "original_sha256": original_hash,
                      "baseline": baseline, "pack_ok": packed.ok,
                      "pack_error": packed.error,
                      "discovery_status": candidate.direct_control_proof_status,
                      "discovery_reason": candidate.direct_control_rejection_reason,
                      "unverified_override": options._allow_unverified_stub_for_tests}
            records.append(record)
            (tmp_path / "computed-entry-receipt.json").write_text(
                json.dumps({"candidate_pins": pins, "records": records}, indent=2),
                encoding="utf-8")
            if kind == "lea_exact":
                assert packed.ok, packed.error
                modified = _execute([str(host), str(output)] if role == "dll"
                                    else [str(output)], tmp_path)
                record["modified"] = modified
                assert modified == {"command": modified["command"],
                                    "exit_status": 0,
                                    "stdout": baseline["stdout"], "stderr": ""}
            else:
                assert not packed.ok, packed.error
                expected = ("RIP address" if kind in ("lea_derived", "lea_branch")
                            else "DIR64 address")
                assert "known source reference: " + expected in packed.error
                assert not output.exists()
            assert _sha(original) == original_hash
    assert len(records) == 10
    assert {path: _sha(Path(path)) for path in pins} == pins
    (tmp_path / "computed-entry-receipt.json").write_text(
        json.dumps({"candidate_pins": pins, "records": records}, indent=2),
        encoding="utf-8")
