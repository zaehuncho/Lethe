"""Materialized EXE/DLL known-reference negatives and callable-entry controls."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest
from lifter import direct_control_flow, virtualization_plan
from packer import assemble, orchestrator, pe_analyze
from tests import test_native_virtualization_runtime as runtime

_C = 'typedef unsigned long DWORD;\n__declspec(dllimport) void* __stdcall GetStdHandle(DWORD);\n__declspec(dllimport) int __stdcall WriteFile(void*,const void*,DWORD,DWORD*,void*);\n__declspec(dllimport) void __stdcall ExitProcess(unsigned int);\nextern int vm_probe(void);\nextern unsigned int native_probe(void);\nstatic char* append(char* p,const char* s){while(*s)*p++=*s++;return p;}\nstatic char* number(char* p,unsigned int n){char t[12];unsigned int k=0;do{t[k++]=(char)(\'0\'+n%10);n/=10;}while(n);while(k)*p++=t[--k];return p;}\n__declspec(dllexport) int fixture_run(void){char b[128];char* p=b;DWORD count;unsigned int v=(unsigned int)vm_probe();unsigned int n=native_probe();int ok=v==42&&n==EXPECTED;\np=append(p,"KNOWN_REFERENCE result=");p=number(p,v);p=append(p," observed=");p=number(p,n);p=append(p,ok?" passed=true\\n":" passed=false\\n");\nWriteFile(GetStdHandle((DWORD)-11),b,(DWORD)(p-b),&count,0);return ok?0:7;}\n#ifdef BUILD_DLL\nint __stdcall DllMain(void* module,DWORD reason,void* reserved){(void)module;(void)reason;(void)reserved;return 1;}\n#else\nvoid fixture_entry(void){ExitProcess((unsigned int)fixture_run());}\n#endif\n'
_HOST = '#include <windows.h>\nint wmain(int argc,wchar_t** argv){if(argc!=2)return 90;HMODULE module=LoadLibraryW(argv[1]);if(!module)return 91;auto f=reinterpret_cast<int(*)()>(GetProcAddress(module,"fixture_run"));if(!f){FreeLibrary(module);return 92;}int result=f();if(!FreeLibrary(module))return 93;return result;}\n'
_KINDS = {'rip': (' .endprolog\n movzx eax,byte ptr [vm_probe+5]\n ret', 0, 0), 'lea': (' .endprolog\n lea rax,vm_probe+5\n movzx eax,byte ptr [rax]\n ret', 0, 0), 'reloc': (' .endprolog\n mov rax,qword ptr [reference_slot]\n movzx eax,byte ptr [rax]\n ret', 5, 0), 'entry': (' sub rsp,28h\n .allocstack 28h\n .endprolog\n mov rax,qword ptr [reference_slot]\n call rax\n add rsp,28h\n ret', 0, 42), 'lea_entry': (' sub rsp,28h\n .allocstack 28h\n .endprolog\n lea rax,vm_probe\n call rax\n add rsp,28h\n ret', 0, 42)}
_KINDS['lea_compare'] = (' .endprolog\n lea r10,vm_probe\n lea r11,vm_probe\n cmp r10,r11\n sete al\n movzx eax,al\n ret', 0, 1)
_KINDS.update({segment: (' .endprolog\n xor eax,eax\n ret', 0, 0) for segment in ('fs', 'gs')})

def _execute(command, cwd):
    result = subprocess.run(command, cwd=cwd, capture_output=True, timeout=180)
    return {"command": command, "stdout": result.stdout.decode("utf-8", errors="replace"),
            "stderr": result.stderr.decode("utf-8", errors="replace"), "exit_status": result.returncode}


def _build(work):
    source = work / "source"
    build = work / "build"
    source.mkdir()
    (source / "fixture.c").write_text(_C)
    (source / "host.cpp").write_text(_HOST)
    cmake = ["cmake_minimum_required(VERSION 3.20)", "project(known_reference C CXX ASM_MASM)",
             "add_executable(reference_host host.cpp)"]
    for kind, (body, offset, expected) in _KINDS.items():
        # Retained/exported but never executed: no Windows thread-segment
        # changes or unknown-base reads are needed to test static rejection.
        segment_body = (
            "segment_probe PROC FRAME\n .endprolog\n movzx eax,byte ptr " + kind +
            ":[reference_slot]\n ret\nsegment_probe ENDP\n" if kind in ("fs", "gs") else "")
        assembly = ("OPTION CASEMAP:NONE\nPUBLIC vm_probe\nPUBLIC reference_slot\nPUBLIC native_probe\n" +
                    ("PUBLIC segment_probe\n" if segment_body else "") + ".data\n" +
                    "reference_slot QWORD " + ("native_probe" if kind == "lea_entry" else "vm_probe") + ("+" + str(offset) if offset else "") +
                    "\n.code\nvm_probe PROC FRAME\n .endprolog\n nop\n mov eax,42\n ret\nvm_probe ENDP\n"
                    "native_probe PROC FRAME\n" + body + "\nnative_probe ENDP\n" + segment_body + "END\n")
        (source / (kind + ".asm")).write_text(assembly)
        for role in ("exe", "dll"):
            target = kind + "_" + role
            cmake += [
                ("add_executable" if role == "exe" else "add_library") + "(" + target +
                (" SHARED" if role == "dll" else "") + " fixture.c " + kind + ".asm)",
                f"target_compile_options({target} PRIVATE $<$<COMPILE_LANGUAGE:C>:/W4;/WX;/O2;/GS->)",
                f"target_compile_definitions({target} PRIVATE EXPECTED={expected}" + (" BUILD_DLL=1)" if role == "dll" else ")"),
                f"target_link_options({target} PRIVATE /INCREMENTAL:NO /OPT:NOICF /DYNAMICBASE /NXCOMPAT /CETCOMPAT:NO /NODEFAULTLIB /EXPORT:vm_probe /EXPORT:reference_slot,DATA " +
                ("/EXPORT:segment_probe " if segment_body else "") +
                ("/ENTRY:fixture_entry /SUBSYSTEM:CONSOLE)" if role == "exe" else "/ENTRY:DllMain /MANIFEST:NO)"),
                f"target_link_libraries({target} PRIVATE kernel32.lib)",
            ]
    (source / "CMakeLists.txt").write_text("\n".join(cmake) + "\n")
    for name, command in (
        ("configure", ["cmake", "-S", str(source), "-B", str(build), "-G", "Visual Studio 17 2022", "-A", "x64"]),
        ("compile", ["cmake", "--build", str(build), "--config", "Release"]),
    ):
        record = _execute(command, work)
        (work / (name + ".json")).write_text(json.dumps(record, indent=2))
        assert record["exit_status"] == 0, record
    return build / "Release"


@pytest.mark.skipif(os.name != "nt" or os.environ.get(runtime._RUN_GATE) != "1",
                    reason="opt-in Windows native materialized acceptance")
def test_materialized_known_reference_admission_exe_and_dll(tmp_path, monkeypatch):
    build = _build(tmp_path)
    strict = os.environ.get("LETHE_STRICT_REFERENCE_STUB_PATH")
    stub = Path(strict) if strict else runtime._candidate_stub_or_build(tmp_path)
    pinned = {str(stub): hashlib.sha256(stub.read_bytes()).hexdigest()}
    if strict:
        manifest = stub.with_suffix(".manifest.json")
        pinned[str(manifest)] = hashlib.sha256(manifest.read_bytes()).hexdigest()
    monkeypatch.setenv(runtime._VIRTUALIZATION_GATE, "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")
    records = []
    for kind, (_, _, expected) in _KINDS.items():
        for role in ("exe", "dll"):
            source = build / (kind + "_" + role + "." + role)
            host = build / "reference_host.exe"
            original_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            command = [str(host), str(source)] if role == "dll" else [str(source)]
            before = _execute(command, tmp_path)
            assert before["exit_status"] == 0 and not before["stderr"], before
            assert before["stdout"] == f"KNOWN_REFERENCE result=42 observed={expected} passed=true\n"
            parsed = pe_analyze.analyze_pe(str(source))
            image = assemble._StubImage(source.read_bytes())
            rva = image.find_export_rva("vm_probe")
            row, = (x for x in parsed.runtime_functions if x.begin_rva == rva)
            spec = virtualization_plan.FunctionSpec("vm_probe", rva, row.end_rva - rva)
            assert spec.size == 7
            assert pe_analyze._slice_at_rva(parsed.sections, rva, 7, what="fixture") == bytes.fromhex("90b82a000000c3")
            if kind in ("fs", "gs"):
                from iced_x86 import Decoder, Mnemonic, Register
                segment_rva = image.find_export_rva("segment_probe")
                segment_row, = (x for x in parsed.runtime_functions if x.begin_rva == segment_rva)
                segment_code = pe_analyze._slice_at_rva(parsed.sections, segment_rva,
                    segment_row.end_rva - segment_rva, what="segment fixture")
                instruction = Decoder(64, segment_code, ip=segment_rva).decode()
                assert instruction.mnemonic == Mnemonic.MOVZX
                assert instruction.is_ip_rel_memory_operand and instruction.memory_base == Register.RIP
                assert instruction.memory_segment == getattr(Register, kind.upper())
                assert instruction.ip_rel_memory_address == image.find_export_rva("reference_slot")
            gaps = direct_control_flow._compute_coverage_gaps(
                direct_control_flow._normalize_sections(parsed),
                tuple((x.begin_rva, x.end_rva) for x in parsed.runtime_functions))
            output = tmp_path / ("packed-" + source.name)
            options = orchestrator.PackOptions(
                output_path=str(output), is_dll=role == "dll", stub_path=str(stub),
                virtualization_specs=(orchestrator.VirtualizationSpec(spec.name, spec.rva, spec.size),),
                virtualization_gap_acknowledgements=tuple(orchestrator.VirtualizationGapAcknowledgement(
                    x.rva, x.size, "Exact generated known-reference fixture gap") for x in gaps),
                acknowledge_unproven_indirect_targets=True,
                _allow_unverified_stub_for_tests=not bool(strict))
            packed = orchestrator.pack_file(str(source), options)
            record = {"kind": kind, "role": role, "input_sha256": original_hash, "original": before,
                      "pack_ok": packed.ok, "pack_error": packed.error,
                      "unverified_override": options._allow_unverified_stub_for_tests}
            records.append(record)
            # Preserve an accepted unsafe fixture even if its assertion fails.
            (tmp_path / "native-reference-receipt.json").write_text(json.dumps({"candidate_pins": pinned, "records": records}, indent=2))
            if kind == "lea_entry":
                assert packed.ok, packed.error
                proof = direct_control_flow.analyze_direct_control_flow(parsed, (spec,), production=False)
                assert proof.indirect_target_closure_proven is False
                after = _execute([str(host), str(output)] if role == "dll" else [str(output)], tmp_path)
                record["packed"] = after
                assert after["stdout"] == before["stdout"] and after["exit_status"] == 0 and not after["stderr"], after
            elif kind == "lea_compare":
                assert packed.ok, packed.error
                proof = direct_control_flow.analyze_direct_control_flow(parsed, (spec,), production=False)
                assert proof.indirect_target_closure_proven is False
                after = _execute([str(host), str(output)] if role == "dll" else [str(output)], tmp_path)
                record["packed"] = after
                assert after["stdout"] == before["stdout"] and after["exit_status"] == 0 and not after["stderr"], after
            else:
                expected_error = ("unbounded source reference: segment-relative memory operand"
                                  if kind in ("fs", "gs") else "known source reference")
                assert not packed.ok and expected_error in packed.error, packed.error
                assert not output.exists()
            assert hashlib.sha256(source.read_bytes()).hexdigest() == original_hash
    assert len(records) == 2 * len(_KINDS)
    assert {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in pinned} == pinned
    (tmp_path / "native-reference-receipt.json").write_text(json.dumps({"candidate_pins": pinned, "records": records}, indent=2))
