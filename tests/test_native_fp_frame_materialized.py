"""Materialized EXE/DLL regression for mixed FP native calls and stack slots."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess

import pytest

from lifter import direct_control_flow, virtualization_plan
from packer import assemble, orchestrator, pe_analyze, virtualize
from tests import test_native_virtualization_runtime as runtime


_ASM = r"""OPTION CASEMAP:NONE
EXTERN native_mix_slot:QWORD
PUBLIC vm_fp_call
PUBLIC vm_alias_pointer
.code
vm_fp_call PROC FRAME
 push rbp
 .pushreg rbp
 mov rbp,rsp
 sub rsp,60h
 .allocstack 60h
 .endprolog
 mov r10,rsp
 mov [rsp+48h],r10
 mov r11,[rsp+48h]
 mov r10,[rbp+30h]
 mov [r11+20h],r10
 mov r10,[rbp+38h]
 mov [r11+28h],r10
 mov r10,[rbp+40h]
 mov [r11+30h],r10
 mov r10,[rbp+48h]
 mov [r11+38h],r10
 mov r11d,0
 call qword ptr [native_mix_slot]
 add rsp,60h
 pop rbp
 ret
vm_fp_call ENDP
vm_alias_pointer PROC FRAME
 push rbp
 .pushreg rbp
 mov rbp,rsp
 sub rsp,40h
 .allocstack 40h
 .endprolog
 mov r10,rsp
 mov [rsp+18h],r10
 mov r11,[rsp+18h]
 mov rax,rdx
 add rax,r8
 add rax,r9
 add rax,[rbp+30h]
 mov [r11+8],rax
 mov rax,[r11+8]
 mov [rcx],rax
 add rsp,40h
 pop rbp
 ret
vm_alias_pointer ENDP
END
"""
_COMMON = r"""#include <stdint.h>
#include <windows.h>
int _fltused=0;
double vm_fp_call(double,uint64_t,double,uint64_t,double,uint64_t,double,uint64_t);
uint64_t vm_alias_pointer(uint64_t*,uint64_t,uint64_t,uint64_t,uint64_t);
__declspec(noinline) double native_mix(double a,uint64_t b,double c,uint64_t d,
 double e,uint64_t f,double g,uint64_t h)
{ return a+(double)b+c+(double)d+e+(double)f+g+(double)h; }
double (*const native_mix_slot)(double,uint64_t,double,uint64_t,double,uint64_t,double,uint64_t)=native_mix;
"""
_EXE = _COMMON + r"""__declspec(noreturn) void fixture_entry(void)
{
 const double answer=vm_fp_call(1.25,7,-3.5,11,5.75,13,-0.5,17);
 uint64_t output=0;
 const uint64_t alias=vm_alias_pointer(&output,7,11,13,17);
 static const char ok[]="FP_FRAME_E2E result=51.0 alias=48 passed=true\r\n";
 static const char bad[]="FP_FRAME_E2E mismatch\r\n";
 const int valid=answer==51.0 && alias==48 && output==48;
 const char *message=valid?ok:bad;
 DWORD written=0;
 WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),message,
           valid?(DWORD)(sizeof(ok)-1):(DWORD)(sizeof(bad)-1),&written,NULL);
 ExitProcess(valid?0U:19U);
}
"""
_DLL = _COMMON + r"""BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved)
{
 (void)module;(void)reason;(void)reserved;
 return TRUE;
}
"""
_HOST = r"""#include <windows.h>
#include <cstdint>
#include <cstdio>
using Fn=double (*)(double,uint64_t,double,uint64_t,double,uint64_t,double,uint64_t);
using AliasFn=uint64_t (*)(uint64_t*,uint64_t,uint64_t,uint64_t,uint64_t);
int wmain(int argc,wchar_t **argv)
{
 if(argc!=2)return 90;
 HMODULE module=LoadLibraryW(argv[1]);
 if(!module)return 91;
 auto address=GetProcAddress(module,"vm_fp_call");
 if(!address){FreeLibrary(module);return 92;}
 auto fn=reinterpret_cast<Fn>(address);
 auto alias_fn=reinterpret_cast<AliasFn>(GetProcAddress(module,"vm_alias_pointer"));
 if(!alias_fn){FreeLibrary(module);return 95;}
 double value=fn(1.25,7,-3.5,11,5.75,13,-0.5,17);
 uint64_t output=0;
 const uint64_t alias=alias_fn(&output,7,11,13,17);
 const bool valid=value==51.0 && alias==48 && output==48;
 std::printf("FP_FRAME_DLL result=%.1f alias=%llu passed=%s\n",value,
             static_cast<unsigned long long>(alias),valid?"true":"false");
 if(!FreeLibrary(module))return 93;
 return valid?0:94;
}
"""


def _build(work: Path) -> tuple[Path, Path, Path]:
    source, build = work / "fp_source", work / "fp_build"
    source.mkdir()
    for name, content in (("frame.asm", _ASM), ("exe.c", _EXE),
                          ("dll.c", _DLL), ("host.cpp", _HOST)):
        (source / name).write_text(content, encoding="ascii")
    (source / "CMakeLists.txt").write_text("""cmake_minimum_required(VERSION 3.20)
project(lethe_fp_frame_materialized C CXX ASM_MASM)
add_executable(fp_exe exe.c frame.asm)
add_library(fp_dll SHARED dll.c frame.asm)
add_executable(fp_host host.cpp)
set_source_files_properties(exe.c dll.c PROPERTIES COMPILE_OPTIONS "/W4;/WX;/O2;/GS-;/fp:strict")
target_link_options(fp_exe PRIVATE /INCREMENTAL:NO /OPT:NOICF /FIXED /NXCOMPAT
 /CETCOMPAT:NO /NODEFAULTLIB /ENTRY:fixture_entry /SUBSYSTEM:CONSOLE /EXPORT:vm_fp_call /EXPORT:vm_alias_pointer)
target_link_options(fp_dll PRIVATE /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT
 /CETCOMPAT:NO /NODEFAULTLIB /ENTRY:DllMain /MANIFEST:NO /EXPORT:vm_fp_call /EXPORT:vm_alias_pointer)
target_link_libraries(fp_exe PRIVATE kernel32.lib)
target_link_libraries(fp_dll PRIVATE kernel32.lib)
""", encoding="ascii")
    runtime._run_checked(["cmake", "-S", str(source), "-B", str(build),
                          "-G", "Visual Studio 17 2022", "-A", "x64"], cwd=work)
    runtime._run_checked(["cmake", "--build", str(build), "--config", "Release"], cwd=work)
    return (build / "Release/fp_exe.exe", build / "Release/fp_dll.dll",
            build / "Release/fp_host.exe")


def _run(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=30, check=False)


@pytest.mark.skipif(os.name != "nt", reason="Windows x64 materialization only")
def test_materialized_fp_stack_frame_exe_and_dll_parity(tmp_path: Path, monkeypatch) -> None:
    if os.environ.get(runtime._RUN_GATE) != "1":
        pytest.skip(f"set {runtime._RUN_GATE}=1 to run the native virtualization proof")
    pytest.importorskip("lief")
    pytest.importorskip("iced_x86")
    if not runtime.shutil.which("cmake") or not runtime._visual_studio_available():
        pytest.skip("CMake + Visual Studio x64 toolchain required")
    exe, dll, host = _build(tmp_path)
    stub = runtime._candidate_stub_or_build(tmp_path)
    stub_pin = hashlib.sha256(stub.read_bytes()).hexdigest()
    monkeypatch.setenv(runtime._VIRTUALIZATION_GATE, "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")
    for source, is_dll in ((exe, False), (dll, True)):
        image = assemble._StubImage(source.read_bytes())
        parsed = pe_analyze.analyze_pe(str(source))
        specs = []
        for name in ("vm_fp_call", "vm_alias_pointer"):
            rva = image.find_export_rva(name)
            assert rva is not None
            records = [record for record in parsed.runtime_functions
                       if record.begin_rva == rva]
            assert len(records) == 1
            record = records[0]
            specs.append(virtualization_plan.FunctionSpec(
                name, rva, record.end_rva - record.begin_rva))
        proof = direct_control_flow.analyze_direct_control_flow(
            parsed, tuple(specs), production=False)
        gaps = tuple(orchestrator.VirtualizationGapAcknowledgement(
            item.rva, item.size, "exact generated FP frame fixture gap")
            for item in proof.coverage_gaps)
        packed = tmp_path / ("fp_frame.packed.dll" if is_dll else "fp_frame.packed.exe")
        source_cmd = [str(host), str(source)] if is_dll else [str(source)]
        packed_cmd = [str(host), str(packed)] if is_dll else [str(packed)]
        before = _run(source_cmd)
        assert before.returncode == 0, (before.stdout, before.stderr)
        captured = {}
        original_materialize = virtualize.materialize_selected_functions

        def capture(*args, **kwargs):
            result = original_materialize(*args, **kwargs)
            captured["result"] = result
            return result

        with monkeypatch.context() as patch:
            patch.setattr(virtualize, "materialize_selected_functions", capture)
            result = orchestrator.pack_file(str(source), orchestrator.PackOptions(
                output_path=str(packed), is_dll=is_dll, stub_path=str(stub),
                virtualization_specs=tuple(orchestrator.VirtualizationSpec(
                    spec.name, spec.rva, spec.size) for spec in specs),
                virtualization_gap_acknowledgements=gaps,
                acknowledge_unproven_indirect_targets=True,
                _allow_unverified_stub_for_tests=True))
        assert result.ok, result.error
        assert {fn.name for fn in captured["result"].manifest.functions} == {
            "vm_fp_call", "vm_alias_pointer"}
        after = _run(packed_cmd)
        assert (after.returncode, after.stdout, after.stderr) == (
            before.returncode, before.stdout, before.stderr)
        assert hashlib.sha256(stub.read_bytes()).hexdigest() == stub_pin
