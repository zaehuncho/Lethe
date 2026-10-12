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
.code
vm_fp_call PROC FRAME
 sub rsp,58h
 .allocstack 58h
 .endprolog
 mov r10,[rsp+80h]
 mov [rsp+20h],r10
 mov r10,[rsp+88h]
 mov [rsp+28h],r10
 mov r10,[rsp+90h]
 mov [rsp+30h],r10
 mov r10,[rsp+98h]
 mov [rsp+38h],r10
 call qword ptr [native_mix_slot]
 add rsp,58h
 ret
vm_fp_call ENDP
END
"""
_COMMON = r"""#include <stdint.h>
#include <windows.h>
int _fltused=0;
double vm_fp_call(double,uint64_t,double,uint64_t,double,uint64_t,double,uint64_t);
__declspec(noinline) double native_mix(double a,uint64_t b,double c,uint64_t d,
 double e,uint64_t f,double g,uint64_t h)
{ return a+(double)b+c+(double)d+e+(double)f+g+(double)h; }
double (*const native_mix_slot)(double,uint64_t,double,uint64_t,double,uint64_t,double,uint64_t)=native_mix;
"""
_EXE = _COMMON + r"""__declspec(noreturn) void fixture_entry(void)
{
 const double answer=vm_fp_call(1.25,7,-3.5,11,5.75,13,-0.5,17);
 static const char ok[]="FP_FRAME_E2E result=51.0 passed=true\r\n";
 static const char bad[]="FP_FRAME_E2E mismatch\r\n";
 const int valid=answer==51.0;
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
int wmain(int argc,wchar_t **argv)
{
 if(argc!=2)return 90;
 HMODULE module=LoadLibraryW(argv[1]);
 if(!module)return 91;
 auto address=GetProcAddress(module,"vm_fp_call");
 if(!address){FreeLibrary(module);return 92;}
 auto fn=reinterpret_cast<Fn>(address);
 double value=fn(1.25,7,-3.5,11,5.75,13,-0.5,17);
 std::printf("FP_FRAME_DLL result=%.1f passed=%s\n",value,value==51.0?"true":"false");
 if(!FreeLibrary(module))return 93;
 return value==51.0?0:94;
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
 /CETCOMPAT:NO /NODEFAULTLIB /ENTRY:fixture_entry /SUBSYSTEM:CONSOLE /EXPORT:vm_fp_call)
target_link_options(fp_dll PRIVATE /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT
 /CETCOMPAT:NO /NODEFAULTLIB /ENTRY:DllMain /MANIFEST:NO /EXPORT:vm_fp_call)
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
        rva = image.find_export_rva("vm_fp_call")
        assert rva is not None
        parsed = pe_analyze.analyze_pe(str(source))
        records = [record for record in parsed.runtime_functions
                   if record.begin_rva == rva]
        assert len(records) == 1
        record = records[0]
        spec = virtualization_plan.FunctionSpec(
            "vm_fp_call", rva, record.end_rva - record.begin_rva)
        proof = direct_control_flow.analyze_direct_control_flow(
            parsed, (spec,), production=False)
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
                virtualization_specs=(orchestrator.VirtualizationSpec(
                    spec.name, spec.rva, spec.size),),
                virtualization_gap_acknowledgements=gaps,
                acknowledge_unproven_indirect_targets=True,
                _allow_unverified_stub_for_tests=True))
        assert result.ok, result.error
        assert len(captured["result"].manifest.functions) == 1
        after = _run(packed_cmd)
        assert (after.returncode, after.stdout, after.stderr) == (
            before.returncode, before.stdout, before.stderr)
        assert hashlib.sha256(stub.read_bytes()).hexdigest() == stub_pin
