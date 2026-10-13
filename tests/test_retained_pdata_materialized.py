"""Strict candidate-bound EXE/DLL rejection of retained PDATA CALLs."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

from lifter import direct_control_flow, virtualization_plan
from packer import assemble, orchestrator, pe_analyze
from tests import test_native_virtualization_runtime as native_fixture


_C = r'''
#include <windows.h>
extern unsigned int vm_probe(void);
static char *append(char *p,const char *s){while(*s)*p++=*s++;return p;}
static char *number(char *p,unsigned int n){char t[12];unsigned k=0;do{t[k++]=(char)('0'+n%10);n/=10;}while(n);while(k)*p++=t[--k];return p;}
__declspec(dllexport) int fixture_run(void){
 char b[128];char *p=b;DWORD count;unsigned v=vm_probe();int ok=(v==EXPECTED);
 p=append(p,"NATIVE_FRAME value=");p=number(p,v);p=append(p,ok?" passed=true\n":" passed=false\n");
 WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),b,(DWORD)(p-b),&count,0);return ok?0:7;
}
#ifdef BUILD_DLL
BOOL WINAPI DllMain(HINSTANCE m,DWORD reason,LPVOID reserved){(void)m;(void)reason;(void)reserved;return TRUE;}
#else
void fixture_entry(void){ExitProcess((UINT)fixture_run());}
#endif
'''
_HOST = r'''
#include <windows.h>
int wmain(int argc,wchar_t** argv){if(argc!=2)return 90;HMODULE m=LoadLibraryW(argv[1]);if(!m)return 91;
 auto f=reinterpret_cast<int(*)()>(GetProcAddress(m,"fixture_run"));if(!f){FreeLibrary(m);return 92;}
 int result=f();if(!FreeLibrary(m))return 93;return result;}
'''
_ASM = r'''
OPTION CASEMAP:NONE
PUBLIC vm_probe
PUBLIC native_probe
.data
PUBLIC reference_slot
reference_slot QWORD native_probe
.code
vm_probe PROC FRAME
 sub rsp,28h
 .allocstack 28h
 .endprolog
{store}
 call native_probe
 add rsp,28h
 ret
vm_probe ENDP
native_probe PROC FRAME
 .endprolog
{body}
 ret
native_probe ENDP
END
'''


def _run(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=60, check=False)


def _build(work: Path, *, return_site: bool) -> tuple[Path, Path, Path]:
    source, build = work / "source", work / "build"
    source.mkdir(parents=True)
    (source / "probe.c").write_text(_C, encoding="ascii")
    (source / "host.cpp").write_text(_HOST, encoding="ascii")
    (source / "probe.asm").write_text(_ASM.format(
        store="" if return_site else "mov qword ptr [rsp+20h],5",
        body=("mov rax,qword ptr [rsp]\n movzx eax,byte ptr [rax]"
              if return_site else "mov eax,dword ptr [rsp+28h]"),
    ), encoding="ascii")
    (source / "CMakeLists.txt").write_text('''cmake_minimum_required(VERSION 3.20)
project(lethe_retained_native_frame C CXX ASM_MASM)
add_executable(probe_exe probe.c probe.asm)
add_library(probe_dll SHARED probe.c probe.asm)
add_executable(reference_host host.cpp)
target_compile_definitions(probe_exe PRIVATE EXPECTED={expected})
target_compile_definitions(probe_dll PRIVATE EXPECTED={expected} BUILD_DLL=1)
set_source_files_properties(probe.c PROPERTIES COMPILE_OPTIONS "/W4;/WX;/O2;/GS-")
target_link_options(probe_exe PRIVATE /INCREMENTAL:NO /OPT:NOICF /DYNAMICBASE /NXCOMPAT /CETCOMPAT:NO /NODEFAULTLIB /ENTRY:fixture_entry /SUBSYSTEM:CONSOLE /EXPORT:vm_probe /EXPORT:reference_slot,DATA)
target_link_options(probe_dll PRIVATE /INCREMENTAL:NO /OPT:NOICF /DYNAMICBASE /NXCOMPAT /CETCOMPAT:NO /NODEFAULTLIB /ENTRY:DllMain /MANIFEST:NO /EXPORT:vm_probe /EXPORT:reference_slot,DATA)
target_link_libraries(probe_exe PRIVATE kernel32.lib)
target_link_libraries(probe_dll PRIVATE kernel32.lib)
'''.format(expected=72 if return_site else 5), encoding="ascii")
    for command in (["cmake", "-S", str(source), "-B", str(build),
                     "-G", "Visual Studio 17 2022", "-A", "x64"],
                    ["cmake", "--build", str(build), "--config", "Release"]):
        completed = _run(command)
        assert completed.returncode == 0, completed.stdout + completed.stderr
    release = build / "Release"
    return release / "probe_exe.exe", release / "probe_dll.dll", release / "reference_host.exe"


@pytest.mark.skipif(os.name != "nt", reason="Windows x64 materialization only")
@pytest.mark.parametrize("return_site", [True, False], ids=["return-site-observer", "ordinary-fifth-argument"])
def test_strict_retained_pdata_call_rejects_exe_and_dll(
    tmp_path: Path, monkeypatch, return_site: bool,
) -> None:
    if os.environ.get(native_fixture._RUN_GATE) != "1":
        pytest.skip(f"set {native_fixture._RUN_GATE}=1 to run materialized proof")
    if not native_fixture.shutil.which("cmake") or not native_fixture._visual_studio_available():
        pytest.skip("CMake and Visual Studio x64 toolchain required")
    stub_name = os.environ.get(native_fixture._STUB_PATH_ENV)
    assert stub_name, "strict materialized proof requires candidate stub path"
    stub = Path(stub_name)
    assert stub.is_file() and stub.with_suffix(".manifest.json").is_file()
    monkeypatch.setenv(native_fixture._VIRTUALIZATION_GATE, "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")
    exe, dll, host = _build(tmp_path, return_site=return_site)
    for source, is_dll in ((exe, False), (dll, True)):
        original = _run([str(host), str(source)] if is_dll else [str(source)])
        assert original.returncode == 0 and not original.stderr
        assert original.stdout == (
            b"NATIVE_FRAME value=72 passed=true\n" if return_site
            else b"NATIVE_FRAME value=5 passed=true\n"
        )
        image = assemble._StubImage(source.read_bytes())
        parsed = pe_analyze.analyze_pe(str(source))
        rva = image.find_export_rva("vm_probe")
        record, = (r for r in parsed.runtime_functions if r.begin_rva == rva)
        proof = direct_control_flow.analyze_direct_control_flow(
            parsed, (virtualization_plan.FunctionSpec(
                "vm_probe", rva, record.end_rva-rva),), production=False,
        )
        output = tmp_path / ("packed.dll" if is_dll else "packed.exe")
        options = orchestrator.PackOptions(
            output_path=str(output), is_dll=is_dll, stub_path=str(stub),
            virtualization_specs=(orchestrator.VirtualizationSpec(
                "vm_probe", rva, record.end_rva-rva),),
            virtualization_gap_acknowledgements=tuple(
                orchestrator.VirtualizationGapAcknowledgement(
                    item.rva, item.size, "exact generated native-frame fixture gap"
                ) for item in proof.coverage_gaps),
            acknowledge_unproven_indirect_targets=True,
            _allow_unverified_stub_for_tests=False,
        )
        result = orchestrator.pack_file(str(source), options)
        # Both source callees are valid Win64 code. The return-site observer
        # demonstrates a concrete miscompile; the fifth-argument leaf remains
        # a deliberate compatibility loss because an external stack observer
        # can still distinguish a native CALL from the VM bridge.
        assert not result.ok and "retained PDATA native CALL lacks physical return-slot" in result.error
        assert not output.exists()
