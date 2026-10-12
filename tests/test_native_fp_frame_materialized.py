"""Materialized EXE/DLL parity for FP calls and conditional source-stack aliases."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess

import pytest
from iced_x86 import Decoder, Mnemonic

from lifter import direct_control_flow, virtualization_plan
from packer import assemble, orchestrator, pe_analyze, virtualize
from tests import test_native_virtualization_runtime as runtime


_ASM = r"""OPTION CASEMAP:NONE
EXTERN native_mix_slot:QWORD
EXTERN native_alias_constant:QWORD
PUBLIC vm_fp_call
PUBLIC vm_alias_pointer
PUBLIC vm_int_pair
PUBLIC vm_alias_choose
PUBLIC vm_alias_choose_spill
PUBLIC vm_tail_native_call
PUBLIC vm_tail_import_call
EXTERN __imp_GetCurrentProcess:QWORD
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
vm_int_pair PROC FRAME
 sub rsp,28h
 .allocstack 28h
 .endprolog
 cvtdq2pd xmm0,qword ptr [rcx]
 movdqu xmmword ptr [rdx],xmm0
 movq xmm1,qword ptr [rcx]
 cvtdq2pd xmm1,xmm1
 movdqu xmmword ptr [rdx+10h],xmm1
 add rsp,28h
 ret
vm_int_pair ENDP
vm_alias_choose PROC FRAME
 push rbp
 .pushreg rbp
 mov rbp,rsp
 sub rsp,40h
 .allocstack 40h
 .endprolog
 mov [rsp+8],r8
 lea r10,[rsp+8]
 lea r11,[rbp+30h]
 test edx,edx
 cmovns r10,r11
 lea r11,[native_alias_constant]
 cmp edx,1
 cmovg r10,r11
 mov rax,[r10]
 mov [rcx],rax
 add rsp,40h
 pop rbp
 ret
vm_alias_choose ENDP
vm_alias_choose_spill PROC FRAME
 push rbp
 .pushreg rbp
 mov rbp,rsp
 sub rsp,40h
 .allocstack 40h
 .endprolog
 mov [rsp+8],r8
 lea r10,[rsp+8]
 lea r11,[rbp+30h]
 mov [rsp+18h],r11
 test edx,edx
 cmovns r10,qword ptr [rsp+18h]
 lea r11,[native_alias_constant]
 cmp edx,1
 cmovg r10,r11
 mov rax,[r10]
 mov [rcx],rax
 add rsp,40h
 pop rbp
 ret
vm_alias_choose_spill ENDP

vm_tail_native_call PROC FRAME
 sub rsp,48h
 .allocstack 48h
 .endprolog
 mov ecx,11
 mov edx,13
 mov r8d,17
 mov r9d,19
 mov qword ptr [rsp+20h],23
 call native_alias_a
 add rsp,48h
 ret
vm_tail_native_call ENDP
vm_tail_import_call PROC FRAME
 sub rsp,48h
 .allocstack 48h
 .endprolog
 call import_alias_a
 add rsp,48h
 ret
vm_tail_import_call ENDP
native_alias_a PROC
 db 0E9h
 dd native_alias_b-($+4)
native_alias_a ENDP
native_alias_b PROC
 db 0E9h
 dd native_tail_leaf-($+4)
native_alias_b ENDP
import_alias_a PROC
 db 0E9h
 dd import_alias_b-($+4)
import_alias_a ENDP
import_alias_b PROC
 db 0E9h
 dd import_alias_iat-($+4)
import_alias_b ENDP
import_alias_iat PROC
 jmp qword ptr [__imp_GetCurrentProcess]
import_alias_iat ENDP
native_tail_leaf PROC FRAME
 sub rsp,8
 .allocstack 8
 .endprolog
 lea rax,[rcx+rdx]
 add rax,r8
 add rax,r9
 add rax,[rsp+30h]
 add rsp,8
 ret
native_tail_leaf ENDP
END
"""
_CONVERSION_CHECK = r"""#include <stdint.h>
#include <windows.h>
#include <intrin.h>
typedef void (*ConversionFn)(const int32_t *,double *);
static int conversion_check(ConversionFn convert)
{
 const int32_t cases[][2]={
  {0,0},{1,-1},{-1,1},{(-2147483647-1),2147483647},
  {1073741825,-1073741825},{16777217,-16777217},
  {305419896,-305419896},{-2147483647,2147483646}
 };
 SYSTEM_INFO system;
 DWORD old_protect=0;
 unsigned control,index,lane;
 const unsigned saved=_mm_getcsr();
 int valid=0;
 unsigned char *region;
 int32_t *input;
 GetSystemInfo(&system);
 region=(unsigned char *)VirtualAlloc(NULL,(SIZE_T)system.dwPageSize*2,
                                    MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
 if(!region)return 0;
 if(!VirtualProtect(region+system.dwPageSize,system.dwPageSize,
                    PAGE_NOACCESS,&old_protect))goto cleanup;
 /* The source ends exactly at an inaccessible page: m128 would fault. */
 input=(int32_t *)(region+system.dwPageSize-8);
 for(control=0;control<32;control++){
  const unsigned csr=((control&3U)<<13)|(((control>>2)&1U)<<15)
                    |((control&8U)?0x3FU:0U)|((control&16U)?0x1F80U:0U)
                    |(saved&0x40U);
  for(index=0;index<(unsigned)(sizeof(cases)/sizeof(cases[0]));index++){
   double output[4]={123.5,123.5,123.5,123.5};
   const double expected[2]={(double)cases[index][0],(double)cases[index][1]};
   unsigned after;
   input[0]=cases[index][0];input[1]=cases[index][1];
   _mm_setcsr(csr);
   convert(input,output);
   after=_mm_getcsr();
   _mm_setcsr(saved);
   if(after!=csr)goto cleanup;
   for(lane=0;lane<4;lane++)if(output[lane]!=expected[lane&1U])goto cleanup;
  }
 }
 valid=1;
cleanup:
 _mm_setcsr(saved);
 if(!VirtualFree(region,0,MEM_RELEASE))valid=0;
 return valid;
}
"""
_CONDITIONAL_ALIAS_CHECK = r"""typedef uint64_t (*ConditionalAliasFn)(uint64_t*,int,uint64_t,uint64_t,uint64_t);
static int conditional_alias_check(ConditionalAliasFn direct,ConditionalAliasFn spilled)
{
 const int selectors[]={(-2147483647-1),-1,0,1,2,2147483647};
 const ConditionalAliasFn functions[]={direct,spilled};
 unsigned index,function;
 for(function=0;function<2;function++){
  for(index=0;index<(unsigned)(sizeof(selectors)/sizeof(selectors[0]));index++){
   const int selector=selectors[index];
   const uint64_t expected=selector<0?7U:(selector>1?17U:31U);
   uint64_t output=0xC0FFEEULL;
   const uint64_t value=functions[function](&output,selector,7U,11U,31U);
   if(value!=expected || output!=expected)return 0;
  }
 }
 return 1;
}
"""
_COMMON = r"""#include <stdint.h>
#include <windows.h>
int _fltused=0;
double vm_fp_call(double,uint64_t,double,uint64_t,double,uint64_t,double,uint64_t);
uint64_t vm_alias_pointer(uint64_t*,uint64_t,uint64_t,uint64_t,uint64_t);
void vm_int_pair(const int32_t*,double*);
uint64_t vm_alias_choose(uint64_t*,int,uint64_t,uint64_t,uint64_t);
uint64_t vm_alias_choose_spill(uint64_t*,int,uint64_t,uint64_t,uint64_t);
uint64_t vm_tail_native_call(void);
uint64_t vm_tail_import_call(void);
const uint64_t native_alias_constant=17U;
__declspec(noinline) double native_mix(double a,uint64_t b,double c,uint64_t d,
 double e,uint64_t f,double g,uint64_t h)
{ return a+(double)b+c+(double)d+e+(double)f+g+(double)h; }
double (*const native_mix_slot)(double,uint64_t,double,uint64_t,double,uint64_t,double,uint64_t)=native_mix;
"""
_EXE = _COMMON + _CONVERSION_CHECK + _CONDITIONAL_ALIAS_CHECK + r"""__declspec(noreturn) void fixture_entry(void)
{
 const double answer=vm_fp_call(1.25,7,-3.5,11,5.75,13,-0.5,17);
 uint64_t output=0;
 const uint64_t alias=vm_alias_pointer(&output,7,11,13,17);
 const int conversion=conversion_check(vm_int_pair);
 const int conditional=conditional_alias_check(vm_alias_choose,vm_alias_choose_spill);
 const int tails=vm_tail_native_call()==83U && vm_tail_import_call()==UINT64_MAX;
 static const char ok[]="FP_FRAME_E2E result=51.0 alias=48 conversion=1 conditional=1 tails=1 passed=true\r\n";
 static const char bad[]="FP_FRAME_E2E mismatch\r\n";
 const int valid=answer==51.0 && alias==48 && output==48 && conversion && conditional && tails;
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
""" + _CONVERSION_CHECK + _CONDITIONAL_ALIAS_CHECK + r"""
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
 auto convert=reinterpret_cast<ConversionFn>(GetProcAddress(module,"vm_int_pair"));
 if(!convert){FreeLibrary(module);return 96;}
 auto choose=reinterpret_cast<ConditionalAliasFn>(GetProcAddress(module,"vm_alias_choose"));
 if(!choose){FreeLibrary(module);return 97;}
 auto choose_spill=reinterpret_cast<ConditionalAliasFn>(GetProcAddress(module,"vm_alias_choose_spill"));
 if(!choose_spill){FreeLibrary(module);return 98;}
 using TailFn=uint64_t (*)();
 auto tail_native=reinterpret_cast<TailFn>(GetProcAddress(module,"vm_tail_native_call"));
 auto tail_import=reinterpret_cast<TailFn>(GetProcAddress(module,"vm_tail_import_call"));
 if(!tail_native || !tail_import){FreeLibrary(module);return 99;}
 double value=fn(1.25,7,-3.5,11,5.75,13,-0.5,17);
 uint64_t output=0;
 const uint64_t alias=alias_fn(&output,7,11,13,17);
 const int conversion=conversion_check(convert);
 const int conditional=conditional_alias_check(choose,choose_spill);
 const int tails=tail_native()==83U && tail_import()==UINT64_MAX;
 const bool valid=value==51.0 && alias==48 && output==48 && conversion && conditional && tails;
 std::printf("FP_FRAME_DLL result=%.1f alias=%llu conversion=%d conditional=%d tails=%d passed=%s\n",value,
             static_cast<unsigned long long>(alias),conversion,conditional,tails,valid?"true":"false");
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
 /CETCOMPAT:NO /NODEFAULTLIB /ENTRY:fixture_entry /SUBSYSTEM:CONSOLE /EXPORT:vm_fp_call /EXPORT:vm_alias_pointer /EXPORT:vm_int_pair /EXPORT:vm_alias_choose /EXPORT:vm_alias_choose_spill /EXPORT:vm_tail_native_call /EXPORT:vm_tail_import_call)
target_link_options(fp_dll PRIVATE /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT
 /CETCOMPAT:NO /NODEFAULTLIB /ENTRY:DllMain /MANIFEST:NO /EXPORT:vm_fp_call /EXPORT:vm_alias_pointer /EXPORT:vm_int_pair /EXPORT:vm_alias_choose /EXPORT:vm_alias_choose_spill /EXPORT:vm_tail_native_call /EXPORT:vm_tail_import_call)
target_link_libraries(fp_exe PRIVATE kernel32.lib)
target_link_libraries(fp_dll PRIVATE kernel32.lib)
""", encoding="ascii")
    runtime._run_checked(["cmake", "-S", str(source), "-B", str(build),
                          "-G", "Visual Studio 17 2022", "-A", "x64"], cwd=work)
    runtime._run_checked(["cmake", "--build", str(build), "--config", "Release"], cwd=work)
    return (build / "Release/fp_exe.exe", build / "Release/fp_dll.dll",
            build / "Release/fp_host.exe")


def _assert_tail_fixture(image, parsed) -> None:
    entries = {record.begin_rva for record in parsed.runtime_functions}
    slots = {function.iat_rva for dll in parsed.imports for function in dll.funcs}
    for name, kind in (("vm_tail_native_call", "pdata"), ("vm_tail_import_call", "iat")):
        rva = image.find_export_rva(name)
        record, = (record for record in parsed.runtime_functions if record.begin_rva == rva)
        calls = [instruction for instruction in Decoder(64, image.read_at_rva(rva, record.end_rva-rva), ip=rva)
                 if instruction.mnemonic == Mnemonic.CALL]
        assert len(calls) == 1 and calls[0].len == 5
        target = calls[0].near_branch_target
        for _ in range(2):
            raw = image.read_at_rva(target, 5)
            assert raw[0] == 0xE9
            assert not any(record.begin_rva <= target < record.end_rva for record in parsed.runtime_functions)
            target += 5 + int.from_bytes(raw[1:], "little", signed=True)
        if kind == "pdata":
            assert target in entries
        else:
            raw = image.read_at_rva(target, 6)
            assert raw[:2] == b"\xFF\x25"
            assert target + 6 + int.from_bytes(raw[2:], "little", signed=True) in slots


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
        _assert_tail_fixture(image, parsed)
        specs = []
        for name in ("vm_fp_call", "vm_alias_pointer", "vm_int_pair",
                     "vm_alias_choose", "vm_alias_choose_spill", "vm_tail_native_call", "vm_tail_import_call"):
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
            "vm_fp_call", "vm_alias_pointer", "vm_int_pair",
            "vm_alias_choose", "vm_alias_choose_spill", "vm_tail_native_call", "vm_tail_import_call"}
        after = _run(packed_cmd)
        assert (after.returncode, after.stdout, after.stderr) == (
            before.returncode, before.stdout, before.stderr)
        assert hashlib.sha256(stub.read_bytes()).hexdigest() == stub_pin
