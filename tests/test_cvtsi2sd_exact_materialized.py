"""Strict candidate-bound legacy CVTSI2SD EXE/DLL parity and typed negatives.

These generated fixtures are not product acceptance.  The selected conversion
functions have no native CALLs or opaque imports, and both pack paths require a
fresh schema-2 source-bound candidate without an unverified-stub override.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

import pytest
from iced_x86 import Decoder, Mnemonic

from lifter import direct_control_flow, virtualization_plan as plan
from packer import assemble, orchestrator, pe_analyze, virtualize
from tests import test_native_virtualization_runtime as runtime


_POSITIVE = (
    ("vm_cvt_i32_reg", "mov r10d,dword ptr [rcx]", "r10d"),
    ("vm_cvt_i32_mem", "mov r10d,dword ptr [rcx]", "dword ptr [rcx]"),
    ("vm_cvt_i64_zero", "mov r10d,dword ptr [rcx]", "r10"),
    ("vm_cvt_i64_sign", "movsxd r10,dword ptr [rcx]", "r10"),
    ("vm_cvt_i64_copy", "movsxd rax,dword ptr [rcx]\n mov r10,rax", "r10"),
    ("vm_cvt_i64_join", "cmp r8d,r9d\n jne cvt_signed\n mov r10d,dword ptr [rcx]\n jmp cvt_join\ncvt_signed:\n movsxd r10,dword ptr [rcx]\ncvt_join:", "r10"),
    ("vm_cvt_i64_limit", "mov r10,20000000000000h", "r10"),
    ("vm_cvt_i64_negative_limit", "mov r10,-20000000000000h", "r10"),
    ("vm_cvt_i64_power", "mov r10,1000000000000000h", "r10"),
)
_NEGATIVE = (
    ("vm_cvt_i64_unknown", "mov r10,qword ptr [rcx]", "r10"),
    ("vm_cvt_i64_inexact", "mov r10,20000000000001h", "r10"),
)
_NAMES = tuple(row[0] for row in _POSITIVE)


def _function(name: str, setup: str, operand: str) -> str:
    # All observations precede the epilogue's ADD, which changes EFLAGS.  SETcc,
    # MOV and MOVDQU do not change the five observed arithmetic flags.
    return f"""PUBLIC {name}
{name} PROC FRAME
 sub rsp,28h
 .allocstack 28h
 .endprolog
 movdqu xmm0,xmmword ptr [rdx]
 mov rax,00DDBBCCAA998877h
 {setup.replace('cvt_signed', name + '_signed').replace('cvt_join', name + '_join')}
 mov r11,0123456789ABCDEFh
 mov qword ptr [rdx+32],r10
 mov qword ptr [rdx+48],r11
 mov qword ptr [rdx+80],rcx
 mov qword ptr [rdx+96],r8
 mov qword ptr [rdx+112],r9
 mov qword ptr [rdx+128],rax
 cmp r8d,r9d
 setb byte ptr [rdx+64]
 sete byte ptr [rdx+65]
 sets byte ptr [rdx+66]
 seto byte ptr [rdx+67]
 setp byte ptr [rdx+68]
 cvtsi2sd xmm0,{operand}
 setb byte ptr [rdx+69]
 sete byte ptr [rdx+70]
 sets byte ptr [rdx+71]
 seto byte ptr [rdx+72]
 setp byte ptr [rdx+73]
 movdqu xmmword ptr [rdx+16],xmm0
 mov qword ptr [rdx+40],r10
 mov qword ptr [rdx+56],r11
 mov qword ptr [rdx+88],rcx
 mov qword ptr [rdx+104],r8
 mov qword ptr [rdx+120],r9
 mov qword ptr [rdx+136],rax
 add rsp,28h
 ret
{name} ENDP
"""


_ASM = ("OPTION CASEMAP:NONE\n.code\n"
        + "\n".join(_function(*row) for row in (*_POSITIVE, *_NEGATIVE))
        + "END\n")
_DECLARATIONS = "\n".join(
    f"void {name}(const int32_t*,struct Observation*,uint32_t,uint32_t);"
    for name in (*_NAMES, *(row[0] for row in _NEGATIVE)))
_DISPATCH = "\n".join(
    f" case {index}: {name}(input,output,left,right); break;"
    for index, name in enumerate(_NAMES))
_C = r"""#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <intrin.h>
int _fltused=0;
struct Observation {
 uint64_t seed[2],actual[2],source_before,source_after,other_before,other_after;
 unsigned char before[5],after[5],padding[6];
 uint64_t pointer_before,pointer_after,left_before,left_after,right_before,right_after;
 uint64_t copy_before,copy_after;
};
typedef char layout_flags[(offsetof(struct Observation,before)==64)?1:-1];
typedef char layout_pointer[(offsetof(struct Observation,pointer_before)==80)?1:-1];
typedef char layout_copy[(offsetof(struct Observation,copy_before)==128)?1:-1];
DECLARATIONS
static void invoke(unsigned index,const int32_t *input,struct Observation *output,
                   uint32_t left,uint32_t right) {
 switch(index) {
DISPATCH
 default: break;
 }
}
static unsigned parity(uint32_t value) {
 unsigned bits=0,i;
 for(i=0;i<8;i++)bits+=(value>>i)&1U;
 return (bits&1U)^1U;
}
static int check_observation(unsigned index,int32_t input,uint32_t left,uint32_t right,
                             const int32_t *pointer,const struct Observation *output) {
 union {double value;uint64_t bits;} expected;
 uint64_t source=(uint64_t)(uint32_t)input;
 const uint32_t difference=left-right;
 unsigned expected_flags[5],i;
 expected.value=(double)input;
 if(index==2 || (index==5 && left==right))expected.value=(double)(uint32_t)input;
 if(index==3 || index==4 || (index==5 && left!=right))source=(uint64_t)(int64_t)input;
 if(index==6){expected.value=9007199254740992.0;source=UINT64_C(0x0020000000000000);}
 if(index==7){expected.value=-9007199254740992.0;source=UINT64_C(0xFFE0000000000000);}
 if(index==8){expected.value=1152921504606846976.0;source=UINT64_C(0x1000000000000000);}
 expected_flags[0]=left<right;
 expected_flags[1]=left==right;
 expected_flags[2]=difference>>31;
 expected_flags[3]=(((left^right)&(left^difference))>>31)&1U;
 expected_flags[4]=parity(difference);
 if(output->actual[0]!=expected.bits || output->actual[1]!=UINT64_C(0x7FF80000F00DBABE))return 1;
 if(output->source_before!=source || output->source_after!=source)return 2;
 if(output->other_before!=UINT64_C(0x0123456789ABCDEF) || output->other_after!=output->other_before)return 3;
 if(output->pointer_before!=(uint64_t)(uintptr_t)pointer || output->pointer_after!=output->pointer_before)return 4;
 if(output->left_before!=left || output->left_after!=left || output->right_before!=right || output->right_after!=right)return 5;
 if(output->copy_before!=(index==4?(uint64_t)(int64_t)input:UINT64_C(0x00DDBBCCAA998877)) || output->copy_after!=output->copy_before)return 6;
 for(i=0;i<5;i++)if(output->before[i]!=expected_flags[i] || output->after[i]!=expected_flags[i])return 7;
 return 0;
}
static int exercise(unsigned start,unsigned end,unsigned *completed) {
 static const int32_t values[]={0,1,-1,(-2147483647-1),2147483647,16777217,-16777217,1073741825,-1073741825};
 static const uint32_t pairs[][2]={{0,0},{0,1},{0x80000000U,1},{0x7FFFFFFFU,0xFFFFFFFFU},{0x12345678U,0x12345670U},{0x80000000U,0x80000001U}};
 SYSTEM_INFO system;
 DWORD old_protect;
 unsigned char *region;
 int32_t *input;
 const unsigned saved=_mm_getcsr();
 unsigned control,index,item,pair;
 int error=0;
 GetSystemInfo(&system);
 region=(unsigned char*)VirtualAlloc(0,(SIZE_T)system.dwPageSize*2,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
 if(!region)return 1001;
 if(!VirtualProtect(region+system.dwPageSize,system.dwPageSize,PAGE_NOACCESS,&old_protect)){error=1002;goto cleanup;}
 /* Every m32/GPR-load input ends exactly at an inaccessible page. */
 input=(int32_t*)(region+system.dwPageSize-4);
 *completed=0;
 for(control=start;control<end;control++){
  const unsigned csr=((control&3U)<<13)|((control&4U)?0x8000U:0U)|((control&8U)?0x40U:0U)|((control&16U)?0x3FU:0U)|((control&32U)?0x1F80U:0U);
  for(index=0;index<9;index++)for(item=0;item<sizeof(values)/sizeof(values[0]);item++)for(pair=0;pair<sizeof(pairs)/sizeof(pairs[0]);pair++){
   struct Observation output;
   unsigned after;
   *input=values[item];
   output.seed[0]=UINT64_C(0xDEADBEEFCAFEBABE);
   output.seed[1]=UINT64_C(0x7FF80000F00DBABE);
   _mm_setcsr(csr);
   invoke(index,input,&output,pairs[pair][0],pairs[pair][1]);
   after=_mm_getcsr();
   _mm_setcsr(saved);
   if(after!=csr){error=1003;goto cleanup;}
   if(*input!=values[item]){error=1004;goto cleanup;}
   error=check_observation(index,values[item],pairs[pair][0],pairs[pair][1],input,&output);
   if(error){error+=(int)(100+index*10);goto cleanup;}
   ++*completed;
  }
 }
 /* Original unknown/inexact controls run outside the exact MXCSR matrix. */
 {
  const uint64_t opaque=UINT64_C(0x0020000000000001);
  struct Observation output;
  output.seed[0]=0;output.seed[1]=UINT64_C(0x7FF80000F00DBABE);
  _mm_setcsr(0x1F80U);
  vm_cvt_i64_unknown((const int32_t*)&opaque,&output,0,0);
  _mm_setcsr(saved);
  if(output.actual[0]!=UINT64_C(0x4340000000000000) || output.actual[1]!=output.seed[1]){error=1005;goto cleanup;}
  _mm_setcsr(0x1F80U);
  vm_cvt_i64_inexact((const int32_t*)&opaque,&output,0,0);
  _mm_setcsr(saved);
  if(output.actual[0]!=UINT64_C(0x4340000000000000) || output.actual[1]!=output.seed[1])error=1006;
 }
cleanup:
 _mm_setcsr(saved);
 if(!VirtualFree(region,0,MEM_RELEASE))error=1007;
 return error;
}
static char *number(char *out,unsigned value){char digits[12];unsigned count=0;do{digits[count++]=(char)('0'+value%10);value/=10;}while(value);while(count)*out++=digits[--count];return out;}
static char *text(char *out,const char *value){while(*value)*out++=*value++;return out;}
static int range_value(const char *value,unsigned *number_out){
 unsigned result=0,index=0;
 if(!value[0])return 0;
 while(value[index]){
  if(index>=2 || value[index]<'0' || value[index]>'9')return 0;
  result=result*10U+(unsigned)(value[index]-'0');++index;
 }
 if(result>64)return 0;
 *number_out=result;return 1;
}
static int configured_range(unsigned *start,unsigned *end){
 char first[16],last[16];
 const DWORD first_size=GetEnvironmentVariableA("LETHE_CVTSI2SD_MATRIX_START",first,sizeof(first));
 const DWORD last_size=GetEnvironmentVariableA("LETHE_CVTSI2SD_MATRIX_END",last,sizeof(last));
 if(!first_size && !last_size){*start=0;*end=64;return 1;}
 if(!first_size || !last_size || first_size>=sizeof(first) || last_size>=sizeof(last))return 0;
 return range_value(first,start) && range_value(last,end) && *start<*end;
}
__declspec(dllexport) int fixture_run(void) {
 unsigned start=0,end=0,completed=0;
 const int error=configured_range(&start,&end)?exercise(start,end,&completed):1008;
 char buffer[256],*cursor=buffer;
 DWORD written;
 if(error){cursor=text(cursor,"CVTSI2SD_EXACT failed code=");cursor=number(cursor,(unsigned)error);}
 else{
  cursor=text(cursor,"CVTSI2SD_EXACT functions=9 mxcsr_start=");cursor=number(cursor,start);
  cursor=text(cursor," mxcsr_end=");cursor=number(cursor,end);
  cursor=text(cursor," cases=");cursor=number(cursor,completed);
  cursor=text(cursor," guard_m32=1 flags=1 gpr=1 upper64=1 negative_original=1 passed=true");
 }
 *cursor++='\n';
 WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),buffer,(DWORD)(cursor-buffer),&written,0);
 return error?21:0;
}
#ifdef BUILD_DLL
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved){(void)module;(void)reason;(void)reserved;return TRUE;}
/* Retain an actual base relocation without taking a selected entry's address. */
__declspec(dllexport) const void *fixture_anchor=(const void*)&DllMain;
#else
__declspec(noreturn) void fixture_entry(void){ExitProcess((UINT)fixture_run());}
#endif
""".replace("DECLARATIONS", _DECLARATIONS).replace("DISPATCH", _DISPATCH)
_HOST = r"""#include <windows.h>
int wmain(int argc,wchar_t **argv){
 if(argc!=2)return 90;
 HMODULE module=LoadLibraryW(argv[1]);if(!module)return 91;
 auto call=reinterpret_cast<int(*)()>(GetProcAddress(module,"fixture_run"));
 if(!call){FreeLibrary(module);return 92;}
 const int result=call();if(!FreeLibrary(module))return 93;return result;
}
"""
_SHARDS = tuple((start, start + 8) for start in range(0, 64, 8))
_RANGE_ENV = ("LETHE_CVTSI2SD_MATRIX_START", "LETHE_CVTSI2SD_MATRIX_END")


def _expected(start: int, end: int) -> bytes:
    return (f"CVTSI2SD_EXACT functions=9 mxcsr_start={start} mxcsr_end={end} "
            f"cases={(end-start)*9*9*6} guard_m32=1 flags=1 gpr=1 upper64=1 "
            "negative_original=1 passed=true\n").encode("ascii")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str | Path], *, cwd: Path,
         env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([str(part) for part in command], cwd=cwd,
                          stdin=subprocess.DEVNULL, capture_output=True,
                          timeout=180, check=False, env=env)


def _compiler_imports() -> dict[str, str]:
    expected = Path(os.environ.get("LETHE_CVTSI2SD_EXPECTED_COMPILER_ROOT",
                                  str(Path(__file__).resolve().parents[1]))).resolve()
    modules = (plan, orchestrator, pe_analyze, assemble, virtualize,
               direct_control_flow, runtime)
    paths = {module.__name__: str(Path(module.__file__).resolve()) for module in modules}
    assert all(Path(path).parents[1] == expected for path in paths.values()), paths
    return paths


def _write_receipt(path: Path, receipt: dict) -> None:
    path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    assert json.loads(path.read_text(encoding="utf-8")) == receipt


def _run_matrix(command, *, cwd: Path, label: str, receipt: dict,
                receipt_path: Path) -> None:
    controls = []
    for start, end in _SHARDS:
        assert 0 <= start < end <= 64 and end-start == 8
        assert not set(controls).intersection(range(start, end))
        env = os.environ.copy()
        env.update(dict(zip(_RANGE_ENV, (str(start), str(end)))))
        row = {"label": label, "argv": [str(item) for item in command], "cwd": str(cwd),
               "range": [start, end], "env": {key: env[key] for key in _RANGE_ENV},
               "expected_cases": (end-start)*9*9*6, "state": "running"}
        receipt["runs"].append(row)
        _write_receipt(receipt_path, receipt)
        clock = time.monotonic()
        try:
            completed = _run(command, cwd=cwd, env=env)
        except subprocess.TimeoutExpired as error:
            row.update({"state": "timeout", "elapsed_seconds": time.monotonic()-clock,
                        "timeout_seconds": error.timeout,
                        "stdout": (error.stdout or b"").decode("ascii", errors="replace"),
                        "stderr": (error.stderr or b"").decode("ascii", errors="replace")})
            _write_receipt(receipt_path, receipt)
            raise
        row.update({"state": "terminal", "elapsed_seconds": time.monotonic()-clock,
                    "exit_status": completed.returncode,
                    "stdout": completed.stdout.decode("ascii", errors="replace"),
                    "stderr": completed.stderr.decode("ascii", errors="replace")})
        _write_receipt(receipt_path, receipt)
        assert (completed.returncode, completed.stdout, completed.stderr) == (0, _expected(start, end), b""), row
        controls.extend(range(start, end))
    assert controls == list(range(64)) and len(set(controls)) == 64
    receipt["partitions"][label] = {"controls": controls, "cases": len(controls)*9*9*6,
                                     "exact_disjoint_union": True}
    _write_receipt(receipt_path, receipt)


def _build(work: Path) -> tuple[Path, Path, Path]:
    source, build = work / "src", work / "build"
    source.mkdir(parents=True)
    (source / "probe.asm").write_text(_ASM, encoding="ascii")
    (source / "probe.c").write_text(_C, encoding="ascii")
    (source / "host.cpp").write_text(_HOST, encoding="ascii")
    exports = " ".join(f"/EXPORT:{name}" for name in (*_NAMES, *(row[0] for row in _NEGATIVE)))
    (source / "CMakeLists.txt").write_text(f"""cmake_minimum_required(VERSION 3.20)
project(lethe_cvtsi2sd_exact C CXX ASM_MASM)
add_executable(probe_exe probe.c probe.asm)
add_library(probe_dll SHARED probe.c probe.asm)
add_executable(reference_host host.cpp)
target_compile_definitions(probe_dll PRIVATE BUILD_DLL=1)
set_source_files_properties(probe.c PROPERTIES COMPILE_OPTIONS "/W4;/WX;/O2;/GS-;/fp:strict")
target_compile_options(reference_host PRIVATE /W4 /WX /O2)
target_link_options(probe_exe PRIVATE /INCREMENTAL:NO /OPT:NOICF /FIXED /NXCOMPAT /CETCOMPAT:NO /NODEFAULTLIB /ENTRY:fixture_entry /SUBSYSTEM:CONSOLE {exports})
target_link_options(probe_dll PRIVATE /INCREMENTAL:NO /OPT:NOICF /DYNAMICBASE /NXCOMPAT /CETCOMPAT:NO /NODEFAULTLIB /ENTRY:DllMain /MANIFEST:NO {exports})
target_link_libraries(probe_exe PRIVATE kernel32.lib)
target_link_libraries(probe_dll PRIVATE kernel32.lib)
""", encoding="ascii")
    for argv in (("cmake", "-S", source, "-B", build,
                  "-G", "Visual Studio 17 2022", "-A", "x64"),
                 ("cmake", "--build", build, "--config", "Release")):
        result = _run(list(argv), cwd=work)
        assert result.returncode == 0, (argv, result.stdout, result.stderr)
    release = build / "Release"
    return release / "probe_exe.exe", release / "probe_dll.dll", release / "reference_host.exe"


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path, Path]:
    if os.name != "nt" or os.environ.get(runtime._RUN_GATE) != "1":
        pytest.skip("opt-in Windows x64 materialized CVTSI2SD proof")
    if not shutil.which("cmake") or not runtime._visual_studio_available():
        pytest.skip("CMake + Visual Studio x64 toolchain required")
    return _build(tmp_path_factory.mktemp("cvt-exact"))


@pytest.fixture(scope="module")
def strict_stub() -> Path:
    _compiler_imports()
    configured = (os.environ.get("LETHE_STRICT_REFERENCE_STUB_PATH")
                  or os.environ.get(runtime._STUB_PATH_ENV))
    assert configured, "strict materialized test requires a fresh source-bound candidate"
    stub = Path(configured).resolve()
    assert stub.is_file() and stub.with_suffix(".manifest.json").is_file()
    return stub


def _specs(source: Path, names: tuple[str, ...]):
    parsed = pe_analyze.analyze_pe(str(source))
    image = assemble._StubImage(source.read_bytes())
    specs = []
    for name in names:
        entry = image.find_export_rva(name)
        assert entry is not None
        row, = (r for r in parsed.runtime_functions if r.begin_rva == entry)
        instructions = tuple(Decoder(64, image.read_at_rva(entry, row.end_rva-entry), ip=entry))
        assert sum(i.mnemonic == Mnemonic.CVTSI2SD for i in instructions) == 1
        assert not any(i.mnemonic == Mnemonic.CALL for i in instructions)
        specs.append(plan.FunctionSpec(name, entry, row.end_rva-entry))
    proof = direct_control_flow.analyze_direct_control_flow(parsed, tuple(specs), production=False)
    gaps = tuple(orchestrator.VirtualizationGapAcknowledgement(
        gap.rva, gap.size, "exact generated CVTSI2SD fixture executable gap")
        for gap in proof.coverage_gaps)
    return tuple(specs), gaps


def _options(output: Path, stub: Path, is_dll: bool, specs, gaps):
    return orchestrator.PackOptions(
        output_path=str(output), is_dll=is_dll, stub_path=str(stub),
        virtualization_specs=tuple(orchestrator.VirtualizationSpec(
            spec.name, spec.rva, spec.size) for spec in specs),
        virtualization_gap_acknowledgements=gaps,
        acknowledge_unproven_indirect_targets=True,
        _allow_unverified_stub_for_tests=False,
    )


def test_strict_cvtsi2sd_exact_exe_dll_parity(
    generated, strict_stub: Path, tmp_path: Path, monkeypatch,
) -> None:
    """Nine exact source domains retain lanes, flags, GPRs and every MXCSR mode."""
    exe, dll, host = generated
    stub_pin, manifest_pin = _sha(strict_stub), _sha(strict_stub.with_suffix(".manifest.json"))
    receipt_path = tmp_path / "native-matrix-receipt.json"
    receipt = {"test_harness": str(Path(__file__).resolve()),
               "test_harness_sha256": _sha(Path(__file__)),
               "compiler_imports": _compiler_imports(), "unverified_override": False,
               "candidate_pins": {str(strict_stub): stub_pin,
                                    str(strict_stub.with_suffix(".manifest.json")): manifest_pin},
               "matrix_dimensions": [64, 9, 9, 6], "runs": [], "partitions": {},
               "image_pins": {}, "selected_code_pins": {}}
    _write_receipt(receipt_path, receipt)
    monkeypatch.setenv(runtime._VIRTUALIZATION_GATE, "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")
    for source, is_dll in ((exe, False), (dll, True)):
        original_pin = _sha(source)
        kind = "dll" if is_dll else "exe"
        receipt["image_pins"][str(source)] = original_pin
        _run_matrix([host, source] if is_dll else [source], cwd=source.parent,
                    label=f"{kind}-original", receipt=receipt, receipt_path=receipt_path)
        specs, gaps = _specs(source, _NAMES)
        image = assemble._StubImage(source.read_bytes())
        receipt["selected_code_pins"][kind] = {
            spec.name: hashlib.sha256(image.read_at_rva(spec.rva, spec.size)).hexdigest()
            for spec in specs}
        output = tmp_path / ("exact.packed.dll" if is_dll else "exact.packed.exe")
        captured = {}
        materialize = virtualize.materialize_selected_functions

        def capture(*args, **kwargs):
            result = materialize(*args, **kwargs)
            captured["result"] = result
            return result

        with monkeypatch.context() as patch:
            patch.setattr(virtualize, "materialize_selected_functions", capture)
            result = orchestrator.pack_file(str(source), _options(output, strict_stub, is_dll, specs, gaps))
        assert result.ok, result.error
        assert {fn.name for fn in captured["result"].manifest.functions} == set(_NAMES)
        receipt["image_pins"][str(output)] = _sha(output)
        _run_matrix([host, output] if is_dll else [output], cwd=output.parent,
                    label=f"{kind}-packed", receipt=receipt, receipt_path=receipt_path)
        assert _sha(source) == original_pin
    assert _sha(strict_stub) == stub_pin
    assert _sha(strict_stub.with_suffix(".manifest.json")) == manifest_pin
    assert set(receipt["partitions"]) == {"exe-original", "exe-packed", "dll-original", "dll-packed"}
    assert len(receipt["runs"]) == 32
    assert all(_sha(Path(path)) == pin for path, pin in receipt["image_pins"].items())
    receipt.update({"state": "verified", "all_coverage_partitions_exact": True,
                    "candidate_pins_unchanged": True, "image_pins_unchanged": True})
    _write_receipt(receipt_path, receipt)


def test_strict_cvtsi2sd_unknown_inexact_r64_rejects_exe_dll(
    generated, strict_stub: Path, tmp_path: Path, monkeypatch,
) -> None:
    """Native-valid unknown/inexact signed64 conversions never create output."""
    exe, dll, host = generated
    stub_pin, manifest_pin = _sha(strict_stub), _sha(strict_stub.with_suffix(".manifest.json"))
    receipt_path = tmp_path / "native-negative-receipt.json"
    receipt = {"test_harness": str(Path(__file__).resolve()),
               "compiler_imports": _compiler_imports(), "unverified_override": False,
               "candidate_pins": {str(strict_stub): stub_pin,
                                    str(strict_stub.with_suffix(".manifest.json")): manifest_pin},
               "original_runs": [], "negative_results": []}
    monkeypatch.setenv(runtime._VIRTUALIZATION_GATE, "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")
    for source, is_dll in ((exe, False), (dll, True)):
        original_pin = _sha(source)
        env = os.environ.copy()
        env.update(dict(zip(_RANGE_ENV, ("0", "64"))))
        command = [host, source] if is_dll else [source]
        clock = time.monotonic()
        baseline = _run(command, cwd=source.parent, env=env)
        receipt["original_runs"].append({"argv": [str(part) for part in command],
            "cwd": str(source.parent), "env": {key: env[key] for key in _RANGE_ENV},
            "elapsed_seconds": time.monotonic()-clock, "exit_status": baseline.returncode,
            "stdout": baseline.stdout.decode("ascii"), "stderr": baseline.stderr.decode("ascii")})
        _write_receipt(receipt_path, receipt)
        assert (baseline.returncode, baseline.stdout, baseline.stderr) == (
            0, _expected(0, 64), b"")
        for name, _setup, _operand in _NEGATIVE:
            specs, gaps = _specs(source, (name,))
            output = tmp_path / (name + (".must-not-exist.dll" if is_dll else ".must-not-exist.exe"))
            result = orchestrator.pack_file(str(source), _options(output, strict_stub, is_dll, specs, gaps))
            receipt["negative_results"].append({"input": str(source), "name": name,
                "output": str(output), "ok": result.ok, "error": result.error,
                "output_exists": output.exists()})
            _write_receipt(receipt_path, receipt)
            assert not result.ok and "cvtsi2sd" in result.error.lower(), result.error
            assert "exact" in result.error.lower() or "proven" in result.error.lower(), result.error
            assert not output.exists()
        assert _sha(source) == original_pin
    assert _sha(strict_stub) == stub_pin
    assert _sha(strict_stub.with_suffix(".manifest.json")) == manifest_pin
    receipt.update({"state": "verified", "negative_outputs_absent": 4,
                    "candidate_pins_unchanged": True})
    _write_receipt(receipt_path, receipt)
