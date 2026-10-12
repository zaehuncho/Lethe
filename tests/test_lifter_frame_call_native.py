"""Native proof of positional FP arguments, volatile state and guard dispatch.

Only generated first-party C/MASM fixtures execute. The guard sentinel proves
that dispatch runs and can deny a target, not the Windows CFG negative matrix.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

pytest.importorskip("iced_x86")
pytest.importorskip("keystone")
from iced_x86 import Decoder, Mnemonic
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lifter"))
sys.path.insert(0, str(ROOT / "daedalus"))
import x64_lifter as lifter
import daedalus_asm
import daedalus_rolling

_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_SLOT = 0x4000


def _program(source: str, *, guard: bool = False) -> bytes:
    first = bytes(_KS.asm(source.format(disp=0), addr=0x1000)[0])
    call = next(i for i in Decoder(64, first, ip=0x1000) if i.mnemonic == Mnemonic.CALL)
    code = bytes(_KS.asm(source.format(disp=hex(_SLOT-call.next_ip)), addr=0x1000)[0])
    from types import SimpleNamespace
    sections = (
        SimpleNamespace(name=".text", rva=0x1000, raw=code, virtual_size=len(code), characteristics=0x60000020),
        SimpleNamespace(name=".rdata", rva=_SLOT, raw=bytes(8), virtual_size=8, characteristics=0x40000040),
    )
    return daedalus_asm.assemble(lifter.lift_function(
        code, base=0x1000, image_sections=sections,
        selected_extents=((0x1000,len(code)),),
        guard_cf_dispatch_rva=_SLOT if guard else None))


def _c_bytes(blob: bytes) -> str:
    return ",".join(str(x) for x in blob)


_ASM = r"""
EXTERN frame_seen_flags:QWORD
EXTERN frame_seen_regs:QWORD
EXTERN frame_seen_xmm:BYTE
EXTERN frame_output_xmm:BYTE
EXTERN frame_guard_allowed:QWORD
EXTERN frame_guard_calls:QWORD
EXTERN frame_guard_rejected:QWORD
EXTERN frame_target_calls:QWORD
PUBLIC frame_state_target
PUBLIC frame_guard_dispatch
PUBLIC frame_guard_target
.code
frame_state_target PROC
    pushfq
    pop frame_seen_flags
    mov frame_seen_regs, rax
    mov frame_seen_regs+8, r10
    mov frame_seen_regs+16, r11
    movdqu xmmword ptr [frame_seen_xmm], xmm0
    movdqu xmmword ptr [frame_seen_xmm+16], xmm1
    movdqu xmmword ptr [frame_seen_xmm+32], xmm2
    movdqu xmmword ptr [frame_seen_xmm+48], xmm3
    movdqu xmmword ptr [frame_seen_xmm+64], xmm4
    movdqu xmmword ptr [frame_seen_xmm+80], xmm5
    movdqu xmm0, xmmword ptr [frame_output_xmm]
    movdqu xmm1, xmmword ptr [frame_output_xmm+16]
    movdqu xmm2, xmmword ptr [frame_output_xmm+32]
    movdqu xmm3, xmmword ptr [frame_output_xmm+48]
    movdqu xmm4, xmmword ptr [frame_output_xmm+64]
    movdqu xmm5, xmmword ptr [frame_output_xmm+80]
    xor eax, eax
    stc
    mov rax, 1234567h
    mov rcx, 11h
    mov rdx, 22h
    mov r8, 33h
    mov r9, 44h
    mov r10, 55h
    mov r11, 66h
    ret
frame_state_target ENDP
frame_guard_dispatch PROC
    inc frame_guard_calls
    cmp rax, frame_guard_allowed
    jne denied
    jmp rax
denied:
    inc frame_guard_rejected
    mov rax, 0BADh
    ret
frame_guard_dispatch ENDP
frame_guard_target PROC
    inc frame_target_calls
    mov rax, 3456h
    ret
frame_guard_target ENDP
END
"""

_C = r"""
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "daedalus_vm.h"
int key_scatter_init(uint8_t p[32]) { (void)p;return 1; }
uint64_t frame_seen_flags,frame_seen_regs[3],frame_seen_xmm[6][2];
uint64_t frame_output_xmm[6][2];
uint64_t frame_guard_allowed,frame_guard_calls,frame_guard_rejected,frame_target_calls;
extern void frame_state_target(void);
extern void frame_guard_dispatch(void);
extern void frame_guard_target(void);
#ifdef DVM_FRAME_CALL_AVAILABLE
extern void daedalus_trampoline_frame(void);
/* RtlVirtualUnwind computes a CONTEXT only; no sentinel address executes. */
static int check_transient_flag_unwind(void)
{
    DWORD64 image_base=0;
    PRUNTIME_FUNCTION entry=RtlLookupFunctionEntry(
        (DWORD64)(uintptr_t)&daedalus_trampoline_frame,&image_base,NULL);
    CONTEXT state;
    PVOID handler_data=NULL;
    DWORD64 establisher=0;
    uint64_t stack[128];
    const uint8_t *code,*unwind;
    size_t size,i;
    unsigned int frame_reg;
    if(!entry)return 110;
    code=(const uint8_t *)(uintptr_t)(image_base+entry->BeginAddress);
    unwind=(const uint8_t *)(uintptr_t)(image_base+entry->UnwindData);
    size=(size_t)(entry->EndAddress-entry->BeginAddress);
    /* Python independently decodes this byte as the unique PUSHFQ instruction. */
    for(i=0;i<size&&code[i]!=0x9C;++i){}
    if(i==size)return 111;
    memset(stack,0,sizeof(stack));memset(&state,0,sizeof(state));
    stack[100]=0x56789ABC;
    state.ContextFlags=CONTEXT_FULL;
    state.Rip=(DWORD64)(uintptr_t)(code+i+1);
    frame_reg=unwind[3]&15u;
    if(frame_reg==5) {
        stack[99]=0x11223344;stack[98]=0x55667788;
        stack[97]=0x99AABBCC;stack[96]=0xDDEEFF00;
        state.Rbp=(DWORD64)(uintptr_t)&stack[87];
        state.Rsp=(DWORD64)(uintptr_t)&stack[86];
    } else if(frame_reg==0) {
        /* Original proposal: three pushes, 64-byte allocation, no frame reg. */
        stack[99]=0x55667788;stack[98]=0x99AABBCC;stack[97]=0xDDEEFF00;
        state.Rbp=0x11223344;
        state.Rsp=(DWORD64)(uintptr_t)&stack[88];
    } else return 112;
    RtlVirtualUnwind(UNW_FLAG_NHANDLER,image_base,state.Rip,entry,&state,
                    &handler_data,&establisher,NULL);
    if(state.Rip!=0x56789ABC||state.Rsp!=(DWORD64)(uintptr_t)&stack[101])return 113;
    if(state.Rbp!=0x11223344||state.R12!=0x55667788||
       state.R13!=0x99AABBCC||state.R14!=0xDDEEFF00)return 114;
    return 0;
}
#endif
static uint64_t bits(double value) { uint64_t u;memcpy(&u,&value,8);return u; }
static uint32_t bits32(float value) { uint32_t u;memcpy(&u,&value,4);return u; }
__declspec(noinline) static float mixed32(uint64_t a,float b,uint64_t c,float d,
 uint64_t e,float f,uint64_t g,float h)
{ return (float)a+b+(float)c+d+(float)e+f+(float)g+h; }
__declspec(noinline) static double variadic(uint64_t count,...)
{
    va_list ap;uint64_t i;double sum=0;
    va_start(ap,count);for(i=0;i<count;++i)sum+=va_arg(ap,double);va_end(ap);
    return sum;
}
__declspec(noinline) static double mixed(double a,uint64_t b,double c,uint64_t d,
 double e,uint64_t f,double g,uint64_t h)
{ return a+(double)b+c+(double)d+e+(double)f+g+(double)h; }
@ARRAYS@
static int execute(const uint8_t *p,uint32_t n,DaedalusX64Context *ctx,uint64_t *slot)
{ return daedalus_vm_exec_x64(p,n,ctx,(const uint8_t *)((uintptr_t)slot-0x4000u)); }
int main(int argc,char **argv)
{
    DaedalusX64Context ctx,before;
    uint64_t stack[128],slot;
    __declspec(align(16)) uint64_t aligned_in[2]={0x11223344,0x55667788},aligned_out[2];
    unsigned int mode,i,j,pattern;
    if(argc!=2)return 2;
#ifdef DVM_FRAME_CALL_AVAILABLE
    if(strcmp(argv[1],"unwind")==0) {
        int result=check_transient_flag_unwind();
        if(result)return result;
        puts("NATIVE_FRAME_CALL unwind windows_checks=1 passed=true");
        return 0;
    }
#endif
#define FAIL(code) do { fprintf(stderr,"phase=%s mode=%u code=%d\n",argv[1],mode,code); return code; } while(0)
    for(mode=0;mode<2;++mode) {
      if(strcmp(argv[1],"float")==0) {
        memset(&ctx,0,sizeof(ctx));memset(stack,0,sizeof(stack));
        ctx.gpr[DVM_X64_RSP]=(uint64_t)(uintptr_t)&stack[80];
        ctx.gpr[DVM_X64_RDX]=7;ctx.gpr[DVM_X64_R9]=11;
        ctx.xmm[0][0]=bits(1.25);ctx.xmm[2][0]=bits(-3.5);
        /* Outgoing slots after SUB RSP,58h. */
        stack[73]=bits(5.75);stack[74]=13;stack[75]=bits(-0.5);stack[76]=17;
        slot=(uint64_t)(uintptr_t)&mixed;
        if(execute(fp_program[mode],fp_size[mode],&ctx,&slot))FAIL(39);
        if(ctx.gpr[DVM_X64_RAX]!=bits(mixed(1.25,7,-3.5,11,5.75,13,-0.5,17)))FAIL(40);
        if(ctx.xmm[0][0]!=ctx.gpr[DVM_X64_RAX])FAIL(41);
        if(ctx.gpr[DVM_X64_RSP]!=(uint64_t)(uintptr_t)&stack[80])FAIL(42);
        memset(&ctx,0,sizeof(ctx));memset(stack,0,sizeof(stack));
        ctx.gpr[DVM_X64_RSP]=(uint64_t)(uintptr_t)&stack[80];
        ctx.gpr[DVM_X64_RCX]=1;ctx.gpr[DVM_X64_R8]=3;
        ctx.xmm[1][0]=UINT64_C(0x1122334400000000)|bits32(2.25f);
        ctx.xmm[3][0]=UINT64_C(0x5566778800000000)|bits32(-4.5f);
        stack[73]=5;stack[74]=UINT64_C(0xABCDEF0000000000)|bits32(6.75f);
        stack[75]=7;stack[76]=UINT64_C(0xFEDCBA0000000000)|bits32(-8.5f);
        slot=(uint64_t)(uintptr_t)&mixed32;
        if(execute(fp_program[mode],fp_size[mode],&ctx,&slot))FAIL(43);
        if((uint32_t)ctx.gpr[DVM_X64_RAX]!=bits32(mixed32(1,2.25f,3,-4.5f,5,6.75f,7,-8.5f)))FAIL(44);
        if((uint32_t)ctx.xmm[0][0]!=(uint32_t)ctx.gpr[DVM_X64_RAX])FAIL(45);
        memset(&ctx,0,sizeof(ctx));memset(stack,0,sizeof(stack));
        ctx.gpr[DVM_X64_RSP]=(uint64_t)(uintptr_t)&stack[80];ctx.gpr[DVM_X64_RCX]=7;
        ctx.gpr[DVM_X64_RDX]=ctx.xmm[1][0]=bits(1.25);
        ctx.gpr[DVM_X64_R8]=ctx.xmm[2][0]=bits(2.5);
        ctx.gpr[DVM_X64_R9]=ctx.xmm[3][0]=bits(3.75);
        stack[73]=bits(4.0);stack[74]=bits(5.0);stack[75]=bits(6.0);stack[76]=bits(7.5);
        slot=(uint64_t)(uintptr_t)&variadic;
        if(execute(fp_program[mode],fp_size[mode],&ctx,&slot))FAIL(46);
        if(ctx.gpr[DVM_X64_RAX]!=bits(variadic(7,1.25,2.5,3.75,4.0,5.0,6.0,7.5)))FAIL(47);

      } else if(strcmp(argv[1],"state")==0) {
        for(pattern=0;pattern<32;++pattern) {
          static const unsigned int shifts[5]={0,2,6,7,11};
          static const unsigned int vol[7]={0,1,2,8,9,10,11};
          static const uint64_t out[7]={0x1234567,0x11,0x22,0x33,0x44,0x55,0x66};
          memset(&ctx,0,sizeof(ctx));memset(stack,0,sizeof(stack));
          for(i=0;i<16;++i)ctx.gpr[i]=0x12340000u+i;
          ctx.gpr[DVM_X64_RSP]=(uint64_t)(uintptr_t)&stack[80];
          ctx.rflags=0x202;
          for(i=0;i<5;++i)ctx.rflags|=(uint64_t)((pattern>>i)&1u)<<shifts[i];
          for(i=0;i<16;++i)for(j=0;j<2;++j)ctx.xmm[i][j]=0xABC00000u+i*32u+j;
          for(i=0;i<6;++i)for(j=0;j<2;++j)frame_output_xmm[i][j]=0xDEF00000u+i*32u+j;
          before=ctx;slot=(uint64_t)(uintptr_t)&frame_state_target;
          if(execute(state_program[mode],state_size[mode],&ctx,&slot))FAIL(59);
          if((frame_seen_flags&DVM_X64_RFLAGS_MASK)!=(before.rflags&DVM_X64_RFLAGS_MASK))FAIL(60);
          if(frame_seen_regs[0]!=before.gpr[0]||frame_seen_regs[1]!=before.gpr[10]||frame_seen_regs[2]!=before.gpr[11])FAIL(61);
          if(memcmp(frame_seen_xmm,before.xmm,sizeof(frame_seen_xmm)))FAIL(62);
          for(i=0;i<7;++i)if(ctx.gpr[vol[i]]!=out[i])FAIL(63);
          if((ctx.rflags&DVM_X64_RFLAGS_MASK)!=0x45)FAIL(64);
          if((ctx.rflags&~DVM_X64_RFLAGS_MASK)!=(before.rflags&~DVM_X64_RFLAGS_MASK))FAIL(65);
          for(i=0;i<16;++i) {
            int is_vol=0;for(j=0;j<7;++j)if(i==vol[j])is_vol=1;
            if(!is_vol&&ctx.gpr[i]!=before.gpr[i])FAIL(66);
          }
          if(memcmp(ctx.xmm,frame_output_xmm,sizeof(frame_output_xmm)))FAIL(67);
          if(memcmp(ctx.xmm[6],before.xmm[6],sizeof(ctx.xmm)-sizeof(frame_output_xmm)))FAIL(68);
        }
      } else if(strcmp(argv[1],"guard")==0) {
        for(pattern=0;pattern<2;++pattern) {
          memset(&ctx,0,sizeof(ctx));memset(stack,0,sizeof(stack));
          frame_guard_calls=frame_guard_rejected=frame_target_calls=0;
          ctx.gpr[DVM_X64_RSP]=(uint64_t)(uintptr_t)&stack[80];
          frame_guard_allowed=(uint64_t)(uintptr_t)&frame_guard_target;
          ctx.gpr[DVM_X64_RAX]=pattern?(uint64_t)(uintptr_t)&frame_state_target:frame_guard_allowed;
          slot=(uint64_t)(uintptr_t)&frame_guard_dispatch;
          if(execute(guard_program[mode],guard_size[mode],&ctx,&slot))FAIL(79);
          if(frame_guard_calls!=1||frame_guard_rejected!=pattern||frame_target_calls!=1-pattern)FAIL(80);
          if(ctx.gpr[DVM_X64_RAX]!=(pattern?0xBADu:0x3456u))FAIL(81);
        }
      } else if(strcmp(argv[1],"aligned")==0) {
        memset(&ctx,0,sizeof(ctx));memset(aligned_out,0,sizeof(aligned_out));
        ctx.gpr[DVM_X64_RSP]=(uint64_t)(uintptr_t)&stack[80];
        ctx.gpr[DVM_X64_RCX]=(uint64_t)(uintptr_t)aligned_out;
        ctx.gpr[DVM_X64_RDX]=(uint64_t)(uintptr_t)aligned_in;slot=1;
        if(execute(aligned_program[mode],aligned_size[mode],&ctx,&slot))return 100;
        if(memcmp(aligned_in,aligned_out,sizeof(aligned_in)))return 101;
      } else if(strcmp(argv[1],"invalid")==0) {
        const uint8_t *bad[5]={mode?bad_7_roll:bad_7,mode?bad_9_roll:bad_9,mode?bad_wide_roll:bad_wide,mode?bad_null_roll:bad_null,mode?bad_underflow_roll:bad_underflow};
        const uint32_t sizes[5]={mode?sizeof(bad_7_roll):sizeof(bad_7),mode?sizeof(bad_9_roll):sizeof(bad_9),mode?sizeof(bad_wide_roll):sizeof(bad_wide),mode?sizeof(bad_null_roll):sizeof(bad_null),mode?sizeof(bad_underflow_roll):sizeof(bad_underflow)};
        for(pattern=0;pattern<5;++pattern) {
          memset(&ctx,0,sizeof(ctx));ctx.gpr[0]=0x12345678;ctx.rflags=0x202;
          before=ctx;frame_guard_calls=0;slot=(uint64_t)(uintptr_t)&frame_guard_dispatch;
          if(execute(bad[pattern],sizes[pattern],&ctx,&slot)!=-1)return 90;
          if(memcmp(&ctx,&before,sizeof(ctx))||frame_guard_calls)return 91;
        }
      } else return 3;
    }
    printf("NATIVE_FRAME_CALL %s modes=2 passed=true\n",argv[1]);
    return 0;
}
"""


def build_frame_fixture(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    arrays=[]
    for name,source,guard in (
        ('fp','sub rsp, 0x58; call qword ptr [rip+{disp}]; movq rax, xmm0; add rsp, 0x58; ret',False),
        ('state','call qword ptr [rip+{disp}]; ret',False),
        ('guard','call qword ptr [rip+{disp}]; ret',True),
        ('aligned','movdqa xmm0,[rdx]; movdqa [rcx],xmm0; call qword ptr [rip+{disp}]; ret',False),
    ):
        if name=='aligned':
            code=bytes(_KS.asm('movdqa xmm0,[rdx]; movdqa [rcx],xmm0; ret',addr=0x1000)[0])
            plain=daedalus_asm.assemble(lifter.lift_function(code,base=0x1000))
        else:
            plain=_program(source,guard=guard)
        rolling=daedalus_rolling.pack_rolling_blob(plain,bytes.fromhex('00112233445566778899aabbccddeeff'))
        for suffix,blob in (('plain',plain),('rolling',rolling)):
            arrays.append(f'static const uint8_t {name}_{suffix}[]={{ {_c_bytes(blob)} }};')
        arrays += [f'static const uint8_t *const {name}_program[2]={{ {name}_plain,{name}_rolling }};',
                   f'static const uint32_t {name}_size[2]={{ sizeof({name}_plain),sizeof({name}_rolling) }};']
    if 'n_call_frame' in daedalus_asm.OPCODES:
        for name,argc,target,count in (('7',7,1,8),('9',9,1,8),('wide',0x100000008,1,8),('null',8,0,8),('underflow',8,1,0)):
            source='.code\n'+('push_imm64 0\n'*count)+f'push_imm64 {argc}\npush_imm64 {target}\nn_call_frame\npush_imm8 0\nhalt\n'
            blob=daedalus_asm.assemble(source)
            arrays.append(f'static const uint8_t bad_{name}[]={{ {_c_bytes(blob)} }};')
            roll=daedalus_rolling.pack_rolling_blob(blob,bytes.fromhex('00112233445566778899aabbccddeeff'))
            arrays.append(f'static const uint8_t bad_{name}_roll[]={{ {_c_bytes(roll)} }};')
    else:
        # Baseline driver probes only the three old bridge defects; compile the
        # structural-negative arrays as a rejected unknown opcode for closure.
        for name in ('7','9','wide','null','underflow'):
            arrays.append(f'static const uint8_t bad_{name}[]={{ 0,0,0x3B }};')
            arrays.append(f'static const uint8_t bad_{name}_roll[]={{ 0,0,0x3B }};')
    (directory/'harness.c').write_text(_C.replace('@ARRAYS@','\n'.join(arrays)),encoding='utf-8')
    (directory/'proof.asm').write_text(_ASM,encoding='utf-8')
    files=['crypto.c','daedalus_vm.c','daedalus_rolling.c','daedalus_store128.asm','daedalus_trampoline.asm']
    has_frame=(ROOT/'stub/src/daedalus_call_frame.asm').exists()
    if has_frame:files.append('daedalus_call_frame.asm')
    frame_define='DVM_FRAME_CALL_AVAILABLE' if has_frame else ''
    sources=' '.join('"'+(ROOT/'stub/src'/name).as_posix()+'"' for name in files)
    (directory/'CMakeLists.txt').write_text(f'''cmake_minimum_required(VERSION 3.20)
project(frame_call_proof C ASM_MASM)
add_executable(frame_call harness.c proof.asm {sources})
target_link_libraries(frame_call PRIVATE bcrypt)
target_include_directories(frame_call PRIVATE "{(ROOT/'stub/src').as_posix()}")
target_compile_definitions(frame_call PRIVATE DVM_ROLLING WIN32_LEAN_AND_MEAN NOMINMAX {frame_define})
target_compile_options(frame_call PRIVATE $<$<COMPILE_LANGUAGE:C>:/W4;/WX;/fp:strict>)
''',encoding='utf-8')
    build=directory/'build'
    for command in (['cmake','-S',str(directory),'-B',str(build),'-G','Visual Studio 17 2022','-A','x64'],
                    ['cmake','--build',str(build),'--config','Release']):
        p=subprocess.run(command,capture_output=True,text=True)
        assert p.returncode==0,p.stdout+p.stderr
    executable=build/'Release/frame_call.exe'
    if (ROOT/'stub/src/daedalus_call_frame.asm').exists():
        # Verify the actual emitted PE unwind record, not just MASM directives.
        import pefile
        pe=pefile.PE(str(executable))
        try:
            prefix=bytes.fromhex('55 41 54 41 55 41 56 48 83 EC 48')
            hits=[]
            for section in pe.sections:
                if section.Characteristics&0x20000000:
                    data=section.get_data();offset=data.find(prefix)
                    if offset>=0:
                        assert data.find(prefix,offset+1)<0
                        hits.append(section.VirtualAddress+offset)
            assert len(hits)==1
            records=[entry.struct for entry in pe.DIRECTORY_ENTRY_EXCEPTION
                     if entry.struct.BeginAddress==hits[0]]
            assert len(records)==1 and records[0].EndAddress>hits[0]+14
            # Version 1, fourteen-byte prolog, RBP frame, six unwind codes:
            # SET_FPREG, alloc72, PUSH R14/R13/R12/RBP (descending code order).
            assert pe.get_data(records[0].UnwindData,16)==bytes.fromhex(
                '01 0E 06 05 0E 53 0B 82 07 E0 05 D0 03 C0 01 50')
            code=pe.get_data(records[0].BeginAddress,
                             records[0].EndAddress-records[0].BeginAddress)
            flag_pushes=[i.ip for i in Decoder(64,code,ip=0)
                         if i.mnemonic==Mnemonic.PUSHFQ]
            assert len(flag_pushes)==1 and code.find(b'\x9c')==flag_pushes[0]
        finally:
            pe.close()
    return executable


@pytest.fixture(scope='module')
def frame_fixture(tmp_path_factory):
    if os.name!='nt' or not shutil.which('cmake'):
        pytest.skip('Windows x64 CMake/MSVC required')
    from test_lifter_external_call_native import _visual_studio_available
    if not _visual_studio_available():pytest.skip('Visual Studio x64 toolchain required')
    return build_frame_fixture(tmp_path_factory.mktemp('frame-call'))


@pytest.mark.parametrize('kind',['float','state','guard','invalid','aligned','unwind'])
def test_native_frame_call_boundary(frame_fixture,kind):
    p=subprocess.run([str(frame_fixture),kind],capture_output=True,text=True)
    assert p.returncode==0,f'{kind}: exit={p.returncode}\n{p.stdout}\n{p.stderr}'
    detail='windows_checks=1' if kind=='unwind' else 'modes=2'
    assert p.stdout.strip()==f'NATIVE_FRAME_CALL {kind} {detail} passed=true'
