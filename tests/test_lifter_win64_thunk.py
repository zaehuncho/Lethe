"""Native tests for the generated Win64 -> Daedalus common entry bridge."""

from __future__ import annotations

import os
import runpy
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lifter"))
sys.path.insert(0, str(ROOT / "daedalus"))

pytest.importorskip("iced_x86")
pytest.importorskip("keystone")

import daedalus_asm  # noqa: E402
import daedalus_rolling  # noqa: E402
import virtualization_plan as plan  # noqa: E402
import win64_thunk  # noqa: E402
import x64_lifter  # noqa: E402
from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # noqa: E402


_KS = Ks(KS_ARCH_X86, KS_MODE_64)


def _asm(source: str) -> bytes:
    encoded, _ = _KS.asm(source, addr=0x1000)
    return bytes(encoded)


def _c_bytes(blob: bytes) -> str:
    return ", ".join(f"0x{byte:02X}" for byte in blob)


def _visual_studio_available() -> bool:
    if shutil.which("cl.exe"):
        return True
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "")) / (
        "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    if not vswhere.is_file():
        return False
    probe = subprocess.run(
        [
            str(vswhere),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return probe.returncode == 0 and bool(probe.stdout.strip())


def test_generated_thunk_has_fixed_descriptor_and_cet_return_shape() -> None:
    source = win64_thunk.render_entry_thunk("virtual_leaf", "virtual_descriptor")
    assert "pushfq\n    .allocstack 8" in source
    assert "sub     rsp, 32\n    .allocstack 32" in source
    assert "call    daedalus_x64_enter_common" in source
    assert "jmp     SHORT virtual_leaf_resume" in source
    assert "dq      OFFSET virtual_descriptor" in source
    assert "add     rsp, 40\n    ret" in source
    assert "mov     ecx, 7" in source
    assert "int     29h" in source
    assert "popfq" not in source
    common = (ROOT / "stub/src/daedalus_x64_thunk.asm").read_text(
        encoding="utf-8"
    )
    assert "test    eax, eax\n    jne     dvm_enter_failed" in common
    assert "cmp     eax, -1" not in common
    assert "DVM_DESCRIPTOR_VERSION_PLAIN EQU 3" in common
    assert "DVM_DESCRIPTOR_VERSION_PAGED EQU 4" in common
    assert "mov     r9, QWORD PTR [r11 + 16]" in common
    assert "mov     rax, QWORD PTR [r11 + 32]" in common
    assert "mov     QWORD PTR [rsp + 32], rax" in common
    with pytest.raises(ValueError):
        win64_thunk.render_entry_thunk("bad-name", "descriptor")


@pytest.mark.parametrize("rolling", [False, True], ids=["plain", "rolling"])
@pytest.mark.skipif(os.name != "nt", reason="the production stub is Win64-only")
def test_fresh_stub_exports_common_entry_and_opcode_provenance(
    tmp_path: Path, rolling: bool
) -> None:
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")
    pytest.importorskip("lief")
    from packer.assemble import _StubImage

    build = tmp_path / "stub-build"
    configured = subprocess.run(
        [
            "cmake",
            "-S", str(ROOT / "stub"),
            "-B", str(build),
            "-G", "Visual Studio 17 2022",
            "-A", "x64",
            f"-DDVM_ROLLING={'ON' if rolling else 'OFF'}",
            "-DDVM_ROLL_POISON=OFF",
            f"-DDVM_SHUFFLE_SEED={'11' * 32}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert configured.returncode == 0, configured.stdout + configured.stderr
    compiled = subprocess.run(
        ["cmake", "--build", str(build), "--config", "Release"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr

    image = _StubImage((build / "Release/lethe_stub_x64.dll").read_bytes())
    common_rva = image.find_export_rva("daedalus_x64_enter_common")
    provenance_rva = image.find_export_rva("daedalus_opcode_mapping_sha256")
    handler_rva = image.find_export_rva("daedalus_handler_variant_sha256")
    assert common_rva is not None and common_rva > 0
    assert image.section_containing(common_rva).characteristics & 0x20000000
    assert provenance_rva is not None and provenance_rva > 0
    assert handler_rva is not None and handler_rva > 0
    exported_hash = image.cstr_at_rva(provenance_rva)
    exported_handler_hash = image.cstr_at_rva(handler_rva)
    generated = runpy.run_path(str(build / "daedalus_opcodes_shuffled.py"))
    table = plan.OpcodeTable.from_mapping(
        generated["SHUFFLED_OPCODES"], identity="fresh-stub"
    )
    assert exported_hash == generated["OPCODE_MAPPING_SHA256"]
    assert exported_hash == table.sha256
    assert exported_handler_hash == generated["HANDLER_VARIANT_SHA256"]


@pytest.mark.parametrize("rolling", [False, True], ids=["plain", "rolling"])
@pytest.mark.skipif(os.name != "nt", reason="the production thunk is Win64-only")
def test_generated_thunk_matches_native_leaf(
    tmp_path: Path, rolling: bool
) -> None:
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")

    # The fifth Win64 integer argument is at [entry RSP + 40]. Proving this load
    # validates that the common bridge models the pre-shim caller RSP, not its
    # own internal stack frame.
    body = _asm(
        "mov rax, rcx; xor rax, rdx; imul r8, r8, 3; "
        "add rax, r8; add rax, r9; mov r10, [rsp+0x28]; add rax, r10"
    )
    program = daedalus_asm.assemble(
        x64_lifter.lift_function(body, base=0x1000)
    )
    if rolling:
        program = daedalus_rolling.pack_rolling_blob(
            program, bytes.fromhex("102132435465768798a9bacbdcedfe0f")
        )

    harness = f"""
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h>
#include "daedalus_vm.h"

int crypto_sha256(const void *data, size_t len, uint8_t out[32])
{{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    NTSTATUS status;
    if (len > 0xFFFFFFFFu)
        return 1;
    status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status >= 0)
        status = BCryptHash(algorithm, NULL, 0, (PUCHAR)data,
                            (ULONG)len, out, 32);
    if (algorithm)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    return status < 0;
}}
int crypto_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len)
{{
    (void)ikm; (void)ikm_len; (void)salt; (void)salt_len;
    (void)info; (void)info_len; (void)out; (void)out_len;
    return 1;
}}
int key_scatter_init(uint8_t key[32]) {{ (void)key; return 1; }}
int daedalus_vm_exec_x64_paged(const uint8_t *envelope,
                               uint32_t envelope_size,
                               const uint8_t expected_program_id[16],
                               DaedalusX64Context *context,
                               const uint8_t *image_base)
{{
    (void)envelope; (void)envelope_size;
    (void)expected_program_id; (void)context; (void)image_base;
    return -1;
}}
uint64_t daedalus_trampoline_call(void *func, int argc, const uint64_t *argv)
{{ (void)func; (void)argc; (void)argv; return 0; }}

static const uint8_t virtual_program[] = {{ {_c_bytes(program)} }};
static const uint8_t nonzero_program[] = {{ 0x00, 0x00, 0x02, 0x01, 0x00 }};

const DaedalusX64Descriptor virtual_descriptor = {{
    DVM_X64_DESCRIPTOR_VERSION,
    (uint32_t)sizeof(virtual_program),
    virtual_program,
    virtual_program
}};
const DaedalusX64Descriptor failure_descriptor = {{
    DVM_X64_DESCRIPTOR_VERSION,
    (uint32_t)sizeof(nonzero_program),
    nonzero_program,
    nonzero_program
}};
const DaedalusX64Descriptor zero_base_descriptor = {{
    DVM_X64_DESCRIPTOR_VERSION,
    (uint32_t)sizeof(virtual_program),
    virtual_program,
    NULL
}};

typedef char DescriptorProgramOffsetGuard[
    offsetof(DaedalusX64Descriptor, program) == 8 ? 1 : -1];
typedef char DescriptorImageBaseOffsetGuard[
    offsetof(DaedalusX64Descriptor, image_base) == 16 ? 1 : -1];

uint64_t virtual_leaf(uint64_t a, uint64_t b, uint64_t c,
                      uint64_t d, uint64_t e);
uint64_t virtual_failure(uint64_t a, uint64_t b, uint64_t c,
                          uint64_t d, uint64_t e);
uint64_t virtual_zero_base(uint64_t a, uint64_t b, uint64_t c,
                           uint64_t d, uint64_t e);
void daedalus_x64_enter_common(void);
int verify_virtual_nonvolatiles(void);

static uint64_t native_leaf(uint64_t a, uint64_t b, uint64_t c,
                            uint64_t d, uint64_t e)
{{
    return (a ^ b) + c * 3 + d + e;
}}

static int verify_thunk_unwind(PRUNTIME_FUNCTION runtime, DWORD64 image_base)
{{
    static const struct {{ DWORD offset; LONG64 rsp_delta; }} points[] = {{
        {{ 0, 0 }},       /* before pushfq */
        {{ 1, -8 }},      /* after pushfq */
        {{ 5, -40 }},     /* body, after complete prolog */
        {{ 20, -40 }},    /* resume body */
        {{ 26, -40 }},    /* add rsp,40 epilog instruction */
        {{ 30, 0 }},      /* ret epilog instruction */
    }};
    DWORD64 stack[32] = {{0}};
    DWORD64 entry_rsp = (DWORD64)(uintptr_t)&stack[16];
    DWORD64 return_address = UINT64_C(0x1234567812345678);
    unsigned int i;
    *(DWORD64 *)(uintptr_t)entry_rsp = return_address;
    for (i = 0; i < sizeof(points) / sizeof(points[0]); i++) {{
        CONTEXT context;
        PVOID handler_data = NULL;
        DWORD64 establisher_frame = 0;
        memset(&context, 0, sizeof(context));
        context.ContextFlags = CONTEXT_CONTROL;
        context.Rip = image_base + runtime->BeginAddress + points[i].offset;
        context.Rsp = (DWORD64)((LONG64)entry_rsp + points[i].rsp_delta);
        RtlVirtualUnwind(
            UNW_FLAG_NHANDLER,
            image_base,
            context.Rip,
            runtime,
            &context,
            &handler_data,
            &establisher_frame,
            NULL);
        if (context.Rip != return_address || context.Rsp != entry_rsp + 8)
            return 1 + (int)i;
    }}
    return 0;
}}

int main(int argc, char **argv)
{{
    static const uint64_t cases[][5] = {{
        {{ 1, 2, 3, 4, 5 }},
        {{ 0x11111111, 0x22222222, 0x3333, 0x4444, 0x5555 }},
        {{ UINT64_C(0xFFFFFFFFFFFFFFF0), 3, 7, 11, 13 }}
    }};
    unsigned int i;
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION thunk_runtime;
    uint8_t normalized_thunk[{win64_thunk.THUNK_CODE_SIZE}];
    static const uint8_t expected_thunk[] = {{
        {_c_bytes(win64_thunk.THUNK_TEMPLATE)}
    }};
    static const uint8_t expected_unwind[] = {{
        0x01, 0x05, 0x02, 0x00, 0x05, 0x32, 0x01, 0x02
    }};
    (void)argv;
    if (argc > 2) {{
        (void)virtual_zero_base(1, 2, 3, 4, 5);
        return 98;
    }}
    if (argc > 1) {{
        (void)virtual_failure(1, 2, 3, 4, 5);
        return 99;
    }}
    memcpy(normalized_thunk, (const void *)(uintptr_t)&virtual_leaf,
           sizeof(normalized_thunk));
    memset(normalized_thunk + {win64_thunk.THUNK_COMMON_REL32_OFFSET}, 0, 4);
    memset(normalized_thunk + {win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET}, 0, 8);
    if (memcmp(normalized_thunk, expected_thunk, sizeof(expected_thunk)) != 0)
        return 5;
    thunk_runtime = RtlLookupFunctionEntry(
        (DWORD64)(uintptr_t)&virtual_leaf, &image_base, NULL);
    if (!thunk_runtime)
        return 1;
    if (thunk_runtime->EndAddress - thunk_runtime->BeginAddress != 40)
        return 3;
    if (memcmp((const void *)(uintptr_t)(image_base + thunk_runtime->UnwindData),
               expected_unwind, sizeof(expected_unwind)) != 0)
        return 4;
    if (verify_thunk_unwind(thunk_runtime, image_base) != 0)
        return 6;
    if (!RtlLookupFunctionEntry(
            (DWORD64)(uintptr_t)&daedalus_x64_enter_common,
            &image_base, NULL))
        return 2;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {{
        uint64_t expected = native_leaf(cases[i][0], cases[i][1], cases[i][2],
                                        cases[i][3], cases[i][4]);
        uint64_t actual = virtual_leaf(cases[i][0], cases[i][1], cases[i][2],
                                       cases[i][3], cases[i][4]);
        if (actual != expected)
            return 10 + (int)i;
    }}
    if (verify_virtual_nonvolatiles() != 0)
        return 20;
    return 0;
}}
"""
    (tmp_path / "harness.c").write_text(harness, encoding="utf-8")
    (tmp_path / "virtual_leaf.asm").write_text(
        win64_thunk.render_entry_thunk("virtual_leaf", "virtual_descriptor"),
        encoding="utf-8",
    )
    (tmp_path / "virtual_failure.asm").write_text(
        win64_thunk.render_entry_thunk("virtual_failure", "failure_descriptor"),
        encoding="utf-8",
    )
    (tmp_path / "virtual_zero_base.asm").write_text(
        win64_thunk.render_entry_thunk(
            "virtual_zero_base", "zero_base_descriptor"
        ),
        encoding="utf-8",
    )

    verifier = r"""
OPTION CASEMAP:NONE
EXTERN virtual_leaf:PROC
EXTERN virtual_failure:PROC
PUBLIC verify_virtual_nonvolatiles
.code

verify_virtual_nonvolatiles PROC FRAME
    push rbx
    .pushreg rbx
    push rbp
    .pushreg rbp
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub  rsp, 40
    .allocstack 40
    .endprolog

    mov rbx, 1111h
    mov rbp, 2222h
    mov rsi, 3333h
    mov rdi, 4444h
    mov r12, 5555h
    mov r13, 6666h
    mov r14, 7777h
    mov r15, 8888h
    mov rcx, 1
    mov rdx, 2
    mov r8, 3
    mov r9, 4
    mov QWORD PTR [rsp + 32], 5
    call virtual_leaf
    cmp rax, 21
    jne verify_nonvolatile_bad
    cmp rbx, 1111h
    jne verify_nonvolatile_bad
    cmp rbp, 2222h
    jne verify_nonvolatile_bad
    cmp rsi, 3333h
    jne verify_nonvolatile_bad
    cmp rdi, 4444h
    jne verify_nonvolatile_bad
    cmp r12, 5555h
    jne verify_nonvolatile_bad
    cmp r13, 6666h
    jne verify_nonvolatile_bad
    cmp r14, 7777h
    jne verify_nonvolatile_bad
    cmp r15, 8888h
    jne verify_nonvolatile_bad
    xor eax, eax
    jmp verify_nonvolatile_done
verify_nonvolatile_bad:
    mov eax, 1
verify_nonvolatile_done:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
verify_virtual_nonvolatiles ENDP

END
"""
    (tmp_path / "verifier.asm").write_text(verifier, encoding="utf-8")

    sources = [
        "harness.c",
        "virtual_leaf.asm",
        "virtual_failure.asm",
        "virtual_zero_base.asm",
        "verifier.asm",
        f'"{(ROOT / "stub/src/daedalus_vm.c").as_posix()}"',
        f'"{(ROOT / "stub/src/daedalus_x64_thunk.asm").as_posix()}"',
    ]
    definitions = ""
    if rolling:
        sources.append(f'"{(ROOT / "stub/src/daedalus_rolling.c").as_posix()}"')
        definitions = "target_compile_definitions(thunk_harness PRIVATE DVM_ROLLING)"
    cmake_source = f"""
cmake_minimum_required(VERSION 3.20)
project(lethe_dvm_entry_thunk_test C ASM_MASM)
add_executable(thunk_harness {' '.join(sources)})
target_include_directories(thunk_harness PRIVATE "{(ROOT / 'stub/src').as_posix()}")
target_compile_definitions(thunk_harness PRIVATE
    WIN32_LEAN_AND_MEAN NOMINMAX DVM_PLAIN_DESCRIPTOR_TEST_ONLY)
target_compile_options(thunk_harness PRIVATE
    $<$<COMPILE_LANGUAGE:C>:/W4> $<$<COMPILE_LANGUAGE:C>:/WX>)
{definitions}
target_link_libraries(thunk_harness PRIVATE bcrypt)
"""
    (tmp_path / "CMakeLists.txt").write_text(cmake_source, encoding="utf-8")

    build = tmp_path / "build"
    configured = subprocess.run(
        [
            "cmake", "-S", str(tmp_path), "-B", str(build),
            "-G", "Visual Studio 17 2022", "-A", "x64",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert configured.returncode == 0, configured.stdout + configured.stderr
    compiled = subprocess.run(
        ["cmake", "--build", str(build), "--config", "Release"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr

    executable = build / "Release/thunk_harness.exe"
    ran = subprocess.run([str(executable)], check=False)
    assert ran.returncode == 0, f"native thunk harness returned {ran.returncode}"
    failed = subprocess.run([str(executable), "--fail-child"], check=False)
    assert failed.returncode != 0
    assert failed.returncode & 0xFFFFFFFF == 0xC0000409
    zero_base = subprocess.run(
        [str(executable), "--zero-base-child", "--select-zero"], check=False
    )
    assert zero_base.returncode != 0
    assert zero_base.returncode & 0xFFFFFFFF == 0xC0000409
