"""Native ABI regression for structured terminal-tail status 2.

The raw and generic paged VM APIs deliberately keep their historical
zero-only frame-commit contract.  Only the descriptor-v5 bridge calls the
separate paged-tail entry, so this test proves both the legacy no-commit cases
and the one authenticated-paging path that must export the lifted frame.
"""

from __future__ import annotations

import os
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
import x64_lifter  # noqa: E402
from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # noqa: E402
from packer import bytecode_pages  # noqa: E402


_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_MASTER_KEY = bytes(range(32))
_PROGRAM_ID = bytes.fromhex("13579bdf2468ace00123456789abcdef")
_SALT = bytes.fromhex("00112233445566778899aabbccddeeff")


def _c_bytes(value: bytes) -> str:
    return ", ".join(f"0x{byte:02X}" for byte in value)


def _visual_studio_available() -> bool:
    if shutil.which("cl.exe"):
        return True
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "")) / (
        "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    if not vswhere.is_file():
        return False
    result = subprocess.run(
        [
            str(vswhere), "-latest", "-products", "*",
            "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property", "installationPath",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and bool(result.stdout.strip())


def _status_two_program() -> bytes:
    body, _ = _KS.asm("mov eax, 0x5a; xor edx, edx", addr=0x1000)
    ordinary = daedalus_asm.assemble(
        x64_lifter.lift_function(bytes(body), base=0x1000)
    )
    # The final ordinary HALT is opcode 4, followed by its u64 immediate and
    # assembler terminator.  Replace only its success value with status 2.
    assert ordinary.endswith(b"\x04" + b"\0" * 9)
    result = ordinary[:-10] + b"\x04" + (2).to_bytes(8, "little") + b"\0"
    assert result[:-1].endswith(b"\x04" + (2).to_bytes(8, "little"))
    return result


@pytest.mark.skipif(os.name != "nt", reason="the production VM is Windows-only")
def test_status_two_commits_only_through_paged_tail_boundary(tmp_path: Path) -> None:
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")

    program = _status_two_program()
    envelope = bytecode_pages.seal_program(
        program,
        _MASTER_KEY,
        program_id=_PROGRAM_ID,
        page_size=bytecode_pages.MIN_PAGE_SIZE,
        salt=_SALT,
    )
    source_dir = ROOT / "stub" / "src"
    harness = f"""
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "daedalus_vm.h"
#include "key_scatter.h"

static const uint8_t program[] = {{ {_c_bytes(program)} }};
static const uint8_t envelope[] = {{ {_c_bytes(envelope)} }};
static uint8_t key[32] = {{ {_c_bytes(_MASTER_KEY)} }};
static const uint8_t program_id[16] = {{ {_c_bytes(_PROGRAM_ID)} }};

uint64_t daedalus_trampoline_call(void *function, int argument_count,
                                  const uint64_t *arguments)
{{
    (void)function; (void)argument_count; (void)arguments;
    return 0;
}}

static void seed(DaedalusX64Context *context)
{{
    uint32_t index;
    memset(context, 0, sizeof(*context));
    for (index = 0; index < DVM_X64_GPR_COUNT; ++index)
        context->gpr[index] = UINT64_C(0x1111111111111111) * (index + 1u);
    context->rflags = UINT64_C(0x202);
}}

int main(void)
{{
    const uint8_t *base = (const uint8_t *)(uintptr_t)UINT64_C(0x180000000);
    DaedalusX64Context context;
    DaedalusX64Context snapshot;

    seed(&context);
    snapshot = context;
    if (daedalus_vm_exec_x64(program, (uint32_t)sizeof(program),
                             &context, base) != DVM_X64_STATUS_TAIL_EXIT)
        return 10;
    if (memcmp(&context, &snapshot, sizeof(context)) != 0)
        return 11;

    if (key_scatter_init(key) != 0)
        return 12;
    seed(&context);
    snapshot = context;
    if (daedalus_vm_exec_x64_paged(
            envelope, (uint32_t)sizeof(envelope), program_id, &context, base)
            != DVM_X64_STATUS_TAIL_EXIT)
        return 13;
    if (memcmp(&context, &snapshot, sizeof(context)) != 0)
        return 14;

    seed(&context);
    snapshot = context;
    if (daedalus_vm_exec_x64_paged_tail(
            envelope, (uint32_t)sizeof(envelope), program_id, &context, base)
            != DVM_X64_STATUS_TAIL_EXIT)
        return 15;
    if (context.gpr[DVM_X64_RAX] != UINT64_C(0x5A)
            || context.gpr[DVM_X64_RDX] != 0
            || memcmp(&context, &snapshot, sizeof(context)) == 0)
        return 16;
    key_scatter_destroy();
    puts("TAIL_STATUS_API raw=paged=unchanged tail=exported");
    return 0;
}}
"""
    (tmp_path / "harness.c").write_text(harness, encoding="ascii")
    cmake = f"""
cmake_minimum_required(VERSION 3.20)
project(lethe_terminal_tail_status_api C ASM_MASM)
add_executable(tail_status_api
    harness.c
    "{(source_dir / 'bytecode_pages.c').as_posix()}"
    "{(source_dir / 'crypto.c').as_posix()}"
    "{(source_dir / 'daedalus_vm.c').as_posix()}"
    "{(source_dir / 'daedalus_store128.asm').as_posix()}"
    "{(source_dir / 'daedalus_call_frame.asm').as_posix()}"
    "{(source_dir / 'key_scatter.c').as_posix()}"
)
target_include_directories(tail_status_api PRIVATE "{source_dir.as_posix()}")
target_compile_definitions(tail_status_api PRIVATE
    WIN32_LEAN_AND_MEAN NOMINMAX DVM_PAGED_RUNTIME)
target_link_libraries(tail_status_api PRIVATE bcrypt)
if(MSVC)
    target_compile_options(tail_status_api PRIVATE
        $<$<COMPILE_LANGUAGE:C>:/W4;/WX;/O2>)
endif()
"""
    (tmp_path / "CMakeLists.txt").write_text(cmake, encoding="ascii")
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
    ran = subprocess.run(
        [str(build / "Release" / "tail_status_api.exe")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert ran.returncode == 0, ran.stdout + ran.stderr
    assert ran.stdout.strip() == "TAIL_STATUS_API raw=paged=unchanged tail=exported"
    assert ran.stderr == ""
