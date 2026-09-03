"""Native vertical slice for x64 body -> lifter -> assembler -> stub VM frame."""

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
pytest.importorskip("unicorn")
pytest.importorskip("keystone")

import daedalus_asm  # noqa: E402
import daedalus_rolling  # noqa: E402
import oracle  # noqa: E402
import x64_lifter as lifter  # noqa: E402
from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # noqa: E402


_KS = Ks(KS_ARCH_X86, KS_MODE_64)


def _asm(source: str) -> bytes:
    encoded, _ = _KS.asm(source, addr=oracle.BASE)
    return bytes(encoded)


def _c_bytes(blob: bytes) -> str:
    return ", ".join(f"0x{byte:02X}" for byte in blob)


def test_native_local_capacity_guard_matches_lifter_scratch_extent() -> None:
    header = (ROOT / "stub/src/daedalus_vm.h").read_text(encoding="utf-8")
    assert lifter.LOCALS_NEEDED == 512
    assert "#define DVM_X64_LOCALS_REQUIRED 512" in header
    assert "#define DVM_X64_LOCAL_PF       232" in header
    assert "#define DVM_X64_LOCAL_IMAGE_BASE 504" in header


def _c_u64s(values: list[int]) -> str:
    return ", ".join(f"UINT64_C(0x{value:016X})" for value in values)


def _flag_mask(flags: dict[str, int]) -> int:
    return sum((flags[name] & 1) << oracle.FLAG_BIT[name] for name in flags)


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


@pytest.mark.skipif(os.name != "nt", reason="the production VM is Windows-only")
def test_lifted_body_executes_through_native_x64_frame(tmp_path: Path) -> None:
    """Prove the new runtime boundary with bytecode emitted from real x64."""
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")

    body = _asm(
        "mov rax, rcx; imul rax, rdx; add rax, r8; xor r11d, r11d"
    )
    blob = daedalus_asm.assemble(lifter.lift_function(body, base=oracle.BASE))
    rolling_blob = daedalus_rolling.pack_rolling_blob(
        blob, bytes.fromhex("00112233445566778899aabbccddeeff")
    )
    initial = [
        0xA0, 7, 6, 0xB3, oracle.STACK, 0xB5, 0xB6, 0xB7,
        5, 0xB9, 0xBA, 0xBBBBBBBBBBBBBBBB,
        0xBC, 0xBD, 0xBE, 0xBF,
    ]
    expected, flags, _ = oracle.run_unicorn(body, initial)

    preserve_cf_body = _asm("inc rax")
    preserve_cf_blob = daedalus_asm.assemble(
        lifter.lift_function(preserve_cf_body, base=oracle.BASE)
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
uint64_t daedalus_trampoline_call(void *func, int argc, const uint64_t *argv)
{{ (void)func; (void)argc; (void)argv; return 0; }}

static const uint8_t lifted_program[] = {{ {_c_bytes(blob)} }};
static const uint8_t lifted_rolling_program[] = {{ {_c_bytes(rolling_blob)} }};
static const uint8_t preserve_cf_program[] = {{ {_c_bytes(preserve_cf_blob)} }};

int main(void)
{{
    const DaedalusX64Context initial = {{ {{ {_c_u64s(initial)} }}, UINT64_C(0x202) }};
    DaedalusX64Context context = initial;
    const uint64_t expected[DVM_X64_GPR_COUNT] = {{ {_c_u64s(expected)} }};
    const uint8_t malformed[] = {{ 0x00, 0x00, 0xFF }};
    const uint8_t nonzero_halt[] = {{ 0x00, 0x00, 0x02, 0x01, 0x00 }};
    DaedalusX64Context snapshot;
    unsigned int i;

    if (daedalus_vm_exec_x64(lifted_program,
            (uint32_t)sizeof(lifted_program), &context,
            (const uint8_t *)(uintptr_t)UINT64_C(0x180000000)) != 0)
        return 10;
    for (i = 0; i < DVM_X64_GPR_COUNT; i++) {{
        if (context.gpr[i] != expected[i])
            return 20 + (int)i;
    }}
    if ((context.rflags & DVM_X64_RFLAGS_MASK)
            != UINT64_C(0x{_flag_mask(flags):X}))
        return 40;
    if ((context.rflags & ~DVM_X64_RFLAGS_MASK)
            != (UINT64_C(0x202) & ~DVM_X64_RFLAGS_MASK))
        return 41;

    context = initial;
    if (daedalus_vm_exec_x64(lifted_rolling_program,
            (uint32_t)sizeof(lifted_rolling_program), &context,
            (const uint8_t *)(uintptr_t)UINT64_C(0x180000000)) != 0)
        return 42;
    for (i = 0; i < DVM_X64_GPR_COUNT; i++) {{
        if (context.gpr[i] != expected[i])
            return 43 + (int)i;
    }}
    if ((context.rflags & DVM_X64_RFLAGS_MASK)
            != UINT64_C(0x{_flag_mask(flags):X}))
        return 59;

    context.gpr[DVM_X64_RAX] = 41;
    context.rflags = UINT64_C(0x203);
    if (daedalus_vm_exec_x64(preserve_cf_program,
            (uint32_t)sizeof(preserve_cf_program), &context,
            (const uint8_t *)(uintptr_t)UINT64_C(0x180000000)) != 0)
        return 50;
    if (context.gpr[DVM_X64_RAX] != 42
            || !(context.rflags & DVM_X64_RFLAGS_CF))
        return 51;

    snapshot = context;
    if (daedalus_vm_exec_x64(malformed,
            (uint32_t)sizeof(malformed), &context,
            (const uint8_t *)(uintptr_t)UINT64_C(0x180000000)) != -1)
        return 60;
    if (memcmp(&context, &snapshot, sizeof(context)) != 0)
        return 61;
    if (daedalus_vm_exec_x64(nonzero_halt,
            (uint32_t)sizeof(nonzero_halt), &context,
            (const uint8_t *)(uintptr_t)UINT64_C(0x180000000)) != 1)
        return 62;
    if (memcmp(&context, &snapshot, sizeof(context)) != 0)
        return 63;
    return 0;
}}
"""
    (tmp_path / "harness.c").write_text(harness, encoding="utf-8")

    vm_source = (ROOT / "stub/src/daedalus_vm.c").as_posix()
    rolling_source = (ROOT / "stub/src/daedalus_rolling.c").as_posix()
    vm_include = (ROOT / "stub/src").as_posix()
    cmake_source = f"""
cmake_minimum_required(VERSION 3.20)
project(lethe_dvm_x64_frame_test C)
add_executable(dvm_x64_frame harness.c "{vm_source}" "{rolling_source}")
target_include_directories(dvm_x64_frame PRIVATE "{vm_include}")
target_compile_definitions(dvm_x64_frame PRIVATE DVM_ROLLING WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(dvm_x64_frame PRIVATE bcrypt)
"""
    (tmp_path / "CMakeLists.txt").write_text(cmake_source, encoding="utf-8")

    build = tmp_path / "build"
    configured = subprocess.run(
        [
            "cmake",
            "-S",
            str(tmp_path),
            "-B",
            str(build),
            "-G",
            "Visual Studio 17 2022",
            "-A",
            "x64",
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

    executable = build / "Release/dvm_x64_frame.exe"
    ran = subprocess.run([str(executable)], check=False)
    assert ran.returncode == 0, f"native harness returned {ran.returncode}"
