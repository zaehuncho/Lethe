"""Native proof for the single-instruction DVM_STORE128 boundary."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from packer import assemble


ROOT = Path(__file__).resolve().parents[1]


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


def _run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=180,
        check=False,
    )


@pytest.mark.skipif(os.name != "nt", reason="guard-page proof is Windows-only")
def test_store128_helper_is_one_movdqu_and_guard_fault_is_atomic(
    tmp_path: Path,
) -> None:
    pytest.importorskip("iced_x86")
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")

    source = tmp_path / "source"
    build = tmp_path / "build"
    source.mkdir()
    (source / "guard_store.c").write_text(
        r'''
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

extern void dvm_store128_unaligned(
    void *destination, uint64_t low, uint64_t high);

static int valid_store(void)
{
    uint8_t output[32] = {0};
    static const uint8_t expected[16] = {
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99
    };
    unsigned int index;
    dvm_store128_unaligned(
        output + 3,
        UINT64_C(0x1122334455667788),
        UINT64_C(0x99AABBCCDDEEFF00));
    for (index = 0; index < 16; ++index) {
        if (output[index + 3] != expected[index])
            return 1;
    }
    return 0;
}

static int guard_fault_is_atomic(void)
{
    SYSTEM_INFO info;
    uint8_t *region;
    uint8_t *target;
    DWORD previous;
    unsigned int index;
    int faulted = 0;
    GetSystemInfo(&info);
    region = (uint8_t *)VirtualAlloc(
        NULL, (SIZE_T)info.dwPageSize * 2u,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (region == NULL)
        return 2;
    if (!VirtualProtect(
            region + info.dwPageSize, info.dwPageSize,
            PAGE_NOACCESS, &previous)) {
        VirtualFree(region, 0, MEM_RELEASE);
        return 3;
    }
    target = region + info.dwPageSize - 8;
    for (index = 0; index < 8; ++index)
        target[index] = 0xA5;
    __try {
        dvm_store128_unaligned(
            target,
            UINT64_C(0x1122334455667788),
            UINT64_C(0x99AABBCCDDEEFF00));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        faulted = 1;
    }
    for (index = 0; index < 8; ++index) {
        if (target[index] != 0xA5) {
            VirtualFree(region, 0, MEM_RELEASE);
            return 4;
        }
    }
    VirtualFree(region, 0, MEM_RELEASE);
    return faulted ? 0 : 5;
}

int main(void)
{
    int result = valid_store();
    return result == 0 ? guard_fault_is_atomic() : result;
}
'''.lstrip(),
        encoding="ascii",
    )
    helper = (ROOT / "stub/src/daedalus_store128.asm").as_posix()
    (source / "CMakeLists.txt").write_text(
        f"""
cmake_minimum_required(VERSION 3.20)
project(lethe_store128_native C ASM_MASM)
add_executable(store128_guard guard_store.c "{helper}")
target_compile_options(store128_guard PRIVATE
    $<$<COMPILE_LANGUAGE:C>:/W4;/WX;/O2>)
target_link_options(store128_guard PRIVATE
    /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT
    /EXPORT:dvm_store128_unaligned)
""".lstrip(),
        encoding="ascii",
    )
    configured = _run([
        "cmake", "-S", str(source), "-B", str(build),
        "-G", "Visual Studio 17 2022", "-A", "x64",
    ], tmp_path)
    assert configured.returncode == 0, configured.stdout
    compiled = _run(
        ["cmake", "--build", str(build), "--config", "Release"],
        tmp_path,
    )
    assert compiled.returncode == 0, compiled.stdout
    executable = build / "Release/store128_guard.exe"
    executed = _run([str(executable)], executable.parent)
    assert executed.returncode == 0, executed.stdout

    image = assemble._StubImage(executable.read_bytes())
    helper_rva = image.find_export_rva("dvm_store128_unaligned")
    assert helper_rva is not None
    from iced_x86 import Decoder, Mnemonic, OpKind
    instructions = []
    for instruction in Decoder(
        64,
        image.read_at_rva(helper_rva, 32),
        ip=image.image_base + helper_rva,
    ):
        instructions.append(instruction)
        if instruction.mnemonic == Mnemonic.RET:
            break
    memory_stores = [
        instruction
        for instruction in instructions
        if instruction.op_count > 0
        and instruction.op_kind(0) == OpKind.MEMORY
    ]
    assert [instruction.mnemonic for instruction in memory_stores] == [
        Mnemonic.MOVDQU
    ]
