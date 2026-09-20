"""Native proof for the single-instruction DVM_STORE128 boundary."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from daedalus import daedalus_asm, daedalus_rolling, shuffle_opcodes
from packer import assemble


ROOT = Path(__file__).resolve().parents[1]


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


@pytest.mark.skipif(os.name != "nt", reason="alignment-fault proof is Windows-only")
def test_aligned128_helpers_enforce_alignment_and_one_instruction_boundaries(
    tmp_path: Path,
) -> None:
    pytest.importorskip("iced_x86")
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")

    source = tmp_path / "source"
    build = tmp_path / "build"
    source.mkdir()
    (source / "aligned_transfer.c").write_text(
        r'''
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

extern void dvm_load128_aligned(
    const void *source, uint64_t *low, uint64_t *high);
extern void dvm_store128_aligned(
    void *destination, uint64_t low, uint64_t high);

static int valid_roundtrip(void)
{
    __declspec(align(16)) uint8_t block[16] = {0};
    uint64_t low = 0;
    uint64_t high = 0;
    dvm_store128_aligned(
        block,
        UINT64_C(0x1122334455667788),
        UINT64_C(0x99AABBCCDDEEFF00));
    dvm_load128_aligned(block, &low, &high);
    return (low == UINT64_C(0x1122334455667788) &&
            high == UINT64_C(0x99AABBCCDDEEFF00)) ? 0 : 1;
}

static int unaligned_store_faults_without_write(void)
{
    __declspec(align(16)) uint8_t block[32];
    unsigned int index;
    int faulted = 0;
    for (index = 0; index < 32; ++index)
        block[index] = 0xA5;
    __try {
        dvm_store128_aligned(
            block + 1,
            UINT64_C(0x1122334455667788),
            UINT64_C(0x99AABBCCDDEEFF00));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        faulted = 1;
    }
    for (index = 0; index < 32; ++index) {
        if (block[index] != 0xA5)
            return 2;
    }
    return faulted ? 0 : 3;
}

static int unaligned_load_faults_without_outputs(void)
{
    __declspec(align(16)) uint8_t block[32] = {0};
    uint64_t low = UINT64_C(0xA5A5A5A5A5A5A5A5);
    uint64_t high = UINT64_C(0x5A5A5A5A5A5A5A5A);
    int faulted = 0;
    __try {
        dvm_load128_aligned(block + 1, &low, &high);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        faulted = 1;
    }
    if (low != UINT64_C(0xA5A5A5A5A5A5A5A5) ||
            high != UINT64_C(0x5A5A5A5A5A5A5A5A))
        return 4;
    return faulted ? 0 : 5;
}

int main(void)
{
    int result = valid_roundtrip();
    if (result != 0)
        return result;
    result = unaligned_store_faults_without_write();
    return result == 0 ? unaligned_load_faults_without_outputs() : result;
}
'''.lstrip(),
        encoding="ascii",
    )
    helper = (ROOT / "stub/src/daedalus_store128.asm").as_posix()
    (source / "CMakeLists.txt").write_text(
        f"""
cmake_minimum_required(VERSION 3.20)
project(lethe_aligned128_native C ASM_MASM)
add_executable(aligned128 aligned_transfer.c "{helper}")
target_compile_options(aligned128 PRIVATE
    $<$<COMPILE_LANGUAGE:C>:/W4;/WX;/O2>)
target_link_options(aligned128 PRIVATE
    /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT
    /EXPORT:dvm_load128_aligned /EXPORT:dvm_store128_aligned)
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
    executable = build / "Release/aligned128.exe"
    executed = _run([str(executable)], executable.parent)
    assert executed.returncode == 0, executed.stdout

    image = assemble._StubImage(executable.read_bytes())
    from iced_x86 import Decoder, Mnemonic, OpKind
    for name in ("dvm_load128_aligned", "dvm_store128_aligned"):
        helper_rva = image.find_export_rva(name)
        assert helper_rva is not None
        instructions = []
        for instruction in Decoder(
            64,
            image.read_at_rva(helper_rva, 48),
            ip=image.image_base + helper_rva,
        ):
            instructions.append(instruction)
            if instruction.mnemonic == Mnemonic.RET:
                break
        memory_xmm = [
            instruction.mnemonic for instruction in instructions
            if instruction.mnemonic in (Mnemonic.MOVDQA, Mnemonic.MOVDQU)
            and any(
                instruction.op_kind(index) == OpKind.MEMORY
                for index in range(instruction.op_count)
            )
        ]
        assert memory_xmm == [Mnemonic.MOVDQA]


@pytest.mark.skipif(os.name != "nt", reason="rolling STORE128 proof is Windows-only")
def test_shuffled_rolling_store128_dispatch_and_guard_fault_are_atomic(
    tmp_path: Path,
) -> None:
    pytest.importorskip("iced_x86")
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")

    shuffle_seed = bytes.fromhex("11" * 32)
    rolling_seed = bytes(range(16))
    generated = shuffle_opcodes.generate_shuffle(shuffle_seed)
    assembler_mapping = {
        mnemonic: (
            generated["real_map"][mnemonic],
            width,
            kind,
        )
        for mnemonic, (_canonical, width, kind)
        in shuffle_opcodes.CANONICAL_OPCODES.items()
    }
    decoder_mapping = {
        wire: (mnemonic, width, kind)
        for mnemonic, (wire, width, kind) in assembler_mapping.items()
    }
    store128_wire = generated["real_map"]["store128"]
    assert store128_wire != shuffle_opcodes.CANONICAL_OPCODES["store128"][0]
    assert generated["unmap"][store128_wire] == 0x38
    assert store128_wire not in generated["decoy_wire"]
    assert store128_wire not in generated["trap_wire"]

    plain = daedalus_asm.assemble(
        """
        .code
          push_arg 0
          push_arg 1
          push_arg 2
          store128
          push_imm8 0
          halt
        """,
        opcodes=assembler_mapping,
    )
    program = daedalus_rolling.pack_rolling_blob(
        plain,
        rolling_seed,
        optable=decoder_mapping,
    )
    _seed, _data, ciphertext, leaders = daedalus_rolling.unpack_rolling_blob(
        program
    )
    assert daedalus_rolling.decode_stream(
        ciphertext,
        rolling_seed,
        leaders,
        decoder_mapping,
    ) == plain[2:]

    source = tmp_path / "source"
    build = tmp_path / "build"
    source.mkdir()
    (source / "daedalus_opcodes_shuffled.h").write_text(
        shuffle_opcodes.emit_c_header(generated),
        encoding="ascii",
    )
    shuffled_module = source / "daedalus_opcodes_shuffled.py"
    shuffled_module.write_text(
        shuffle_opcodes.emit_py_dict(generated, 0.0),
        encoding="ascii",
    )
    generated_programs = _run([
        sys.executable,
        str(ROOT / "daedalus/generate_programs.py"),
        "--shuffled-map", str(shuffled_module),
        "--programs-dir", str(ROOT / "daedalus/programs"),
        "--output", str(source / "daedalus_programs_shuffled.h"),
        "--rolling",
    ], tmp_path)
    assert generated_programs.returncode == 0, generated_programs.stdout
    (source / "rolling_store.c").write_text(
        rf'''
#include <windows.h>
#include <stdint.h>
#include "daedalus_vm.h"

static const uint8_t rolling_program[] = {{ {_c_bytes(program)} }};

static int run_store(void *destination)
{{
    const uint64_t arguments[3] = {{
        (uint64_t)(uintptr_t)destination,
        UINT64_C(0x1122334455667788),
        UINT64_C(0x99AABBCCDDEEFF00)
    }};
    return daedalus_vm_exec(
        rolling_program, (uint32_t)sizeof(rolling_program), arguments, 3);
}}

static int valid_store(void)
{{
    uint8_t output[24];
    static const uint8_t expected[16] = {{
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99
    }};
    unsigned int index;
    for (index = 0; index < (unsigned int)sizeof(output); ++index)
        output[index] = 0xA5;
    if (run_store(output + 3) != 0)
        return 1;
    for (index = 0; index < 16; ++index) {{
        if (output[index + 3] != expected[index])
            return 2;
    }}
    if (output[2] != 0xA5 || output[19] != 0xA5)
        return 3;
    return 0;
}}

static int guard_fault_is_atomic(void)
{{
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
        return 4;
    if (!VirtualProtect(
            region + info.dwPageSize, info.dwPageSize,
            PAGE_NOACCESS, &previous)) {{
        VirtualFree(region, 0, MEM_RELEASE);
        return 5;
    }}
    target = region + info.dwPageSize - 8;
    for (index = 0; index < 8; ++index)
        target[index] = 0xA5;
    __try {{
        (void)run_store(target);
    }} __except (EXCEPTION_EXECUTE_HANDLER) {{
        faulted = 1;
    }}
    for (index = 0; index < 8; ++index) {{
        if (target[index] != 0xA5) {{
            VirtualFree(region, 0, MEM_RELEASE);
            return 6;
        }}
    }}
    VirtualFree(region, 0, MEM_RELEASE);
    return faulted ? 0 : 7;
}}

int main(void)
{{
    int result = valid_store();
    return result == 0 ? guard_fault_is_atomic() : result;
}}
'''.lstrip(),
        encoding="ascii",
    )
    stub_source = ROOT / "stub/src"
    (source / "CMakeLists.txt").write_text(
        f"""
cmake_minimum_required(VERSION 3.20)
project(lethe_store128_rolling_native C ASM_MASM)
add_executable(store128_rolling
    rolling_store.c
    "{(stub_source / 'daedalus_vm.c').as_posix()}"
    "{(stub_source / 'daedalus_rolling.c').as_posix()}"
    "{(stub_source / 'daedalus_store128.asm').as_posix()}"
    "{(stub_source / 'daedalus_trampoline.asm').as_posix()}"
    "{(stub_source / 'key_scatter.c').as_posix()}"
    "{(stub_source / 'crypto.c').as_posix()}")
target_include_directories(store128_rolling PRIVATE
    "{source.as_posix()}" "{stub_source.as_posix()}")
target_compile_definitions(store128_rolling PRIVATE
    WIN32_LEAN_AND_MEAN NOMINMAX DVM_SHUFFLED DVM_ROLLING)
target_compile_options(store128_rolling PRIVATE
    $<$<COMPILE_LANGUAGE:C>:/W4;/WX;/O2>)
target_link_libraries(store128_rolling PRIVATE bcrypt)
target_link_options(store128_rolling PRIVATE
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
    executable = build / "Release/store128_rolling.exe"
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
