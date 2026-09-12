"""Direct internal x64 CALL/RET differential and native runtime coverage."""
from __future__ import annotations

import os
import random
import shutil
import subprocess
from pathlib import Path

import pytest


pytest.importorskip("iced_x86")
pytest.importorskip("keystone")
pytest.importorskip("unicorn")

from daedalus import daedalus_asm  # noqa: E402
from daedalus.daedalus_ref import RefVM  # noqa: E402
from iced_x86 import Decoder, Mnemonic  # noqa: E402
from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # noqa: E402
from lifter import oracle  # noqa: E402
from lifter import x64_lifter as lifter  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_CODE_RVA = 0x2200
_RUNTIME_IMAGE_BASE = 0x0000_7FF6_4000_0000


def _asm(source: str, *, rva: int = _CODE_RVA) -> bytes:
    encoded, _ = _KS.asm(source, addr=rva)
    return bytes(encoded)


def _init(**registers: int) -> list[int]:
    values = [0] * 16
    for name, value in registers.items():
        values[lifter.GPR_NAMES.index(name)] = value
    return values


def _nested_source(body: str = "") -> str:
    return (
        "jmp entry; "
        "inner: imul rax, rdx; ret; "
        f"outer: add rax, rcx; call inner; {body} xor rax, r8; ret; "
        "entry: call outer; add rax, r9; ret"
    )


def _program(code: bytes) -> tuple[bytes, bytes]:
    blob = daedalus_asm.assemble(
        lifter.lift_function(code, base=_CODE_RVA)
    )
    data_size = int.from_bytes(blob[:2], "little")
    return blob[2:2 + data_size], blob[2 + data_size:]


def test_nested_internal_calls_match_unicorn_at_nonpreferred_image_base() -> None:
    code = _asm(_nested_source())
    initial = _init(
        rax=3,
        rcx=5,
        rdx=7,
        r8=0x55,
        r9=11,
        rsp=oracle.STACK,
    )
    analysis = lifter.analyze_internal_calls(code, _CODE_RVA)
    assert len(analysis.internal_call_rvas) == 2
    assert len(analysis.internal_return_rvas) == 2
    assert len(analysis.top_level_return_rvas) == 1
    assert analysis.max_call_depth == 2

    oracle.check_function(
        code,
        init=initial,
        code_rva=_CODE_RVA,
        runtime_image_base=_RUNTIME_IMAGE_BASE,
    )

    stack_base = oracle.STACK - 0x1000
    stack = bytearray(0x2000)
    data, program = _program(code)
    vm = RefVM(program, data, mem=stack, mem_base=stack_base)
    for index, value in enumerate(initial):
        vm.locals[index * 8:index * 8 + 8] = value.to_bytes(8, "little")
    vm.locals[lifter.IMAGE_BASE:lifter.IMAGE_BASE + 8] = (
        _RUNTIME_IMAGE_BASE.to_bytes(8, "little")
    )
    assert vm.run() == 0

    calls = {
        instruction.ip: instruction
        for instruction in Decoder(64, code, ip=_CODE_RVA)
        if instruction.mnemonic == Mnemonic.CALL
    }
    return_vas = {
        _RUNTIME_IMAGE_BASE + instruction.ip + instruction.len
        for instruction in calls.values()
    }
    observed_slots = {
        int.from_bytes(vm.mem[0x0FF0:0x0FF8], "little"),
        int.from_bytes(vm.mem[0x0FF8:0x1000], "little"),
    }
    assert observed_slots == return_vas
    assert int.from_bytes(vm.locals[32:40], "little") == oracle.STACK


def test_randomized_nested_call_bodies_match_unicorn() -> None:
    rng = random.Random(0xCA11_4080)
    operations = ("add", "sub", "xor", "and", "or")
    for _ in range(64):
        body = "; ".join(
            f"{rng.choice(operations)} rax, {rng.choice(('r10', 'r11', 'r12'))}"
            for _ in range(rng.randint(0, 5))
        )
        if body:
            body += "; "
        code = _asm(_nested_source(body))
        initial = [rng.getrandbits(64) for _ in range(16)]
        initial[lifter.GPR_NAMES.index("rsp")] = oracle.STACK
        oracle.check_function(
            code,
            init=initial,
            code_rva=_CODE_RVA,
            runtime_image_base=_RUNTIME_IMAGE_BASE,
        )


def test_early_top_level_returns_remain_distinct_from_internal_ret() -> None:
    code = _asm(
        "test rcx, rcx; jz early; call helper; ret; "
        "helper: add rax, rdx; ret; early: mov eax, 7; ret"
    )
    analysis = lifter.analyze_internal_calls(code, _CODE_RVA)
    assert len(analysis.internal_return_rvas) == 1
    assert len(analysis.top_level_return_rvas) == 2
    for rcx in (0, 1):
        oracle.check_function(
            code,
            init=_init(rax=10, rcx=rcx, rdx=5, rsp=oracle.STACK),
            code_rva=_CODE_RVA,
            runtime_image_base=_RUNTIME_IMAGE_BASE,
        )


@pytest.mark.parametrize(
    ("source", "reason"),
    (
        ("call 0x9000; ret", "outside lifted function"),
        ("call rax; ret", "indirect / non-near call"),
        ("call 0x2200; ret", "recursive internal call"),
        (
            "test rcx, rcx; jz shared; call shared; ret; shared: ret",
            "both internal and top-level",
        ),
        ("jmp entry; entry: call helper; ret; helper: nop", "fall through"),
    ),
)
def test_unproven_call_and_return_shapes_fail_closed(source: str, reason: str) -> None:
    with pytest.raises(lifter.LiftUnsupported, match=reason):
        lifter.lift_function(_asm(source), base=_CODE_RVA)


def test_return_slot_rewrite_halts_before_vm_ret() -> None:
    code = _asm(
        "jmp entry; helper: mov qword ptr [rsp], 0; ret; "
        "entry: call helper; ret"
    )
    data, program = _program(code)
    stack_base = oracle.STACK - 0x1000
    vm = RefVM(program, data, mem=bytes(0x2000), mem_base=stack_base)
    vm.locals[32:40] = oracle.STACK.to_bytes(8, "little")
    vm.locals[lifter.IMAGE_BASE:lifter.IMAGE_BASE + 8] = (
        _RUNTIME_IMAGE_BASE.to_bytes(8, "little")
    )
    assert vm.run() == 1
    assert vm.ret_stack


def test_call_depth_beyond_native_vm_return_capacity_is_rejected() -> None:
    functions = [f"f{index}: call f{index + 1}; ret" for index in range(32)]
    source = "; ".join(("jmp entry", *functions, "f32: ret", "entry: call f0; ret"))
    with pytest.raises(lifter.LiftUnsupported, match="exceeds 32 frames"):
        lifter.lift_function(_asm(source), base=_CODE_RVA)


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
            str(vswhere), "-latest", "-products", "*",
            "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property", "installationPath",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return probe.returncode == 0 and bool(probe.stdout.strip())


def _c_bytes(blob: bytes) -> str:
    return ", ".join(f"0x{byte:02X}" for byte in blob)


@pytest.mark.skipif(os.name != "nt", reason="the production VM is Windows-only")
def test_internal_calls_execute_in_native_vm_with_strict_warnings(tmp_path: Path) -> None:
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")

    code = _asm(_nested_source())
    call_returns = sorted(
        _RUNTIME_IMAGE_BASE + instruction.ip + instruction.len
        for instruction in Decoder(64, code, ip=_CODE_RVA)
        if instruction.mnemonic == Mnemonic.CALL
    )
    assert len(call_returns) == 2
    blob = daedalus_asm.assemble(lifter.lift_function(code, base=_CODE_RVA))
    tampered_code = _asm(
        "jmp entry; helper: mov qword ptr [rsp], 0; ret; "
        "entry: call helper; ret"
    )
    tampered_blob = daedalus_asm.assemble(
        lifter.lift_function(tampered_code, base=_CODE_RVA)
    )
    harness = f"""
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

static const uint8_t call_program[] = {{ {_c_bytes(blob)} }};
static const uint8_t tampered_program[] = {{ {_c_bytes(tampered_blob)} }};

static void initialize(DaedalusX64Context *context, uint64_t *stack)
{{
    memset(context, 0, sizeof(*context));
    memset(stack, 0, 64u * sizeof(*stack));
    context->gpr[DVM_X64_RAX] = 3;
    context->gpr[DVM_X64_RCX] = 5;
    context->gpr[DVM_X64_RDX] = 7;
    context->gpr[DVM_X64_R8] = UINT64_C(0x55);
    context->gpr[DVM_X64_R9] = 11;
    context->gpr[DVM_X64_RSP] = (uint64_t)(uintptr_t)&stack[32];
    context->rflags = UINT64_C(0x202);
}}

int main(void)
{{
    const uint8_t *image_base =
        (const uint8_t *)(uintptr_t)UINT64_C(0x00007FF640000000);
    DaedalusX64Context context;
    DaedalusX64Context snapshot;
    uint64_t stack[64];
    uint64_t original_rsp;

    initialize(&context, stack);
    original_rsp = context.gpr[DVM_X64_RSP];
    if (daedalus_vm_exec_x64(call_program, (uint32_t)sizeof(call_program),
            &context, image_base) != 0)
        return 10;
    if (context.gpr[DVM_X64_RAX] != UINT64_C(0x78)
            || context.gpr[DVM_X64_RSP] != original_rsp)
        return 11;
    if (stack[30] != UINT64_C(0x{call_returns[0]:016X})
            || stack[31] != UINT64_C(0x{call_returns[1]:016X}))
        return 12;

    snapshot = context;
    if (daedalus_vm_exec_x64(call_program, (uint32_t)sizeof(call_program),
            &context, NULL) != -1 || memcmp(&context, &snapshot, sizeof(context)) != 0)
        return 13;

    initialize(&context, stack);
    snapshot = context;
    if (daedalus_vm_exec_x64(
            tampered_program, (uint32_t)sizeof(tampered_program),
            &context, image_base) != 1)
        return 14;
    if (memcmp(&context, &snapshot, sizeof(context)) != 0)
        return 15;
    return 0;
}}
"""
    (tmp_path / "harness.c").write_text(harness, encoding="utf-8")
    vm_source = (ROOT / "stub/src/daedalus_vm.c").as_posix()
    rolling_source = (ROOT / "stub/src/daedalus_rolling.c").as_posix()
    vm_include = (ROOT / "stub/src").as_posix()
    (tmp_path / "CMakeLists.txt").write_text(
        f"""
cmake_minimum_required(VERSION 3.20)
project(lethe_internal_call_native C)
add_executable(internal_call harness.c "{vm_source}" "{rolling_source}")
target_include_directories(internal_call PRIVATE "{vm_include}")
target_compile_definitions(internal_call PRIVATE DVM_ROLLING WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(internal_call PRIVATE /W4 /WX)
target_link_libraries(internal_call PRIVATE bcrypt)
""".lstrip(),
        encoding="utf-8",
    )
    build = tmp_path / "build"
    configured = subprocess.run(
        [
            "cmake", "-S", str(tmp_path), "-B", str(build),
            "-G", "Visual Studio 17 2022", "-A", "x64",
        ],
        capture_output=True, text=True, check=False,
    )
    assert configured.returncode == 0, configured.stdout + configured.stderr
    compiled = subprocess.run(
        ["cmake", "--build", str(build), "--config", "Release"],
        capture_output=True, text=True, check=False,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    ran = subprocess.run(
        [str(build / "Release/internal_call.exe")], check=False
    )
    assert ran.returncode == 0, f"native harness returned {ran.returncode}"
