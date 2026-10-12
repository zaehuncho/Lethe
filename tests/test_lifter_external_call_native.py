"""Native runtime differential proof for the external-call ABI bridge.

The Python reference VM refuses native ``n_*`` ops, so a call-out cannot be
verified in the pure-Python oracle. Mirroring Cut 9's internal-call strategy,
this builds the real stub VM plus the real Win64 native-call trampoline with
MSVC, runs a lifted caller that reaches an imported routine through a
RIP-relative pointer slot, and asserts the bridged result is bit-identical to a
direct native call: return value (RAX), the callee's output-parameter memory,
and the caller's preserved nonvolatile registers and RSP.

Two callees are exercised through the same bridge: a deterministic in-harness
function taking four register arguments, two stack arguments and an output
pointer (proving the full Win64 argument marshalling), and a real Win32 API
(``GetCurrentProcessId``) resolved through the slot exactly like an IAT entry.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


pytest.importorskip("iced_x86")
pytest.importorskip("keystone")

from iced_x86 import Decoder, Mnemonic  # noqa: E402
from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # noqa: E402

import sys  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lifter"))
sys.path.insert(0, str(ROOT / "daedalus"))

import daedalus_asm  # noqa: E402
import x64_lifter as lifter  # noqa: E402


_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_CODE_RVA = 0x1000
_SLOT_RVA = 0x4000
_SLOT2_RVA = 0x4008


class _Section:
    def __init__(self, name, rva, virtual_size, raw, characteristics):
        self.name = name
        self.rva = rva
        self.virtual_size = virtual_size
        self.raw = raw
        self.characteristics = characteristics


def _asm_call_to_slot(source_template: str, slot_rva: int) -> bytes:
    """Assemble a function whose single ``call qword ptr [rip+D]`` resolves to
    ``slot_rva``. RIP-relative displacements are always 4 bytes, so a first pass
    fixes every instruction position and the second only rewrites the immediate.
    """
    first, _ = _KS.asm(source_template.format(disp=0), addr=_CODE_RVA)
    first = bytes(first)
    call = next(
        ins for ins in Decoder(64, first, ip=_CODE_RVA)
        if ins.mnemonic == Mnemonic.CALL
    )
    disp = slot_rva - (call.ip + call.len)
    literal = hex(disp) if disp >= 0 else "-" + hex(-disp)
    encoded, _ = _KS.asm(source_template.format(disp=literal), addr=_CODE_RVA)
    encoded = bytes(encoded)
    call = next(
        ins for ins in Decoder(64, encoded, ip=_CODE_RVA)
        if ins.mnemonic == Mnemonic.CALL
    )
    assert call.ip_rel_memory_address == slot_rva
    return encoded


def _lift(code: bytes, slot_rva: int) -> bytes:
    sections = (
        _Section(".text", _CODE_RVA, len(code), code, 0x60000020),
        _Section(
            ".rdata", 0x4000, 0x1000, b"\x00" * 0x1000,
            lifter.IMAGE_SCN_MEM_READ,
        ),
    )
    vasm = lifter.lift_function(
        code,
        base=_CODE_RVA,
        image_sections=sections,
        selected_extents=((_CODE_RVA, len(code)),),
    )
    assert "n_call_frame" in vasm
    return daedalus_asm.assemble(vasm)


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
            str(vswhere), "-latest", "-products", "*",
            "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property", "installationPath",
        ],
        capture_output=True, text=True, check=False,
    )
    return probe.returncode == 0 and bool(probe.stdout.strip())


# Caller that forwards four register args + two stack args + an output pointer.
_MARSHAL_SOURCE = (
    "sub rsp, 0x38; "
    "mov [rsp+0x20], rsi; "     # 5th arg  (e)
    "mov [rsp+0x28], rdi; "     # 6th arg  (f)
    "mov [rsp+0x30], rbx; "     # 7th arg  (out pointer)
    "call qword ptr [rip+{disp}]; "
    "add rsp, 0x38; "
    "ret"
)

# Caller that reaches a zero-argument Win32 API through the same slot form.
_ZEROARG_SOURCE = (
    "sub rsp, 0x28; "
    "call qword ptr [rip+{disp}]; "
    "add rsp, 0x28; "
    "ret"
)


@pytest.mark.skipif(os.name != "nt", reason="the production VM is Windows-only")
def test_external_call_bridge_matches_native(tmp_path: Path) -> None:
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")

    marshal_blob = _lift(
        _asm_call_to_slot(_MARSHAL_SOURCE, _SLOT_RVA), _SLOT_RVA
    )
    zeroarg_blob = _lift(
        _asm_call_to_slot(_ZEROARG_SOURCE, _SLOT2_RVA), _SLOT2_RVA
    )

    harness = f"""
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include "daedalus_vm.h"

/* Unused native crypto opcodes: satisfy the linker without pulling crypto.c. */
int crypto_sha256(const void *data, size_t len, uint8_t out[32])
{{ (void)data; (void)len; (void)out; return 1; }}
int crypto_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len)
{{ (void)ikm; (void)ikm_len; (void)salt; (void)salt_len;
   (void)info; (void)info_len; (void)out; (void)out_len; return 1; }}
int key_scatter_init(uint8_t key[32]) {{ (void)key; return 1; }}

/* Deterministic callee: four register args + two stack args + output pointer. */
static uint64_t bridge_callee(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                              uint64_t e, uint64_t f, uint64_t *out)
{{
    *out = a + 2u * b + 3u * c + 4u * d + 5u * e + 6u * f;
    return a ^ (b << 8) ^ (c << 16) ^ (d << 24) ^ (e << 32) ^ (f << 40);
}}

static const uint8_t marshal_program[] = {{ {_c_bytes(marshal_blob)} }};
static const uint8_t zeroarg_program[] = {{ {_c_bytes(zeroarg_blob)} }};

int main(void)
{{
    const uint64_t a = 0x11, b = 0x22, c = 0x33, d = 0x44, e = 0x55, f = 0x66;
    uint64_t slot;                 /* stands in for the IAT / pointer slot */
    const uint8_t *image_base;
    DaedalusX64Context context;
    uint64_t stack[64];
    uint64_t vm_out = 0, ref_out = 0;
    uint64_t expected_ret;

    /* ---- marshalling callee ---- */
    slot = (uint64_t)(uintptr_t)&bridge_callee;
    image_base = (const uint8_t *)((uintptr_t)&slot - (uintptr_t){_SLOT_RVA});

    memset(&context, 0, sizeof(context));
    memset(stack, 0, sizeof(stack));
    context.gpr[DVM_X64_RCX] = a;
    context.gpr[DVM_X64_RDX] = b;
    context.gpr[DVM_X64_R8]  = c;
    context.gpr[DVM_X64_R9]  = d;
    context.gpr[DVM_X64_RSI] = e;
    context.gpr[DVM_X64_RDI] = f;
    context.gpr[DVM_X64_RBX] = (uint64_t)(uintptr_t)&vm_out;
    context.gpr[DVM_X64_RSP] = (uint64_t)(uintptr_t)&stack[40];
    context.rflags = UINT64_C(0x202);

    if (daedalus_vm_exec_x64(marshal_program,
            (uint32_t)sizeof(marshal_program), &context, image_base) != 0)
        return 10;

    expected_ret = bridge_callee(a, b, c, d, e, f, &ref_out);
    if (context.gpr[DVM_X64_RAX] != expected_ret) return 11;
    if (vm_out != ref_out) return 12;
    /* Nonvolatiles and RSP survive the bridged call unchanged. */
    if (context.gpr[DVM_X64_RSI] != e) return 13;
    if (context.gpr[DVM_X64_RDI] != f) return 14;
    if (context.gpr[DVM_X64_RBX] != (uint64_t)(uintptr_t)&vm_out) return 15;
    if (context.gpr[DVM_X64_RSP] != (uint64_t)(uintptr_t)&stack[40]) return 16;

    /* ---- real zero-argument Win32 API through the same slot form ---- */
    slot = (uint64_t)(uintptr_t)&GetCurrentProcessId;
    image_base = (const uint8_t *)((uintptr_t)&slot - (uintptr_t){_SLOT2_RVA});

    memset(&context, 0, sizeof(context));
    memset(stack, 0, sizeof(stack));
    context.gpr[DVM_X64_RSP] = (uint64_t)(uintptr_t)&stack[40];
    context.rflags = UINT64_C(0x202);

    if (daedalus_vm_exec_x64(zeroarg_program,
            (uint32_t)sizeof(zeroarg_program), &context, image_base) != 0)
        return 20;
    /* A DWORD return only defines EAX; compare the low 32 bits. */
    if ((uint32_t)context.gpr[DVM_X64_RAX] != GetCurrentProcessId()) return 21;
    if (context.gpr[DVM_X64_RSP] != (uint64_t)(uintptr_t)&stack[40]) return 22;

    return 0;
}}
"""
    (tmp_path / "harness.c").write_text(harness, encoding="utf-8")

    vm_source = (ROOT / "stub/src/daedalus_vm.c").as_posix()
    rolling_source = (ROOT / "stub/src/daedalus_rolling.c").as_posix()
    store128_source = (ROOT / "stub/src/daedalus_store128.asm").as_posix()
    frame_source = (ROOT / "stub/src/daedalus_call_frame.asm").as_posix()
    trampoline_source = (ROOT / "stub/src/daedalus_trampoline.asm").as_posix()
    vm_include = (ROOT / "stub/src").as_posix()
    (tmp_path / "CMakeLists.txt").write_text(
        f"""
cmake_minimum_required(VERSION 3.20)
project(lethe_external_call_native C ASM_MASM)
add_executable(external_call harness.c "{vm_source}" "{rolling_source}"
    "{store128_source}" "{frame_source}" "{trampoline_source}")
target_include_directories(external_call PRIVATE "{vm_include}")
target_compile_definitions(external_call PRIVATE DVM_ROLLING WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(external_call PRIVATE $<$<COMPILE_LANGUAGE:C>:/W4;/WX>)
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
        [str(build / "Release/external_call.exe")], check=False
    )
    assert ran.returncode == 0, f"native harness returned {ran.returncode}"
