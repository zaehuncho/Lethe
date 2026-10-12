"""End-to-end proof for the chain-group strict-gate isolation unlock.

Target: ``orion::VirtualController::toDs4`` at RemotePlayCore.dll RVA 0x48DB0 --
the pure ``ControllerState const& -> Ds4Report`` mapping the virtual DualShock4
controller uses to translate an abstract pad state into a DS4 HID report. It is
a self-contained value transform (no internal or external calls; 11 conditional
branches for the D-pad hat decode and the analog-stick clamps), so it dual-runs
cleanly.

Why this proves THIS run's unlock: RemotePlayCore.dll is wholly un-packable
before this change -- its strict direct-control gate raises on two CRT
cold-fragment jump tables (chain groups at 0x49690 and 0x4A550) whose indexing
instruction lives in the primary fragment, poisoning the whole-image proof. The
new chain-group isolation decodes each whole contiguous chain group (resolving
the table from the in-group dispatch reference, every dword entry proven a real
in-group instruction start) and leaves it native and un-selectable, so any real
function in the DLL -- here toDs4 -- becomes packable.

Behavioural proof: load the genuine RemotePlayCore.dll, and for a battery of
inputs that exercise BOTH sides of the D-pad ``cmp/jbe`` reject branch and the
stick clamps, run the real native ``toDs4`` AND the lifted bytecode through
``daedalus_vm_exec_x64`` and assert the emitted Ds4Report bytes are identical.

Member-ABI note: ``toDs4`` returns a >8-byte struct by value from a member
function, so RCX=this (unused here), RDX=&Ds4Report (return buffer), R8=&state,
and RAX returns the buffer pointer. A tiny MASM thunk drives the native call
with exactly those registers; the VM context mirrors them.

Requires the installed app + CMake + MSVC x64. Needs a short --basetemp
(MSBuild 260-char tlog limit) and a plain shell.
"""

from __future__ import annotations

import os
import random
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("iced_x86")
pytest.importorskip("keystone")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "lifter"))
sys.path.insert(0, str(ROOT / "daedalus"))

import daedalus_asm  # noqa: E402
import pefile  # noqa: E402
import x64_lifter as lifter  # noqa: E402

VENICE = Path(r"C:\Program Files\Venice")
REMOTE_PLAY = VENICE / "RemotePlayCore.dll"
TODS4_RVA = 0x48DB0
TODS4_SIZE = 0x2C8
STATE_LEN = 64          # ControllerState reads up to +0x1A
REPORT_LEN = 16         # Ds4Report writes +0..+8

pytestmark = pytest.mark.skipif(
    os.environ.get("LETHE_RUN_INSTALLED_PRODUCT_E2E") != "1"
    or os.name != "nt"
    or not REMOTE_PLAY.is_file(),
    reason=(
        "explicit external-product evidence only: set "
        "LETHE_RUN_INSTALLED_PRODUCT_E2E=1 with the pinned Venice binaries"
    ),
)


class _Section:
    def __init__(self, name, rva, virtual_size, raw, characteristics):
        self.name = name
        self.rva = rva
        self.virtual_size = virtual_size
        self.raw = raw
        self.characteristics = characteristics


def _visual_studio_available() -> bool:
    if shutil.which("cl.exe"):
        return True
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "")) / (
        "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    if not vswhere.is_file():
        return False
    probe = subprocess.run(
        [str(vswhere), "-latest", "-products", "*", "-requires",
         "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
         "-property", "installationPath"],
        capture_output=True, text=True, check=False,
    )
    return probe.returncode == 0 and bool(probe.stdout.strip())


def _sections():
    pe = pefile.PE(str(REMOTE_PLAY))
    return [
        _Section(
            s.Name.rstrip(b"\x00").decode("latin1"),
            s.VirtualAddress, s.Misc_VirtualSize, s.get_data(), s.Characteristics,
        )
        for s in pe.sections
    ]


def _tods4_code() -> bytes:
    pe = pefile.PE(str(REMOTE_PLAY))
    for s in pe.sections:
        if s.VirtualAddress <= TODS4_RVA < s.VirtualAddress + max(
            s.Misc_VirtualSize, s.SizeOfRawData
        ):
            return s.get_data(TODS4_RVA, TODS4_SIZE)
    raise AssertionError("toDs4 RVA not found")


def _lift_real_tods4() -> bytes:
    code = _tods4_code()
    assert len(code) == TODS4_SIZE
    vasm = lifter.lift_function(
        code, base=TODS4_RVA, image_sections=_sections(),
        selected_extents=((TODS4_RVA, TODS4_SIZE),),
        source_extent_size=TODS4_SIZE,
    )
    # A pure transform: no external, direct-call, or CFG-dispatch bridges.
    assert vasm.count("n_call_ptr") == 0
    return daedalus_asm.assemble(vasm)


def _test_inputs() -> list[bytes]:
    """ControllerState buffers exercising both sides of the D-pad branch.

    Layout used by toDs4: word buttons at +0, D-pad dword at +4 (``cmp 8; jbe``
    reject path when <=8), four analog dwords at +8/+0xC/+0x10/+0x14 (clamped to
    a byte), trigger/flag bytes at +0x18/+0x19/+0x1A.
    """
    rng = random.Random(0x70D54)
    inputs: list[bytes] = []

    dpad_values = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xF, 0xFF, 0xFFFFFFFF, 0x10]
    button_words = [
        0x0000, 0x0001, 0x0002, 0x0004, 0x0008, 0x000F, 0x0010, 0x0020, 0x0040,
        0x0080, 0x0100, 0x0200, 0x0400, 0x0800, 0x1000, 0x2000, 0x4000, 0x8000,
        0xFFFF, 0xAAAA, 0x5555,
    ]
    axis_values = [0x00, 0x01, 0x7F, 0x80, 0x81, 0xFF, 0x100,
                   0xFFFFFF80, 0xFFFFFFFF, 0x40, 0xC0]
    flag_bytes = [0x00, 0x17, 0x18, 0x19, 0x20, 0xFF]

    def make(word, dpad, axes, flags, filler):
        buf = bytearray(filler)
        struct.pack_into("<H", buf, 0, word & 0xFFFF)
        struct.pack_into("<I", buf, 4, dpad & 0xFFFFFFFF)
        for i, a in enumerate(axes):
            struct.pack_into("<I", buf, 8 + 4 * i, a & 0xFFFFFFFF)
        for i, f in enumerate(flags):
            buf[0x18 + i] = f & 0xFF
        return bytes(buf)

    # Directed sweep across the branch-relevant fields.
    for dpad in dpad_values:
        for word in button_words:
            axes = [rng.choice(axis_values) for _ in range(4)]
            flags = [rng.choice(flag_bytes) for _ in range(3)]
            inputs.append(make(word, dpad, axes, flags,
                               bytes(rng.getrandbits(8) for _ in range(STATE_LEN))))
    # Axis-clamp edge coverage with the D-pad on the fall-through side.
    for a0 in axis_values:
        for a1 in axis_values:
            inputs.append(make(rng.getrandbits(16), 0xF,
                               [a0, a1, rng.choice(axis_values), rng.choice(axis_values)],
                               [rng.choice(flag_bytes) for _ in range(3)],
                               bytes(rng.getrandbits(8) for _ in range(STATE_LEN))))
    # Fully random fuzz.
    for _ in range(256):
        inputs.append(bytes(rng.getrandbits(8) for _ in range(STATE_LEN)))
    return inputs


def _c_bytes(blob: bytes) -> str:
    return ", ".join(f"0x{b:02X}" for b in blob)


def test_real_tods4_dual_run_matches_native(tmp_path: Path) -> None:
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")

    blob = _lift_real_tods4()
    inputs = _test_inputs()
    n = len(inputs)
    flat = b"".join(inputs)
    venice_literal = str(VENICE).replace("\\", "\\\\")

    thunk = """
_TEXT SEGMENT
; void* lethe_call_member(void* fn, void* thisptr, void* sret, const void* state)
;   rcx=fn  rdx=thisptr  r8=sret  r9=state
lethe_call_member PROC
    mov  r10, rcx
    mov  rcx, rdx
    mov  rdx, r8
    mov  r8,  r9
    sub  rsp, 28h
    call r10
    add  rsp, 28h
    ret
lethe_call_member ENDP
_TEXT ENDS
END
"""
    (tmp_path / "member_call.asm").write_text(thunk, encoding="utf-8")

    harness = f"""
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include "daedalus_vm.h"

/* The plain (non-rolling) VM path does not touch these, but the rolling build
   references them; stub them so the harness links. */
int crypto_sha256(const void *d, size_t n, uint8_t o[32]) {{ (void)d;(void)n;(void)o; return 1; }}
int crypto_hkdf_sha256(const uint8_t *a, size_t b, const uint8_t *c, size_t e,
                       const uint8_t *f, size_t g, uint8_t *h, size_t i)
{{ (void)a;(void)b;(void)c;(void)e;(void)f;(void)g;(void)h;(void)i; return 1; }}
int key_scatter_init(uint8_t k[32]) {{ (void)k; return 1; }}

extern void *lethe_call_member(void *fn, void *thisptr, void *sret,
                               const void *state);

static const uint8_t tods4_program[] = {{ {_c_bytes(blob)} }};
static const unsigned char INPUTS[] = {{ {_c_bytes(flat)} }};
#define N_INPUTS {n}
#define STATE_LEN {STATE_LEN}
#define REPORT_LEN {REPORT_LEN}

static int run_vm(uintptr_t base, void *sret, const void *state) {{
    DaedalusX64Context ctx;
    uint64_t stack[256];
    unsigned char thisbuf[64];
    memset(&ctx, 0, sizeof(ctx));
    memset(stack, 0, sizeof(stack));
    memset(thisbuf, 0, sizeof(thisbuf));
    ctx.gpr[DVM_X64_RCX] = (uint64_t)(uintptr_t)thisbuf;      /* this (unused) */
    ctx.gpr[DVM_X64_RDX] = (uint64_t)(uintptr_t)sret;         /* return buffer */
    ctx.gpr[DVM_X64_R8]  = (uint64_t)(uintptr_t)state;        /* &ControllerState */
    ctx.gpr[DVM_X64_RSP] = (uint64_t)(uintptr_t)&stack[160];
    ctx.rflags = UINT64_C(0x202);
    if (daedalus_vm_exec_x64(tods4_program, (uint32_t)sizeof(tods4_program),
                             &ctx, (const uint8_t *)base) != 0)
        return -1;
    /* RAX must be the return-buffer pointer the function was handed. */
    if (ctx.gpr[DVM_X64_RAX] != (uint64_t)(uintptr_t)sret)
        return -2;
    return 0;
}}

int main(void) {{
    SetDllDirectoryW(L"{venice_literal}");
    HMODULE h = LoadLibraryW(L"{venice_literal}\\\\RemotePlayCore.dll");
    if (!h) return 10;
    uintptr_t base = (uintptr_t)h;
    void *fn = (void *)(base + 0x{TODS4_RVA:X});
    unsigned char thisbuf[64];
    memset(thisbuf, 0, sizeof(thisbuf));

    for (int i = 0; i < N_INPUTS; i++) {{
        const unsigned char *state = INPUTS + (size_t)i * STATE_LEN;
        unsigned char native_out[REPORT_LEN], vm_out[REPORT_LEN];
        memset(native_out, 0, sizeof(native_out));
        memset(vm_out, 0, sizeof(vm_out));

        void *nret = lethe_call_member(fn, thisbuf, native_out, state);
        if (nret != (void *)native_out) return 20;           /* native RAX != sret */

        int rc = run_vm(base, vm_out, state);
        if (rc == -1) return 30;                             /* vm exec failed */
        if (rc == -2) return 31;                             /* vm RAX != sret */

        if (memcmp(native_out, vm_out, REPORT_LEN) != 0)
            return 100 + i;                                  /* byte mismatch */
    }}
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
project(lethe_tods4_dualrun C ASM_MASM)
add_executable(tods4_dualrun harness.c member_call.asm "{vm_source}"
    "{rolling_source}" "{store128_source}" "{frame_source}" "{trampoline_source}")
target_include_directories(tods4_dualrun PRIVATE "{vm_include}")
target_compile_definitions(tods4_dualrun PRIVATE DVM_ROLLING WIN32_LEAN_AND_MEAN NOMINMAX)
""".lstrip(),
        encoding="utf-8",
    )

    build = tmp_path / "build"
    configured = subprocess.run(
        ["cmake", "-S", str(tmp_path), "-B", str(build),
         "-G", "Visual Studio 17 2022", "-A", "x64"],
        capture_output=True, text=True, check=False,
    )
    assert configured.returncode == 0, configured.stdout + configured.stderr
    compiled = subprocess.run(
        ["cmake", "--build", str(build), "--config", "Release"],
        capture_output=True, text=True, check=False,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    ran = subprocess.run([str(build / "Release/tods4_dualrun.exe")], check=False)
    assert ran.returncode == 0, (
        f"toDs4 dual-run returned {ran.returncode} "
        f"(10=LoadLibrary, 20=native RAX!=sret, 30=vm fail, 31=vm RAX!=sret, "
        f">=100 => byte mismatch at input index rc-100 of {n})"
    )


def _file_offset(dll: Path, rva: int) -> int:
    pe = pefile.PE(str(dll), fast_load=True)
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(
            s.Misc_VirtualSize, s.SizeOfRawData
        ):
            return s.PointerToRawData + (rva - s.VirtualAddress)
    raise AssertionError("rva not found")


# Full-pipeline materialization proof (scrub) + gate. This pack SUCCEEDS only
# because the new chain-group isolation unblocks RemotePlayCore's strict gate;
# before the change orchestrator.pack_file raised on the cold-fragment jump
# tables and no RemotePlayCore function could be virtualized at all. Opt-in.
@pytest.mark.skipif(
    os.environ.get("LETHE_RUN_REAL_PACK") != "1",
    reason="set LETHE_RUN_REAL_PACK=1 to pack the real toDs4 end-to-end",
)
def test_real_tods4_materializes_and_scrubs(tmp_path: Path, monkeypatch) -> None:
    import hashlib
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")
    from packer import orchestrator, virtualize, pe_analyze
    from lifter import function_discovery

    stub = ROOT / "stub" / "build" / "Release" / "lethe_stub_x64.dll"
    if not stub.is_file():
        pytest.skip("build the CET stub first: stub/build_stub.ps1 -Clean -Config Release")

    source = tmp_path / "RemotePlayCore.dll"
    shutil.copyfile(REMOTE_PLAY, source)           # never pack the installed file
    packed = Path(
        os.environ.get("LETHE_REAL_PACK_OUT", str(tmp_path / "RemotePlayCore.packed.dll"))
    )

    discovery = function_discovery.discover_functions(
        pe_analyze.analyze_pe(str(source)), exports=()
    )
    gap_acks = tuple(
        orchestrator.VirtualizationGapAcknowledgement(
            gap.rva, gap.size, "RemotePlayCore linker/compiler executable gap"
        )
        for gap in discovery.executable_coverage_gaps
    )

    captured: dict = {}
    real_materialize = virtualize.materialize_selected_functions

    def capture(*args, **kwargs):
        result = real_materialize(*args, **kwargs)
        captured["result"] = result
        return result

    monkeypatch.setattr(virtualize, "materialize_selected_functions", capture)
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION", "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")

    progress: list[str] = []
    result = orchestrator.pack_file(
        str(source),
        orchestrator.PackOptions(
            output_path=str(packed),
            is_dll=True,
            anti_debug=False,
            stub_path=str(stub),
            virtualization_specs=(
                orchestrator.VirtualizationSpec(
                    "toDs4", TODS4_RVA, TODS4_SIZE, TODS4_SIZE),
            ),
            virtualization_gap_acknowledgements=gap_acks,
            acknowledge_unproven_indirect_targets=True,
            _allow_unverified_stub_for_tests=True,
        ),
        progress.append,
    )
    assert result.ok, f"{result.error}\n" + "\n".join(progress)
    assert packed.is_file()
    assert any("virtualized 1 selected function" in line for line in progress), progress

    function = captured["result"].manifest.functions[0]
    assert function.target_size == TODS4_SIZE
    patch = function.target_entry_patch.patch
    assert patch[0] == 0xE9
    disp, = struct.unpack("<i", patch[1:5])
    assert TODS4_RVA + 5 + disp == function.target_entry_patch.destination_rva
    assert patch[5:] == b"\xCC" * (TODS4_SIZE - 5)     # whole extent scrubbed
    off = _file_offset(source, TODS4_RVA)
    assert function.original_sha256 == hashlib.sha256(
        source.read_bytes()[off:off + TODS4_SIZE]
    ).hexdigest()
