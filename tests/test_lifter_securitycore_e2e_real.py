"""Crown-jewel end-to-end proof: virtualize a REAL SecurityCore security function.

The jump-table / data-in-code gate fix (lifter/jump_table.py) stops a compiler
switch table from poisoning SecurityCore.dll's whole-image direct-control gate,
so its first-party functions become selectable. This proves the payoff on the
security logic that matters most.

Target: ``bool orion::LeaseGate::fireAllowed() const`` at RVA 0x2710 -- the
lease-gate admission check (one of the task's named crown-jewel candidates). It
is a first-party non-handler function that reaches four Qt6Core clock imports
(``QDateTime::currentSecsSinceEpoch``, ``QElapsedTimer::isValid/start/elapsed``)
through RIP-relative IAT slots, so it is liftable ONLY via the external-call
bridge (Cut 16) AND only now that the jump-table gate no longer rejects the
whole image.

Behavioral proof (the real prize): load the genuine SecurityCore.dll, call the
real native ``fireAllowed`` on several hand-built LeaseGate states, then run the
lifted bytecode of the SAME function through ``daedalus_vm_exec_x64`` with the
module's real load base -- so the bridge resolves and calls the module's live Qt
IAT slots -- and assert the returned bool is identical to native. The states are
chosen so the result is clock-independent (the admission decision is decided by
``this`` fields, or the clock values are compared against saturated thresholds),
so the dual-run is deterministic even though wall/elapsed clocks advance between
the two calls.

Requires the installed app + CMake + MSVC x64; skips otherwise. Needs a short
--basetemp (MSBuild 260-char tlog limit) and a plain shell (not a VS dev shell).
"""

from __future__ import annotations

import hashlib
import os
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
SECURITY_CORE = VENICE / "SecurityCore.dll"
FA_RVA = 0x2710
FA_SIZE = 0x8A

pytestmark = pytest.mark.skipif(
    os.environ.get("LETHE_RUN_INSTALLED_PRODUCT_E2E") != "1"
    or os.name != "nt"
    or not SECURITY_CORE.is_file(),
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
    pe = pefile.PE(str(SECURITY_CORE))
    return [
        _Section(
            s.Name.rstrip(b"\x00").decode("latin1"),
            s.VirtualAddress, s.Misc_VirtualSize, s.get_data(), s.Characteristics,
        )
        for s in pe.sections
    ]


def _fa_code() -> bytes:
    pe = pefile.PE(str(SECURITY_CORE))
    for s in pe.sections:
        if s.VirtualAddress <= FA_RVA < s.VirtualAddress + max(
            s.Misc_VirtualSize, s.SizeOfRawData
        ):
            return s.get_data(FA_RVA, FA_SIZE)
    raise AssertionError("fireAllowed RVA not found")


def _lift_real_fire_allowed() -> bytes:
    code = _fa_code()
    assert len(code) == FA_SIZE
    vasm = lifter.lift_function(
        code, base=FA_RVA, image_sections=_sections(),
        selected_extents=((FA_RVA, FA_SIZE),),
    )
    assert "n_call_ptr" in vasm, "the real function must use the external-call bridge"
    return daedalus_asm.assemble(vasm)


def _c_bytes(blob: bytes) -> str:
    return ", ".join(f"0x{b:02X}" for b in blob)


def test_real_security_function_bridge_matches_native(tmp_path: Path) -> None:
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")

    blob = _lift_real_fire_allowed()
    dll_copy = tmp_path / "SecurityCore.dll"
    shutil.copyfile(SECURITY_CORE, dll_copy)
    dll_literal = str(dll_copy).replace("\\", "\\\\")
    venice_literal = str(VENICE).replace("\\", "\\\\")

    # LeaseGate layout used by fireAllowed (offsets read by the disassembly):
    #   [0]   u8   -- 0 => admit unconditionally (return true)
    #   [1]   u8   -- 0 => reject (return false)
    #   [8]   i64  -- wall-clock (secs-since-epoch) expiry bound
    #   [16]  i64  -- elapsed-timer origin (<0 => reject)
    #   [24]  i64  -- max elapsed window
    # Each case below is decided by these fields alone (clock reads are unused
    # or compared against INT64_MAX), so native and lifted must agree exactly.
    harness = f"""
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include "daedalus_vm.h"

/* Unused native crypto opcodes: satisfy the linker without pulling crypto.c. */
int crypto_sha256(const void *d, size_t n, uint8_t o[32]) {{ (void)d;(void)n;(void)o; return 1; }}
int crypto_hkdf_sha256(const uint8_t *a, size_t b, const uint8_t *c, size_t e,
                       const uint8_t *f, size_t g, uint8_t *h, size_t i)
{{ (void)a;(void)b;(void)c;(void)e;(void)f;(void)g;(void)h;(void)i; return 1; }}
int key_scatter_init(uint8_t k[32]) {{ (void)k; return 1; }}

typedef int (*fa_fn)(void *self);   /* bool fireAllowed() const, in AL */

static const uint8_t fa_program[] = {{ {_c_bytes(blob)} }};

static void set_state(uint8_t gate[64], uint8_t b0, uint8_t b1,
                      int64_t expiry, int64_t origin, int64_t window)
{{
    memset(gate, 0, 64);
    gate[0] = b0;
    gate[1] = b1;
    memcpy(gate + 8, &expiry, 8);
    memcpy(gate + 16, &origin, 8);
    memcpy(gate + 24, &window, 8);
}}

static int run_case(uintptr_t base, fa_fn native, const uint8_t gate_template[64])
{{
    uint8_t gate_n[64], gate_v[64];
    memcpy(gate_n, gate_template, 64);
    memcpy(gate_v, gate_template, 64);

    int native_result = native(gate_n) & 1;

    DaedalusX64Context ctx;
    uint64_t stack[64];
    memset(&ctx, 0, sizeof(ctx));
    memset(stack, 0, sizeof(stack));
    ctx.gpr[DVM_X64_RCX] = (uint64_t)(uintptr_t)gate_v;   /* this */
    ctx.gpr[DVM_X64_RSP] = (uint64_t)(uintptr_t)&stack[40];
    ctx.rflags = UINT64_C(0x202);
    if (daedalus_vm_exec_x64(fa_program, (uint32_t)sizeof(fa_program), &ctx,
                             (const uint8_t *)base) != 0)
        return 1;                                          /* vm failure */
    int vm_result = (int)(ctx.gpr[DVM_X64_RAX] & 1);
    if (native_result != vm_result)
        return 2;                                          /* mismatch */
    return 0;
}}

int main(void)
{{
    SetDllDirectoryW(L"{venice_literal}");
    HMODULE h = LoadLibraryW(L"{dll_literal}");
    if (!h) return 10;
    uintptr_t base = (uintptr_t)h;
    fa_fn native = (fa_fn)(base + 0x{FA_RVA:X});

    uint8_t gate[64];
    const int64_t MAXI = INT64_MAX;

    /* A: b0==0 => admit unconditionally (true), clock unused. */
    set_state(gate, 0, 0, 0, 0, 0);
    if (run_case(base, native, gate)) return 20 + run_case(base, native, gate);

    /* B: b0!=0, b1==0 => reject (false), clock unused. */
    set_state(gate, 1, 0, 0, 0, 0);
    if (run_case(base, native, gate)) return 30 + run_case(base, native, gate);

    /* C: origin<0 => reject (false), clock unused. */
    set_state(gate, 1, 1, MAXI, -1, MAXI);
    if (run_case(base, native, gate)) return 40 + run_case(base, native, gate);

    /* D: saturated thresholds => admit (true); clocks << INT64_MAX so stable. */
    set_state(gate, 1, 1, MAXI, 0, MAXI);
    if (run_case(base, native, gate)) return 50 + run_case(base, native, gate);

    /* E: window==0, origin==0 => elapsed>0 exceeds window => reject (false). */
    set_state(gate, 1, 1, MAXI, 0, 0);
    if (run_case(base, native, gate)) return 60 + run_case(base, native, gate);

    return 0;
}}
"""
    (tmp_path / "harness.c").write_text(harness, encoding="utf-8")

    vm_source = (ROOT / "stub/src/daedalus_vm.c").as_posix()
    rolling_source = (ROOT / "stub/src/daedalus_rolling.c").as_posix()
    store128_source = (ROOT / "stub/src/daedalus_store128.asm").as_posix()
    trampoline_source = (ROOT / "stub/src/daedalus_trampoline.asm").as_posix()
    vm_include = (ROOT / "stub/src").as_posix()
    (tmp_path / "CMakeLists.txt").write_text(
        f"""
cmake_minimum_required(VERSION 3.20)
project(lethe_securitycore_bridge C ASM_MASM)
add_executable(sc_bridge harness.c "{vm_source}" "{rolling_source}"
    "{store128_source}" "{trampoline_source}")
target_include_directories(sc_bridge PRIVATE "{vm_include}")
target_compile_definitions(sc_bridge PRIVATE DVM_ROLLING WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(sc_bridge PRIVATE $<$<COMPILE_LANGUAGE:C>:/W4;/WX>)
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
    ran = subprocess.run([str(build / "Release/sc_bridge.exe")], check=False)
    assert ran.returncode == 0, (
        f"crown-jewel dual-run returned {ran.returncode} "
        f"(2X..6X = case A..E; last digit 1=vm-fail, 2=native/vm mismatch, "
        f"10=LoadLibrary failed)"
    )


# Full-pipeline materialization proof (scrub) + gate. Opt-in like the bridge
# test: drives the experimental selective-virtualization packer with a freshly
# built (test-only, unverified) stub. Set LETHE_RUN_REAL_PACK=1 to run.
@pytest.mark.skipif(
    os.environ.get("LETHE_RUN_REAL_PACK") != "1",
    reason="set LETHE_RUN_REAL_PACK=1 to pack the real security function end-to-end",
)
def test_real_security_function_materializes_and_scrubs(tmp_path: Path, monkeypatch) -> None:
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")
    from packer import orchestrator, virtualize, pe_analyze
    from lifter import function_discovery

    stub = ROOT / "stub" / "build" / "Release" / "lethe_stub_x64.dll"
    if not stub.is_file():
        pytest.skip("build the CET stub first: stub/build_stub.ps1 -Clean -Config Release")

    source = tmp_path / "SecurityCore.dll"
    shutil.copyfile(SECURITY_CORE, source)         # never pack the installed file
    packed = Path(
        os.environ.get("LETHE_REAL_PACK_OUT", str(tmp_path / "SecurityCore.packed.dll"))
    )

    # exports=() sidesteps this DLL's ICF-folded aliased exports (a separate,
    # unrelated issue) while still enumerating the pdata gaps to acknowledge.
    discovery = function_discovery.discover_functions(
        pe_analyze.analyze_pe(str(source)), exports=()
    )
    gap_acks = tuple(
        orchestrator.VirtualizationGapAcknowledgement(
            gap.rva, gap.size, "SecurityCore linker/compiler executable gap"
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
                    "LeaseGate_fireAllowed", FA_RVA, FA_SIZE, FA_SIZE),
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
    assert function.target_size == FA_SIZE
    patch = function.target_entry_patch.patch
    assert patch[0] == 0xE9
    disp, = struct.unpack("<i", patch[1:5])
    assert FA_RVA + 5 + disp == function.target_entry_patch.destination_rva
    assert patch[5:] == b"\xCC" * (FA_SIZE - 5)
    off = _file_offset(source, FA_RVA)
    assert function.original_sha256 == hashlib.sha256(
        source.read_bytes()[off:off + FA_SIZE]
    ).hexdigest()


def _file_offset(dll: Path, rva: int) -> int:
    pe = pefile.PE(str(dll), fast_load=True)
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(
            s.Misc_VirtualSize, s.SizeOfRawData
        ):
            return s.PointerToRawData + (rva - s.VirtualAddress)
    raise AssertionError("rva not found")
