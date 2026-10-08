"""Real-function E2E for the discovery-wired direct-near-call -> native bridge.

Target: SecurityCore.dll RVA 0x19E14 -- a small first-party function that, in
the SHIPPED discovery pass, bailed SOLELY on ``call 0x19F4C`` (a proven pdata
function entry OUTSIDE its own extent).  With the discovery/selection wiring it
now reports liftable + selectable, because ``function_discovery`` supplies
0x19F4C as a ``native_call_target``.  0x19F4C is left native; only 0x19E14 is
virtualized.

Behavioural proof: load the genuine SecurityCore.dll and, for each case, run the
real native 0x19E14 AND the lifted bytecode through ``daedalus_vm_exec_x64`` at
the module's real base, asserting the returned bool is byte-identical.  Two
representative paths through the SAME bridged call:

* cold  -- the lazy-init flag is cleared first, so 0x19F4C runs its self-contained
  initialiser (reads an .rdata constant, writes the .data singleton, returns 1);
* warm  -- the flag is left set, so 0x19F4C returns immediately.

Requires the installed app + CMake + MSVC x64.  Needs a short --basetemp
(MSBuild 260-char tlog limit) and a plain shell.
"""

from __future__ import annotations

import hashlib
import os
import shutil
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
import x64_lifter as lifter  # noqa: E402
from lifter import function_discovery  # noqa: E402
from packer import pe_analyze  # noqa: E402

VENICE = Path(r"C:\Program Files\Venice")
SECURITY_CORE = VENICE / "SecurityCore.dll"
FN_RVA = 0x19E14
FN_SIZE = 0x15
CALLEE_RVA = 0x19F4C          # bridged native callee (proven pdata entry)
INIT_FLAG_RVA = 0x30719       # lazy-init byte flag in .data
INIT_GUARD_RVA = 0x30090      # 0 => 0x19F4C takes the self-contained init path
# Bind to the exact shipped bytes so the test fails loudly if the DLL changes.
FN_SHA256 = "9eac3534f876f8e092c1cfc25c6fcb997441dccb80f97d42154ea084b3d37a78"

pytestmark = pytest.mark.skipif(
    os.environ.get("LETHE_RUN_INSTALLED_PRODUCT_E2E") != "1"
    or os.name != "nt"
    or not SECURITY_CORE.is_file(),
    reason=(
        "explicit external-product evidence only: set "
        "LETHE_RUN_INSTALLED_PRODUCT_E2E=1 with the pinned Venice binaries"
    ),
)


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


def _lift_via_discovery() -> tuple[bytes, bytes]:
    """Lift 0x19E14 with the SAME native_call_targets discovery now supplies,
    and confirm discovery independently reports it liftable + selectable."""
    parsed = pe_analyze.analyze_pe(str(SECURITY_CORE))
    sections = function_discovery._validate_image(parsed)
    runtime = function_discovery._runtime_ranges(parsed, sections)
    code = function_discovery._read_executable(sections, FN_RVA, FN_SIZE, "target")
    assert hashlib.sha256(code).hexdigest() == FN_SHA256, "SecurityCore.dll changed"

    report = function_discovery.discover_functions(parsed, exports=())
    candidate = next(c for c in report.candidates if c.rva == FN_RVA)
    assert candidate.liftable is True
    assert candidate.direct_control_proof_status == "passed"
    assert candidate.exact_extent and candidate.unwind_flags == 0

    native_call_targets = frozenset(
        item.begin for item in runtime
        if not (FN_RVA <= item.begin < FN_RVA + FN_SIZE)
    )
    assert CALLEE_RVA in native_call_targets
    vasm = lifter.lift_function(
        code, base=FN_RVA, image_sections=sections,
        selected_extents=((FN_RVA, FN_SIZE),), source_extent_size=FN_SIZE,
        native_call_targets=native_call_targets,
    )
    assert vasm.count("n_call_ptr") == 1        # the single bridged direct call
    return code, daedalus_asm.assemble(vasm)


def _c_bytes(blob: bytes) -> str:
    return ", ".join(f"0x{b:02X}" for b in blob)


def test_real_securitycore_direct_call_dual_run_matches_native(tmp_path: Path) -> None:
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")

    _code, blob = _lift_via_discovery()
    venice_literal = str(VENICE).replace("\\", "\\\\")

    harness = f"""
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include "daedalus_vm.h"

int crypto_sha256(const void *d, size_t n, uint8_t o[32]) {{ (void)d;(void)n;(void)o; return 1; }}
int crypto_hkdf_sha256(const uint8_t *a, size_t b, const uint8_t *c, size_t e,
                       const uint8_t *f, size_t g, uint8_t *h, size_t i)
{{ (void)a;(void)b;(void)c;(void)e;(void)f;(void)g;(void)h;(void)i; return 1; }}
int key_scatter_init(uint8_t k[32]) {{ (void)k; return 1; }}

typedef int (*fn0)(void);
static const uint8_t fn_program[] = {{ {_c_bytes(blob)} }};

static void reset_cold(uintptr_t base) {{
    *(volatile unsigned char *)(base + 0x{INIT_FLAG_RVA:X}) = 0;
    *(volatile int *)(base + 0x{INIT_GUARD_RVA:X}) = 0;
}}

static int run_vm(uintptr_t base) {{
    DaedalusX64Context ctx;
    uint64_t stack[256];
    memset(&ctx, 0, sizeof(ctx));
    memset(stack, 0, sizeof(stack));
    ctx.gpr[DVM_X64_RSP] = (uint64_t)(uintptr_t)&stack[160];
    ctx.rflags = UINT64_C(0x202);
    if (daedalus_vm_exec_x64(fn_program, (uint32_t)sizeof(fn_program), &ctx,
                             (const uint8_t *)base) != 0)
        return -1;
    return (int)(ctx.gpr[DVM_X64_RAX] & 1);
}}

int main(void) {{
    SetDllDirectoryW(L"{venice_literal}");
    HMODULE h = LoadLibraryW(L"{venice_literal}\\\\SecurityCore.dll");
    if (!h) return 10;
    uintptr_t base = (uintptr_t)h;
    fn0 f = (fn0)(base + 0x{FN_RVA:X});

    /* cold path through the bridge: reset before EACH engine. */
    reset_cold(base);
    int n_cold = f() & 1;
    reset_cold(base);
    int v_cold = run_vm(base);
    if (v_cold < 0) return 20;
    if (n_cold != v_cold) return 21;
    if (n_cold != 1) return 22;

    /* warm path through the bridge: flag already set by the cold native call. */
    int n_warm = f() & 1;
    int v_warm = run_vm(base);
    if (v_warm < 0) return 30;
    if (n_warm != v_warm) return 31;
    if (n_warm != 1) return 32;
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
project(lethe_sc_dualrun C ASM_MASM)
add_executable(sc_dualrun harness.c "{vm_source}" "{rolling_source}"
    "{store128_source}" "{trampoline_source}")
target_include_directories(sc_dualrun PRIVATE "{vm_include}")
target_compile_definitions(sc_dualrun PRIVATE DVM_ROLLING WIN32_LEAN_AND_MEAN NOMINMAX)
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
    ran = subprocess.run([str(build / "Release/sc_dualrun.exe")], check=False)
    assert ran.returncode == 0, (
        f"SecurityCore 0x19E14 dual-run returned {ran.returncode} "
        f"(2X=cold, 3X=warm; last digit 0=vm-fail, 1=native/vm mismatch, "
        f"2=unexpected result; 10=LoadLibrary)"
    )
