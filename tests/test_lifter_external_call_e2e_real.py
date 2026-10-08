"""End-to-end proof of the external-call bridge on a REAL first-party function.

Cut 16's synthetic-fixture tests prove the bridge in isolation. This proves it on
an actual installed first-party DLL.

Target: ``orion::AppConfig::tr(QString* ret, const char* s, const char* c, int n)``
at RVA 0x1800 in OrionCommon.dll -- a real exported translation wrapper that
marshals four register arguments plus one outgoing stack argument and reaches
``QMetaObject::tr`` through a RIP-relative IAT slot, returning a QString. It is
exported, reached by direct calls, passes the whole-image direct-control gate,
and (per Cut 16 discovery) is liftable ONLY because of the external-call bridge.

The behavioral proof loads the genuine OrionCommon.dll into the test process,
calls the real native ``tr``, then runs the lifted bytecode of the SAME function
through ``daedalus_vm_exec_x64`` with the module's real load base -- so the bridge
resolves and calls the module's live ``QMetaObject::tr`` IAT slot -- and asserts
the returned QString is byte-identical to native for several inputs. This is the
Cut 16 dual-run applied to a real function and a real Qt API; it is the guard for
the arity/volatile caveats since it exercises the function's real call path.

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
ORION_COMMON = VENICE / "OrionCommon.dll"
TR_RVA = 0x1800
TR_SIZE = 45

pytestmark = pytest.mark.skipif(
    os.environ.get("LETHE_RUN_INSTALLED_PRODUCT_E2E") != "1"
    or os.name != "nt"
    or not ORION_COMMON.is_file(),
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


def _lift_real_tr() -> bytes:
    pe = pefile.PE(str(ORION_COMMON))
    sections = [
        _Section(
            s.Name.rstrip(b"\x00").decode("latin1"),
            s.VirtualAddress, s.Misc_VirtualSize, s.get_data(), s.Characteristics,
        )
        for s in pe.sections
    ]
    code = None
    for s in pe.sections:
        if s.VirtualAddress <= TR_RVA < s.VirtualAddress + max(
            s.Misc_VirtualSize, s.SizeOfRawData
        ):
            code = s.get_data(TR_RVA, TR_SIZE)
            break
    assert code is not None and len(code) == TR_SIZE
    vasm = lifter.lift_function(
        code, base=TR_RVA, image_sections=sections,
        selected_extents=((TR_RVA, TR_SIZE),),
    )
    assert "n_call_ptr" in vasm, "the real function must use the external-call bridge"
    return daedalus_asm.assemble(vasm)


def _c_bytes(blob: bytes) -> str:
    return ", ".join(f"0x{b:02X}" for b in blob)


@pytest.mark.skipif(True is False, reason="")
def test_real_function_bridge_matches_native(tmp_path: Path) -> None:
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")

    blob = _lift_real_tr()
    dll_copy = tmp_path / "OrionCommon.dll"
    shutil.copyfile(ORION_COMMON, dll_copy)
    dll_literal = str(dll_copy).replace("\\", "\\\\")
    venice_literal = str(VENICE).replace("\\", "\\\\")

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

/* Qt6 QString == QArrayDataPointer<char16_t> {{ Data* d; char16_t* ptr; qsizetype size; }} */
typedef struct {{ void *d; unsigned short *ptr; long long size; }} QStr;
typedef void *(*tr_fn)(void *ret, const char *s, const char *c, int n);

static const uint8_t tr_program[] = {{ {_c_bytes(blob)} }};

static int run_case(uintptr_t base, tr_fn native_tr, const char *s)
{{
    QStr qn; QStr qv;
    memset(&qn, 0, sizeof(qn)); memset(&qv, 0, sizeof(qv));

    /* native */
    native_tr(&qn, s, NULL, -1);

    /* virtualized: run the lifted bytecode of the SAME function */
    DaedalusX64Context ctx;
    uint64_t stack[64];
    memset(&ctx, 0, sizeof(ctx));
    memset(stack, 0, sizeof(stack));
    ctx.gpr[DVM_X64_RCX] = (uint64_t)(uintptr_t)&qv;   /* hidden QString return */
    ctx.gpr[DVM_X64_RDX] = (uint64_t)(uintptr_t)s;     /* sourceText */
    ctx.gpr[DVM_X64_R8]  = 0;                          /* disambiguation = NULL */
    ctx.gpr[DVM_X64_R9]  = (uint64_t)(int64_t)-1;      /* n = -1 */
    ctx.gpr[DVM_X64_RSP] = (uint64_t)(uintptr_t)&stack[40];
    ctx.rflags = UINT64_C(0x202);
    if (daedalus_vm_exec_x64(tr_program, (uint32_t)sizeof(tr_program), &ctx,
                             (const uint8_t *)base) != 0)
        return 100;
    if (ctx.gpr[DVM_X64_RAX] != (uint64_t)(uintptr_t)&qv)
        return 101;                                    /* returns the hidden ptr */

    if (qn.size < 0 || qn.size > 4096) return 102;
    if (qn.size != qv.size) return 103;
    if (qn.size > 0 && (qn.ptr == NULL || qv.ptr == NULL)) return 104;
    if (qn.size > 0 && memcmp(qn.ptr, qv.ptr, (size_t)qn.size * 2u) != 0)
        return 105;
    return 0;
}}

int main(void)
{{
    SetDllDirectoryW(L"{venice_literal}");
    HMODULE h = LoadLibraryW(L"{dll_literal}");
    if (!h) return 10;
    uintptr_t base = (uintptr_t)h;
    tr_fn native_tr = (tr_fn)(base + 0x{TR_RVA:X});

    static const char *cases[] = {{
        "Meter", "", "License expired", "0123456789ABCDEF", "\\xC3\\xA9tat",
    }};
    for (int i = 0; i < 5; i++) {{
        int rc = run_case(base, native_tr, cases[i]);
        if (rc) return 20 + i * 10 + rc;
    }}
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
project(lethe_real_bridge C ASM_MASM)
add_executable(real_bridge harness.c "{vm_source}" "{rolling_source}"
    "{store128_source}" "{trampoline_source}")
target_include_directories(real_bridge PRIVATE "{vm_include}")
target_compile_definitions(real_bridge PRIVATE DVM_ROLLING WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(real_bridge PRIVATE $<$<COMPILE_LANGUAGE:C>:/W4;/WX>)
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
    ran = subprocess.run([str(build / "Release/real_bridge.exe")], check=False)
    assert ran.returncode == 0, (
        f"real-function dual-run returned {ran.returncode} "
        f"(2X=case X failed; last digit: 0 ok,1 vm-fail,2 bad-size,3 size-mismatch,"
        f"4 null-ptr,5 content-mismatch)"
    )


# Full-pipeline materialization proof (STEP 2 + scrub). Gated behind an explicit
# opt-in because it drives the experimental selective-virtualization packer with
# a freshly built (test-only, unverified) stub, mirroring the accepted pattern in
# tests/test_native_virtualization_runtime.py. Set LETHE_RUN_REAL_PACK=1 to run.
@pytest.mark.skipif(
    os.environ.get("LETHE_RUN_REAL_PACK") != "1",
    reason="set LETHE_RUN_REAL_PACK=1 to pack a real function end-to-end",
)
def test_real_function_materializes_and_scrubs(tmp_path: Path, monkeypatch) -> None:
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")
    from packer import orchestrator, virtualize, pe_analyze
    from lifter import function_discovery

    stub = ROOT / "stub" / "build" / "Release" / "lethe_stub_x64.dll"
    if not stub.is_file():
        pytest.skip("build the CET stub first: stub/build_stub.ps1 -Clean -Config Release")

    source = tmp_path / "OrionCommon.dll"
    shutil.copyfile(ORION_COMMON, source)          # never pack the installed file
    # Optional stable output (for the manual app-launch check); default ephemeral.
    packed = Path(
        os.environ.get("LETHE_REAL_PACK_OUT", str(tmp_path / "OrionCommon.packed.dll"))
    )

    # Every executable byte must be inside a runtime function or an acknowledged
    # gap. Enumerate the DLL's linker/compiler padding + data-in-code gaps and
    # acknowledge each (this asserts no gap holds an entry into our selected
    # function; the direct-control analysis independently proves no direct edge).
    discovery = function_discovery.discover_functions(
        pe_analyze.analyze_pe(str(source)), exports=()
    )
    gap_acks = tuple(
        orchestrator.VirtualizationGapAcknowledgement(
            gap.rva, gap.size, "OrionCommon linker/compiler executable gap"
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
                orchestrator.VirtualizationSpec("AppConfig_tr", TR_RVA, TR_SIZE, TR_SIZE),
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

    # Scrub proof on the pre-encryption materialized image: the whole selected
    # extent becomes an E9 rel32 jump to the generated thunk, then INT3 tombstones.
    function = captured["result"].manifest.functions[0]
    assert function.target_size == TR_SIZE
    patch = function.target_entry_patch.patch
    assert patch[0] == 0xE9
    disp, = struct.unpack("<i", patch[1:5])
    assert TR_RVA + 5 + disp == function.target_entry_patch.destination_rva
    assert patch[5:] == b"\xCC" * (TR_SIZE - 5)
    off = _file_offset(source, TR_RVA)
    assert function.original_sha256 == hashlib.sha256(
        source.read_bytes()[off:off + TR_SIZE]      # exact source extent
    ).hexdigest()


def _file_offset(dll: Path, rva: int) -> int:
    pe = pefile.PE(str(dll), fast_load=True)
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(
            s.Misc_VirtualSize, s.SizeOfRawData
        ):
            return s.PointerToRawData + (rva - s.VirtualAddress)
    raise AssertionError("rva not found")
