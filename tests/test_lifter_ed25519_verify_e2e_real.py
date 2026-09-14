"""Crown-jewel end-to-end proof: virtualize the REAL Ed25519 signature verifier.

Target: ``orion::...::ed25519Verify`` at SecurityCore.dll RVA 0x1E40 -- the
Ed25519 signature-verification dispatcher shared by ``verifyLeaseSignature`` and
``verifyReleaseIntegrity``. Unlike the LeaseGate crown jewel, this function is
liftable ONLY with three capabilities proven here:

* a **multi-range (multi-fragment) extent** -- the linker split the function
  into a primary pdata record ``[0x1E40,0x1EB7)`` plus four contiguous
  ``CHAININFO`` fragments ending at 0x1F7D, including the cold return-false
  epilogue at 0x1F69 that the length-check ``jne`` targets;
* a **direct near-call bridge** for ``call 0x1780`` (a magic-static getter left
  native); and
* a **GuardCF-dispatched indirect-call bridge** for the six
  ``call qword ptr [__guard_dispatch_icall_fptr]`` sites that dispatch through
  RAX into the OpenSSL EVP primitives.

Behavioural proof (the real prize): load the genuine SecurityCore.dll, populate
its OpenSSL EVP dispatch vtable (the app normally resolves it from
``libcrypto-3-x64.dll`` via QCoreApplication::applicationDirPath, which a bare
LoadLibrary lacks), then for each input run the real native ``ed25519Verify``
AND the lifted bytecode through ``daedalus_vm_exec_x64`` at the module's real
base and assert the returned bool is byte-identical across BOTH outcomes:

* a VALID RFC 8032 Ed25519 signature  -> true  (full crypto path + normal epilogue)
* a tampered same-length signature     -> false (crypto reject, normal epilogue)
* a wrong-length public key            -> false (out-of-extent cold epilogue)

Requires the installed app + CMake + MSVC x64 + the ``cryptography`` package.
Needs a short --basetemp (MSBuild 260-char tlog limit) and a plain shell.
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
EV_RVA = 0x1E40
EV_END = 0x1F7D
EV_SIZE = EV_END - EV_RVA          # 0x13D -- primary + 4 chained fragments
HELPER_RVA = 0x1780                # magic-static getter (direct near call)
GUARD_DISPATCH_RVA = 0x1EBA8       # GuardCFDispatchFunctionPointer slot
SINGLETON_RVA = 0x30D40            # EVP dispatch object
GUARD_EPOCH_RVA = 0x30D9C          # magic-static init guard

pytestmark = pytest.mark.skipif(
    os.name != "nt" or not SECURITY_CORE.is_file(),
    reason="requires the installed Venice SecurityCore.dll on Windows",
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


def _ev_code() -> bytes:
    pe = pefile.PE(str(SECURITY_CORE))
    for s in pe.sections:
        if s.VirtualAddress <= EV_RVA < s.VirtualAddress + max(
            s.Misc_VirtualSize, s.SizeOfRawData
        ):
            return s.get_data(EV_RVA, EV_SIZE)
    raise AssertionError("ed25519Verify RVA not found")


def _lift_real_ed25519_verify() -> bytes:
    code = _ev_code()
    assert len(code) == EV_SIZE
    vasm = lifter.lift_function(
        code, base=EV_RVA, image_sections=_sections(),
        selected_extents=((EV_RVA, EV_SIZE),),
        native_call_targets=frozenset({HELPER_RVA}),
        guard_cf_dispatch_rva=GUARD_DISPATCH_RVA,
    )
    # 1 direct-call bridge + 3 constData imports + 6 GuardCF dispatch calls.
    assert vasm.count("n_call_ptr") == 10, vasm.count("n_call_ptr")
    return daedalus_asm.assemble(vasm)


def _c_bytes(blob: bytes) -> str:
    return ", ".join(f"0x{b:02X}" for b in blob)


def _ed25519_vector():
    ed = pytest.importorskip(
        "cryptography.hazmat.primitives.asymmetric.ed25519"
    )
    serialization = pytest.importorskip(
        "cryptography.hazmat.primitives.serialization"
    )
    sk = ed.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    msg = b"lethe-ed25519-dualrun-vector"
    sig = sk.sign(msg)
    assert len(pub) == 32 and len(sig) == 64
    return pub, msg, sig


def test_real_ed25519_verify_dual_run_matches_native(tmp_path: Path) -> None:
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")

    blob = _lift_real_ed25519_verify()
    pub, msg, sig = _ed25519_vector()
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

typedef int (*verify_fn)(const void *, const void *, const void *);
struct QBA {{ void *d; const char *ptr; long long size; }};
static const uint8_t ev_program[] = {{ {_c_bytes(blob)} }};
static const unsigned char EV_PUB[] = {{ {_c_bytes(pub)} }};
static const unsigned char EV_MSG[] = {{ {_c_bytes(msg)} }};
static const unsigned char EV_SIG[] = {{ {_c_bytes(sig)} }};

/* EVP dispatch vtable order recovered from the SecurityCore constructor. */
static const char *SYMS[] = {{
    "EVP_PKEY_new_raw_public_key", "EVP_PKEY_new_raw_private_key",
    "EVP_PKEY_get_raw_public_key", "EVP_MD_CTX_new", "EVP_MD_CTX_free",
    "EVP_PKEY_free", "EVP_DigestVerifyInit", "EVP_DigestVerify",
    "EVP_DigestSignInit", "EVP_DigestSign",
}};

static void mk(struct QBA *q, const unsigned char *b, long long n) {{
    q->d = 0; q->ptr = (const char *)b; q->size = n;
}}

static int populate(uintptr_t base) {{
    HMODULE crypto = LoadLibraryW(L"{venice_literal}\\\\libcrypto-3-x64.dll");
    if (!crypto) return 0;
    unsigned char *obj = (unsigned char *)(base + 0x{SINGLETON_RVA:X});
    void **slot = (void **)(obj + 8);
    for (int i = 0; i < 10; i++) {{
        FARPROC pfn = GetProcAddress(crypto, SYMS[i]);
        if (!pfn) return 0;
        slot[i] = (void *)pfn;
    }}
    *(volatile int *)(base + 0x{GUARD_EPOCH_RVA:X}) = (int)0x80000000;
    obj[0] = 1;
    return 1;
}}

static int run_vm(uintptr_t base, const struct QBA *p, const struct QBA *m,
                  const struct QBA *s) {{
    DaedalusX64Context ctx;
    uint64_t stack[256];
    memset(&ctx, 0, sizeof(ctx));
    memset(stack, 0, sizeof(stack));
    ctx.gpr[DVM_X64_RCX] = (uint64_t)(uintptr_t)p;
    ctx.gpr[DVM_X64_RDX] = (uint64_t)(uintptr_t)m;
    ctx.gpr[DVM_X64_R8]  = (uint64_t)(uintptr_t)s;
    ctx.gpr[DVM_X64_RSP] = (uint64_t)(uintptr_t)&stack[160];
    ctx.rflags = UINT64_C(0x202);
    if (daedalus_vm_exec_x64(ev_program, (uint32_t)sizeof(ev_program), &ctx,
                             (const uint8_t *)base) != 0)
        return -1;
    return (int)(ctx.gpr[DVM_X64_RAX] & 1);
}}

static int run_case(uintptr_t base, verify_fn f, const struct QBA *p,
                    const struct QBA *m, const struct QBA *s) {{
    int n = f(p, m, s) & 1;
    int v = run_vm(base, p, m, s);
    if (v < 0) return 1;      /* vm failure */
    if (n != v) return 2;     /* native/vm mismatch */
    return n ? 4 : 0;         /* encode the (agreed) native result in bit 2 */
}}

int main(void) {{
    SetDllDirectoryW(L"{venice_literal}");
    HMODULE h = LoadLibraryW(L"{venice_literal}\\\\SecurityCore.dll");
    if (!h) return 10;
    uintptr_t base = (uintptr_t)h;
    if (!populate(base)) return 11;
    verify_fn f = (verify_fn)(base + 0x{EV_RVA:X});

    struct QBA pub, msg, sig;
    mk(&pub, EV_PUB, sizeof EV_PUB);
    mk(&msg, EV_MSG, sizeof EV_MSG);
    mk(&sig, EV_SIG, sizeof EV_SIG);
    unsigned char s2[64]; memcpy(s2, EV_SIG, 64); s2[0] ^= 1;
    struct QBA sig2; mk(&sig2, s2, 64);
    struct QBA pub0; mk(&pub0, EV_PUB, 0);

    int rc;
    /* valid: both must agree AND be true (bit 2 set). */
    rc = run_case(base, f, &pub, &msg, &sig);
    if (rc != 4) return 20 + rc;
    /* tampered same-length signature: both must agree AND be false. */
    rc = run_case(base, f, &pub, &msg, &sig2);
    if (rc != 0) return 30 + rc;
    /* wrong-length pubkey: both must agree AND be false (cold epilogue). */
    rc = run_case(base, f, &pub0, &msg, &sig);
    if (rc != 0) return 40 + rc;
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
project(lethe_ed25519_dualrun C ASM_MASM)
add_executable(ev_dualrun harness.c "{vm_source}" "{rolling_source}"
    "{store128_source}" "{trampoline_source}")
target_include_directories(ev_dualrun PRIVATE "{vm_include}")
target_compile_definitions(ev_dualrun PRIVATE DVM_ROLLING WIN32_LEAN_AND_MEAN NOMINMAX)
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
    ran = subprocess.run([str(build / "Release/ev_dualrun.exe")], check=False)
    assert ran.returncode == 0, (
        f"ed25519Verify dual-run returned {ran.returncode} "
        f"(2X=valid, 3X=tampered, 4X=wronglen; last digit 1=vm-fail, "
        f"2=native/vm mismatch, 4=unexpected-true; 10=LoadLibrary, 11=populate)"
    )


# Full-pipeline materialization proof (scrub) + gate. Opt-in like the LeaseGate
# pack test: drives the experimental selective-virtualization packer with a
# freshly built (test-only, unverified) stub. Set LETHE_RUN_REAL_PACK=1 to run.
@pytest.mark.skipif(
    os.environ.get("LETHE_RUN_REAL_PACK") != "1",
    reason="set LETHE_RUN_REAL_PACK=1 to pack the real ed25519 verifier end-to-end",
)
def test_real_ed25519_verify_materializes_and_scrubs(tmp_path: Path, monkeypatch) -> None:
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
                    "ed25519Verify", EV_RVA, EV_SIZE, EV_SIZE),
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
    assert function.target_size == EV_SIZE
    patch = function.target_entry_patch.patch
    assert patch[0] == 0xE9
    disp, = struct.unpack("<i", patch[1:5])
    assert EV_RVA + 5 + disp == function.target_entry_patch.destination_rva
    assert patch[5:] == b"\xCC" * (EV_SIZE - 5)     # whole multi-fragment extent scrubbed
    off = _file_offset(source, EV_RVA)
    assert function.original_sha256 == hashlib.sha256(
        source.read_bytes()[off:off + EV_SIZE]
    ).hexdigest()


def _file_offset(dll: Path, rva: int) -> int:
    pe = pefile.PE(str(dll), fast_load=True)
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(
            s.Misc_VirtualSize, s.SizeOfRawData
        ):
            return s.PointerToRawData + (rva - s.VirtualAddress)
    raise AssertionError("rva not found")
