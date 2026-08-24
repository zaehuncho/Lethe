# Lethe — custom x64 Windows PE packer / protector

Lethe is an **internal, build-time** software-protection tool for Orion's own
first-party Windows binaries (EXEs **and** DLLs). It transforms an x64 PE into a
protected PE that runs identically, using the *Aggressive* protection tier:
per-section **zlib (deflate) compression + AES-256-GCM encryption**, **import
elision** (the original import table is hidden inside the encrypted payload),
reloc / TLS / x64-exception handling, a **code-hash-bound key** (tamper ⇒ wrong
key ⇒ decrypt fails), **gated, AV-clean anti-debug**, and an **anti-dump layer**
(see *Honest limitations* below). Compression is deflate, not LZMA: the stub's
bundled miniz can only decode deflate.

It is a tool that *produces* the shipping product — it is **never shipped to
customers**, and it never touches the license/entitlement server (your real
enforcement lives there, in native C++). Lethe fills the packer slot the IP
pipeline already reserves: `tools/security/pack_lethe_release.py` invokes any
packer through a `--packer-command "<cmd> {input} {output}"` template, and this
tool matches that contract exactly.

> **Status:** the container ABI (`packer/container.py`) is complete and tested
> now. The native stub, some builder modules, and the frozen GUI are landed by
> sibling work; the round-trip harness auto-skips until the stub is built.

## Two front-ends, one core

Both front-ends are thin wrappers over the single core function
`packer.orchestrator.pack_file()` (with `PackOptions` / `PackResult`), so they
never drift:

- **CLI** — `lethe.py`. The pipeline drop-in.
- **GUI** — `gui/app.py`, frozen to `Lethe.exe` (PySide6 + Nuitka) for
  manual, clickable use.

## Layout

```
lethe.py            CLI front-end (pipeline drop-in)
packer/container.py     THE ABI — struct layouts, magic, constants (mirror of pack_info.h)
packer/pe_analyze.py    LIEF PE extraction (sections, imports, relocs, TLS, .pdata, .rsrc)
packer/payload.py       per-section LZMA + AES-GCM, blob serialize, keygen + code-hash bind
packer/assemble.py      output PE construction, PackInfo patch          (landed by sibling work)
packer/orchestrator.py  pack_file()/PackOptions/PackResult — the one core API (sibling work)
gui/app.py              PySide6 GUI; gui/build_gui.ps1 freezes it to Lethe.exe
stub/src/*.c,*.h        native C stub (manual PE loader + crypto + anti-*), pack_info.h = ABI mirror
stub/build_stub.ps1     builds the stub -> stub/prebuilt/stub_x64.bin (sibling work)
stub/prebuilt/stub_x64.bin  checked-in compiled stub the builder grafts in (pack-time needs no compiler)
tests/                  round-trip harness + sample PEs + additional ABI unit tests
tests/test_lethe_container_abi.py   container.py <-> pack_info.h agreement (runs now)
README.md / RUNBOOK.md
```

The gate-registered container round-trip test lives at repo root:
`tests/test_lethe_container.py` (see RUNBOOK).

## Build the stub

The builder consumes a **prebuilt** stub PE, so packing itself needs no compiler
— but you rebuild the stub whenever any `stub/src/*` file changes:

```powershell
# Standalone CMake project (VS2022 / x64, C, minimal CRT, no Qt),
# mirroring installer/OrionSetup/CMakeLists.txt's hardening spirit.
powershell tools\security\packer\stub\build_stub.ps1
# -> refreshes tools\security\packer\stub\prebuilt\stub_x64.bin
```

Under the hood this is roughly:

```powershell
cmake -S tools\security\packer\stub -B <build> -G "Visual Studio 17 2022" -A x64
cmake --build <build> --config Release
```

The stub is compiled with the same hardening as the real binaries
(`/guard:cf /DYNAMICBASE /NXCOMPAT`) and links only `kernel32` (pure C crypto
eliminates any system crypto import; `BCryptGenRandom` is resolved dynamically
at runtime for CSPRNG entropy only). It must **never** load or touch
`libcrypto-3-x64.dll` (hash-pinned for Ed25519, `Ed25519.cpp:122-160`).

## Use the CLI

```
python lethe.py INPUT [OUTPUT]
                    [--dll] [--anti-debug {on,off}] [--memory-guard]
                    [--level N] [--verbose]
```

| flag             | default                | meaning                                                   |
|------------------|------------------------|-----------------------------------------------------------|
| `OUTPUT`         | `<input>.packed<ext>`  | where to write the packed PE                              |
| `--dll`          | auto-detect            | force DLL packing (otherwise read from the PE header)     |
| `--anti-debug`   | `on`                   | gated, AV-clean debugger checks in the stub               |
| `--memory-guard` | off                    | opt-in on-demand page decryption — **AV-test first**      |
| `--level N`      | `9`                    | zlib (deflate) compression level (0–9)                    |
| `--verbose`      | off                    | stream builder/stub progress + raw `PackResult` fields    |

Exit codes: **0** success · **1** packing ran but failed · **2** bad args /
missing input / core import failure.

```powershell
# examples
python lethe.py OrionOwner.exe OrionOwner.packed.exe
python lethe.py SecurityCore.dll SecurityCore.packed.dll --dll
python lethe.py OrionNative.exe out.exe --memory-guard --anti-debug on --verbose
```

**Pipeline contract:** the pipeline calls exactly `lethe.py {input} {output}`,
so `--packer-command "python tools\security\packer\lethe.py {input} {output}"`
drops in with zero pipeline changes.

## Use the GUI

```powershell
# run from source during development
python tools\security\packer\gui\app.py

# freeze to a clickable Lethe.exe (bundles the packer lib + LIEF + stub_x64.bin)
powershell tools\security\packer\gui\build_gui.ps1
```

Workflow: **Add PEs** (button / drag-drop, multi-select) → each row shows the
auto-detected type (EXE/DLL from the header), arch and size → set **Options**
(output folder, anti-debug on/off, memory-guard on/off with an *"opt-in, AV-test
first"* note, compression level; global with per-row override) → **Pack**. Each
file is packed on a worker thread (the UI stays responsive) with a live log and a
per-file result row (✓/✗, sizes, ratio, time, inline errors).

## Tests & round-trip harness

```powershell
# container ABI round-trips (no third-party deps — pass NOW)
python -m pytest tests\test_lethe_container.py
python -m pytest tools\security\packer\tests\test_lethe_container_abi.py

# end-to-end acceptance: build samples -> pack -> run original vs packed ->
# assert identical stdout/exit + host-loads-packed-DLL. SKIPS cleanly (exit 2)
# until lethe.py + stub_x64.bin exist; needs MSVC (cl.exe) to build samples.
powershell tools\security\packer\tests\roundtrip.ps1
```

`roundtrip.ps1` encodes plan Verification **#2** (EXE round-trip) and **#4** (DLL
round-trip). The remaining verification steps (PE-viewer entropy/imports checks,
ASLR/DEP, signability, AV smoke, anti-dump, memory-guard, GUI) are manual — see
RUNBOOK.

---

## Honest limitations (state these plainly)

**No packer makes code unbreakable.** Lethe is *one layer* of a
defense-in-depth stack (obfuscation + packing + anti-dump + optional
virtualization); your real teeth are the **server-enforced license/entitlement
gate**, which a client-side dump does **not** bypass.

- **Base packing is dumpable once unpacked in RAM.** The anti-dump layer
  erases PE headers immediately after section decryption (before imports,
  relocs, or TLS are processed), so there is no single breakpoint that yields
  a perfect dump with intact headers. A determined analyst can still
  reconstruct from the headerless mapped sections.
- **Anti-dump — on by default (`antidump.c`), AV-clean:** in-memory PE **header
  erasure** (MZ/PE signature + section table wiped after load), **payload +
  loader wipe** (the compressed/encrypted blob and decrypt scratch are zeroed
  after use, so a dump reveals no second copy and no unpack logic), and
  **anti-injection** via `SetProcessMitigationPolicy` (blocks non-Microsoft /
  unsigned DLL loads, stopping Scylla-style dumper/injector DLLs). This moves
  dumping from *trivial* to *expensive* — a determined expert with
  kernel/hypervisor tooling can still eventually win.
- **Memory-guard — opt-in (`memguard.c`, `--memory-guard`), OFF by default:** a
  VEH page-fault decryptor keeps code pages AES-encrypted + `PAGE_NOACCESS` and
  decrypts a page only on first touch, so **no single snapshot holds the whole
  program**. Costs page-fault perf, complexity, and possible AV suspicion —
  hence opt-in and **A/B it on a Defender VM before shipping**.
- **Packing drops CFG enforcement on the packed image (§6).** The original code
  is materialized at runtime and made executable by the stub, so Windows Control
  Flow Guard is *not* enforced on those pages (the OS never populated a CFG
  valid-target bitmap for dynamically-produced code). The **stub itself** is
  built `/guard:cf`, but the protected payload loses CFG. Weigh this per binary.
- **Packing disables crash-dump / support triage** on protected binaries
  (erased headers + encrypted/wiped payload make minidumps unusable). This is why
  `RELEASE_SECURITY.md:126-156` **defers packing until after live sign-off** —
  pack last, once you no longer need field crash telemetry from that build.
- **The code-hash key binding raises cost, not certainty.** Patching the stub
  changes its `.text` hash ⇒ the derived key is wrong ⇒ decryption fails; but a
  debugger can still recover the key at runtime.

## AV / Authenticode / CFG notes

- **AV posture (Aggressive-but-clean):** the tier is tuned to stay clean on a
  Windows Defender VM — "persistent AV false positives" is a release blocker in
  the IP plan. The anti-debug set includes 13 checks at startup plus 4
  scattered tripwires (PEB, NtGlobalFlag, RDTSC, hardware breakpoints) at
  different loader stages, each independently wiping key material. Known AV red
  flags are **excluded on purpose**: `ThreadHideFromDebugger`, `int 2d`/`int 3`
  tricks, self-modifying code. Import resolution uses FNV-1a hashing + PEB/
  export-table walking (no `GetProcAddress` with plaintext names). Use
  `--anti-debug off` to A/B the Defender impact per release. **Always AV-smoke
  packed output on a clean Defender VM before shipping** (plan Verification #6).
- **Authenticode:** Lethe does **not** sign. Signing is the pipeline's job
  and runs **after** packing (`signtool` between pack and manifest-hash, per
  `IP_PROTECTION_PLAN.md:279-286`). Packed EXEs/DLLs must remain signable —
  `.rsrc` (icon, `RT_VERSION`, `RT_MANIFEST` for UAC/DPI) is preserved as real
  bytes at its original RVA so the OS, Authenticode, SmartScreen and the
  installer can read it. v1 does not encrypt resources (metadata, not
  crown-jewel code).
- **CFG:** see the *Honest limitations* CFG bullet — packed payload loses CFG
  enforcement; the stub is `/guard:cf`. Verify `DYNAMICBASE` + `NXCOMPAT` survive
  on the packed image (plan Verification #3) and that there are **no RWX pages**
  at any point (the stub `VirtualProtect`s to final RX/R/RW perms after writing).
