# Lethe

**Build-time protection tooling for first-party x64 Windows executables.** Lethe
transforms an unmanaged EXE into a protected PE and raises the cost of casual
reverse-engineering and tampering. Every output still requires application-level
validation; Lethe makes no universal compatibility, security, or antivirus claim.

It is a **build-time** tool: you run it on binaries you own to produce the
shipping artifact. It is not a general-purpose packer-for-hire and it deliberately
excludes AV/EDR-evasion tricks — it is defensive IP protection and security
research. Current Defender scanning is a required release gate, not a permanent
property of the tool.

> Lethe is a cost multiplier, not a security boundary. Any code that executes on
> a user-controlled machine can ultimately be observed. See
> [Scope and limits](#scope--limits) before adopting it.

## The suite

Lethe is the umbrella brand; the engines have their own codenames so each stays a
clean, separable component.

| Component | What it is |
|-----------|------------|
| **Lethe** (`packer/`, `stub/`) | The PE packer: per-section deflate + **AES-256-GCM**, a **code-hash-bound key**, reloc/TLS/`.pdata`/`.rsrc` handling, optional anti-debug checks, compatibility-preserving **anti-dump** metadata sanitization, and an experimental VEH **memory-guard**. The supported release path is unmanaged x64 EXEs. |
| **Kalypso** (`cipher/`) | A custom **ChaCha20-Poly1305 AEAD** (RFC 8439) with a per-build sigma + word-permutation, checked against RFC vectors and the `cryptography` library. |
| **Daedalus** (`daedalus/`, `stub/src/daedalus_*`) | A custom stack-machine **VM** for protector routines and explicitly selected application functions. Production-selected programs use independently authenticated AES-GCM bytecode pages, a one-page plaintext cache, per-build opcode shuffle, and build-bound handler variants. Rolling bytecode remains a separate mode for hand-authored VM programs. |
| **x64 lifter** (`lifter/`) | A from-scratch **x64 → Daedalus** lifter for selected-function virtualization. Its supported scalar register/memory subset is checked against a Unicorn differential oracle; unsupported instructions reject the whole selected function. A read-only discovery/report tool inventories exact candidates and coverage gaps without auto-selecting code. |
| **Obfuscation** (`obfuscation/`) | A custom LLVM pass plugin (control-flow flattening + opaque predicates + MBA + bogus control flow, per-build randomized). *Drafted, not yet compiled — needs an LLVM toolchain; see its README.* |
| **bind** (`bind/`) | Hash-pin a packed EXE's first-party dependency DLLs so they can't be swapped, without fragile single-EXE bundling. |
| **tracing** (`tracing/`) | Per-customer build variance and issuance-side identifiers for investigating leaked builds. |
| **bounty** (`bounty/`) | A "recover the flag" challenge generator (Argon2id + AES-256-GCM) with a leak-audit gate for authorized research exercises. |

## Highlights

- **Crypto with explicit test oracles.** Kalypso's ChaCha20-Poly1305 behavior is
  checked against RFC 8439 vectors and the `cryptography` implementation. Those
  checks are strong regression evidence, not a formal proof or external audit.
- **A real virtual machine + a real lifter.** Daedalus runs selected scalar x64
  bodies as VM bytecode. Production materialization replaces the complete native
  extent with a Win64 thunk and stores bytecode in authenticated 256-byte pages;
  wrong keys, page swaps, truncation, descriptor mismatch, and modified page
  metadata fail closed. Unicorn differential tests remain the semantic oracle.
- **Per-build variance.** Keys, optional opcode mappings, and customer-specific
  issuance metadata can differ between builds. Treat this as traceability and
  defense-in-depth, not as a guarantee that analysis will not transfer.
- **Constrained AV posture.** Known high-noise primitives such as
  `ThreadHideFromDebugger`, `int 2d`/`int 3`, self-modifying `.text`, and RWX are
  avoided. Every signed release still requires a clean-VM scan and smoke test.

## Quickstart

```powershell
# pack a supported unmanaged x64 EXE
python lethe.py yourapp.exe yourapp.packed.exe

# inventory exact function candidates and lift blockers without modifying input
python tools/virtualization_report.py yourapp.exe --format table

# GUI (QML front-end): batch queue, options, presets, post-pack validation, reports
python gui/venice.py            # or the widgets twin: python gui/app.py

# install the locked toolchain and run the core suite
uv sync --frozen --group dev
uv run pytest -q -p no:cacheprovider `
  --ignore=tests/test_lifter.py `
  --ignore=tests/test_lifter_internal_calls.py `
  --ignore=tests/test_lifter_native_runtime.py `
  --ignore=tests/test_lifter_scalar_batch.py
uv run pytest tests/test_lifter.py tests/test_lifter_internal_calls.py `
  tests/test_lifter_native_runtime.py tests/test_lifter_scalar_batch.py `
  -q -p no:cacheprovider -p no:faulthandler
```

The packer ships a prebuilt stub (`stub/prebuilt/lethe_stub_x64.dll`), so packing
itself needs **no compiler**. Ordinary native builds stay under `stub/build` and
do not overwrite the tracked prebuilt. See
[`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md) before promotion.
The adjacent manifest pins the tracked DLL's hash and provenance. Default packing
fails closed unless that manifest records a matching clean-source build; use
`--stub-path` while validating an unpromoted candidate.

## CLI

```
python lethe.py INPUT [OUTPUT] [--anti-debug {on,off}]
                               [--memory-guard] [--process-hardening]
                               [--level N]
                               [--virtualize-function NAME:RVA:SIZE]
                               [--enable-experimental-virtualization]
                               [--stub-path PATH] [--verbose]
```

| flag | default | meaning |
|------|---------|---------|
| `OUTPUT` | `<input>.packed<ext>` | packed output path |
| `--dll` | off | force DLL mode; requires `--enable-experimental-dll` and is not release-approved |
| `--anti-debug` | `off` | experimental debugger checks; enable only for targeted validation |
| `--memory-guard` | off | experimental on-demand page decryption; not release-approved |
| `--process-hardening` | off | opt in to irreversible EXE process mitigations and restricted default DLL search directories; unavailable for DLL mode |
| `--virtualize-function NAME:RVA:SIZE` | none | select one exact first-party function extent; repeatable |
| `--enable-experimental-virtualization` | off | acknowledge the selected-function path; requires an explicit fresh `--stub-path` |
| `--level N` | `9` | deflate compression level (0–9) |
| `--stub-path PATH` | tracked prebuilt | use a fresh stub without promoting it |
| `--verbose` | off | stream builder/stub progress |

Managed/.NET assemblies are refused up front. DLL packing is disabled unless the
caller supplies the explicit experimental acknowledgment. The guarded DLL path
supports dynamic and static import consumers plus tested TLS, unwind, attach,
detach, unload, and reload lifecycles, but is not release-approved until every
required DLL compatibility row is proven. Experimental behavior must not be used
for release artifacts.

### Server shard mode

Server shard mode is an experimental integration and is disabled by default. It
requires `--server-shard --enable-experimental-server-shard`, HTTPS, a license
ID, a target HWID SHA-256, and a builder secret. It is not a supported release
path until a versioned backend contract and signed end-to-end deployment test are
available.

The packer publishes the output only after the server accepts its 32-byte shard
and echoes the matching `build_id`. That ID is a signing-stable SHA-256 PE
content ID: the mutable checksum, certificate directory entry, and Authenticode
certificate bytes are excluded so the launcher identifies the same artifact
after signing.

## Repo layout

```
lethe.py            CLI front-end
packer/             the packer core (container ABI, PE analysis, payload, assemble, orchestrator)
stub/               native no-CRT C stub (manual PE loader + crypto + anti-* + Daedalus VM)
cipher/             Kalypso (kalypso.py/.c/.h) + the red-team crackme generators
daedalus/           the Daedalus VM: assembler, disassembler, reference interpreter, MBA, rolling, shuffle
lifter/             x64 -> Daedalus lifter + the Unicorn differential oracle
obfuscation/        custom LLVM obfuscation pass plugin (draft, uncompiled)
bind/               dependency hash-pinning
tracing/            per-customer variance + traitor tracing
bounty/             money-grade break-it challenge + audit
gui/                PySide6 front-ends (QML "Venice" + widgets) + build script
tests/              pytest suite (packer ABI, cipher, VM, lifter, bind, tracing, bounty, report)
docs/               release checklist, security notes, loader-coverage audit
```

Component deep-dives live in `lifter/README.md`, `obfuscation/README.md`, and
`bounty/README.md`.

## Scope & limits

No client-side packer makes code unbreakable. The protected instructions and
keys eventually exist on a machine controlled by the operator, and a sufficiently
capable observer can recover them. Lethe is therefore defense-in-depth for
authorized first-party software, not a substitute for server-side authorization,
secure update design, or platform mitigations.

Concrete, honest limitations of the offline layer:

- **Base packing is dumpable once unpacked in RAM.** Anti-dump now preserves the
  loader-facing PE/section geometry required by resources, exports, and host APIs,
  while clearing nonessential import/debug/bound-import/IAT metadata. A determined analyst
  can still reconstruct executable pages after they activate.
- **Native memory-guard activation is monotonic.** First touch briefly inflates an
  executable section, immediately re-wraps untouched pages, and leaves activated
  pages immutable RX. This avoids corrupting concurrent execution; a long-running
  process can eventually expose every native page. Selected VM bytecode uses the
  stronger authenticated one-page cache because the interpreter owns every fetch.
- **Supported GuardCF load-configs are preserved, not downgraded.** The output
  publishes a loader-visible load config, relocations, GFIDs, restored support
  slots, volatile metadata, CastGuard/GuardMemcpy slots, and runtime target
  registration. Current MSVC GuardCF/XFG-slot and delay-import fixtures run with
  exact behavior parity. Dynamic-value-relocation, CHPE, CodeIntegrity, return-flow
  guard, hotpatch, enclave, UMA, suppressed GFIDs, and CET-specific metadata remain
  fail-closed rather than silently stripped. Selected-function virtualization of
  an XFG-enabled input also fails preflight until generated thunk GFIDs can carry
  source-compatible 8-byte XFG function hashes.
- **Packing disables crash-dump/support triage** on protected binaries. Pack last,
  after live sign-off, and canary an unpacked build before packed goes wide.
- **The code-hash key binding raises cost, not certainty** — a debugger can still
  recover the key at runtime.
- **Status of components:** the included tests cover the implemented packer core,
  Kalypso, Daedalus, and supported lifter subset. They do not establish universal
  PE compatibility. The LLVM obfuscation layer is a **drafted, uncompiled** first
  cut. Selected scalar functions have a native Win64 thunk and VM entry path;
  direct non-recursive calls within one selected extent preserve ASLR-correct
  stack return addresses and use shadow-validated VM returns. Native/external or
  indirect calls, SIMD/FP, exception-bearing selected bodies, and indirect target
  closure remain unsupported.

## AV / Authenticode

- **AV posture:** persistent false positives are a release blocker. Always scan
  and runtime-smoke the exact signed output on a clean Defender VM before shipping.
- **Authenticode:** Lethe does **not** sign — sign *after* packing. `.rsrc`
  (icon, version info, manifest) is preserved as real bytes at its original RVA so
  the OS, Authenticode, and SmartScreen can read it.

## Development

```powershell
uv sync --frozen --group dev
uv run pytest -q -p no:cacheprovider `
  --ignore=tests/test_lifter.py `
  --ignore=tests/test_lifter_internal_calls.py `
  --ignore=tests/test_lifter_native_runtime.py `
  --ignore=tests/test_lifter_scalar_batch.py
uv run pytest tests/test_lifter.py tests/test_lifter_internal_calls.py `
  tests/test_lifter_native_runtime.py tests/test_lifter_scalar_batch.py `
  -q -p no:cacheprovider -p no:faulthandler
```

Python 3.12 is the supported tooling runtime. Dependencies are recorded in
`pyproject.toml` and locked in `uv.lock`. Unicorn intentionally handles Windows
access violations internally; disabling pytest's faulthandler for these four
Unicorn-backed files prevents misleading megabytes of fatal-exception diagnostics
without dropping coverage.

## License

Copyright (c) 2026 zaehuncho. Licensed under the Apache License 2.0.
See [`LICENSE`](LICENSE) and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
