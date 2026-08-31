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
| **Lethe** (`packer/`, `stub/`) | The PE packer: per-section deflate + **AES-256-GCM**, a **code-hash-bound key**, reloc/TLS/`.pdata`/`.rsrc` handling, optional anti-debug checks, **anti-dump** (in-memory header wipe), and an experimental VEH **memory-guard**. The supported release path is unmanaged x64 EXEs. |
| **Kalypso** (`cipher/`) | A custom **ChaCha20-Poly1305 AEAD** (RFC 8439) with a per-build sigma + word-permutation, checked against RFC vectors and the `cryptography` library. |
| **Daedalus** (`daedalus/`, `stub/src/daedalus_*`) | A custom stack-machine **VM** that virtualizes the protector's crypto-critical routines (key derivation, license/lease checks). Hardened with **rolling self-decrypting bytecode**, per-build **opcode shuffle**, and **observation-poison** (debugging corrupts the decode). |
| **x64 lifter** (`lifter/`) | A from-scratch **x64 → Daedalus** lifter for on-demand function virtualization. Its supported register/memory integer subset is checked against a Unicorn differential oracle; unsupported instructions bail to native handling. |
| **Obfuscation** (`obfuscation/`) | A custom LLVM pass plugin (control-flow flattening + opaque predicates + MBA + bogus control flow, per-build randomized). *Drafted, not yet compiled — needs an LLVM toolchain; see its README.* |
| **bind** (`bind/`) | Hash-pin a packed EXE's first-party dependency DLLs so they can't be swapped, without fragile single-EXE bundling. |
| **tracing** (`tracing/`) | Per-customer build variance and issuance-side identifiers for investigating leaked builds. |
| **bounty** (`bounty/`) | A "recover the flag" challenge generator (Argon2id + AES-256-GCM) with a leak-audit gate for authorized research exercises. |

## Highlights

- **Crypto with explicit test oracles.** Kalypso's ChaCha20-Poly1305 behavior is
  checked against RFC 8439 vectors and the `cryptography` implementation. Those
  checks are strong regression evidence, not a formal proof or external audit.
- **A real virtual machine + a real lifter.** Daedalus runs the crown-jewel logic
  as opaque bytecode; the lifter turns native x64 into that bytecode, and its
  correctness is enforced by a differential oracle (Unicorn is ground truth) over
  thousands of fuzzed sequences.
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

# GUI (QML front-end): batch queue, options, presets, post-pack validation, reports
python gui/venice.py            # or the widgets twin: python gui/app.py

# install the locked toolchain and run the core suite
uv sync --frozen --group dev
uv run pytest -q -p no:cacheprovider --ignore=tests/test_lifter.py
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
                               [--memory-guard] [--level N]
                               [--stub-path PATH] [--verbose]
```

| flag | default | meaning |
|------|---------|---------|
| `OUTPUT` | `<input>.packed<ext>` | packed output path |
| `--dll` | off | force DLL mode; requires `--enable-experimental-dll` and is not release-approved |
| `--anti-debug` | `off` | experimental debugger checks; enable only for targeted validation |
| `--memory-guard` | off | experimental on-demand page decryption; not release-approved |
| `--level N` | `9` | deflate compression level (0–9) |
| `--stub-path PATH` | tracked prebuilt | use a fresh stub without promoting it |
| `--verbose` | off | stream builder/stub progress |

Managed/.NET assemblies are refused up front. DLL packing is disabled unless the
caller supplies the explicit experimental acknowledgment; the current DLL path
performs initialization under Windows loader lock and does not support static
import consumers. Experimental behavior must not be used for release artifacts.

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

- **Base packing is dumpable once unpacked in RAM.** Anti-dump erases PE headers
  right after section decryption, so there's no clean single-breakpoint dump, but
  a determined analyst can still reconstruct from the headerless mapped image.
- **Memory-guard** (opt-in) keeps code pages encrypted + `PAGE_NOACCESS` and
  decrypts per-page on first touch, so no single snapshot holds the whole
  program — at a page-fault cost and possible AV suspicion. A/B it on a Defender
  VM before shipping.
- **Packing drops CFG enforcement** on dynamically materialized payload code.
  The current hash-bound native stub is also built without Guard CF. Treat this
  as a concrete mitigation regression when deciding which binaries may be packed.
- **Packing disables crash-dump/support triage** on protected binaries. Pack last,
  after live sign-off, and canary an unpacked build before packed goes wide.
- **The code-hash key binding raises cost, not certainty** — a debugger can still
  recover the key at runtime.
- **Status of components:** the included tests cover the implemented packer core,
  Kalypso, Daedalus, and supported lifter subset. They do not establish universal
  PE compatibility. The LLVM obfuscation layer is a **drafted, uncompiled** first
  cut; the lifter's runtime C thunk (`call`/`ret` + Win64-ABI glue) is future work.

## AV / Authenticode

- **AV posture:** persistent false positives are a release blocker. Always scan
  and runtime-smoke the exact signed output on a clean Defender VM before shipping.
- **Authenticode:** Lethe does **not** sign — sign *after* packing. `.rsrc`
  (icon, version info, manifest) is preserved as real bytes at its original RVA so
  the OS, Authenticode, and SmartScreen can read it.

## Development

```powershell
uv sync --frozen --group dev
uv run pytest -q -p no:cacheprovider --ignore=tests/test_lifter.py
uv run pytest tests/test_lifter.py -q -p no:cacheprovider -p no:faulthandler
```

Python 3.12 is the supported tooling runtime. Dependencies are recorded in
`pyproject.toml` and locked in `uv.lock`. Unicorn intentionally handles Windows
access violations internally; disabling pytest's faulthandler for the lifter file
prevents misleading megabytes of fatal-exception diagnostics.

## License

Copyright (c) 2026 zaehuncho. Licensed under the Apache License 2.0.
See [`LICENSE`](LICENSE) and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
