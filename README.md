# Lethe

**A custom, AV-clean software protector for your own first-party x64 Windows
binaries.** Lethe transforms an EXE or DLL into a protected PE that runs
identically, while making it genuinely expensive to reverse-engineer or tamper
with — with its own cipher, its own virtual machine, and a from-scratch
x64→bytecode lifter, all built from the ground up and test-verified.

It is a **build-time** tool: you run it on binaries you own to produce the
shipping artifact. It is not a general-purpose packer-for-hire and it deliberately
excludes AV/EDR-evasion tricks — it is defensive IP protection and security
research, tuned to stay clean on Windows Defender.

> **Honest framing up front:** no client-side packer makes code unbreakable — and
> that's not an engineering gap, it's provable (see [Scope & limits](#scope--limits)).
> Lethe is a *cost multiplier*, deliberately maxed out for what an offline
> protector can be. The only true wall is server-side enforcement, which packing
> complements rather than replaces.

## The suite

Lethe is the umbrella brand; the engines have their own codenames so each stays a
clean, separable component.

| Component | What it is |
|-----------|------------|
| **Lethe** (`packer/`, `stub/`) | The PE packer: per-section deflate + **AES-256-GCM**, **import elision** (FNV-1a hashing + PEB/Ldr walk — no plaintext `GetProcAddress`), a **code-hash-bound key** (tamper ⇒ wrong key ⇒ decrypt fails), reloc/TLS/`.pdata`/`.rsrc` handling, gated **AV-clean anti-debug**, **anti-dump** (in-memory header wipe), and an opt-in VEH **memory-guard**. Freestanding, no-CRT, kernel32-only stub. |
| **Kalypso** (`cipher/`) | A custom **ChaCha20-Poly1305 AEAD** (RFC 8439) with a per-build sigma + word-permutation. Proven **bit-identical to RFC 8439** and cross-checked against the `cryptography` library. |
| **Daedalus** (`daedalus/`, `stub/src/daedalus_*`) | A custom stack-machine **VM** that virtualizes the protector's crypto-critical routines (key derivation, license/lease checks). Hardened with **rolling self-decrypting bytecode**, per-build **opcode shuffle**, and **observation-poison** (debugging corrupts the decode). |
| **x64 lifter** (`lifter/`) | A from-scratch **x64 → Daedalus** lifter for on-demand function virtualization. Covers the register + memory integer subset; **every instruction proven bit-exact against a Unicorn differential oracle**. Bails to native on anything it can't reproduce faithfully — it never bricks a function. |
| **Obfuscation** (`obfuscation/`) | A custom LLVM pass plugin (control-flow flattening + opaque predicates + MBA + bogus control flow, per-build randomized). *Drafted, not yet compiled — needs an LLVM toolchain; see its README.* |
| **bind** (`bind/`) | Hash-pin a packed EXE's first-party dependency DLLs so they can't be swapped, without fragile single-EXE bundling. |
| **tracing** (`tracing/`) | Per-customer build variance + **traitor tracing**: each customer gets a uniquely-morphed binary, and a leaked build can be traced back to its buyer. |
| **bounty** (`bounty/`) | A money-grade "recover the flag" challenge generator (Argon2id + AES-256-GCM) with a leak-audit gate — for a public break-it bounty. |

## Highlights

- **Custom crypto, done right.** Kalypso is not homemade magic — its core is
  ChaCha20 with the proven rotations, verified against the RFC 8439 test vectors,
  with a per-build twist that's provably security-neutral.
- **A real virtual machine + a real lifter.** Daedalus runs the crown-jewel logic
  as opaque bytecode; the lifter turns native x64 into that bytecode, and its
  correctness is enforced by a differential oracle (Unicorn is ground truth) over
  thousands of fuzzed sequences.
- **Per-build polymorphism.** Every build differs (sigma, opcode shuffle, rolling
  state, key), so a crack doesn't transfer — and per-customer builds make that a
  distribution-layer weapon plus a traitor-tracing signal.
- **AV-clean by construction.** No `ThreadHideFromDebugger`, no `int 2d`/`int 3`,
  no self-modifying `.text`, no RWX, no static system-crypto import.

## Quickstart

```powershell
# pack a binary (auto-detects EXE vs DLL from the header)
python lethe.py yourapp.exe yourapp.packed.exe

# GUI (QML front-end): batch queue, options, presets, post-pack validation, reports
python gui/venice.py            # or the widgets twin: python gui/app.py

# run the test suite
python -m pytest -m "not slow"
```

The packer ships a prebuilt stub (`stub/prebuilt/lethe_stub_x64.dll`), so packing
itself needs **no compiler**. Rebuild the stub only when `stub/src/*` changes
(VS2022 / MSVC, see `RUNBOOK.md`).

## CLI

```
python lethe.py INPUT [OUTPUT] [--dll] [--anti-debug {on,off}]
                               [--memory-guard] [--level N] [--verbose]
```

| flag | default | meaning |
|------|---------|---------|
| `OUTPUT` | `<input>.packed<ext>` | packed output path |
| `--dll` | auto-detect | force DLL packing |
| `--anti-debug` | `on` | gated, AV-clean debugger checks |
| `--memory-guard` | off | opt-in on-demand page decryption — **AV-test first** |
| `--level N` | `9` | deflate compression level (0–9) |
| `--verbose` | off | stream builder/stub progress |

Managed/.NET assemblies are **refused** up front (packing them the native way
would silently break them).

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
docs/               runbooks, security notes, loader-coverage audit
```

Component deep-dives live in `lifter/README.md`, `obfuscation/README.md`, and
`bounty/README.md`.

## Scope & limits

**No client-side packer can make code unbreakable — this is provable, not
unsolved.** Any implementation must present real instructions to a CPU the
adversary controls, and a passive hypervisor/Intel-PT observer can read them
without tripping any defense (cf. Barak et al., *On the (Im)possibility of
Obfuscating Programs*, 2001). So Lethe's job is to be an expensive **cost
multiplier**, and the one true wall is **server-side** (release the decryption
key / critical code per session, bound to a license) — which the packer
complements.

Concrete, honest limitations of the offline layer:

- **Base packing is dumpable once unpacked in RAM.** Anti-dump erases PE headers
  right after section decryption, so there's no clean single-breakpoint dump, but
  a determined analyst can still reconstruct from the headerless mapped image.
- **Memory-guard** (opt-in) keeps code pages encrypted + `PAGE_NOACCESS` and
  decrypts per-page on first touch, so no single snapshot holds the whole
  program — at a page-fault cost and possible AV suspicion. A/B it on a Defender
  VM before shipping.
- **Packing drops CFG enforcement** on the packed image (the OS never builds a
  CFG bitmap for dynamically-materialized code). The stub itself is `/guard:cf`.
  Weigh per binary — fine for game/UI/license logic, worse for network-reachable
  code.
- **Packing disables crash-dump/support triage** on protected binaries. Pack last,
  after live sign-off, and canary an unpacked build before packed goes wide.
- **The code-hash key binding raises cost, not certainty** — a debugger can still
  recover the key at runtime.
- **Status of components:** the packer core, Kalypso, Daedalus, and the lifter are
  test-verified in this repo; the LLVM obfuscation layer is a **drafted,
  uncompiled** first cut (needs an LLVM box + oracle validation); the lifter's
  runtime C thunk (`call`/`ret` + Win64-ABI glue) is future work.

## AV / Authenticode

- **AV posture:** tuned to stay clean on Windows Defender — persistent false
  positives are a release blocker. Known red flags are excluded on purpose (see
  above). Always AV-smoke packed output on a clean Defender VM before shipping.
- **Authenticode:** Lethe does **not** sign — sign *after* packing. `.rsrc`
  (icon, version info, manifest) is preserved as real bytes at its original RVA so
  the OS, Authenticode, and SmartScreen can read it.

## Development

```powershell
python -m pytest -m "not slow"      # full suite
```

The lifter tests need `iced-x86`, `unicorn`, and `keystone-engine`
(`pip install iced-x86 unicorn keystone-engine`); the cipher/bounty tests need
`cryptography` (and `argon2-cffi` for the bounty). Tests `importorskip` optional
deps, so the suite stays green where they're absent.

## License

Choose a license before publishing. This is proprietary IP-protection software;
pick terms deliberately (all-rights-reserved, source-available, or open-core).
