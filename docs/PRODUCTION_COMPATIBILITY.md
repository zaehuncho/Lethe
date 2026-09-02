# Lethe production compatibility gate

Production readiness is declared in
[`production_compatibility.json`](production_compatibility.json). The file is
machine-validated and intentionally remains red while any required EXE or DLL
contract is failing, partial, experimental, blocked, or unverified.

The declaration is not a test counter. A feature marked `proven` must name
repository evidence. Native runtime features can additionally name
`native_checks`; those checks must appear as passed in evidence from the exact
stub under test. Evidence from a tracked-dirty source tree is rejected for a
release claim.

## Current native corpus

`build_production_corpus.ps1` creates two first-party unmanaged x64 EXEs plus
guarded DLL lifecycle fixtures:

- `compat_core_exe.exe` has real RCDATA, a DIR64 function pointer, a deliberately
  unusual preferred base, and DYNAMICBASE. It proves `FindResourceW`, relocation,
  and a non-preferred runtime base together.
- `compat_delay_exe.exe` has a real `/DELAYLOAD:compat_dependency.dll` directory
  and current MSVC GuardCF/XFG/CastGuard/volatile-metadata load config. Its flags
  must not be weakened to make the fixture pack.
- `sample_dll.dll` preserves its unmodified GuardCF table, including
  export-suppressed GFIDs. Dynamic, static-import, pre-existing-thread, and
  eight-cycle unload/reload hosts compare packed behavior with the original.
- Auxiliary DLLs cover `/NOENTRY`, rejected `DLL_PROCESS_ATTACH`, C++ x64
  unwind, TLS-free `DisableThreadLibraryCalls`, and 64-byte TLS alignment.
- `resource_offset_dll.dll` places its resource root 0x40 bytes inside the
  owning section. The corpus requires exact source/packed DataDirectory
  geometry and matching `FindResourceW`/`LoadResource` bytes.
- `compat_delay_dll.dll` carries a real GuardCF `/DELAYLOAD` and unload IAT.
  Its host proves the dependency is absent before the first delayed call,
  loaded by that call, explicitly unloaded, and clean over eight reloads.

The DLL lane is no longer blocked on ordinary exports, static consumers,
loader-preloaded dependencies, TLS, x64 unwind, offset-root resources, DLL
delay-load, or compatibility-preserving anti-dump metadata sanitization. The
matrix now records process policy, anti-debug, and native executable-page memory
guard separately: local evidence advances those rows without implying that one
hardening mode proves the others. Candidate staging binds the complete opt-in
hardening pytest file to the exact fresh stub hash and rejects skips or partial
passes. DLL release remains blocked on native anti-debug host behavior,
provenance, and clean-VM evidence. Selected-function virtualization now keeps
the original GFID/XFG identity at the source RVA and reaches its generated thunk
only through the direct entry `E9`; the thunk is never declared as a generated
GFID. Crafted generated-thunk GFIDs remain fail-closed.

The release stub deliberately contains both VM execution capabilities. Internal
hand-authored programs may use history-keyed rolling containers, while lifted
selected functions remain independently encrypted and authenticated per page.
Candidate promotion and release rebuild configure `DVM_ROLLING=ON` and
`DVM_ROLL_POISON=OFF`; the latter is explicit so an `anti_debug=off` pack remains
compatible with `DEBUG_PROCESS` control. A rolling-capable stub is therefore not
a reason to reject paged selected-function materialization, which continues to
pass `rolling=False` and `paged=True`.
The candidate-bound runtime command is mandatory during promotion and release
replay. It runs `test_native_runtime_hardening_stress.py` together with
`test_native_virtualization_runtime.py` against the exact rebuilt artifact,
requires all seven native cases without skips, and proves the selected leaf emits
a paged-v1 program whose eager and memory-guard packed outputs match the original.
The hardening side also runs a bounded one-minute, minimum-64-launch forced-ASLR
memory-guard soak and proves that a debugged host rejects an anti-debug protected
DLL without terminating the host process.

The harness captures the packer's stdout and stderr independently. Runtime
stdout, stderr, and exit code are recorded in JSON even when the packed process
fails before `main`.

```powershell
.\tests\build_production_corpus.ps1 -OutDir .test-production-corpus
.\tests\production_corpus.ps1 `
  -StubPath .\stub\build\Release\lethe_stub_x64.dll `
  -BuildDir .test-production-corpus `
  -EvidencePath .test-production-corpus\evidence.json

python tools\production_gate.py `
  --scope exe `
  --evidence .test-production-corpus\evidence.json
```

Use `--scope dll` for the DLL contract and `--scope all` for the complete
product claim. Both remain red while any required DLL row is non-proven.
`--validate-only` checks schema and evidence references without
claiming readiness; CI runs that mode so the red development declaration stays
machine-readable while work continues.

## What a green result means

A green gate proves only the declared first-party corpus at the recorded source
and stub hashes. Release approval additionally requires the clean-VM, signing,
scanner, and application-workflow evidence named in the matrix. The gate must
remain red until those records exist; changing a status without supplying its
named evidence is not a valid release action.

Candidate and production release identity are separate. The candidate manifest
hashes a frozen candidate matrix and promotion evidence. A detached Ed25519
attestation later binds that candidate, the current green release matrix, the
release-source commit, and every external evidence record. The verifier trusts
only active public keys pinned in `packer/release_trust.json` and re-evaluates
the all-scope gate with the bundled native evidence. Scanner, clean-VM, and
application documents also require detached Ed25519 provider attestations from
non-revoked keys authorized by evidence kind in `packer/evidence_trust.json`.
That separate policy requires accepted Authenticode signer and
timestamp-authority thumbprints; its checked-in empty state blocks
production release. Authenticode, scanner, and
application evidence is subject-bound to the actual packed output and records
which candidate stub protected it; signing never masquerades as an unchanged
candidate-DLL hash. Release signing first snapshots every input and performs a
clean Git-archive rebuild with the candidate's exact seed and toolchain; the
rebuilt DLL must be byte-identical and must pass replayed CTest, native runtime
hardening, EXE/DLL roundtrip, and production-corpus gates. External evidence
uses one shared subject registry that includes both an AMD64 PE32+ EXE and DLL.
Every subject must pass independently replayed Windows Authenticode validation,
Defender plus an independent scan, at least two application workflows, and the
four declared clean-VM cells with machine-image, state, and runner identities.
Provider signatures bind each canonical document plus its declared hashes.
Portable contained paths retain the packed subjects, pack reports, protection
profiles, per-engine scanner output and receipts, per-cell VM logs, and
structured application result/log pairs so the producer and verifier both
rehash the underlying evidence.
Release-signing and evidence-provider key IDs are required to be disjoint,
including revoked entries, preventing accidental reuse across trust roles.
