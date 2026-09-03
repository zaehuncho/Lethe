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
loader-preloaded dependencies, TLS, x64 unwind, offset-root resources, or
DLL delay-load. It remains non-release while the matrix records hardening,
provenance, and clean-VM rows as non-proven. Generated virtualization thunk
GFIDs remain fail-closed for XFG-enabled sources because the planner does not
synthesize the source-compatible 8-byte XFG function hash.

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
