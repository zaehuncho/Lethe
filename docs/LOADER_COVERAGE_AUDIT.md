# Lethe PE Loader — Functional Coverage Audit

*Goal: functionality is paramount — a protector that bricks the app is worthless.
This audits which PE features the stub loader (`stub/src/pe_loader.c`) + the
builder (`packer/`) handle, so real packed EXEs still run.*

## Coverage

| Feature | Status | Notes |
|---|---|---|
| Base relocations (`.reloc`) | **OK** | `apply_relocs` handles `DIR64`/`ABSOLUTE`; eager + memguard-deferred passes, filtered by exec/non-exec (`pe_loader.c:446`, applied `:884`). |
| Imports (normal IAT) | **OK** | Import blob resolved at load; import elision hides the table. |
| **Forwarded exports** | **EXPERIMENTAL** | Runtime resolution exists, but packed DLLs are not release-approved and static consumers cannot resolve the encrypted export table before `DllMain`. |
| TLS callbacks + data | **OK WITH SCOPE LIMITS** | The protected template (up to 4096 bytes) and callback RVA recipe persist for the module lifetime. The main thread receives `PROCESS_ATTACH`/`PROCESS_DETACH`; threads created after unpack receive a fresh template followed by `THREAD_ATTACH`, then `THREAD_DETACH` before their reserved block is wiped. For a dynamically loaded DLL, pre-existing threads receive the native raw TLS initializer from the outer anchor without a synthetic `THREAD_ATTACH`, matching Windows. That initializer is necessarily loader-visible plaintext. Abrupt `TerminateThread`/`TerminateProcess` does not deliver detach callbacks. |
| Exceptions (x64 `.pdata`) | **OK** | `RtlAddFunctionTable(pdata_rva, pdata_count)` so C++/SEH unwinding works after unpack (`:912`). |
| Resources (`.rsrc`) | **OK** | Preserved **plaintext** at `rsrc_rva` so `FindResource`/dialogs/version-info/manifest work (`payload.py:348`). |
| Section page protections | **OK** | Per-section `VirtualProtect`, **never RWX** ("drop W when X", `:41, :984`) — good for AV posture too. |
| Entry point (EXE / DLL / none) | **EXE SUPPORTED; DLL EXPERIMENTAL** | The release path is unmanaged x64 EXEs. DLL packing is fail-closed unless explicitly acknowledged because initialization currently runs under loader lock. |
| **Managed / .NET PE** | **FIXED** | Was: silently packed → broken. Now: `analyze_pe` **refuses** a CLR runtime header (`pe_analyze.py`). |
| **Delay-load imports** | **UNVERIFIED** | No explicit handling. Section bytes are preserved, so the app's own `__delayLoadHelper2` *probably* resolves them at runtime — but this is untested. **Needs a live `/DELAYLOAD` round-trip test.** |
| Load Config / CFG | **PARTIAL; FAIL-CLOSED OUTSIDE THE PROVEN ENVELOPE** | Supported PE32+ inputs emit a loader-visible `.lcfg` with bound relocations, exact Guard CF/IAT/long-jump/EH-continuation inventories, authenticated shadow copies of loader-populated SecurityCookie/GuardCF/XFG/CastGuard/GuardMemcpy slots, and runtime target registration. Current-SDK CastGuard (`0x01000000`) and guarded-memcpy (`0x02000000`) flags require their complete load-config slots, while a zero pre-load pointer remains valid. Unsupported families and generated-thunk XFG hashes fail before output mutation. Local native coverage exists; clean-VM enforcement evidence remains outstanding, so the production mitigation row stays partial. |
| Bound imports | **LIKELY OK** | Re-resolved via the normal INT/IAT; low risk. |
| Digital signature (cert dir) | **N/A** | Packing invalidates any Authenticode signature by design; re-sign the packed output (release pipeline does). |

## Top compatibility risks (ranked)

1. **DLL initialization and static exports.** Full unpacking can load dependencies under loader lock, and the original export table is unavailable to static import resolution before `DllMain`. DLL mode is therefore experimental and prohibited for releases.
2. **Static TLS confidentiality.** Windows must read a DLL's raw TLS initializer before its entry point, including for threads that predate `LoadLibrary`. Lethe mirrors up to 4096 bytes into the outer TLS anchor for correctness; do not treat that initializer as encrypted payload data.
3. **Delay-load imports (UNVERIFIED).** Build a sample that delay-loads a DLL, pack it, and confirm the delayed call resolves at runtime.
4. **TLS > 4096 bytes** is refused rather than emitted as a broken artifact. Forced thread/process termination also bypasses detach callbacks, matching Windows notification semantics.
5. **Load-config coverage is bounded.** Supported GuardCF/XFG-slot,
   CastGuard, GuardMemcpy, volatile-metadata, and target-table shapes preserve the
   emitted outer contract. Dynamic-value-relocation, CHPE, CodeIntegrity,
   return-flow guard, hotpatch, enclave, UMA, generated-thunk XFG hashes, and
   unrecognized GuardFlags remain blocked rather than stripped. Clean-VM CFG/XFG
   enforcement is still required before the mitigation row can advance.

## Verification still owed

- Force a nonzero relocation delta and exercise anti-debug/memory-guard variants on supported Windows versions.
- Re-run current-SDK GuardCF/XFG/CastGuard/GuardMemcpy fixtures on the declared
  clean-VM matrix and retain loader-enforcement evidence for the exact candidate.
- Round-trip `/DELAYLOAD`, large-TLS, and resource-heavy EXE fixtures. Native EXE and DLL callback fixtures cover the loading/main thread, a worker created after unpack/`LoadLibrary`, and a thread predating dynamic DLL load.
- Redesign DLL initialization outside loader lock and add both static-import and dynamic-load hosts before promoting DLL support.

## TLS and anti-dump visibility

NTDLL revisits the main image's PE header when it creates a worker for a
static-TLS EXE. Fully erasing the EXE header caused `CreateThread` to fail with
`ERROR_BAD_EXE_FORMAT` before the anchor dispatcher ran. TLS-bearing EXEs now
keep the same minimal `MZ -> PE -> optional-header` path retained for packed
DLL export compatibility. Consumed import/debug/TLS/bound-import/IAT directory
entries, the entry point, sizes, and section table are still cleared, and the
encrypted metadata envelope is still wiped. The tradeoff is explicit: a TLS
EXE exposes recognizable DOS/NT header structure in memory instead of receiving
the strongest full-header anti-dump erasure.
