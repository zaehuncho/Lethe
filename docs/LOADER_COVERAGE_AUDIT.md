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
| TLS callbacks + data | **PARTIAL** | Process-attach callbacks and a TLS template up to 4096 bytes are handled. The full thread/process callback lifecycle is not dispatched, so DLL support is experimental and TLS-heavy EXEs require application-specific testing. |
| Exceptions (x64 `.pdata`) | **OK** | `RtlAddFunctionTable(pdata_rva, pdata_count)` so C++/SEH unwinding works after unpack (`:912`). |
| Resources (`.rsrc`) | **OK** | Preserved **plaintext** at `rsrc_rva` so `FindResource`/dialogs/version-info/manifest work (`payload.py:348`). |
| Section page protections | **OK** | Per-section `VirtualProtect`, **never RWX** ("drop W when X", `:41, :984`) — good for AV posture too. |
| Entry point (EXE / DLL / none) | **EXE SUPPORTED; DLL EXPERIMENTAL** | The release path is unmanaged x64 EXEs. DLL packing is fail-closed unless explicitly acknowledged because initialization currently runs under loader lock. |
| **Managed / .NET PE** | **FIXED** | Was: silently packed → broken. Now: `analyze_pe` **refuses** a CLR runtime header (`pe_analyze.py`). |
| **Delay-load imports** | **UNVERIFIED** | No explicit handling. Section bytes are preserved, so the app's own `__delayLoadHelper2` *probably* resolves them at runtime — but this is untested. **Needs a live `/DELAYLOAD` round-trip test.** |
| Load Config / CFG | **DROPPED (known)** | Packing does not carry CFG, and the current hash-bound stub is also built without Guard CF. Treat this as a mitigation regression per binary; see `docs/RELEASE_CHECKLIST.md`. |
| Bound imports | **LIKELY OK** | Re-resolved via the normal INT/IAT; low risk. |
| Digital signature (cert dir) | **N/A** | Packing invalidates any Authenticode signature by design; re-sign the packed output (release pipeline does). |

## Top compatibility risks (ranked)

1. **DLL initialization and static exports.** Full unpacking can load dependencies under loader lock, and the original export table is unavailable to static import resolution before `DllMain`. DLL mode is therefore experimental and prohibited for releases.
2. **TLS lifecycle.** Only process-attach callbacks are dispatched. Thread/process detach behavior and new-thread initialization need native fixtures before broader support claims.
3. **Delay-load imports (UNVERIFIED).** Build a sample that delay-loads a DLL, pack it, and confirm the delayed call resolves at runtime.
4. **TLS > 4096 bytes** is refused rather than emitted as a broken artifact.
5. **CFG is dropped.** This is a documented mitigation regression and must be accepted per target binary.

## Verification still owed

- Force a nonzero relocation delta and exercise anti-debug/memory-guard variants on supported Windows versions.
- Round-trip `/DELAYLOAD`, large-TLS, TLS-callback, and resource-heavy EXE fixtures.
- Redesign DLL initialization outside loader lock and add both static-import and dynamic-load hosts before promoting DLL support.
