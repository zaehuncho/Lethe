# Lethe PE Loader — Functional Coverage Audit

*Goal: functionality is paramount — a protector that bricks the app is worthless.
This audits which PE features the stub loader (`stub/src/pe_loader.c`) + the
builder (`packer/`) handle, so real packed EXEs still run.*

## Coverage

| Feature | Status | Notes |
|---|---|---|
| Base relocations (`.reloc`) | **OK** | `apply_relocs` handles `DIR64`/`ABSOLUTE`; eager + memguard-deferred passes, filtered by exec/non-exec (`pe_loader.c:446`, applied `:884`). |
| Imports (normal IAT) | **OK** | Import blob resolved at load; import elision hides the table. |
| **Forwarded exports** | **OK** | `resolve_forwarder` handles `DLL.Func` / `DLL.#ord`, recursion capped at depth 5 (`pe_loader.c:185, 316`). |
| TLS callbacks + data | **OK** (capped) | `invoke_tls_callbacks` run *after* final page protections so code is RX (`:495, 1007`). **Cap: TLS template ≤ 4096 bytes** (`payload.py:399`) — larger templates are *refused* (graceful, not a brick). |
| Exceptions (x64 `.pdata`) | **OK** | `RtlAddFunctionTable(pdata_rva, pdata_count)` so C++/SEH unwinding works after unpack (`:912`). |
| Resources (`.rsrc`) | **OK** | Preserved **plaintext** at `rsrc_rva` so `FindResource`/dialogs/version-info/manifest work (`payload.py:348`). |
| Section page protections | **OK** | Per-section `VirtualProtect`, **never RWX** ("drop W when X", `:41, :984`) — good for AV posture too. |
| Entry point (EXE / DLL / none) | **OK** | `is_dll` captured; DLL vs EXE OEP paths in `stub_main.c`. |
| **Managed / .NET PE** | **FIXED** | Was: silently packed → broken. Now: `analyze_pe` **refuses** a CLR runtime header (`pe_analyze.py`). |
| **Delay-load imports** | **UNVERIFIED** | No explicit handling. Section bytes are preserved, so the app's own `__delayLoadHelper2` *probably* resolves them at runtime — but this is untested. **Needs a live `/DELAYLOAD` round-trip test.** |
| Load Config / CFG | **DROPPED (known)** | Packing doesn't carry CFG (documented regression, `docs/POST_LAUNCH_HARDENING.md`). Fine for non-network-reachable game/UI/license logic; be explicit per-binary. |
| Bound imports | **LIKELY OK** | Re-resolved via the normal INT/IAT; low risk. |
| Digital signature (cert dir) | **N/A** | Packing invalidates any Authenticode signature by design; re-sign the packed output (release pipeline does). |

## Top brick risks (ranked)

1. **Delay-load imports (UNVERIFIED).** Real apps commonly `/DELAYLOAD` optional DLLs. Build a sample that delay-loads a DLL, pack it, and confirm the delayed call resolves at runtime. If it breaks, capture + preserve the `DELAY_IMPORT_DESCRIPTOR` directory (LIEF exposes it) and its IAT.
2. **Managed/.NET — FIXED** this pass (now refused up front instead of silently broken).
3. **TLS > 4096 bytes** — refused, not bricked, but a coverage cap. Raise `STUB_TLS_CAPACITY` (+ the C `tls_anchor` reservation) if a real target needs more.
4. **CFG dropped** — known/accepted; document per packed binary.

## Verification still owed (needs a live MSVC build + run — not doable offline here)

- Round-trip a `/DELAYLOAD` EXE, a large-TLS EXE, and a resource-heavy EXE (dialogs/icons) and confirm each **runs** after packing.
- The existing `tests/roundtrip.ps1` harness is the right place to add these fixtures.
