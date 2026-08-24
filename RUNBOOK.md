# Lethe — operational RUNBOOK

Operational sequence for applying Lethe to an Orion release, the **never-pack**
list, how to register the container test in the release gate, and the
future pipeline-wiring work (documented now, not built).

> Lethe is applied **last**, after live sign-off — packing disables
> crash-dump / support triage on the protected binary
> (`RELEASE_SECURITY.md:126-156`). Do not pack a build you still need field crash
> telemetry from.

---

## 0. One-time / whenever stub sources change

```powershell
# (a) build the native stub -> refreshes stub\prebuilt\stub_x64.bin
powershell stub\build_stub.ps1

# (b) freeze the GUI -> Lethe.exe (bundles packer lib + LIEF + stub_x64.bin)
powershell gui\build_gui.ps1
```

Rebuild the stub after editing any `stub/src/*`. Pack-time itself needs no
compiler — only the checked-in `stub_x64.bin`.

---

## 1. Per-release sequence

1. **Build stub** (§0a) if `stub/src/*` changed since the last `stub_x64.bin`.
2. **Freeze GUI** (§0b) if you'll pack manually, or skip and use the CLI.
3. **Pack the first-party targets** — CLI (pipeline/manual) or GUI. Only the
   binaries in the release package's first-party list; honor the **never-pack**
   list (§2).
   ```powershell
   # EXE
   python lethe.py OrionOwner.exe OrionOwner.packed.exe
   # DLL (or rely on header auto-detect and drop --dll)
   python lethe.py SecurityCore.dll SecurityCore.packed.dll --dll
   ```
4. **Verify** each packed binary per the plan's Verification checklist (§3).
5. **Sign** (pipeline, *after* pack) and regenerate the manifest hash — see §5.

---

## 2. NEVER PACK — leave these untouched

Packing any of these will break the product, AV posture, or the pinned crypto
path. **First-party Orion code only** gets packed.

| Do NOT pack                         | Why                                                             |
|-------------------------------------|----------------------------------------------------------------|
| `Qt6*.dll` (Qt6Core, Qt6Gui, …)     | Third-party; huge; resource/plugin machinery breaks when packed |
| `opencv_world4110.dll`              | Third-party; not our code to protect                            |
| `ViGEmClient.dll`                   | Third-party controller-emulation client                        |
| `libcrypto-3-x64.dll`               | **Hash-pinned** for Ed25519 (`Ed25519.cpp:122-160`); the stub must never load/touch it. Packing changes its bytes ⇒ pin fails |
| `OrionSidecar.exe` (+ numpy / cv2)  | Python/Nuitka bundle with native numpy/cv2 deps; packing corrupts the embedded runtime |
| `OrionStream.exe`                   | Streaming runtime; excluded                                     |

Everything else third-party (VC runtime, system DLLs, api-ms-* etc.) is likewise
off-limits. When in doubt: **first-party Orion binary → yes; anything else → no.**

---

## 3. Verification checklist (plan "Verification (end-to-end)")

Automated by `roundtrip.ps1` unless marked *manual*.

| #  | Check | How |
|----|-------|-----|
| 1  | Stub builds, `stub_x64.bin` refreshed | §0a |
| 2  | **EXE round-trip**: packed == original stdout + exit code; imports absent from packed import dir; high-entropy payload; `.rsrc`/version/icon intact | `roundtrip.ps1` (behavioral); *manual* PE-viewer for entropy/imports/rsrc |
| 3  | ASLR/DEP: packed still has `DYNAMICBASE`+`NXCOMPAT`; forced-reloc exercises the reloc path; **no RWX pages** | *manual* (Process Hacker / VMMap; forced-ASLR) |
| 4  | **DLL round-trip**: `host.exe` LoadLibrarys the packed DLL, resolves the export, gets the known value, DllMain ran | `roundtrip.ps1` |
| 5  | Signability: `signtool sign` a test cert on the packed EXE; `signtool verify /pa` passes | *manual* |
| 6  | **AV smoke**: drop packed output on a clean Windows Defender VM; confirm no quarantine | *manual* — do this every release |
| 7  | **pytest** green + registered in the gate | §4 |
| 8  | Anti-dump (v1): dump the running packed EXE (Task Mgr / PE-sieve) → erased headers, no compressed payload/loader bytes; an unsigned test DLL fails to inject | *manual* |
| 9  | Memory-guard (opt-in): pack `--memory-guard`, snapshot mid-run → only a small working set is plaintext; re-run #2 with the flag to prove correctness + measure perf | *manual* |
| 10 | GUI: add a sample EXE+DLL, pick options, Pack → working packed binaries, per-file result rows, errors surface in the log | *manual* |

**Harness exit codes:** `roundtrip.ps1` → **0** PASS · **2** SKIP (a prerequisite
was missing — no MSVC, or `lethe.py`/`stub_x64.bin` not built yet — nothing
tested) · **1** FAIL (a step that ran failed). `build_samples.ps1` → **0** built ·
**3** SKIP (no MSVC `cl.exe`) · **1** compile/link failed.

---

## 4. Register the container test in the release gate

`tests/test_lethe_container.py` is the gate-registered container ABI test
(pure Python, no third-party deps — passes now). It should be added to the
explicit pytest list in **`scripts/verify_orion.ps1`** (the
`"[orion] Python sidecar tests"` step, around **lines 170–196**).

> **Do NOT** let an agent silently rewrite `verify_orion.ps1` — it is a shared
> release script. Make this one-line addition deliberately. This RUNBOOK
> documents it rather than editing the script.

That step is a single `& $Python -m pytest <list> -q` with backtick-continued
lines; `tests\test_packing_workflow.py` is already in it (around line 192). Add
the container test as a neighbor, e.g.:

```powershell
        tests\test_release_packaging.py `
        tests\test_packing_workflow.py `
        tests\test_lethe_container.py `      # <-- add this line
        tests\test_orion_admin.py `
```

(The `tests\test_lethe_container_abi.py` cross-check
also passes now and is collected by a plain `python -m pytest` from the repo
root, since `tests` is not in `pytest.ini`'s
`norecursedirs`; add it to the explicit gate list too if you want it enforced by
name.)

---

## 5. Future pipeline-wiring (plan "Later-phase notes" — documented, not built)

When the product ships and packing goes live, wire Lethe into
`tools/security/pack_lethe_release.py`:

- **Point `--packer-command` at Lethe** (no pipeline change required — the
  CLI already matches the `{input} {output}` contract):
  ```
  --packer-command "python lethe.py {input} {output}"
  ```
- **Add `OrionCommon.dll` to `DEFAULT_TARGETS`** — it is currently missing from
  the target list (`pack_lethe_release.py:33-43`, which lists OrionOwner/Staff/
  Native/Updater `.exe` + AutomationCore/Vision/RemotePlay/Security/Updater
  `.dll`).
- **Insert an Authenticode step** — no `signtool` step exists yet. Sign
  **between pack and manifest-hash** per `IP_PROTECTION_PLAN.md:279-286`, then
  flip `enforce_authenticode: true`. Packing preserves `.rsrc`/version/manifest,
  so packed output stays signable.
- **Phase 2 (before packing):** clang-cl + OLLVM-style control-flow flattening /
  string encryption / symbol stripping on the gameplay DLLs, applied *before*
  Lethe for defense-in-depth. Not built here.

**Reminder:** packing is a client-side tamper-resistance layer only.
Authorization is enforced server-side (native C++); a client dump does not bypass
it.
