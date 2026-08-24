# Lethe — Complete Operations Guide

Step-by-step instructions for packing Orion binaries with the 3-tier server
shard gate, from build to deployment.

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python 3.10+ | with `lief`, `cryptography` | `pip install lief cryptography` |
| Visual Studio 2022 | x64 C/C++ workload | VS Installer |
| AWS CLI | 2.x | `winget install Amazon.AWSCLI` (for shard admin only) |

---

## Architecture Overview

```
User clicks OrionLauncher.exe
        │
        ├── 1. SHA-256 hash packed OrionNative.exe → build_id
        ├── 2. Read license_key from settings.json
        ├── 3. Compute HWID
        ├── 4. POST /api/shard/fetch → get 16-byte shard
        ├── 5. Set NV_RT_GATE env var
        └── 6. Spawn OrionNative.exe (packed)
                │
                └── Stub reads NV_RT_GATE, XORs into AES key,
                    decrypts all sections, runs original code
```

**Three tiers of protection:**

- **Tier 1 — Anti-fingerprinting:** LETHE01 magic zeroed in output, section
  names deduplicated, invariant strings stripped
- **Tier 2 — Key scattering:** 8 key fragments scattered across random
  VirtualAlloc pages with XOR-encrypted descriptor table
- **Tier 3 — Server shard gate:** 16-byte random shard XOR'd into the AES key
  at build time; the packed binary cannot decrypt without fetching the shard
  from the AWS Lambda shard gate at runtime

---

## 1. Build the Stub (one-time / when stub sources change)

```powershell
powershell tools\security\packer\stub\build_stub.ps1
```

Or manually:

```powershell
cmake -S tools\security\packer\stub -B build_stub -G "Visual Studio 17 2022" -A x64
cmake --build build_stub --config Release
# Copy the built DLL to the prebuilt location:
copy build_stub\Release\lethe_stub_x64.dll tools\security\packer\stub\prebuilt\
```

Only needed when any file in `stub/src/` changes. The packer uses the
checked-in prebuilt — no compiler needed at pack time.

---

## 2. Build the Bootstrap Launcher (one-time / when shard_bootstrap.c changes)

```powershell
cmake -S tools\security\packer\bootstrap -B build_bootstrap -G "Visual Studio 17 2022" -A x64
cmake --build build_bootstrap --config Release
```

Output: `build_bootstrap\Release\OrionLauncher.exe` (17.5 KB).

---

## 3. Pack a Binary

### Without server shard (Tier 1 + 2 only)

```powershell
cd tools\security\packer
python lethe.py <input.exe> <output.exe>
```

### With server shard (Tier 1 + 2 + 3) — production use

```powershell
cd tools\security\packer
python lethe.py <input.exe> <output.exe> ^
    --server-shard ^
    --shard-url https://api.zaeorion.com/api/shard ^
    --shard-auth <BUILDER_SECRET>
```

The `BUILDER_SECRET` is stored in `tools/security/packer/.env` (gitignored).

**CLI flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--dll` | auto-detect | Force DLL mode |
| `--anti-debug on\|off` | `on` | Gated debugger checks |
| `--memory-guard` | off | On-demand page decryption (AV-test first) |
| `--level N` | `9` | LZMA compression level (0-9) |
| `--server-shard` | off | Enable Tier 3 server shard |
| `--shard-url URL` | — | Shard gate endpoint |
| `--shard-auth TOKEN` | — | Bearer token for shard upload |
| `--verbose` | off | Show build progress + raw result |

---

## 4. Deployment Layout

Ship these files together in the install directory:

```
OrionLauncher.exe       ← user's shortcut / Start Menu points here
OrionNative.exe         ← packed with --server-shard
settings.json           ← created on first activation (contains license_key)
```

The user always launches `OrionLauncher.exe`, never `OrionNative.exe` directly.
Without the shard, the packed binary fails to decrypt and exits silently.

---

## 5. AWS Lambda Shard Gate API

### Deployed at: `api.zaeorion.com/api/shard/*`

Backend: AWS Lambda + DynamoDB (`orion-shards`) + SSM (`/orion/shard_encryption_key`).

**Endpoints:**

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/shard/store` | Bearer (BUILDER_SECRET) | Upload shard at build time |
| `POST` | `/api/shard/retrieve` | License key + HWID | Retrieve shard at launch (rate-limited) |
| `POST` | `/api/admin/shard/revoke` | Bearer (BUILDER_SECRET) | Brick a build remotely |
| `GET`  | `/api/admin/shard/status` | Bearer (BUILDER_SECRET) | Check shard status |

### Revoke a build (brick all copies remotely)

```powershell
curl -X POST https://api.zaeorion.com/api/admin/shard/revoke ^
  -H "Authorization: Bearer <BUILDER_SECRET>" ^
  -H "Content-Type: application/json" ^
  -d "{\"build_id\": \"<build-uuid>\"}"
```

The `build_id` is the UUID returned by the packer (shown in CLI output and `PackResult.build_id`).

---

## 6. Full Release Sequence

```
1. Build stub          (if stub/src/* changed)
2. Build bootstrap     (if shard_bootstrap.c changed)
3. Pack first-party binaries with --server-shard
4. Verify:
   a. Run roundtrip.ps1 (8/8 pass)
   b. Defender scan (MpCmdRun -Scan -ScanType 3 -File <packed.exe>)
   c. Run packed binary, confirm identical behavior
5. Authenticode sign the packed binaries (signtool, after pack)
6. Ship: OrionLauncher.exe + packed OrionNative.exe + settings.json template
```

### Never pack these:

| Binary | Reason |
|--------|--------|
| `Qt6*.dll` | Third-party; plugin machinery breaks |
| `opencv_world4110.dll` | Third-party |
| `ViGEmClient.dll` | Third-party controller client |
| `libcrypto-3-x64.dll` | Hash-pinned for Ed25519 |
| `OrionSidecar.exe` | Python/Nuitka bundle |
| `OrionStream.exe` | Streaming runtime |

---

## 7. AV Smoke Test

```powershell
# Scan individual files
& "C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File <packed.exe>

# Run the packed binary and confirm it works
.\sample_exe.packed.exe
# Expected: same output and exit code as the original
```

If Defender flags a packed binary, try `--anti-debug off` to isolate whether
the anti-debug module is the trigger. Report the finding and A/B before shipping.

---

## 8. Secrets Reference

Stored in `tools/security/packer/.env` (gitignored, never committed):

| Secret | Where it's used | Stored in |
|--------|-----------------|-----------|
| `ORION_BUILDER_SECRET` | `--shard-auth` when packing | Lambda env var `BUILDER_SECRET` |
| `ORION_EDGE_AUTH_SECRET` | Lambda ↔ license API auth | Lambda env var `EDGE_AUTH_SECRET` |
| Shard encryption key | At-rest encryption of shards in DynamoDB | SSM `/orion/shard_encryption_key` |

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Packed binary exits immediately | Missing/wrong shard | Check NV_RT_GATE env var is set; verify build_id matches |
| `"License validation failed (403)"` at launch | Invalid or expired license | Re-activate in settings.json |
| `"Too many launch attempts"` | Rate limit (30/hr per license) | Wait 1 hour |
| `"Build not recognized (404)"` | build_id not in KV | Re-pack and upload; or the build was revoked |
| `ModuleNotFoundError: pe_analyze` | Running lethe.py from wrong directory | `cd tools\security\packer` first |
| Defender quarantines packed binary | Anti-debug or memguard triggered AV | Try `--anti-debug off`; never ship `--memory-guard` without Defender testing |
| Packed DLL fails LoadLibrary | Bounds check regression | Rebuild stub (`build_stub.ps1`) |

---

## 10. File Reference

```
tools/security/packer/
├── lethe.py              CLI front-end
├── packer/
│   ├── container.py          ABI (PackInfo + SectionDesc structs)
│   ├── pe_analyze.py         LIEF PE parser
│   ├── payload.py            LZMA + AES-GCM encryption
│   ├── assemble.py           Output PE assembly + shard XOR
│   └── orchestrator.py       pack_file() — the one API
├── stub/
│   ├── src/                  Native C stub (pe_loader, crypto, anti-*)
│   ├── prebuilt/             Checked-in compiled stub DLL
│   └── build_stub.ps1        Build script
├── bootstrap/
│   ├── shard_bootstrap.c     Bootstrap launcher source
│   └── CMakeLists.txt        Build config
├── gui/
│   ├── app.py                PySide6 GUI
│   └── build_gui.ps1         Nuitka freeze script
├── tests/
│   ├── roundtrip.ps1         End-to-end acceptance test
│   ├── build_samples.ps1     Compile sample EXE/DLL/host
│   └── sample/               Sample source files
├── .env                      Secrets (gitignored)
├── README.md                 Design documentation
├── RUNBOOK.md                Operational runbook
└── OPERATIONS.md             This file
```
