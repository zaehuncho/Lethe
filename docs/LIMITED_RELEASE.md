# Limited v1 shipping profile

`tools/pack_limited_release.py` is the narrow path for shipping a first product
before Lethe's full production matrix is complete. It does not weaken or replace
the strict public-release gate. It creates a separate, explicit
`lethe-limited-v1` bundle from an intact schema-2 candidate.

The profile supports unmanaged AMD64 PE32+ EXEs and DLLs that pass Lethe's
preflight. Exported EXEs require a matching export-capable stub
(`lethe_exe_export_abi=1`); older stubs fail closed. Native tests cover named,
ordinal-only, data and forwarded exports after startup, plus a plugin loaded
after startup calling into the EXE during plugin attach. **Original dependencies
calling into the EXE during early attach remain unsupported** and fail the
separate characterization test. DLL exports remain in the
declared DLL fixture envelope; name/ordinal parity alone is not runtime proof.
The profile uses compression, authenticated encrypted sections, relocation,
TLS, resource, import, EXE/DLL-export, and unwind handling from the base packer. It keeps
anti-debug, memory guard, process hardening, tamper monitoring, server shards, and selected-function
virtualization disabled.

```powershell
uv run python tools/pack_limited_release.py `
  --stub-path C:\path\to\candidate\lethe_stub_x64.dll `
  --exe C:\path\to\product.exe `
  --dll C:\path\to\product.dll `
  --output-dir C:\path\to\new-dist-directory
```

The destination must not already exist. Both files are staged and structurally
validated before the directory is published. A failure leaves no partial output.
`lethe-limited-release.json` records source hashes, packed hashes, sizes, build
IDs, the exact candidate hash and source commit, and the disabled features.
The helper reserves its manifest filename (case-insensitively), binds all source
files before packing, and rechecks every source and validated output before
publication. Missing, replaced, linked or changed files abort the transaction;
concurrent source edits are preserved, never rolled back by the helper. These
checks detect drift at their checkpoints, not arbitrary writes after publication.

Export snapshots retain their original mapped size and RVA but omit trailing
zero-only file padding beyond the export span. This reduces file overhead without
changing the authenticated export bytes or the restored source payload. Small
inputs may still grow because they must include the runtime.

Before distribution:

1. Authenticode-sign and timestamp after packing, then verify those signatures.
2. Regenerate and sign any application integrity/release manifests over the final
   distributed bytes, after packing and PE signing have finished. Use the existing
   product manifest pipeline; do not disable integrity checks or patch signature
   verification to accommodate stale hashes. Both packing and PE signing change
   file hashes, so an unchanged pre-pack product manifest is not runtime acceptance.
3. Run the packed EXE through startup, shutdown, update, and core workflows with
   the product's integrity verification enabled.
4. Load the packed DLL through the real host and exercise attach, exported APIs,
   worker threads, detach, unload, and reload paths used by the product.
5. Scan the exact final package.
6. Canary the exact signed hashes and retain the unpacked symbolized build.

This profile is suitable only for inputs whose own workflows pass. Unsupported
PE shapes still fail closed during packing; a successful structural validation
does not substitute for the product-specific runtime checks above.
