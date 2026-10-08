# Limited v1 shipping profile

`tools/pack_limited_release.py` is the narrow path for shipping a first product
before Lethe's full production matrix is complete. It does not weaken or replace
the strict public-release gate. It creates a separate, explicit
`lethe-limited-v1` bundle from an intact schema-2 candidate.

The profile supports unmanaged AMD64 PE32+ EXEs and DLLs that pass Lethe's
preflight. EXEs with export directories are rejected: the current EXE assembler
does not preserve their loader-visible export table. DLL exports remain in the
declared DLL fixture envelope; name/ordinal parity alone is not runtime proof.
The profile uses compression, authenticated encrypted sections, relocation,
TLS, resource, import, DLL-export, and unwind handling from the base packer. It keeps
anti-debug, memory guard, process hardening, server shards, and selected-function
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

Before distribution:

1. Run the packed EXE through the product's startup, shutdown, update, and core
   workflows.
2. Load the packed DLL through the real host and exercise attach, exported APIs,
   worker threads, detach, unload, and reload paths used by the product.
3. Scan the exact packed files.
4. Authenticode-sign and timestamp after packing, then verify those signatures.
5. Canary the exact signed hashes and retain the unpacked symbolized build.

This profile is suitable only for inputs whose own workflows pass. Unsupported
PE shapes still fail closed during packing; a successful structural validation
does not substitute for the product-specific runtime checks above.
