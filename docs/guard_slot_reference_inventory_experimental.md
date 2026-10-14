# Experimental exact-source GuardCF reference inventory

`lifter.guard_slot_references.collect_guard_slot_references` inventories an
unchanged AMD64 PE against an exact PDB coverage/commit binding. It does not
modify, pack, load or execute that PE. It does execute the explicitly supplied
DIA helper and DIA runtime on source snapshots. Those tools are operator-trusted
inputs; Python types, self-hashes and this API do not authenticate arbitrary
executables supplied by a caller.

## Required inputs and replay

The API requires all three arguments:

```python
inventory = collect_guard_slot_references(
    parsed, binding,
    pdb_inputs=PdbInputFiles(pdb=pdb_path, helper=helper_path, msdia=msdia_path),
)
```

`parsed` must be an actual `ParsedPE`, and `binding` an actual
`PdbCommitBinding`. `PdbInputFiles` is a frozen record of three `pathlib.Path`
values. There is no two-argument or missing-evidence fallback.

The collector checks the exact image/parsed fields and source digests, replays
the direct-flow binding, and reconstructs PDB coverage and the entire commit
binding through the existing real DIA snapshot pipeline. It checks the PDB
GUID/age against the PE RSDS record and rechecks evidence after collection.
A recomputed binding self-hash alone does not establish PDB provenance. Missing,
changed, mismatched or malformed evidence raises `GuardReferenceError`; invalid
Python call signatures retain normal Python argument errors.

The supported evidence path uses regular non-reparse files and bounded reads
under temporary Windows read/write/delete-sharing controls. These controls
preserve the inputs during the operation; they are not a claim of arbitrary
same-user filesystem tampering resistance or authenticity of a caller-selected
toolchain. No evidence or source file is repaired or overwritten on failure.

## What the immutable result means

The result records source/PDB/tool identities, load-config flags, file-backed
aligned guard slots, strict executable ownership, a unique instruction index,
fixed-address references, data-literal candidates and canonical alias windows.
CF-check, CF-dispatch and the three XFG slot kinds stay distinct. Presence of XFG
fields is not the same as `IMAGE_GUARD_XFG_ENABLED`.

Memory references use actual image VAs and `InstructionInfo.used_memory()` as
well as explicit operands. Full access spans are considered, not only start
addresses. This includes implicit stack/string/CALL effects. LEA remains address
taking, not a read. FS/GS, register-dependent addresses, unknown extents and
unproved wrapping semantics remain unresolved. Literal equality is a candidate
reference, not proof that a scalar is used as a pointer.

`unresolved` contains domain counts and at most eight example RVAs per domain.
Global boundary records have a count of one to mark an unresolved domain and
no example RVA; their counts are not observed instruction/site counts.
It is a **sampled domain summary**, not a complete per-instruction list of all
unknown references. A future transformer must not infer that unlisted sites are
absent. Large literal domains and resource/work bounds likewise cannot become
an absence proof. Collection can fail closed rather than silently truncate a
fixed-address candidate inventory.

`canonical_bytes()` emits deterministic inspection JSON. It is not a proof
importer. The result has no admission, indirect-closure or production-ready
success field. Known predecessor/metadata geometry does not exclude unknown
computed predecessors, runtime mutation, resident-runtime targets or external
host/callback routes. No packer/runtime admission path imports this experiment.

## Building and testing the contract

The generated contract tests build PE/PDB fixtures with MASM/LINK, then invoke
the real DIA/coverage/binding APIs. They do not execute generated fixture images
or NexusVision. Explicitly configure the trusted tools for the mandatory lane:

```powershell
$env:LETHE_GUARD_TEST_DIA_HELPER = 'C:\trusted-tools\pdb_function_dump.exe'
$env:LETHE_GUARD_TEST_MSDIA = 'C:\trusted-tools\msdia140.dll'
$env:LETHE_GUARD_REFERENCE_REQUIRE_NATIVE = '1'
python -B -m pytest -q -p no:cacheprovider tests/test_guard_slot_references.py
```

Without configured Windows MASM/LINK/DIA inputs, native fixture tests skip;
with `LETHE_GUARD_REFERENCE_REQUIRE_NATIVE=1`, missing inputs fail. A skip is not
native evidence. Optional exact-product static parity additionally requires
`LETHE_GUARD_REFERENCE_PRODUCT_ROOT` and `LETHE_GUARD_REFERENCE_PDB_ROOT`; it is
not application workflow or packed-product acceptance.

No GuardCF wrapper, alias retargeting, native-call waiver, changed prebuilt,
signing bypass or production promotion is included. A private alias-slot load
followed by post-CALL register normalization has a separately reproduced
synchronous CALL-fault context mismatch. That rejected proposal is not enabled
by collecting its source references. Clean-VM, final scanner, exact EXE/DLL-host
workflow and signed-release acceptance remain separate release requirements.
