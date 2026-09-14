# Phase C: durable prepared evidence

`packer.external_evidence_phase_c` persists the immutable `PreparedEvidence`
created by Phase B so another process can collect and verify detached receipts
against the same preparation. It serializes data, never Python objects or
pickle, and never executes an artifact.

## API and independently retained commitment

```python
from pathlib import Path
from packer.external_evidence_phase_c import (
    load_prepared_bundle,
    publish_prepared_bundle,
)

# `prepared` comes from Phase B's prepare_evidence with a trusted, bytes-only
# candidate verifier. Persist this pin separately through a trusted channel.
expected_context_id = prepared.context_id
bundle_dir = Path("private-evidence") / "new-preparation"
descriptor_path = publish_prepared_bundle(prepared, bundle_dir)

# In a later process, supply the separately retained pin, not a value read
# from prepared.json. The parent of bundle_dir must already exist.
reloaded = load_prepared_bundle(
    bundle_dir, expected_context_id=expected_context_id,
)
assert reloaded.context_id == expected_context_id
# Use reloaded with Phase B's ingest_receipt and finalize_evidence APIs.
```

Both operations accept an optional aware `now` for controlled verification
and tests; otherwise they use the current time. Reload validates the challenge
again, including expiry. Persistence neither renews a challenge nor substitutes
for a new preparation when the original expires.

The pin commits to the prepared bytes and candidate-verifier assertion.
Matching it detects changed content relative to that independently retained
commitment; it does not establish provenance on its own. Reload does not rerun
the candidate verifier. A pin copied from the untrusted bundle is not an
independent check. Finalization still requires current trust-policy validation
and the explicit bytes-only Authenticode verifier required by Phase B.

## Bundle format

The new flat directory contains canonical `prepared.json` plus one
`<lowercase-sha256>.bin` file per distinct retained byte sequence. Equal
content used by multiple purposes shares a file and is captured only once
during reload. The descriptor uses its own schema version 1 and kind
`lethe-prepared-evidence-bundle`; this does not modify the v1 release schemas
or v2 challenge/receipt schemas.

The exact descriptor fields are `schema`, `kind`, `release_authorized`,
`context_id`, `candidate_verification`, `candidate`, `subjects`, and `files`.
`release_authorized` must be `false`. Each file record has only `purpose`,
`path`, `sha256`, and integer `size_bytes`. Purpose ordering is:

1. `challenge`, `initial-trust`, `candidate-stub`, `candidate-manifest`,
   `production-native`;
2. for each retained subject in order: `<subject_id>:unsigned`,
   `<subject_id>:input`, `<subject_id>:pack_report`, and
   `<subject_id>:protection_profile`.

Original snapshot path, inode, device identity fields, and executable callbacks
are not serialized. Retained file contents remain verbatim and may themselves
contain paths; publication does not scrub them. Reload returns new immutable snapshots whose paths and filesystem
identities describe the bundle captures. Their bytes, hashes, sizes, subject
order, and context commitment match the preparation; full dataclass equality
with the original path-bearing snapshots is not expected.

## Validation and storage contract

The loader rejects duplicate JSON keys, noncanonical or oversized descriptor
JSON (over 1 MiB), unknown fields, invalid types, duplicate or reordered
purposes, incorrect subject bindings, candidate-verification mismatches,
changed hashes or sizes, and a missing or mismatched external pin. Artifact
names must exactly equal their digest plus `.bin`, excluding absolute paths,
traversal, and case aliases. Directory membership must be exact. Links,
junctions, reparse points, hard-linked files, subdirectories, and nonregular
entries are rejected; ancestor directories are checked too. The restored
context is revalidated by Phase B before it is returned.

Descriptor capture itself is capped at 1 MiB before its contents are read.
After strict descriptor validation, the loader recomputes the existing Phase B
context commitment from the challenge/trust hashes, candidate-verification
record, and ordered material purpose/hash/size records. That commitment must
match the independently retained pin before any artifact capture. Candidate
source/hash bindings are checked separately against the candidate file records.

Each material capture is bounded by its pinned size, not an arbitrary PE size
ceiling. Challenge/trust sizes are not fields in the Phase B commitment, so
they retain a separate 1..1 MiB JSON bound. Shared contents are still captured
once; an empty opaque material file uses a one-byte budget and must still pass
the exact zero-size/hash check. `snapshot_file(max_bytes=...)` checks the held
handle's size before reading and reads at most the budget plus one sentinel
byte to detect growth. Its optional limit must be an exact positive integer
smaller than `sys.maxsize` so the sentinel read size is representable. Existing
callers that omit the limit keep their previous behavior. These pre-read checks
do not replace the full post-capture challenge/trust/material validation.

Publication validates retained bytes without reopening original sources. It
creates a new directory exclusively, writes each file with exclusive creation,
flushes and fsyncs it, and writes `prepared.json` last. An existing directory,
even an empty one, is never overwritten. Failure leaves the partial directory
for inspection; use a new destination rather than resuming into it. A failed
descriptor write can leave a partial marker, so the marker's existence alone
never proves completion: only successful full reload does. File fsync and
marker ordering are not a claim of power-loss-atomic directory publication.

Callers provide a private, stable storage parent throughout publication and
reload. The loader compares root identity and exact membership before and
after captures, but this is not a held-directory guarantee against concurrent
hostile ancestor replacement. Each accepted file is retained as an immutable
byte snapshot, not later reopened from its path.

## Integration boundary

This module is evidence-only. It does not collect scanner/VM/application
results, run subject binaries, sign files, provide default candidate or
Authenticode verifiers, authorize a release, or change `tools/release_stub.py`.
It does not satisfy an external production-matrix row. Provider workflows may
resume Phase B intake/finalization from the reloaded preparation; production
release integration remains a separate cut.

Focused checks:

```powershell
python -B -m pytest -q -p no:cacheprovider tests/test_strict_json.py tests/test_pe_content_id.py tests/test_external_evidence_v2.py tests/test_external_evidence_phase_c.py
```
