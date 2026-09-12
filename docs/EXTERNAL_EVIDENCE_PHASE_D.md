# Phase D: finalized evidence reload and replay

`packer.external_evidence_phase_d` reloads the flat directory written by Phase
B's `publish_evidence()`. It independently reverifies the retained receipts and
Authenticode results, then requires a byte-for-byte replay of the historical
publication. It is an evidence-only boundary and always returns
`release_authorized=False`.

## API and independent pins

```python
import hashlib
from datetime import datetime
from pathlib import Path

from packer.external_evidence_phase_d import load_finalized_evidence

# Persist both values through a trusted channel when Phase B publishes.
expected_context_id = finalized.context_id
expected_manifest_sha256 = hashlib.sha256(finalized.manifest_bytes).hexdigest()

def verify_authenticode(subject_bytes: bytes, reference_time: datetime):
    # Trusted integration returns Phase B AuthenticodeResult after validating
    # the supplied bytes at exactly reference_time with chain, timestamp, and
    # revocation enforcement. It does not reopen or execute the subject.
    ...

result = load_finalized_evidence(
    Path("private-evidence/finalized"),
    expected_context_id=expected_context_id,
    expected_manifest_sha256=expected_manifest_sha256,
    current_trust_document=current_trust_bytes,
    authenticode_verifier=verify_authenticode,
)
assert result.release_authorized is False
assert result.published.manifest_bytes == finalized.manifest_bytes
```

The manifest digest and prepared-context ID must be retained independently;
values copied from the directory are not pins. The bundled `current-trust`
artifact must exactly equal the caller-supplied canonical bytes. Current policy
is re-evaluated, so provider revocation and Authenticode pin removal fail the
reload.

## Two reference-time passes

Reload first calls Phase B finalization with caller `now` and current trust.
It then calls it again with the manifest's recorded `finalized_at_utc`. Every
recorded Authenticode `verified_at_utc` must equal that time, which must not be
future-dated and must lie inside the challenge interval. The historical pass
must reproduce the canonical manifest and every ordered artifact byte exactly.

The verifier is therefore called twice per subject with explicit reference
times. A verifier integration must interpret its time argument as the requested
verification reference time; silently substituting wall-clock time fails the
result checks. A challenge still must be valid at caller `now`; reload does not
renew expired evidence.

## Read and storage boundary

`manifest.json` is captured with a 1 MiB ceiling. Its SHA-256 must match the
external manifest pin immediately after capture, before directory inventory or
any manifest-directed read. The manifest is strict canonical JSON: duplicate
keys, unknown fields, noncanonical bytes, wrong schema/kind, or any authority
claim fail closed.

The loader enforces exact flat membership and exact
`artifact-NNNNN-<sha256>.bin` names, order, purpose, hash, and size. It rejects
missing/extra/case-aliased entries, directories, nonregular files, links,
junctions, reparse points, and hardlinks. Directory membership/identity and
captured-file identities are checked again after replay. Callers must keep the
storage parent private and stable; this is a consistency boundary, not a held
directory transaction.

Control JSON uses fixed 1 MiB limits and raw signatures use a fixed 64-byte
limit. Prepared candidate/subject material is not read until manifest metadata
recomputes the externally pinned Phase B context ID, which commits its sizes.
Signed-subject and backing reads occur only through
`verify_detached_receipt_lazy`, after the provider signature and the complete
receipt metadata set pass validation. Their read budgets come from signed
receipt sizes. A malformed later backing triggers no material callback. Each
bundle file is snapshotted at most once; replay never uses original source
paths.

## Integration boundary

Phase D does not collect observations, build, sign, execute, publish, or approve
artifacts. It supplies no default candidate or Authenticode verifier and is not
wired into `tools/release_stub.py`. Provider CLI orchestration and release-gate
authorization remain later cuts.

Focused checks:

```powershell
python -B -m pytest -q -p no:cacheprovider tests/test_strict_json.py tests/test_pe_content_id.py tests/test_external_evidence_v2.py tests/test_external_evidence_phase_c.py tests/test_external_evidence_phase_d.py
```
