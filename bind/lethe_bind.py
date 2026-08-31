"""Lethe binding manifest: pin a packed EXE's first-party dependencies by hash.

Anti-tamper for the normal multi-file app layout. Instead of physically merging
the app's DLLs into one EXE (fragile, AV-hostile, brick-prone), Lethe records the
SHA-256 of each FIRST-PARTY dependency in a manifest embedded in the packed EXE
(itself integrity-bound by the stub's code-hash key). At startup -- before control
reaches the app's original entry point -- the stub re-hashes the named sibling
files and refuses to run on any mismatch, so an attacker cannot swap a first-party
DLL for a patched one. Third-party / system DLLs are deliberately NOT pinned:
their legitimate updates would trip the check and they are not your IP.

The manifest can also be Ed25519-signed so it is tamper-evident as a standalone
sidecar; the stub pins the signer's public key by hash. This module is the
reference + builder the pipeline uses and the C verifier mirrors.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from typing import Dict, List

SCHEME = "lethe-bind-v1"
_CHUNK = 1 << 20


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class Manifest:
    scheme: str
    main: str            # main exe filename
    main_sha256: str
    deps: Dict[str, str] = field(default_factory=dict)   # filename -> sha256 hex

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> "Manifest":
        d = json.loads(text)
        return cls(scheme=d["scheme"], main=d["main"],
                   main_sha256=d["main_sha256"], deps=dict(d.get("deps", {})))

    def canonical_bytes(self) -> bytes:
        """Deterministic bytes for signing (sorted keys, no whitespace)."""
        return json.dumps(asdict(self), sort_keys=True,
                          separators=(",", ":")).encode()


def build_manifest(exe_path: str, dependency_paths: List[str]) -> Manifest:
    """Hash the main EXE and each first-party dependency into a manifest."""
    deps = {os.path.basename(p): sha256_file(p) for p in dependency_paths}
    return Manifest(scheme=SCHEME, main=os.path.basename(exe_path),
                    main_sha256=sha256_file(exe_path), deps=deps)


def verify_manifest(manifest: Manifest, base_dir: str, *,
                    check_main: bool = False) -> List[str]:
    """Re-hash the pinned files in base_dir; return failures (empty == all match).

    A missing or mismatched first-party dependency is fail-closed. `check_main`
    also re-hashes the EXE itself (the stub normally relies on its own code-hash
    binding for that, so it defaults off)."""
    fails: List[str] = []
    if check_main:
        mp = os.path.join(base_dir, manifest.main)
        if not os.path.isfile(mp):
            fails.append(f"main missing: {manifest.main}")
        elif sha256_file(mp) != manifest.main_sha256:
            fails.append(f"main hash mismatch: {manifest.main}")
    for name, expected in sorted(manifest.deps.items()):
        p = os.path.join(base_dir, name)
        if not os.path.isfile(p):
            fails.append(f"dependency missing: {name}")
        elif sha256_file(p) != expected:
            fails.append(f"dependency hash mismatch: {name}")
    return fails


# --- optional Ed25519 signing (standalone tamper-evidence) -----------------
def sign_manifest(manifest: Manifest, private_key_pem: bytes) -> str:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    key = load_pem_private_key(private_key_pem, password=None)
    return base64.b64encode(key.sign(manifest.canonical_bytes())).decode()


def verify_signature(manifest: Manifest, signature_b64: str,
                     public_key_pem: bytes) -> bool:
    """True iff `signature_b64` is a valid signature over the manifest by the key.
    Any failure (bad signature, malformed input, wrong key) returns False."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    try:
        key = load_pem_public_key(public_key_pem)
        key.verify(base64.b64decode(signature_b64), manifest.canonical_bytes())
        return True
    except Exception:
        return False
