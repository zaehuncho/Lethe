#!/usr/bin/env python3
"""Generate a Lethe bounty challenge from LETHE_CRACKME_PASSWORD/FLAG (env).

Writes challenge.json (salt / nonce / ciphertext only) -- the public artifact you
hand to solvers. The password and flag are read from the environment and are
never written anywhere. A round-trip self-check proves the real password recovers
the flag (and a wrong one does not) BEFORE the challenge is emitted.

Usage (PowerShell):
    $env:LETHE_CRACKME_PASSWORD='...'; $env:LETHE_CRACKME_FLAG='...'
    python bounty/gen_bounty.py [--out challenge.json] [--kdf argon2id|scrypt]
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lethe_bounty as lb  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=Path("challenge.json"))
    ap.add_argument("--kdf", choices=["argon2id", "scrypt"], default=None,
                    help="default: argon2id if available, else scrypt")
    args = ap.parse_args(argv)

    password = os.environ.get("LETHE_CRACKME_PASSWORD", "").encode()
    flag = os.environ.get("LETHE_CRACKME_FLAG", "").encode()
    if not password or not flag:
        sys.stderr.write("set LETHE_CRACKME_PASSWORD and LETHE_CRACKME_FLAG "
                         "(deliberately kept out of the repo)\n")
        return 2
    if args.kdf == "argon2id" and not lb.have_argon2():
        sys.stderr.write("argon2id requested but argon2-cffi is not installed "
                         "(pip install argon2-cffi)\n")
        return 2

    kdf = args.kdf or ("argon2id" if lb.have_argon2() else "scrypt")
    print(f"[bounty] sealing flag under {kdf} + AES-256-GCM...")
    challenge = lb.generate(password, flag, kdf=kdf)

    # Self-check with the REAL password before publishing anything.
    if lb.attempt(challenge, password) != flag:
        sys.stderr.write("SELF-CHECK FAILED: real password did not recover the "
                         "flag; refusing to write.\n")
        return 1
    if lb.attempt(challenge, password + b"\x00wrong") is not None:
        sys.stderr.write("SELF-CHECK FAILED: a wrong password decrypted; "
                         "refusing to write.\n")
        return 1

    args.out.write_text(challenge.to_json(), encoding="utf-8")
    print(f"[bounty] wrote {args.out}  (kdf={kdf}, params={challenge.params})")
    print("[bounty] self-check OK: real password recovers the flag; wrong fails.")
    print("[bounty] artifact holds ONLY salt/nonce/ciphertext - run "
          "audit_bounty.py to prove it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
