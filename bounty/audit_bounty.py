#!/usr/bin/env python3
"""Audit a Lethe bounty challenge -- prove the shipped artifact leaks NOTHING.

Given challenge.json (and optionally the compiled challenge binary), plus the
real password/flag from the environment, assert:

  1. the password bytes do not appear in any shipped artifact,
  2. the flag bytes do not appear in any shipped artifact,
  3. the derived key bytes do not appear in any shipped artifact,
  4. the real password recovers the flag (correctness),
  5. a battery of wrong guesses recover NOTHING (no plaintext, no partial leak).

Checks 1-3 are the confidentiality guarantee (no secret bytes ship at all); an
entropy heuristic is intentionally NOT used -- a short AES-GCM ciphertext cannot
reach 8 bits/byte, so it produces false positives and adds nothing over 1-3.

This is the "the password never appears on a wrong guess" proof: the real
password is not in the artifact at all, so no run -- right or wrong -- can
surface it, and a wrong guess fails GCM authentication with no plaintext.

Exit 0 = safe to publish. Any failure = do NOT stake money on it.

Usage:
    $env:LETHE_CRACKME_PASSWORD='...'; $env:LETHE_CRACKME_FLAG='...'
    python bounty/audit_bounty.py challenge.json [--binary path\\to\\challenge.exe]
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lethe_bounty as lb  # noqa: E402


def audit(challenge: lb.Challenge, password: bytes, flag: bytes,
          artifacts: Dict[str, bytes]) -> List[str]:
    """Return a list of failure strings (empty list = every check passed)."""
    fails: List[str] = []
    key = lb.derive_key(challenge.kdf, password, challenge.salt_bytes(),
                        challenge.params)
    secrets_map = {"password": password, "flag": flag, "derived key": key}

    # 1-3: no secret bytes present in any shipped artifact.
    for aname, blob in artifacts.items():
        for sname, sval in secrets_map.items():
            if sval and sval in blob:
                fails.append(f"{sname} bytes found inside {aname}")

    # 4: correctness -- the real password recovers the flag.
    if lb.attempt(challenge, password) != flag:
        fails.append("real password does NOT recover the flag (challenge broken)")

    # 5: wrong guesses reveal nothing -- including feeding the flag as the guess.
    wrong = [password + b"x", password[:-1] or b"_", password.upper(),
             password.lower(), b"", b"password", b"admin", password[::-1], flag]
    for w in wrong:
        if w == password:            # a mutation collided with the real pw
            continue
        if lb.attempt(challenge, w) is not None:
            fails.append(f"a WRONG guess ({w!r}) decrypted the flag")

    return fails


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("challenge", type=Path)
    ap.add_argument("--binary", type=Path, default=None,
                    help="also scan this compiled challenge binary for leaks")
    args = ap.parse_args(argv)

    password = os.environ.get("LETHE_CRACKME_PASSWORD", "").encode()
    flag = os.environ.get("LETHE_CRACKME_FLAG", "").encode()
    if not password or not flag:
        sys.stderr.write("set LETHE_CRACKME_PASSWORD and LETHE_CRACKME_FLAG "
                         "to audit\n")
        return 2

    try:
        challenge = lb.Challenge.from_json(
            args.challenge.read_text(encoding="utf-8"))
        artifacts = {args.challenge.name: args.challenge.read_bytes()}
        if args.binary:
            artifacts[args.binary.name] = args.binary.read_bytes()
    except (OSError, ValueError, KeyError) as exc:
        sys.stderr.write(f"cannot load inputs: {exc}\n")
        return 2

    fails = audit(challenge, password, flag, artifacts)
    print(f"[audit] scheme={challenge.scheme} kdf={challenge.kdf} "
          f"artifacts={list(artifacts)}")
    if fails:
        print("[audit] FAILED - do NOT publish / stake money:")
        for f in fails:
            print("   x", f)
        return 1
    print("[audit] PASS - no password/flag/key in any artifact; wrong guesses "
          "reveal nothing; real password recovers the flag.")
    print("[audit] safe to publish.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
