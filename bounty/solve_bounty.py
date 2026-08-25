#!/usr/bin/env python3
"""Attempt a Lethe bounty challenge.

Given challenge.json + a password guess, prints the flag on success or
``incorrect`` on failure (exit 1). This IS the reference check a solver runs
against their guesses -- they may run it as often as they like; brute force is
the part that is meant to be infeasible.

Usage:
    python bounty/solve_bounty.py challenge.json --password GUESS
    echo GUESS | python bounty/solve_bounty.py challenge.json      # via stdin
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
    ap.add_argument("challenge", type=Path)
    ap.add_argument("--password",
                    help="password guess (else one line is read from stdin)")
    args = ap.parse_args(argv)

    try:
        challenge = lb.Challenge.from_json(
            args.challenge.read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError) as exc:
        sys.stderr.write(f"cannot load challenge: {exc}\n")
        return 2

    guess = args.password
    if guess is None:
        guess = sys.stdin.readline().rstrip("\n")

    flag = lb.attempt(challenge, guess.encode())
    if flag is None:
        print("incorrect")
        return 1
    try:
        print(flag.decode())
    except UnicodeDecodeError:
        print(repr(flag))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
