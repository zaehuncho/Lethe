#!/usr/bin/env python3
"""Test-harness entry point for fresh, not-yet-promoted native stubs."""
from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import lethe  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(lethe.main(_allow_unverified_stub_for_tests=True))
