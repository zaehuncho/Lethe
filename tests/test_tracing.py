"""Tests for tracing/lethe_tracing.py: per-customer seed + traitor tracing."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tracing"))
import lethe_tracing as lt  # noqa: E402

MASTER = b"server-side-master-secret-bytes-here!!"


def test_seed_deterministic_and_input_sensitive():
    s1 = lt.derive_build_seed(MASTER, "cust-A", "LIC-1")
    assert s1 == lt.derive_build_seed(MASTER, "cust-A", "LIC-1")
    assert len(s1) == 16
    assert lt.derive_build_seed(MASTER, "cust-B", "LIC-1") != s1        # customer
    assert lt.derive_build_seed(MASTER, "cust-A", "LIC-2") != s1        # license
    assert lt.derive_build_seed(MASTER, "cust-A", "LIC-1", "x") != s1   # product
    assert lt.derive_build_seed(b"other", "cust-A", "LIC-1") != s1      # master


def test_empty_master_rejected():
    with pytest.raises(ValueError):
        lt.derive_build_seed(b"", "c", "l")


def test_morph_differs_per_customer():
    sa, pa = lt.morph_for_seed(lt.derive_build_seed(MASTER, "A", "L"))
    sb, pb = lt.morph_for_seed(lt.derive_build_seed(MASTER, "B", "L"))
    assert (sa, pa) != (sb, pb)                 # distinct customers -> distinct morph
    assert sorted(pa) == list(range(16))        # a real permutation


def test_fingerprint_recoverable_from_morph():
    seed = lt.derive_build_seed(MASTER, "A", "L")
    sigma, perm = lt.morph_for_seed(seed)
    # fingerprint from the OBSERVABLE morph == the issuance-side fingerprint
    assert lt.fingerprint_morph(sigma, perm) == lt.fingerprint_for_seed(seed)


def test_registry_traces_a_leak_to_its_customer():
    issuances = [("alice", "LIC-A", "lethe"), ("bob", "LIC-B", "lethe"),
                 ("carol", "LIC-C", "lethe")]
    reg = lt.build_registry(MASTER, issuances)
    # a leaked build from bob: recover his morph -> fingerprint -> trace
    bob_seed = lt.derive_build_seed(MASTER, "bob", "LIC-B", "lethe")
    fp = lt.fingerprint_morph(*lt.morph_for_seed(bob_seed))
    assert reg.trace(fp) == "bob"
    assert reg.trace("deadbeefdeadbeef") is None      # unknown build
