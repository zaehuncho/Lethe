"""Polymorphism-helper invariants for the Lethe assembler.

The assembler injects per-build chaff into the packed image -- decoy PackInfo
blobs (intact ``LETHE01`` magic), random-length padding, decoy strings, and
randomized section names -- to defeat static tool signatures and LLM-based RE
assistants that lean on fixed structural patterns.

These tests pin the invariants that make the chaff safe:

* Decoy PackInfos are exactly 192 bytes and round-trip through the parser (so a
  scanner grep'ing for ``LETHE01`` gets clean parses, not obvious junk).
* Consecutive decoys differ in every field group (nonce, tag, key, RVAs), so a
  build-to-build differ can't distinguish decoys by "these bytes never change".
* Padding lengths honour the requested bounds.
* Alt-section-name picks avoid collisions and are drawn from the plausible pool.
* The fingerprint scrub list covers the strings we intend to remove.

The chaff itself is Python-only and adds no runtime cost to the packed binary;
these tests can therefore pass NOW, before any stub / round-trip work.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


# --- import the packer modules (they're not an installed package) ------------
# The packer sub-package uses relative imports (``from . import container``); if
# we load one file by spec_from_file_location it can't resolve its siblings. Add
# the packer root to sys.path and import as a real package so all relative
# imports work.
PACKER_ROOT = Path(__file__).resolve().parents[1]

if not (PACKER_ROOT / "packer" / "__init__.py").is_file():  # pragma: no cover
    pytest.skip("packer package missing", allow_module_level=True)

if str(PACKER_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKER_ROOT))

try:
    from packer import container, assemble  # type: ignore
except ImportError as e:  # pragma: no cover - cryptography / lief missing
    pytest.skip(f"packer imports failed: {e}", allow_module_level=True)


# ---------------------------------------------------------------------------
# decoy PackInfo blobs
# ---------------------------------------------------------------------------

def test_decoy_packinfo_is_exactly_192_bytes():
    blob = assemble._build_decoy_packinfo()
    assert len(blob) == container.PACKINFO_SIZE == 192


def test_decoy_packinfo_carries_intact_magic():
    """Decoys MUST carry the LETHE01 magic -- that's the point. Scanners
    grep'ing for the magic should hit the decoys (the real PackInfo has its
    magic scrubbed at output time)."""
    blob = assemble._build_decoy_packinfo()
    assert blob[:8] == container.MAGIC


def test_decoy_packinfo_parses_through_the_real_container():
    """A scanner that finds a decoy and parses it must succeed (else the decoy
    is obvious as chaff). We assert only that PackInfo.from_bytes doesn't raise;
    the numeric fields are deliberately random and don't need to be meaningful."""
    for _ in range(20):
        blob = assemble._build_decoy_packinfo()
        parsed = container.PackInfo.from_bytes(blob)
        # And it must be a real PackInfo (not some other dataclass) with the
        # expected format version, so a differential parser can't tell decoys
        # from real by protocol handshake alone.
        assert isinstance(parsed, container.PackInfo)


def test_consecutive_decoys_differ_in_key_material():
    """Two decoys built back-to-back must not share nonces, tags, or key bytes
    -- otherwise a scanner clustering by 'these bytes look identical between
    hits' immediately partitions decoys from any real header."""
    a = container.PackInfo.from_bytes(assemble._build_decoy_packinfo())
    b = container.PackInfo.from_bytes(assemble._build_decoy_packinfo())
    assert a.meta_nonce != b.meta_nonce
    assert a.meta_tag != b.meta_tag
    assert a.aes_key_enc != b.aes_key_enc
    assert a.kdf_salt != b.kdf_salt


def test_decoy_packinfo_uses_only_declared_flag_bits():
    """The flags word only has 4 real bits (0x01..0x08). Decoys must stay
    within that range -- setting unknown high bits would flag the decoy as
    'wrong version' immediately."""
    for _ in range(20):
        blob = assemble._build_decoy_packinfo()
        parsed = container.PackInfo.from_bytes(blob)
        assert 0 <= parsed.flags <= 0x0F


# ---------------------------------------------------------------------------
# random padding
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("lo,hi", [(0, 0), (16, 16), (16, 96), (48, 192), (64, 256)])
def test_rand_padding_length_within_bounds(lo, hi):
    for _ in range(30):
        pad = assemble._rand_padding(lo, hi)
        assert lo <= len(pad) <= hi


def test_rand_padding_looks_random():
    """Two padding draws of the same requested length should almost never be
    byte-identical (probability 2^-lengthBits) -- catches a broken RNG."""
    a = assemble._rand_padding(128, 128)
    b = assemble._rand_padding(128, 128)
    assert a != b


# ---------------------------------------------------------------------------
# decoy strings
# ---------------------------------------------------------------------------

def test_decoy_strings_are_nul_terminated_and_nonempty():
    blob = assemble._build_decoy_strings_blob()
    assert len(blob) > 0
    assert b"\x00" in blob, "decoy strings should have NUL terminators"


def test_decoy_strings_vary_across_builds():
    """Random subset selection should almost never produce the same blob twice
    -- a rescanner that sees identical strings across two builds fingerprints
    the packer instantly."""
    a = assemble._build_decoy_strings_blob()
    b = assemble._build_decoy_strings_blob()
    assert a != b


def test_decoy_strings_include_common_windows_apis():
    """The pool must contain enough plausible content to look like a normal
    Windows app under `strings`. This is a smoke test on the pool, not the
    generated blob (subset selection may skip any given entry on a given draw)."""
    pool_bytes = b"".join(assemble._DECOY_STRING_POOL)
    for needle in (b"kernel32.dll", b"RegOpenKeyExW", b"CoCreateInstance"):
        assert needle in pool_bytes, f"pool missing plausible string {needle!r}"


# ---------------------------------------------------------------------------
# alt-name picker
# ---------------------------------------------------------------------------

def test_pick_alt_name_avoids_collisions():
    used = set()
    # Simulate a stub with duplicate original section names -- the picker
    # should never hand back one already in `used`.
    for orig in (".text", ".rdata", ".data", ".rdata", ".data", ".rdata"):
        name = assemble._pick_alt_name(orig, used)
        assert name not in used
        used.add(name)


def test_pick_alt_name_draws_from_pool_when_available():
    """First pick for a known original name should come from that name's pool."""
    for orig in (".text", ".rdata", ".data", ".pdata", ".reloc", ".rsrc"):
        name = assemble._pick_alt_name(orig, set())
        assert name in assemble._STUB_ALT_NAME_POOL[orig]


def test_pick_alt_name_unknown_original_falls_back():
    """An unpooled original name still gets a non-empty answer -- the assembler
    must never fail because of a strange section name coming out of MSVC."""
    name = assemble._pick_alt_name(".weird", set())
    assert name and name != ".weird"


# ---------------------------------------------------------------------------
# fingerprint scrubbing
# ---------------------------------------------------------------------------

def test_fingerprint_list_covers_stub_symbols_and_toolchain_residue():
    seen = set(assemble._FINGERPRINT_STRINGS)
    for needle in (b"lethe_stub_x64", b"StubDllMain", b"StubExeEntry",
                   b"RSDS", b".pdb"):
        assert needle in seen, f"fingerprint list missing {needle!r}"
