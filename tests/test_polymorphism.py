"""Transparent assembler-layout contracts.

Lethe keeps encrypted payloads randomized through their real cryptographic
nonces, but does not add fake application strings, decoy metadata, or randomized
names intended to confuse inspection tools.
"""
from __future__ import annotations

import inspect

import pytest

from packer import assemble


@pytest.mark.parametrize(
    "original, expected",
    [
        (".text", ".ltext"),
        (".rdata", ".lrdata"),
        (".data", ".ldata"),
        (".pdata", ".lpdata"),
        (".reloc", ".lreloc"),
        (".rsrc", ".lrsrc"),
        (".unknown", ".lstub"),
    ],
)
def test_stub_section_names_are_stable_and_identifiable(original, expected):
    assert assemble._stub_section_name(original, set()) == expected


def test_stub_section_names_remain_unique_without_randomization():
    used: set[str] = set()
    names = []
    for original in (".text", ".rdata", ".data", ".rdata", ".data", ".unknown"):
        name = assemble._stub_section_name(original, used)
        assert name not in used
        assert len(name.encode("ascii")) <= 8
        used.add(name)
        names.append(name)

    assert names == [".ltext", ".lrdata", ".ldata", ".lrdata0", ".ldata0", ".lstub"]


def test_evasion_only_chaff_helpers_are_not_part_of_the_assembler():
    for removed_name in (
        "_build_decoy_packinfo",
        "_build_decoy_strings_blob",
        "_rand_padding",
        "_FINGERPRINT_STRINGS",
        "_STUB_ALT_NAME_POOL",
    ):
        assert not hasattr(assemble, removed_name)


def test_payload_assembly_contains_no_fake_metadata_or_strings():
    source = inspect.getsource(assemble.build_output_pe)
    assert "_build_decoy" not in source
    assert "_rand_padding" not in source
    assert "_FINGERPRINT_STRINGS" not in source
    assert "meta_rva = _emit(meta_ct)" in source
