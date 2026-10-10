"""Bounded virtualization selection parsing; no native code or product execution."""
import json
from unittest.mock import Mock
import pytest
from packer import virtualization_selection as selection
from packer.strict_json import MAX_JSON_DEPTH, MAX_JSON_NODES


def _nested(depth):
    return b'{"x":' + b'[' * (depth - 1) + b'0' + b']' * (depth - 1) + b'}\n'


def test_selection_parser_accepts_exact_depth_limit():
    raw = _nested(MAX_JSON_DEPTH)
    assert selection._parse_canonical(raw) == json.loads(raw)


def test_selection_parser_rejects_depth_before_decoder(monkeypatch):
    decoder = Mock(side_effect=AssertionError("decoder received an over-deep tree"))
    monkeypatch.setattr(selection.json, "loads", decoder)
    with pytest.raises(selection.VirtualizationSelectionError, match="nesting limit"):
        selection._parse_canonical(_nested(MAX_JSON_DEPTH + 1))
    decoder.assert_not_called()


def test_selection_parser_accepts_exact_node_limit():
    # Root, its key and the array account for three nodes.
    document = {"x": [0] * (MAX_JSON_NODES - 3)}
    raw = selection.canonical_json(document)
    assert len(raw) <= selection.MAX_MANIFEST_BYTES
    assert selection._parse_canonical(raw) == document


def test_selection_parser_rejects_excess_nodes():
    raw = selection.canonical_json({"x": [0] * (MAX_JSON_NODES - 2)})
    with pytest.raises(selection.VirtualizationSelectionError, match="node limit"):
        selection._parse_canonical(raw)


def test_structure_characters_inside_strings_do_not_count_as_depth():
    document = {"x": '\\"[{}]\\' * (MAX_JSON_DEPTH * 2)}
    assert selection._parse_canonical(selection.canonical_json(document)) == document


@pytest.mark.parametrize("token", [b"1.0", b"1e0", b"NaN", b"Infinity", b"-Infinity"])
def test_integer_only_number_contract_is_unchanged(token):
    with pytest.raises(selection.VirtualizationSelectionError):
        selection._parse_canonical(b'{"x":' + token + b'}\n')


@pytest.mark.parametrize("raw", [
    b'{"x":1,"x":2}\n', b'{"x":1,"\\u0078":2}\n',
    b'{ "x":1}\n', b'{"x":1}', b'{"x":-0}\n', b'[]\n',
])
def test_ambiguous_or_noncanonical_documents_remain_rejected(raw):
    with pytest.raises(selection.VirtualizationSelectionError):
        selection._parse_canonical(raw)


def test_twenty_digit_integer_boundary_is_preserved():
    allowed = {"x": 10**19}
    assert selection._parse_canonical(selection.canonical_json(allowed)) == allowed
    with pytest.raises(selection.VirtualizationSelectionError, match="integer token"):
        selection._parse_canonical(selection.canonical_json({"x": 10**20}))


def test_manifest_byte_limit_still_precedes_decoding(monkeypatch):
    decoder = Mock(side_effect=AssertionError("oversized document decoded"))
    monkeypatch.setattr(selection.json, "loads", decoder)
    with pytest.raises(selection.VirtualizationSelectionError, match="1 MiB"):
        selection._parse_canonical(b" " * (selection.MAX_MANIFEST_BYTES + 1))
    decoder.assert_not_called()
