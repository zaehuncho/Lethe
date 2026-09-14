from __future__ import annotations

import pytest

from packer import strict_json


def test_loads_plain_utf8_object_and_preserves_scalar_types():
    result = strict_json.load_json_object_bytes(
        '{"label":"café","enabled":true,"count":2,"ratio":1.5,"none":null}'.encode())
    assert result == {
        "label": "café", "enabled": True, "count": 2, "ratio": 1.5, "none": None,
    }
    assert type(result["enabled"]) is bool
    assert type(result["count"]) is int


@pytest.mark.parametrize("data", [
    b'{"a":1,"a":2}',
    b'{"nested":{"key":1,"key":1}}',
    b'{"a":1,"\\u0061":2}',
])
def test_rejects_duplicate_keys_including_decoded_aliases(data):
    with pytest.raises(strict_json.StrictJSONError, match="duplicate"):
        strict_json.load_json_object_bytes(data)


@pytest.mark.parametrize("number", [b"NaN", b"Infinity", b"-Infinity", b"1e9999"])
def test_rejects_all_nonfinite_numbers(number):
    with pytest.raises(strict_json.StrictJSONError, match="nonfinite"):
        strict_json.load_json_object_bytes(b'{"number":' + number + b'}')


@pytest.mark.parametrize("data", [
    b"[]", b"null", b"1", b'"object"', b'{"key":}', b'{} {}',
    b"\xef\xbb\xbf{}", b'{"label":"\xff"}',
])
def test_rejects_invalid_encoding_syntax_or_root(data):
    with pytest.raises(ValueError):
        strict_json.load_json_object_bytes(data, what="receipt")


def test_byte_limit_is_inclusive_and_checked_before_decoding():
    assert strict_json.load_json_object_bytes(b"{}", max_bytes=2) == {}
    with pytest.raises(strict_json.StrictJSONError, match="receipt exceeds"):
        strict_json.load_json_object_bytes(b"\xff" * 3, what="receipt", max_bytes=2)


@pytest.mark.parametrize("limit", [True, 0, -1, 2.0, "2"])
def test_byte_limit_requires_positive_exact_integer(limit):
    with pytest.raises(strict_json.StrictJSONError, match="positive integer"):
        strict_json.load_json_object_bytes(b"{}", max_bytes=limit)


@pytest.mark.parametrize("data", ["{}", bytearray(b"{}"), memoryview(b"{}")])
def test_input_requires_immutable_bytes(data):
    with pytest.raises(strict_json.StrictJSONError, match="must be bytes"):
        strict_json.load_json_object_bytes(data)


def test_depth_boundary_and_escaped_string_delimiters():
    arrays = strict_json.MAX_JSON_DEPTH - 1
    data = b'{"items":' + b'[' * arrays + b'0' + b']' * arrays + b'}'
    assert "items" in strict_json.load_json_object_bytes(data)
    with pytest.raises(strict_json.StrictJSONError, match="nesting"):
        strict_json.load_json_object_bytes(
            b'{"items":' + b'[' * (arrays + 1) + b'0' + b']' * (arrays + 1) + b'}')
    assert strict_json.load_json_object_bytes(b'{"text":"[\\\"{\\\\}]"}') == {
        "text": '["{\\}]',
    }


def test_node_boundary_counts_keys_and_container_values(monkeypatch):
    monkeypatch.setattr(strict_json, "MAX_JSON_NODES", 7)
    assert strict_json.load_json_object_bytes(b'{"items":[1,2,3,4]}')
    with pytest.raises(strict_json.StrictJSONError, match="node"):
        strict_json.load_json_object_bytes(b'{"items":[1,2,3,4,5]}')


def test_default_node_limit_rejects_large_flat_fixture():
    data = b'{"items":[' + b'0,' * strict_json.MAX_JSON_NODES + b'0]}'
    with pytest.raises(strict_json.StrictJSONError, match="node"):
        strict_json.load_json_object_bytes(data)
