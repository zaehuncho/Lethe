"""Small, bounded JSON-object boundary for external evidence documents."""

from __future__ import annotations

import json
import math
from typing import Any


MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100_000


class StrictJSONError(ValueError):
    """Input is not a bounded, unambiguous UTF-8 JSON object."""


def load_json_object_bytes(
    data: bytes, *, what: str = "JSON", max_bytes: int = 1048576,
) -> dict[str, Any]:
    """Reject duplicate keys, nonfinite numbers, and excessive document size.

    UTF-8 without a BOM is required. The root object counts as depth one;
    object keys and all values count toward the fixed node limit. A lexical
    depth check precedes decoding so the decoder never receives a deep tree.
    """
    if type(max_bytes) is not int or max_bytes <= 0:
        raise StrictJSONError(f"{what} byte limit must be a positive integer")
    if type(data) is not bytes:
        raise StrictJSONError(f"{what} input must be bytes")
    if len(data) > max_bytes:
        raise StrictJSONError(f"{what} exceeds the {max_bytes}-byte limit")
    try:
        source = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StrictJSONError(f"{what} must be UTF-8") from exc

    depth = 0
    in_string = False
    escaped = False
    for char in source:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise StrictJSONError(f"{what} exceeds the nesting limit")
        elif char in "]}":
            depth -= 1

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise StrictJSONError(f"{what} contains a duplicate object key")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise StrictJSONError(f"{what} contains a nonfinite number")

    def finite_float(value: str) -> float:
        result = float(value)
        if not math.isfinite(result):
            raise StrictJSONError(f"{what} contains a nonfinite number")
        return result

    try:
        payload = json.loads(
            source, object_pairs_hook=object_pairs,
            parse_constant=reject_constant, parse_float=finite_float,
        )
    except StrictJSONError:
        raise
    except (ValueError, RecursionError) as exc:
        raise StrictJSONError(f"{what} is not valid JSON") from exc
    if type(payload) is not dict:
        raise StrictJSONError(f"{what} root must be an object")

    pending = [payload]
    nodes = 0
    while pending:
        value = pending.pop()
        nodes += 1
        if type(value) is dict:
            nodes += len(value)
            pending.extend(value.values())
        elif type(value) is list:
            pending.extend(value)
        if nodes > MAX_JSON_NODES:
            raise StrictJSONError(f"{what} exceeds the node limit")
    return payload


__all__ = ["StrictJSONError", "load_json_object_bytes"]
