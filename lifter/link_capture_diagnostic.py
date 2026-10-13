"""Non-admitting, byte-bound /LINKREPRO input format inventory.

This module intentionally does not infer linker member extraction, relocation
targets, source/output equivalence, XFG closure, or production admission.  It
preserves each archive member by its header offset even when vendor import
libraries reuse a DLL label for thousands of distinct members.  Labels are
never interpreted as filesystem paths.

The stricter synthetic ``link_capture_archive.inspect_capture`` contract is
unchanged and is not implemented in terms of this diagnostic reader.
"""

from __future__ import annotations

from collections import Counter
from hashlib import sha256
from pathlib import Path
import re
import struct

from .link_capture_archive import _capture_regular_file, _capture_root, _capture_token


class CaptureDiagnosticError(ValueError):
    """An input cannot be bounded as one of the diagnostic formats."""


MAX_INPUTS = 256
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_CAPTURE_BYTES = 256 * 1024 * 1024
MAX_SECTIONS = 65535  # ordinary COFF's 16-bit section-count ceiling
MAX_SYMBOLS = 2_000_000
MAX_RELOCATIONS = 3_000_000
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_INDEX_SYMBOLS = 500_000
MAX_LABEL_BYTES = 512
BIGOBJ_CLASS_ID = bytes.fromhex("c7a1bad1eebaa94baf20faf66aa4dcb8")


def _require(ok: bool, reason: str) -> None:
    if not ok:
        raise CaptureDiagnosticError(reason)


def _bounded(start: int, size: int, length: int, reason: str) -> None:
    _require(0 <= start <= length and 0 <= size <= length - start, reason)


def _ascii_cstring(raw: bytes, start: int, *, end: int | None = None) -> tuple[str, int]:
    limit = len(raw) if end is None else end
    _bounded(start, 1, limit, "archive symbol string is out of bounds")
    stop = raw.find(b"\0", start, limit)
    _require(stop >= 0 and stop - start <= MAX_LABEL_BYTES,
             "archive symbol string is unterminated or excessive")
    try:
        value = raw[start:stop].decode("ascii")
    except UnicodeDecodeError as exc:
        raise CaptureDiagnosticError("archive symbol string is not ASCII") from exc
    _require(bool(value), "archive symbol string is empty")
    return value, stop + 1


def _object_sections(identity: str, raw: bytes, *, header_size: int,
                     section_count: int, symbol_offset: int,
                     symbol_count: int, symbol_width: int, kind: str) -> dict:
    _require(0 < section_count <= MAX_SECTIONS, "COFF section count is unsupported")
    section_end = header_size + section_count * 40
    _bounded(header_size, section_count * 40, len(raw), "COFF section table is truncated")
    _require(0 <= symbol_count <= MAX_SYMBOLS, "COFF symbol count is unsupported")
    if symbol_count:
        _require(symbol_offset >= section_end, "COFF symbol table precedes sections")
        _bounded(symbol_offset, symbol_count * symbol_width + 4, len(raw),
                 "COFF symbol/string table is truncated")
        strings = symbol_offset + symbol_count * symbol_width
        string_size = struct.unpack_from("<I", raw, strings)[0]
        _bounded(strings, string_size, len(raw), "COFF string table is out of bounds")
        _require(string_size >= 4, "COFF string table is invalid")
    else:
        _require(symbol_offset == 0 or symbol_offset <= len(raw),
                 "COFF symbol pointer is out of bounds")

    relocation_kinds: Counter[int] = Counter()
    executable_sections = 0
    executable_relocations = 0
    directives: list[dict] = []
    relocation_count = 0
    for index in range(section_count):
        off = header_size + index * 40
        name = raw[off:off + 8]
        size, data_offset, relocation_offset = struct.unpack_from("<III", raw, off + 16)
        nrel = struct.unpack_from("<H", raw, off + 32)[0]
        flags = struct.unpack_from("<I", raw, off + 36)[0]
        _require(not (flags & 0x01000000), "COFF relocation overflow is unsupported")
        if size and data_offset:
            _bounded(data_offset, size, len(raw), "COFF section bytes are out of bounds")
        elif size:
            _require(bool(flags & 0x00000080), "COFF initialized section has no bytes")
        if nrel:
            _require(relocation_offset >= section_end, "COFF relocation table precedes sections")
            _bounded(relocation_offset, nrel * 10, len(raw),
                     "COFF relocation table is out of bounds")
        relocation_count += nrel
        _require(relocation_count <= MAX_RELOCATIONS,
                 "COFF relocation count is unsupported")
        for rel in range(nrel):
            field, symbol_index, rel_kind = struct.unpack_from(
                "<IIH", raw, relocation_offset + rel * 10)
            _require(symbol_index < symbol_count,
                     "COFF relocation symbol index is out of bounds")
            # The field offset is relative to the section's raw or BSS extent.
            _require(field < size, "COFF relocation field is out of section bounds")
            relocation_kinds[rel_kind] += 1
        if flags & 0x20000000:
            executable_sections += 1
            executable_relocations += nrel
        if name == b".drectve":
            _require(size > 0 and data_offset > 0,
                     "COFF .drectve section lacks raw bytes")
            body = raw[data_offset:data_offset + size]
            directives.append({"owner": identity,
                               "section_index": index + 1,
                               "section_header_offset": off,
                               "data_offset": data_offset,
                               "size": size,
                               "sha256": sha256(body).hexdigest(),
                               "raw_hex": body.hex()})
    return {"identity": identity, "kind": kind, "sha256": sha256(raw).hexdigest(),
            "bytes": len(raw), "sections": section_count,
            "executable_sections": executable_sections,
            "symbol_records": symbol_count,
            "relocations": relocation_count,
            "executable_relocations": executable_relocations,
            "relocation_kinds": {f"0x{k:04x}": v
                                 for k, v in sorted(relocation_kinds.items())},
            "directives": directives}


def inspect_object_bytes(identity: str, raw: bytes, *, in_archive: bool = False) -> dict:
    """Classify one exact capture-local member without admitting it as code."""
    _require(bool(identity) and len(raw) <= MAX_INPUT_BYTES,
             "COFF identity or byte count is unsupported")
    if len(raw) >= 20 and raw[:4] == b"\0\0\xff\xff":
        version, machine = struct.unpack_from("<HH", raw, 4)
        _require(machine == 0x8664, "anonymous COFF machine is unsupported")
        if version == 0:
            _require(in_archive, "short import must be an archive member")
            _, _, _, _, _, data_size, ordinal, type_info = struct.unpack_from(
                "<HHHHIIHH", raw)
            _require(data_size > 0 and len(raw) == 20 + data_size,
                     "short import size differs from member bytes")
            _require(type_info & ~0x1f == 0 and (type_info & 3) <= 2 and
                     ((type_info >> 2) & 7) <= 4,
                     "short import type/name bits are unsupported")
            payload = raw[20:]
            _require(payload.endswith(b"\0"), "short import strings are unterminated")
            parts = payload[:-1].split(b"\0")
            _require(2 <= len(parts) <= 3 and all(parts),
                     "short import name/DLL payload is invalid")
            try:
                decoded = [part.decode("ascii") for part in parts]
            except UnicodeDecodeError as exc:
                raise CaptureDiagnosticError("short import name/DLL is not ASCII") from exc
            _require(all(len(part) <= MAX_LABEL_BYTES for part in parts),
                     "short import name/DLL is excessive")
            return {"identity": identity, "kind": "short_import_v0",
                    "sha256": sha256(raw).hexdigest(), "bytes": len(raw),
                    "machine": "amd64", "ordinal_hint": ordinal,
                    "type_info": type_info, "names": decoded,
                    "sections": 0, "executable_sections": 0,
                    "symbol_records": 0, "relocations": 0,
                    "executable_relocations": 0, "relocation_kinds": {},
                    "directives": []}
        if version == 2:
            _require(len(raw) >= 56 and raw[12:28] == BIGOBJ_CLASS_ID,
                     "bigobj class ID or header is invalid")
            count, symptr, nsyms = struct.unpack_from("<III", raw, 44)
            return _object_sections(identity, raw, header_size=56,
                section_count=count, symbol_offset=symptr, symbol_count=nsyms,
                symbol_width=20, kind="bigobj_amd64")
        raise CaptureDiagnosticError("anonymous COFF version or LTCG is unsupported")
    _require(len(raw) >= 20, "ordinary COFF header is truncated")
    machine, count, _, symptr, nsyms, optional, _ = struct.unpack_from(
        "<HHIIIHH", raw)
    _require(machine == 0x8664 and optional == 0,
             "ordinary AMD64 COFF header is invalid")
    return _object_sections(identity, raw, header_size=20,
        section_count=count, symbol_offset=symptr, symbol_count=nsyms,
        symbol_width=18, kind="ordinary_amd64_coff")


def _archive_label(field: bytes, longnames: bytes) -> str:
    try:
        value = field.decode("ascii").rstrip()
    except UnicodeDecodeError as exc:
        raise CaptureDiagnosticError("archive label is not ASCII") from exc
    if value.startswith("/") and value[1:].isdigit():
        off = int(value[1:])
        _bounded(off, 1, len(longnames), "archive long-name offset is out of bounds")
        ends = [p for p in (longnames.find(b"/\n", off),
                             longnames.find(b"\0", off)) if p >= 0]
        _require(bool(ends), "archive long-name is unterminated")
        try:
            value = longnames[off:min(ends)].decode("ascii")
        except UnicodeDecodeError as exc:
            raise CaptureDiagnosticError("archive long-name is not ASCII") from exc
    else:
        _require(value.endswith("/"), "archive member label format is unsupported")
        value = value[:-1]
    _require(0 < len(value) <= MAX_LABEL_BYTES and
             all(32 <= ord(c) < 127 for c in value),
             "archive member label is empty, excessive or control-bearing")
    return value


def _archive_index(first: bytes, second: bytes,
                   offsets: list[int]) -> dict:
    _bounded(0, 4, len(first), "first archive index is truncated")
    nfirst = struct.unpack_from(">I", first)[0]
    _require(nfirst <= MAX_ARCHIVE_INDEX_SYMBOLS,
             "first archive symbol count is unsupported")
    _bounded(4, 4 * nfirst, len(first), "first archive offsets are truncated")
    offset_set = set(offsets)
    first_offsets = [struct.unpack_from(">I", first, 4 + i * 4)[0]
                     for i in range(nfirst)]
    pos = 4 + nfirst * 4
    first_pairs = []
    for off in first_offsets:
        _require(off in offset_set, "first archive index points outside members")
        symbol, pos = _ascii_cstring(first, pos)
        first_pairs.append((symbol, off))
    _require(pos == len(first), "first archive index has trailing bytes")

    _bounded(0, 4, len(second), "second archive index is truncated")
    nmembers = struct.unpack_from("<I", second)[0]
    _require(nmembers == len(offsets), "second archive member count differs")
    _bounded(4, 4 * nmembers + 4, len(second),
             "second archive member offsets are truncated")
    second_offsets = [struct.unpack_from("<I", second, 4 + i * 4)[0]
                      for i in range(nmembers)]
    # LINK.EXE's second index orders members for symbol lookup, not necessarily
    # in physical archive order.  Bind selectors to this exact permutation.
    _require(len(set(second_offsets)) == nmembers and
             set(second_offsets) == offset_set,
             "second archive member offsets differ from headers")
    pos = 4 + nmembers * 4
    nsecond = struct.unpack_from("<I", second, pos)[0]
    pos += 4
    _require(nsecond <= MAX_ARCHIVE_INDEX_SYMBOLS,
             "second archive symbol count is unsupported")
    _bounded(pos, 2 * nsecond, len(second),
             "second archive symbol selectors are truncated")
    selectors = [struct.unpack_from("<H", second, pos + i * 2)[0]
                 for i in range(nsecond)]
    pos += 2 * nsecond
    second_pairs = []
    for selector in selectors:
        _require(1 <= selector <= nmembers,
                 "second archive index selector is invalid")
        symbol, pos = _ascii_cstring(second, pos)
        second_pairs.append((symbol, second_offsets[selector - 1]))
    _require(pos == len(second) and Counter(first_pairs) == Counter(second_pairs),
             "archive linker indexes disagree")
    return {"first_symbols": nfirst, "second_symbols": nsecond,
            "member_count": nmembers,
            "first_sha256": sha256(first).hexdigest(),
            "second_sha256": sha256(second).hexdigest()}


def inspect_archive_bytes(name: str, raw: bytes) -> dict:
    """Inventory all members by archive offset, not by reusable display name."""
    _require(raw.startswith(b"!<arch>\n") and len(raw) <= MAX_INPUT_BYTES,
             "Microsoft archive magic or size is unsupported")
    items: list[tuple[int, bytes, bytes]] = []
    pos = 8
    while pos < len(raw):
        _bounded(pos, 60, len(raw), "archive member header is truncated")
        header = raw[pos:pos + 60]
        _require(header[58:60] == b"`\n", "archive member terminator is invalid")
        try:
            size_text = header[48:58].decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise CaptureDiagnosticError("archive member size is not ASCII") from exc
        _require(bool(size_text) and size_text.isdigit(),
                 "archive member size is invalid")
        size = int(size_text)
        _bounded(pos + 60, size, len(raw), "archive member bytes are truncated")
        items.append((pos, header[:16], raw[pos + 60:pos + 60 + size]))
        _require(len(items) <= MAX_ARCHIVE_MEMBERS + 3,
                 "archive member count is unsupported")
        pos += 60 + size + (size & 1)
    _require(pos == len(raw) and len(items) >= 3,
             "archive has trailing bytes or no object members")
    _require(items[0][1].strip() == b"/" and items[1][1].strip() == b"/",
             "Microsoft archive linker indexes are missing")
    first, second = items[0][2], items[1][2]
    has_longnames = items[2][1].strip() == b"//"
    longnames = items[2][2] if has_longnames else b""
    bodies = items[3 if has_longnames else 2:]
    _require(bool(bodies), "archive has no object members")
    offsets = [off for off, _, _ in bodies]
    index = _archive_index(first, second, offsets)
    members = []
    counts: Counter[str] = Counter()
    for offset, field, body in bodies:
        label = _archive_label(field, longnames)
        identity = f"{name}@0x{offset:x}"
        obj = inspect_object_bytes(identity, body, in_archive=True)
        counts[obj["kind"]] += 1
        members.append({"header_offset": offset,
                        "display_label": label,
                        "raw_label_hex": field.hex(),
                        **obj})
    return {"name": name, "kind": "microsoft_coff_archive",
            "sha256": sha256(raw).hexdigest(), "bytes": len(raw),
            "index": index, "member_count": len(members),
            "member_kinds": dict(sorted(counts.items())),
            "members": members,
            "linker_extraction_proven": False}


def inspect_capture_inputs(capture: Path) -> dict:
    """Return a complete format inventory, never a production admissibility result."""
    root = _capture_root(capture)
    rsp = _capture_regular_file(root, "link.rsp")
    _require(rsp.startswith(b"\xff\xfe") and len(rsp) <= 1024 * 1024,
             "LINKREPRO response encoding or size is unsupported")
    try:
        tokens = [_capture_token(line) for line in rsp.decode("utf-16").splitlines()]
    except UnicodeError as exc:
        raise CaptureDiagnosticError("LINKREPRO response is invalid Unicode") from exc
    _require(len(tokens) <= 2048 and tokens,
             "LINKREPRO response token count is unsupported")
    switches = [token for token in tokens if token.startswith("/")]
    _require(not any(token.upper().startswith(("/LTCG", "/WHOLEARCHIVE"))
                     for token in switches),
             "LINKREPRO LTCG/whole-archive mode is unsupported")
    paths = [token for token in tokens if not token.startswith("/")]
    _require(paths and len(paths) <= MAX_INPUTS,
             "LINKREPRO input count is unsupported")
    occurrences: Counter[str] = Counter()
    order: list[str] = []
    for token in paths:
        _require(token.startswith(".\\") and ".." not in token and "/" not in token,
                 "LINKREPRO input escapes capture")
        name = token[2:]
        _require(bool(re.fullmatch(r"[A-Za-z0-9_.@+\-$]+\.(obj|lib|res)", name, re.I)),
                 "LINKREPRO input name or extension is unsupported")
        if name.casefold() not in occurrences:
            order.append(name)
        occurrences[name.casefold()] += 1
    _require(len(order) <= MAX_INPUTS, "LINKREPRO distinct inputs are excessive")

    inputs = []
    totals: Counter[str] = Counter()
    aggregate = 0
    for name in order:
        raw = _capture_regular_file(root, name)
        _require(len(raw) <= MAX_INPUT_BYTES, "LINKREPRO input is excessive")
        aggregate += len(raw)
        _require(aggregate <= MAX_CAPTURE_BYTES,
                 "LINKREPRO total input bytes are excessive")
        if name.casefold().endswith(".lib"):
            item = inspect_archive_bytes(name, raw)
            totals["libraries"] += 1
            totals["archive_members"] += item["member_count"]
            for kind, number in item["member_kinds"].items():
                totals["member_" + kind] += number
            totals["executable_archive_sections"] += sum(
                member["executable_sections"] for member in item["members"])
            totals["directive_sections"] += sum(
                len(member["directives"]) for member in item["members"])
        elif name.casefold().endswith(".res"):
            # Resource syntax is intentionally outside this COFF inventory.
            # Preserve exact bytes and keep every closure/admission flag false.
            item = {"identity": name, "kind": "opaque_win32_resource",
                    "sha256": sha256(raw).hexdigest(), "bytes": len(raw),
                    "format_interpreted": False, "directives": []}
            totals["opaque_resources"] += 1
        else:
            item = inspect_object_bytes(name, raw)
            totals["explicit_" + item["kind"]] += 1
            totals["explicit_executable_sections"] += item["executable_sections"]
            totals["directive_sections"] += len(item["directives"])
        item["rsp_occurrences"] = occurrences[name.casefold()]
        inputs.append(item)
    return {"status": "diagnostic_input_inventory_only",
            "capture": str(root), "link_rsp_sha256": sha256(rsp).hexdigest(),
            "input_occurrences": len(paths), "distinct_inputs": len(inputs),
            "total_input_bytes": aggregate,
            "switches": switches,
            "counts": dict(sorted(totals.items())), "inputs": inputs,
            "linker_member_extraction_proven": False,
            "direct_instruction_boundaries_proven": False,
            "indirect_target_closure_proven": False,
            "source_output_binding": False,
            "final_image_reference_closure_proven": False,
            "production_admitted": False}
