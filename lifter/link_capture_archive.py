"""Experimental, conservative AMD64 /LINKREPRO archive relocation inventory.

This module intentionally does not admit production source linking.  It reads
every member of each capture-local Microsoft COFF archive, rather than assuming
that an unobserved linker extraction decision makes a member harmless.  /GL,
LTCG, weak externals, unsupported relocations and unbound link options reject.
The result is an input-closure prerequisite, not a final-PE closure proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import stat
import re
import struct


class CaptureClosureError(ValueError):
    """A capture cannot be conservatively inventoried."""


def _require(ok: bool, reason: str) -> None:
    if not ok:
        raise CaptureClosureError(reason)


def _no_reparse_components(path: Path) -> None:
    """Reject a symlink/junction/reparse point at any existing path component."""
    absolute = path.absolute()
    for component in reversed((absolute, *absolute.parents)):
        try:
            info = component.lstat()
        except OSError as exc:
            raise CaptureClosureError("LINKREPRO path component missing or unreadable") from exc
        attributes = getattr(info, "st_file_attributes", 0)
        _require(not stat.S_ISLNK(info.st_mode) and
                 not (attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)) and
                 not getattr(component, "is_junction", lambda: False)(),
                 "LINKREPRO path traverses symlink, junction or reparse point")


def _capture_root(capture: Path) -> Path:
    _no_reparse_components(capture)
    _require(capture.is_dir(), "LINKREPRO directory missing")
    try:
        return capture.resolve(strict=True)
    except OSError as exc:
        raise CaptureClosureError("LINKREPRO root cannot resolve") from exc


def _capture_regular_file(root: Path, name: str) -> bytes:
    """Check both canonical containment and reparse-free path before reading."""
    candidate = root / name
    _no_reparse_components(candidate)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise CaptureClosureError("LINKREPRO input cannot resolve") from exc
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise CaptureClosureError("LINKREPRO input resolves outside capture") from exc
    _require(relative.parts == (name,) and candidate.is_file(),
             "LINKREPRO input is not a capture-local regular file")
    try:
        before = candidate.stat()
        raw = candidate.read_bytes()
        after = candidate.stat()
    except OSError as exc:
        raise CaptureClosureError("LINKREPRO input unreadable") from exc
    _require(stat.S_ISREG(before.st_mode) and
             (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and
             len(raw) == before.st_size,
             "LINKREPRO input changed during read")
    return raw


def _cstring(data: bytes, start: int) -> tuple[str, int]:
    _require(0 <= start < len(data), "archive string offset out of bounds")
    end = data.find(b"\0", start)
    _require(end >= 0, "archive string is unterminated")
    try:
        return data[start:end].decode("ascii"), end + 1
    except UnicodeDecodeError as exc:
        raise CaptureClosureError("archive string is not ASCII") from exc


@dataclass(frozen=True)
class Symbol:
    name: str
    value: int
    section: int
    storage: int


@dataclass(frozen=True)
class Section:
    name: str
    data: bytes


@dataclass(frozen=True)
class Relocation:
    section_index: int
    field_offset: int
    kind: int
    symbol_index: int
    addend: int
    previous_byte: int | None


@dataclass(frozen=True)
class Object:
    identity: str
    raw: bytes
    sections: tuple[Section, ...]
    symbols: dict[int, Symbol]
    relocations: tuple[Relocation, ...]


def _coff_name(field: bytes, strings: bytes) -> str:
    if field[:4] == b"\0" * 4:
        off = struct.unpack_from("<I", field, 4)[0]
        name, _ = _cstring(strings, off)
        return name
    try:
        return field.split(b"\0", 1)[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise CaptureClosureError("COFF name is not ASCII") from exc


def parse_object(identity: str, raw: bytes) -> Object:
    _require(len(raw) >= 20, "truncated COFF object")
    machine, count, _, symptr, symcount, optsize, _ = struct.unpack_from("<HHIIIHH", raw)
    _require(machine == 0x8664 and optsize == 0 and 0 < count < 256,
             "non-AMD64, /GL/LTCG, bigobj or image input")
    _require(symptr >= 20 + count * 40 and symptr + symcount * 18 + 4 <= len(raw),
             "COFF symbol table out of bounds")
    strptr = symptr + symcount * 18
    strlen = struct.unpack_from("<I", raw, strptr)[0]
    _require(4 <= strlen and strptr + strlen <= len(raw), "COFF string table out of bounds")
    strings = raw[strptr:strptr + strlen]
    sections: list[Section] = []
    relocation_tables: list[tuple[int, int]] = []
    for section_no in range(count):
        off = 20 + section_no * 40
        field = raw[off:off + 8]
        if field.startswith(b"/"):
            try:
                index = int(field[1:].split(b"\0", 1)[0])
            except ValueError as exc:
                raise CaptureClosureError("invalid COFF long section name") from exc
            name, _ = _cstring(strings, index)
        else:
            name = _coff_name(field, strings)
        size, dataoff, reloff = struct.unpack_from("<III", raw, off + 16)
        relcount = struct.unpack_from("<H", raw, off + 32)[0]
        flags = struct.unpack_from("<I", raw, off + 36)[0]
        _require(not (flags & 0x01000000), "COFF relocation overflow unsupported")
        _require(dataoff + size <= len(raw) and reloff + relcount * 10 <= len(raw),
                 "COFF section or relocation table out of bounds")
        data = raw[dataoff:dataoff + size]
        if name == ".drectve":
            _require(not any(s in data.upper() for s in
                             (b"DEFAULTLIB", b"WHOLEARCHIVE", b"LTCG", b"ALTERNATENAME")),
                     "implicit library, weak alias or LTCG directive")
        sections.append(Section(name, data))
        relocation_tables.append((reloff, relcount))
    symbols: dict[int, Symbol] = {}
    i = 0
    while i < symcount:
        off = symptr + i * 18
        value, section, _, storage, aux = struct.unpack_from("<IhHBB", raw, off + 8)
        _require(i + aux < symcount, "truncated COFF auxiliary records")
        _require(storage != 105 and section <= count,
                 "weak external or invalid COFF symbol section")
        symbols[i] = Symbol(_coff_name(raw[off:off + 8], strings), value, section, storage)
        i += aux + 1
    relocs: list[Relocation] = []
    for section_no, (relptr, relcount) in enumerate(relocation_tables, 1):
        data = sections[section_no - 1].data
        for i in range(relcount):
            field, symidx, kind = struct.unpack_from("<IIH", raw, relptr + i * 10)
            _require(symidx in symbols and kind in (0x3, 0x4) and field + 4 <= len(data),
                     "unsupported, missing-symbol or out-of-bounds COFF relocation")
            addend = struct.unpack_from("<i" if kind == 0x4 else "<I", data, field)[0]
            relocs.append(Relocation(section_no, field, kind, symidx, addend,
                                     data[field - 1] if field else None))
    return Object(identity, raw, tuple(sections), symbols, tuple(relocs))


@dataclass(frozen=True)
class Archive:
    name: str
    raw: bytes
    objects: tuple[Object, ...]
    index: dict[str, str]


def _member_name(field: bytes, longnames: bytes) -> str:
    try:
        value = field.decode("ascii").rstrip()
    except UnicodeDecodeError as exc:
        raise CaptureClosureError("archive member name is not ASCII") from exc
    if value.startswith("/") and value[1:].isdigit():
        off = int(value[1:])
        _require(off < len(longnames), "archive long-name offset out of bounds")
        # COFF archive producers use either slash-newline or NUL termination.
        ends = [p for p in (longnames.find(b"/\n", off), longnames.find(b"\0", off))
                if p >= 0]
        end = min(ends) if ends else -1
        _require(end >= 0, "archive long name is unterminated")
        try:
            value = longnames[off:end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise CaptureClosureError("archive long name is not ASCII") from exc
    else:
        _require(value.endswith("/"), "archive member name format unsupported")
        value = value[:-1]
    _require(bool(re.fullmatch(r"[A-Za-z0-9_.@+\-$]+\.obj", value, re.I)) and
             value not in (".", ".."), "archive member path or type unsupported")
    return value


def parse_archive(name: str, raw: bytes) -> Archive:
    _require(raw.startswith(b"!<arch>\n"), "not a Microsoft COFF archive")
    members: list[tuple[int, bytes, bytes]] = []
    off = 8
    while off < len(raw):
        _require(off + 60 <= len(raw) and raw[off + 58:off + 60] == b"`\n",
                 "truncated or invalid archive member header")
        header = raw[off:off + 60]
        try:
            size_text = header[48:58].decode("ascii").strip()
            _require(size_text.isdigit(), "invalid archive member size")
            size = int(size_text)
        except UnicodeDecodeError as exc:
            raise CaptureClosureError("archive member size is not ASCII") from exc
        end = off + 60 + size
        _require(end <= len(raw), "archive member exceeds file")
        members.append((off, header[:16], raw[off + 60:end]))
        off = end + (size & 1)
    _require(off == len(raw) and len(members) >= 3,
             "archive has trailing bytes or no object members")
    _require(members[0][1].strip() == b"/" and members[1][1].strip() == b"/",
             "Microsoft first/second linker members missing")
    longnames = b""
    object_start = 2
    if members[2][1].strip() == b"//":
        longnames = members[2][2]
        object_start = 3
    _require(object_start < len(members), "archive has no COFF objects")
    object_offsets = [m[0] for m in members[object_start:]]
    _require(len(object_offsets) < 65536, "archive object count unsupported")
    seen_names: set[str] = set()
    objects: list[Object] = []
    for _, field, body in members[object_start:]:
        member_name = _member_name(field, longnames)
        _require(member_name.casefold() not in seen_names, "ambiguous duplicate archive member name")
        seen_names.add(member_name.casefold())
        objects.append(parse_object(f"{name}:{member_name}", body))
    first = members[0][2]
    second = members[1][2]
    _require(len(first) >= 4 and len(second) >= 4, "truncated archive linker index")
    n_first = struct.unpack_from(">I", first)[0]
    _require(4 + n_first * 4 <= len(first), "first archive index out of bounds")
    first_offsets = [struct.unpack_from(">I", first, 4 + i * 4)[0]
                     for i in range(n_first)]
    pos = 4 + n_first * 4
    first_map: dict[str, int] = {}
    for member_off in first_offsets:
        sym, pos = _cstring(first, pos)
        _require(sym not in first_map and member_off in object_offsets,
                 "duplicate symbol or bad first archive index offset")
        first_map[sym] = member_off
    _require(pos == len(first), "first archive index has trailing bytes")
    n_members = struct.unpack_from("<I", second)[0]
    _require(n_members == len(object_offsets) and 4 + n_members * 4 + 4 <= len(second),
             "second archive member count mismatch")
    second_offsets = [struct.unpack_from("<I", second, 4 + i * 4)[0]
                      for i in range(n_members)]
    _require(second_offsets == object_offsets, "second archive member offset mismatch")
    pos = 4 + n_members * 4
    n_second = struct.unpack_from("<I", second, pos)[0]
    pos += 4
    _require(pos + 2 * n_second <= len(second), "second archive symbol index out of bounds")
    indices = [struct.unpack_from("<H", second, pos + i * 2)[0]
               for i in range(n_second)]
    pos += 2 * n_second
    second_map: dict[str, int] = {}
    for idx in indices:
        sym, pos = _cstring(second, pos)
        _require(1 <= idx <= n_members and sym not in second_map,
                 "invalid or duplicate second archive symbol index")
        second_map[sym] = object_offsets[idx - 1]
    _require(pos == len(second) and first_map == second_map,
             "archive linker symbol indexes disagree")
    externals: dict[str, int] = {}
    for member_off, obj in zip(object_offsets, objects):
        for sym in obj.symbols.values():
            if sym.storage == 2 and sym.section > 0:
                _require(sym.name not in externals, "archive has duplicate defined external")
                externals[sym.name] = member_off
    _require(externals == first_map, "archive index differs from COFF definitions")
    index = {sym: objects[object_offsets.index(member_off)].identity
             for sym, member_off in first_map.items()}
    return Archive(name, raw, tuple(objects), index)


def _capture_token(line: str) -> str:
    _require(line.startswith('"') and line.endswith('"') and len(line) > 2,
             "LINKREPRO token is not individually quoted")
    token = line[1:-1]
    _require('"' not in token and token, "malformed LINKREPRO token")
    return token


def inspect_capture(capture: Path, *, selected: str = "vm_scalar",
                    selected_size: int = 7) -> dict:
    root = _capture_root(capture)
    rsp_raw = _capture_regular_file(root, "link.rsp")
    _require(rsp_raw.startswith(b"\xff\xfe"), "LINKREPRO response is not UTF-16LE")
    try:
        tokens = [_capture_token(line) for line in rsp_raw.decode("utf-16").splitlines()]
    except UnicodeError as exc:
        raise CaptureClosureError("LINKREPRO response is invalid Unicode") from exc
    switches = [t.upper() for t in tokens if t.startswith("/")]
    supported = {
        "/NOLOGO", "/MACHINE:X64", "/NODEFAULTLIB", "/DEBUG:FULL",
        "/INCREMENTAL:NO", "/OPT:NOREF", "/OPT:NOICF", "/CETCOMPAT",
        "/BREPRO", "/MAP:.\\FIXTURE.MAP", "/PDB:.\\FIXTURE.PDB",
        "/OUT:.\\FIXTURE.EXE", "/OUT:.\\FIXTURE.DLL",
        "/SUBSYSTEM:CONSOLE", "/ENTRY:ENTRY", "/ENTRY:DLLMAIN",
        "/EXPORT:PROBE_CALL", "/DLL", "/VERBOSE:LIB",
    }
    _require(set(switches) <= supported and
             {"/MACHINE:X64", "/NODEFAULTLIB", "/INCREMENTAL:NO", "/BREPRO"} <= set(switches),
             "LINKREPRO has unsupported or missing link options")
    paths = [t for t in tokens if not t.startswith("/")]
    _require(paths and len(paths) == len(set(p.casefold() for p in paths)),
             "LINKREPRO inputs missing or duplicated")
    objects: list[Object] = []
    archives: list[Archive] = []
    input_hashes: dict[str, str] = {}
    for token in paths:
        _require(token.startswith(".\\") and ".." not in token and "/" not in token,
                 "LINKREPRO input escapes capture")
        name = token[2:]
        _require(bool(re.fullmatch(r"[A-Za-z0-9_.@+\-$]+\.(obj|lib)", name, re.I)),
                 "LINKREPRO input type unsupported")
        raw = _capture_regular_file(root, name)
        input_hashes[name] = sha256(raw).hexdigest()
        if name.casefold().endswith(".obj"):
            objects.append(parse_object(name, raw))
        else:
            archive = parse_archive(name, raw)
            archives.append(archive)
            objects.extend(archive.objects)
    _require(bool(archives), "archive experiment requires a library input")
    definitions: dict[str, tuple[Object, Symbol]] = {}
    for obj in objects:
        for sym in obj.symbols.values():
            if sym.storage == 2 and sym.section > 0:
                _require(sym.name not in definitions, "duplicate public definition across inputs")
                definitions[sym.name] = (obj, sym)
    _require(selected in definitions, "selected symbol not uniquely defined")
    target_obj, target = definitions[selected]
    _require(selected_size > 0 and target.value == 0 and
             target.section > 0 and target.section <= len(target_obj.sections),
             "selected function extent is not synthetic sole-section entry")
    target_section = target_obj.sections[target.section - 1]
    _require(target_section.name.startswith(".text") and
             selected_size == len(target_section.data),
             "selected function extent is not synthetic sole-section body")
    events: list[dict] = []
    for obj in objects:
        for rel in obj.relocations:
            sym = obj.symbols[rel.symbol_index]
            if sym.section > 0:
                resolved = (obj, sym)
            else:
                resolved = definitions.get(sym.name)
            _require(resolved is not None, "unresolved relocation symbol")
            owner, definition = resolved
            if owner.identity != target_obj.identity or definition.section != target.section:
                continue
            effective = definition.value + rel.addend
            if obj.identity == target_obj.identity and obj.sections[rel.section_index - 1].name in (".pdata", ".xdata"):
                continue
            _require(effective == target.value,
                     "selected relocation targets interior or non-entry")
            section = obj.sections[rel.section_index - 1]
            _require(section.name.startswith(".text") and rel.kind == 0x4 and
                     rel.previous_byte == 0xE8,
                     "selected relocation lacks E8 predecessor byte candidate")
            events.append({"object": obj.identity, "section": section.name,
                           "offset": rel.field_offset, "symbol": sym.name,
                           "addend": rel.addend, "effective_offset": effective,
                           "classification": "e8_predecessor_candidate_not_decoded_call"})
    _require(bool(events), "no selected E8 predecessor candidate")
    return {
        "status": "archive_inputs_inventoried",
        "selected": selected,
        "selected_object": target_obj.identity,
        "selected_size": selected_size,
        "link_rsp_sha256": sha256(rsp_raw).hexdigest(),
        "input_sha256": input_hashes,
        "archives": {a.name: {"sha256": sha256(a.raw).hexdigest(),
                              "members": [o.identity for o in a.objects],
                              "index": a.index} for a in archives},
        "references": events,
        "all_archive_members_scanned": True,
        "capture_paths_resolved_and_reparse_free": True,
        "capture_read_race_eliminated": False,
        "direct_call_instruction_boundary_proven": False,
        "library_member_selection_proven": False,
        "source_output_binding": False,
        "final_image_reference_closure_proven": False,
        "production_admitted": False,
    }
