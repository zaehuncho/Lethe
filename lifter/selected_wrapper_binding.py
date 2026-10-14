"""Consumed selected direct caller binding for the two authenticated fixtures.

This narrow NOICF profile never proves global/indirect closure or that captured
runtime COFF objects were compiled from the runtime source manifest.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
import re
import struct

from . import direct_control_flow, pdb_coverage, pdb_function_inventory
from . import link_capture_final_callsites as final_calls
from .link_capture_archive import _capture_root, _capture_regular_file
from .link_capture_diagnostic import inspect_capture_inputs, CaptureDiagnosticError
from .link_capture_response_pair import (
    _read_response as _pair_response, _profile, _environment_profile, _PDBMAP,
)
from .link_capture_selected_references import (
    inspect_selected_capture, _scan_inventory, SelectedReferenceError, _archive_bodies, _name,
)
from .source_link_product_admission import (
    ProductSourceInputs, ProductSourceProofError, _coff_defined_externals,
    _require_no_executable_relocations,
)


class SelectedWrapperProofError(ValueError):
    """A selected fixture caller or transformation cannot be attributed."""


@dataclass(frozen=True)
class SelectedWrapperLinkInputs:
    original_capture: Path
    generated_inputs: tuple[Path, ...]
    native_initializer_object: Path | None = None


@dataclass(frozen=True)
class _MaterializedWrapperEntry:
    symbol: str
    prefix: str
    wrapper_rva: int
    wrapper_size: int
    thunk_rva: int
    common_rva: int
    descriptor_rva: int
    final_pe_sha256: str
    final_pdb_sha256: str
    final_map_sha256: str


_RUNTIME_OBJECTS = (
    "daedalus_vm.obj", "crypto.obj", "bytecode_pages.obj", "key_scatter.obj",
    "daedalus_x64_thunk.obj", "daedalus_store128.obj",
    "daedalus_call_frame.obj", "daedalus_trampoline.obj",
)


def _require(value, reason):
    if not value:
        raise SelectedWrapperProofError(reason)


def _sha(raw):
    return sha256(raw).hexdigest()


def validate_inputs(inputs: SelectedWrapperLinkInputs) -> None:
    _require(type(inputs) is SelectedWrapperLinkInputs and
             isinstance(inputs.original_capture, Path) and
             type(inputs.generated_inputs) is tuple and
             len(inputs.generated_inputs) == 11 and
             all(isinstance(p, Path) for p in inputs.generated_inputs) and
             (inputs.native_initializer_object is None or
              isinstance(inputs.native_initializer_object, Path)),
             "exact selected wrapper inputs with eleven generated objects required")
    _require(len({p.name.casefold() for p in inputs.generated_inputs}) == 11,
             "generated object names are duplicated")


def _wrapper_response(inventory, output):
    switches = inventory.get("switches")
    _require(type(switches) is list and all(type(s) is str for s in switches),
             "wrapper response switch inventory is malformed")
    lower = [s.casefold() for s in switches]
    _require(lower.count("/guard:xfg") == 1 and
             lower.count("/opt:noicf") == 1 and "/opt:icf" not in lower,
             "wrapper profile requires unique XFG declaration and NOICF")
    # The existing conventional whitelist remains unchanged; the new profile
    # consumes and pins only this additional declaration before delegating.
    conventional = dict(inventory)
    conventional["switches"] = [s for s in switches if s.casefold() != "/guard:xfg"]
    final_calls._required_response(conventional, output,
        _require_import_library=False)


def _coff_section_names(raw: bytes, kind: str) -> tuple[bytes, ...]:
    """Resolve actual COFF names, including bounded /decimal string offsets."""
    header, width = (56, 20) if kind == "bigobj_amd64" else (20, 18)
    _require(len(raw) >= header, "COFF section-name header is truncated")
    count = (struct.unpack_from("<I", raw, 44)[0] if header == 56
             else struct.unpack_from("<H", raw, 2)[0])
    _require(0 <= count <= 65535 and header + count * 40 <= len(raw),
             "COFF section-name inventory is malformed")
    strings = None
    cache = {}
    work = 0
    names = []
    for index in range(count):
        field = raw[header + index * 40:header + index * 40 + 8]
        name, _, suffix = field.partition(b"\0")
        _require(not suffix.strip(b"\0"), "COFF short section name has hidden suffix bytes")
        if name.startswith(b"/"):
            _require(re.fullmatch(br"/[0-9]{1,7}", name) is not None,
                     "COFF long section offset is malformed")
            if strings is None:
                symptr, nsyms = struct.unpack_from("<II", raw, 48 if header == 56 else 8)
                start = symptr + nsyms * width
                _require(nsyms <= 2_000_000 and symptr >= header + count * 40 and
                         start + 4 <= len(raw), "COFF long section string table is missing")
                length = struct.unpack_from("<I", raw, start)[0]
                _require(4 <= length <= 64 * 1024 * 1024 and start + length <= len(raw),
                         "COFF long section string table is truncated")
                strings = raw[start:start + length]
            offset = int(name[1:])
            _require(4 <= offset < len(strings), "COFF long section offset is out of bounds")
            if offset not in cache:
                budget = min(4097, len(strings) - offset)
                work += budget
                _require(work <= 8 * 1024 * 1024, "COFF section-name work exceeds bound")
                end = strings.find(b"\0", offset, offset + budget)
                _require(end > offset, "COFF long section name is empty, unterminated or excessive")
                cache[offset] = strings[offset:end]
            name = cache[offset]
        _require(0 < len(name) <= 4096 and
                 re.fullmatch(br"[A-Za-z0-9_.$@?+\-]+", name) is not None,
                 "COFF section name is non-ASCII or ambiguous")
        names.append(name)
    return tuple(names)


def _native_initializer(raw: bytes, symbol: str) -> None:
    defined = _coff_defined_externals(raw)
    _require(len(defined) == 1 and defined[0][0] == symbol and defined[0][2] == 0,
             "native initializer must define only the exact no-op init symbol")
    _require_no_executable_relocations(raw)
    section = defined[0][1]
    _require(struct.unpack_from("<I", raw, 20 + (section - 1) * 40 + 36)[0] & 0x20000000,
             "native initializer definition is not in the sole executable section")
    size, pointer = struct.unpack_from("<II", raw, 20 + (section - 1) * 40 + 16)
    _require(size == 3 and 0 < pointer and pointer + size <= len(raw) and
             raw[pointer:pointer + size] in (b"\x33\xc0\xc3", b"\x31\xc0\xc3"),
             "native initializer is not exact XOR EAX,EAX; RET")
    count = struct.unpack_from("<H", raw, 2)[0]
    symptr, nsyms = struct.unpack_from("<II", raw, 8)
    primary = []
    i = 0
    while i < nsyms:
        pos = symptr + i * 18
        if raw[pos + 16] == 2 and struct.unpack_from("<h", raw, pos + 12)[0] > 0:
            primary.append(i)
        i += 1 + raw[pos + 17]
    _require(len(primary) == 1, "native initializer external index is ambiguous")
    names = _coff_section_names(raw, "ordinary_amd64_coff")
    for index in range(count):
        pos = 20 + index * 40
        name = names[index]
        size, pointer, reloc = struct.unpack_from("<III", raw, pos + 16)
        nreloc = struct.unpack_from("<H", raw, pos + 32)[0]
        flags = struct.unpack_from("<I", raw, pos + 36)[0]
        _require(pointer + size <= len(raw),
                 "native initializer section name/data is ambiguous")
        body = raw[pointer:pointer + size]
        if index + 1 == section:
            continue
        if name in (b".debug$S", b".debug$T"):
            _require(flags & 0x02000000 and not flags & (0x20000000 | 0x80000000) and
                     body[:4] == b"\x04\0\0\0" and
                     (not nreloc or (name == b".debug$S" and reloc > 0 and
                                     reloc + nreloc * 10 <= len(raw))),
                     "native initializer debug metadata is unclassified")
            for j in range(nreloc):
                field, target, kind = struct.unpack_from("<IIH", raw, reloc + j * 10)
                _require(kind in (0xA, 0xB) and field + (2 if kind == 0xA else 4) <= size and target == primary[0],
                         "native initializer debug relocation is unclassified")
        elif name == b".drectve":
            _require(flags == 0x00100A00 and not reloc and not nreloc and
                     body.split() == [b'/DEFAULTLIB:"MSVCRT"', b'/DEFAULTLIB:"OLDNAMES"'],
                     "native initializer linker directives are unclassified")
        elif name == b".gxfg$y":
            _require(flags == 0x40501040 and not reloc and not nreloc and size == 16 and
                     struct.unpack_from("<Q", body)[0] == primary[0] and
                     body[8:] == bytes.fromhex("7030525e472705d3"),
                     "native initializer guard metadata differs from int(void) profile")
        elif name == b".chks64":
            _require(flags == 0xA00 and not reloc and not nreloc and 0 < size <= 768,
                     "native initializer compiler checksum metadata is unclassified")
        else:
            raise SelectedWrapperProofError("native initializer has unclassified runtime data/sections")
    _reject_other_typeservers(raw, "ordinary_amd64_coff")


def _wrapper_coff(raw: bytes, symbol: str, prefix: str) -> None:
    defined = _coff_defined_externals(raw)
    _require(len(defined) == 1 and defined[0][0] == symbol and defined[0][2] == 0,
             "wrapper object must define only the selected entry")
    count = struct.unpack_from("<H", raw, 2)[0]
    index = defined[0][1]
    executable = [i + 1 for i in range(count)
                  if struct.unpack_from("<I", raw, 20 + i * 40 + 36)[0] & 0x20000000]
    _require(executable == [index], "wrapper object has an unclassified executable section")
    pos = 20 + (index - 1) * 40
    size, pointer, reloc = struct.unpack_from("<III", raw, pos + 16)
    nreloc = struct.unpack_from("<H", raw, pos + 32)[0]
    expected = bytes.fromhex("0fb644242888442428") if prefix == "policy_vm" else b""
    expected += b"\xe9\0\0\0\0"
    _require(size == len(expected) and pointer > 0 and pointer + size <= len(raw) and
             raw[pointer:pointer + size] == expected and nreloc == 1 and
             0 < reloc and reloc + 10 <= len(raw),
             "wrapper COFF does not contain the exact typed tail template")
    field, target, kind = struct.unpack_from("<IIH", raw, reloc)
    symptr, nsyms = struct.unpack_from("<II", raw, 8)
    primary_indices = set()
    index = 0
    while index < nsyms:
        primary_indices.add(index)
        index += 1 + raw[symptr + index * 18 + 17]
    _require(kind == 4 and field == len(expected) - 4 and target < nsyms,
             "wrapper COFF tail relocation differs")
    _require(target in primary_indices, "wrapper COFF tail names an auxiliary symbol")
    strings = raw[symptr + nsyms * 18:]
    target_pos = symptr + target * 18
    _require(_name(raw[target_pos:target_pos + 8], strings) == prefix and
             struct.unpack_from("<h", raw, target_pos + 12)[0] == 0 and
             raw[target_pos + 16] == 2,
             "wrapper tail relocation does not name the generated thunk")


def _material(inventory):
    result = {}
    for item in (*inventory["inputs"], *inventory.get("implicit_libraries", ())):
        name = item.get("name", item.get("identity"))
        _require(type(name) is str and name not in result,
                 "captured material input identity is duplicated")
        result[name] = item["sha256"]
    return result


def _reject_other_typeservers(raw: bytes, kind: str) -> None:
    """First profile rejects every retained type server, including all aliases.

    Parsing record boundaries rather than searching a path avoids treating a
    slash/dot/short-name spelling as independent debug provenance. Z7 inline
    type records remain supported; unknown/malformed debug metadata rejects.
    """
    if kind in ("short_import_v0", "opaque_win32_resource"):
        return
    _require(kind in ("ordinary_amd64_coff", "bigobj_amd64", "neutral_debug_coff"),
             "unclassified retained debug input")
    header = 56 if kind == "bigobj_amd64" else 20
    count = (struct.unpack_from("<I", raw, 44)[0] if header == 56
             else struct.unpack_from("<H", raw, 2)[0])
    _require(0 <= count <= 65535 and header + count * 40 <= len(raw),
             "retained debug section inventory is malformed")
    records = 0
    names = _coff_section_names(raw, kind)
    for index in range(count):
        pos = header + index * 40
        if names[index].lower() != b".debug$t":
            continue
        size, pointer = struct.unpack_from("<II", raw, pos + 16)
        _require(size >= 4 and 0 < pointer and pointer + size <= len(raw),
                 "retained type section is truncated")
        body = raw[pointer:pointer + size]
        _require(body[:4] == b"\x04\0\0\0", "retained type section has unsupported signature")
        off = 4
        while off < len(body):
            _require(off + 4 <= len(body), "retained type record header is truncated")
            length, leaf = struct.unpack_from("<HH", body, off)
            end = off + 2 + length
            _require(length >= 2 and end <= len(body), "retained type record is truncated")
            _require(leaf not in (0x1515, 0x1501, 0x0016),
                     "retained input type server prevents unique helper PDBMAP removal")
            records += 1
            _require(records <= 2_000_000, "retained type record count exceeds bound")
            off = end


def _helper_debug_pdb_delta(source, old_root, new_root, old_tokens, new_tokens,
                            old_pdb, new_pdb, old_rows, new_rows, removed):
    """Only the removed helper's unique LF_TYPESERVER2 PDBMAP may disappear.

    This binds debug input provenance, not an independently parsed compiler-PDB
    identity. Fresh original/final raw-PE replay and final DIA proofs remain
    mandatory. A byte mention by any retained material input rejects removal.
    """
    if old_pdb == new_pdb and old_rows == new_rows:
        return []
    _require(not new_pdb and not new_rows and len(old_pdb) == len(old_rows) == 1,
             "unrelated mapped PDB input changed")
    mappings = [m.groups() for token in old_tokens if (m := _PDBMAP.fullmatch(token))]
    _require(len(mappings) == 1 and not any(_PDBMAP.fullmatch(x) for x in new_tokens),
             "removed helper debug PDB mapping is ambiguous")
    original_path, mapped = mappings[0]
    raw = final_calls._read(source.helper_object, "original helper debug COFF")
    count = struct.unpack_from("<H", raw, 2)[0]
    bodies = []
    names = _coff_section_names(raw, "ordinary_amd64_coff")
    for index in range(count):
        pos = 20 + index * 40
        if names[index].lower() != b".debug$t":
            continue
        size, pointer = struct.unpack_from("<II", raw, pos + 16)
        _require(0 < pointer and pointer + size <= len(raw), "helper type-server section is truncated")
        bodies.append(raw[pointer:pointer + size])
    _require(len(bodies) == 1 and 27 <= len(bodies[0]) <= 4096,
             "helper requires a single bounded CodeView type-server record")
    body = bodies[0]
    length, kind = struct.unpack_from("<HH", body, 4)
    _require(body[:4] == b"\x04\0\0\0" and kind == 0x1515 and
             length + 6 == len(body), "helper CodeView is not exact LF_TYPESERVER2")
    nul = body.find(b"\0", 28)
    _require(nul >= 28 and body[nul + 1:] in (b"", b"\xf1", b"\xf2\xf1", b"\xf3\xf2\xf1"),
             "helper type-server path/padding is malformed")
    try:
        path = body[28:nul].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SelectedWrapperProofError("helper type-server path is not UTF-8") from exc
    _require(path.casefold() == original_path.casefold() and
             mapped[2:].casefold() in old_pdb,
             "removed PDBMAP does not bind the removed helper type server")
    _require(re.fullmatch(r"[A-Za-z]:\\(?:[A-Za-z0-9_. -]+\\)*[A-Za-z0-9_. -]+", path) is not None and
             str(Path(path)) == path and
             all(part not in (".", "..") and not part.endswith((".", " "))
                 for part in Path(path).parts[1:]) and
             body[8:24] != bytes(16) and struct.unpack_from("<I", body, 24)[0] > 0,
             "helper type-server identity/path is noncanonical")
    for root in (old_root, new_root):
        inventory = inspect_capture_inputs(root)
        for item in (*inventory["inputs"], *inventory.get("implicit_libraries", ())):
            name = item.get("name", item.get("identity"))
            if root == old_root and name == source.helper_object.name:
                continue
            retained = _capture_regular_file(root, name)
            if item["kind"] == "microsoft_coff_archive":
                for member, member_raw in _archive_bodies(retained, item["members"]):
                    _reject_other_typeservers(member_raw, member["kind"])
            else:
                _reject_other_typeservers(retained, item["kind"])
    return [{"mapped_name": mapped[2:], "sha256": old_pdb[mapped[2:].casefold()],
             "helper_typeserver_path": path, "helper_typeserver_guid_bytes": body[8:24].hex(),
             "helper_typeserver_age": struct.unpack_from("<I", body, 24)[0],
             "compiler_pdb_identity_independently_proven": False}]


def _capture_contract(source, replay, inputs, prefix):
    """Fresh complete scans plus exact bounded material delta and order."""
    validate_inputs(inputs)
    selected = inspect_selected_capture(inputs.original_capture, source)
    before = inspect_capture_inputs(inputs.original_capture)
    after = inspect_capture_inputs(replay.capture_dir)
    _wrapper_response(before, source.image.name)
    _wrapper_response(after, replay.built_image.name)
    _require(source.image.name == replay.built_image.name and
             source.pdb.name == replay.built_pdb.name and
             source.link_map.name == replay.built_map.name and
             source.pdb.name == source.image.stem + ".pdb" and
             source.link_map.name == source.image.stem + ".map",
             "original/final output and sidecar basenames must match")
    helper = selected["helper_object"]
    _require(helper == source.helper_object.name,
             "captured original helper identity differs")
    generated_names = tuple(p.name for p in inputs.generated_inputs)
    roles = {prefix + "_wrapper.obj", prefix + ".obj", prefix + "_data.obj", *_RUNTIME_OBJECTS}
    _require(set(generated_names) == roles,
             "generated objects differ from the fixed fixture role set")
    pins = {}
    for path in inputs.generated_inputs:
        raw = final_calls._read(path, "generated compiled input")
        pins[str(path)] = _sha(raw)
        if path.name == prefix + "_wrapper.obj":
            _wrapper_coff(raw, source.symbol, prefix)
    old, new = _material(before), _material(after)
    removed = {helper}
    if inputs.native_initializer_object is not None:
        init_path = inputs.native_initializer_object
        init = final_calls._read(init_path, "native initializer")
        _native_initializer(init, prefix + "_fixture_init")
        _require(old.get(init_path.name) == _sha(init) and init_path.name != helper,
                 "native initializer differs from original capture")
        removed.add(init_path.name)
        pins[str(init_path)] = _sha(init)
    _require(set(old) - set(new) == removed and set(new) - set(old) == roles,
             "captured material delta differs from exact helper/init replacement")
    _require(all(new[name] == digest for name, digest in old.items() if name not in removed),
             "nonhelper material input changed")
    _require(all(new[name] == pins[str(path)] for name, path in
                 zip(generated_names, inputs.generated_inputs)),
             "generated captured object differs from supplied compiled bytes")
    old_root, new_root = _capture_root(inputs.original_capture), _capture_root(replay.capture_dir)
    old_rsp, old_tokens = _pair_response(old_root)
    new_rsp, new_tokens = _pair_response(new_root)
    old_profile, old_order, old_pdb, old_pdb_rows = _profile(old_root, old_tokens)
    new_profile, new_order, new_pdb, new_pdb_rows = _profile(new_root, new_tokens)
    _require(tuple(x for x in old_profile if x.startswith("/")) ==
             tuple(x for x in new_profile if x.startswith("/")),
             "link options changed")
    removed_debug = _helper_debug_pdb_delta(source, old_root, new_root,
        old_tokens, new_tokens, old_pdb, new_pdb, old_pdb_rows, new_pdb_rows, removed)
    _require(tuple(x for x in old_order if x[2:] not in removed) ==
             tuple(x for x in new_order if x[2:] not in roles) and
             tuple(x[2:] for x in new_order if x[2:] in roles) == generated_names and
             all(old_order.count('.\\' + name) == 1 for name in removed) and
             all(new_order.count('.\\' + name) == 1 for name in roles),
             "unchanged material input order or exact generated order differs")
    _require(_environment_profile(old_root)[1] == _environment_profile(new_root)[1],
             "captured material environment changed")
    definitions, references, _debug, _counts = _scan_inventory(
        replay.capture_dir, after, source.symbol, prefix + "_wrapper.obj")
    _require(len(definitions) == 1 and definitions[0]["object"] == prefix + "_wrapper.obj" and
             definitions[0]["section"] > 0 and definitions[0]["value"] == 0,
             "final capture has missing or competing selected wrapper definition")
    _require(references == selected["references"],
             "final capture has changed or additional selected direct references")
    if inputs.native_initializer_object is not None:
        init_symbol = prefix + "_fixture_init"
        old_defs, old_refs, _debug, _counts = _scan_inventory(
            inputs.original_capture, before, init_symbol, inputs.native_initializer_object.name)
        new_defs, new_refs, _debug, _counts = _scan_inventory(
            replay.capture_dir, after, init_symbol, prefix + "_data.obj")
        _require(len(old_defs) == len(new_defs) == 1 and
                 old_defs[0]["object"] == inputs.native_initializer_object.name and
                 new_defs[0]["object"] == prefix + "_data.obj" and
                 old_defs[0]["value"] == new_defs[0]["value"] == 0 and
                 old_refs == new_refs and bool(old_refs),
                 "initializer replacement definition or unchanged direct callers differ")
    old_hash = selected["source_coff_sha256"]
    for item in (*after["inputs"], *after.get("implicit_libraries", ())):
        name = item.get("name", item.get("identity"))
        raw = _capture_regular_file(new_root, name)
        _require(_sha(raw) != old_hash, "original helper remains in final capture")
        if item["kind"] == "microsoft_coff_archive":
            _require(all(_sha(body) != old_hash for _, body in _archive_bodies(raw, item["members"])),
                     "original helper remains in a captured archive")
    final_calls._reject_archive_caller_label_aliases(before, selected)
    final_calls._reject_archive_caller_label_aliases(after, selected)
    return selected, before, after, pins, {"original_rsp_sha256": old_rsp,
        "replacement_rsp_sha256": new_rsp, "removed_objects": sorted(removed),
        "removed_helper_debug_pdb_inputs": removed_debug,
        "generated_objects": list(generated_names), "all_nonhelper_material_bytes_equal": True,
        "unchanged_material_order_equal": True, "environment_equal_except_bound_capture_paths": True}


def _same_inventory(built, replayed, replay):
    _require(replayed.image_sha256 == built.image_sha256 == replay["pe_sha256"] and
             replayed.identity == built.identity and replayed.symbol_count == built.symbol_count and
             replayed.distinct_ranges == built.distinct_ranges and
             replayed.supplemental_ranges == built.supplemental_ranges and
             replayed.range_multiplicities == built.range_multiplicities and
             replayed.helper_sha256 == built.helper_sha256 and replayed.msdia_sha256 == built.msdia_sha256 and
             replayed.pdb_sha256 == replay["replay_pdb_sha256"] and
             built.pdb_sha256 == replay["built_pdb_sha256"],
             "replayed wrapper PDB identity or complete inventory differs")


def _thunk_direct_entries(direct_flow, entry):
    end = entry.thunk_rva + 46
    incoming = []
    for edge in direct_flow.direct_transfers:
        if not entry.thunk_rva <= edge.target_rva < end:
            continue
        _require(not entry.thunk_rva + 15 <= edge.target_rva < entry.thunk_rva + 23,
                 "direct transfer enters thunk descriptor data")
        if entry.thunk_rva <= edge.source_rva < end:
            _require((edge.source_rva - entry.thunk_rva, edge.target_rva - entry.thunk_rva, edge.kind)
                     in ((13, 23, "jump"), (27, 39, "conditional_jump")),
                     "thunk internal direct edge differs from exact template")
        else:
            incoming.append(edge)
    _require(len(incoming) == 1 and incoming[0].kind == "jump" and
             incoming[0].source_rva == entry.wrapper_rva + entry.wrapper_size - 5 and
             incoming[0].target_rva == entry.thunk_rva and incoming[0].reachable_from_selected_entry,
             "only the freshly verified wrapper tail may directly enter the thunk")


def prove_selected_wrapper(source: ProductSourceInputs, replay, inputs,
                           entry: _MaterializedWrapperEntry, replay_parent: Path) -> dict:
    """Called only after the public verifier freshly authenticates this entry."""
    _require(type(entry) is _MaterializedWrapperEntry and entry.symbol == source.symbol,
             "fresh private wrapper entry binding required")
    tool_pins = {path: _sha(final_calls._read(path, "selected proof DIA/ABI tool", final_calls._MAX_TOOL))
                 for path in (source.dia_helper, source.msdia, source.typed_abi_helper)}
    selected, before, after, external_pins, delta = _capture_contract(
        source, replay, inputs, entry.prefix)
    link, link_sha = final_calls._validated_linker(replay.link_exe)
    replay_parent.mkdir()
    final_calls._validated_replay_parent(replay_parent, (
        _capture_root(inputs.original_capture), _capture_root(replay.capture_dir),
        source.image.parent, source.pdb.parent, source.link_map.parent,
        replay.built_image.parent, replay.built_pdb.parent, replay.built_map.parent,
    ))
    # As in the existing exact fixture replay, bind RSDS path bytes from the
    # built image; only debug path metadata is appended to direct argv.
    from .product_fixture_link_verify import _rsds
    original_pdb_path = _rsds(final_calls._read(source.image, "original RSDS PE"))[2]
    final_pdb_path = _rsds(final_calls._read(replay.built_image, "final RSDS PE"))[2]
    old_replay = final_calls._copy_and_replay(
        inputs.original_capture, before, source, replay_parent, "original", link,
        _bound_pdb_path=original_pdb_path)
    old = final_calls._one_image(inputs.original_capture, source, selected, old_replay)
    final_source = replace(source, image=replay.built_image, pdb=replay.built_pdb,
                           link_map=replay.built_map,
                           helper_object=next(p for p in inputs.generated_inputs
                                              if p.name == entry.prefix + "_wrapper.obj"))
    new_replay = final_calls._copy_and_replay(
        replay.capture_dir, after, final_source, replay_parent, "replacement", link,
        _bound_pdb_path=final_pdb_path)
    _require(new_replay["pe_sha256"] == entry.final_pe_sha256 and
             new_replay["built_pdb_sha256"] == entry.final_pdb_sha256 and
             new_replay["map_sha256"] == entry.final_map_sha256,
             "final replay differs from authenticated wrapper entry")
    parsed = final_calls.analyze_pe(str(replay.built_image))
    sections = direct_control_flow._normalize_sections(parsed)
    thunk = direct_control_flow._EntryThunkRange(entry.thunk_rva, entry.common_rva, entry.descriptor_rva)
    # Fresh exact template/PDATA/unwind/data-skip decode precedes the sole
    # executable relocation exception. Every other executable DIR64 rejects.
    direct_control_flow._entry_thunk_decodes(parsed, sections, (thunk,))
    island = (entry.thunk_rva + 15, entry.thunk_rva + 23)
    for relocation in parsed.dir64_relocations:
        site = relocation.target_rva
        if any(s.characteristics & 0x20000000 and site < s.mapped_end and
               s.rva < site + 8 for s in sections):
            _require(site == island[0], "unclassified DIR64 changes executable code")
    jump = entry.wrapper_rva + entry.wrapper_size - 5
    tail = direct_control_flow.TailExitPolicy((direct_control_flow.TailExitApproval(
        entry.wrapper_rva, jump, entry.thunk_rva, "fresh exact authenticated typed wrapper tail"),))
    chosen = (direct_control_flow.SelectedFunctionRange(source.symbol, entry.wrapper_rva, entry.wrapper_size),)
    coverage = pdb_coverage.prove_pdb_executable_coverage(
        parsed, replay.built_image, replay.built_pdb, source.dia_helper, source.msdia,
        chosen, tail_exit_policy=tail, _structured_entry_thunks=(thunk,))
    _thunk_direct_entries(coverage.direct_flow, entry)
    common_range = [item for item in parsed.runtime_functions if item.begin_rva == entry.common_rva]
    _require(len(common_range) == 1 and
             [(begin, end, count) for begin, end, count in coverage.inventory.range_multiplicities
              if begin == entry.common_rva] == [(entry.common_rva, common_range[0].end_rva, 1)],
             "common bridge PDB/PDATA entry is missing or aliased")
    replay_parsed = final_calls.analyze_pe(str(new_replay["replay_pe"]))
    replayed_inventory = pdb_function_inventory.run_bound_inventory(
        replay_parsed, new_replay["replay_pe"], new_replay["replay_pdb"], source.dia_helper, source.msdia)
    _same_inventory(coverage.inventory, replayed_inventory, new_replay)
    rows = final_calls._strict_map_rows(final_calls._read(replay.built_map, "final caller MAP"))
    final_calls._require_explicit_helper_row(rows, source.symbol,
        parsed.image_base + entry.wrapper_rva, entry.prefix + "_wrapper.obj")
    refs, expected, outcomes = final_calls._attribute_selected_callers(
        replay.capture_dir, selected, rows, coverage, parsed, entry.wrapper_rva,
        new_replay["stdout"], data_islands=(island,))
    _require([(i["object"], i["section_index"], i["primary"], i["status"]) for i in old["section_outcomes"]] ==
             [(i["object"], i["section_index"], i["primary"], i["status"]) for i in outcomes] and
             old["retained_direct_calls"] == len(expected),
             "selected caller retained/discarded disposition changed")
    for path, digest in external_pins.items():
        _require(_sha(final_calls._read(Path(path), "post-proof compiled input")) == digest,
                 "compiled input changed during selected wrapper proof")
    for capture, inventory in ((inputs.original_capture, before), (replay.capture_dir, after)):
        _require(inspect_capture_inputs(capture) == inventory,
                 "captured inputs changed during selected wrapper proof")
    final_calls._final_source_and_replay_pins(source, old, old_replay, selected["source_coff_sha256"])
    for path, digest in ((replay.built_image, entry.final_pe_sha256),
                         (replay.built_pdb, entry.final_pdb_sha256), (replay.built_map, entry.final_map_sha256),
                         (new_replay["replay_pe"], entry.final_pe_sha256),
                         (new_replay["replay_pdb"], new_replay["replay_pdb_sha256"]),
                         (new_replay["replay_map"], entry.final_map_sha256),
                         (new_replay["log_path"], new_replay["log_sha256"])):
        _require(_sha(final_calls._read(path, "post-proof bound output")) == digest,
                 "wrapper output or sidecar changed during proof")
    _require(_sha(final_calls._read(replay.link_exe, "post-proof linker")) == link_sha and
             all(old_replay["environment"][name] == new_replay["environment"][name] for name in
                 ("cmd_exe_sha256", "taskkill_exe_sha256", "rc_exe_sha256", "mt_exe_sha256")),
             "selected proof linker or SDK tools changed")
    for path, digest in tool_pins.items():
        _require(_sha(final_calls._read(path, "post-proof DIA/ABI tool", final_calls._MAX_TOOL)) == digest,
                 "selected proof DIA/ABI tool changed")
    for capture, proof in ((inputs.original_capture, old_replay), (replay.capture_dir, new_replay)):
        _require(final_calls._replay_environment(capture, proof["replay_pe"].parent, Path(link))[1] == proof["environment"],
                 "selected proof replay environment or SDK tools changed after DIA")
    return {"schema": 1, "status": "authenticated_selected_wrapper_references_bound",
        "selected": source.symbol, "original": old, "replacement": {
            "selected_rva": entry.wrapper_rva, "selected_size": entry.wrapper_size,
            "source_relocation_count": len(refs), "retained_direct_calls": len(expected),
            "discarded_selected_relocations": len(refs) - len(expected),
            "section_outcomes": outcomes, "output_call_rvas": sorted(expected)},
        "capture_delta": delta, "compiled_input_sha256": external_pins,
        "selected_direct_source_output_equivalence_proven": True,
        "authenticated_selected_wrapper_reference_binding_proven": True,
        "original_helper_object_omission_proven": True,
        "global_source_output_reference_equivalence_proven": False,
        "runtime_source_compile_binding_proven": False, "indirect_target_closure_proven": False,
        "xfg_enforcement_proven": False, "production_admitted": False}
