"""Selected-symbol COFF reference proof for exact conventional /LINKREPRO inputs.

This is deliberately narrower than a final-image closure proof. Every captured
explicit object and captured archive member is checked, so the selected-symbol
result does not assume a linker member-extraction order. Linker extraction,
/OPT:REF/ICF mapping, indirect target closure and production admission remain
separate false fields until stronger evidence exists.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import struct

from iced_x86 import Decoder, FlowControl, Mnemonic, OpKind

from .link_capture_archive import _capture_regular_file, _capture_root
from .link_capture_diagnostic import CaptureDiagnosticError, inspect_capture_inputs
from .source_link_product_admission import (
    ProductSourceInputs, ProductSourceProofError, inspect_source,
)


class SelectedReferenceError(ValueError):
    """The selected symbol's captured source references are not proven."""


@dataclass(frozen=True)
class _Symbol:
    name: str
    section: int
    value: int
    kind: int
    storage: int
    aux: int
    weak_tag: int | None


def _require(ok: bool, reason: str) -> None:
    if not ok:
        raise SelectedReferenceError(reason)


def _name(field: bytes, strings: bytes) -> str:
    if field[:4] == b"\0" * 4:
        off = struct.unpack_from("<I", field, 4)[0]
        _require(4 <= off < len(strings), "COFF long symbol offset is invalid")
        end = strings.find(b"\0", off)
        _require(end >= 0 and end - off <= 65535, "COFF long symbol is unbounded")
        data = strings[off:end]
    else:
        data = field.split(b"\0", 1)[0]
    try:
        return data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SelectedReferenceError("COFF symbol is not ASCII") from exc


def _scan_object(identity: str, raw: bytes, kind: str, selected: str,
                 *, helper_name: str | None = None) -> dict:
    """Parse actual primary symbols and selected relocations, including bigobj."""
    if kind == "short_import_v0":
        _require(selected.encode("ascii") not in raw,
                 "selected symbol is imported by an archive short-import member")
        return {"definitions": [], "references": [], "debug_references": [], "weak_symbols": 0,
                "target_weak_aliases": 0, "target_directives": 0,
                "all_executable_relocations": 0}
    if kind == "neutral_debug_coff":
        _require(selected.encode("ascii") not in raw,
                 "selected symbol appears in neutral debug-only archive member")
        return {"definitions": [], "references": [], "debug_references": [], "weak_symbols": 0,
                "target_weak_aliases": 0, "target_directives": 0,
                "all_executable_relocations": 0}
    _require(kind in ("ordinary_amd64_coff", "bigobj_amd64"),
             "uninterpreted selected-symbol input")
    big = kind == "bigobj_amd64"
    header, width = (56, 20) if big else (20, 18)
    if big:
        _require(len(raw) >= 56 and raw[:4] == b"\0\0\xff\xff",
                 "bigobj header differs from inventory")
        count, symptr, nsyms = struct.unpack_from("<III", raw, 44)
    else:
        _require(len(raw) >= 20 and struct.unpack_from("<H", raw)[0] == 0x8664,
                 "ordinary COFF header differs from inventory")
        count = struct.unpack_from("<H", raw, 2)[0]
        symptr, nsyms = struct.unpack_from("<II", raw, 8)
    _require(0 < count <= 65535 and header + count * 40 <= len(raw),
             "COFF sections are unbounded")
    _require(0 <= nsyms <= 2_000_000, "COFF symbols are unbounded")
    if nsyms:
        _require(symptr >= header + count * 40 and
                 symptr + nsyms * width + 4 <= len(raw),
                 "COFF symbol table is out of bounds")
        string_start = symptr + nsyms * width
        string_size = struct.unpack_from("<I", raw, string_start)[0]
        _require(4 <= string_size <= len(raw) - string_start,
                 "COFF string table is out of bounds")
        strings = raw[string_start:string_start + string_size]
    else:
        strings = b""
    symbols: dict[int, _Symbol] = {}
    i = 0
    while i < nsyms:
        off = symptr + i * width
        if big:
            value, section, type_code, storage, aux = struct.unpack_from(
                "<IiHBB", raw, off + 8)
        else:
            value, section, type_code, storage, aux = struct.unpack_from(
                "<IhHBB", raw, off + 8)
        _require(i + aux < nsyms and section <= count,
                 "COFF symbol auxiliary range or section is invalid")
        weak_tag = None
        if storage == 105:
            _require(aux >= 1, "weak COFF external lacks auxiliary record")
            weak_tag = struct.unpack_from("<I", raw, off + width)[0]
            _require(weak_tag < nsyms, "weak COFF alternative is out of bounds")
        symbols[i] = _Symbol(_name(raw[off:off + 8], strings), section,
                             value, type_code, storage, aux, weak_tag)
        i += aux + 1
    for symbol in symbols.values():
        if symbol.weak_tag is not None:
            _require(symbol.weak_tag in symbols,
                     "weak COFF alternative references an auxiliary record")
    weak_total = sum(s.weak_tag is not None for s in symbols.values())
    target_weak = sum(s.weak_tag is not None and
                      (s.name == selected or symbols[s.weak_tag].name == selected)
                      for s in symbols.values())
    _require(target_weak == 0, "selected symbol has weak external/alternate route")
    definitions = []
    selected_indices = set()
    for index, symbol in symbols.items():
        if symbol.name == selected:
            _require(symbol.storage == 2 and symbol.kind & 0x20 and
                     symbol.section >= 0 and symbol.value == 0,
                     "selected symbol is not an exact external function")
            selected_indices.add(index)
            if symbol.section:
                definitions.append({"object": identity, "section": symbol.section,
                                    "value": symbol.value})
    refs = []
    debug_refs = []
    target_directives = 0
    all_executable_relocations = 0
    for section_no in range(1, count + 1):
        head = header + (section_no - 1) * 40
        size, dataoff, reloff = struct.unpack_from("<III", raw, head + 16)
        nrel = struct.unpack_from("<H", raw, head + 32)[0]
        flags = struct.unpack_from("<I", raw, head + 36)[0]
        _require(not flags & 0x01000000 and reloff + nrel * 10 <= len(raw),
                 "COFF relocation span is unsupported")
        if flags & 0x20000000:
            all_executable_relocations += nrel
        section_label = raw[head:head + 8].split(b"\0", 1)[0]
        if section_label == b".drectve":
            _require(size > 0 and dataoff > 0 and dataoff + size <= len(raw),
                     "COFF linker directive bytes are unsupported")
            if selected.encode("ascii") in raw[dataoff:dataoff + size]:
                target_directives += 1
        if not selected_indices or not nrel:
            continue
        for j in range(nrel):
            field, index, rel_kind = struct.unpack_from("<IIH", raw, reloff + j * 10)
            if index not in selected_indices:
                continue
            if (not flags & 0x20000000 and identity == helper_name and
                    section_label == b".debug$S" and rel_kind in (0xA, 0xB)):
                _require(dataoff > 0 and dataoff + size <= len(raw) and
                         field + 4 <= size,
                         "selected helper debug relocation field is out of bounds")
                debug_refs.append({"object": identity, "section_index": section_no,
                                   "relocation_field": field, "relocation_kind": rel_kind,
                                   "classification": "self_debug_metadata_not_runtime_proven"})
                continue
            _require(flags & 0x20000000 and flags & 0x20,
                     f"selected relocation is non-executable or address-taken: {identity} section={section_no} kind=0x{rel_kind:x} field={field}")
            _require(dataoff > 0 and dataoff + size <= len(raw) and
                     1 <= field and field + 4 <= size,
                     "selected relocation field is out of executable section")
            body = raw[dataoff:dataoff + size]
            addend = struct.unpack_from("<i", body, field)[0]
            _require(rel_kind == 0x4 and addend == 0 and body[field - 1] == 0xE8,
                     "selected relocation is not zero-addend AMD64 REL32 E8")
            # The E8 predecessor is not enough: validate it is a decoded CALL
            # at the actual section instruction boundary, not embedded data.
            decoded = tuple(Decoder(64, body, ip=0))
            _require(decoded and all(not ins.is_invalid for ins in decoded) and
                     sum(ins.len for ins in decoded) == len(body),
                     "selected source section has ambiguous instruction bytes")
            by_ip = {ins.ip: ins for ins in decoded}
            _require(len(by_ip) == len(decoded) and 0 in by_ip,
                     "selected source section has ambiguous instruction boundaries")
            reachable: set[int] = set()
            pending = [0]
            while pending:
                ip = pending.pop()
                if ip in reachable:
                    continue
                _require(ip in by_ip,
                         "selected source section branches into data or middle of instruction")
                reachable.add(ip)
                ins = by_ip[ip]
                if ins.flow_control in (FlowControl.NEXT, FlowControl.CALL,
                                        FlowControl.INDIRECT_CALL):
                    successors = (ins.next_ip,)
                elif ins.flow_control == FlowControl.CONDITIONAL_BRANCH:
                    successors = (ins.next_ip, ins.near_branch_target)
                elif ins.flow_control == FlowControl.UNCONDITIONAL_BRANCH:
                    successors = (ins.near_branch_target,)
                elif ins.flow_control == FlowControl.RETURN:
                    successors = ()
                else:
                    raise SelectedReferenceError(
                        "selected source section has unsupported control flow")
                _require(all(child in by_ip for child in successors),
                         "selected source section has an unbounded branch/fallthrough")
                pending.extend(successors)
            _require(len(reachable) == len(decoded),
                     "selected source section has unreachable encoded bytes")
            calls = [ins for ins in decoded if ins.ip + 1 == field]
            _require(len(calls) == 1 and calls[0].ip in reachable and
                     calls[0].len == 5 and calls[0].mnemonic == Mnemonic.CALL and
                     calls[0].op_count == 1 and
                     calls[0].op_kind(0) == OpKind.NEAR_BRANCH64,
                     "selected E8 is not a reachable decoded direct CALL boundary")
            refs.append({"object": identity, "section_index": section_no,
                         "section_label_hex": raw[head:head + 8].hex(),
                         "relocation_field": field, "relocation_kind": rel_kind,
                         "symbol_index": index, "section_sha256": sha256(body).hexdigest(),
                         "classification": "decoded_call_rel32_zero_addend"})
    _require(target_directives == 0,
             "selected symbol appears in linker directive/alternate route")
    return {"definitions": definitions, "references": refs,
            "debug_references": debug_refs, "weak_symbols": weak_total, "target_weak_aliases": target_weak,
            "target_directives": target_directives,
            "all_executable_relocations": all_executable_relocations}


def _archive_bodies(raw: bytes, members: list[dict]):
    """Rebind diagnostic member offsets/hashes to the original archive bytes."""
    for member in members:
        pos = member["header_offset"]
        _require(8 <= pos and pos + 60 <= len(raw) and raw[pos + 58:pos + 60] == b"`\n",
                 "archive member header changed after diagnostic inventory")
        text = raw[pos + 48:pos + 58].decode("ascii").strip()
        _require(text.isdigit(), "archive member length is invalid")
        size = int(text)
        _require(pos + 60 + size <= len(raw), "archive member exceeds captured file")
        body = raw[pos + 60:pos + 60 + size]
        _require(sha256(body).hexdigest() == member["sha256"],
                 "archive member changed after diagnostic inventory")
        yield member, body


def _scan_inventory(capture: Path, inventory: dict, selected: str,
                    helper_name: str) -> tuple[list[dict], list[dict], list[dict], Counter]:
    root = _capture_root(capture)
    definitions: list[dict] = []
    references: list[dict] = []
    debug_references: list[dict] = []
    counts: Counter[str] = Counter()
    for item in (*inventory["inputs"], *inventory.get("implicit_libraries", ())):
        name = item.get("name", item.get("identity"))
        _require(isinstance(name, str), "captured input identity is missing")
        raw = _capture_regular_file(root, name)
        _require(sha256(raw).hexdigest() == item["sha256"],
                 "captured input changed after diagnostic inventory")
        if item["kind"] == "microsoft_coff_archive":
            counts["libraries"] += 1
            for member, body in _archive_bodies(raw, item["members"]):
                counts["archive_members"] += 1
                if member["kind"] == "short_import_v0":
                    counts["short_import_members"] += 1
                scan = _scan_object(member["identity"], body, member["kind"], selected,
                                    helper_name=helper_name)
                definitions.extend(scan["definitions"])
                references.extend(scan["references"])
                debug_references.extend(scan["debug_references"])
                counts["weak_symbols"] += scan["weak_symbols"]
                counts["all_executable_relocations"] += scan["all_executable_relocations"]
                if scan["references"]:
                    counts["selected_archive_references"] += len(scan["references"])
        elif item["kind"] == "opaque_win32_resource":
            counts["opaque_resources"] += 1
            _require(selected.encode("ascii") not in raw,
                     "selected symbol bytes in uninterpreted resource")
        else:
            counts["explicit_objects"] += 1
            if item["kind"] == "bigobj_amd64":
                counts["explicit_bigobj"] += 1
            scan = _scan_object(name, raw, item["kind"], selected,
                                helper_name=helper_name)
            definitions.extend(scan["definitions"])
            references.extend(scan["references"])
            debug_references.extend(scan["debug_references"])
            counts["weak_symbols"] += scan["weak_symbols"]
            counts["all_executable_relocations"] += scan["all_executable_relocations"]
    return definitions, references, debug_references, counts


def inspect_selected_capture(capture: Path, inputs: ProductSourceInputs) -> dict:
    """Classify selected-symbol references in captured explicit and implicit COFF.

    This scans every member of each captured archive, but cannot prove that
    LINK.EXE used only these copies or which archive members it extracted.
    """
    try:
        source = inspect_source(inputs)
    except ProductSourceProofError as exc:
        raise SelectedReferenceError(f"exact source proof failed: {exc}") from exc
    _require(source["source_body_and_abi_verified"] is True and
             source["symbol"] == inputs.symbol,
             "exact source PE/PDB/MAP/COFF proof is missing")
    try:
        inventory = inspect_capture_inputs(capture)
    except CaptureDiagnosticError as exc:
        raise SelectedReferenceError(f"LINKREPRO inventory failed: {exc}") from exc
    _require(not any(inputs.symbol in token for token in inventory["switches"]),
             "selected symbol appears in LINKREPRO linker option")
    # LINKREPRO can suffix the same file label after repeated captures. The
    # exact COFF hash, not that display label, binds the source helper.
    helper_matches = [item for item in inventory["inputs"]
                      if item.get("kind") == "ordinary_amd64_coff" and
                      item["sha256"] == source["source_coff_sha256"]]
    _require(len(helper_matches) == 1,
             "captured original helper COFF is missing or duplicated")
    helper_name = helper_matches[0]["identity"]
    definitions, references, debug_references, counts = _scan_inventory(
        capture, inventory, inputs.symbol, helper_name)
    _require(len(definitions) == 1 and definitions[0]["object"] == helper_name and
             definitions[0]["section"] > 0 and definitions[0]["value"] == 0,
             "selected symbol has a missing or competing definition")
    _require(bool(references), "captured inputs contain no selected direct calls")
    counts["selected_direct_calls"] = len(references)
    counts["selected_debug_metadata_relocations"] = len(debug_references)
    counts["nonselected_executable_relocations"] = (
        counts["all_executable_relocations"] - len(references))
    _require(counts["nonselected_executable_relocations"] >= 0,
             "selected executable relocation accounting is inconsistent")
    # Re-read exact capture-local inputs before returning. Diagnostic and scan
    # are separate passes, not a claim of race-free filesystem handles.
    root = _capture_root(capture)
    for item in (*inventory["inputs"], *inventory.get("implicit_libraries", ())):
        name = item.get("name", item.get("identity"))
        _require(sha256(_capture_regular_file(root, name)).hexdigest() == item["sha256"],
                 "captured input changed after selected-reference scan")
    return {"schema": 1, "status": "selected_input_references_classified",
            "selected": inputs.symbol, "helper_object": helper_name,
            "source_pe_sha256": source["source_pe_sha256"],
            "source_pdb_sha256": source["source_pdb_sha256"],
            "source_map_sha256": source["source_map_sha256"],
            "source_coff_sha256": source["source_coff_sha256"],
            "pdb_binding_sha256": source["pdb_binding_sha256"],
            "capture_rsp_sha256": inventory["link_rsp_sha256"],
            "capture_input_hashes": {item.get("name", item.get("identity")): item["sha256"]
                                     for item in (*inventory["inputs"],
                                                  *inventory.get("implicit_libraries", ()))},
            "response_input_hashes": {item.get("name", item.get("identity")): item["sha256"]
                                      for item in inventory["inputs"]},
            "implicit_library_hashes": {item["name"]: item["sha256"]
                                         for item in inventory.get("implicit_libraries", ())},
            "capture_file_sha256": inventory.get("capture_file_sha256", {}),
            "capture_file_roles": inventory.get("capture_file_roles", {}),
            "definitions": definitions, "references": references,
            "debug_references": debug_references,
            "counts": dict(sorted(counts.items())),
            "all_possible_archive_members_scanned": False,
            "all_captured_archive_members_scanned": True,
            "all_captured_implicit_libraries_inventoried": inventory.get(
                "all_captured_implicit_libraries_inventoried", False),
            "all_captured_implicit_libraries_scanned": True,
            "selected_input_references_classified": True,
            "capture_read_race_eliminated": False,
            "archive_member_extraction_proven": False,
            "source_output_reference_equivalence_proven": False,
            "original_helper_object_omission_proven": False,
            "indirect_target_closure_proven": False,
            "xfg_enforcement_proven": False,
            "production_admitted": False}


def inspect_replacement_omission(original: dict, replacement_capture: Path) -> dict:
    """Check exact material-input omission, not PE/linker behavioral parity."""
    _require(original.get("selected_input_references_classified") is True,
             "original selected capture proof is missing")
    try:
        replacement = inspect_capture_inputs(replacement_capture)
    except CaptureDiagnosticError as exc:
        raise SelectedReferenceError(f"replacement LINKREPRO inventory failed: {exc}") from exc
    old_hash = original["source_coff_sha256"]
    helper = original["helper_object"]
    before = original["capture_input_hashes"]
    after = {item.get("name", item.get("identity")): item["sha256"]
             for item in (*replacement["inputs"],
                          *replacement.get("implicit_libraries", ()))}
    _require(set(before) == set(after) and helper in after and
             after[helper] != old_hash,
             "replacement input set/helper object is not exact")
    _require(all(after[name] == digest for name, digest in before.items()
                 if name != helper),
             "non-helper captured inputs differ from original link")
    _require(all(item["sha256"] != old_hash for item in
                 (*replacement["inputs"], *replacement.get("implicit_libraries", ()))),
             "original helper object remains a captured top-level input")
    _require(all(member["sha256"] != old_hash
                 for item in (*replacement["inputs"],
                              *replacement.get("implicit_libraries", ()))
                 if item["kind"] == "microsoft_coff_archive"
                 for member in item["members"]),
             "original helper object remains in a captured archive")
    root = _capture_root(replacement_capture)
    changed_raw = _capture_regular_file(root, helper)
    changed_item = next(item for item in replacement["inputs"]
                        if item.get("identity") == helper)
    changed = _scan_object(helper, changed_raw, changed_item["kind"],
                           original["selected"], helper_name=helper)
    _require(len(changed["definitions"]) == 1 and
             changed["definitions"][0]["object"] == helper,
             "replacement does not define the exact selected symbol")
    return {"status": "original_object_absent_from_captured_replacement_inputs",
            "original_coff_sha256": old_hash,
            "replacement_coff_sha256": after[helper],
            "replacement_rsp_sha256": replacement["link_rsp_sha256"],
            "replacement_implicit_library_hashes": {
                item["name"]: item["sha256"]
                for item in replacement.get("implicit_libraries", ())},
            "replacement_capture_file_sha256": replacement.get(
                "capture_file_sha256", {}),
            "replacement_capture_file_roles": replacement.get(
                "capture_file_roles", {}),
            "other_input_hashes_equal": True,
            "original_helper_object_omission_proven": True,
            "archive_member_extraction_proven": False,
            "source_output_reference_equivalence_proven": False,
            "final_image_reference_closure_proven": False,
            "indirect_target_closure_proven": False,
            "production_admitted": False}








