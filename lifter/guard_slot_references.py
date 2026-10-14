"""Source/PDB-bound GuardCF reference inventory, never an admission proof.

This read-only collector runs an explicitly supplied trusted DIA helper against
snapshots and compares a freshly reconstructed full commit binding. It records
unresolved domains rather than guessing absence of computed references. No
packer/runtime module imports this opt-in API.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from contextlib import ExitStack
from dataclasses import dataclass, fields, is_dataclass, replace
from hashlib import sha256
import bisect
import json
import os
from pathlib import Path
import stat
import tempfile

from iced_x86 import (Decoder, FlowControl, InstructionInfoFactory, MemorySizeExt,
                      Mnemonic, OpKind, Register)

from packer import pe_analyze
from . import direct_control_flow, jump_table, pdb_coverage, pdb_function_inventory


class GuardReferenceError(ValueError):
    """The exact source, binding, metadata, or instruction ownership disagrees."""


@dataclass(frozen=True)
class PdbInputFiles:
    """Explicit operator-trusted tools and PDB, not object-type authentication."""
    pdb: Path
    helper: Path
    msdia: Path


@dataclass(frozen=True)
class SourceIdentity:
    image_sha256: str
    pdb_sha256: str
    helper_sha256: str
    msdia_sha256: str
    parsed_sha256: str
    binding_sha256: str
    rsds_guid: str
    rsds_age: int


@dataclass(frozen=True)
class SourceRange:
    begin: int
    end: int
    owners: tuple[str, ...]
    runtime_members: tuple[tuple[int, int, int, int, int], ...]
    pdb_members: tuple[tuple[int, int, int], ...]


@dataclass(frozen=True)
class GuardSlot:
    kind: str
    rva: int
    initial_value: int
    section: str
    section_flags: int
    page_rva: int
    page_section_flags: tuple[int, ...]
    load_config_field_rva: int


@dataclass(frozen=True)
class ReferenceTarget:
    kind: str
    rva: int
    size: int


@dataclass(frozen=True)
class TargetOverlap:
    kind: str
    target_offset: int


@dataclass(frozen=True)
class SourceReference:
    rva: int
    end_rva: int
    source_bytes: bytes
    kind: str
    targets: tuple[TargetOverlap, ...]
    access: int | None = None
    width: int | None = None
    segment: int | None = None
    address_size: int | None = None
    effective_address: int | None = None


@dataclass(frozen=True)
class DataReference:
    rva: int
    source_bytes: bytes
    encoding: str
    targets: tuple[TargetOverlap, ...]
    metadata_owners: tuple[str, ...]


@dataclass(frozen=True)
class AliasCandidate:
    load_rva: int
    call_rva: int
    call_end_rva: int
    register: int
    slot_kind: str
    load_bytes: bytes
    call_bytes: bytes
    known_interior_reference_rvas: tuple[int, ...]


@dataclass(frozen=True)
class UnresolvedDomain:
    """Aggregate count plus at most eight samples, NOT a per-site inventory."""
    reason: str
    count: int
    example_rvas: tuple[int, ...]


@dataclass(frozen=True)
class GuardSlotReferenceInventory:
    version: int
    identity: SourceIdentity
    guard_flags: int
    xfg_fields_present: bool
    xfg_enabled: bool
    slots: tuple[GuardSlot, ...]
    targets: tuple[ReferenceTarget, ...]
    ranges: tuple[SourceRange, ...]
    unique_instruction_count: int
    instruction_index_sha256: str
    indirect_instruction_rvas: tuple[int, ...]
    references: tuple[SourceReference, ...]
    data_references: tuple[DataReference, ...]
    aliases: tuple[AliasCandidate, ...]
    unresolved: tuple[UnresolvedDomain, ...]

    def canonical_bytes(self) -> bytes:
        """Deterministic inspection format, not an unchecked proof importer."""
        def encode(value):
            if is_dataclass(value):
                return {f.name: encode(getattr(value, f.name)) for f in fields(value)}
            if isinstance(value, tuple):
                return [encode(item) for item in value]
            if isinstance(value, bytes):
                return value.hex()
            return value
        return json.dumps(encode(self), sort_keys=True, separators=(",", ":")).encode()


_SLOTS = (("cf_check", "guard_cf_check_function_pointer_rva", 112),
          ("cf_dispatch", "guard_cf_dispatch_function_pointer_rva", 120),
          ("xfg_check", "guard_xfg_check_function_pointer_rva", 280),
          ("xfg_dispatch", "guard_xfg_dispatch_function_pointer_rva", 288),
          ("xfg_table", "guard_xfg_table_dispatch_function_pointer_rva", 296))
_MAX_IMAGE = 512 * 1024 * 1024
_MAX_INPUT_TOTAL = 768 * 1024 * 1024
_MAX_INSTRUCTIONS = 2_000_000
_MAX_REFERENCES = 100_000
_MAX_LITERAL_SEARCH_WORK = 1024 * 1024 * 1024
_IMMEDIATES = frozenset(getattr(OpKind, n) for n in dir(OpKind)
                        if n.startswith("IMMEDIATE"))
_NEAR = frozenset((OpKind.NEAR_BRANCH16, OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH64))


def collect_guard_slot_references(
    parsed: pe_analyze.ParsedPE, binding: pdb_coverage.PdbCommitBinding,
    *, pdb_inputs: PdbInputFiles,
) -> GuardSlotReferenceInventory:
    """Collect all fixed-address candidates and explicit unresolved domains.

    A completed commit binding and explicit trusted PDB/tool paths are required.
    The actual PDB/DIA coverage and full binding are rebuilt, not authenticated
    by a Python type or self-hash. The result never closes computed routes.
    Unresolved records are aggregate domain summaries with sampled RVAs;
    unlisted instructions must never be inferred free of computed references.
    """
    if type(parsed) is not pe_analyze.ParsedPE or type(binding) is not pdb_coverage.PdbCommitBinding:
        raise GuardReferenceError("exact ParsedPE and PdbCommitBinding are required")
    if type(pdb_inputs) is not PdbInputFiles or any(not isinstance(p, Path) for p in
            (pdb_inputs.pdb, pdb_inputs.helper, pdb_inputs.msdia)):
        raise GuardReferenceError("explicit PdbInputFiles paths are required")
    # This shares the existing DIA snapshot trust model. Preflight rejects
    # reparse components, but is not a hostile ancestor-race/handle-ID proof.
    try:
        paths = (Path(parsed.path), pdb_inputs.pdb, pdb_inputs.helper, pdb_inputs.msdia)
        for path in paths:
            if not path.is_absolute() or ".." in path.parts:
                raise GuardReferenceError("input paths must be absolute and canonical")
            for component in (path, *path.parents):
                info = component.lstat()
                if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    raise GuardReferenceError("reparse input paths are unsupported")
            if not stat.S_ISREG(path.stat().st_mode):
                raise GuardReferenceError("input path is not a regular file")
        if len(set(path.resolve() for path in paths)) != 4:
            raise GuardReferenceError("source/PDB/tool input roles must use distinct files")
        grouped = defaultdict(list)
        for path in paths:
            grouped[path.parent].append(path)
        with ExitStack() as stack:
            for group in grouped.values():
                stack.enter_context(pdb_function_inventory._seal_snapshot_paths(tuple(group)))
            if any(os.path.samefile(left,right) for index,left in enumerate(paths)
                   for right in paths[index+1:]):
                raise GuardReferenceError("input roles must identify distinct file objects")
            sizes = tuple(path.stat().st_size for path in paths)
            if any(not 0 < size <= _MAX_IMAGE for size in sizes) or sum(sizes) > _MAX_INPUT_TOTAL:
                raise GuardReferenceError("source/PDB/tool input size bounds exceeded")
            return _collect_locked(parsed, binding, pdb_inputs)
    except (OSError, ValueError, AttributeError, TypeError) as exc:
        if isinstance(exc, GuardReferenceError):
            raise
        raise GuardReferenceError(f"input snapshot validation failed: {exc}") from exc


def _bounded_read(path: Path) -> bytes:
    with path.open("rb") as stream:
        content = stream.read(_MAX_IMAGE+1)
    if len(content) > _MAX_IMAGE:
        raise GuardReferenceError("input grew beyond bounded capacity")
    return content


def _collect_locked(parsed, binding, pdb_inputs):
    for name in ("image_sha256", "pdb_sha256", "helper_sha256", "msdia_sha256",
                 "source_parsed_sha256", "binding_sha256"):
        value = getattr(binding, name)
        if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise GuardReferenceError("binding source identities are not canonical SHA-256")
    try:
        source = Path(parsed.path)
        if not 0 < source.stat().st_size <= _MAX_IMAGE:
            raise GuardReferenceError("source image exceeds inventory bounds")
        image = _bounded_read(source)
        if len(image) > _MAX_IMAGE or sha256(image).hexdigest() != binding.image_sha256:
            raise GuardReferenceError("source image differs from binding")
        # Parsing a private snapshot avoids mixing file versions during parsing.
        with tempfile.TemporaryDirectory(prefix="lethe-guard-refs-") as root:
            snapshot = Path(root) / "image.bin"
            snapshot.write_bytes(image)
            with pdb_function_inventory._seal_snapshot_paths((snapshot,)):
                if _bounded_read(snapshot) != image:
                    raise GuardReferenceError("private source snapshot changed before parsing")
                fresh = replace(pe_analyze.analyze_pe(str(snapshot)), path=parsed.path)
                if _bounded_read(snapshot) != image:
                    raise GuardReferenceError("private source snapshot changed during parsing")
        if fresh != parsed:
            raise GuardReferenceError("parsed PE differs from exact source snapshot")
        pdb_coverage.validate_pdb_commit_binding(parsed, binding.direct_flow.selected_functions, binding)
        external = (pdb_inputs.pdb, pdb_inputs.helper, pdb_inputs.msdia)
        external_hashes = tuple(sha256(_bounded_read(p)).hexdigest() for p in external)
        if external_hashes != (binding.pdb_sha256, binding.helper_sha256, binding.msdia_sha256):
            raise GuardReferenceError("external PDB/tool files differ from binding")
        proof = pdb_coverage.prove_pdb_executable_coverage(
            parsed, source, pdb_inputs.pdb, pdb_inputs.helper, pdb_inputs.msdia,
            binding.direct_flow.selected_functions, tail_exit_policy=binding.tail_exit_policy)
        rebuilt = pdb_coverage.bind_pdb_commit_proof(parsed, proof, binding.direct_flow.selected_functions)
        if rebuilt != binding:
            raise GuardReferenceError("fresh external PDB coverage/binding differs")
        identity = proof.inventory.identity
        if identity != pdb_function_inventory.extract_codeview_identity(image):
            raise GuardReferenceError("fresh PDB identity differs from source RSDS")
    except (OSError, TypeError, AttributeError, ValueError) as exc:
        if isinstance(exc, GuardReferenceError):
            raise
        raise GuardReferenceError(f"source/binding validation failed: {exc}") from exc

    lc = parsed.load_config
    if type(lc) is not pe_analyze.ParsedLoadConfig:
        raise GuardReferenceError("a validated load-config inventory is required")
    base = parsed.image_base
    if type(base) is not int or not 0 < base < 1 << 64 or base + parsed.size_of_image > 1 << 64:
        raise GuardReferenceError("invalid preferred image VA range")

    def raw(rva, size):
        owners = [s for s in parsed.sections
                  if s.rva <= rva and 0 <= size <= len(s.raw)
                  and rva - s.rva <= len(s.raw) - size]
        if len(owners) != 1:
            raise GuardReferenceError("reference is not uniquely file backed")
        s = owners[0]
        return s.raw[rva-s.rva:rva-s.rva+size], s

    counts = Counter()
    examples = defaultdict(list)
    def unknown(reason, rva=None):
        counts[reason] += 1
        if rva is not None and len(examples[reason]) < 8 and rva not in examples[reason]:
            examples[reason].append(rva)
    def bounded_append(items, item):
        if len(items) >= _MAX_REFERENCES:
            raise GuardReferenceError("reference inventory exceeds bounded capacity")
        items.append(item)

    slots = []
    relocations = {r.target_rva for r in parsed.dir64_relocations}
    for kind, attribute, field in _SLOTS:
        rva = getattr(lc, attribute)
        if not rva:
            continue
        if type(rva) is not int or rva & 7 or not 0 < rva <= parsed.size_of_image - 8:
            raise GuardReferenceError("guard slot is not an aligned image qword")
        if any(abs(rva - prior.rva) < 8 for prior in slots):
            raise GuardReferenceError("guard slot spans overlap")
        data, section = raw(rva, 8)
        value = int.from_bytes(data, "little")
        field_rva = lc.directory_rva + field
        field_data, _ = raw(field_rva, 8)
        if int.from_bytes(field_data, "little") != base + rva:
            raise GuardReferenceError("load-config field does not identify its guard slot")
        if field_rva not in relocations or (base <= value < base + parsed.size_of_image and rva not in relocations):
            raise GuardReferenceError("guard slot pointer lacks source DIR64 provenance")
        page = rva & ~0xFFF
        page_flags = tuple(s.characteristics for s in parsed.sections
                           if s.rva < page + 0x1000
                           and page < s.rva + max(s.virtual_size, len(s.raw)))
        if any(f & 0x80000000 for f in page_flags):
            unknown("statically_writable_guard_slot_page", rva)
        slots.append(GuardSlot(kind, rva, value, section.name, section.characteristics,
                               page, page_flags, field_rva))
    if not slots:
        raise GuardReferenceError("load-config declares no guard slots")

    flow = binding.direct_flow
    span_owners = defaultdict(set)
    for r in flow.decoded_runtime_functions:
        span_owners[(r.begin_rva, r.end_rva)].add("runtime")
    for r in flow.decoded_supplemental_ranges:
        span_owners[(r.begin_rva, r.end_rva)].add("pdb_or_canonical_residual")
    for r in flow.selected_functions:
        span_owners[(r.rva, r.end_rva)].add("selected")
    spans = sorted(span_owners)
    if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
        raise GuardReferenceError("strict decode ownership spans overlap")
    instructions = {}
    embedded_data = []
    for a, b in spans:
        try:
            body = jump_table.decode_function_body(raw(a, b-a)[0], a, b)
        except jump_table.JumpTableError as exc:
            raise GuardReferenceError(f"strict source decode failed: {exc}") from exc
        embedded_data.extend(body.data_ranges)
        for instruction in body.instructions:
            ip = instruction.ip
            if ip in instructions:
                raise GuardReferenceError("duplicate instruction ownership")
            data = raw(ip, instruction.len)[0]
            decoder = Decoder(64, data, ip=base+ip)
            actual = decoder.decode()
            if actual.is_invalid or actual.len != len(data):
                raise GuardReferenceError("actual-VA instruction decode disagrees")
            instructions[ip] = (actual, data)
            if len(instructions) > _MAX_INSTRUCTIONS:
                raise GuardReferenceError("instruction inventory exceeds bounds")
    ips = sorted(instructions)
    if any(a+len(instructions[a][1]) > b for a,b in zip(ips, ips[1:])):
        raise GuardReferenceError("decoded instruction byte spans overlap")
    indirect = tuple(ip for ip in ips if instructions[ip][0].flow_control
                     in (FlowControl.INDIRECT_CALL, FlowControl.INDIRECT_BRANCH))
    expected = tuple(sorted(r.source_rva for r in flow.indirect_transfers))
    if len(set(expected)) != len(expected) or indirect != expected:
        raise GuardReferenceError("unique indirect IP inventory differs from binding")

    targets = [ReferenceTarget(s.kind, s.rva, 8) for s in slots]
    for slot in slots:
        rva = slot.initial_value - base
        exact = [span for span in spans if span[0] == rva]
        if not 0 <= rva < parsed.size_of_image or not exact:
            unknown("initial_dispatch_target_not_owned_source_entry", slot.rva)
            continue
        a,b = exact[0]
        targets.append(ReferenceTarget(slot.kind+"_initial_target", a, b-a))
    aliases = []
    for ip in ips:
        i, data = instructions[ip]
        if (len(data) == 7 and data[:3] in (b"\x48\x8b\x15", b"\x4c\x8b\x0d")
                and i.segment_prefix == Register.NONE and i.memory_base == Register.RIP):
            slot = next((s for s in slots if base+s.rva == int(i.ip_rel_memory_address)), None)
            next_pair = instructions.get(ip+7)
            if slot and next_pair:
                call, call_data = next_pair
                if ((data[:3] == b"\x48\x8b\x15" and call_data == b"\xff\xd2") or
                    (data[:3] == b"\x4c\x8b\x0d" and call_data == b"\x41\xff\xd1")):
                    aliases.append(AliasCandidate(ip, ip+7, ip+7+len(call_data),
                                                  i.op_register(0), slot.kind, data, call_data, ()))
                    if len(aliases) > 256:
                        raise GuardReferenceError("alias inventory exceeds bounded capacity")
                    # Include every known reference to window interior, not just
                    # branches that also happen to target a guard slot.
                    targets.append(ReferenceTarget("alias_interior_"+str(ip), ip+1,
                                                   6+len(call_data)))
    targets = tuple(targets)

    def hits(address, width, *, rva=False):
        offset = 0 if rva else base
        return tuple(TargetOverlap(t.kind, max(0,address-(offset+t.rva))) for t in targets
                     if max(address,offset+t.rva) < min(address+width,offset+t.rva+t.size))
    references = []
    factory = InstructionInfoFactory()
    for ip in ips:
        i,data = instructions[ip]
        end = ip + len(data)
        if i.op_count and i.op_kind(0) in _NEAR:
            matched = hits(int(i.near_branch_target),1)
            if matched:
                bounded_append(references, SourceReference(ip,end,data,"direct_transfer",matched))
        for operand in range(i.op_count):
            if i.op_kind(operand) in _IMMEDIATES:
                value = int(i.immediate(operand))
                for encoding,matched in (("immediate_VA_candidate",hits(value,1)),
                                          ("immediate_RVA_candidate",hits(value,1,rva=True))):
                    if matched:
                        bounded_append(references, SourceReference(ip,end,data,encoding,matched,
                                                                   effective_address=value))
        if i.mnemonic == Mnemonic.LEA:
            if i.is_ip_rel_memory_operand:
                matched = hits(int(i.ip_rel_memory_address),1)
                if matched:
                    bounded_append(references, SourceReference(ip,end,data,"address_take_LEA",matched,
                                                               effective_address=int(i.ip_rel_memory_address)))
            else:
                unknown("computed_LEA_address",ip)
        for memory in factory.info(i).used_memory():
            width = MemorySizeExt.size(memory.memory_size)
            if not width:
                unknown("variable_or_unknown_memory_extent",ip)
            if memory.segment in (Register.FS, Register.GS):
                unknown("FS_GS_segment_base",ip)
                continue
            if memory.base != Register.NONE or memory.index != Register.NONE:
                unknown("base_index_or_implicit_memory",ip)
                continue
            address = int(memory.displacement)
            if memory.address_size == 2:
                address &= 0xFFFFFFFF
            elif memory.address_size == 1:
                address &= 0xFFFF
            elif memory.address_size != 3:
                unknown("unknown_address_size",ip)
                continue
            if not width or address + width > 1 << 64:
                unknown("unbounded_or_wrapping_static_memory_span",ip)
                continue
            if memory.address_size in (1, 2) and address + width > (1 << (16 if memory.address_size == 1 else 32)):
                # Do not assume byte-span wrap/segmentation semantics from the
                # starting effective address alone.
                unknown("address_size_span_boundary",ip)
                continue
            matched = hits(address,width)
            if matched:
                kind = "fixed_memory"
                if i.is_ip_rel_memory_operand and i.segment_prefix == Register.NONE:
                    if len(data)==6 and data[:2]==b"\xff\x15":kind="canonical_memory_CALL"
                    elif data[:2]==b"\xff\x25" and len(data)==6 or data[:3]==b"\x48\xff\x25" and len(data)==7:kind="canonical_memory_JMP"
                bounded_append(references, SourceReference(ip,end,data,kind,matched,memory.access,width,
                                                           memory.segment,memory.address_size,address))

    data_refs = []
    def metadata_at(rva):
        owners = []
        if rva in relocations:owners.append("DIR64")
        if lc.directory_rva <= rva < lc.directory_rva+lc.declared_size:
            owners.append("load_config+"+str(rva-lc.directory_rva))
        if parsed.pdata_rva <= rva < parsed.pdata_rva+12*parsed.pdata_count:
            owners.append("pdata+"+str(rva-parsed.pdata_rva))
        if any(s.rva==rva for s in slots):owners.append("guard_slot_storage")
        return tuple(owners)
    for rva in sorted(relocations):
        data,_ = raw(rva,8)
        matched = hits(int.from_bytes(data,"little"),1)
        if matched:
            bounded_append(data_refs,DataReference(rva,data,"DIR64_VA",matched,metadata_at(rva)))
    # Exact and interior literal candidates at every byte alignment in data.
    patterns = set()
    for target in targets:
        if target.size > 4096:
            unknown("large_initial_target_interior_literal_domain",target.rva)
        for delta in range(min(target.size,4096)):
            for encoding,value,width in (("RVA32",target.rva+delta,4),
                                          ("VA64",base+target.rva+delta,8)):
                patterns.add((encoding,value.to_bytes(width,"little")))
    domains = [(s.rva,s.rva+len(s.raw)) for s in parsed.sections
               if not s.characteristics&0x20000000] + embedded_data
    if sum(b-a for a,b in set(domains)) * len(patterns) > _MAX_LITERAL_SEARCH_WORK:
        raise GuardReferenceError("literal scan work exceeds bounded capacity")
    for a,b in sorted(set(domains)):
        blob,_ = raw(a,b-a)
        for encoding,needle in sorted(patterns):
            pos=0
            while True:
                at=blob.find(needle,pos)
                if at<0:break
                pos=at+1
                value=int.from_bytes(needle,"little")
                matched=hits(value,1,rva=encoding=="RVA32")
                bounded_append(data_refs,DataReference(a+at,needle,encoding+"_candidate",matched,
                                                       metadata_at(a+at)))
    aliases = tuple(replace(a,known_interior_reference_rvas=tuple(sorted({
        ref.rva for ref in references
        if any(t.kind == "alias_interior_"+str(a.load_rva) for t in ref.targets)
    } | {d.rva for d in data_refs
         if any(t.kind == "alias_interior_"+str(a.load_rva) for t in d.targets)}
      | {t.rva for table in (lc.guard_cf_targets, lc.guard_long_jump_targets,
                             lc.guard_eh_continuation_targets) for t in table
         if a.load_rva<t.rva<a.call_end_rva}))) for a in aliases)
    # These boundaries remain explicit even when their observed count is zero.
    for reason in ("unknown_computed_reference_routes","external_host_and_callback_routes",
                   "resident_runtime_target_domains","runtime_page_and_slot_lifetime"):
        unknown(reason)
    if lc.guard_flags & 0x800000:
        unknown("active_XFG_contract")
    try:
        if (_bounded_read(source) != image
                or tuple(sha256(_bounded_read(p)).hexdigest() for p in external) != external_hashes
                or pdb_coverage.parsed_source_sha256(parsed) != binding.source_parsed_sha256):
            raise GuardReferenceError("source or external evidence changed during inventory")
    except OSError as exc:
        raise GuardReferenceError("source or external evidence became unavailable") from exc
    digest=sha256()
    for ip in ips:
        data=instructions[ip][1];digest.update(ip.to_bytes(4,"little"));digest.update(len(data).to_bytes(1,"little"));digest.update(data)
    runtime_rows = tuple(sorted((r.begin_rva,r.end_rva,r.unwind_info_rva,r.unwind_flags,r.chain_primary_rva)
                                for r in parsed.runtime_functions))
    pdb_rows = proof.inventory.range_multiplicities
    runtime_begins = tuple(r[0] for r in runtime_rows)
    pdb_begins = tuple(r[0] for r in pdb_rows)
    def overlapping(rows, begins, a, b):
        lo = max(0,bisect.bisect_right(begins,a)-1)
        hi = bisect.bisect_left(begins,b)
        return tuple(r for r in rows[lo:hi] if r[1]>a)
    return GuardSlotReferenceInventory(1,SourceIdentity(binding.image_sha256,binding.pdb_sha256,
        binding.helper_sha256,binding.msdia_sha256,binding.source_parsed_sha256,binding.binding_sha256,
        str(identity.guid),identity.age),lc.guard_flags,lc.xfg_present,bool(lc.guard_flags&0x800000),
        tuple(slots),targets,tuple(SourceRange(a,b,tuple(sorted(span_owners[(a,b)])),
            overlapping(runtime_rows,runtime_begins,a,b), overlapping(pdb_rows,pdb_begins,a,b))
            for a,b in spans),
        len(ips),digest.hexdigest(),indirect,tuple(references),tuple(sorted(data_refs,key=lambda x:(x.rva,x.encoding,x.source_bytes))),
        aliases,tuple(UnresolvedDomain(reason,count,tuple(examples[reason])) for reason,count in sorted(counts.items())))
