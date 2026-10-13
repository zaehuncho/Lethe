"""Read-only admission proof for product-shaped scalar source helpers.

This proves an exact PE/PDB/MAP/COFF body, scalar DIA ABI, and bounded native
control-flow graph. It does not emit bytecode, waive XFG, close final-link
references, or approve production virtualization.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import os
import re
import stat
import struct
import subprocess

from iced_x86 import Decoder, FlowControl, Mnemonic, OpKind, Register
import pefile

from daedalus import daedalus_asm
from packer.pe_analyze import (
    IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT, analyze_pe,
)
from . import (
    direct_control_flow, pdb_coverage, pdb_function_inventory,
    source_link_build, x64_lifter,
)


class ProductSourceProofError(ValueError):
    """A product-shaped source helper did not meet the narrow proof contract."""


@dataclass(frozen=True)
class ProductSourceInputs:
    image: Path
    pdb: Path
    link_map: Path
    helper_object: Path
    symbol: str
    abi: str
    dia_helper: Path
    msdia: Path
    typed_abi_helper: Path


_DECORATED = re.compile(r"\?[A-Za-z_][A-Za-z0-9_?@]{1,190}@Z\Z")
_TYPED_OUTPUT = re.compile(
    r"ABI_TYPED rva=([0-9A-F]{8}) size=([0-9]+) argc=([0-8]) "
    r"ret=bool args=((?:bool|i64)(?:,(?:bool|i64)){0,7}) callconv=0\r?\n\Z"
)


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _read(path: Path, label: str) -> bytes:
    _reject_reparse_components(Path(path))
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise ProductSourceProofError(f"missing {label}") from exc


def _reject_reparse_components(path: Path) -> None:
    """Reject an observed symlink/junction path, not claim race-free access."""
    current = Path(os.path.abspath(path))
    while True:
        try:
            info = current.lstat()
        except OSError as exc:
            raise ProductSourceProofError("source proof path component is missing") from exc
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0) &
            getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise ProductSourceProofError("source proof path contains reparse component")
        if current.parent == current:
            break
        current = current.parent


def _typed_signature(abi: str) -> tuple[str, ...]:
    if not isinstance(abi, str) or not abi.startswith("win64:bool(") or not abi.endswith(")"):
        raise ProductSourceProofError("exact bool-returning Win64 scalar ABI required")
    text = abi[len("win64:bool("):-1]
    args = tuple(text.split(","))
    if not 1 <= len(args) <= 8 or any(arg not in ("bool", "i64") for arg in args):
        raise ProductSourceProofError("only one to eight bool/i64 arguments are supported")
    return args


def _coff_defined_externals(raw: bytes) -> tuple[tuple[str, int, int], ...]:
    """Parse actual COFF symbol records, not dumpbin's annotated text rows."""
    if len(raw) < 20:
        raise ProductSourceProofError("COFF header truncated")
    machine, sections, _time, symbol_ptr, count, optional, _flags = struct.unpack_from(
        "<HHIIIHH", raw
    )
    if machine != 0x8664 or not 1 <= sections <= 96 or optional:
        raise ProductSourceProofError("helper must be ordinary AMD64 COFF, not LTCG/bigobj")
    if symbol_ptr < 20 + 40 * sections or count > 100_000 or symbol_ptr + 18 * count + 4 > len(raw):
        raise ProductSourceProofError("COFF symbol table is unbounded or truncated")
    string_ptr = symbol_ptr + 18 * count
    string_length = struct.unpack_from("<I", raw, string_ptr)[0]
    if string_length < 4 or string_ptr + string_length > len(raw):
        raise ProductSourceProofError("COFF string table is malformed")
    strings = raw[string_ptr:string_ptr + string_length]

    def name(field: bytes) -> str:
        if field[:4] == b"\0" * 4:
            offset = struct.unpack_from("<I", field, 4)[0]
            if not 4 <= offset < len(strings):
                raise ProductSourceProofError("COFF long-symbol offset is invalid")
            end = strings.find(b"\0", offset)
            if end < 0:
                raise ProductSourceProofError("COFF long symbol is unterminated")
            data = strings[offset:end]
        else:
            data = field.split(b"\0", 1)[0]
        try:
            return data.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ProductSourceProofError("COFF symbol is not ASCII") from exc

    found = []
    index = 0
    while index < count:
        offset = symbol_ptr + 18 * index
        value, section, _type, storage, auxiliaries = struct.unpack_from(
            "<IhHBB", raw, offset + 8
        )
        if index + auxiliaries >= count:
            raise ProductSourceProofError("COFF auxiliary symbol range is invalid")
        if section > sections:
            raise ProductSourceProofError("COFF symbol section is invalid")
        if storage == 105:
            raise ProductSourceProofError("helper COFF weak external is unsupported")
        if storage == 2 and section > 0:
            found.append((name(raw[offset:offset + 8]), section, value))
        index += auxiliaries + 1
    if len(found) != 1:
        raise ProductSourceProofError("helper object must define exactly one external symbol")
    return tuple(found)


def _require_no_executable_relocations(raw: bytes) -> None:
    if len(raw) < 20:
        raise ProductSourceProofError("COFF header truncated")
    count = struct.unpack_from("<H", raw, 2)[0]
    if not 1 <= count <= 96 or 20 + 40 * count > len(raw):
        raise ProductSourceProofError("COFF section table is invalid")
    executable = 0
    for index in range(count):
        offset = 20 + 40 * index
        reloc_ptr = struct.unpack_from("<I", raw, offset + 24)[0]
        reloc_count = struct.unpack_from("<H", raw, offset + 32)[0]
        flags = struct.unpack_from("<I", raw, offset + 36)[0]
        if flags & 0x20000000:
            executable += 1
            if reloc_ptr or reloc_count or flags & 0x01000000:
                raise ProductSourceProofError("helper executable COFF section has relocations")
    if executable != 1:
        raise ProductSourceProofError("helper must have exactly one executable COFF section")


def _require_no_guard_target_in_span(target_rvas, rva: int, size: int) -> None:
    if any(rva <= target < rva + size for target in target_rvas):
        raise ProductSourceProofError("source helper span contains a Guard CF/XFG target")


def _bounded_branch_graph(body: bytes, rva: int) -> tuple[int, int, str]:
    if not isinstance(body, bytes) or not 1 <= len(body) <= 512 or not 0 < rva <= 0xFFFFFFFF:
        raise ProductSourceProofError("native helper body is not bounded")
    instructions = tuple(Decoder(64, body, ip=rva))
    if not instructions or sum(item.len for item in instructions) != len(body):
        raise ProductSourceProofError("helper body is not exactly decodable")
    by_ip = {item.ip: item for item in instructions}
    if len(by_ip) != len(instructions):
        raise ProductSourceProofError("helper instruction addresses overlap")
    successors: dict[int, tuple[int, ...]] = {}
    returns = 0
    for item in instructions:
        if item.is_invalid:
            raise ProductSourceProofError("invalid helper instruction")
        if item.flow_control == FlowControl.RETURN and item.mnemonic == Mnemonic.RET and item.op_count == 0:
            successors[item.ip] = ()
            returns += 1
        elif item.flow_control == FlowControl.NEXT:
            successors[item.ip] = (item.next_ip,)
        elif item.flow_control == FlowControl.CONDITIONAL_BRANCH:
            successors[item.ip] = (item.next_ip, item.near_branch_target)
        else:
            raise ProductSourceProofError("helper requires call-free direct conditional control flow")
        if any(target not in by_ip for target in successors[item.ip]):
            raise ProductSourceProofError("helper branch/fallthrough is not an instruction boundary")
        if item.mnemonic == Mnemonic.LEA:
            raise ProductSourceProofError("helper address formation is unsupported")
        for index in range(item.op_count):
            if item.op_kind(index) == OpKind.MEMORY and (
                item.memory_base != Register.RSP or item.memory_index != Register.NONE
            ):
                raise ProductSourceProofError("helper has non-RSP data memory")
    if not returns:
        raise ProductSourceProofError("helper has no terminal RET")
    active: set[int] = set()
    visited: set[int] = set()

    def visit(ip: int) -> None:
        if ip in active:
            raise ProductSourceProofError("helper has a cyclic branch graph")
        if ip in visited:
            return
        active.add(ip)
        for child in successors[ip]:
            visit(child)
        active.remove(ip)
        visited.add(ip)

    visit(rva)
    if len(visited) != len(instructions):
        raise ProductSourceProofError("helper contains unreachable encoded instructions")
    try:
        x64_lifter.validate_materialized_stack_window(
            body, base=rva, window_size=512
        )
        assembly = x64_lifter.lift_function(
            body, base=rva, selected_extents=((rva, len(body)),)
        )
        bytecode = daedalus_asm.assemble(assembly)
    except (x64_lifter.LiftUnsupported, ValueError, TypeError, KeyError, RuntimeError) as exc:
        raise ProductSourceProofError(f"helper stack/lifter contract failed: {exc}") from exc
    return len(instructions), returns, _sha(bytecode)


def _validate_typed_output(stdout: bytes, rva: int, size: int,
                           args: tuple[str, ...]) -> None:
    if len(stdout) > 512:
        raise ProductSourceProofError("typed DIA ABI output is unbounded")
    try:
        match = _TYPED_OUTPUT.fullmatch(stdout.decode("ascii"))
    except UnicodeDecodeError as exc:
        raise ProductSourceProofError("typed DIA ABI output is not ASCII") from exc
    if (match is None or int(match[1], 16) != rva or int(match[2]) != size
            or int(match[3]) != len(args) or tuple(match[4].split(",")) != args):
        raise ProductSourceProofError("PDB function ABI differs from declared bool/i64 signature")


def _prove_dia_abi(inputs: ProductSourceInputs, rva: int, size: int,
                   args: tuple[str, ...]) -> str:
    helper = Path(inputs.typed_abi_helper)
    pins = ((Path(inputs.pdb), _sha(_read(inputs.pdb, "PDB"))),
            (Path(inputs.msdia), _sha(_read(inputs.msdia, "DIA library"))),
            (helper, _sha(_read(helper, "typed ABI helper"))))
    try:
        proc = subprocess.run(
            (str(helper), str(inputs.msdia), str(inputs.pdb), f"{rva:08X}",
             str(size), inputs.symbol),
            capture_output=True, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProductSourceProofError("typed DIA ABI helper did not complete") from exc
    if proc.returncode in (29, 30) and not proc.stdout and not proc.stderr:
        raise ProductSourceProofError(
            "PDB decorated public identity differs from exact COFF/MAP symbol"
        )
    if proc.returncode or proc.stderr:
        raise ProductSourceProofError("typed DIA ABI helper failed or emitted diagnostics")
    _validate_typed_output(proc.stdout, rva, size, args)
    if any(_sha(_read(path, "typed ABI proof input")) != digest for path, digest in pins):
        raise ProductSourceProofError("typed DIA ABI proof input changed during query")
    return pins[2][1]


def inspect_source(inputs: ProductSourceInputs) -> dict[str, object]:
    """Prove only an immutable source-helper contract; never admit a final PE."""
    source_root = Path(__file__).resolve().parents[1]
    try:
        source_link_build._bind_loaded_project_modules(source_root)
    except source_link_build.SourceLinkError as exc:
        raise ProductSourceProofError(str(exc)) from exc
    code_pins = tuple((path, _sha(path.read_bytes())) for path in (
        Path(__file__), Path(x64_lifter.__file__), Path(daedalus_asm.__file__),
    ))
    if not isinstance(inputs.symbol, str) or not _DECORATED.fullmatch(inputs.symbol):
        raise ProductSourceProofError("exact decorated C++ helper symbol required")
    args = _typed_signature(inputs.abi)
    # These binaries are invoked downstream; reject observed child junctions
    # before either DIA inventory/helper process is launched.
    for tool in (inputs.dia_helper, inputs.msdia, inputs.typed_abi_helper):
        _reject_reparse_components(Path(tool))
    image = _read(inputs.image, "source PE")
    pdb = _read(inputs.pdb, "source PDB")
    link_map = _read(inputs.link_map, "source MAP")
    obj = _read(inputs.helper_object, "helper COFF")
    parsed = analyze_pe(str(inputs.image))
    if not (parsed.extended_dll_characteristics & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT):
        raise ProductSourceProofError("source PE lacks CETCOMPAT declaration")
    if (parsed.load_config is None or not parsed.load_config.has_guard_cf
            or parsed.load_config.unsupported_features):
        raise ProductSourceProofError("source PE lacks Guard CF or has unsupported load config")
    try:
        rows = source_link_build._map_rows(link_map)
    except source_link_build.SourceLinkError as exc:
        raise ProductSourceProofError(str(exc)) from exc
    owner = Path(inputs.helper_object).name.lower()
    try:
        va = source_link_build._unique_map_symbol(rows, inputs.symbol, owner)
    except source_link_build.SourceLinkError as exc:
        raise ProductSourceProofError(str(exc)) from exc
    rva = va - parsed.image_base
    if not 0 < rva < parsed.size_of_image:
        raise ProductSourceProofError("source MAP helper address is outside PE")
    if any(name != inputs.symbol and address == va for name, address, _ in rows):
        raise ProductSourceProofError("source MAP has an aliased helper entry")
    defined = _coff_defined_externals(obj)[0]
    if defined[0] != inputs.symbol or defined[2] != 0:
        raise ProductSourceProofError("source COFF external identity/offset differs from MAP")
    try:
        inventory = pdb_function_inventory.run_bound_inventory(
            parsed, Path(inputs.image), Path(inputs.pdb), Path(inputs.dia_helper),
            Path(inputs.msdia),
        )
    except pdb_function_inventory.PdbInventoryError as exc:
        raise ProductSourceProofError(f"PDB inventory failed: {exc}") from exc
    extents = [(end - begin, count) for begin, end, count
               in inventory.range_multiplicities if begin == rva]
    if len(extents) != 1 or extents[0][1] != 1 or not 1 <= extents[0][0] <= 512:
        raise ProductSourceProofError("PDB helper function extent is absent or ambiguous")
    size = extents[0][0]
    if any(item.begin_rva < rva + size and rva < item.end_rva
           for item in parsed.runtime_functions):
        raise ProductSourceProofError("helper intersects PDATA; only a leaf is supported")
    _require_no_guard_target_in_span(
        (item.rva for item in parsed.load_config.guard_cf_targets), rva, size
    )
    pe = pefile.PE(data=image, fast_load=False)
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and any(
        item.address >= rva and item.address < rva + size
        for item in pe.DIRECTORY_ENTRY_EXPORT.symbols
    ):
        raise ProductSourceProofError("internal helper has export or interior alias")
    body = pe.get_data(rva, size)
    if len(body) != size:
        raise ProductSourceProofError("helper body is not wholly file-backed")
    try:
        source_link_build._coff_exact_body(obj, defined[1], defined[2], body)
    except (source_link_build.SourceLinkError, struct.error) as exc:
        raise ProductSourceProofError(str(exc)) from exc
    _require_no_executable_relocations(obj)
    typed_helper_sha = _prove_dia_abi(inputs, rva, size, args)
    count, returns, bytecode_sha = _bounded_branch_graph(body, rva)
    selected = (direct_control_flow.SelectedFunctionRange(inputs.symbol, rva, size),)
    try:
        coverage = pdb_coverage.prove_pdb_executable_coverage(
            parsed, Path(inputs.image), Path(inputs.pdb),
            Path(inputs.dia_helper), Path(inputs.msdia), selected,
        )
        binding = pdb_coverage.bind_pdb_commit_proof(parsed, coverage, selected)
    except (pdb_coverage.PdbCoverageError,
            pdb_function_inventory.PdbInventoryError,
            direct_control_flow.DirectControlFlowError) as exc:
        raise ProductSourceProofError(f"source direct/coverage proof failed: {exc}") from exc
    if any(_sha(_read(path, "source input")) != expected for path, expected in (
        (Path(inputs.image), _sha(image)), (Path(inputs.pdb), _sha(pdb)),
        (Path(inputs.link_map), _sha(link_map)),
        (Path(inputs.helper_object), _sha(obj)),
    )):
        raise ProductSourceProofError("source PE/PDB/MAP/COFF changed during proof")
    if any(_sha(path.read_bytes()) != expected for path, expected in code_pins):
        raise ProductSourceProofError("source inspector/lifter/assembler changed during proof")
    return {
        "schema": 1,
        "symbol": inputs.symbol,
        "abi": inputs.abi,
        "rva": rva,
        "size": size,
        "instructions": count,
        "returns": returns,
        "source_body_sha256": _sha(body),
        "source_pe_sha256": _sha(image),
        "source_pdb_sha256": _sha(pdb),
        "source_map_sha256": _sha(link_map),
        "source_coff_sha256": _sha(obj),
        "lifted_bytecode_sha256": bytecode_sha,
        "typed_abi_helper_sha256": typed_helper_sha,
        "dia_inventory_helper_sha256": inventory.helper_sha256,
        "msdia_sha256": inventory.msdia_sha256,
        "inspector_source_sha256": code_pins[0][1],
        "lifter_source_sha256": code_pins[1][1],
        "assembler_source_sha256": code_pins[2][1],
        "pdb_binding_sha256": binding.binding_sha256,
        "source_body_and_abi_verified": True,
        "source_reference_closure_proven": False,
        "original_helper_object_omission_proven": False,
        "indirect_target_closure_proven": False,
        "xfg_enforcement_proven": False,
        "production_admitted": False,
    }
