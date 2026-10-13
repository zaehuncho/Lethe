"""Experimental source-link virtualization for one scalar helper.

The recipe requests original-object omission, but complete final-link input
closure is not proven. This is NOT a post-link virtualization waiver or
production key service. The only runnable key mode is
``synthetic_fixture`` and embeds its deterministic test key in generated C.
"""

from __future__ import annotations

from dataclasses import dataclass
import copy
from hashlib import sha256
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

from iced_x86 import (
    Decoder, FlowControl, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register, RegisterExt,
)
import pefile

from daedalus import daedalus_asm
from packer import bytecode_pages
from packer.pe_analyze import (
    IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT, analyze_pe,
)
from . import (
    direct_control_flow, pdb_coverage, pdb_function_inventory,
    source_references, win64_thunk, x64_lifter,
)


class SourceLinkError(ValueError):
    """An exact source-build or final-link proof failed."""


@dataclass(frozen=True)
class SourceLinkInputs:
    image: Path
    pdb: Path
    helper_object: Path
    link_map: Path
    symbol: str
    abi: str
    dia_helper: Path
    abi_helper: Path
    msdia: Path
    dumpbin: Path
    runtime_root: Path
    # Deliberately narrow source-build fixture: a compiler-typed public C
    # wrapper retains XFG's hash, while the VM thunk is an internal tail target.
    xfg_pointer_symbol: str | None = None
    xfg_caller_symbol: str | None = None


RUNTIME_SOURCES = (
    "stub/src/daedalus_vm.c", "stub/src/crypto.c",
    "stub/src/bytecode_pages.c", "stub/src/key_scatter.c",
    "stub/src/daedalus_x64_thunk.asm", "stub/src/daedalus_store128.asm",
    "stub/src/daedalus_call_frame.asm", "stub/src/daedalus_trampoline.asm",
    "stub/src/daedalus_vm.h", "stub/src/bytecode_pages.h",
    "stub/src/key_scatter.h",
)
COMPILER_SOURCES = (
    "lifter/x64_lifter.py", "lifter/win64_thunk.py",
    "lifter/pdb_function_inventory.py", "daedalus/daedalus_asm.py",
    "packer/bytecode_pages.py", "tools/source_link_abi_dump.cpp",
)


def _source_tree_hashes(root: Path, *, runtime: bool) -> dict[str, str]:
    """Bind the maintained transitive source trees, not a hand-picked include list."""
    root = Path(root)
    specs = (
        (("stub/src",), frozenset({".c", ".h", ".asm", ".inc"}))
        if runtime else
        (("lifter", "packer", "daedalus"), frozenset({".py"}))
    )
    directories, suffixes = specs
    paths: list[Path] = []
    for directory in directories:
        base = root / directory
        if not base.is_dir() or base.is_symlink():
            raise SourceLinkError(f"missing or redirected provenance tree {directory}")
        for path in base.rglob("*"):
            if path.suffix.lower() in suffixes:
                if not path.is_file() or path.is_symlink():
                    raise SourceLinkError("provenance source is missing or redirected")
                paths.append(path)
    if not runtime:
        paths.append(root / "tools" / "source_link_abi_dump.cpp")
        _bind_loaded_project_modules(root)
    if not 1 <= len(paths) <= 1000:
        raise SourceLinkError("source provenance tree has an unsupported file count")
    return {
        path.relative_to(root).as_posix(): _sha(_read(path, "provenance source"))
        for path in sorted(paths)
    }


def _bind_loaded_project_modules(root: Path) -> None:
    """Reject a manifest claiming a different tree from executing Python code."""
    root = Path(root).resolve(strict=True)
    prefixes = ("lifter", "packer", "daedalus")
    for name, module in tuple(sys.modules.items()):
        if not any(name == p or name.startswith(p + ".") for p in prefixes):
            continue
        module_file = getattr(module, "__file__", None)
        if module_file is None:
            locations = tuple(getattr(module, "__path__", ()))
            if not locations:
                raise SourceLinkError(f"unbound imported compiler module {name}")
            actual_paths = tuple(Path(p).resolve(strict=True) for p in locations)
        else:
            actual_paths = (Path(module_file).resolve(strict=True),)
        for actual in actual_paths:
            try:
                actual.relative_to(root)
            except ValueError as exc:
                raise SourceLinkError(
                    f"imported compiler module {name} differs from runtime root"
                ) from exc
_SYMBOL = re.compile(r"[A-Za-z_][A-Za-z_0-9]{0,127}\Z")
_MAP_LINE = re.compile(
    r"^\s*[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{8,16})"
    r"(?:\s+f)?\s+(\S+\.obj)\s*$"
)
_COFF_EXTERNAL = re.compile(
    r"^\s*[0-9A-Fa-f]+\s+([0-9A-Fa-f]+)\s+(SECT[0-9]+|UNDEF|ABS)"
    r"\s+.*?\bExternal\s+\|\s+(\S+)\s*$"
)
_ABI = re.compile(r"win64:u64\((?:u64(?:,u64){0,7})?\)\Z")
_ABI_OUTPUT = re.compile(r"ABI_U64 rva=([0-9A-F]{8}) size=([0-9]+) argc=([0-8]) callconv=0\r?\n?\Z")


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _fixture_envelope(
    source_pe_sha256: str, body: bytes, bytecode: bytes, abi: str,
    runtime_sha256: str, opcode_sha256: str, fixture_key: bytes,
) -> tuple[bytes, bytes]:
    if type(fixture_key) is not bytes or len(fixture_key) != 32:
        raise SourceLinkError("synthetic fixture key must be exactly 32 bytes")
    identity = sha256(
        b"LetheSourceLinkFixtureV1\0" + bytes.fromhex(source_pe_sha256)
        + body + bytecode + abi.encode("ascii")
        + bytes.fromhex(runtime_sha256) + bytes.fromhex(opcode_sha256)
    ).digest()[:16]
    salt = sha256(b"Lethe synthetic fixture salt\0" + identity + fixture_key).digest()[:16]
    envelope = bytecode_pages.seal_program(
        bytecode, fixture_key, program_id=identity, salt=salt
    )
    if bytecode_pages.open_program(envelope, fixture_key) != bytecode:
        raise SourceLinkError("authenticated envelope failed fixture round-trip")
    return identity, envelope


def _render_fixture_data(symbol: str, envelope: bytes, identity: bytes, key: bytes) -> bytes:
    def c_array(data: bytes) -> str:
        return ",".join(f"0x{value:02X}" for value in data)
    descriptor = symbol + "_descriptor"
    envelope_symbol = symbol + "_envelope"
    initializer = symbol + "_fixture_init"
    return f'''/* SYNTHETIC FIXTURE ONLY: embeds a deterministic test key. */
#include <stdint.h>
#include "daedalus_vm.h"
#include "key_scatter.h"
extern const char __ImageBase;
static const uint8_t {envelope_symbol}[] = {{{c_array(envelope)}}};
const DaedalusX64PagedDescriptor {descriptor} = {{
    DVM_X64_PAGED_DESCRIPTOR_VERSION, sizeof({envelope_symbol}), {envelope_symbol},
    {{{c_array(identity)}}}, (const uint8_t *)&__ImageBase
}};
int {initializer}(void) {{
    uint8_t key[32] = {{{c_array(key)}}};
    return key_scatter_init(key);
}}
'''.encode("ascii")


def _render_typed_xfg_wrapper(symbol: str, abi: str) -> bytes:
    if not _SYMBOL.fullmatch(symbol) or not _ABI.fullmatch(abi):
        raise SourceLinkError("typed-XFG wrapper has invalid ABI or symbol")
    argc = abi.count("u64") - 1
    params = ", ".join(f"uint64_t a{i}" for i in range(argc)) or "void"
    values = ", ".join(f"a{i}" for i in range(argc))
    return f'''/* SYNTHETIC FIXTURE ONLY: MSVC emits the public XFG signature. */
#include <stdint.h>
uint64_t __cdecl {symbol}_vm({params});
__declspec(dllexport) __declspec(noinline)
uint64_t __cdecl {symbol}({params}) {{
    return {symbol}_vm({values});
}}
'''.encode("ascii")


def _read(path: Path, label: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise SourceLinkError(f"missing {label}") from exc


def _require_supported_mitigations(parsed, label: str, *, typed_xfg: bool = False) -> None:
    if not (parsed.extended_dll_characteristics & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT):
        raise SourceLinkError(f"{label} PE lacks CETCOMPAT declaration")
    if parsed.load_config is None or not parsed.load_config.has_guard_cf:
        raise SourceLinkError(f"{label} PE lacks Guard CF declaration")
    if parsed.load_config.xfg_present and not typed_xfg:
        raise SourceLinkError(f"{label} XFG requires an exact VM thunk function-hash contract")
    if typed_xfg and not parsed.load_config.xfg_present:
        raise SourceLinkError(f"{label} typed-XFG mode requires XFG metadata")
    if parsed.load_config.unsupported_features:
        raise SourceLinkError(f"{label} load config has unsupported VM thunk features")


def _selected_target_xfg_status(*, typed_xfg: bool, linked_tag: bool,
                                gfid_metadata: str | None) -> tuple[bool, str | None]:
    """Report only the selected target's observed linked tag and Guard CF row.

    This is structural metadata, never proof that Windows enabled XFG policy.
    The admissible typed fixture has exactly one unsuppressed GFID row (00).
    """
    if not typed_xfg:
        return False, None
    if linked_tag and gfid_metadata == "00":
        return True, "linked_xfg_tag_and_gfid_verified_enforcement_unproven"
    if not linked_tag and gfid_metadata == "00":
        return False, "cfg_only_no_linked_xfg_hash"
    return False, "selected_target_xfg_metadata_unverified"


def _unique_export(pe: pefile.PE, name: str) -> int:
    matches = [entry for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols
               if entry.name == name.encode("ascii") and not entry.forwarder]
    if len(matches) != 1:
        raise SourceLinkError(f"XFG export {name} is not unique/direct")
    return matches[0].address


def _compiler_xfg_hash(object_path: Path, target_symbol: str) -> str:
    raw = _read(object_path, "XFG compiler object")
    if len(raw) < 20:
        raise SourceLinkError("truncated XFG compiler object")
    machine, count, _, symbol_table, symbol_count, _, _ = struct.unpack_from(
        "<HHIIIHH", raw
    )
    if machine != 0x8664 or not 1 <= count <= 96 or len(raw) < 20 + 40 * count:
        raise SourceLinkError("invalid AMD64 XFG compiler object")
    string_table = symbol_table + 18 * symbol_count
    if (not 0 < symbol_table < len(raw) or string_table + 4 > len(raw)
            or symbol_count > 1_000_000):
        raise SourceLinkError("XFG compiler object symbol table is invalid")
    string_size = struct.unpack_from("<I", raw, string_table)[0]
    if not 4 <= string_size <= len(raw) - string_table:
        raise SourceLinkError("XFG compiler object string table is invalid")
    records = []
    for index in range(count):
        name, _, _, size, offset, _, _, _, _, _ = struct.unpack_from(
            "<8sIIIIIIHHI", raw, 20 + 40 * index
        )
        if name.rstrip(b"\0") == b".gxfg$y":
            if offset + size > len(raw):
                raise SourceLinkError("XFG compiler record extends beyond object")
            records.append(raw[offset:offset + size])
    if (len(records) != 1 or len(records[0]) != 16
            or not 0 < struct.unpack_from("<Q", records[0])[0] < symbol_count
            or records[0][8:16] == bytes(8)):
        raise SourceLinkError("expected one nonzero compiler-produced XFG hash")
    symbol_index = struct.unpack_from("<Q", records[0])[0]
    symbol = raw[symbol_table + 18 * symbol_index:
                 symbol_table + 18 * (symbol_index + 1)]
    name_bytes = symbol[:8]
    if name_bytes[:4] == bytes(4):
        offset = int.from_bytes(name_bytes[4:8], "little")
        if not 4 <= offset < string_size:
            raise SourceLinkError("XFG target symbol name offset is invalid")
        start = string_table + offset
        stop = raw.find(b"\0", start, string_table + string_size)
        if stop < 0:
            raise SourceLinkError("XFG target symbol name is unterminated")
        name_bytes = raw[start:stop]
    else:
        name_bytes = name_bytes.rstrip(b"\0")
    section, symbol_type, storage_class, aux_count = struct.unpack_from(
        "<hHBB", symbol, 12
    )
    if (name_bytes != target_symbol.encode("ascii") or not 1 <= section <= count
            or symbol_type != 0x20 or storage_class != 2 or aux_count):
        raise SourceLinkError("XFG compiler record does not bind target function symbol")
    return records[0][8:16].hex()


def _validated_typed_xfg_callsite(encoded: bytes, *, caller_va: int,
                                  slot_va: int, dispatch_va: int) -> bytes:
    """Accept only the compiler-emitted straight-line five-argument call template.

    The surrounding caller may contain other control flow. The protected call
    itself must have one entry, exact RIP-relative pointer/dispatch loads, and
    no possible RAX/R10 clobber between their definitions and dispatch. This
    intentionally rejects compiler variants until their flow is proved.
    """
    instructions = list(Decoder(64, encoded, ip=caller_va))
    if not instructions or any(item.is_invalid for item in instructions):
        raise SourceLinkError("typed-XFG caller is not strictly decodable")
    if sum(item.len for item in instructions) != len(encoded):
        raise SourceLinkError("typed-XFG caller is not exactly decodable")
    raw = [encoded[item.ip - caller_va:item.next_ip - caller_va]
           for item in instructions]
    # Every accepted opcode has fixed register and addressing encodings. Only
    # the two RIP displacements, compiler hash, and scalar argument literals
    # vary. In particular, a syntactically plausible but clobbering XOR EAX or
    # R10D, an indirect branch, or a non-RIP MOV/CALL cannot match this lane.
    shapes = (
        (bytes.fromhex("488b05"), 7),          # mov rax,[rip+slot]
        (bytes.fromhex("48895c2430"), 5),      # mov [rsp+30h],rbx
        (bytes.fromhex("49ba"), 10),           # mov r10,compiler hash
        (bytes.fromhex("ba"), 5),             # mov edx,arg2
        (bytes.fromhex("48c7442420"), 9),    # mov qword [rsp+20h],arg5
        (bytes.fromhex("41b9"), 6),           # mov r9d,arg4
        (bytes.fromhex("41b8"), 6),           # mov r8d,arg3
        (bytes.fromhex("b9"), 5),             # mov ecx,arg1
        (bytes.fromhex("ff15"), 6),           # call qword [rip+dispatch]
    )
    sites = []
    for start in range(len(instructions) - len(shapes) + 1):
        sequence = raw[start:start + len(shapes)]
        if not all(len(data) == length and data.startswith(prefix)
                   for data, (prefix, length) in zip(sequence, shapes)):
            continue
        first = instructions[start]
        last = instructions[start + len(shapes) - 1]
        if (first.memory_base != Register.RIP or first.memory_index != Register.NONE
                or first.memory_displacement != slot_va
                or last.memory_base != Register.RIP or last.memory_index != Register.NONE
                or last.memory_displacement != dispatch_va):
            continue
        sites.append((start, sequence[2][2:10], first.ip, last.next_ip))
    if len(sites) != 1:
        raise SourceLinkError("typed-XFG caller has no unique live pointer/hash/dispatch template")
    start, compiler_hash, begin, end = sites[0]
    if raw[0] != bytes.fromhex("4883ec38"):
        raise SourceLinkError("typed-XFG caller lacks the exact Win64 stack prologue")
    by_ip = {item.ip: index for index, item in enumerate(instructions)}
    if len(by_ip) != len(instructions):
        raise SourceLinkError("typed-XFG caller has overlapping instructions")
    rsp_writes = (OpAccess.WRITE, OpAccess.COND_WRITE,
                  OpAccess.READ_WRITE, OpAccess.READ_COND_WRITE)
    info_factory = InstructionInfoFactory()
    # Validate all decoded instructions, not merely a matching byte substring.
    # The accepted caller begins with SUB RSP,38h, permitting a 16-byte aligned
    # outgoing CALL frame and the fifth qword argument at [RSP+20h]. Each
    # internal branch must land at an instruction boundary; direct CALLs into
    # this caller and all other stack writers are excluded.
    for index, item in enumerate(instructions):
        if item.flow_control not in (
            FlowControl.NEXT, FlowControl.RETURN,
            FlowControl.UNCONDITIONAL_BRANCH, FlowControl.CONDITIONAL_BRANCH,
            FlowControl.CALL, FlowControl.INDIRECT_CALL,
        ):
            raise SourceLinkError("typed-XFG caller has unsupported control flow")
        if item.flow_control == FlowControl.RETURN and raw[index] != b"\xC3":
            raise SourceLinkError("typed-XFG caller has an unsupported return form")
        if (item.flow_control == FlowControl.INDIRECT_CALL
            and not start <= index < start + len(shapes)
        ):
            raise SourceLinkError("typed-XFG caller has an unbounded indirect transfer")
        if item.flow_control == FlowControl.INDIRECT_CALL and item.ip != instructions[start + len(shapes) - 1].ip:
            raise SourceLinkError("typed-XFG caller has an unexpected indirect call")
        if item.flow_control in (FlowControl.UNCONDITIONAL_BRANCH,
                                 FlowControl.CONDITIONAL_BRANCH,
                                 FlowControl.CALL):
            target = item.near_branch_target
            if begin < target < end or (item.flow_control == FlowControl.CALL
                                        and begin <= target < end):
                raise SourceLinkError("typed-XFG caller branches into live call template")
            if item.flow_control == FlowControl.CALL:
                if caller_va <= target < caller_va + len(encoded):
                    raise SourceLinkError("typed-XFG caller calls into its own extent")
            elif (target not in by_ip or target <= item.ip):
                raise SourceLinkError("typed-XFG caller branch is out of extent or backward")
        writes_rsp = any(
            RegisterExt.full_register(used.register) == Register.RSP
            and used.access in rsp_writes
            for used in info_factory.info(item).used_registers()
        )
        if writes_rsp and item.flow_control not in (
            FlowControl.CALL, FlowControl.INDIRECT_CALL, FlowControl.RETURN,
        ) and not (index == 0 and raw[index] == bytes.fromhex("4883ec38")) \
                and raw[index] != bytes.fromhex("4883c438"):
            raise SourceLinkError("typed-XFG caller has unproved stack modification")
        if not start <= index < start + len(shapes):
            # A second load or dispatch could make the unique call ambiguous.
            if ((item.mnemonic == Mnemonic.MOV and item.op0_kind == OpKind.REGISTER
                 and item.op0_register == Register.RAX and item.op1_kind == OpKind.MEMORY
                 and item.memory_displacement == slot_va)
                    or (item.mnemonic == Mnemonic.CALL and item.op0_kind == OpKind.MEMORY
                        and item.memory_displacement == dispatch_va)):
                raise SourceLinkError("typed-XFG caller has ambiguous pointer or dispatch use")
    # Propagate the exact allocated-frame size over every locally reachable
    # path. A jump from a restored frame, or a path skipping the prologue,
    # cannot reach the protected call with the required Win64 argument layout.
    pending = [(caller_va, 0)]
    seen = set()
    live_call_depths = set()
    while pending:
        ip, depth = pending.pop()
        if (ip, depth) in seen:
            continue
        seen.add((ip, depth))
        if len(seen) > 2 * len(instructions):
            raise SourceLinkError("typed-XFG caller stack flow is unbounded")
        index = by_ip.get(ip)
        if index is None:
            raise SourceLinkError("typed-XFG caller flow leaves decoded extent")
        item = instructions[index]
        if raw[index] == bytes.fromhex("4883ec38"):
            if index != 0 or depth != 0:
                raise SourceLinkError("typed-XFG caller has repeated stack prologue")
            depth = 0x38
        elif raw[index] == bytes.fromhex("4883c438"):
            if depth != 0x38:
                raise SourceLinkError("typed-XFG caller restores an unallocated frame")
            depth = 0
        if item.ip == begin or item.ip == instructions[start + len(shapes) - 1].ip:
            live_call_depths.add(depth)
            if depth != 0x38:
                raise SourceLinkError("typed-XFG caller reaches dispatch without Win64 frame")
        if item.flow_control == FlowControl.RETURN:
            if depth != 0:
                raise SourceLinkError("typed-XFG caller returns with an active frame")
            continue
        if item.flow_control == FlowControl.UNCONDITIONAL_BRANCH:
            pending.append((item.near_branch_target, depth))
        else:
            if item.next_ip not in by_ip:
                raise SourceLinkError("typed-XFG caller falls through outside PDB extent")
            pending.append((item.next_ip, depth))
            if item.flow_control == FlowControl.CONDITIONAL_BRANCH:
                pending.append((item.near_branch_target, depth))
    if live_call_depths != {0x38}:
        raise SourceLinkError("typed-XFG dispatch is not reachable with a proven Win64 frame")
    return compiler_hash


def _typed_xfg_proof(parsed, pe: pefile.PE, inventory, *, target_rva: int,
                     target_symbol: str, pointer_symbol: str, caller_symbol: str,
                     compiler_object: Path) -> dict[str, object]:
    """Bind the source/final compiler hash to one actual XFG indirect caller."""
    if not all(_SYMBOL.fullmatch(name) for name in
               (target_symbol, pointer_symbol, caller_symbol)):
        raise SourceLinkError("invalid typed-XFG symbol")
    if _unique_export(pe, target_symbol) != target_rva:
        raise SourceLinkError("typed-XFG target export differs from proven entry")
    pointer_rva = _unique_export(pe, pointer_symbol)
    caller_rva = _unique_export(pe, caller_symbol)
    caller_extents = [(end - begin, count) for begin, end, count
                      in inventory.range_multiplicities if begin == caller_rva]
    if (len(caller_extents) != 1 or caller_extents[0][1] != 1
            or not 1 <= caller_extents[0][0] <= 512):
        raise SourceLinkError("typed-XFG caller PDB extent is not unique and bounded")
    try:
        # Validate the complete raw inventory before exempting the one exact
        # typed-wrapper pointer from source-body reference closure. Filtering
        # first would hide an overlapping relocation at slot+1 through +7.
        source_references.dir64_references(parsed)
    except source_references.SourceReferenceError as exc:
        raise SourceLinkError(f"typed-XFG DIR64 inventory is invalid: {exc}") from exc
    if pointer_rva not in {item.target_rva for item in parsed.dir64_relocations}:
        raise SourceLinkError("typed-XFG pointer slot lacks DIR64 relocation")
    if int.from_bytes(pe.get_data(pointer_rva, 8), "little") != parsed.image_base + target_rva:
        raise SourceLinkError("typed-XFG pointer slot does not target wrapper")
    gfids = [item.metadata.hex() for item in parsed.load_config.guard_cf_targets
             if item.rva == target_rva]
    if gfids != ["00"]:
        raise SourceLinkError("typed-XFG target lacks unique unsuppressed Guard CF metadata")
    dispatch_rva = parsed.load_config.guard_xfg_dispatch_function_pointer_rva
    if not dispatch_rva:
        raise SourceLinkError("typed-XFG dispatch pointer is absent")
    encoded = pe.get_data(caller_rva, caller_extents[0][0])
    if len(encoded) != caller_extents[0][0]:
        raise SourceLinkError("typed-XFG caller is truncated")
    callsite_hash = _validated_typed_xfg_callsite(
        encoded, caller_va=parsed.image_base + caller_rva,
        slot_va=parsed.image_base + pointer_rva,
        dispatch_va=parsed.image_base + dispatch_rva,
    )
    compiler_hash = _compiler_xfg_hash(compiler_object, target_symbol)
    if callsite_hash.hex() != compiler_hash:
        raise SourceLinkError("typed-XFG call-site hash differs from compiler target hash")
    return {
        "compiler_hash": compiler_hash, "callsite_hash": callsite_hash.hex(),
        "gfid_metadata": gfids[0], "pointer_rva": pointer_rva,
        "caller_rva": caller_rva,
        "compiler_object_sha256": _sha(_read(compiler_object, "XFG compiler object")),
    }


def _map_rows(raw: bytes) -> tuple[tuple[str, int, str], ...]:
    try:
        lines = raw.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError as exc:
        raise SourceLinkError("MAP is not UTF-8") from exc
    rows = []
    for line in lines:
        match = _MAP_LINE.fullmatch(line)
        if match:
            # MAP ownership may be an archive member (library:member.obj),
            # not just a plain object path. Compare the final member name.
            owner = match[3].split(":")[-1].replace("\\", "/").split("/")[-1]
            rows.append((match[1], int(match[2], 16), owner.lower()))
    if not rows:
        raise SourceLinkError("MAP has no object-bound symbols")
    return tuple(rows)


def _unique_map_symbol(rows, symbol: str, object_name: str) -> int:
    matches = [(value, obj) for name, value, obj in rows if name == symbol]
    if len(matches) != 1 or matches[0][1] != object_name.lower():
        raise SourceLinkError(f"MAP symbol {symbol} is absent, duplicated, or owned by another object")
    return matches[0][0]


def _coff_defined_externals(object_path: Path, dumpbin: Path) -> tuple[tuple[str, int, int], ...]:
    try:
        proc = subprocess.run(
            (str(dumpbin), "/symbols", str(object_path)),
            capture_output=True, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SourceLinkError("COFF symbol tool did not complete") from exc
    if proc.returncode or proc.stderr or len(proc.stdout) > 4_000_000:
        raise SourceLinkError("COFF symbol tool failed or emitted diagnostics")
    try:
        lines = proc.stdout.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError as exc:
        raise SourceLinkError("COFF symbol output is not UTF-8") from exc
    defined = []
    for line in lines:
        match = _COFF_EXTERNAL.fullmatch(line)
        if match and match[2].startswith("SECT"):
            defined.append((match[3], int(match[2][4:]), int(match[1], 16)))
    if not defined:
        raise SourceLinkError("COFF object has no defined external symbol")
    return tuple(defined)


def _coff_exact_body(raw: bytes, section_number: int, symbol_offset: int, body: bytes) -> None:
    if len(raw) < 20:
        raise SourceLinkError("truncated COFF helper object")
    machine, count, _time, _symbols, _symbol_count, optional, _flags = struct.unpack_from(
        "<HHIIIHH", raw
    )
    if machine != 0x8664 or not 1 <= count <= 96 or optional != 0:
        raise SourceLinkError("helper object is not bounded AMD64 COFF")
    if section_number < 1 or section_number > count or 20 + 40 * count > len(raw):
        raise SourceLinkError("helper COFF symbol has invalid section")
    executable = []
    for index in range(count):
        offset = 20 + index * 40
        name, _vsize, _vrva, size, raw_offset, _reloc, _line, _nr, _nl, flags = struct.unpack_from(
            "<8sIIIIIIHHI", raw, offset
        )
        if flags & 0x20000000:
            if not (flags & 0x20) or not size or raw_offset + size > len(raw):
                raise SourceLinkError("helper COFF has invalid executable section")
            executable.append((index + 1, name.rstrip(b"\0"), raw[raw_offset:raw_offset + size]))
    if len(executable) != 1 or executable[0][0] != section_number or symbol_offset != 0:
        raise SourceLinkError("helper COFF must contain only one function at executable section start")
    if executable[0][2] != body:
        raise SourceLinkError("source PE body differs from linked helper COFF text")


def _prove_typed_wrapper_object(object_path: Path, dumpbin: Path,
                                symbol: str, thunk_symbol: str) -> None:
    """Require one compiler branch relocation, not arbitrary wrapper bytes."""
    raw = _read(object_path, "typed-XFG wrapper object")
    if len(raw) < 20:
        raise SourceLinkError("typed-XFG wrapper COFF is truncated")
    machine, count, _, symbols, symbol_count, optional, _ = struct.unpack_from(
        "<HHIIIHH", raw
    )
    if (machine != 0x8664 or not 1 <= count <= 96 or optional
            or symbols + 18 * symbol_count + 4 > len(raw)):
        raise SourceLinkError("typed-XFG wrapper COFF header is invalid")
    defined = _coff_defined_externals(object_path, dumpbin)
    if len(defined) != 1 or defined[0][0] != symbol or defined[0][2] != 0:
        raise SourceLinkError("typed-XFG wrapper defines extra public code")
    executable = []
    for index in range(count):
        off = 20 + 40 * index
        name, _, _, size, file_offset, reloc_offset, _, reloc_count, _, flags = (
            struct.unpack_from("<8sIIIIIIHHI", raw, off)
        )
        if flags & 0x20000000:
            executable.append((index + 1, name.rstrip(b"\0"), size, file_offset,
                               reloc_offset, reloc_count))
    if len(executable) != 1 or executable[0][0] != defined[0][1]:
        raise SourceLinkError("typed-XFG wrapper has extra executable COFF sections")
    _, _, size, file_offset, reloc_offset, reloc_count = executable[0]
    if (size != 5 or file_offset + size > len(raw) or reloc_count != 1
            or reloc_offset + 10 > len(raw) or raw[file_offset:file_offset+5] != b"\xE9\0\0\0\0"):
        raise SourceLinkError("typed-XFG wrapper COFF is not one direct tail jump")
    branch_offset, target_index, relocation_type = struct.unpack_from(
        "<IIH", raw, reloc_offset
    )
    if branch_offset != 1 or relocation_type != 4 or target_index >= symbol_count:
        raise SourceLinkError("typed-XFG wrapper branch relocation is not exact REL32")
    record = raw[symbols + 18 * target_index:symbols + 18 * (target_index + 1)]
    name_bytes = record[:8]
    if name_bytes[:4] == bytes(4):
        string_base = symbols + 18 * symbol_count
        string_size = struct.unpack_from("<I", raw, string_base)[0]
        offset = int.from_bytes(name_bytes[4:8], "little")
        if not 4 <= offset < string_size <= len(raw) - string_base:
            raise SourceLinkError("typed-XFG wrapper branch symbol offset is invalid")
        begin = string_base + offset
        end = raw.find(b"\0", begin, string_base + string_size)
        if end < 0:
            raise SourceLinkError("typed-XFG wrapper branch symbol is unterminated")
        name_bytes = raw[begin:end]
    else:
        name_bytes = name_bytes.rstrip(b"\0")
    section, _, storage, aux = struct.unpack_from("<hHBB", record, 12)
    if name_bytes != thunk_symbol.encode("ascii") or section != 0 or storage != 2 or aux:
        raise SourceLinkError("typed-XFG wrapper branch does not relocate to VM thunk")


def _reject_encoded_interior_aliases(parsed, rva: int, size: int) -> None:
    """Conservatively reject literal RVA, section-relative and VA aliases.

    The scan includes unaligned windows in *all* file-backed source sections,
    except bytes of the dedicated object that will be omitted. A coincidental
    integer match is a rejection, not an exception. This is only a negative
    proof for literal encodings; it does not prove arbitrary computed targets.
    """
    owners = [section for section in parsed.sections
              if section.rva <= rva and rva + size <= section.rva + len(section.raw)]
    if len(owners) != 1:
        raise SourceLinkError("helper must have one file-backed source section")
    owner = owners[0]
    for section in parsed.sections:
        raw = bytes(section.raw)
        for width in (4, 8):
            for offset in range(len(raw) - width + 1):
                site = section.rva + offset
                if site < rva + size and rva < site + width:
                    continue
                value = int.from_bytes(raw[offset:offset + width], "little")
                targets = (
                    (value, value + owner.rva) if width == 4
                    else (value - parsed.image_base,)
                )
                if any(rva < target < rva + size for target in targets):
                    raise SourceLinkError(
                        f"literal source helper interior alias at RVA 0x{site:X}"
                    )


def _prove_abi(inputs: SourceLinkInputs, rva: int, size: int) -> str:
    """Require DIA type metadata, not just a caller-written ABI string."""
    originals = (inputs.pdb, inputs.abi_helper, inputs.msdia)
    contents = tuple(_read(path, label) for path, label in zip(
        originals, ("source PDB", "ABI DIA helper", "DIA runtime")
    ))
    digests = tuple(_sha(data) for data in contents)
    with tempfile.TemporaryDirectory(prefix="lethe-source-link-abi-") as directory:
        root = Path(directory)
        snapshots = (root / "input.pdb", root / "source_link_abi_dump.exe",
                     root / "msdia140.dll")
        for path, data in zip(snapshots, contents):
            path.write_bytes(data)
        with pdb_function_inventory._seal_snapshot_paths(snapshots):
            try:
                proc = subprocess.run(
                    (str(snapshots[1]), str(snapshots[2]), str(snapshots[0]),
                     inputs.symbol), capture_output=True, timeout=30, check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise SourceLinkError("ABI DIA helper did not complete") from exc
            if proc.returncode or proc.stderr or len(proc.stdout) > 256:
                raise SourceLinkError("ABI DIA helper failed or emitted diagnostics")
            try:
                match = _ABI_OUTPUT.fullmatch(proc.stdout.decode("ascii"))
            except UnicodeDecodeError as exc:
                raise SourceLinkError("ABI DIA helper output is not ASCII") from exc
            argc_expected = inputs.abi.count("u64") - 1
            if (match is None or int(match[1], 16) != rva
                    or int(match[2]) != size or int(match[3]) != argc_expected):
                raise SourceLinkError("PDB function ABI does not match declared u64 signature")
            if any(_sha(_read(path, "ABI input")) != expected
                   for path, expected in zip(originals, digests)):
                raise SourceLinkError("ABI proof input changed during DIA query")
    return digests[1]


def _source_body(inputs: SourceLinkInputs):
    if not _SYMBOL.fullmatch(inputs.symbol):
        raise SourceLinkError("invalid helper symbol")
    if not _ABI.fullmatch(inputs.abi):
        raise SourceLinkError("explicit Win64 scalar u64 ABI required (at most eight arguments)")
    raw = _read(inputs.image, "source PE")
    pdb_raw = _read(inputs.pdb, "source PDB")
    obj_raw = _read(inputs.helper_object, "helper object")
    map_raw = _read(inputs.link_map, "source MAP")
    dumpbin_raw = _read(inputs.dumpbin, "COFF symbol tool")
    parsed = analyze_pe(str(inputs.image))
    typed_xfg = bool(inputs.xfg_pointer_symbol and inputs.xfg_caller_symbol)
    if bool(inputs.xfg_pointer_symbol) != bool(inputs.xfg_caller_symbol):
        raise SourceLinkError("typed-XFG pointer and caller symbols must both be set")
    _require_supported_mitigations(parsed, "source", typed_xfg=typed_xfg)
    inventory = pdb_function_inventory.run_bound_inventory(
        parsed, inputs.image, inputs.pdb, inputs.dia_helper, inputs.msdia
    )
    pe = pefile.PE(data=raw, fast_load=False)
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        raise SourceLinkError("initial lane requires an exported test helper")
    matches = [entry for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols
               if entry.name == inputs.symbol.encode("ascii") and not entry.forwarder]
    if len(matches) != 1:
        raise SourceLinkError("source export identity is not unique/direct")
    rva = matches[0].address
    records = [item for item in parsed.runtime_functions if item.begin_rva == rva]
    if len(records) > 1 or (records and records[0].unwind_flags):
        raise SourceLinkError("source helper has ambiguous/chained PDATA")
    extents = [(end - begin, count) for begin, end, count
               in inventory.range_multiplicities if begin == rva]
    if len(extents) != 1 or extents[0][1] != 1:
        raise SourceLinkError("PDB does not contain one unique helper extent")
    size = records[0].end_rva - rva if records else extents[0][0]
    if not 1 <= size <= 512:
        raise SourceLinkError("source helper extent is unbounded")
    if not records and any(
        item.begin_rva < rva + size and rva < item.end_rva
        for item in parsed.runtime_functions
    ):
        raise SourceLinkError("PDB-only helper overlaps a source PDATA extent")
    if [(a, b, count) for a, b, count in inventory.range_multiplicities
        if a == rva and b == rva + size] != [(rva, rva + size, 1)]:
        raise SourceLinkError("PDB does not contain exactly one matching helper function extent")
    source_xfg = _typed_xfg_proof(
        parsed, pe, inventory, target_rva=rva, target_symbol=inputs.symbol,
        pointer_symbol=inputs.xfg_pointer_symbol,
        caller_symbol=inputs.xfg_caller_symbol,
        compiler_object=inputs.helper_object,
    ) if typed_xfg else None
    closure_parsed = parsed
    if source_xfg is not None:
        # This is a SOURCE-LINK replacement, not a post-link patch. The one
        # validated pointer slot is re-emitted to the typed wrapper in final
        # PE. Keep every other relocation in the strict reference analysis.
        closure_parsed = copy.copy(parsed)
        closure_parsed.dir64_relocations = tuple(
            item for item in parsed.dir64_relocations
            if item.target_rva != source_xfg["pointer_rva"]
        )
    selected = (direct_control_flow.SelectedFunctionRange(inputs.symbol, rva, size),)
    try:
        coverage = pdb_coverage.prove_pdb_executable_coverage(
            closure_parsed, inputs.image, inputs.pdb, inputs.dia_helper, inputs.msdia,
            selected,
        )
        pdb_binding = pdb_coverage.bind_pdb_commit_proof(closure_parsed, coverage, selected)
    except (pdb_coverage.PdbCoverageError, direct_control_flow.DirectControlFlowError) as exc:
        raise SourceLinkError(f"source executable/reference closure failed: {exc}") from exc
    abi_helper_sha = _prove_abi(inputs, rva, size)
    if any(entry.address >= rva and entry.address < rva + size
           and entry is not matches[0] for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols):
        raise SourceLinkError("export aliases or interior exports target source helper")
    rows = _map_rows(map_raw)
    object_name = inputs.helper_object.name.lower()
    mapped_va = _unique_map_symbol(rows, inputs.symbol, object_name)
    if mapped_va != parsed.image_base + rva:
        raise SourceLinkError("source MAP disagrees with export/PDB/PDATA")
    other_retained = [(name, va) for name, va, obj in rows
                      if obj == object_name and va > parsed.image_base and name != inputs.symbol
                      and not name.startswith(("$unwind$", "$xdatasym"))]
    if other_retained:
        raise SourceLinkError("helper object retains other symbols; extract a dedicated translation unit")
    defined = _coff_defined_externals(inputs.helper_object, inputs.dumpbin)
    if len(defined) != 1 or defined[0][0] != inputs.symbol:
        raise SourceLinkError("helper object defines additional public symbols")
    body = pe.get_data(rva, size)
    if len(body) != size:
        raise SourceLinkError("source body not wholly file-backed")
    _coff_exact_body(obj_raw, defined[0][1], defined[0][2], body)
    _reject_encoded_interior_aliases(parsed, rva, size)
    for reloc in parsed.dir64_relocations:
        site = reloc.target_rva
        if rva <= site < rva + size:
            raise SourceLinkError("source helper contains a DIR64 relocation")
        target = int.from_bytes(pe.get_data(site, 8), "little") - parsed.image_base
        if rva <= target < rva + size and not (
            source_xfg is not None and site == source_xfg["pointer_rva"]
            and target == rva
        ):
            raise SourceLinkError("source helper address escapes through a DIR64 pointer")
    instructions = list(Decoder(64, body, ip=rva))
    if not instructions or sum(item.len for item in instructions) != len(body):
        raise SourceLinkError("source helper is not exactly decodable")
    if instructions[-1].flow_control != FlowControl.RETURN:
        raise SourceLinkError("source helper does not terminate in RET")
    for item in instructions:
        if item.is_invalid or item.flow_control not in (FlowControl.NEXT, FlowControl.RETURN):
            raise SourceLinkError("initial source-link lane requires call-free, branch-free scalar code")
        for index in range(item.op_count):
            if item.op_kind(index) == OpKind.MEMORY and item.mnemonic != Mnemonic.LEA and (
                item.memory_base != Register.RSP or item.memory_index != Register.NONE
            ):
                raise SourceLinkError("initial source-link lane requires direct RSP-relative scalar memory")
    depth = x64_lifter.validate_materialized_stack_window(
        body, base=rva, window_size=win64_thunk.STACK_WINDOW_SIZE
    )
    assembly = x64_lifter.lift_function(
        body, base=rva, selected_extents=((rva, size),)
    )
    bytecode = daedalus_asm.assemble(assembly)
    if any(_sha(_read(path, label)) != expected for path, label, expected in (
        (inputs.image, "source PE", _sha(raw)),
        (inputs.pdb, "source PDB", _sha(pdb_raw)),
        (inputs.helper_object, "helper object", _sha(obj_raw)),
        (inputs.link_map, "source MAP", _sha(map_raw)),
        (inputs.dumpbin, "COFF symbol tool", _sha(dumpbin_raw)),
    )):
        raise SourceLinkError("source input changed during proof")
    return body, bytecode, rva, depth, inventory, parsed, {
        "pe": _sha(raw), "pdb": _sha(pdb_raw), "object": _sha(obj_raw),
        "map": _sha(map_raw), "dia_helper": inventory.helper_sha256,
        "msdia": inventory.msdia_sha256, "abi_helper": abi_helper_sha,
        "dumpbin": _sha(dumpbin_raw),
        "source_direct_binding": pdb_binding.binding_sha256,
        "typed_xfg": source_xfg,
    }


def emit_fixture(
    inputs: SourceLinkInputs, output_dir: Path, *,
    key_mode: str = "production", synthetic_fixture_key: bytes | None = None,
) -> dict:
    """Emit thunk, v4 authenticated data and manifest for an explicit test key.

Production is deliberately unavailable: callers must not silently fall back
to an embedded key or reinterpret a fixture manifest as a release manifest.
"""
    if key_mode != "synthetic_fixture":
        raise SourceLinkError("authenticated per-build production key provisioning is not configured")
    if type(synthetic_fixture_key) is not bytes or len(synthetic_fixture_key) != 32:
        raise SourceLinkError("synthetic fixture key must be exactly 32 bytes")
    output_dir = Path(output_dir)
    if output_dir.exists() and any(output_dir.iterdir()):
        raise SourceLinkError("output directory must be empty")
    body, bytecode, rva, depth, inventory, _parsed, hashes = _source_body(inputs)
    runtime_hashes = _source_tree_hashes(inputs.runtime_root, runtime=True)
    compiler_hashes = _source_tree_hashes(inputs.runtime_root, runtime=False)
    opcode_map = json.dumps(daedalus_asm.OPCODES, sort_keys=True, separators=(",", ":")).encode()
    opcode_sha = _sha(opcode_map)
    identity, envelope = _fixture_envelope(
        hashes["pe"], body, bytecode, inputs.abi,
        runtime_hashes["stub/src/daedalus_vm.c"], opcode_sha,
        synthetic_fixture_key,
    )
    descriptor = inputs.symbol + "_descriptor"
    typed_xfg = hashes["typed_xfg"] is not None
    thunk_symbol = inputs.symbol + "_vm" if typed_xfg else inputs.symbol
    thunk = win64_thunk.render_entry_thunk(thunk_symbol, descriptor).encode("ascii")
    data_c = _render_fixture_data(inputs.symbol, envelope, identity, synthetic_fixture_key)
    generated = {
        inputs.symbol + ("_vm.asm" if typed_xfg else ".asm"): thunk,
        inputs.symbol + "_data.c": data_c,
    }
    if typed_xfg:
        generated[inputs.symbol + "_typed_wrapper.c"] = _render_typed_xfg_wrapper(
            inputs.symbol, inputs.abi
        )
    recipe = {
        "schema": 1,
        "omit_source_object": inputs.helper_object.name,
        "include_generated": sorted(generated),
        "include_runtime": list(RUNTIME_SOURCES[:8]),
        "required_flags": ["/DEBUG:FULL", "/MAP", "/CETCOMPAT", "/guard:cf", "/GUARD:CF"]
        + (["/guard:xfg", "/GUARD:XFG"] if typed_xfg else []),
        "link_rule": "Do not pass the original helper object to the final linker.",
    }
    manifest = {
        "schema": 1, "mode": "synthetic_fixture_only", "symbol": inputs.symbol,
        "typed_xfg_wrapper": typed_xfg,
        "xfg_pointer_symbol": inputs.xfg_pointer_symbol,
        "xfg_caller_symbol": inputs.xfg_caller_symbol,
        "abi_declaration": inputs.abi, "source_rva": rva,
        "source_size": len(body), "source_body_sha256": _sha(body),
        "source_stack_depth": depth, "source_object_name": inputs.helper_object.name,
        "source_hashes": hashes,
        "source_rsds_guid": str(inventory.identity.guid),
        "source_rsds_age": inventory.identity.age,
        "bytecode_sha256": _sha(bytecode), "bytecode_size": len(bytecode),
        "envelope_sha256": _sha(envelope), "envelope_size": len(envelope),
        "program_id": identity.hex(), "descriptor_version": 4,
        "thunk_template_sha256": _sha(win64_thunk.THUNK_TEMPLATE),
        "thunk_unwind_sha256": _sha(win64_thunk.THUNK_UNWIND_INFO),
        "runtime_source_sha256": runtime_hashes, "opcode_mapping_sha256": opcode_sha,
        "compiler_source_sha256": compiler_hashes,
        "generator_sha256": _sha(Path(__file__).read_bytes()),
        "output_sha256": {name: _sha(data) for name, data in generated.items()},
        "release_key_provisioned": False, "unverified_stub_override": False,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, data in generated.items():
        (output_dir / name).write_bytes(data)
    (output_dir / "link_recipe.json").write_text(
        json.dumps(recipe, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "source_link_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def verify_final(
    manifest_path: Path, source_image: Path, final_image: Path,
    final_pdb: Path, final_map: Path, dia_helper: Path, msdia: Path,
    *, typed_wrapper_object: Path | None = None,
) -> dict:
    """Verify original-object omission and exact thunk/envelope in final PE."""
    manifest = json.loads(_read(manifest_path, "source-link manifest"))
    if manifest.get("schema") != 1 or manifest.get("mode") != "synthetic_fixture_only":
        raise SourceLinkError("unsupported or non-fixture source-link manifest")
    typed_xfg = manifest.get("typed_xfg_wrapper") is True
    if typed_xfg and typed_wrapper_object is None:
        raise SourceLinkError("typed-XFG final compiler object is required")
    symbol = manifest["symbol"]
    source_raw = _read(source_image, "source PE")
    if _sha(source_raw) != manifest["source_hashes"]["pe"]:
        raise SourceLinkError("stale source PE")
    source_pe = pefile.PE(data=source_raw)
    body = source_pe.get_data(manifest["source_rva"], manifest["source_size"])
    if _sha(body) != manifest["source_body_sha256"]:
        raise SourceLinkError("stale source helper body")
    final_raw = _read(final_image, "final PE")
    final_pdb_raw = _read(final_pdb, "final PDB")
    map_raw = _read(final_map, "final MAP")
    if body in final_raw or body in final_pdb_raw:
        raise SourceLinkError("original native helper body remains in final PE/PDB")
    final = analyze_pe(str(final_image))
    _require_supported_mitigations(final, "final", typed_xfg=typed_xfg)
    inventory = pdb_function_inventory.run_bound_inventory(
        final, final_image, final_pdb, dia_helper, msdia
    )
    rows = _map_rows(map_raw)
    old = manifest["source_object_name"].lower()
    if any(obj == old for _, _, obj in rows):
        raise SourceLinkError("original helper object remains in final MAP")
    thunk_symbol = symbol + "_vm" if typed_xfg else symbol
    thunk_obj = thunk_symbol.lower() + ".obj"
    thunk_va = _unique_map_symbol(rows, thunk_symbol, thunk_obj)
    entry_rva = thunk_va - final.image_base
    pe = pefile.PE(data=final_raw)
    exports = [item for item in pe.DIRECTORY_ENTRY_EXPORT.symbols
               if item.name == symbol.encode("ascii") and not item.forwarder]
    if len(exports) != 1:
        raise SourceLinkError("final public target export is absent or ambiguous")
    linked_xfg_target_tag_matches_compiler = False
    selected_target_gfid_metadata = None
    if typed_xfg:
        wrapper_rva = exports[0].address
        if any(item.name == thunk_symbol.encode("ascii")
               for item in pe.DIRECTORY_ENTRY_EXPORT.symbols):
            raise SourceLinkError("internal VM thunk must not be exported")
        wrapper_obj = Path(typed_wrapper_object).name.lower()
        if _unique_map_symbol(rows, symbol, wrapper_obj) != final.image_base + wrapper_rva:
            raise SourceLinkError("typed-XFG wrapper MAP ownership is not exact")
        wrapper = pe.get_data(wrapper_rva, 5)
        if len(wrapper) != 5 or wrapper[0] != 0xE9 or (
            wrapper_rva + 5 + struct.unpack_from("<i", wrapper, 1)[0] != entry_rva
        ):
            raise SourceLinkError("typed-XFG wrapper is not a direct tail jump to VM thunk")
        if [(begin, end, count) for begin, end, count in inventory.range_multiplicities
            if begin == wrapper_rva] != [(wrapper_rva, wrapper_rva + 5, 1)]:
            raise SourceLinkError("typed-XFG wrapper PDB extent is not exact")
        compiler_hash = _compiler_xfg_hash(Path(typed_wrapper_object), symbol)
        if compiler_hash != manifest["source_hashes"]["typed_xfg"]["compiler_hash"]:
            raise SourceLinkError("typed-XFG final compiler hash differs from native source")
        final_xfg = _typed_xfg_proof(
            final, pe, inventory, target_rva=wrapper_rva, target_symbol=symbol,
            pointer_symbol=manifest["xfg_pointer_symbol"],
            caller_symbol=manifest["xfg_caller_symbol"],
            compiler_object=Path(typed_wrapper_object),
        )
        source_xfg = manifest["source_hashes"]["typed_xfg"]
        if (final_xfg["compiler_hash"] != source_xfg["compiler_hash"]
                or final_xfg["gfid_metadata"] != source_xfg["gfid_metadata"]):
            raise SourceLinkError("typed-XFG final metadata differs from source")
        selected_target_gfid_metadata = final_xfg["gfid_metadata"]
        # A compiler COFF record and a call-site immediate alone do not prove
        # that the linker installed the target tag consumed by enforced XFG.
        # This fixture currently has padding at wrapper_rva-8; report that
        # absence rather than conflating structural dispatch with OS policy.
        expected_tag = (int.from_bytes(
            bytes.fromhex(final_xfg["compiler_hash"]), "little"
        ) | 1).to_bytes(8, "little")
        tag_sections = [section for section in final.sections
                        if section.rva <= wrapper_rva - 8
                        and wrapper_rva <= section.rva + len(section.raw)]
        if wrapper_rva >= 8 and len(tag_sections) == 1:
            section = tag_sections[0]
            offset = wrapper_rva - 8 - section.rva
            linked_xfg_target_tag_matches_compiler = (
                section.raw[offset:offset + 8] == expected_tag
            )
        if entry_rva in {item.rva for item in final.load_config.guard_cf_targets}:
            raise SourceLinkError("internal VM thunk was made a Guard CF/XFG target")
    elif exports[0].address != entry_rva:
        raise SourceLinkError("final export does not resolve to VM thunk")
    if any(
        entry_rva < item.address < entry_rva + win64_thunk.THUNK_CODE_SIZE
        for item in pe.DIRECTORY_ENTRY_EXPORT.symbols
    ):
        raise SourceLinkError("final export alias enters VM thunk interior")
    if [(begin, end, count) for begin, end, count in inventory.range_multiplicities
        if begin == entry_rva] != [(
            entry_rva, entry_rva + win64_thunk.THUNK_CODE_SIZE, 1
        )]:
        raise SourceLinkError("final PDB does not have one exact VM thunk extent")
    cf_targets = tuple(item.rva for item in final.load_config.guard_cf_targets)
    if not typed_xfg and entry_rva not in cf_targets:
        raise SourceLinkError("VM thunk entry is absent from Guard CF targets")
    if any(entry_rva < target < entry_rva + win64_thunk.THUNK_CODE_SIZE
           for target in cf_targets):
        raise SourceLinkError("Guard CF permits an interior VM thunk entry")
    desc_name = symbol + "_descriptor"
    env_name = symbol + "_envelope"
    data_obj = symbol.lower() + "_data.obj"
    desc_va = _unique_map_symbol(rows, desc_name, data_obj)
    env_va = _unique_map_symbol(rows, env_name, data_obj)
    desc_rva, env_rva = desc_va - final.image_base, env_va - final.image_base
    thunk = pe.get_data(entry_rva, win64_thunk.THUNK_CODE_SIZE)
    observed = bytearray(thunk)
    if len(observed) != win64_thunk.THUNK_CODE_SIZE:
        raise SourceLinkError("truncated final VM thunk")
    rel32 = struct.unpack_from("<i", observed, win64_thunk.THUNK_COMMON_REL32_OFFSET)[0]
    call_va = thunk_va + win64_thunk.THUNK_COMMON_REL32_OFFSET + 4 + rel32
    common_va = _unique_map_symbol(
        rows, "daedalus_x64_enter_common_stack512", "daedalus_x64_thunk.obj"
    )
    if call_va != common_va:
        raise SourceLinkError("VM thunk call target differs from runtime bridge")
    pointer = struct.unpack_from("<Q", observed, win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET)[0]
    if pointer != desc_va:
        raise SourceLinkError("VM thunk descriptor pointer differs from MAP")
    observed[win64_thunk.THUNK_COMMON_REL32_OFFSET:win64_thunk.THUNK_COMMON_REL32_OFFSET + 4] = b"\0" * 4
    observed[win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET:win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET + 8] = b"\0" * 8
    if bytes(observed) != win64_thunk.THUNK_TEMPLATE:
        raise SourceLinkError("final VM thunk differs from pinned template")
    pdata = [item for item in final.runtime_functions if item.begin_rva == entry_rva]
    if len(pdata) != 1 or pdata[0].end_rva != entry_rva + len(thunk):
        raise SourceLinkError("final VM thunk PDATA extent mismatch")
    unwind = pe.get_data(pdata[0].unwind_info_rva, len(win64_thunk.THUNK_UNWIND_INFO))
    if unwind != win64_thunk.THUNK_UNWIND_INFO:
        raise SourceLinkError("final VM thunk unwind metadata mismatch")
    reloc_sites = {item.target_rva for item in final.dir64_relocations}
    if not {entry_rva + win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET,
            desc_rva + 8, desc_rva + 32} <= reloc_sites:
        raise SourceLinkError("VM thunk/descriptor ASLR relocations are missing")
    descriptor = pe.get_data(desc_rva, 40)
    version, size, env_pointer = struct.unpack_from("<IIQ", descriptor)
    if (version != 4 or size != manifest["envelope_size"] or env_pointer != env_va
            or descriptor[16:32].hex() != manifest["program_id"]
            or struct.unpack_from("<Q", descriptor, 32)[0] != final.image_base):
        raise SourceLinkError("final v4 descriptor is not bound to envelope/program/image")
    envelope = pe.get_data(env_rva, size)
    if _sha(envelope) != manifest["envelope_sha256"]:
        raise SourceLinkError("final envelope differs from generated authenticated bytes")
    if bytecode_pages.parse_envelope(envelope).program_id.hex() != manifest["program_id"]:
        raise SourceLinkError("final envelope program identity mismatch")
    selected_target_xfg_metadata_verified, selected_target_status = (
        _selected_target_xfg_status(
            typed_xfg=typed_xfg,
            linked_tag=linked_xfg_target_tag_matches_compiler,
            gfid_metadata=selected_target_gfid_metadata,
        )
    )
    return {
        "source_pe_sha256": _sha(source_raw), "final_pe_sha256": _sha(final_raw),
        "final_pdb_sha256": _sha(final_pdb_raw), "final_map_sha256": _sha(map_raw),
        "final_rsds_guid": str(inventory.identity.guid), "final_rsds_age": inventory.identity.age,
        "symbol": symbol, "thunk_rva": entry_rva, "thunk_size": len(thunk),
        "envelope_rva": env_rva,
        "original_helper_body_absent": True,
        "original_helper_public_map_rows_absent": True,
        "original_helper_object_omission_proven": False,
        "envelope_sha256": _sha(envelope), "descriptor_version": version,
        "source_link_structural_verified": True,
        "source_link_fixture_verified": False,
        "typed_xfg_wrapper_verified": typed_xfg,
        "linked_xfg_target_tag_matches_compiler": linked_xfg_target_tag_matches_compiler,
        "selected_target_xfg_metadata_verified": selected_target_xfg_metadata_verified,
        "selected_target_status": selected_target_status,
        "xfg_enforcement_proven": False,
        "typed_xfg_wrapper_rva": wrapper_rva if typed_xfg else None,
        "typed_xfg_wrapper_size": 5 if typed_xfg else None,
        "source_reference_closure_proven": False,
        "production_admitted": False,
    }


def verify_final_bound(
    manifest_path: Path, inputs: SourceLinkInputs, final_image: Path,
    final_pdb: Path, final_map: Path, *, synthetic_fixture_key: bytes | None = None,
    typed_wrapper_object: Path | None = None,
) -> dict:
    """Re-prove all source/build inputs before validating the final image."""
    if type(synthetic_fixture_key) is not bytes or len(synthetic_fixture_key) != 32:
        raise SourceLinkError("synthetic fixture key must be exactly 32 bytes")
    manifest_path = Path(manifest_path)
    manifest = json.loads(_read(manifest_path, "source-link manifest"))
    body, bytecode, rva, depth, inventory, _parsed, hashes = _source_body(inputs)
    if (
        manifest.get("source_hashes") != hashes
        or manifest.get("symbol") != inputs.symbol
        or manifest.get("abi_declaration") != inputs.abi
        or manifest.get("source_rva") != rva
        or manifest.get("source_size") != len(body)
        or manifest.get("source_body_sha256") != _sha(body)
        or manifest.get("source_stack_depth") != depth
        or manifest.get("bytecode_sha256") != _sha(bytecode)
        or manifest.get("source_rsds_guid") != str(inventory.identity.guid)
        or manifest.get("source_rsds_age") != inventory.identity.age
        or manifest.get("source_object_name") != inputs.helper_object.name
    ):
        raise SourceLinkError("manifest differs from current source PE/PDB/COFF/MAP/ABI")
    runtime_hashes = _source_tree_hashes(inputs.runtime_root, runtime=True)
    compiler_hashes = _source_tree_hashes(inputs.runtime_root, runtime=False)
    opcode_sha = _sha(json.dumps(
        daedalus_asm.OPCODES, sort_keys=True, separators=(",", ":")
    ).encode())
    if (
        manifest.get("runtime_source_sha256") != runtime_hashes
        or manifest.get("compiler_source_sha256") != compiler_hashes
        or manifest.get("opcode_mapping_sha256") != opcode_sha
        or manifest.get("generator_sha256") != _sha(Path(__file__).read_bytes())
        or manifest.get("thunk_template_sha256") != _sha(win64_thunk.THUNK_TEMPLATE)
        or manifest.get("thunk_unwind_sha256") != _sha(win64_thunk.THUNK_UNWIND_INFO)
    ):
        raise SourceLinkError("manifest compiler/runtime provenance is stale")
    identity, expected_envelope = _fixture_envelope(
        hashes["pe"], body, bytecode, inputs.abi,
        runtime_hashes["stub/src/daedalus_vm.c"], opcode_sha,
        synthetic_fixture_key,
    )
    typed_xfg = hashes["typed_xfg"] is not None
    if manifest.get("typed_xfg_wrapper") is not typed_xfg:
        raise SourceLinkError("manifest typed-XFG mode differs from source")
    if manifest.get("xfg_pointer_symbol") != inputs.xfg_pointer_symbol or (
        manifest.get("xfg_caller_symbol") != inputs.xfg_caller_symbol
    ):
        raise SourceLinkError("manifest typed-XFG symbols differ from source")
    thunk_symbol = inputs.symbol + "_vm" if typed_xfg else inputs.symbol
    expected_sources = {
        inputs.symbol + ("_vm.asm" if typed_xfg else ".asm"):
            win64_thunk.render_entry_thunk(
                thunk_symbol, inputs.symbol + "_descriptor"
            ).encode("ascii"),
        inputs.symbol + "_data.c": _render_fixture_data(
            inputs.symbol, expected_envelope, identity, synthetic_fixture_key
        ),
    }
    if typed_xfg:
        expected_sources[inputs.symbol + "_typed_wrapper.c"] = (
            _render_typed_xfg_wrapper(inputs.symbol, inputs.abi)
        )
    for name, expected in expected_sources.items():
        if _read(manifest_path.parent / name, "generated source") != expected:
            raise SourceLinkError("generated source differs from freshly proven source/key")
    for name, digest in manifest.get("output_sha256", {}).items():
        if name not in expected_sources:
            raise SourceLinkError("manifest output name is not canonical")
        if _sha(_read(manifest_path.parent / name, "generated source")) != digest:
            raise SourceLinkError("generated source differs from manifest")
    if set(manifest.get("output_sha256", {})) != set(expected_sources):
        raise SourceLinkError("manifest generated source set is incomplete")
    if typed_xfg:
        if typed_wrapper_object is None:
            raise SourceLinkError("typed-XFG wrapper compiler object is required")
        _prove_typed_wrapper_object(
            Path(typed_wrapper_object), inputs.dumpbin,
            inputs.symbol, inputs.symbol + "_vm",
        )
    result = verify_final(
        manifest_path, inputs.image, final_image, final_pdb, final_map,
        inputs.dia_helper, inputs.msdia,
        typed_wrapper_object=typed_wrapper_object,
    )
    if typed_xfg:
        if typed_wrapper_object is None:
            raise SourceLinkError("typed-XFG wrapper compiler object is required")
        final_wrapper_rva = result["typed_xfg_wrapper_rva"]
        final_wrapper_size = result["typed_xfg_wrapper_size"]
        final_inputs = SourceLinkInputs(
            final_image, final_pdb, Path(typed_wrapper_object), final_map,
            inputs.symbol, inputs.abi, inputs.dia_helper, inputs.abi_helper,
            inputs.msdia, inputs.dumpbin, inputs.runtime_root,
            inputs.xfg_pointer_symbol, inputs.xfg_caller_symbol,
        )
        _prove_abi(final_inputs, final_wrapper_rva, final_wrapper_size)
    if (
        manifest.get("program_id") != identity.hex()
        or manifest.get("envelope_sha256") != _sha(expected_envelope)
        or manifest.get("envelope_size") != len(expected_envelope)
    ):
        raise SourceLinkError("fixture envelope differs from freshly lifted source bytecode")
    final_pe = pefile.PE(data=_read(final_image, "final PE"))
    final_envelope = final_pe.get_data(result["envelope_rva"], len(expected_envelope))
    if final_envelope != expected_envelope or bytecode_pages.open_program(
        final_envelope, synthetic_fixture_key
    ) != bytecode:
        raise SourceLinkError("final authenticated envelope is not the source VM bytecode")
    result["source_bytecode_bound_to_current_inputs"] = True
    result["source_reference_closure_proven"] = False
    result["production_admitted"] = False
    result["source_link_fixture_verified"] = True
    return result
