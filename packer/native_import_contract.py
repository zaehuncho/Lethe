"""Exact-binary proof for a narrow class of imported Win64 leaf calls."""
from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile

import pefile
from iced_x86 import (
    Code, Decoder, FlowControl, InstructionInfoFactory, MemorySizeExt, Mnemonic,
    OpAccess, OpKind, Register, RegisterExt,
)

from lifter import native_tail_calls, virtualization_plan
from . import pe_analyze
from .strict_json import StrictJSONError, load_json_object_bytes


SCHEMA = "lethe.native-import-call-contract"
VERSION = 1
MAX_CONTRACT_BYTES = 1_048_576
MAX_DEPENDENCY_BYTES = 512 * 1024 * 1024
MAX_CALLS = 512
MAX_LEAF_BYTES = 256
_HEX = frozenset("0123456789abcdef")
_ROOT_KEYS = frozenset(("schema", "version", "source_sha256", "calls"))
_CALL_KEYS = frozenset((
    "function_rva", "call_rva", "iat_rva", "module", "symbol",
    "dependency_path", "dependency_sha256", "export_rva", "export_ordinal",
    "body_size", "body_sha256",
))
_NONVOLATILE = frozenset((
    Register.RBX, Register.RBP, Register.RDI, Register.RSI, Register.RSP,
    Register.R12, Register.R13, Register.R14, Register.R15,
    Register.XMM6, Register.XMM7, Register.XMM8, Register.XMM9,
    Register.ZMM6, Register.ZMM7, Register.ZMM8, Register.ZMM9,
    Register.ZMM10, Register.ZMM11, Register.ZMM12, Register.ZMM13,
    Register.ZMM14, Register.ZMM15,
))
_WRITE_ACCESS = frozenset((
    OpAccess.WRITE, OpAccess.COND_WRITE, OpAccess.READ_WRITE,
    OpAccess.READ_COND_WRITE,
))
# iced-x86's register effects do not model the Win64-preserved x87 control
# word or MXCSR control bits. Reject those instruction families rather than
# treating an incomplete register list as proof of ABI preservation. XSAVE
# restore operations can likewise mutate extended architectural state outside
# the ordinary register model.
_UNMODELED_ABI_STATE_MUTATORS = frozenset(
    getattr(Mnemonic, name)
    for name in dir(Mnemonic)
    if name.startswith("F") or name in {
        "LDMXCSR", "XRSTOR", "XRSTORS", "XRSTOR64", "XRSTORS64",
    }
)


class NativeImportContractError(ValueError):
    """A native-import contract is malformed, stale, or not a proven leaf."""


def _err(message: str) -> NativeImportContractError:
    return NativeImportContractError(message)


def _int(value, label: str, minimum: int = 0, maximum: int = 0xFFFFFFFF) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _err(f"contract {label} must be an integer in range")
    return value


def _text(value, label: str, maximum: int = 4096) -> str:
    if type(value) is not str or not value or len(value) > maximum or "\0" in value:
        raise _err(f"contract {label} must be a nonempty bounded string")
    return value


def _sha(value, label: str) -> str:
    if type(value) is not str or len(value) != 64 or any(c not in _HEX for c in value):
        raise _err(f"contract {label} must be lowercase SHA-256")
    return value


def _rva_bytes(parsed, rva: int, size: int, *, executable: bool) -> bytes:
    if rva <= 0 or size <= 0 or rva + size > parsed.size_of_image:
        raise _err("contract target range is outside the PE image")
    owners = [s for s in parsed.sections
              if s.rva <= rva and rva + size <= s.rva + len(s.raw)]
    if len(owners) != 1:
        raise _err("contract target bytes are not uniquely file-backed")
    section = owners[0]
    if bool(section.characteristics & 0x20000000) != executable:
        raise _err("contract target section has the wrong protection")
    if section.characteristics & 0x02000000:
        raise _err("contract target section is discardable")
    start = rva - section.rva
    return bytes(section.raw[start:start + size])


def _prove_leaf(code: bytes, base: int) -> None:
    """Accept only a forward-only, call-free, stack-neutral CFG ending in RET."""
    if not code or len(code) > MAX_LEAF_BYTES:
        raise _err("leaf body exceeds the byte limit")
    insns = list(Decoder(64, code, ip=base))
    starts, cursor = {}, base
    for index, insn in enumerate(insns):
        if insn.ip != cursor or insn.code == Code.INVALID or insn.len <= 0:
            raise _err(f"leaf decode failed at 0x{cursor:X}")
        starts[insn.ip] = index
        cursor += insn.len
    if not insns or cursor != base + len(code):
        raise _err("leaf body is not exactly decoded")

    factory, edges = InstructionInfoFactory(), []
    for index, insn in enumerate(insns):
        if insn.mnemonic in _UNMODELED_ABI_STATE_MUTATORS:
            raise _err(
                "leaf changes x87, MXCSR, or extended processor state "
                "outside the Win64 preservation proof"
            )
        flow = insn.flow_control
        if flow not in (FlowControl.NEXT, FlowControl.CONDITIONAL_BRANCH,
                        FlowControl.UNCONDITIONAL_BRANCH, FlowControl.RETURN):
            raise _err("leaf contains a call or nonlocal control flow")
        if flow == FlowControl.RETURN:
            if insn.mnemonic != Mnemonic.RET or insn.op_count != 0:
                raise _err("leaf must use plain near RET")
            edges.append(())
            continue
        successors = []
        nxt = index + 1
        if flow == FlowControl.NEXT:
            if nxt >= len(insns):
                raise _err("leaf can fall through past its body")
            successors.append(nxt)
        else:
            if insn.op_count != 1 or insn.op_kind(0) != OpKind.NEAR_BRANCH64:
                raise _err("leaf contains an indirect branch")
            target = int(insn.near_branch_target)
            target_index = starts.get(target)
            if target_index is None or target <= insn.ip:
                raise _err("leaf branch is not a forward internal edge")
            successors.append(target_index)
            if flow == FlowControl.CONDITIONAL_BRANCH:
                if nxt >= len(insns):
                    raise _err("leaf conditional branch can fall through")
                successors.append(nxt)
        info = factory.info(insn)
        for used in info.used_registers():
            reg = RegisterExt.full_register(used.register)
            if reg == Register.RSP:
                raise _err("leaf reads or writes RSP")
            if reg in _NONVOLATILE and used.access in _WRITE_ACCESS:
                raise _err("leaf clobbers a Win64 nonvolatile register")
        for memory in info.used_memory():
            if (RegisterExt.full_register(memory.base) == Register.RSP
                    or RegisterExt.full_register(memory.index) == Register.RSP):
                raise _err("leaf addresses memory through RSP")
        edges.append(tuple(successors))

    seen, pending = set(), [0]
    while pending:
        index = pending.pop()
        if index in seen:
            continue
        seen.add(index)
        pending.extend(edges[index])
    if len(seen) != len(insns) or not any(
        insns[i].flow_control == FlowControl.RETURN for i in seen
    ):
        raise _err("leaf has unreachable bytes or no terminating RET")


def _call_target(parsed, spec, call_rva: int) -> int:
    code = virtualization_plan.SectionImage.from_parsed_sections(
        parsed.sections
    ).read_file_backed_executable(spec.rva, spec.body_size)
    for insn in Decoder(64, code, ip=spec.rva):
        if insn.ip != call_rva:
            continue
        if (insn.mnemonic != Mnemonic.CALL or insn.op_count != 1
                or insn.op_kind(0) != OpKind.MEMORY
                or not insn.is_ip_rel_memory_operand
                or insn.memory_base != Register.RIP
                or insn.segment_prefix != Register.NONE
                or MemorySizeExt.size(insn.memory_size) != 8):
            raise _err("call site is not a canonical RIP-relative qword CALL")
        target = int(insn.ip_rel_memory_address)
        if not 0 < target < parsed.size_of_image:
            raise _err("CALL target is outside the source image")
        return target
    raise _err("CALL RVA is not an instruction boundary in the selected body")


def _import_identity(parsed, iat_rva: int) -> tuple[str, str]:
    found = [(dll, fn) for dll in parsed.imports for fn in dll.funcs
             if fn.iat_rva == iat_rva]
    if len(found) != 1:
        raise _err("IAT RVA is not a unique normal import")
    dll, fn = found[0]
    if fn.by_ordinal or not fn.name:
        raise _err("only exact named imports are supported")
    return str(dll.name), str(fn.name)


def _verify_dependency(
    dependency: Path, expected_sha: str, symbol: str, rva: int, ordinal: int,
    size: int, body_sha: str,
) -> None:
    try:
        if dependency.stat().st_size > MAX_DEPENDENCY_BYTES:
            raise _err("dependency exceeds the verification size limit")
        raw = dependency.read_bytes()
    except OSError as exc:
        raise _err(f"cannot read pinned dependency: {exc}") from exc
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise _err("dependency SHA-256 does not match the contract")
    try:
        # Parse the same hashed bytes, not a second mutable path image.
        with tempfile.TemporaryDirectory(prefix="lethe-native-leaf-") as td:
            snapshot = Path(td) / dependency.name
            snapshot.write_bytes(raw)
            parsed = pe_analyze.analyze_pe(str(snapshot))
            if not parsed.is_dll:
                raise _err("dependency is not an AMD64 DLL")
            pe = pefile.PE(data=raw, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
            )
            exports = getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", ())
            matches = [item for item in exports
                       if item.name == symbol.encode("ascii", errors="strict")]
            if len(matches) != 1:
                raise _err("dependency lacks one exact named export")
            item = matches[0]
            if item.forwarder is not None:
                raise _err("forwarded exports are not admissible")
            if int(item.address) != rva or int(item.ordinal) != ordinal:
                raise _err("dependency export identity is stale")
            if any(record.begin_rva < rva + size and rva < record.end_rva
                   for record in parsed.runtime_functions):
                raise _err("import leaf with runtime unwind metadata is not admissible")
            body = _rva_bytes(parsed, rva, size, executable=True)
            if hashlib.sha256(body).hexdigest() != body_sha:
                raise _err("dependency export body SHA-256 is stale")
            _prove_leaf(body, rva)
    except NativeImportContractError:
        raise
    except Exception as exc:
        raise _err(f"dependency export verification failed: {exc}") from exc


def load_and_verify(contract_path: str, *, parsed,
                    specs: tuple[virtualization_plan.FunctionSpec, ...]):
    """Return call proofs only after binding source sites and pinned exports."""
    if type(contract_path) is not str or not contract_path or "\0" in contract_path:
        raise _err("contract path must be a nonempty string")
    try:
        path = Path(contract_path).resolve(strict=True)
        if not path.is_file() or path.stat().st_size > MAX_CONTRACT_BYTES:
            raise _err("contract is missing, non-regular, or oversized")
        raw = path.read_bytes()
    except OSError as exc:
        raise _err(f"cannot read contract: {exc}") from exc
    try:
        doc = load_json_object_bytes(raw, what="native import contract",
                                     max_bytes=MAX_CONTRACT_BYTES)
    except StrictJSONError as exc:
        raise _err(str(exc)) from exc
    if frozenset(doc) != _ROOT_KEYS or doc.get("schema") != SCHEMA \
            or type(doc.get("version")) is not int or doc["version"] != VERSION:
        raise _err("unsupported contract schema, version, or fields")
    try:
        source_hash = hashlib.sha256(Path(parsed.path).read_bytes()).hexdigest()
    except OSError as exc:
        raise _err(f"cannot read source snapshot: {exc}") from exc
    if _sha(doc.get("source_sha256"), "source_sha256") != source_hash:
        raise _err("contract is not bound to this exact source image")
    calls = doc.get("calls")
    if type(calls) is not list or not calls or len(calls) > MAX_CALLS:
        raise _err("calls must be a nonempty bounded array")
    specs_by_rva = {spec.rva: spec for spec in specs}
    seen, proofs = set(), []
    for index, rec in enumerate(calls):
        if type(rec) is not dict or frozenset(rec) != _CALL_KEYS:
            raise _err(f"call[{index}] has missing or unknown fields")
        function_rva = _int(rec.get("function_rva"), "function_rva")
        call_rva = _int(rec.get("call_rva"), "call_rva")
        iat_rva = _int(rec.get("iat_rva"), "iat_rva", 1)
        module = _text(rec.get("module"), "module", 260)
        symbol = _text(rec.get("symbol"), "symbol")
        dependency_text = _text(rec.get("dependency_path"), "dependency_path")
        dep_sha = _sha(rec.get("dependency_sha256"), "dependency_sha256")
        export_rva = _int(rec.get("export_rva"), "export_rva", 1)
        ordinal = _int(rec.get("export_ordinal"), "export_ordinal", 1, 65535)
        body_size = _int(rec.get("body_size"), "body_size", 1, MAX_LEAF_BYTES)
        body_sha = _sha(rec.get("body_sha256"), "body_sha256")
        spec = specs_by_rva.get(function_rva)
        if spec is None or not spec.rva <= call_rva < spec.rva + spec.body_size:
            raise _err("call site is not inside a selected function body")
        if call_rva in seen:
            raise _err("duplicate call site")
        seen.add(call_rva)
        if _call_target(parsed, spec, call_rva) != iat_rva:
            raise _err("IAT RVA does not match the selected source CALL")
        actual_module, actual_symbol = _import_identity(parsed, iat_rva)
        if actual_module.casefold() != module.casefold() or actual_symbol != symbol:
            raise _err("import identity does not match the source IAT")
        dependency = Path(dependency_text)
        if not dependency.is_absolute():
            dependency = path.parent / dependency
        try:
            dependency = dependency.resolve(strict=True)
        except OSError as exc:
            raise _err(f"cannot resolve pinned dependency: {exc}") from exc
        if dependency.name.casefold() != actual_module.casefold():
            raise _err("dependency filename does not match the imported module")
        _verify_dependency(dependency, dep_sha, symbol, export_rva, ordinal,
                           body_size, body_sha)
        proofs.append(native_tail_calls.VerifiedNativeImportCallProof(
            function_rva, call_rva, iat_rva, actual_module, actual_symbol,
            dep_sha, export_rva, ordinal, body_size, body_sha,
        ))
    return tuple(proofs)


__all__ = ["MAX_CALLS", "MAX_CONTRACT_BYTES", "MAX_LEAF_BYTES",
           "NativeImportContractError", "SCHEMA", "VERSION", "load_and_verify"]
