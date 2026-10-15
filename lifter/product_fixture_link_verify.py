"""Opt-in final-link byte binding for the two synthetic product-helper fixtures.

This module reruns an exact /LINKREPRO capture in a new directory and compares
the resulting PE *bytes* with the built fixture PE. It also re-emits the fixture
from current source and checks the linked VM structure. It is not a generic
product linker, archive-closure proof, XFG enforcement proof, or production
admission path.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import uuid

import pefile

from packer import bytecode_pages
from packer.pe_analyze import analyze_pe
from . import pdb_function_inventory, source_link_build, win64_thunk
from .source_link_product_admission import (
    ProductSourceInputs, ProductSourceProofError, _reject_reparse_components,
)
from .source_link_product_fixture import ProductFixtureError, emit_product_fixture
from .selected_wrapper_binding import (
    SelectedWrapperLinkInputs, SelectedWrapperProofError, _MaterializedWrapperEntry,
    validate_inputs as _validate_selected_wrapper_inputs, prove_selected_wrapper,
)
from .runtime_coff_compile import (
    RuntimeCompileError, require_runtime_compile_ready,
    prove_runtime_coff_compilation,
)


class ProductLinkProofError(ValueError):
    """An exact synthetic fixture replay or binding check failed."""


@dataclass(frozen=True)
class ReplayInputs:
    capture_dir: Path
    built_image: Path
    built_pdb: Path
    built_map: Path
    replay_dir: Path
    link_exe: Path
    vsdevcmd: Path


_NAME = re.compile(r"[A-Za-z0-9_.@+\-$]+\Z")
_REL_INPUT = re.compile(r"\.\\([A-Za-z0-9_.@+\-$]+\.(?:obj|lib))\Z", re.I)
_OUTPUT = re.compile(r"/out:\.\\([A-Za-z0-9_.@+\-$]+\.(?:exe|dll))\Z", re.I)
_PDB = re.compile(r"/pdb:\.\\([A-Za-z0-9_.@+\-$]+\.pdb)\Z", re.I)
_IMPLIB = re.compile(r"/implib:\.\\[A-Za-z0-9_.@+\-$]+\.lib\Z", re.I)
_PDBMAP = re.compile(r"/pdbmap:[^\"\r\n=]+?=\.\\vc143(?:\.[0-9]+)?\.pdb\Z", re.I)
_FLAGS = {
    "/incremental:no", "/nologo", "/manifest", "/manifest:embed",
    "/debug:full", "/map", "/subsystem:console", "/opt:noicf", "/opt:ref",
    "/tlbid:1", "/machine:x64", "/cetcompat", "/guard:cf",
    "/guard:xfg", "/brepro", "/verbose:lib", "/dll",
    "/manifestuac:level='asInvoker' uiAccess='false'".casefold(),
}
_REQUIRED = {
    "/incremental:no", "/debug:full", "/machine:x64", "/cetcompat",
    "/guard:cf", "/guard:xfg", "/brepro", "/opt:noicf",
}
_MAX_CAPTURE_FILES = 128
_MAX_CAPTURE_BYTES = 256 * 1024 * 1024
_MAX_REPLAY_AGE = 16
_CMD_PATH = re.compile(r"[A-Za-z]:\\(?:[A-Za-z0-9_. -]+\\)*[A-Za-z0-9_. -]+\Z")
_VS_EDITIONS = {"community", "professional", "enterprise", "buildtools"}


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _read(path: Path, label: str) -> bytes:
    try:
        _reject_reparse_components(path)
        if not path.is_file():
            raise ProductLinkProofError(f"{label} is not an ordinary file")
        before = path.stat()
        raw = path.read_bytes()
        after = path.stat()
    except (OSError, ProductSourceProofError) as exc:
        raise ProductLinkProofError(f"{label} is missing or redirected") from exc
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or len(raw) != before.st_size):
        raise ProductLinkProofError(f"{label} changed during read")
    return raw


def _validated_tool_paths(link_exe: Path, vsdevcmd: Path) -> None:
    """Permit only canonical VS linker/setup paths safe for CMD interpolation.

    Both paths are embedded in a generated .cmd script. Quoting alone does not
    prevent CMD's percent or delayed-exclamation expansion, so the lexical
    profile excludes every CMD metacharacter, relative component, alternate
    namespace and non-Visual-Studio tool location before either tool is read.
    """
    for path in (link_exe, vsdevcmd):
        if not isinstance(path, Path) or not path.is_absolute():
            raise ProductLinkProofError("canonical absolute Visual Studio tool path required")
        raw = str(path)
        if (_CMD_PATH.fullmatch(raw) is None or
                os.path.normcase(os.path.normpath(raw)) != os.path.normcase(raw) or
                any(part in (".", "..") or part.endswith((" ", "."))
                    for part in path.parts[1:])):
            raise ProductLinkProofError("unsafe or noncanonical Visual Studio tool path")
    root = vsdevcmd.parents[2]
    if (tuple(part.casefold() for part in vsdevcmd.relative_to(root).parts) !=
            ("common7", "tools", "vsdevcmd.bat") or
            root.name.casefold() not in _VS_EDITIONS or
            root.parent.name != "2022" or
            root.parent.parent.name.casefold() != "microsoft visual studio" or
            root.parent.parent.parent != Path(root.anchor) / "Program Files"):
        raise ProductLinkProofError("unrecognized Visual Studio developer setup path")
    try:
        suffix = link_exe.relative_to(root).parts
    except ValueError as exc:
        raise ProductLinkProofError("linker and developer setup have different roots") from exc
    if (len(suffix) != 8 or
            tuple(part.casefold() for part in suffix[:3]) != ("vc", "tools", "msvc") or
            re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", suffix[3]) is None or
            tuple(part.casefold() for part in suffix[4:]) !=
            ("bin", "hostx64", "x64", "link.exe")):
        raise ProductLinkProofError("unrecognized Visual Studio AMD64 linker path")


def _rsds(raw: bytes) -> tuple[str, int, str]:
    pe = pefile.PE(data=raw, fast_load=False)
    records = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_DEBUG", ()):
        if entry.struct.Type != 2:
            continue
        off, size = entry.struct.PointerToRawData, entry.struct.SizeOfData
        if off <= 0 or size < 25 or off + size > len(raw):
            raise ProductLinkProofError("CodeView record is out of bounds")
        record = raw[off:off + size]
        if not record.startswith(b"RSDS") or record.find(b"\0", 24) != len(record) - 1:
            raise ProductLinkProofError("CodeView record is not canonical RSDS")
        try:
            path = record[24:-1].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProductLinkProofError("RSDS path is not UTF-8") from exc
        if (not path or '"' in path or "\r" in path or "\n" in path
                or not re.fullmatch(r"[A-Za-z]:\\[^\x00-\x1f]+", path)):
            raise ProductLinkProofError("RSDS PDB path is not an absolute ordinary path")
        records.append((str(uuid.UUID(bytes_le=record[4:20])),
                        struct.unpack_from("<I", record, 20)[0], path))
    if len(records) != 1 or not 1 <= records[0][1] <= _MAX_REPLAY_AGE:
        raise ProductLinkProofError("unique bounded RSDS identity/age required")
    return records[0]


def _capture_files(root: Path) -> dict[str, bytes]:
    try:
        _reject_reparse_components(root)
    except ProductSourceProofError as exc:
        raise ProductLinkProofError("capture path is redirected") from exc
    if not root.is_dir():
        raise ProductLinkProofError("capture directory is missing")
    files: dict[str, bytes] = {}
    total = 0
    seen: set[str] = set()
    for path in root.iterdir():
        if not path.is_file() or not _NAME.fullmatch(path.name):
            raise ProductLinkProofError("capture has unsupported or nested input")
        if path.name.casefold() in seen:
            raise ProductLinkProofError("capture has ambiguous case-folded names")
        seen.add(path.name.casefold())
        if path.suffix.casefold() not in (".obj", ".lib", ".pdb") and path.name not in (
                "link.rsp", "env.setting"):
            raise ProductLinkProofError("capture has unsupported file kind")
        raw = _read(path, "capture input")
        total += len(raw)
        if total > _MAX_CAPTURE_BYTES or len(files) >= _MAX_CAPTURE_FILES:
            raise ProductLinkProofError("capture exceeds fixture bounds")
        files[path.name] = raw
    if "link.rsp" not in files:
        raise ProductLinkProofError("LINKREPRO response missing")
    return files


def _response(raw: bytes, image_name: str, pdb_name: str) -> tuple[str, ...]:
    if not raw.startswith(b"\xff\xfe"):
        raise ProductLinkProofError("LINKREPRO response is not UTF-16LE")
    try:
        lines = raw.decode("utf-16").splitlines()
    except UnicodeError as exc:
        raise ProductLinkProofError("LINKREPRO response is invalid Unicode") from exc
    tokens = []
    for line in lines:
        if not line.startswith('"') or not line.endswith('"') or len(line) < 3:
            raise ProductLinkProofError("LINKREPRO response token is not singly quoted")
        token = line[1:-1]
        if '"' in token or "\0" in token:
            raise ProductLinkProofError("LINKREPRO response token is malformed")
        tokens.append(token)
    outputs = [m[1] for token in tokens if (m := _OUTPUT.fullmatch(token))]
    pdbs = [m[1] for token in tokens if (m := _PDB.fullmatch(token))]
    if outputs != [image_name] or pdbs != [pdb_name]:
        raise ProductLinkProofError("LINKREPRO output/PDB target differs from built fixture")
    flags = set()
    inputs = []
    for token in tokens:
        if _OUTPUT.fullmatch(token) or _PDB.fullmatch(token) or _IMPLIB.fullmatch(token):
            continue
        if _PDBMAP.fullmatch(token):
            continue
        if token.startswith("/"):
            option = token.casefold()
            if option not in _FLAGS:
                raise ProductLinkProofError("LINKREPRO has unsupported linker option")
            flags.add(option)
            continue
        match = _REL_INPUT.fullmatch(token)
        if match is None:
            raise ProductLinkProofError("LINKREPRO input escapes capture or has unsupported type")
        inputs.append(match[1])
    if not _REQUIRED <= flags or not inputs or ("/dll" in flags) != image_name.lower().endswith(".dll"):
        raise ProductLinkProofError("LINKREPRO is missing required fixture options/inputs")
    return tuple(inputs)


def replay_exact_pe(inputs: ReplayInputs, *, required_objects: tuple[str, ...] = (),
                    forbidden_object: str | None = None) -> dict[str, object]:
    """Run a bounded fresh capture replay and compare raw built/replayed PEs.

    A replay proves the *supplied capture* can reproduce the supplied image;
    archive member selection and full source-reference closure remain separate.
    """
    if type(inputs) is not ReplayInputs:
        raise ProductLinkProofError("exact ReplayInputs required")
    _validated_tool_paths(inputs.link_exe, inputs.vsdevcmd)
    link_tool_raw = _read(Path(inputs.link_exe), "link tool")
    vsdevcmd_raw = _read(Path(inputs.vsdevcmd), "VsDevCmd")
    built_raw = _read(Path(inputs.built_image), "built PE")
    built_pdb_raw = _read(Path(inputs.built_pdb), "built PDB")
    built_map_raw = _read(Path(inputs.built_map), "built MAP")
    guid, age, pdb_path = _rsds(built_raw)
    if Path(pdb_path).name.casefold() != Path(inputs.built_pdb).name.casefold():
        raise ProductLinkProofError("RSDS path names a different PDB")
    capture = _capture_files(Path(inputs.capture_dir))
    declared = _response(capture["link.rsp"], Path(inputs.built_image).name,
                         Path(inputs.built_pdb).name)
    names = {name.casefold() for name in capture}
    if any(name.casefold() not in names for name in declared):
        raise ProductLinkProofError("LINKREPRO declared input is missing")
    if any(name.casefold() not in {value.casefold() for value in declared}
           for name in required_objects):
        raise ProductLinkProofError("required VM object absent from LINKREPRO")
    if forbidden_object is not None and forbidden_object.casefold() in (
            value.casefold() for value in declared):
        raise ProductLinkProofError("original helper object remains a direct link input")
    work = Path(inputs.replay_dir)
    if work.exists():
        try:
            _reject_reparse_components(work)
        except ProductSourceProofError as exc:
            raise ProductLinkProofError("replay directory is redirected") from exc
        if not work.is_dir() or any(work.iterdir()):
            raise ProductLinkProofError("replay directory must be empty")
    else:
        try:
            _reject_reparse_components(work.parent)
        except ProductSourceProofError as exc:
            raise ProductLinkProofError("replay parent is redirected") from exc
        if not work.parent.is_dir():
            raise ProductLinkProofError("replay parent is missing")
        work.mkdir()
    for name, raw in capture.items():
        (work / name).write_bytes(raw)
    replay_pdb = work / Path(inputs.built_pdb).name
    if replay_pdb.exists():
        replay_pdb.unlink()  # Only the isolated capture copy is touched.
    extra = ('"/PDBALTPATH:' + pdb_path + '"\r\n').encode("utf-16le")
    (work / "link.rsp").write_bytes(capture["link.rsp"] + extra)
    script = work / "run_replay.cmd"
    script.write_text(
        '@echo off\r\ncall "' + str(inputs.vsdevcmd) +
        '" -arch=x64 >nul || exit /b 100\r\n"' + str(inputs.link_exe) +
        '" @link.rsp > replay.stdout 2> replay.stderr\r\nexit /b %ERRORLEVEL%\r\n',
        encoding="ascii",
    )
    hashes = []
    for index in range(1, age + 1):
        try:
            proc = subprocess.run(("cmd.exe", "/d", "/c", "run_replay.cmd"),
                                  cwd=work, capture_output=True, timeout=120,
                                  check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProductLinkProofError("LINKREPRO replay did not complete") from exc
        if proc.returncode or proc.stderr or (work / "replay.stderr").read_bytes():
            raise ProductLinkProofError(f"LINKREPRO replay pass {index} failed")
        output = _read(work / Path(inputs.built_image).name, "replayed PE")
        hashes.append(_sha(output))
    replay_raw = _read(work / Path(inputs.built_image).name, "replayed PE")
    if replay_raw != built_raw:
        raise ProductLinkProofError("replayed PE bytes differ from built fixture")
    replay_guid, replay_age, replay_path = _rsds(replay_raw)
    if (replay_guid, replay_age, replay_path) != (guid, age, pdb_path):
        raise ProductLinkProofError("replayed RSDS identity/age/path differs")
    # PDB/MAP *raw* equality is intentionally not required or reported.
    for path, original in ((inputs.built_image, built_raw), (inputs.built_pdb, built_pdb_raw),
                           (inputs.built_map, built_map_raw),
                           (inputs.link_exe, link_tool_raw),
                           (inputs.vsdevcmd, vsdevcmd_raw)):
        if _read(Path(path), "pinned replay input") != original:
            raise ProductLinkProofError("built image, sidecar or tool changed during replay")
    if _capture_files(Path(inputs.capture_dir)) != capture:
        raise ProductLinkProofError("LINKREPRO capture changed during replay")
    return {
        "schema": 1, "raw_pe_byte_equal": True, "built_pe_sha256": _sha(built_raw),
        "replay_pe_sha256": _sha(replay_raw), "replay_pass_sha256": hashes,
        "replay_pass_count": age, "source_link_capture_sha256": _sha(capture["link.rsp"]),
        "capture_file_sha256": {name: _sha(raw) for name, raw in sorted(capture.items())},
        "link_exe_sha256": _sha(_read(Path(inputs.link_exe), "link tool")),
        "vsdevcmd_sha256": _sha(_read(Path(inputs.vsdevcmd), "VsDevCmd")),
        "rsds_guid": guid, "rsds_age": age, "rsds_path": pdb_path,
        "pdb_raw_byte_equal_claimed": False, "map_raw_byte_equal_claimed": False,
        "archive_member_selection_proven": False,
        "source_reference_closure_proven": False, "production_admitted": False,
    }


def verify_product_fixture_final_link(
    source: ProductSourceInputs, header: Path, generated_dir: Path,
    replay: ReplayInputs, *, synthetic_fixture_key: bytes,
    selected_reference_inputs: SelectedWrapperLinkInputs,
    runtime_compile_session=None,
) -> dict[str, object]:
    """Re-prove current source and synthetic VM output, then replay exact PE."""
    if type(synthetic_fixture_key) is not bytes or len(synthetic_fixture_key) != 32:
        raise ProductLinkProofError("exact synthetic fixture key required")
    try:
        _validate_selected_wrapper_inputs(selected_reference_inputs)
    except SelectedWrapperProofError as exc:
        raise ProductLinkProofError(str(exc)) from exc
    try:
        require_runtime_compile_ready(runtime_compile_session)
    except RuntimeCompileError as exc:
        raise ProductLinkProofError(f"runtime compilation preflight failed: {exc}") from exc
    if (type(replay) is not ReplayInputs or not all(
            isinstance(getattr(replay, name), Path) for name in (
                "capture_dir", "built_image", "built_pdb", "built_map",
                "replay_dir", "link_exe", "vsdevcmd"))):
        raise ProductLinkProofError("exact replay paths required")
    replay_root = Path(replay.replay_dir)
    # The fresh generated copy is distinct from the replay capture copy.
    if replay_root.exists() and any(replay_root.iterdir()):
        raise ProductLinkProofError("replay root must be empty")
    if not replay_root.exists():
        replay_root.mkdir()
    fresh = replay_root / "fresh_emit"
    try:
        manifest = emit_product_fixture(
            source, header, fresh, key_mode="synthetic_fixture",
            synthetic_fixture_key=synthetic_fixture_key,
        )
    except (ProductFixtureError, OSError) as exc:
        raise ProductLinkProofError(f"current source fixture proof failed: {exc}") from exc
    emitted = set(manifest["emitted_sha256"]) | {"manifest.json"}
    actual = Path(generated_dir)
    try:
        _reject_reparse_components(actual)
        if {p.name for p in actual.iterdir()} != emitted:
            raise ProductLinkProofError("generated fixture file set differs")
    except (ProductSourceProofError, OSError) as exc:
        raise ProductLinkProofError("generated fixture directory is missing or redirected") from exc
    for name in emitted:
        if _read(actual / name, "generated fixture") != _read(fresh / name, "fresh fixture"):
            raise ProductLinkProofError("generated fixture differs from current source/key")
    generated_pins = {name: _sha(_read(actual / name, "generated fixture"))
                      for name in emitted}
    source_pins = {name: _sha(_read(Path(path), name)) for name, path in (
        ("source_pe", source.image), ("source_pdb", source.pdb),
        ("source_map", source.link_map), ("source_coff", source.helper_object),
        ("source_header", header),
    )}
    capture_pins = {
        path: {name: _sha(raw) for name, raw in _capture_files(path).items()}
        for path in (selected_reference_inputs.original_capture, replay.capture_dir)
    }
    tool_pins = {Path(path): _sha(_read(Path(path), "public proof tool"))
                 for path in (source.dia_helper, source.msdia, source.typed_abi_helper,
                              replay.link_exe, replay.vsdevcmd)}
    final_raw = _read(Path(replay.built_image), "built VM PE")
    final_pdb_raw = _read(Path(replay.built_pdb), "built VM PDB")
    final_map_raw = _read(Path(replay.built_map), "built VM MAP")
    final = analyze_pe(str(replay.built_image))
    if (final.load_config is None or not final.load_config.has_guard_cf
            or not final.load_config.xfg_present or final.load_config.unsupported_features):
        raise ProductLinkProofError("final VM PE lacks required CFG/XFG declaration")
    inventory = pdb_function_inventory.run_bound_inventory(
        final, Path(replay.built_image), Path(replay.built_pdb),
        Path(source.dia_helper), Path(source.msdia),
    )
    rows = source_link_build._map_rows(final_map_raw)
    symbol, prefix = source.symbol, "policy_vm" if "allowedRuntime" in source.symbol else "lease_vm"
    if prefix not in ("policy_vm", "lease_vm") or symbol != manifest["symbol"]:
        raise ProductLinkProofError("unexpected product helper identity")
    original_obj = Path(source.helper_object).name.casefold()
    if any(obj == original_obj for _, _, obj in rows):
        raise ProductLinkProofError("original helper object remains in final MAP")
    def unique(name: str, owner: str) -> int:
        try:
            return source_link_build._unique_map_symbol(rows, name, owner)
        except source_link_build.SourceLinkError as exc:
            raise ProductLinkProofError(f"final MAP symbol/owner mismatch: {name}") from exc
    wrapper_va = unique(symbol, prefix + "_wrapper.obj")
    thunk_va = unique(prefix, prefix + ".obj")
    descriptor_va = unique(prefix + "_descriptor", prefix + "_data.obj")
    envelope_va = unique(prefix + "_envelope", prefix + "_data.obj")
    common_va = unique("daedalus_x64_enter_common_stack512", "daedalus_x64_thunk.obj")
    wrapper_rva, thunk_rva = wrapper_va - final.image_base, thunk_va - final.image_base
    pe = pefile.PE(data=final_raw, fast_load=False)
    wrapper_size = 14 if prefix == "policy_vm" else 5
    wrapper = pe.get_data(wrapper_rva, wrapper_size)
    jump_off = 9 if prefix == "policy_vm" else 0
    if (len(wrapper) != wrapper_size or (prefix == "policy_vm" and
            wrapper[:9] != bytes.fromhex("0fb644242888442428")) or
            wrapper[jump_off] != 0xE9 or
            wrapper_rva + jump_off + 5 + struct.unpack_from("<i", wrapper, jump_off + 1)[0]
            != thunk_rva):
        raise ProductLinkProofError("final typed wrapper is not exact bounded tail jump")
    if ([(begin, end, count) for begin, end, count in inventory.range_multiplicities
         if begin == wrapper_rva] != [(wrapper_rva, wrapper_rva + wrapper_size, 1)]):
        raise ProductLinkProofError("final typed wrapper PDB extent differs")
    thunk = pe.get_data(thunk_rva, win64_thunk.THUNK_CODE_SIZE)
    if len(thunk) != win64_thunk.THUNK_CODE_SIZE:
        raise ProductLinkProofError("final VM thunk truncated")
    normalized = bytearray(thunk)
    rel = struct.unpack_from("<i", normalized, win64_thunk.THUNK_COMMON_REL32_OFFSET)[0]
    if thunk_va + win64_thunk.THUNK_COMMON_REL32_OFFSET + 4 + rel != common_va:
        raise ProductLinkProofError("VM thunk common bridge target differs")
    if struct.unpack_from("<Q", normalized,
                          win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET)[0] != descriptor_va:
        raise ProductLinkProofError("VM thunk descriptor pointer differs")
    normalized[win64_thunk.THUNK_COMMON_REL32_OFFSET:
               win64_thunk.THUNK_COMMON_REL32_OFFSET + 4] = b"\0" * 4
    normalized[win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET:
               win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET + 8] = b"\0" * 8
    if bytes(normalized) != win64_thunk.THUNK_TEMPLATE:
        raise ProductLinkProofError("VM thunk differs from pinned template")
    if ([(begin, end, count) for begin, end, count in inventory.range_multiplicities
         if begin == thunk_rva] != [(thunk_rva, thunk_rva + len(thunk), 1)]):
        raise ProductLinkProofError("VM thunk PDB extent differs")
    pdata = [entry for entry in final.runtime_functions if entry.begin_rva == thunk_rva]
    if len(pdata) != 1 or pdata[0].end_rva != thunk_rva + len(thunk):
        raise ProductLinkProofError("VM thunk PDATA extent differs")
    if pe.get_data(pdata[0].unwind_info_rva, len(win64_thunk.THUNK_UNWIND_INFO)) != (
            win64_thunk.THUNK_UNWIND_INFO):
        raise ProductLinkProofError("VM thunk unwind metadata differs")
    descriptor_rva, envelope_rva = descriptor_va - final.image_base, envelope_va - final.image_base
    reloc_sites = {item.target_rva for item in final.dir64_relocations}
    if not {thunk_rva + win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET,
            descriptor_rva + 8, descriptor_rva + 32} <= reloc_sites:
        raise ProductLinkProofError("VM thunk/descriptor ASLR relocations missing")
    descriptor = pe.get_data(descriptor_rva, 40)
    if len(descriptor) != 40:
        raise ProductLinkProofError("VM descriptor truncated")
    version, size, pointer = struct.unpack_from("<IIQ", descriptor)
    if (version != 4 or size != manifest["envelope_size"] or pointer != envelope_va
            or descriptor[16:32].hex() != manifest["program_id"]
            or struct.unpack_from("<Q", descriptor, 32)[0] != final.image_base):
        raise ProductLinkProofError("VM descriptor identity differs")
    envelope = pe.get_data(envelope_rva, size)
    if _sha(envelope) != manifest["envelope_sha256"]:
        raise ProductLinkProofError("VM envelope differs from current source")
    if _sha(bytecode_pages.open_program(envelope, synthetic_fixture_key)) != (
            manifest["bytecode_sha256"]):
        raise ProductLinkProofError("VM program differs from current source bytecode")
    cf_targets = {item.rva for item in final.load_config.guard_cf_targets}
    if thunk_rva in cf_targets or any(
            thunk_rva < value < thunk_rva + len(thunk) for value in cf_targets):
        raise ProductLinkProofError("CFG permits internal VM thunk entry")
    if _read(Path(replay.built_image), "built VM PE") != final_raw or _read(
            Path(replay.built_pdb), "built VM PDB") != final_pdb_raw or _read(
            Path(replay.built_map), "built VM MAP") != final_map_raw:
        raise ProductLinkProofError("final VM image or sidecars changed during structural proof")
    result = replay_exact_pe(
        ReplayInputs(replay.capture_dir, replay.built_image, replay.built_pdb,
                     replay.built_map, replay_root / "link", replay.link_exe,
                     replay.vsdevcmd),
        required_objects=(prefix + "_wrapper.obj", prefix + ".obj",
                          prefix + "_data.obj", "daedalus_vm.obj",
                          "daedalus_x64_thunk.obj"),
        forbidden_object=Path(source.helper_object).name,
    )
    entry = _MaterializedWrapperEntry(
        symbol, prefix, wrapper_rva, wrapper_size, thunk_rva,
        common_va - final.image_base, descriptor_rva,
        _sha(final_raw), _sha(final_pdb_raw), _sha(final_map_raw),
    )
    try:
        selected_binding = prove_selected_wrapper(
            source, replay, selected_reference_inputs, entry, replay_root / "selected_calls")
    except (SelectedWrapperProofError, ProductSourceProofError,
            ValueError, OSError) as exc:
        raise ProductLinkProofError(f"selected wrapper reference proof failed: {exc}") from exc
    try:
        runtime_compilation = prove_runtime_coff_compilation(
            runtime_compile_session, selected_reference_inputs.generated_inputs,
            Path(replay.capture_dir))
    except (RuntimeCompileError, OSError) as exc:
        raise ProductLinkProofError(f"runtime compilation proof failed: {exc}") from exc
    for path, raw in ((replay.built_image, final_raw), (replay.built_pdb, final_pdb_raw),
                      (replay.built_map, final_map_raw)):
        if _read(Path(path), "post-compile final artifact") != raw:
            raise ProductLinkProofError("final VM artifact changed during compilation")
    for path, pins in capture_pins.items():
        if {name: _sha(raw) for name, raw in _capture_files(path).items()} != pins:
            raise ProductLinkProofError("LINK capture changed during runtime compilation")
    if capture_pins[replay.capture_dir] != result["capture_file_sha256"]:
        raise ProductLinkProofError("runtime compilation and replay capture pins differ")
    for path, digest in selected_binding["compiled_input_sha256"].items():
        if _sha(_read(Path(path), "post-compile generated object")) != digest:
            raise ProductLinkProofError("generated object changed during runtime compilation")
    for path, digest in tool_pins.items():
        if _sha(_read(path, "post-compile public proof tool")) != digest:
            raise ProductLinkProofError("public proof tool changed during runtime compilation")
    if any(_sha(_read(actual / name, "generated fixture")) != digest
           for name, digest in generated_pins.items()):
        raise ProductLinkProofError("generated fixture changed during replay")
    if any(_sha(_read(Path(path), name)) != source_pins[name] for name, path in (
        ("source_pe", source.image), ("source_pdb", source.pdb),
        ("source_map", source.link_map), ("source_coff", source.helper_object),
        ("source_header", header),
    )):
        raise ProductLinkProofError("source proof inputs changed during replay")
    source_root = Path(__file__).resolve().parents[1]
    if (source_link_build._source_tree_hashes(source_root, runtime=True) !=
            manifest["runtime_source_sha256"] or
            source_link_build._source_tree_hashes(source_root, runtime=False) !=
            manifest["compiler_source_sha256"]):
        raise ProductLinkProofError("compiler/runtime source changed during replay")
    return {
        "schema": 1, "mode": "synthetic_fixture_only", "symbol": symbol,
        "source_pe_sha256": manifest["source_proof"]["source_pe_sha256"],
        "source_body_sha256": manifest["source_proof"]["source_body_sha256"],
        "generated_manifest_sha256": _sha(_read(actual / "manifest.json", "manifest")),
        "final_pe_sha256": _sha(final_raw), "final_pdb_sha256": _sha(final_pdb_raw),
        "final_map_sha256": _sha(final_map_raw), "wrapper_rva": wrapper_rva,
        "thunk_rva": thunk_rva, "envelope_rva": envelope_rva,
        "final_link_byte_binding_proven": result["raw_pe_byte_equal"],
        "linked_fixture_structure_verified": True,
        "wrapper_guard_cf_target_present": wrapper_rva in cf_targets,
        "source_reference_closure_proven": False,
        "original_helper_object_omission_proven": selected_binding["original_helper_object_omission_proven"],
        "authenticated_selected_wrapper_reference_binding_proven": True,
        "selected_direct_source_output_equivalence_proven": True,
        "global_source_output_reference_equivalence_proven": False,
        "runtime_source_compile_binding_proven":
            runtime_compilation["runtime_source_compile_binding_proven"],
        "indirect_target_closure_proven": False,
        "xfg_enforcement_proven": False,
        "production_key_service_configured": False,
        "production_admitted": False,
        "replay": result,
        "selected_reference_binding": selected_binding,
        "runtime_compilation": runtime_compilation,
    }


__all__ = ["ProductLinkProofError", "ReplayInputs", "SelectedWrapperLinkInputs", "replay_exact_pe",
           "verify_product_fixture_final_link"]
