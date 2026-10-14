"""Opt-in selected direct-call output proof for conventional LINKREPRO pairs.

This module deliberately does not admit a protected product. It binds only a
single COFF-selected helper's direct REL32 caller sections to final PE calls.
Unknown section mapping, ICF folding, linker diagnostics, or replay drift fail
closed. Indirect targets, startup, keys, signing, and original-product equality
remain separate unproved gates.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
import json
import ctypes
from ctypes import wintypes
from pathlib import Path
import re
import struct
import subprocess
import threading
import time

from iced_x86 import Decoder, FlowControl, Mnemonic, OpKind

from packer.pe_analyze import analyze_pe
from . import direct_control_flow, pdb_coverage, pdb_function_inventory
from .link_capture_archive import (
    CaptureClosureError, _capture_regular_file, _capture_root,
)
from .link_capture_diagnostic import (
    CaptureDiagnosticError, inspect_capture_inputs,
)
from .link_capture_response_pair import ResponsePairError, inspect_response_pair
from .link_capture_response_pair import _environment_profile
from .link_capture_selected_references import (
    SelectedReferenceError, _scan_object, inspect_selected_capture,
)
from .source_link_product_admission import (
    ProductSourceInputs, ProductSourceProofError, _reject_reparse_components,
    _prove_dia_abi, _typed_signature, inspect_source,
)


class FinalCallsiteError(ValueError):
    """One bounded selected output direct-call attribution failed."""


@dataclass(frozen=True)
class FinalCallsiteInputs:
    original_capture: Path
    replacement_capture: Path
    original_source: ProductSourceInputs
    replacement_source: ProductSourceInputs
    replay_parent: Path
    link_exe: Path


@dataclass(frozen=True)
class _CallerSection:
    object_name: str
    section_index: int
    primary: str
    body: bytes
    reloc_fields: tuple[int, ...]
    selected_field: int


_TOOL_PATH = re.compile(r"[A-Za-z]:\\(?:[A-Za-z0-9_. -]+\\)*[A-Za-z0-9_. -]+\Z")
_NAME = re.compile(r"[A-Za-z0-9_.@+\-$]+\Z")
_OUT = re.compile(r"/out:\.\\([A-Za-z0-9_.@+\-$]+\.(?:exe|dll))\Z", re.I)
_RAW_MAP_LINE = re.compile(
    r"^\s*[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{8,16})"
    r"(?:\s+[fi]){0,2}\s+(\S+\.obj)\s*$"
)
_REQUIRED_OPTIONS = ("/opt:ref", "/brepro", "/debug:full",
                     "/incremental:no", "/map")
_KNOWN_FIXED_OPTIONS = frozenset((
    "/incremental:no", "/nologo", "/manifest",
    "/manifestuac:level='asinvoker' uiaccess='false'", "/manifest:embed",
    "/debug:full", "/map", "/subsystem:windows", "/subsystem:console",
    "/opt:ref", "/opt:icf", "/opt:noicf", "/tlbid:1",
    "/dynamicbase", "/nxcompat", "/machine:x64", "/cetcompat",
    "/guard:cf", "/pdbaltpath:%%%%_pdb%%%%", "/dll", "/brepro",
    "/verbose:lib",
))
_MAX_LOG = 64 * 1024 * 1024
_MAX_FILE = 64 * 1024 * 1024
_MAX_TOOL = 16 * 1024 * 1024
_MAX_SECTIONS = 65535
_MAX_SYMBOLS = 2_000_000
_MAX_REFERENCES = 1024


def _require(ok: bool, reason: str) -> None:
    if not ok:
        raise FinalCallsiteError(reason)


def _sha(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def _read(path: Path, label: str, limit: int = _MAX_FILE) -> bytes:
    try:
        _reject_reparse_components(path)
        before = path.stat()
        _require(path.is_file() and 0 < before.st_size <= limit,
                 f"{label} is missing or exceeds the bounded file size")
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
        after = path.stat()
    except (OSError, ProductSourceProofError) as exc:
        raise FinalCallsiteError(f"{label} is missing or redirected") from exc
    _require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
             and len(raw) == before.st_size and len(raw) <= limit,
             f"{label} changed during read")
    return raw


def _validated_linker(link: Path) -> tuple[str, str]:
    """Pin an absolute canonical VS 2022 AMD64 linker, never PATH lookup."""
    raw = str(link)
    _require(isinstance(link, Path) and link.is_absolute() and
             _TOOL_PATH.fullmatch(raw) is not None and
             all(part not in (".", "..") and not part.endswith((" ", "."))
                 for part in link.parts[1:]),
             "noncanonical linker path")
    try:
        edition = link.parents[7]
        suffix = link.relative_to(edition).parts
    except (IndexError, ValueError) as exc:
        raise FinalCallsiteError("linker is not in a canonical VS root") from exc
    _require(edition.parent == Path(r"C:\Program Files\Microsoft Visual Studio\2022") and
             edition.name.casefold() in
             {"community", "professional", "enterprise", "buildtools"} and
             len(suffix) == 8 and
             tuple(part.casefold() for part in suffix[:3]) == ("vc", "tools", "msvc") and
             re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", suffix[3]) is not None and
             tuple(part.casefold() for part in suffix[4:]) ==
             ("bin", "hostx64", "x64", "link.exe"),
             "unrecognized Visual Studio AMD64 linker path")
    return str(link), _sha(_read(link, "link.exe", _MAX_TOOL))


@dataclass(frozen=True)
class _ReplayProcess:
    returncode: int
    stdout: bytes
    stderr: bytes
    status: str


def _validated_replay_parent(parent: Path, forbidden: tuple[Path, ...]) -> None:
    """A replay cannot be inside or contain any capture or source directory."""
    _reject_reparse_components(parent)
    _require(parent.is_dir() and parent.is_absolute() and
             re.match(r"^[A-Za-z]:\\", str(parent)) is not None and
             not any(char in str(parent) for char in '%!&^|<>"\r\n'),
             "replay parent is not a canonical local directory")
    root = parent.resolve(strict=True)
    for item in forbidden:
        _reject_reparse_components(item)
        directory = item.resolve(strict=True)
        _require(root != directory and
                 root not in directory.parents and
                 directory not in root.parents,
                 "replay parent overlaps a capture or source directory")


def _replay_environment(capture: Path, work: Path,
                        link: Path) -> tuple[dict[str, str], dict[str, str]]:
    """Project only pinned material linker inputs; no ambient PATH/CMD/VS state."""
    try:
        captured_sha, rows, _local = _environment_profile(_capture_root(capture))
    except ResponsePairError as exc:
        raise FinalCallsiteError("captured linker environment is invalid") from exc
    profile = dict(rows)
    _require("link" not in profile and "_link_" not in profile,
             "captured LINK or _LINK_ override is unsupported")
    library = profile.get("lib")
    sdk_raw = profile.get("windowssdkverbinpath")
    _require(type(library) is str and 0 < len(library) <= 8192 and
             type(sdk_raw) is str and len(sdk_raw) <= 260,
             "captured LIB or SDK bin path is missing or excessive")
    edition = link.parents[7]
    sdk_root = Path(r"C:\Program Files (x86)\Windows Kits\10")
    paths = library.split(";")
    _require(1 <= len(paths) <= 16 and all(paths),
             "captured LIB search path count is unsupported")
    for entry in paths:
        directory = Path(entry)
        _reject_reparse_components(directory)
        _require(directory.is_absolute() and directory.is_dir() and
                 any(directory.resolve(strict=True).is_relative_to(root)
                     for root in (edition, sdk_root)),
                 "captured LIB resolves outside VS or Windows SDK")
    _reject_reparse_components(Path(sdk_raw))
    sdk = Path(sdk_raw).resolve(strict=True)
    _require(sdk.parent == sdk_root / "bin" and
             re.fullmatch(r"10\.0\.[0-9]+\.[0-9]+", sdk.name) is not None,
             "captured SDK bin is not a versioned Windows 10 kit")
    sdk_bin = sdk / "x64"
    _reject_reparse_components(sdk_bin)
    _require(sdk_bin.is_dir(), "captured SDK x64 tools are missing")
    cmd = Path(r"C:\Windows\System32\cmd.exe")
    taskkill = Path(r"C:\Windows\System32\taskkill.exe")
    tool_hashes = {
        "link_exe_sha256": _sha(_read(link, "link.exe", _MAX_TOOL)),
        "cmd_exe_sha256": _sha(_read(cmd, "System32 cmd.exe", _MAX_TOOL)),
        "taskkill_exe_sha256": _sha(_read(taskkill, "System32 taskkill.exe", _MAX_TOOL)),
        "rc_exe_sha256": _sha(_read(sdk_bin / "rc.exe", "SDK rc.exe", _MAX_TOOL)),
        "mt_exe_sha256": _sha(_read(sdk_bin / "mt.exe", "SDK mt.exe", _MAX_TOOL)),
    }
    env = {
        "SystemRoot": r"C:\Windows", "windir": r"C:\Windows",
        "ComSpec": str(cmd),
        "Path": ";".join((str(link.parent), str(sdk_bin),
                          r"C:\Windows\System32", r"C:\Windows",
                          r"C:\Windows\System32\Wbem")),
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "TEMP": str(work), "TMP": str(work), "SystemDrive": "C:",
        "LIB": library,
    }
    projection = _sha(json.dumps(sorted(env.items()), separators=(",", ":"),
                                 ensure_ascii=True).encode("ascii"))
    return env, {"captured_env_sha256": captured_sha,
                 "projected_env_sha256": projection, **tool_hashes}


class _JobBasicLimits(ctypes.Structure):
    _fields_ = (("process_time", ctypes.c_longlong),
                ("job_time", ctypes.c_longlong),
                ("flags", wintypes.DWORD),
                ("minimum_working_set", ctypes.c_size_t),
                ("maximum_working_set", ctypes.c_size_t),
                ("active_process_limit", wintypes.DWORD),
                ("affinity", ctypes.c_size_t),
                ("priority", wintypes.DWORD),
                ("scheduling", wintypes.DWORD))


class _JobIoCounters(ctypes.Structure):
    _fields_ = tuple((name, ctypes.c_ulonglong) for name in (
        "read_operations", "write_operations", "other_operations",
        "read_bytes", "write_bytes", "other_bytes"))


class _JobExtendedLimits(ctypes.Structure):
    _fields_ = (("basic", _JobBasicLimits), ("io", _JobIoCounters),
                ("process_memory", ctypes.c_size_t),
                ("job_memory", ctypes.c_size_t),
                ("peak_process_memory", ctypes.c_size_t),
                ("peak_job_memory", ctypes.c_size_t))


def _make_kill_on_close_job() -> tuple[object, int]:
    """Create a nested Windows job before starting the suspended linker."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = (
        wintypes.HANDLE, wintypes.INT, ctypes.c_void_p, wintypes.DWORD)
    kernel.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    job = kernel.CreateJobObjectW(None, None)
    _require(bool(job), "bounded replay job creation failed")
    limits = _JobExtendedLimits()
    limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits),
                                         ctypes.sizeof(limits)):
        kernel.CloseHandle(job)
        raise FinalCallsiteError("bounded replay job configuration failed")
    return kernel, job


def _close_job(kernel, job: int) -> None:
    _require(bool(kernel.CloseHandle(job)),
             "bounded replay process-tree termination failed")


def _run_bounded(argv: tuple[str, ...], cwd: Path, env: dict[str, str],
                 *, limit: int = _MAX_LOG, timeout: float = 180) -> _ReplayProcess:
    """Bound combined stdout/stderr in memory while a single direct link runs."""
    _require(0 < limit <= _MAX_LOG and 0 < timeout <= 180,
             "replay output/time budget is invalid")
    kernel, job = _make_kill_on_close_job()
    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                creationflags=0x4)  # CREATE_SUSPENDED
    except (OSError, ValueError) as exc:
        _close_job(kernel, job)
        raise FinalCallsiteError("absolute linker process did not start") from exc
    try:
        if not kernel.AssignProcessToJobObject(job, int(proc._handle)):
            raise FinalCallsiteError("suspended linker could not join bounded job")
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        ntdll.NtResumeProcess.argtypes = (wintypes.HANDLE,)
        ntdll.NtResumeProcess.restype = ctypes.c_long
        _require(ntdll.NtResumeProcess(int(proc._handle)) == 0,
                 "bounded linker job could not resume")
    except Exception:
        _close_job(kernel, job)
        proc.kill()
        proc.wait(timeout=10)
        raise
    lock = threading.Lock()
    overflow = threading.Event()
    errors: list[OSError] = []
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0

    def drain(name: str, stream) -> None:
        nonlocal total
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return
                with lock:
                    room = max(0, limit - total)
                    kept = chunk[:room]
                    captured[name].extend(kept)
                    total += len(kept)
                    if len(kept) != len(chunk):
                        overflow.set()
        except OSError as exc:
            errors.append(exc)

    workers = [threading.Thread(target=drain, args=(name, stream), daemon=True)
               for name, stream in (("stdout", proc.stdout),
                                    ("stderr", proc.stderr))]
    for worker in workers:
        worker.start()
    deadline = time.monotonic() + timeout
    status = "exited"
    job_open = True
    try:
        while proc.poll() is None:
            if overflow.is_set():
                status = "output_limit"
                break
            if time.monotonic() >= deadline:
                status = "timeout"
                break
            time.sleep(0.01)
        _close_job(kernel, job)
        job_open = False
        proc.wait(timeout=10)
        for worker in workers:
            worker.join(timeout=10)
        _require(all(not worker.is_alive() for worker in workers) and not errors,
                 "bounded replay pipe reader did not finish")
        if overflow.is_set():
            status = "output_limit"
        return _ReplayProcess(proc.returncode,
                              bytes(captured["stdout"]),
                              bytes(captured["stderr"]), status)
    finally:
        try:
            if job_open:
                _close_job(kernel, job)
        finally:
            for stream in (proc.stdout, proc.stderr):
                stream.close()


def _require_clean_linker_replay(proc: _ReplayProcess) -> None:
    """Reject diagnostics regardless of ASCII case before using REF/ICF logs."""
    folded = proc.stdout.lower()
    _require(proc.status == "exited" and proc.returncode == 0 and not proc.stderr and
             0 < len(proc.stdout) <= _MAX_LOG and
             b"warning lnk" not in folded and b"error lnk" not in folded,
             "verbose linker replay failed or emitted diagnostics")


def _required_response(inventory: dict, output: str) -> None:
    switches = inventory.get("switches")
    _require(type(switches) is list and all(type(item) is str for item in switches),
             "LINKREPRO switch inventory is malformed")
    folded = [item.casefold() for item in switches]
    _require(all(folded.count(option) == 1 for option in _REQUIRED_OPTIONS),
             "LINKREPRO lacks unique REF, BREPRO, debug, MAP or fixed-link option")
    _require(sum(folded.count(option) for option in ("/opt:icf", "/opt:noicf")) == 1,
             "LINKREPRO ICF mode is missing or ambiguous")
    _require(all(item in _KNOWN_FIXED_OPTIONS or
                 _OUT.fullmatch(item) is not None or
                 re.fullmatch(r"/pdb:\.\\[a-z0-9_.@+\-$]+\.pdb", item) is not None or
                 re.fullmatch(r"/implib:\.\\[a-z0-9_.@+\-$]+\.lib", item) is not None or
                 item.startswith("/pdbmap:")
                 for item in folded) and
             folded.count("/dll") == (1 if output.lower().endswith(".dll") else 0) and
             1 <= folded.count("/machine:x64") <= 2 and
             1 <= folded.count("/guard:cf") <= 2 and
             sum(item.startswith("/pdb:") for item in folded) == 1 and
             sum(item.startswith("/implib:") for item in folded) == 1 and
             sum(item.startswith("/pdbmap:") for item in folded) <= 2,
             "LINKREPRO has unknown, conflicting or duplicated linker options")
    outputs = [match.group(1) for item in switches if (match := _OUT.fullmatch(item))]
    _require(len(outputs) == 1 and outputs[0].casefold() == output.casefold() and
             sum(item.startswith("/out:") for item in folded) == 1 and
             "/machine:x64" in folded,
             "LINKREPRO output or machine differs from source image")


def _reject_archive_caller_label_aliases(inventory: dict,
                                         selected: dict) -> None:
    """An archive member cannot impersonate a printed explicit MAP owner."""
    refs = selected.get("references")
    helper = selected.get("helper_object")
    _require(type(refs) is list and type(helper) is str and
             all(type(row) is dict and type(row.get("object")) is str
                 for row in refs), "selected caller labels are malformed")
    owners = {helper.casefold(), *(row["object"].casefold() for row in refs)}
    for item in (*inventory.get("inputs", ()),
                 *inventory.get("implicit_libraries", ())):
        if item.get("kind") != "microsoft_coff_archive":
            continue
        for member in item.get("members", ()):
            label = member.get("display_label")
            _require(type(label) is str and label and "\x00" not in label,
                     "archive MAP label is malformed")
            _require(Path(label.replace("/", "\\")).name.casefold() not in owners,
                     "archive member label aliases an explicit caller/helper owner")


def _copy_and_replay(capture: Path, inventory: dict,
                     source_inputs: ProductSourceInputs,
                     replay_parent: Path, label: str,
                     link: str) -> dict:
    """Direct absolute-link replay with bounded IO and bound output sidecars."""
    root = _capture_root(capture)
    files = inventory.get("capture_file_sha256")
    _require(type(files) is dict and 1 <= len(files) <= 512 and
             all(type(name) is str and _NAME.fullmatch(name) is not None and
                 type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest)
                 for name, digest in files.items()),
             "LINKREPRO complete file inventory is malformed")
    _require(set(files) == {path.name for path in root.iterdir()},
             "LINKREPRO capture gained or lost a file")
    _validated_replay_parent(replay_parent, (root,))
    work = replay_parent / label
    _require(not work.exists() and label in ("original", "replacement"),
             "replay destination already exists or is ambiguous")
    work.mkdir()
    total = 0
    for name, expected in sorted(files.items()):
        raw = _capture_regular_file(root, name)
        total += len(raw)
        _require(total <= 256 * 1024 * 1024 and _sha(raw) == expected,
                 "LINKREPRO input changed or exceeds replay bound")
        with (work / name).open("xb") as stream:
            stream.write(raw)
    _require(all(_sha(_capture_regular_file(root, name)) == expected
                 for name, expected in files.items()),
             "LINKREPRO input changed after isolated copy")
    output_names = (source_inputs.image.name, source_inputs.link_map.name)
    _require(all(name not in files for name in output_names),
             "capture already contains final PE or MAP output")
    stale_pdb = work / source_inputs.pdb.name
    prior_pdb_sha = files.get(stale_pdb.name)
    if prior_pdb_sha is not None:
        _require(_sha(_read(stale_pdb, "captured output PDB")) == prior_pdb_sha,
                 "captured output PDB changed before replay")
    retained_inputs = {name: digest for name, digest in files.items()
                       if name != stale_pdb.name}
    _require(all(_sha(_read(work / name, "isolated linker input")) == digest
                 for name, digest in retained_inputs.items()),
             "isolated linker input changed before execution")
    environment, env_receipt = _replay_environment(capture, work, Path(link))
    argv = (link, "@link.rsp", "/VERBOSE:REF", "/VERBOSE:ICF")
    proc = _run_bounded(argv, work, environment)
    log_path = replay_parent / f"{label}.verbose.stdout.txt"
    stderr_path = replay_parent / f"{label}.verbose.stderr.txt"
    exit_path = replay_parent / f"{label}.verbose.exit.txt"
    with log_path.open("xb") as stream:
        stream.write(proc.stdout)
    with stderr_path.open("xb") as stream:
        stream.write(proc.stderr)
    with exit_path.open("x", encoding="ascii") as stream:
        stream.write(f"{proc.returncode} {proc.status}\n")
    meta = {"argv": argv, "argv_sha256": _sha(json.dumps(argv).encode("ascii")),
            "status": proc.status, "returncode": proc.returncode,
            "captured_stdout_bytes": len(proc.stdout),
            "captured_stderr_bytes": len(proc.stderr), **env_receipt}
    (replay_parent / f"{label}.replay.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _require(all(_sha(_read(work / name, "post-replay linker input")) == digest
                 for name, digest in retained_inputs.items()),
             "isolated linker input changed during execution")
    _require(all(_sha(_capture_regular_file(root, name)) == digest
                 for name, digest in files.items()),
             "captured linker input changed during isolated replay")
    _require(_replay_environment(capture, work, Path(link))[1] == env_receipt and
             _sha(_read(Path(link), "post-replay link.exe", _MAX_TOOL)) ==
             env_receipt["link_exe_sha256"],
             "replay environment or SDK tool changed during execution")
    _require_clean_linker_replay(proc)
    _require(b"Discarded " in proc.stdout or b"Selected symbol:" in proc.stdout,
             "verbose REF/ICF record is missing")
    output = _read(work / source_inputs.image.name, "replayed PE")
    built = _read(source_inputs.image, "built PE")
    _require(output == built, "verbose replay PE differs from built PE")
    map_output = _read(work / source_inputs.link_map.name, "replayed MAP")
    map_built = _read(source_inputs.link_map, "built MAP")
    _require(map_output == map_built, "verbose replay MAP differs from built MAP")
    replay_pdb = work / source_inputs.pdb.name
    replay_pdb_sha = _sha(_read(replay_pdb, "replayed PDB"))
    _require(prior_pdb_sha is None or replay_pdb_sha != prior_pdb_sha,
             "linker did not rewrite captured output PDB")
    built_pdb_sha = _sha(_read(source_inputs.pdb, "built PDB"))
    _require(_sha(_read(log_path, "retained verbose log")) == _sha(proc.stdout),
             "verbose linker log changed after retention")
    return {"stdout": proc.stdout, "pe_sha256": _sha(output),
            "map_sha256": _sha(map_output), "replay_pdb_sha256": replay_pdb_sha,
            "built_pdb_sha256": built_pdb_sha,
            "captured_stale_output_pdb_sha256": prior_pdb_sha,
            "replay_pe": work / source_inputs.image.name,
            "replay_pdb": replay_pdb,
            "replay_map": work / source_inputs.link_map.name,
            "log_path": log_path,
            "log_sha256": _sha(proc.stdout), "environment": env_receipt}


def _coff_primary(raw: bytes, object_name: str, section_index: int,
                  selected_field: int) -> _CallerSection:
    """Bind one selected REL32 to one ordinary or bigobj COMDAT function."""
    big = raw[:4] == b"\0\0\xff\xff"
    header, width = (56, 20) if big else (20, 18)
    _require(len(raw) >= header, "caller COFF header is truncated")
    if big:
        count, symptr, nsyms = struct.unpack_from("<III", raw, 44)
    else:
        _require(struct.unpack_from("<H", raw)[0] == 0x8664,
                 "caller COFF is not ordinary AMD64")
        count = struct.unpack_from("<H", raw, 2)[0]
        symptr, nsyms = struct.unpack_from("<II", raw, 8)
    _require(0 < count <= _MAX_SECTIONS and 0 < section_index <= count and
             header + 40 * count <= len(raw) and 0 < nsyms <= _MAX_SYMBOLS and
             header + 40 * count <= symptr and
             symptr + width * nsyms + 4 <= len(raw),
             "caller COFF sections/symbols are out of bounds")
    string_at = symptr + width * nsyms
    string_size = struct.unpack_from("<I", raw, string_at)[0]
    _require(4 <= string_size <= len(raw) - string_at,
             "caller COFF string table is out of bounds")
    strings = raw[string_at:string_at + string_size]
    primaries: list[str] = []
    index = 0
    while index < nsyms:
        offset = symptr + width * index
        field = raw[offset:offset + 8]
        if field[:4] == b"\0" * 4:
            pos = struct.unpack_from("<I", field, 4)[0]
            _require(4 <= pos < len(strings), "caller symbol string offset is invalid")
            end = strings.find(b"\0", pos)
            _require(end > pos and end - pos <= 65535,
                     "caller symbol name is unbounded")
            name_raw = strings[pos:end]
        else:
            name_raw = field.split(b"\0", 1)[0]
        try:
            name = name_raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise FinalCallsiteError("caller symbol is not ASCII") from exc
        if big:
            value, section, kind, storage, aux = struct.unpack_from(
                "<IiHBB", raw, offset + 8)
        else:
            value, section, kind, storage, aux = struct.unpack_from(
                "<IhHBB", raw, offset + 8)
        _require(index + aux < nsyms and section <= count,
                 "caller symbol record is malformed")
        if section == section_index and value == 0 and kind & 0x20 and storage in (2, 3):
            primaries.append(name)
        index += aux + 1
    _require(len(primaries) == 1 and 0 < len(primaries[0]) <= 65535 and
             all(33 <= ord(char) <= 126 and char not in '()"\\'
                 for char in primaries[0]),
             "caller COMDAT has no unique primary function symbol")
    head = header + 40 * (section_index - 1)
    section_label = raw[head:head + 8].split(b"\0", 1)[0]
    size, dataoff, reloff = struct.unpack_from("<III", raw, head + 16)
    nrel = struct.unpack_from("<H", raw, head + 32)[0]
    flags = struct.unpack_from("<I", raw, head + 36)[0]
    _require(section_label.startswith(b".text") and
             flags & 0x20000000 and flags & 0x20 and flags & 0x1000 and
             not flags & 0x01000000 and 1 <= size <= 1 << 20 and
             dataoff > 0 and dataoff + size <= len(raw) and
             0 < nrel <= 65535 and reloff > 0 and
             reloff + nrel * 10 <= len(raw),
             "caller section is not bounded executable COMDAT")
    body = raw[dataoff:dataoff + size]
    fields = []
    for j in range(nrel):
        field, symbol, kind = struct.unpack_from("<IIH", raw, reloff + 10 * j)
        _require(kind == 4 and 1 <= field and field + 4 <= size and
                 symbol < nsyms,
                 "caller section has unsupported relocation")
        fields.append(field)
    fields.sort()
    _require(len(fields) == len(set(fields)) and
             all(right >= left + 4 for left, right in zip(fields, fields[1:])) and
             selected_field in fields and body[selected_field - 1] == 0xE8,
             "caller REL32 fields overlap or omit selected E8")
    return _CallerSection(object_name, section_index, primaries[0], body,
                          tuple(fields), selected_field)


def _discarded(log: bytes, primary: str, object_name: str) -> bool:
    marker = b"(" + primary.encode("ascii") + b") from " + object_name.encode("ascii")
    hits = [line.strip() for line in log.splitlines() if marker in line]
    _require(len(hits) <= 1, "selected caller appears ambiguously in REF/ICF log")
    if not hits:
        return False
    _require(hits[0].startswith(b'Discarded "') and hits[0].endswith(marker),
             "selected caller was folded or has unknown linker log form")
    return True


def _strict_map_rows(raw: bytes) -> tuple[tuple[str, int, str], ...]:
    """Keep exact owner spelling; never collapse LIB:member.obj to basename."""
    try:
        lines = raw.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError as exc:
        raise FinalCallsiteError("caller MAP is not UTF-8") from exc
    rows = []
    for line in lines:
        match = _RAW_MAP_LINE.fullmatch(line)
        if match:
            name, va, owner = match.groups()
            rows.append((name, int(va, 16), owner.casefold()))
    _require(bool(rows), "caller MAP has no object-bound symbols")
    return tuple(rows)


def _require_explicit_helper_row(rows: tuple, symbol: str, va: int,
                                 object_name: str) -> None:
    helper_rows = [(address, owner) for name, address, owner in rows
                   if name == symbol]
    _require(helper_rows == [(va, object_name.casefold())],
             "selected helper MAP owner is archive-qualified or ambiguous")


def _reject_executable_dir64(parsed, sections: tuple) -> None:
    """On-disk decode must equal loader-mapped executable bytes at any ASLR base."""
    for relocation in parsed.dir64_relocations:
        start = relocation.target_rva
        _require(not any(
            section.characteristics & direct_control_flow.IMAGE_SCN_MEM_EXECUTE and
            start < section.mapped_end and section.rva < start + 8
            for section in sections),
            "DIR64 base relocation changes executable bytes after mapping")


def _linked_callsite(section: _CallerSection, rows: tuple,
                     inventory: pdb_coverage.PdbCoverageProof,
                     parsed, helper_rva: int, log: bytes) -> tuple[int | None, dict]:
    discarded = _discarded(log, section.primary, section.object_name)
    matches = [(va, owner) for name, va, owner in rows if name == section.primary]
    _require((discarded and not matches) or
             (not discarded and len(matches) == 1 and
              matches[0][1] == section.object_name.casefold()),
             "caller REF discard and MAP ownership disagree")
    if discarded:
        return None, {"object": section.object_name,
                      "section_index": section.section_index,
                      "primary": section.primary, "status": "ref_discarded"}
    begin = matches[0][0] - parsed.image_base
    _require(0 < begin < 0x1_0000_0000 and
             sum(va == matches[0][0] for _name, va, _owner in rows) == 1,
             "caller MAP entry is aliased or out of image")
    spans = [(end - start, count) for start, end, count in
             inventory.inventory.range_multiplicities if start == begin]
    _require(spans == [(len(section.body), 1)],
             "caller MAP/PDB section contribution is missing or aliased")
    try:
        body = direct_control_flow._read_executable(
            direct_control_flow._normalize_sections(parsed), begin,
            len(section.body), "linked caller")
    except direct_control_flow.DirectControlFlowError as exc:
        raise FinalCallsiteError("caller is not file-backed executable") from exc
    mask = bytearray(len(body))
    for field in section.reloc_fields:
        mask[field:field + 4] = b"\x01" * 4
    _require(all(left == right or mask[index] for index, (left, right)
                 in enumerate(zip(section.body, body))),
             "caller linked PE differs from COFF outside declared REL32 fields")
    call_rva = begin + section.selected_field - 1
    displacement = struct.unpack_from("<i", body, section.selected_field)[0]
    _require(call_rva + 5 + displacement == helper_rva,
             "caller REL32 resolves away from exact selected helper")
    decoded = tuple(Decoder(64, body, ip=begin))
    _require(decoded and all(not item.is_invalid for item in decoded) and
             sum(item.len for item in decoded) == len(body),
             "caller linked bytes are not exactly decodable")
    calls = [item for item in decoded if item.ip == call_rva]
    _require(len(calls) == 1 and calls[0].len == 5 and
             calls[0].mnemonic == Mnemonic.CALL and
             calls[0].flow_control == FlowControl.CALL and
             calls[0].op_count == 1 and
             calls[0].op_kind(0) == OpKind.NEAR_BRANCH64 and
             calls[0].near_branch_target == helper_rva,
             "linked caller E8 is not a decoded selected CALL boundary")
    return call_rva, {"object": section.object_name,
                      "section_index": section.section_index,
                      "primary": section.primary,
                      "status": "retained_direct_call",
                      "caller_rva": begin, "call_rva": call_rva,
                      "section_size": len(body),
                      "section_sha256": _sha(body),
                      "rel32_fields": len(section.reloc_fields)}


def _one_image(capture: Path, source_inputs: ProductSourceInputs,
               selected: dict, replay: dict) -> dict:
    log = replay["stdout"]
    source = inspect_source(source_inputs)
    _require(source.get("source_body_and_abi_verified") is True and
             source.get("symbol") == selected.get("selected"),
             "exact PE/PDB/MAP/COFF helper proof differs from selected input")
    _require(source["source_pe_sha256"] == replay["pe_sha256"] and
             source["source_map_sha256"] == replay["map_sha256"] and
             source["source_pdb_sha256"] == replay["built_pdb_sha256"] and
             source["source_coff_sha256"] == _sha(_capture_regular_file(
                 _capture_root(capture), source_inputs.helper_object.name)),
             "built PE/PDB/MAP/helper differs from replay or captured helper")
    parsed = analyze_pe(str(source_inputs.image))
    executable_sections = direct_control_flow._normalize_sections(parsed)
    _reject_executable_dir64(parsed, executable_sections)
    chosen = (direct_control_flow.SelectedFunctionRange(
        source_inputs.symbol, source["rva"], source["size"]),)
    try:
        coverage = pdb_coverage.prove_pdb_executable_coverage(
            parsed, source_inputs.image, source_inputs.pdb,
            source_inputs.dia_helper, source_inputs.msdia, chosen)
        replay_parsed = analyze_pe(str(replay["replay_pe"]))
        replay_inventory = pdb_function_inventory.run_bound_inventory(
            replay_parsed, replay["replay_pe"], replay["replay_pdb"],
            source_inputs.dia_helper, source_inputs.msdia)
        map_raw = _read(source_inputs.link_map, "caller MAP")
        _require(_sha(map_raw) == source["source_map_sha256"],
                 "caller MAP changed after source proof")
        rows = _strict_map_rows(map_raw)
    except (pdb_coverage.PdbCoverageError,
            pdb_function_inventory.PdbInventoryError) as exc:
        raise FinalCallsiteError("exact PDB/decoded executable or MAP proof failed") from exc
    built_inventory = coverage.inventory
    _require(replay_inventory.image_sha256 == built_inventory.image_sha256 ==
             replay["pe_sha256"] and
             replay_inventory.identity == built_inventory.identity and
             replay_inventory.symbol_count == built_inventory.symbol_count and
             replay_inventory.distinct_ranges == built_inventory.distinct_ranges and
             replay_inventory.supplemental_ranges ==
             built_inventory.supplemental_ranges and
             replay_inventory.range_multiplicities ==
             built_inventory.range_multiplicities and
             replay_inventory.helper_sha256 == built_inventory.helper_sha256 and
             replay_inventory.msdia_sha256 == built_inventory.msdia_sha256 and
             replay_inventory.pdb_sha256 == replay["replay_pdb_sha256"] and
             built_inventory.pdb_sha256 == replay["built_pdb_sha256"],
             "replayed PDB identity or complete function inventory differs")
    _prove_dia_abi(replace(source_inputs, pdb=replay["replay_pdb"]),
                   source["rva"], source["size"],
                   _typed_signature(source_inputs.abi))
    _require_explicit_helper_row(rows, source_inputs.symbol,
                                 parsed.image_base + source["rva"],
                                 source_inputs.helper_object.name)
    helper_marker = (b"(" + source_inputs.symbol.encode("ascii") + b") from " +
                     source_inputs.helper_object.name.encode("ascii"))
    _require(not any(helper_marker in line for line in log.splitlines()),
             "selected helper appears in REF/ICF discard or fold log")
    refs = selected.get("references")
    explicit = selected.get("response_input_hashes")
    _require(type(refs) is list and 1 <= len(refs) <= _MAX_REFERENCES and
             type(explicit) is dict,
             "selected caller inventory is missing or excessive")
    seen: set[tuple[str, int, int]] = set()
    sections: list[_CallerSection] = []
    cache: dict[str, bytes] = {}
    for ref in refs:
        _require(type(ref) is dict and
                 ref.get("classification") == "decoded_call_rel32_zero_addend" and
                 type(ref.get("object")) is str and
                 ref["object"] in explicit and ref["object"].lower().endswith(".obj") and
                 type(ref.get("section_index")) is int and
                 type(ref.get("relocation_field")) is int and
                 ref.get("relocation_kind") == 4,
                 "selected archive extraction or relocation is ambiguous")
        key = (ref["object"], ref["section_index"], ref["relocation_field"])
        _require(key not in seen, "selected caller relocation is duplicated")
        seen.add(key)
        if ref["object"] not in cache:
            cache[ref["object"]] = _capture_regular_file(
                _capture_root(capture), ref["object"])
        raw = cache[ref["object"]]
        _require(_sha(raw) == explicit[ref["object"]],
                 "caller COFF differs from selected input report")
        item = _coff_primary(raw, ref["object"], ref["section_index"],
                             ref["relocation_field"])
        _require(_sha(item.body) == ref["section_sha256"],
                 "caller COFF section differs from selected input report")
        sections.append(item)
    expected: set[int] = set()
    outcomes = []
    for section in sections:
        call, result = _linked_callsite(
            section, rows, coverage, parsed, source["rva"], log)
        if call is not None:
            _require(call not in expected, "two caller sections alias one output call")
            expected.add(call)
        outcomes.append(result)
    edges = [item for item in coverage.direct_flow.direct_transfers
             if item.target_rva == source["rva"]]
    _require(all(item.kind == "call" and item.target_is_selected_entry
                 for item in edges) and
             {item.source_rva for item in edges} == expected and
             len(edges) == len(expected) and expected,
             "decoded final executable has missing, extra or non-CALL selected edge")
    # An E8-looking byte sequence in data/operands can only make this stricter:
    # the raw executable sweep cannot miss a real E8 encoding to this target.
    raw_calls: set[int] = set()
    for executable in executable_sections:
        if not executable.characteristics & direct_control_flow.IMAGE_SCN_MEM_EXECUTE:
            continue
        body = executable.raw
        for offset in range(max(0, len(body) - 4)):
            if body[offset] != 0xE8:
                continue
            ip = executable.rva + offset
            displacement = struct.unpack_from("<i", body, offset + 1)[0]
            if ip + 5 + displacement == source["rva"]:
                raw_calls.add(ip)
    _require(raw_calls == expected,
             "raw executable contains an extra or missing E8 to selected helper")
    _require(coverage.direct_flow.direct_reference_gate_passed and
             not coverage.direct_flow.coverage_gaps,
             "selected final executable coverage is incomplete")
    return {"source_pe_sha256": source["source_pe_sha256"],
            "source_pdb_sha256": source["source_pdb_sha256"],
            "source_map_sha256": source["source_map_sha256"],
            "source_coff_sha256": source["source_coff_sha256"],
            "replayed_map_sha256": replay["map_sha256"],
            "replayed_pdb_sha256": replay["replay_pdb_sha256"],
            "replayed_pdb_identity_and_inventory_equal": True,
            "selected_rva": source["rva"], "selected_size": source["size"],
            "source_relocation_count": len(refs),
            "retained_direct_calls": len(expected),
            "ref_discarded_sections": len({
                (item["object"], item["section_index"])
                for item in outcomes if item["status"] == "ref_discarded"}),
            "discarded_selected_relocations": len(refs) - len(expected),
            "output_call_rvas": sorted(expected),
            "section_outcomes": outcomes,
            "full_decoded_direct_reference_gate_passed": True}


def _final_source_and_replay_pins(source: ProductSourceInputs,
                                  proof: dict, replay: dict,
                                  captured_helper_sha256: str) -> None:
    """Close the post-DIA window for every built and replayed proof input."""
    pins = (
        (source.image, proof["source_pe_sha256"], "built PE"),
        (source.pdb, proof["source_pdb_sha256"], "built PDB"),
        (source.link_map, proof["source_map_sha256"], "built MAP"),
        (source.helper_object, proof["source_coff_sha256"], "built helper COFF"),
        (replay["replay_pe"], replay["pe_sha256"], "replayed PE"),
        (replay["replay_pdb"], replay["replay_pdb_sha256"], "replayed PDB"),
        (replay["replay_map"], replay["map_sha256"], "replayed MAP"),
        (replay["log_path"], replay["log_sha256"], "replayed verbose log"),
    )
    _require(proof["source_pe_sha256"] == replay["pe_sha256"] and
             proof["source_pdb_sha256"] == replay["built_pdb_sha256"] and
             proof["source_map_sha256"] == replay["map_sha256"] and
             proof["source_coff_sha256"] == captured_helper_sha256,
             "final built PE/PDB/MAP/helper provenance differs")
    for path, expected, label in pins:
        _require(_sha(_read(path, "final " + label)) == expected,
                 label + " changed during callsite proof")


def inspect_final_callsite_pair(inputs: FinalCallsiteInputs) -> dict:
    """Prove only selected direct-callsite output equivalence, never admission.

    The two verbose replays are fresh child processes from exact copied capture
    bytes. Their raw PE output must match the separately PDB/MAP/COFF-proven
    built images. Logs are used only for exact selected COMDAT discard evidence;
    unrelated ICF representative/order differences are not normalized away.
    """
    _require(type(inputs) is FinalCallsiteInputs and
             type(inputs.original_source) is ProductSourceInputs and
             type(inputs.replacement_source) is ProductSourceInputs,
             "exact final callsite input contract required")
    _require(inputs.original_source.symbol == inputs.replacement_source.symbol and
             inputs.original_source.abi == inputs.replacement_source.abi and
             inputs.original_source.image.name == inputs.replacement_source.image.name,
             "original/replacement helper or target differs")
    link, link_sha = _validated_linker(inputs.link_exe)
    _validated_replay_parent(inputs.replay_parent, (
        _capture_root(inputs.original_capture),
        _capture_root(inputs.replacement_capture),
        *(path.parent for source in (inputs.original_source,
                                     inputs.replacement_source)
          for path in (source.image, source.pdb, source.link_map,
                       source.helper_object)),
    ))
    try:
        pair = inspect_response_pair(
            inputs.original_capture, inputs.replacement_capture,
            inputs.original_source)
        selected = inspect_selected_capture(
            inputs.original_capture, inputs.original_source)
        before = inspect_capture_inputs(inputs.original_capture)
        after = inspect_capture_inputs(inputs.replacement_capture)
    except (ResponsePairError, SelectedReferenceError,
            CaptureDiagnosticError) as exc:
        raise FinalCallsiteError("captured source/reference/response prerequisite failed") from exc
    _require(pair.get("status") == "captured_response_and_inputs_paired" and
             pair.get("selected_input_references_classified") is True and
             pair.get("original_helper_object_omission_proven") is True and
             pair.get("all_nonhelper_input_hashes_equal") is True and
             pair.get("captured_implicit_libraries_equal") is True and
             pair.get("environment_equal_except_bound_capture_local_paths") is True,
             "complete captured input/environment parity is not established")
    _require(selected.get("capture_rsp_sha256") == before.get("link_rsp_sha256") and
             pair.get("original_rsp_sha256") == before.get("link_rsp_sha256") and
             pair.get("replacement_rsp_sha256") == after.get("link_rsp_sha256") and
             selected.get("source_pe_sha256") == _sha(_read(
                 inputs.original_source.image, "original PE")),
             "source/capture provenance differs")
    helper = selected.get("helper_object")
    _require(type(helper) is str and
             inputs.original_source.helper_object.name == helper and
             inputs.replacement_source.helper_object.name == helper and
             _sha(_read(inputs.original_source.helper_object, "original helper COFF")) ==
             selected.get("source_coff_sha256") and
             _sha(_read(inputs.replacement_source.helper_object, "replacement helper COFF")) ==
             after.get("capture_file_sha256", {}).get(helper) and
             inputs.original_source.pdb.name == inputs.original_source.image.stem + ".pdb" and
             inputs.replacement_source.pdb.name == inputs.replacement_source.image.stem + ".pdb" and
             inputs.original_source.link_map.name == inputs.original_source.image.stem + ".map" and
             inputs.replacement_source.link_map.name == inputs.replacement_source.image.stem + ".map",
             "built helper or sidecar name differs from exact captured output")
    replacement_item = [item for item in after.get("inputs", ())
                        if item.get("identity") == helper]
    _require(len(replacement_item) == 1 and
             not _scan_object(helper,
                              _capture_regular_file(_capture_root(inputs.replacement_capture),
                                                    helper),
                              replacement_item[0]["kind"],
                              inputs.original_source.symbol,
                              helper_name=helper)["references"],
             "replacement helper contains unaccounted selected relocations")
    _required_response(before, inputs.original_source.image.name)
    _required_response(after, inputs.replacement_source.image.name)
    _reject_archive_caller_label_aliases(before, selected)
    _reject_archive_caller_label_aliases(after, selected)
    original_replay = _copy_and_replay(
        inputs.original_capture, before, inputs.original_source,
        inputs.replay_parent, "original", link)
    replacement_replay = _copy_and_replay(
        inputs.replacement_capture, after, inputs.replacement_source,
        inputs.replay_parent, "replacement", link)
    old = _one_image(inputs.original_capture, inputs.original_source,
                     selected, original_replay)
    new = _one_image(inputs.replacement_capture, inputs.replacement_source,
                     selected, replacement_replay)
    _require(old["source_relocation_count"] == new["source_relocation_count"] and
             old["retained_direct_calls"] == new["retained_direct_calls"] and
             old["ref_discarded_sections"] == new["ref_discarded_sections"] and
             [(item["object"], item["section_index"], item["primary"], item["status"])
              for item in old["section_outcomes"]] ==
             [(item["object"], item["section_index"], item["primary"], item["status"])
              for item in new["section_outcomes"]],
             "selected source sections changed final-link disposition")
    _require(_sha(_read(inputs.link_exe, "link.exe", _MAX_TOOL)) == link_sha and
             all(original_replay["environment"][name] ==
                 replacement_replay["environment"][name]
                 for name in ("cmd_exe_sha256", "taskkill_exe_sha256",
                              "rc_exe_sha256", "mt_exe_sha256")),
             "linker or SDK tool changed during pair replay")
    _final_source_and_replay_pins(inputs.original_source, old, original_replay,
                                  selected["source_coff_sha256"])
    _final_source_and_replay_pins(inputs.replacement_source, new,
                                  replacement_replay,
                                  after["capture_file_sha256"][helper])
    return {"schema": 1,
            "status": "selected_final_direct_callsites_equivalent",
            "selected": inputs.original_source.symbol,
            "original": old, "replacement": new,
            "original_verbose_replay_pe_sha256": original_replay["pe_sha256"],
            "replacement_verbose_replay_pe_sha256": replacement_replay["pe_sha256"],
            "original_verbose_log_sha256": original_replay["log_sha256"],
            "replacement_verbose_log_sha256": replacement_replay["log_sha256"],
            "original_replay_environment": original_replay["environment"],
            "replacement_replay_environment": replacement_replay["environment"],
            "link_exe_sha256": link_sha,
            "direct_absolute_linker_replay": True,
            "bounded_direct_linker_stdout_stderr_and_pe_reads": True,
            "bounded_material_replay_environment_projection": True,
            "replay_environment_semantics_identical_to_capture": False,
            "replayed_map_bytes_equal_built": True,
            "replayed_pdb_inventory_equal_built": True,
            "captured_response_and_inputs_paired": True,
            "all_selected_input_relocations_accounted": True,
            "selected_direct_source_output_equivalence_proven": True,
            "selected_archive_reference_ambiguity_rejected": True,
            "selected_icf_alias_ambiguity_rejected": True,
            "full_archive_extraction_proven": False,
            "global_source_output_reference_equivalence_proven": False,
            "indirect_target_closure_proven": False,
            "xfg_enforcement_proven": False,
            "production_admitted": False}


__all__ = ["FinalCallsiteError", "FinalCallsiteInputs", "inspect_final_callsite_pair"]
