"""Fresh, consumed raw runtime compilation for the synthetic fixture profile.

Operator-provided tool/header pins are trust inputs, never build certificates.
An active factory-owned capsule is required: build, LINK, then independently
compile again at the same logical paths. No timestamp/debug/path normalization
or externally supplied execution receipt participates in the proof.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import struct
import sys
import threading

from . import source_link_build
from .source_link_product_admission import (
    ProductSourceProofError, _reject_reparse_components,
)


class RuntimeCompileError(ValueError):
    """An unsupported profile, lifecycle, compilation or raw comparison."""


@dataclass(frozen=True)
class RuntimeFilePin:
    path: Path
    sha256: str


@dataclass(frozen=True)
class RuntimeCompileInputs:
    capsule: Path
    tool_directory: Path
    include_roots: tuple[Path, ...]
    tool_files: tuple[RuntimeFilePin, ...]
    external_headers: tuple[RuntimeFilePin, ...]
    # Four ordered rows; project names are maintained source-relative paths.
    # External names are absolute paths. Repeated includes remain repeated.
    ordered_includes: tuple[tuple[str, tuple[str, ...]], ...]
    profile: str = "msvc-14.44.35207-sdk-10.0.26100.0-raw-v2"
    # Separate from the complete compiler-directory inventory. This closed
    # profile has one observed external native dependency, not a trusted tree.
    support_files: tuple[RuntimeFilePin, ...] = ()
    # Explicit observed native tool dependency; never a NativeImages tree waiver.
    native_image_pins: tuple[RuntimeFilePin, ...] = ()
    # Separate exact framework NI role; never a NativeImages tree waiver.
    framework_native_image_pins: tuple[RuntimeFilePin, ...] = ()


@dataclass(frozen=True)
class _RuntimeCompileSession:
    """Opaque handle. Mutable authoritative state is not exposed on this object."""


_ACTIVE: dict[int, tuple[_RuntimeCompileSession, "_State"]] = {}
_SOURCE = Path(__file__).resolve().parents[1]
_PROFILE = "msvc-14.44.35207-sdk-10.0.26100.0-raw-v2"
_PROFILE_V3 = "msvc-14.44.35207-sdk-10.0.26100.0-raw-v3"
_PROFILE_V4 = "msvc-14.44.35207-sdk-10.0.26100.0-raw-v4"
_PROFILE_V5 = "msvc-14.44.35207-sdk-10.0.26100.0-raw-v5"
_SETUP_SUPPORT = Path(r"C:\ProgramData\Microsoft\VisualStudio\Setup\x64\Microsoft.VisualStudio.Setup.Configuration.Native.dll")
_ROLES = (
    ("daedalus_vm", ".c"), ("crypto", ".c"), ("bytecode_pages", ".c"),
    ("key_scatter", ".c"), ("daedalus_x64_thunk", ".asm"),
    ("daedalus_store128", ".asm"), ("daedalus_call_frame", ".asm"),
    ("daedalus_trampoline", ".asm"),
)
_CFLAGS = ("/nologo", "/c", "/O2", "/GL-", "/Z7", "/Gy", "/Gw",
           "/GS", "/MD", "/guard:cf", "/guard:xfg", "/ZH:SHA_256",
           "/DDVM_PAGED_RUNTIME", "/Brepro")
_AFLAGS = ("/nologo", "/c", "/Zi", "/Brepro")
_PATH = re.compile(r"[A-Za-z]:\\(?:[A-Za-z0-9_. ()-]+\\)*[A-Za-z0-9_. ()-]+\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_MAX_FILE = 16 * 1024 * 1024
_TMP_MARKER = re.compile(r"\{[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}\}\Z")
# Observed exact option record emitted during this fixed MSVC profile. This is
# a quiescent same-job association, not file-writer or transient-I/O tracing.
_TMP_MARKER_SHA256 = "5022255dd7e5fe534a180ae25ce6edeb2ad6af125e16cbb5b2b548f16ca1bc74"


def _require(value, reason):
    if not value:
        raise RuntimeCompileError(reason)


def _key(path):
    return os.path.normcase(str(path))


def _path(value, label):
    _require(type(value) is type(Path()), f"{label} requires an exact native Path")
    text = str(value)
    _require(value.is_absolute() and len(text) <= 240 and
             _PATH.fullmatch(text) is not None and text == os.path.normpath(text)
             and all(p not in (".", "..") and not p.endswith((" ", "."))
                     for p in value.parts[1:]), f"{label} is not canonical")
    return value


def _string_path(value, label):
    _require(type(value) is str, f"{label} requires a string")
    path = _path(Path(value), label)
    _require(str(path) == value, f"{label} has noncanonical original spelling")
    return path


def _pins(value, label, maximum):
    _require(type(value) is tuple and 1 <= len(value) <= maximum,
             f"{label} requires a bounded tuple")
    paths = set()
    for pin in value:
        _require(type(pin) is RuntimeFilePin and type(pin.sha256) is str and
                 _HEX.fullmatch(pin.sha256) is not None,
                 f"{label} contains an invalid pin")
        _path(pin.path, label)
        _require(_key(pin.path) not in paths, f"{label} has duplicate/case-alias paths")
        paths.add(_key(pin.path))


def _native_image_path(path):
    from .runtime_compiler_trace import _native_image_path as validate, CompilerTraceError
    try:
        return validate(path)
    except CompilerTraceError as exc:
        raise RuntimeCompileError(str(exc)) from exc


def _framework_native_image_path(path):
    from .runtime_compiler_trace import _framework_native_image_path as validate, CompilerTraceError
    try:
        return validate(path)
    except CompilerTraceError as exc:
        raise RuntimeCompileError(str(exc)) from exc


def _framework_native_image_pins(value, *, profile):
    _require(type(profile) is str and profile == _PROFILE_V5,
             "unsupported framework native-image profile")
    _require(type(value) is tuple and len(value) == 1,
             "v5 requires exactly one explicit framework native-image pin")
    pin = value[0]
    _require(type(pin) is RuntimeFilePin and type(pin.sha256) is str and
             _HEX.fullmatch(pin.sha256) is not None,
             "invalid framework native-image pin")
    _framework_native_image_path(pin.path)


def _native_image_pins(value, *, profile=_PROFILE_V3):
    _require(type(profile) is str and profile in (_PROFILE_V3, _PROFILE_V4, _PROFILE_V5),
             "unsupported native-image profile")
    count = 1 if profile == _PROFILE_V3 else 2
    _require(type(value) is tuple and len(value) == count,
             "v3 requires one explicit native-image pin" if profile == _PROFILE_V3
             else "v4/v5 requires exactly two explicit native-image pins")
    families = set()
    for pin in value:
        _require(type(pin) is RuntimeFilePin and type(pin.sha256) is str and
                 _HEX.fullmatch(pin.sha256) is not None, "invalid native-image pin")
        _native_image_path(pin.path)
        name = pin.path.name.casefold()
        _require(name not in families, "duplicate/ambiguous native-image family")
        families.add(name)
    expected = {"microsoft.visualstudio.remotecontrol.ni.dll"}
    if profile in (_PROFILE_V4, _PROFILE_V5):
        expected.add("newtonsoft.json.ni.dll")
    _require(families == expected, "native-image families differ from explicit profile")


def validate_runtime_compile_inputs(inputs):
    """Pure shape/path preflight, before any capsule or child is created."""
    _require(type(inputs) is RuntimeCompileInputs and type(inputs.profile) is str
             and inputs.profile in (_PROFILE, _PROFILE_V3, _PROFILE_V4, _PROFILE_V5), "exact supported RuntimeCompileInputs required")
    _path(inputs.capsule, "capsule")
    tool = _path(inputs.tool_directory, "compiler directory")
    suffix = tuple(p.casefold() for p in tool.parts[-7:])
    _require(suffix == ("vc", "tools", "msvc", "14.44.35207",
                        "bin", "hostx64", "x64") and
             tool.parents[6].name.casefold() in
             ("community", "professional", "enterprise", "buildtools") and
             tool.parents[7].name == "2022" and
             tool.parents[8].name.casefold() == "microsoft visual studio" and
             tool.parents[9] == Path(r"C:\Program Files"),
             "unreviewed compiler directory/profile")
    sdk = Path(r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0")
    expected = (tool.parents[2] / "include", *(sdk / n for n in
                ("ucrt", "shared", "um", "winrt", "cppwinrt")))
    _require(type(inputs.include_roots) is tuple and
             len(inputs.include_roots) == len(expected), "exact ordered INCLUDE roots required")
    for path, want in zip(inputs.include_roots, expected):
        _path(path, "INCLUDE root")
        _require(path == want, "unreviewed INCLUDE root/order")
    _pins(inputs.tool_files, "compiler files", 128)
    _require(all(p.path.is_relative_to(tool) for p in inputs.tool_files),
             "compiler pin escapes compiler directory")
    _require({tool / "cl.exe", tool / "ml64.exe", tool / "vctip.exe"} <=
             {p.path for p in inputs.tool_files}, "compiler driver/helper pins missing")
    _pins(inputs.support_files, "Setup support files", 1)
    _require(len(inputs.support_files) == 1 and
             inputs.support_files[0].path == _SETUP_SUPPORT,
             "exact external Setup support file required")
    _require(type(inputs.native_image_pins) is tuple, "native-image pins require exact tuple")
    _require(type(inputs.framework_native_image_pins) is tuple,
             "framework native-image pins require exact tuple")
    if inputs.profile == _PROFILE:
        _require(not inputs.native_image_pins and not inputs.framework_native_image_pins,
                 "v2 does not admit native-image pins")
    else:
        _native_image_pins(inputs.native_image_pins, profile=inputs.profile)
        if inputs.profile == _PROFILE_V5:
            _framework_native_image_pins(inputs.framework_native_image_pins, profile=inputs.profile)
        else:
            _require(not inputs.framework_native_image_pins,
                     "framework native-image pins require exact v5 profile")
        _require(tool / "Microsoft.VisualStudio.RemoteControl.dll" in
                 {p.path for p in inputs.tool_files}, "v3 requires RemoteControl IL tool pin")
        if inputs.profile in (_PROFILE_V4, _PROFILE_V5):
            _require(tool / "Newtonsoft.Json.dll" in {p.path for p in inputs.tool_files},
                     "v4/v5 requires exact Newtonsoft IL tool pin")
    _pins(inputs.external_headers, "external headers", 1024)
    _require(all(any(p.path.is_relative_to(root) for root in expected)
                 for p in inputs.external_headers), "external header escapes INCLUDE roots")
    rows = inputs.ordered_includes
    _require(type(rows) is tuple and len(rows) == 4, "exact four ordered C include rows required")
    external = {_key(p.path) for p in inputs.external_headers}
    used = set()
    for row, (role, _) in zip(rows, _ROLES[:4]):
        _require(type(row) is tuple and len(row) == 2 and
                 type(row[0]) is str and row[0] == role and
                 type(row[1]) is tuple and 1 <= len(row[1]) <= 1000,
                 "C include role/order/type differs")
        for name in row[1]:
            _require(type(name) is str and 1 <= len(name) <= 240,
                     "invalid ordered include name")
            if name.startswith("stub/src/"):
                _require(re.fullmatch(r"stub/src/[A-Za-z0-9_]+\.(?:h|inc)", name) is not None,
                         "invalid project include path")
            else:
                path = _string_path(name, "resolved include")
                _require(_key(path) in external, "resolved include is not pinned")
                used.add(_key(path))
    _require(used == external, "unused or missing external header pins")


def _ordinary(path, label, *, directory=False, allow_empty=False):
    try:
        _reject_reparse_components(path)
        st = path.stat()
        _require(path.is_dir() if directory else path.is_file(),
                 f"{label} has wrong file kind")
        if not directory:
            _require(st.st_nlink == 1 and (0 if allow_empty else 1) <= st.st_size <= _MAX_FILE,
                     f"{label} is linked/empty/excessive")
        return st
    except (OSError, ProductSourceProofError) as exc:
        raise RuntimeCompileError(f"{label} is missing or redirected") from exc


def _ordinary_native_image(path):
    _native_image_path(path)
    return _ordinary(path, "native-image pin")


def _ordinary_framework_native_image(path):
    _framework_native_image_path(path)
    return _ordinary(path, "framework native-image pin")


def _native_identity(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_nlink,
            getattr(st, "st_file_attributes", 0))


def _read(path, label, *, allow_empty=False):
    before = _ordinary(path, label, allow_empty=allow_empty)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RuntimeCompileError(f"{label} cannot be read") from exc
    after = _ordinary(path, label, allow_empty=allow_empty)
    _require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and
             len(raw) == before.st_size, f"{label} changed during read")
    return raw


def _sha(raw):
    return sha256(raw).hexdigest()


def _tool_inventory(root):
    """Bound the complete reviewed compiler directory, including resources."""
    pending, files, directories = [root], set(), 0
    while pending:
        directory = pending.pop()
        _ordinary(directory, "compiler subdirectory", directory=True)
        directories += 1
        _require(directories <= 64 and len(directory.relative_to(root).parts) <= 4,
                 "compiler directory traversal exceeds profile")
        for path in directory.iterdir():
            try:
                _reject_reparse_components(path)
                if path.is_dir():
                    pending.append(path)
                else:
                    _ordinary(path, "compiler file")
                    files.add(path)
                    _require(len(files) <= 256, "compiler file inventory exceeds bound")
            except (OSError, ProductSourceProofError) as exc:
                raise RuntimeCompileError("compiler inventory is missing or redirected") from exc
    return files


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate dependency JSON key")
        result[key] = value
    return result


def _validate_report(raw, source, expected, bound):
    _require(type(raw) is bytes and 1 <= len(raw) <= 256 * 1024,
             "dependency report size/type")
    try:
        obj = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RuntimeCompileError("malformed dependency JSON") from exc
    _require(type(obj) is dict and set(obj) == {"Version", "Data"} and
             obj["Version"] == "1.2", "unsupported dependency schema")
    data = obj["Data"]
    _require(type(data) is dict and set(data) == {"Source", "ProvidedModule", "Includes"}
             and type(data["ProvidedModule"]) is str and data["ProvidedModule"] == "",
             "unsupported module/PCH/header-unit dependency")
    _require(type(data["Source"]) is str and type(data["Includes"]) is list and
             len(data["Includes"]) == len(expected), "dependency source/include shape")
    actual = [_string_path(data["Source"], "dependency source")]
    for name in data["Includes"]:
        _require(type(name) is str, "dependency path type")
        actual.append(_string_path(name, "dependency include"))
    for path, want in zip(actual, (source, *expected)):
        _require(_key(path) == _key(want) and path.samefile(want),
                 "ordered dependency identity differs")
        _require(_key(path) in bound and _sha(_read(path, "resolved dependency")) ==
                 bound[_key(path)], "unbound or changed dependency bytes")
    return {"report_sha256": _sha(raw), "ordered_include_count": len(expected),
            "source": str(source), "ordered_includes": [str(p) for p in expected]}


class _State:
    def __init__(self, inputs):
        # Frozen dataclasses still expose __dict__. Never retain caller-owned
        # record containers as authoritative mutable session configuration.
        self.inputs = RuntimeCompileInputs(
            Path(str(inputs.capsule)), Path(str(inputs.tool_directory)),
            tuple(Path(str(p)) for p in inputs.include_roots),
            tuple(RuntimeFilePin(Path(str(p.path)), p.sha256) for p in inputs.tool_files),
            tuple(RuntimeFilePin(Path(str(p.path)), p.sha256) for p in inputs.external_headers),
            tuple((role, tuple(name for name in names)) for role, names in inputs.ordered_includes),
            inputs.profile,
            tuple(RuntimeFilePin(Path(str(p.path)), p.sha256) for p in inputs.support_files),
            tuple(RuntimeFilePin(Path(str(p.path)), p.sha256) for p in inputs.native_image_pins),
            tuple(RuntimeFilePin(Path(str(p.path)), p.sha256) for p in inputs.framework_native_image_pins))
        self.stack = ExitStack()
        self.known = None
        self.runs = []
        self.exports = {}
        self.built = False
        self.closed = False
        self.failed = False
        self.source_pins = {}
        self.native_locks = {}
        self.framework_native_locks = {}
        self.directories = {}
        self.logs = {}
        self.temporary = {}
        self.owner_thread = threading.get_ident()

    def _lock(self, path, digest=None, *, lease=False, native_image=False,
              framework_native_image=False):
        """Hold a Windows no-write/no-delete file handle until session closes."""
        import ctypes
        from ctypes import wintypes
        import msvcrt
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        _require(type(native_image) is bool and type(framework_native_image) is bool and
                 not (lease and (native_image or framework_native_image)) and
                 not (native_image and framework_native_image), "invalid native-image lock mode")
        if native_image:
            ordinary = lambda: _ordinary_native_image(path)
        elif framework_native_image:
            ordinary = lambda: _ordinary_framework_native_image(path)
        else:
            ordinary = lambda: _ordinary(path, "locked input")
        if not lease:
            ordinary()
        handle = kernel.CreateFileW(str(path), 0xC0000000 if lease else 0x80000000,
                                    0 if lease else 1, None, 1 if lease else 3, 0x80, None)
        _require(handle not in (None, ctypes.c_void_p(-1).value), "input lock/capsule lease failed")
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except Exception:
            kernel.CloseHandle(handle)
            raise
        stream = self.stack.enter_context(os.fdopen(fd, "rb"))
        if not lease:
            st = os.fstat(stream.fileno())
            current = ordinary()
            _require((st.st_dev, st.st_ino) == (current.st_dev, current.st_ino),
                     "locked input identity differs")
            raw = stream.read(_MAX_FILE + 1)
            _require(len(raw) == st.st_size and len(raw) <= _MAX_FILE and
                     (digest is None or _sha(raw) == digest), "locked input hash differs")
            stream.seek(0)
            if native_image or framework_native_image:
                _require(_native_identity(st) == _native_identity(current),
                         "native-image locked metadata differs")
                locks = self.framework_native_locks if framework_native_image else self.native_locks
                _require(path not in locks, "duplicate native-image lock")
                locks[path] = (stream, _native_identity(st), digest)
            return raw
        return b""

    def prepare(self):
        validate_runtime_compile_inputs(self.inputs)
        _require(os.name == "nt", "reviewed Windows compiler profile required")
        w, t = self.inputs.capsule, self.inputs.tool_directory
        _ordinary(w.parent, "capsule parent", directory=True)
        _require(not w.exists() and not w.is_symlink() and
                 not w.is_relative_to(_SOURCE) and not _SOURCE.is_relative_to(w),
                 "capsule occupied or overlaps executing source")
        _ordinary(t, "compiler directory", directory=True)
        for root in self.inputs.include_roots:
            _ordinary(root, "INCLUDE root", directory=True)
        pins = {p.path for p in self.inputs.tool_files}
        _require(_tool_inventory(t) == pins,
                 "complete compiler directory differs from pinned inventory")
        self.source_pins = source_link_build._source_tree_hashes(_SOURCE, runtime=True)
        for _, names in self.inputs.ordered_includes:
            _require(all(not n.startswith("stub/src/") or n in self.source_pins
                         for n in names), "unmaintained project include")
        # Verify and lock the explicit NI before creating any capsule effects.
        for pin in self.inputs.native_image_pins:
            self._lock(pin.path, pin.sha256, native_image=True)
        for pin in self.inputs.framework_native_image_pins:
            self._lock(pin.path, pin.sha256, framework_native_image=True)
        w.mkdir()
        self._lock(w / ".runtime-compile.lease", lease=True)
        for name in ("stub", "stub/src", "out", "deps", "tmp", "logs"):
            (w / name).mkdir()
        for path in (w, *(w / n for n in ("stub", "stub/src", "out", "deps", "tmp", "logs"))):
            st = _ordinary(path, "owned capsule directory", directory=True)
            self.directories[path] = (st.st_dev, st.st_ino)
        for name, digest in self.source_pins.items():
            src = self._lock(_SOURCE / name, digest)
            dest = w / name
            _require(dest.parent == w / "stub/src", "unsupported runtime source layout")
            with dest.open("xb") as f:
                f.write(src)
            self._lock(dest, digest)
            if dest.suffix.casefold() == ".asm":
                text = src.decode("utf-8-sig").splitlines()
                _require(not any(re.match(r"\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"
                    r"(?:include|includelib|incbin)\b", line.split(";", 1)[0], re.I)
                    for line in text), "assembler external input directive unsupported")
        for pin in (*self.inputs.tool_files, *self.inputs.external_headers, *self.inputs.support_files):
            self._lock(pin.path, pin.sha256)
        self.recheck()

    def recheck(self):
        _require(not self.closed, "closed compiler session")
        _require(not self.failed, "failed compiler session must not be reused")
        self._check_native_images()
        self._check_framework_native_images()
        self._check_directories()
        self._check_temporary_outputs()
        _require(_tool_inventory(self.inputs.tool_directory) ==
                 {p.path for p in self.inputs.tool_files},
                 "compiler directory inventory changed")
        _require(source_link_build._source_tree_hashes(_SOURCE, runtime=True) ==
                 self.source_pins, "executing runtime source inventory changed")
        for name, digest in self.source_pins.items():
            _require(_sha(_read(self.inputs.capsule / name, "runtime snapshot")) == digest,
                     "runtime snapshot changed")
        for pin in (*self.inputs.tool_files, *self.inputs.external_headers, *self.inputs.support_files,
                    *getattr(self.inputs, "framework_native_image_pins", ())):
            _require(_sha(_read(pin.path, "tool/header")) == pin.sha256,
                     "tool/header input changed")

    def _check_native_images(self):
        _require(set(self.native_locks) == {p.path for p in self.inputs.native_image_pins},
                 "native-image held-lock inventory differs")
        for pin in self.inputs.native_image_pins:
            stream, identity, digest = self.native_locks[pin.path]
            current = _ordinary_native_image(pin.path)
            _require(not stream.closed and _native_identity(os.fstat(stream.fileno())) ==
                     identity == _native_identity(current), "native-image held identity drift")
            stream.seek(0)
            raw = stream.read(_MAX_FILE + 1)
            stream.seek(0)
            _require(len(raw) == current.st_size and digest == pin.sha256 and
                     _sha(raw) == digest and _native_identity(os.fstat(stream.fileno())) == identity,
                     "native-image held bytes drift")

    def _check_framework_native_images(self):
        locks = getattr(self, "framework_native_locks", {})
        pins = getattr(self.inputs, "framework_native_image_pins", ())
        _require(set(locks) == {pin.path for pin in pins},
                 "framework native-image held-lock inventory differs")
        for pin in pins:
            stream, identity, digest = locks[pin.path]
            current = _ordinary_framework_native_image(pin.path)
            _require(not stream.closed and _native_identity(os.fstat(stream.fileno())) ==
                     identity == _native_identity(current),
                     "framework native-image held identity drift")
            stream.seek(0)
            raw = stream.read(_MAX_FILE + 1)
            stream.seek(0)
            _require(len(raw) == current.st_size and digest == pin.sha256 and
                     _sha(raw) == digest and _native_identity(os.fstat(stream.fileno())) == identity,
                     "framework native-image held bytes drift")

    def _check_directories(self):
        w = self.inputs.capsule
        for path, identity in self.directories.items():
            st = _ordinary(path, "owned capsule directory", directory=True)
            _require((st.st_dev, st.st_ino) == identity, "owned capsule directory replaced")
        _require({p.name for p in w.iterdir()} ==
                 {".runtime-compile.lease", "stub", "out", "deps", "tmp", "logs"} and
                 {p.name for p in (w / "stub").iterdir()} == {"src"},
                 "capsule contains unsupported root inputs")
        _require({p.relative_to(w).as_posix() for p in (w / "stub/src").iterdir()} ==
                 set(self.source_pins), "runtime snapshot inventory changed")
        _require({p.name for p in (w / "logs").iterdir()} == set(self.logs),
                 "compiler log inventory changed")
        for name, digest in self.logs.items():
            _require(_sha(_read(w / "logs" / name, "retained compiler log", allow_empty=True))
                     == digest, "retained compiler log changed")

    def _log(self, name, raw):
        self._check_directories()
        path = self.inputs.capsule / "logs" / name
        _require(type(raw) is bytes and not path.exists(), "compiler log target occupied")
        with path.open("xb") as stream:
            stream.write(raw)
        self.logs[name] = _sha(raw)

    def _temporary_descriptor(self, path):
        before = _ordinary(path, "owned temporary output")
        raw = _read(path, "owned temporary output")
        after = _ordinary(path, "owned temporary output")
        fields = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_nlink)
        _require(fields(before) == fields(after), "temporary output changed during capture")
        return raw, {"device": after.st_dev, "inode": after.st_ino,
                     "size": after.st_size, "mtime_ns": after.st_mtime_ns,
                     "links": after.st_nlink, "sha256": _sha(raw)}

    def _check_temporary_outputs(self, expected=None):
        w = self.inputs.capsule
        expected = self.temporary if expected is None else expected
        _require({p.name for p in (w / "tmp").iterdir()} == set(expected),
                 "unknown/missing temporary output")
        for name, descriptor in expected.items():
            _, actual = self._temporary_descriptor(w / "tmp" / name)
            _require(actual == descriptor, "known temporary output changed/replaced")

    def _clear_temporary_outputs(self):
        self._check_directories()
        # All names, physical identities and raw hashes are checked before the
        # first unlink. No unknown path, directory or recursive tree is deleted.
        self._check_temporary_outputs()
        for name in self.temporary:
            (self.inputs.capsule / "tmp" / name).unlink()
        self.temporary = {}

    def _temporary_helper_associations(self, result):
        expected = self.inputs.tool_directory / "vctip.exe"
        digest = next(p.sha256 for p in self.inputs.tool_files if p.path == expected)
        processes = {p["pid"]: p for p in result.processes}
        creates = {e["pid"]: e for e in result.trace_events if e.get("event") == 3}
        associations = []
        for pid, process in processes.items():
            if process["parent_pid"] not in processes:
                continue
            image = creates.get(pid, {}).get("image", {})
            if image.get("path") != str(expected):
                continue
            st = _ordinary(expected, "temporary helper pin")
            _require(image.get("classification") == "pinned_compiler_module" and
                     image.get("pid") == pid and image.get("sha256") == digest and
                     type(image.get("volume")) is int and image["volume"] > 0 and
                     image.get("index") == st.st_ino and image.get("size") == st.st_size and
                     process["exit_code"] == 0 and process["exit_continued"] is True and
                     process["wait_terminal"] is True,
                     "temporary helper CREATE/physical pin/terminal record differs")
            associations.append({"pid": pid, "parent_pid": process["parent_pid"],
                                 "image": dict(image)})
        return associations

    def _capture_temporary_outputs(self, label, result):
        self._check_directories()
        _require(self.temporary == {}, "previous temporary outputs not cleared")
        paths = tuple((self.inputs.capsule / "tmp").iterdir())
        _require(len(paths) <= 1, "unsupported temporary output count")
        helpers = self._temporary_helper_associations(result) if paths else []
        captured = {}
        payloads = []
        for path in paths:
            _require(helpers and _TMP_MARKER.fullmatch(path.name) is not None,
                     "temporary output lacks reviewed same-job helper association/name")
            raw, descriptor = self._temporary_descriptor(path)
            _require(len(raw) == 79 and descriptor["sha256"] == _TMP_MARKER_SHA256,
                     "unsupported temporary output bytes")
            captured[path.name] = descriptor
            payloads.append(raw)
        # Capture every byte and its identity before authorizing future cleanup.
        for index, raw in enumerate(payloads):
            self._log(label + f".tmp-{index}.bin", raw)
        observation = {"outputs": captured, "helper_associations": helpers,
                       "scope": "quiescent_same_job_interval_only",
                       "file_writer_attribution_proven": False,
                       "transient_file_IO_closure_proven": False}
        self._log(label + ".tmp.json", (json.dumps(observation, indent=2) + "\n").encode("utf8"))
        # A failure at the final check must not enroll even a formerly matching
        # descriptor. Commit the staged authority only after every check passes.
        self._check_temporary_outputs(captured)
        self.temporary = captured
        return observation

    def environment(self):
        w, t = self.inputs.capsule, self.inputs.tool_directory
        return {"SystemRoot": r"C:\Windows", "WINDIR": r"C:\Windows",
                "PATH": str(t) + r";C:\Windows\System32;C:\Windows",
                "TEMP": str(w / "tmp"), "TMP": str(w / "tmp"),
                "INCLUDE": ";".join(map(str, self.inputs.include_roots)),
                "VSLANG": "1033", "PROCESSOR_ARCHITECTURE": "AMD64",
                "NUMBER_OF_PROCESSORS": "16"}

    def _replace_known_outputs(self):
        self._check_directories()
        self._check_temporary_outputs()
        w = self.inputs.capsule
        actual = {p.relative_to(w).as_posix() for directory in ("out", "deps")
                  for p in (w / directory).iterdir()}
        _require(actual == (set() if self.known is None else set(self.known)),
                 "capsule contains unknown/missing outputs")
        if self.known is not None:
            for name, digest in self.known.items():
                _require(_sha(_read(w / name, "known disposable output")) == digest,
                         "known disposable output changed")
            for name in self.known:
                (w / name).unlink()  # Exact preflighted files only; never recursive.
        self.known = None

    def compile(self):
        _require(not self.failed, "failed compiler session must not be reused")
        try:
            return self._compile()
        except BaseException:
            # A caught failure is not authority to retry the same active
            # capsule. Preserve primary diagnostics and all output bytes.
            self.failed = True
            raise

    def _compile(self):
        self.recheck()
        _require(len(self.runs) + 8 <= 64, "compiler session execution budget exhausted")
        self._replace_known_outputs()
        from .runtime_compiler_trace import (
            CompilerTracePolicy, CompilerTraceError, run_traced_compiler,
        )
        policy = CompilerTracePolicy(
            tool_pins=tuple((p.path, p.sha256) for p in self.inputs.tool_files),
            windows_root=Path(r"C:\Windows"),
            # Observed MSVC tool-graph edge, not arbitrary executable admission.
            # The helper must itself be one of the exact locked compiler pins.
            allowed_child_images=(self.inputs.tool_directory / "vctip.exe",),
            support_pins=tuple((p.path, p.sha256) for p in self.inputs.support_files),
            native_image_pins=tuple((p.path, p.sha256) for p in self.inputs.native_image_pins),
            framework_native_image_pins=tuple((p.path, p.sha256) for p in getattr(self.inputs, "framework_native_image_pins", ())))
        w, t = self.inputs.capsule, self.inputs.tool_directory
        bound = {_key(w / n): h for n, h in self.source_pins.items()}
        bound.update({_key(p.path): p.sha256 for p in self.inputs.external_headers})
        results, raw_objects, reports = [], {}, {}
        for index, (name, suffix) in enumerate(_ROLES):
            # Each compiler starts with no persisted TMP input from a prior
            # role, initial build or later public verification compilation.
            self._clear_temporary_outputs()
            source, output = w / "stub/src" / (name + suffix), w / "out" / (name + ".obj")
            report = w / "deps" / (name + ".json")
            argv = (str(t / ("cl.exe" if suffix == ".c" else "ml64.exe")),
                    *(_CFLAGS if suffix == ".c" else _AFLAGS))
            if suffix == ".c":
                argv += ("/I" + str(w / "stub/src"), "/sourceDependencies", str(report))
            argv += ("/Fo" + str(output), str(source))
            _require(not output.exists() and not report.exists(), "compiler output occupied")
            label = f"{len(self.runs):03d}-{name}"
            try:
                result = run_traced_compiler(argv, w, self.environment(), policy=policy,
                                             timeout=90, max_log=4 * 1024 * 1024)
            except CompilerTraceError as exc:
                self._log(label + ".stdout", exc.stdout)
                self._log(label + ".stderr", exc.stderr)
                self._log(label + ".trace-error.json",
                          (json.dumps(exc.evidence, indent=2) + "\n").encode("utf8"))
                raise RuntimeCompileError(f"compiler trace rejected: {exc}") from exc
            # Raw stdout/stderr are retained, never filtered.
            self._log(label + ".stdout", result.stdout)
            self._log(label + ".stderr", result.stderr)
            record = result.to_record()
            record.update(argv=list(argv), cwd=str(w), environment=self.environment())
            self._log(label + ".json", (json.dumps(record, indent=2) + "\n").encode("utf8"))
            self.runs.append(record)
            _require(result.status == "exited" and result.exit_code == 0 and
                     bool(result.processes) and
                     all(row["exit_code"] == 0 and row["exit_continued"] and row["wait_terminal"]
                         for row in result.processes) and
                     result.stderr == b"" and not re.search(
                        br"\b(?:warning|error|ignoring|unrecognized|unknown option)\b",
                        result.stdout + result.stderr, re.I),
                     "traced compiler failed/warned/exceeded its bounds")
            _require(result.cleanup.get("reaped") is True and
                     result.cleanup.get("job_accounting", {}).get("active_processes") == 0 and
                     result.cleanup["job_accounting"].get("total_processes") == len(result.processes),
                     "temporary capture requires a physically terminal owned Job")
            record["temporary_outputs"] = self._capture_temporary_outputs(label, result)
            raw = _read(output, "fresh raw COFF")
            _require(len(raw) >= 20 and raw[:2] == b"\x64\x86" and
                     20 + 40 * struct.unpack_from("<H", raw, 2)[0] <= len(raw),
                     "fresh output is not supported ordinary AMD64 COFF")
            raw_objects[name + ".obj"] = raw
            if suffix == ".c":
                names = self.inputs.ordered_includes[index][1]
                expected = tuple(w / n if n.startswith("stub/src/") else Path(n) for n in names)
                reports[name] = _validate_report(_read(report, "actual dependency report"),
                                                source, expected, bound)
            self.recheck()
            results.append(record)
        self.known = {p.relative_to(w).as_posix(): _sha(_read(p, "owned output"))
                      for directory in ("out", "deps") for p in (w / directory).iterdir()}
        _require(len(self.known) == 12, "actual output inventory differs")
        return raw_objects, reports, results


def _session_state(session):
    _require(type(session) is _RuntimeCompileSession and
             id(session) in _ACTIVE and _ACTIVE[id(session)][0] is session,
             "active factory-owned runtime compiler session required")
    state = _ACTIVE[id(session)][1]
    _require(threading.get_ident() == state.owner_thread,
             "runtime compiler session used from another thread")
    validate_runtime_compile_inputs(state.inputs)
    _require(not state.closed, "closed runtime compiler session")
    _require(not state.failed, "failed compiler session must not be reused")
    return state


def validate_runtime_compile_session(session):
    """Validate handle identity without exposing mutable authoritative state."""
    _session_state(session)


def require_runtime_compile_ready(session):
    """Reject an active but unbuilt session before public LINK/DIA effects."""
    state = _session_state(session)
    _require(state.built, "initial runtime build is missing")
    state.recheck()


@contextmanager
def runtime_compile_session(inputs: RuntimeCompileInputs):
    """Create an absent owned capsule; hold inputs/lease through final proof."""
    validate_runtime_compile_inputs(inputs)
    state = _State(inputs)
    session = _RuntimeCompileSession()
    try:
        state.prepare()
        _ACTIVE[id(session)] = (session, state)
        yield session
    except (OSError, ProductSourceProofError, source_link_build.SourceLinkError) as exc:
        raise RuntimeCompileError(f"runtime compiler session failed: {exc}") from exc
    finally:
        _ACTIVE.pop(id(session), None)
        state.closed = True
        primary = sys.exc_info()[1]
        try:
            state.stack.close()
        except OSError as exc:
            if primary is not None:
                primary.add_note(f"runtime input/lease release also failed: {exc}")
            else:
                raise RuntimeCompileError("runtime input/lease release failed") from exc


def build_runtime_objects(session, output_dir: Path) -> tuple[Path, ...]:
    """Build the initial runtime8, exporting copies distinct from disposable slots."""
    state = _session_state(session)
    _require(not state.built, "runtime objects already built in this session")
    out = _path(output_dir, "export directory")
    _ordinary(out.parent, "export parent", directory=True)
    _require(not out.exists() and not out.is_symlink() and
             not out.is_relative_to(state.inputs.capsule) and
             not state.inputs.capsule.is_relative_to(out) and
             not out.is_relative_to(_SOURCE) and not _SOURCE.is_relative_to(out),
             "export directory occupied or overlaps source/capsule")
    objects, _, _ = state.compile()
    _ordinary(out.parent, "export parent", directory=True)
    _require(not out.exists() and not out.is_symlink(), "export directory became occupied")
    out.mkdir()
    paths = []
    for name, raw in objects.items():
        path = out / name
        with path.open("xb") as stream:
            stream.write(raw)
        state._lock(path, _sha(raw))
        state.exports[_key(path)] = _sha(raw)
        paths.append(path)
    state.built = True
    return tuple(paths)


def prove_runtime_coff_compilation(session, generated_inputs, capture_dir):
    """Execute fresh runtime8 now, then consume whole-byte supplied/captured matches."""
    state = _session_state(session)
    _require(state.built, "initial runtime build is missing")
    _require(type(generated_inputs) is tuple and len(generated_inputs) == 11 and
             all(type(p) is type(Path()) for p in generated_inputs),
             "exact eleven generated inputs required")
    _path(capture_dir, "final capture")
    _ordinary(capture_dir, "final capture", directory=True)
    _require(not capture_dir.is_relative_to(state.inputs.capsule) and
             not state.inputs.capsule.is_relative_to(capture_dir),
             "final capture overlaps disposable capsule")
    names = {name + ".obj" for name, _ in _ROLES}
    selected = {p.name: p for p in generated_inputs if p.name in names}
    _require(set(selected) == names and len({p.name.casefold() for p in generated_inputs}) == 11,
             "runtime generated roles missing/duplicated")
    supplied, captured = {}, {}
    for name, path in selected.items():
        _path(path, "supplied runtime object")
        _require(_key(path) in state.exports, "runtime object not exported by this active build")
        supplied[name] = state._lock(path, state.exports[_key(path)])
        captured[name] = state._lock(capture_dir / name, _sha(supplied[name]))
        _require(supplied[name] == captured[name], "supplied/captured runtime bytes differ")
    fresh, reports, runs = state.compile()
    _require(all(fresh[n] == supplied[n] == captured[n] for n in names),
             "complete raw runtime COFF compilation mismatch")
    state.recheck()
    support = {str(pin.path): pin.sha256 for pin in state.inputs.support_files}
    support_profile = {"profile": state.inputs.profile, "allowed_role": "direct_child_vctip_LOAD_DLL",
                       "support_files": support}
    ni = {str(pin.path): pin.sha256 for pin in state.inputs.native_image_pins}
    il_names = ("Microsoft.VisualStudio.RemoteControl.dll",)
    if state.inputs.profile in (_PROFILE_V4, _PROFILE_V5):
        il_names += ("Newtonsoft.Json.dll",)
    il_paths = {state.inputs.tool_directory / name for name in il_names}
    il = {str(pin.path): pin.sha256 for pin in state.inputs.tool_files
          if pin.path in il_paths}
    ni_profile = {"profile": state.inputs.profile,
                  "allowed_role": "direct_child_vctip_LOAD_DLL_with_active_exact_pinned_IL",
                  "native_image_pins": ni, "required_IL_tool_pin": il}
    result = {"schema": 1, "profile": state.inputs.profile, "scope": "synthetic_runtime8_only",
              "same_logical_path_only": True, "fresh_compiler_invocations": len(runs),
              "raw_equal_roles": sorted(names), "raw_object_sha256": {n: _sha(fresh[n]) for n in names},
              "dependency_reports": reports, "compiler_executions": runs,
              "source_manifest_sha256": dict(state.source_pins),
              "support_file_sha256": support,
              "support_profile_sha256": _sha(json.dumps(support_profile, sort_keys=True,
                  separators=(",", ":"), ensure_ascii=True).encode("ascii")),
              "native_image_sha256": ni,
              "native_image_profile_sha256": _sha(json.dumps(ni_profile, sort_keys=True,
                  separators=(",", ":"), ensure_ascii=True).encode("ascii")),
              "NI_compilation_authenticity_proven": False,
              "IL_native_semantic_equivalence_proven": False,
              "NGEN_dependency_closure_proven": False,
              "JIT_closure_proven": False,
              "trusted_windows_loader_domain": True,
              "trusted_Windows_CLR_GAC_and_JIT_semantics": True,
              "managed_assembly_closure_proven": False,
              "loaded_memory_attestation_proven": False,
              "full_OS_attestation_proven": False,
              "runtime_source_compile_binding_proven": True}
    if state.inputs.profile == _PROFILE_V5:
        framework = {str(pin.path): pin.sha256
                     for pin in state.inputs.framework_native_image_pins}
        framework_profile = {"profile": state.inputs.profile,
            "allowed_role": "direct_child_vctip_LOAD_DLL_with_operator_pinned_framework_NI",
            "framework_native_image_pins": framework}
        result.update({"framework_native_image_sha256": framework,
            "framework_native_image_profile_sha256": _sha(json.dumps(
                framework_profile, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True).encode("ascii")),
            "framework_IL_binding_proven": False,
            "managed_resource_reference_closure_proven": False})
    return result


__all__ = ["RuntimeCompileError", "RuntimeFilePin", "RuntimeCompileInputs",
           "runtime_compile_session", "build_runtime_objects",
           "validate_runtime_compile_inputs", "validate_runtime_compile_session",
           "prove_runtime_coff_compilation"]
