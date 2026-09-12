#!/usr/bin/env python3
"""Venice -- PySide6/QML backend for the Lethe PE packer.

Venice is the branded QML twin of the widgets GUI (``gui/app.py``). Both are
thin wrappers over the single core :func:`packer.orchestrator.pack_file`, so the
two front-ends can never drift. This module exposes three objects to QML:

* :class:`FileListModel` -- a ``QAbstractListModel`` of queued PE files that a
  QML ``ListView`` binds to via custom roles.
* :class:`PackWorker`    -- a ``QThread`` that runs ``pack_file`` for each queued
  job off the UI thread and reports progress/results back through signals.
* :class:`VeniceBackend` -- the ``QObject`` set as the ``"venice"`` context
  property; it owns the model, the options and the worker lifecycle.

The packer core is imported lazily (inside the worker thread) so the GUI can
start -- and the queue can be built -- even while ``packer.orchestrator`` or one
of its sibling builder modules is still landing or missing a dependency.
"""
from __future__ import annotations

import json
import os
import struct
import sys
from typing import List, Optional, Tuple

# --- import bootstrap ------------------------------------------------------
# venice_backend.py lives at gui/venice_backend.py; the
# ``packer`` package sits one directory up (packer). Put
# that parent on sys.path so ``import packer.orchestrator`` resolves both when
# run from source and when frozen.
_GUI_DIR = os.path.dirname(os.path.abspath(__file__))
_PACKER_ROOT = os.path.dirname(_GUI_DIR)  # Lethe
if _PACKER_ROOT not in sys.path:
    sys.path.insert(0, _PACKER_ROOT)

from PySide6.QtCore import (
    Property,
    QAbstractListModel,
    QByteArray,
    QModelIndex,
    QObject,
    Qt,
    QThread,
    QUrl,
    Signal,
    Slot,
)


# ---------------------------------------------------------------------------
# PE header probe (inline -- mirrors the walk the packer core does)
# ---------------------------------------------------------------------------

# COFF IMAGE_FILE_HEADER.Machine -> friendly architecture label.
_MACHINE_MAP = {
    0x8664: "x64",
    0x014C: "x86",
    0xAA64: "ARM64",
}

# IMAGE_FILE_DLL bit in the COFF Characteristics field.
_IMAGE_FILE_DLL = 0x2000


def _detect_pe(path: str) -> Tuple[str, str]:
    """Return ``(file_type, arch)`` read inline from the PE header.

    ``file_type`` is ``"EXE"`` / ``"DLL"`` / ``"?"`` and ``arch`` is
    ``"x64"`` / ``"x86"`` / ``"ARM64"`` / ``"?"``. Anything that is not a valid
    PE (or cannot be read) reports ``("?", "?")``. The walk is DOS ``MZ`` ->
    ``e_lfanew`` -> ``PE\\0\\0`` -> IMAGE_FILE_HEADER, testing IMAGE_FILE_DLL.
    """
    try:
        with open(path, "rb") as fh:
            dos = fh.read(64)
            if len(dos) < 64 or dos[:2] != b"MZ":
                return ("?", "?")
            (e_lfanew,) = struct.unpack_from("<I", dos, 0x3C)
            fh.seek(e_lfanew)
            if fh.read(4) != b"PE\x00\x00":
                return ("?", "?")
            coff = fh.read(20)  # IMAGE_FILE_HEADER
            if len(coff) < 20:
                return ("?", "?")
            (machine,) = struct.unpack_from("<H", coff, 0)
            (characteristics,) = struct.unpack_from("<H", coff, 18)
    except (OSError, struct.error):
        return ("?", "?")
    file_type = "DLL" if (characteristics & _IMAGE_FILE_DLL) else "EXE"
    arch = _MACHINE_MAP.get(machine, "?")
    return (file_type, arch)


def _human_size(n: Optional[int]) -> str:
    """Format a byte count: ``B`` under 1024, then KB/MB/GB/TB at 2 decimals."""
    if n is None:
        return "n/a"
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            return f"{int(size)} B" if unit == "B" else f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"


# ---------------------------------------------------------------------------
# file list model
# ---------------------------------------------------------------------------

class FileListModel(QAbstractListModel):
    """A ``QAbstractListModel`` of queued PE files for a QML ``ListView``.

    Each entry is a plain ``dict`` keyed by the role names below; the custom
    roles let a QML delegate reference ``path``, ``filename``, ``status`` etc.
    directly.
    """

    countChanged = Signal()

    PathRole = Qt.UserRole + 1
    FilenameRole = Qt.UserRole + 2
    FileTypeRole = Qt.UserRole + 3
    ArchRole = Qt.UserRole + 4
    FileSizeRole = Qt.UserRole + 5
    HumanSizeRole = Qt.UserRole + 6
    StatusRole = Qt.UserRole + 7
    StatusTextRole = Qt.UserRole + 8
    RatioRole = Qt.UserRole + 9
    ElapsedRole = Qt.UserRole + 10
    OutputPathRole = Qt.UserRole + 11

    # role int -> dict key / QML role name
    _ROLE_KEYS = {
        PathRole: "path",
        FilenameRole: "filename",
        FileTypeRole: "fileType",
        ArchRole: "arch",
        FileSizeRole: "fileSize",
        HumanSizeRole: "humanSize",
        StatusRole: "status",
        StatusTextRole: "statusText",
        RatioRole: "ratio",
        ElapsedRole: "elapsed",
        OutputPathRole: "outputPath",
    }

    # roles updated together when a file finishes / is reset
    _RESULT_ROLES = [
        StatusRole, StatusTextRole, RatioRole, ElapsedRole, OutputPathRole,
    ]

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._entries: List[dict] = []

    # -- Qt model interface ------------------------------------------------
    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        if parent.isValid():
            return 0
        return len(self._entries)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):  # noqa: N802
        if not index.isValid() or not (0 <= index.row() < len(self._entries)):
            return None
        key = self._ROLE_KEYS.get(role)
        if key is None:
            return None
        return self._entries[index.row()].get(key)

    def roleNames(self):  # noqa: N802
        return {role: QByteArray(key.encode()) for role, key in self._ROLE_KEYS.items()}

    # -- QML-callable slots ------------------------------------------------
    @Slot(list)
    def addFiles(self, paths: list) -> None:
        """Add PE files, deduped by absolute path. Folders contribute their
        ``.exe`` / ``.dll`` children. Each new entry starts ``status="ready"``.
        """
        expanded: List[str] = []
        for raw in paths:
            if raw is None:
                continue
            path = str(raw)
            if os.path.isdir(path):
                try:
                    children = sorted(os.listdir(path))
                except OSError:
                    children = []
                for name in children:
                    if name.lower().endswith((".exe", ".dll")):
                        expanded.append(os.path.join(path, name))
            elif os.path.isfile(path):
                expanded.append(path)

        existing = {entry["path"] for entry in self._entries}
        new_entries: List[dict] = []
        for path in expanded:
            abspath = os.path.abspath(path)
            if abspath in existing:
                continue
            existing.add(abspath)
            new_entries.append(self._make_entry(abspath))

        if not new_entries:
            return
        start = len(self._entries)
        self.beginInsertRows(QModelIndex(), start, start + len(new_entries) - 1)
        self._entries.extend(new_entries)
        self.endInsertRows()
        self.countChanged.emit()

    @Slot(int)
    def removeFile(self, index: int) -> None:
        if not (0 <= index < len(self._entries)):
            return
        self.beginRemoveRows(QModelIndex(), index, index)
        del self._entries[index]
        self.endRemoveRows()
        self.countChanged.emit()

    @Slot()
    def clear(self) -> None:
        if not self._entries:
            return
        self.beginResetModel()
        self._entries = []
        self.endResetModel()
        self.countChanged.emit()

    # -- count property ----------------------------------------------------
    def _get_count(self) -> int:
        return len(self._entries)

    count = Property(int, _get_count, notify=countChanged)

    # -- entry construction / mutation (called on the GUI thread) ----------
    @staticmethod
    def _make_entry(abspath: str) -> dict:
        file_type, arch = _detect_pe(abspath)
        try:
            size = os.path.getsize(abspath)
        except OSError:
            size = 0
        return {
            "path": abspath,
            "filename": os.path.basename(abspath),
            "fileType": file_type,
            "arch": arch,
            "fileSize": size,
            "humanSize": _human_size(size),
            "status": "ready",
            "statusText": "Ready",
            "ratio": 0.0,
            "elapsed": 0,
            "outputPath": "",
        }

    def set_status(self, row: int, status: str, status_text: str) -> None:
        """Update just the status of one row (used when a file starts packing)."""
        if not (0 <= row < len(self._entries)):
            return
        entry = self._entries[row]
        entry["status"] = status
        entry["statusText"] = status_text
        idx = self.index(row, 0)
        self.dataChanged.emit(idx, idx, [self.StatusRole, self.StatusTextRole])

    def set_result(self, row: int, status: str, status_text: str,
                   ratio: float, elapsed: int, output_path: str) -> None:
        """Update the full result of one row (done / error)."""
        if not (0 <= row < len(self._entries)):
            return
        entry = self._entries[row]
        entry["status"] = status
        entry["statusText"] = status_text
        entry["ratio"] = float(ratio)
        entry["elapsed"] = int(elapsed)
        entry["outputPath"] = output_path or ""
        idx = self.index(row, 0)
        self.dataChanged.emit(idx, idx, self._RESULT_ROLES)

    def reset_statuses(self) -> None:
        """Reset every row back to a clean ``"ready"`` state before a run."""
        if not self._entries:
            return
        for entry in self._entries:
            entry["status"] = "ready"
            entry["statusText"] = "Ready"
            entry["ratio"] = 0.0
            entry["elapsed"] = 0
            entry["outputPath"] = ""
        top = self.index(0, 0)
        bottom = self.index(len(self._entries) - 1, 0)
        self.dataChanged.emit(top, bottom, self._RESULT_ROLES)

    # -- read helpers for the backend --------------------------------------
    def jobs(self) -> List[Tuple[int, str]]:
        """Return ``[(row, path), ...]`` for every queued file."""
        return [(i, entry["path"]) for i, entry in enumerate(self._entries)]

    def filename_at(self, row: int) -> str:
        if 0 <= row < len(self._entries):
            return self._entries[row]["filename"]
        return f"row {row}"

    def output_at(self, row: int) -> str:
        if 0 <= row < len(self._entries):
            return self._entries[row]["outputPath"]
        return ""

    def path_at(self, row: int) -> str:
        if 0 <= row < len(self._entries):
            return self._entries[row]["path"]
        return ""


# ---------------------------------------------------------------------------
# background packer
# ---------------------------------------------------------------------------

class PackWorker(QThread):
    """Runs ``pack_file`` for each queued job off the UI thread.

    Every signal carries the model row index so the backend can update the
    right entry. The shared core is imported here (on the worker thread) so a
    late-arriving or missing ``packer.orchestrator`` surfaces as a clean
    per-file error rather than crashing the GUI at startup.
    """

    fileStarted = Signal(int)           # row
    progressLine = Signal(int, str)     # row, message
    fileFinished = Signal(int, object)  # row, PackResult
    fileError = Signal(int, str)        # row, error message
    allFinished = Signal()

    def __init__(self, jobs: List[Tuple[int, str]], options: dict,
                 parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._jobs = list(jobs)         # list[(row, input_path)]
        self._options = dict(options)   # runtime flags, level, out_dir
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def _output_for(self, input_path: str) -> str:
        """``{stem}.packed{ext}`` in the chosen output dir, else beside input."""
        stem, ext = os.path.splitext(os.path.basename(input_path))
        name = f"{stem}.packed{ext}"
        out_dir = self._options.get("output_directory") \
            or os.path.dirname(os.path.abspath(input_path))
        return os.path.join(out_dir, name)

    def run(self) -> None:  # noqa: N802
        try:
            from packer.orchestrator import PackOptions, pack_file
        except Exception as exc:  # noqa: BLE001
            for row, _ in self._jobs:
                self.fileError.emit(row, f"cannot import packer core: {exc}")
            self.allFinished.emit()
            return

        for row, input_path in self._jobs:
            if self._cancel:
                break
            self.fileStarted.emit(row)
            options = PackOptions(
                anti_debug=bool(self._options.get("anti_debug", False)),
                memory_guard=bool(self._options.get("memory_guard", False)),
                process_hardening=bool(
                    self._options.get("process_hardening", False)),
                compression_level=int(self._options.get("compression_level", 9)),
                output_path=self._output_for(input_path),
                is_dll=None,  # auto-detect authoritatively in the core
            )

            def progress(line: str, _row: int = row) -> None:
                self.progressLine.emit(_row, line)

            try:
                result = pack_file(input_path, options, progress=progress)
            except Exception as exc:  # noqa: BLE001 -- core promises not to, but be safe
                self.fileError.emit(row, str(exc))
            else:
                self.fileFinished.emit(row, result)
        self.allFinished.emit()


# ---------------------------------------------------------------------------
# backend QObject (the "venice" context property)
# ---------------------------------------------------------------------------

_MAX_LOG_LINES = 5000

# Built-in option presets (always present, cannot be deleted/overwritten). Each
# maps the four persisted knobs. User presets saved from the UI live alongside
# them in ~/.lethe/presets.json.
_BUILTIN_PRESETS = {
    "Balanced (recommended)": {
        "anti_debug": False, "memory_guard": False, "process_hardening": False,
        "compression_level": 9, "validate_after_pack": True,
    },
    "Memory guard (experimental)": {
        "anti_debug": False, "memory_guard": True, "process_hardening": False,
        "compression_level": 9, "validate_after_pack": True,
    },
    "Process hardening (experimental)": {
        "anti_debug": False, "memory_guard": False, "process_hardening": True,
        "compression_level": 9, "validate_after_pack": True,
    },
    "Fast (dev)": {
        "anti_debug": False, "memory_guard": False, "process_hardening": False,
        "compression_level": 3, "validate_after_pack": False,
    },
}
_PRESET_KEYS = ("anti_debug", "memory_guard", "process_hardening", "compression_level",
                "validate_after_pack")


def _presets_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".lethe", "presets.json")


def _load_user_presets() -> dict:
    try:
        with open(_presets_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    out: dict = {}
    if isinstance(data, dict):
        for name, cfg in data.items():
            if isinstance(name, str) and isinstance(cfg, dict):
                out[name] = {k: cfg[k] for k in _PRESET_KEYS if k in cfg}
    return out


def _save_user_presets(presets: dict) -> None:
    path = _presets_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(presets, fh, indent=2)


class VeniceBackend(QObject):
    """The QObject QML talks to: owns options, the file model and the worker."""

    antiDebugChanged = Signal()
    memoryGuardChanged = Signal()
    processHardeningChanged = Signal()
    compressionLevelChanged = Signal()
    outputDirectoryChanged = Signal()
    isPackingChanged = Signal()
    validateAfterPackChanged = Signal()
    presetsChanged = Signal()
    logTextChanged = Signal()
    logMessage = Signal(str)            # emitted once per progress/status line
    statsChanged = Signal()

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._anti_debug = False
        self._memory_guard = False
        self._process_hardening = False
        self._compression_level = 9
        self._output_directory = ""
        self._is_packing = False
        self._validate_after_pack = True
        self._user_presets = _load_user_presets()
        self._file_model = FileListModel(self)
        self._log_lines: List[str] = []
        self._worker: Optional[PackWorker] = None
        self._done_count = 0
        self._fail_count = 0
        self._total_jobs = 0
        self._file_model.countChanged.connect(self.statsChanged)

    # -- logging -----------------------------------------------------------
    def _append_log(self, line: str) -> None:
        self._log_lines.append(line)
        if len(self._log_lines) > _MAX_LOG_LINES:
            # keep the tail so recent activity stays visible
            self._log_lines = self._log_lines[-_MAX_LOG_LINES:]
        self.logTextChanged.emit()
        self.logMessage.emit(line)

    # -- antiDebug (r/w) ---------------------------------------------------
    def _get_anti_debug(self) -> bool:
        return self._anti_debug

    def _set_anti_debug(self, value: bool) -> None:
        value = bool(value)
        if self._anti_debug != value:
            self._anti_debug = value
            self.antiDebugChanged.emit()

    antiDebug = Property(bool, _get_anti_debug, _set_anti_debug,
                         notify=antiDebugChanged)

    # -- memoryGuard (r/w) -------------------------------------------------
    def _get_memory_guard(self) -> bool:
        return self._memory_guard

    def _set_memory_guard(self, value: bool) -> None:
        value = bool(value)
        if self._memory_guard != value:
            self._memory_guard = value
            self.memoryGuardChanged.emit()

    memoryGuard = Property(bool, _get_memory_guard, _set_memory_guard,
                           notify=memoryGuardChanged)

    # -- processHardening (r/w) -------------------------------------------
    def _get_process_hardening(self) -> bool:
        return self._process_hardening

    def _set_process_hardening(self, value: bool) -> None:
        value = bool(value)
        if self._process_hardening != value:
            self._process_hardening = value
            self.processHardeningChanged.emit()

    processHardening = Property(bool, _get_process_hardening,
                                _set_process_hardening,
                                notify=processHardeningChanged)

    # -- validateAfterPack (r/w) ------------------------------------------
    def _get_validate_after_pack(self) -> bool:
        return self._validate_after_pack

    def _set_validate_after_pack(self, value: bool) -> None:
        value = bool(value)
        if self._validate_after_pack != value:
            self._validate_after_pack = value
            self.validateAfterPackChanged.emit()

    validateAfterPack = Property(bool, _get_validate_after_pack,
                                 _set_validate_after_pack,
                                 notify=validateAfterPackChanged)

    # -- compressionLevel (r/w) -------------------------------------------
    def _get_compression_level(self) -> int:
        return self._compression_level

    def _set_compression_level(self, value: int) -> None:
        value = int(value)
        if self._compression_level != value:
            self._compression_level = value
            self.compressionLevelChanged.emit()

    compressionLevel = Property(int, _get_compression_level,
                                _set_compression_level,
                                notify=compressionLevelChanged)

    # -- outputDirectory (r/w) --------------------------------------------
    def _get_output_directory(self) -> str:
        return self._output_directory

    def _set_output_directory(self, value: str) -> None:
        value = str(value or "")
        if self._output_directory != value:
            self._output_directory = value
            self.outputDirectoryChanged.emit()

    outputDirectory = Property(str, _get_output_directory,
                               _set_output_directory,
                               notify=outputDirectoryChanged)

    # -- isPacking (read-only) --------------------------------------------
    def _get_is_packing(self) -> bool:
        return self._is_packing

    def _set_is_packing(self, value: bool) -> None:
        value = bool(value)
        if self._is_packing != value:
            self._is_packing = value
            self.isPackingChanged.emit()

    isPacking = Property(bool, _get_is_packing, notify=isPackingChanged)

    # -- fileModel (read-only) --------------------------------------------
    def _get_file_model(self) -> QObject:
        return self._file_model

    fileModel = Property(QObject, _get_file_model, constant=True)

    # -- logText (read-only) ----------------------------------------------
    def _get_log_text(self) -> str:
        return "\n".join(self._log_lines)

    logText = Property(str, _get_log_text, notify=logTextChanged)

    # -- dashboard stats (read-only) --------------------------------------
    def _get_total_size(self) -> str:
        total = sum(e.get("fileSize", 0) for e in self._file_model._entries)
        return _human_size(total) if total else "0 B"

    totalSize = Property(str, _get_total_size, notify=statsChanged)

    def _get_done_count(self) -> int:
        return self._done_count

    doneCount = Property(int, _get_done_count, notify=statsChanged)

    def _get_fail_count(self) -> int:
        return self._fail_count

    failCount = Property(int, _get_fail_count, notify=statsChanged)

    def _get_total_jobs(self) -> int:
        return self._total_jobs

    totalJobs = Property(int, _get_total_jobs, notify=statsChanged)

    def _get_pack_progress(self) -> float:
        if self._total_jobs <= 0:
            return 0.0
        return (self._done_count + self._fail_count) / self._total_jobs

    packProgress = Property(float, _get_pack_progress, notify=statsChanged)

    # -- packing lifecycle -------------------------------------------------
    @Slot()
    def packAll(self) -> None:
        if self._is_packing:
            return
        jobs = self._file_model.jobs()
        if not jobs:
            self._append_log("no files queued")
            return

        self._file_model.reset_statuses()
        self._done_count = 0
        self._fail_count = 0
        self._total_jobs = len(jobs)
        self.statsChanged.emit()
        self._set_is_packing(True)

        options = {
            "anti_debug": self._anti_debug,
            "memory_guard": self._memory_guard,
            "process_hardening": self._process_hardening,
            "compression_level": self._compression_level,
            "output_directory": self._output_directory or None,
        }
        self._append_log(
            f"packing {len(jobs)} file(s)  ·  "
            f"anti-debug={'on' if self._anti_debug else 'off'}  "
            f"memory-guard={'on' if self._memory_guard else 'off'}  "
            f"process-hardening={'on' if self._process_hardening else 'off'}  "
            f"level={self._compression_level}  "
            + (f"out={self._output_directory}" if self._output_directory
               else "out=beside input")
        )

        self._worker = PackWorker(jobs, options, self)
        self._worker.fileStarted.connect(self._on_file_started)
        self._worker.progressLine.connect(self._on_progress_line)
        self._worker.fileFinished.connect(self._on_file_finished)
        self._worker.fileError.connect(self._on_file_error)
        self._worker.allFinished.connect(self._on_all_finished)
        self._worker.start()

    @Slot()
    def cancelPacking(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            self._append_log("cancelling after the current file…")

    # -- worker signal handlers (run on the GUI thread) --------------------
    @Slot(int)
    def _on_file_started(self, row: int) -> None:
        self._file_model.set_status(row, "packing", "Packing…")
        self._append_log(f"[{self._file_model.filename_at(row)}] started")

    @Slot(int, str)
    def _on_progress_line(self, row: int, line: str) -> None:
        self._append_log(f"[{self._file_model.filename_at(row)}] {line}")

    @Slot(int, object)
    def _on_file_finished(self, row: int, result: object) -> None:
        name = self._file_model.filename_at(row)
        if bool(getattr(result, "ok", False)):
            ratio = float(getattr(result, "ratio", 0.0) or 0.0)
            elapsed = int(getattr(result, "elapsed_ms", 0) or 0)
            output_path = getattr(result, "output_path", "") or ""
            status_text = f"Done · {ratio * 100:.1f}% · {elapsed} ms"

            # Optional structural round-trip: parse the packed output back and
            # confirm the Lethe container is well-formed. Never executes it.
            valid = True
            if self._validate_after_pack and output_path:
                try:
                    from packer.report import validate_packed
                    vr = validate_packed(output_path)
                except Exception as exc:  # noqa: BLE001
                    self._append_log(f"[{name}] validation error: {exc}")
                else:
                    if vr.ok:
                        status_text += " · validated"
                        self._append_log(f"[{name}] validation OK — {vr.summary()}")
                    else:
                        valid = False
                        status_text = f"Packed but INVALID — {vr.reason}"
                        self._append_log(
                            f"[{name}] VALIDATION FAILED — {vr.summary()}")

            if valid:
                self._file_model.set_result(
                    row, "done", status_text, ratio, elapsed, output_path)
                self._append_log(f"[{name}] OK → {output_path}  ({status_text})")
                self._done_count += 1
            else:
                # A packed-but-invalid output is not usable -> count it as a fail
                # so the dashboard never reports a broken pack as a success.
                self._file_model.set_result(
                    row, "error", status_text, ratio, elapsed, output_path)
                self._fail_count += 1
            self.statsChanged.emit()
        else:
            error = getattr(result, "error", None) or "unknown error"
            elapsed = int(getattr(result, "elapsed_ms", 0) or 0)
            self._file_model.set_result(row, "error", error, 0.0, elapsed, "")
            self._append_log(f"[{name}] FAILED: {error}")
            self._fail_count += 1
            self.statsChanged.emit()

    @Slot(int, str)
    def _on_file_error(self, row: int, message: str) -> None:
        self._file_model.set_result(row, "error", message, 0.0, 0, "")
        self._append_log(f"[{self._file_model.filename_at(row)}] ERROR: {message}")
        self._fail_count += 1
        self.statsChanged.emit()

    @Slot()
    def _on_all_finished(self) -> None:
        worker = self._worker
        self._worker = None
        if worker is not None:
            worker.wait()
            worker.deleteLater()
        self._set_is_packing(False)
        self._append_log("finished")

    # -- file / folder dialogs --------------------------------------------
    @Slot()
    def browseFiles(self) -> None:
        """Open a native multi-select dialog and queue the chosen PEs."""
        try:
            from PySide6.QtWidgets import QFileDialog
            paths, _ = QFileDialog.getOpenFileNames(
                None, "Add PE files", "",
                "PE files (*.exe *.dll);;All files (*.*)",
            )
        except Exception as exc:  # noqa: BLE001 -- e.g. no QApplication for widgets
            self._append_log(f"file picker unavailable: {exc}")
            return
        if paths:
            self._file_model.addFiles(list(paths))

    @Slot()
    def browseOutputDir(self) -> None:
        try:
            from PySide6.QtWidgets import QFileDialog
            folder = QFileDialog.getExistingDirectory(None, "Choose output folder")
        except Exception as exc:  # noqa: BLE001
            self._append_log(f"folder picker unavailable: {exc}")
            return
        if folder:
            self._set_output_directory(folder)

    @Slot()
    def resetOutputDir(self) -> None:
        self._set_output_directory("")

    @Slot(int)
    def openOutputFile(self, index: int) -> None:
        """Reveal the packed output for ``index`` in its containing folder."""
        output_path = self._file_model.output_at(index)
        if not output_path:
            self._append_log("no output file to open yet")
            return
        folder = os.path.dirname(os.path.abspath(output_path))
        try:
            startfile = getattr(os, "startfile", None)
            if startfile is not None:
                startfile(folder)  # Windows Explorer
            else:
                from PySide6.QtGui import QDesktopServices
                QDesktopServices.openUrl(QUrl.fromLocalFile(folder))
        except Exception as exc:  # noqa: BLE001
            self._append_log(f"could not open folder: {exc}")

    # -- presets -----------------------------------------------------------
    def _get_preset_names(self) -> list:
        return list(_BUILTIN_PRESETS.keys()) + sorted(self._user_presets.keys())

    presetNames = Property("QVariantList", _get_preset_names,
                           notify=presetsChanged)

    def _preset(self, name: str) -> Optional[dict]:
        if name in _BUILTIN_PRESETS:
            return _BUILTIN_PRESETS[name]
        return self._user_presets.get(name)

    @Slot(str)
    def applyPreset(self, name: str) -> None:
        cfg = self._preset(name)
        if not cfg:
            self._append_log(f"preset not found: {name!r}")
            return
        if "anti_debug" in cfg:
            self._set_anti_debug(bool(cfg["anti_debug"]))
        if "memory_guard" in cfg:
            self._set_memory_guard(bool(cfg["memory_guard"]))
        if "process_hardening" in cfg:
            self._set_process_hardening(bool(cfg["process_hardening"]))
        if "compression_level" in cfg:
            self._set_compression_level(int(cfg["compression_level"]))
        if "validate_after_pack" in cfg:
            self._set_validate_after_pack(bool(cfg["validate_after_pack"]))
        self._append_log(f"applied preset: {name}")

    @Slot(str)
    def savePreset(self, name: str) -> None:
        name = (name or "").strip()
        if not name:
            self._append_log("preset needs a name")
            return
        if name in _BUILTIN_PRESETS:
            self._append_log(f"cannot overwrite built-in preset {name!r}")
            return
        self._user_presets[name] = {
            "anti_debug": self._anti_debug,
            "memory_guard": self._memory_guard,
            "process_hardening": self._process_hardening,
            "compression_level": self._compression_level,
            "validate_after_pack": self._validate_after_pack,
        }
        try:
            _save_user_presets(self._user_presets)
        except OSError as exc:
            self._append_log(f"could not save preset: {exc}")
            return
        self.presetsChanged.emit()
        self._append_log(f"saved preset: {name}")

    @Slot(str)
    def deletePreset(self, name: str) -> None:
        if name in _BUILTIN_PRESETS:
            self._append_log(f"cannot delete built-in preset {name!r}")
            return
        if name in self._user_presets:
            del self._user_presets[name]
            try:
                _save_user_presets(self._user_presets)
            except OSError as exc:
                self._append_log(f"could not update presets: {exc}")
            self.presetsChanged.emit()
            self._append_log(f"deleted preset: {name}")

    # -- section / entropy report -----------------------------------------
    @Slot(int)
    def showReport(self, index: int) -> None:
        """Log a section/entropy report for row ``index`` (original vs packed)."""
        path = self._file_model.path_at(index)
        if not path:
            self._append_log("select a file to report on")
            return
        packed = self._file_model.output_at(index) or None
        try:
            from packer.report import format_report
            text = format_report(path, packed)
        except Exception as exc:  # noqa: BLE001
            self._append_log(f"report failed: {exc}")
            return
        self._append_log("── section / entropy report ──")
        for line in text.splitlines():
            self._append_log(line)

    # -- drag & drop from QML ---------------------------------------------
    @Slot(list)
    def addDroppedUrls(self, urls: list) -> None:
        """Accept a QML ``DropArea``'s ``drop.urls`` (QUrl or file:// strings)."""
        paths: List[str] = []
        for url in urls:
            local = self._url_to_local(url)
            if local:
                paths.append(local)
        if paths:
            self._file_model.addFiles(paths)

    @staticmethod
    def _url_to_local(url) -> str:
        if url is None:
            return ""
        if isinstance(url, QUrl):
            return url.toLocalFile()
        text = str(url)
        if text.startswith("file:"):
            return QUrl(text).toLocalFile()
        return text
