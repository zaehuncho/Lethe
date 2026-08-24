#!/usr/bin/env python3
"""Lethe GUI -- clickable PySide6 front-end for the x64 PE packer.

This is the graphical twin of ``lethe.py``; both are thin wrappers over the
single core :func:`packer.orchestrator.pack_file`, so the CLI and the GUI never
drift. Lethe is an internal build tool (it *produces* protected first-party
binaries and is never shipped to customers), which is why freezing it with
Nuitka -- see ``gui/build_gui.ps1`` -- is fine.

Design
------
* A drop-enabled file table: add PEs with the button *or* by dragging them in
  (multi-select). Each row shows filename, detected type (EXE/DLL, read inline
  from the PE header), architecture, size and a live status cell.
* A global options panel: output-folder picker, anti-debug toggle, memory-guard
  toggle (opt-in; test against your AV first) and an LZMA compression level.
* A Pack button that runs ``pack_file`` for every queued file on a background
  QThread (the UI never blocks), streams ``progress(str)`` lines into a log pane
  and updates each row's status in place.

Licensing: PySide6 (LGPL), matching the project's existing Qt stack.

Run from source::

    python gui/app.py

The packing logic is deliberately isolated in :class:`PackWorker` (a QThread)
so the widgets never touch ``pack_file`` directly.
"""
from __future__ import annotations

import os
import struct
import sys

# --- import bootstrap ------------------------------------------------------
# app.py lives at gui/app.py; the ``packer`` package sits
# one directory up (packer). Put that parent on sys.path
# so ``import packer.orchestrator`` resolves both when run from source and when
# frozen (the frozen build also embeds the package via --include-package=packer,
# which makes it importable regardless of sys.path).
_GUI_DIR = os.path.dirname(os.path.abspath(__file__))
_PACKER_ROOT = os.path.dirname(_GUI_DIR)  # Lethe
if _PACKER_ROOT not in sys.path:
    sys.path.insert(0, _PACKER_ROOT)

# --- PySide6 import guard --------------------------------------------------
try:
    from PySide6.QtCore import Qt, QThread, Signal
    from PySide6.QtGui import (
        QColor, QFont, QGuiApplication, QPainter, QPalette,
    )
    from PySide6.QtWidgets import (
        QAbstractItemView, QApplication, QCheckBox, QFileDialog, QFrame,
        QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
        QPlainTextEdit, QPushButton, QSlider, QSplitter, QTableWidget,
        QTableWidgetItem, QVBoxLayout, QWidget,
    )
except ImportError as exc:  # pragma: no cover - environment without PySide6
    sys.stderr.write(
        "Lethe GUI requires PySide6 (LGPL).\n"
        f"  import error: {exc}\n"
        "  install it with:  python -m pip install PySide6\n"
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# theme
# ---------------------------------------------------------------------------

BG_WINDOW = "#1e1f24"
BG_PANEL = "#26272e"
BG_INPUT = "#2d2f37"
BG_HOVER = "#343642"
BORDER = "#3a3c46"
TEXT = "#e7e7ec"
MUTED = "#9a9ba6"
ACCENT = "#4c8dff"
ACCENT_HOVER = "#5f9bff"
ACCENT_PRESS = "#3c7ae6"
OK_GREEN = "#4bcf72"
ERR_RED = "#ec5b52"
RUN_AMBER = "#e0a63a"

_STYLESHEET = f"""
QWidget {{
    background: {BG_WINDOW};
    color: {TEXT};
    font-size: 13px;
}}
QLabel#title {{ font-size: 20px; font-weight: 600; }}
QLabel#subtitle {{ color: {MUTED}; font-size: 12px; }}
QLabel#section {{ color: {MUTED}; font-size: 11px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 1px; }}
QLabel#caption {{ color: {MUTED}; font-size: 11px; }}

QGroupBox {{
    background: {BG_PANEL};
    border: 1px solid {BORDER};
    border-radius: 8px;
    margin-top: 10px;
    padding: 12px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px; padding: 0 4px;
    color: {MUTED}; font-weight: 600;
}}

QPushButton {{
    background: {BG_INPUT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 7px 14px;
}}
QPushButton:hover {{ background: {BG_HOVER}; }}
QPushButton:disabled {{ color: {MUTED}; background: {BG_PANEL}; }}
QPushButton#primary {{
    background: {ACCENT}; border: 1px solid {ACCENT};
    color: white; font-weight: 600; padding: 8px 22px;
}}
QPushButton#primary:hover {{ background: {ACCENT_HOVER}; border-color: {ACCENT_HOVER}; }}
QPushButton#primary:pressed {{ background: {ACCENT_PRESS}; }}
QPushButton#primary:disabled {{ background: {BG_PANEL}; border-color: {BORDER}; color: {MUTED}; }}

QLineEdit, QPlainTextEdit {{
    background: {BG_INPUT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 6px 8px;
    selection-background-color: {ACCENT};
}}
QPlainTextEdit {{ font-family: Consolas, "Cascadia Mono", monospace; font-size: 12px; }}

QTableWidget {{
    background: {BG_PANEL};
    border: 1px solid {BORDER};
    border-radius: 8px;
    gridline-color: {BORDER};
    selection-background-color: {BG_HOVER};
    selection-color: {TEXT};
}}
QHeaderView::section {{
    background: {BG_PANEL};
    color: {MUTED};
    border: none;
    border-bottom: 1px solid {BORDER};
    padding: 8px;
    font-weight: 600;
}}
QTableWidget::item {{ padding: 6px; }}

QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{
    width: 16px; height: 16px; border-radius: 4px;
    border: 1px solid {BORDER}; background: {BG_INPUT};
}}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}

QSlider::groove:horizontal {{
    height: 4px; background: {BORDER}; border-radius: 2px;
}}
QSlider::sub-page:horizontal {{ background: {ACCENT}; border-radius: 2px; }}
QSlider::handle:horizontal {{
    background: {TEXT}; width: 14px; height: 14px;
    margin: -6px 0; border-radius: 7px;
}}

QSplitter::handle {{ background: transparent; }}
QScrollBar:vertical {{ background: {BG_WINDOW}; width: 12px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {BORDER}; border-radius: 6px; min-height: 24px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
"""


def apply_dark_theme(app: QApplication) -> None:
    """Fusion base + a dark palette so native widgets render dark too."""
    app.setStyle("Fusion")
    pal = QPalette()
    pal.setColor(QPalette.Window, QColor(BG_WINDOW))
    pal.setColor(QPalette.WindowText, QColor(TEXT))
    pal.setColor(QPalette.Base, QColor(BG_INPUT))
    pal.setColor(QPalette.AlternateBase, QColor(BG_PANEL))
    pal.setColor(QPalette.Text, QColor(TEXT))
    pal.setColor(QPalette.Button, QColor(BG_INPUT))
    pal.setColor(QPalette.ButtonText, QColor(TEXT))
    pal.setColor(QPalette.Highlight, QColor(ACCENT))
    pal.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    pal.setColor(QPalette.ToolTipBase, QColor(BG_PANEL))
    pal.setColor(QPalette.ToolTipText, QColor(TEXT))
    pal.setColor(QPalette.PlaceholderText, QColor(MUTED))
    app.setPalette(pal)
    app.setStyleSheet(_STYLESHEET)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_MACHINE = {
    0x8664: "x64",
    0x014C: "x86",
    0xAA64: "ARM64",
    0x0200: "IA64",
}


def human_size(n: "int | None") -> str:
    if n is None:
        return "n/a"
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            return f"{int(size)} B" if unit == "B" else f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"


def detect_pe(path: str) -> "tuple[str, str]":
    """Detect (kind, arch) inline from the PE header, no external deps.

    ``kind`` is ``"EXE"`` / ``"DLL"`` / ``"not a PE"``; ``arch`` is ``"x64"`` /
    ``"x86"`` / ``"ARM64"`` / ``"?"``. Mirrors the header walk the packer does:
    DOS ``MZ`` -> ``e_lfanew`` -> ``PE\\0\\0`` -> IMAGE_FILE_HEADER, testing the
    ``IMAGE_FILE_DLL`` (0x2000) characteristic.
    """
    try:
        with open(path, "rb") as fh:
            dos = fh.read(64)
            if len(dos) < 64 or dos[:2] != b"MZ":
                return ("not a PE", "?")
            e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
            fh.seek(e_lfanew)
            if fh.read(4) != b"PE\x00\x00":
                return ("not a PE", "?")
            coff = fh.read(20)  # IMAGE_FILE_HEADER
            if len(coff) < 20:
                return ("not a PE", "?")
            machine, _nsec, _ts, _psym, _nsym, _optsz, characteristics = (
                struct.unpack_from("<HHIIIHH", coff, 0)
            )
    except (OSError, struct.error):
        return ("not a PE", "?")
    kind = "DLL" if (characteristics & 0x2000) else "EXE"
    return (kind, _MACHINE.get(machine, f"0x{machine:04x}"))


# ---------------------------------------------------------------------------
# drop-enabled table
# ---------------------------------------------------------------------------

class DropTable(QTableWidget):
    """QTableWidget that accepts dropped files/folders and Delete-to-remove."""

    filesDropped = Signal(list)
    removeSelectedRequested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(0, 5, parent)
        self.setHorizontalHeaderLabels(["File", "Type", "Arch", "Size", "Status"])
        self.setAcceptDrops(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.verticalHeader().setVisible(False)
        self.setShowGrid(False)
        self.setWordWrap(False)
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        for col in (1, 2, 3):
            header.setSectionResizeMode(col, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        header.setStretchLastSection(True)

    # external file drops -------------------------------------------------
    def dragEnterEvent(self, event):  # noqa: N802 (Qt override)
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event):  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event):  # noqa: N802
        if event.mimeData().hasUrls():
            paths = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]
            paths = [p for p in paths if p]
            if paths:
                self.filesDropped.emit(paths)
            event.acceptProposedAction()
        else:
            super().dropEvent(event)

    def keyPressEvent(self, event):  # noqa: N802
        if event.key() in (Qt.Key_Delete, Qt.Key_Backspace):
            self.removeSelectedRequested.emit()
        else:
            super().keyPressEvent(event)

    # empty-state hint ----------------------------------------------------
    def paintEvent(self, event):  # noqa: N802
        super().paintEvent(event)
        if self.rowCount() == 0:
            painter = QPainter(self.viewport())
            painter.setPen(QColor(MUTED))
            font = self.font()
            font.setPointSize(font.pointSize() + 1)
            painter.setFont(font)
            painter.drawText(
                self.viewport().rect(),
                Qt.AlignCenter,
                "Drop EXE / DLL files here\nor use  “Add PEs…”",
            )
            painter.end()


# ---------------------------------------------------------------------------
# background packer
# ---------------------------------------------------------------------------

class PackWorker(QThread):
    """Runs ``pack_file`` for each queued job off the UI thread.

    Signals carry the table row index so the window can update the right row.
    The shared core is imported here (on the worker thread) so a late-arriving
    or missing ``packer.orchestrator`` surfaces as a clean per-file error rather
    than crashing the GUI at startup.
    """

    fileStarted = Signal(int)          # row
    progressLine = Signal(int, str)    # row, message
    fileFinished = Signal(int, object)  # row, PackResult
    fileError = Signal(int, str)       # row, error message
    countChanged = Signal(int, int)    # done, total
    allFinished = Signal()

    def __init__(self, jobs, opts, parent=None) -> None:
        super().__init__(parent)
        self._jobs = list(jobs)     # list[(row, input_path)]
        self._opts = dict(opts)     # anti_debug, memory_guard, level, out_dir
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def _output_for(self, input_path: str) -> str:
        stem, ext = os.path.splitext(os.path.basename(input_path))
        name = f"{stem}.packed{ext}"
        out_dir = self._opts.get("out_dir") or os.path.dirname(os.path.abspath(input_path))
        return os.path.join(out_dir, name)

    def run(self) -> None:  # noqa: N802
        try:
            from packer.orchestrator import PackOptions, pack_file
        except Exception as exc:  # noqa: BLE001
            for row, _ in self._jobs:
                self.fileError.emit(row, f"cannot import packer core: {exc}")
            self.allFinished.emit()
            return

        total = len(self._jobs)
        done = 0
        for row, input_path in self._jobs:
            if self._cancel:
                break
            self.fileStarted.emit(row)
            options = PackOptions(
                anti_debug=self._opts["anti_debug"],
                memory_guard=self._opts["memory_guard"],
                compression_level=self._opts["level"],
                output_path=self._output_for(input_path),
                is_dll=None,  # auto-detect authoritatively in the core
            )

            def progress(line: str, _row: int = row) -> None:
                self.progressLine.emit(_row, line)

            try:
                result = pack_file(input_path, options, progress=progress)
            except Exception as exc:  # noqa: BLE001
                self.fileError.emit(row, str(exc))
            else:
                self.fileFinished.emit(row, result)
            done += 1
            self.countChanged.emit(done, total)
        self.allFinished.emit()


# ---------------------------------------------------------------------------
# main window
# ---------------------------------------------------------------------------

COL_NAME, COL_TYPE, COL_ARCH, COL_SIZE, COL_STATUS = range(5)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Lethe")
        self.setMinimumSize(880, 560)
        self.resize(1040, 700)

        self._paths: set[str] = set()   # dedupe by absolute path
        self._worker: "PackWorker | None" = None

        self._build_ui()
        self._refresh_states()
        self._probe_core()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(12)

        # header
        title = QLabel("Lethe")
        title.setObjectName("title")
        subtitle = QLabel("x64 PE packer · internal build tool (protected binaries never ship the packer)")
        subtitle.setObjectName("subtitle")
        header = QVBoxLayout()
        header.setSpacing(2)
        header.addWidget(title)
        header.addWidget(subtitle)
        root.addLayout(header)

        # main split: [ table+toolbar | options ] over [ log ]
        splitter = QSplitter(Qt.Vertical)
        root.addWidget(splitter, 1)

        upper = QWidget()
        upper_l = QHBoxLayout(upper)
        upper_l.setContentsMargins(0, 0, 0, 0)
        upper_l.setSpacing(12)
        upper_l.addWidget(self._build_files_panel(), 1)
        upper_l.addWidget(self._build_options_panel())
        splitter.addWidget(upper)

        splitter.addWidget(self._build_log_panel())
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        # action bar
        action_bar = QHBoxLayout()
        self.summary_label = QLabel("")
        self.summary_label.setObjectName("caption")
        self.pack_btn = QPushButton("Pack")
        self.pack_btn.setObjectName("primary")
        self.pack_btn.clicked.connect(self._on_pack_clicked)
        action_bar.addWidget(self.summary_label)
        action_bar.addStretch(1)
        action_bar.addWidget(self.pack_btn)
        root.addLayout(action_bar)

    def _build_files_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        toolbar = QHBoxLayout()
        self.add_btn = QPushButton("Add PEs…")
        self.add_btn.clicked.connect(self._on_add_clicked)
        self.remove_btn = QPushButton("Remove")
        self.remove_btn.clicked.connect(self._remove_selected)
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self._clear_all)
        self.count_label = QLabel("0 files")
        self.count_label.setObjectName("caption")
        toolbar.addWidget(self.add_btn)
        toolbar.addWidget(self.remove_btn)
        toolbar.addWidget(self.clear_btn)
        toolbar.addStretch(1)
        toolbar.addWidget(self.count_label)
        layout.addLayout(toolbar)

        self.table = DropTable()
        self.table.filesDropped.connect(self._add_paths)
        self.table.removeSelectedRequested.connect(self._remove_selected)
        self.table.itemSelectionChanged.connect(self._refresh_states)
        layout.addWidget(self.table, 1)
        return panel

    def _build_options_panel(self) -> QWidget:
        group = QGroupBox("Options")
        group.setFixedWidth(300)
        layout = QVBoxLayout(group)
        layout.setSpacing(10)

        # output folder
        layout.addWidget(self._section_label("Output folder"))
        self.out_edit = QLineEdit()
        self.out_edit.setReadOnly(True)
        self.out_edit.setPlaceholderText("Beside each input file")
        out_row = QHBoxLayout()
        out_row.addWidget(self.out_edit, 1)
        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self._on_browse_output)
        reset_btn = QPushButton("Reset")
        reset_btn.clicked.connect(lambda: self.out_edit.clear())
        out_row.addWidget(browse_btn)
        out_row.addWidget(reset_btn)
        layout.addLayout(out_row)
        self._add_divider(layout)

        # protection toggles
        layout.addWidget(self._section_label("Protection"))
        self.anti_debug_cb = QCheckBox("Anti-debug (gated, AV-clean)")
        self.anti_debug_cb.setChecked(True)
        layout.addWidget(self.anti_debug_cb)

        self.memguard_cb = QCheckBox("Memory guard (on-demand decrypt)")
        self.memguard_cb.setChecked(False)
        layout.addWidget(self.memguard_cb)
        memguard_caption = QLabel("opt-in — test against your AV first")
        memguard_caption.setObjectName("caption")
        memguard_caption.setContentsMargins(24, 0, 0, 0)
        layout.addWidget(memguard_caption)
        self._add_divider(layout)

        # compression
        level_header = QHBoxLayout()
        level_header.addWidget(self._section_label("Compression"))
        level_header.addStretch(1)
        self.level_value = QLabel("9")
        self.level_value.setObjectName("caption")
        level_header.addWidget(self.level_value)
        layout.addLayout(level_header)
        self.level_slider = QSlider(Qt.Horizontal)
        self.level_slider.setRange(0, 9)
        self.level_slider.setValue(9)
        self.level_slider.setTickPosition(QSlider.TicksBelow)
        self.level_slider.setTickInterval(1)
        self.level_slider.valueChanged.connect(lambda v: self.level_value.setText(str(v)))
        layout.addWidget(self.level_slider)

        layout.addStretch(1)
        return group

    def _build_log_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(self._section_label("Activity log"))
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(5000)
        self.log.setPlaceholderText("Progress and results appear here.")
        layout.addWidget(self.log, 1)
        return panel

    def _section_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("section")
        return label

    def _add_divider(self, layout: QVBoxLayout) -> None:
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet(f"color: {BORDER}; background: {BORDER}; max-height: 1px;")
        layout.addWidget(line)

    # -------------------------------------------------------------- files
    def _on_add_clicked(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Add PE files", "",
            "PE files (*.exe *.dll);;All files (*.*)",
        )
        if paths:
            self._add_paths(paths)

    def _add_paths(self, paths) -> None:
        expanded: list[str] = []
        for path in paths:
            if os.path.isdir(path):
                # convenience: a dropped folder contributes its EXE/DLL children
                for name in sorted(os.listdir(path)):
                    if name.lower().endswith((".exe", ".dll")):
                        expanded.append(os.path.join(path, name))
            elif os.path.isfile(path):
                expanded.append(path)

        added = 0
        for path in expanded:
            abspath = os.path.abspath(path)
            if abspath in self._paths:
                continue
            self._paths.add(abspath)
            self._append_row(abspath)
            added += 1
        if added:
            self.log_line(f"added {added} file(s)")
        self._refresh_states()

    def _append_row(self, abspath: str) -> None:
        kind, arch = detect_pe(abspath)
        try:
            size = os.path.getsize(abspath)
        except OSError:
            size = None

        row = self.table.rowCount()
        self.table.insertRow(row)

        name_item = QTableWidgetItem(os.path.basename(abspath))
        name_item.setData(Qt.UserRole, abspath)
        name_item.setToolTip(abspath)

        type_item = QTableWidgetItem(kind)
        if kind == "not a PE":
            type_item.setForeground(QColor(ERR_RED))

        arch_item = QTableWidgetItem(arch)
        if arch != "x64":
            # the packer targets x64; flag anything else so it stands out
            arch_item.setForeground(QColor(RUN_AMBER))

        size_item = QTableWidgetItem(human_size(size))
        size_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)

        status_item = QTableWidgetItem("queued")
        status_item.setForeground(QColor(MUTED))

        self.table.setItem(row, COL_NAME, name_item)
        self.table.setItem(row, COL_TYPE, type_item)
        self.table.setItem(row, COL_ARCH, arch_item)
        self.table.setItem(row, COL_SIZE, size_item)
        self.table.setItem(row, COL_STATUS, status_item)

    def _remove_selected(self) -> None:
        rows = sorted({idx.row() for idx in self.table.selectedIndexes()}, reverse=True)
        for row in rows:
            item = self.table.item(row, COL_NAME)
            if item is not None:
                self._paths.discard(item.data(Qt.UserRole))
            self.table.removeRow(row)
        if rows:
            self._refresh_states()

    def _clear_all(self) -> None:
        self.table.setRowCount(0)
        self._paths.clear()
        self._refresh_states()

    # ------------------------------------------------------------ options
    def _on_browse_output(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Choose output folder")
        if folder:
            self.out_edit.setText(folder)

    def _current_options(self) -> dict:
        out_dir = self.out_edit.text().strip()
        return {
            "anti_debug": self.anti_debug_cb.isChecked(),
            "memory_guard": self.memguard_cb.isChecked(),
            "level": self.level_slider.value(),
            "out_dir": out_dir or None,
        }

    # --------------------------------------------------------------- pack
    def _on_pack_clicked(self) -> None:
        if self._worker is not None:  # button is showing "Cancel"
            self._worker.cancel()
            self.pack_btn.setText("Cancelling…")
            self.pack_btn.setEnabled(False)
            return

        jobs: list[tuple[int, str]] = []
        for row in range(self.table.rowCount()):
            item = self.table.item(row, COL_NAME)
            if item is None:
                continue
            jobs.append((row, item.data(Qt.UserRole)))
            self._set_status(row, "queued", MUTED)
        if not jobs:
            return

        opts = self._current_options()
        self.log_line(
            f"packing {len(jobs)} file(s)  ·  anti-debug={'on' if opts['anti_debug'] else 'off'}"
            f"  memory-guard={'on' if opts['memory_guard'] else 'off'}  level={opts['level']}"
            + (f"  out={opts['out_dir']}" if opts["out_dir"] else "  out=beside input")
        )

        self._worker = PackWorker(jobs, opts, self)
        self._worker.fileStarted.connect(self._on_file_started)
        self._worker.progressLine.connect(self._on_progress_line)
        self._worker.fileFinished.connect(self._on_file_finished)
        self._worker.fileError.connect(self._on_file_error)
        self._worker.countChanged.connect(self._on_count_changed)
        self._worker.allFinished.connect(self._on_all_finished)
        self._set_running(True)
        self._worker.start()

    def _on_file_started(self, row: int) -> None:
        self._set_status(row, "packing…", RUN_AMBER)

    def _on_progress_line(self, row: int, line: str) -> None:
        self.log_line(f"[{self._row_name(row)}] {line}")

    def _on_file_finished(self, row: int, result: object) -> None:
        ok = bool(getattr(result, "ok", False))
        name = self._row_name(row)
        if ok:
            original = getattr(result, "original_size", None)
            packed = getattr(result, "packed_size", None)
            elapsed = getattr(result, "elapsed_ms", None)
            pct = (packed / original * 100.0) if (original and packed is not None) else None
            text = f"✓ {human_size(original)} → {human_size(packed)}"
            if pct is not None:
                text += f"  ({pct:.0f}%)"
            if elapsed is not None:
                text += f"  · {int(elapsed)} ms"
            self._set_status(row, text, OK_GREEN)
            self.log_line(f"[{name}] OK → {getattr(result, 'output_path', '?')}  ({text})")
        else:
            error = getattr(result, "error", None) or "unknown error"
            self._set_status(row, f"✗ {error}", ERR_RED)
            self.log_line(f"[{name}] FAILED: {error}")

    def _on_file_error(self, row: int, message: str) -> None:
        self._set_status(row, f"✗ {message}", ERR_RED)
        self.log_line(f"[{self._row_name(row)}] ERROR: {message}")

    def _on_count_changed(self, done: int, total: int) -> None:
        self.summary_label.setText(f"packing {done}/{total}…")

    def _on_all_finished(self) -> None:
        worker = self._worker
        self._worker = None
        if worker is not None:
            worker.wait()
            worker.deleteLater()
        self._set_running(False)
        self.summary_label.setText("done")
        self.log_line("finished")

    # -------------------------------------------------------------- state
    def _set_running(self, running: bool) -> None:
        self.add_btn.setEnabled(not running)
        self.remove_btn.setEnabled(not running and self._has_selection())
        self.clear_btn.setEnabled(not running and self.table.rowCount() > 0)
        self.anti_debug_cb.setEnabled(not running)
        self.memguard_cb.setEnabled(not running)
        self.level_slider.setEnabled(not running)
        self.table.setEnabled(not running)
        if running:
            self.pack_btn.setText("Cancel")
            self.pack_btn.setObjectName("")  # neutral look while cancel
            self.pack_btn.setEnabled(True)
        else:
            self.pack_btn.setText("Pack")
            self.pack_btn.setObjectName("primary")
            self.pack_btn.setEnabled(self.table.rowCount() > 0)
        # re-polish so the objectName change re-applies the stylesheet
        self.pack_btn.style().unpolish(self.pack_btn)
        self.pack_btn.style().polish(self.pack_btn)

    def _refresh_states(self) -> None:
        running = self._worker is not None
        has_rows = self.table.rowCount() > 0
        self.count_label.setText(f"{self.table.rowCount()} file(s)")
        if not running:
            self.pack_btn.setEnabled(has_rows)
            self.clear_btn.setEnabled(has_rows)
            self.remove_btn.setEnabled(self._has_selection())

    def _has_selection(self) -> bool:
        return len(self.table.selectionModel().selectedRows()) > 0 if self.table.selectionModel() else False

    def _probe_core(self) -> None:
        """Report at startup whether the shared core is importable yet."""
        try:
            import packer.orchestrator  # noqa: F401
            self.log_line("packer core ready.")
        except Exception as exc:  # noqa: BLE001
            self.log_line(f"note: packer core not importable yet ({exc}).")
            self.log_line("      packing will retry the import when you click Pack.")

    # ------------------------------------------------------------ helpers
    def _row_name(self, row: int) -> str:
        item = self.table.item(row, COL_NAME)
        return item.text() if item is not None else f"row {row}"

    def _set_status(self, row: int, text: str, color: str) -> None:
        item = self.table.item(row, COL_STATUS)
        if item is None:
            item = QTableWidgetItem()
            self.table.setItem(row, COL_STATUS, item)
        item.setText(text)
        item.setForeground(QColor(color))
        item.setToolTip(text)

    def log_line(self, text: str) -> None:
        self.log.appendPlainText(text)

    # ------------------------------------------------------------- events
    def closeEvent(self, event):  # noqa: N802
        if self._worker is not None:
            self._worker.cancel()
            self._worker.wait(3000)
        super().closeEvent(event)


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def main(argv: "list[str] | None" = None) -> int:
    QGuiApplication.setApplicationName("Lethe")
    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationDisplayName("Lethe")
    apply_dark_theme(app)

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
