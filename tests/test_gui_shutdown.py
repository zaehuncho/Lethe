"""Real Qt worker-lifetime regression tests; no protected PE is executed."""
from __future__ import annotations

import os
from pathlib import Path
import threading
import time
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication
from shiboken6 import isValid

from gui import app as gui


@pytest.fixture(scope="module")
def application():
    app = QApplication.instance() or QApplication([])
    app.setQuitOnLastWindowClosed(False)
    yield app
    app.processEvents()


def _until(app, predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(.002)
    assert predicate(), "Qt worker transition did not complete"


@pytest.fixture
def window(application, monkeypatch):
    monkeypatch.setattr(gui.MainWindow, "_probe_core", lambda self: None)
    win = gui.MainWindow()
    win.show()
    application.processEvents()
    yield win
    worker = win._worker
    if worker is not None:
        if hasattr(worker, "release"):
            worker.release.set()
        worker.cancel()
        assert worker.wait(15000)
        _until(application, lambda: win._worker is None)
    if isValid(win):
        win.close()
        win.deleteLater()
    application.processEvents()


def _start(window, monkeypatch, tmp_path, *, early_signal=False, emit_custom=True):
    class ControlledWorker(gui.PackWorker):
        def __init__(self, *args):
            super().__init__(*args)
            self.started_event = threading.Event()
            self.release = threading.Event()

        def run(self):
            if early_signal:
                self.allFinished.emit()
            self.started_event.set()
            self.release.wait(10)
            if emit_custom and not early_signal:
                self.allFinished.emit()

    monkeypatch.setattr(gui, "PackWorker", ControlledWorker)
    window._append_row(str(tmp_path / "not-executed.exe"))
    window._on_pack_clicked()
    worker = window._worker
    assert worker.started_event.wait(3)
    return worker


def test_idle_close_is_accepted(window):
    assert window.close()
    assert not window.isVisible()


def test_close_defers_without_blocking_and_retains_running_worker(
        application, window, monkeypatch, tmp_path):
    worker = _start(window, monkeypatch, tmp_path)
    started = time.monotonic()
    try:
        assert not window.close()
        assert time.monotonic() - started < .5
        assert window.isVisible()
        assert window._worker is worker
        assert worker.isRunning() and worker._cancel
        assert window._close_pending
        assert not window.pack_btn.isEnabled()
        assert not window.close()
        assert window.log.toPlainText().count("Closing after") == 1
    finally:
        worker.release.set()
    _until(application, lambda: window._worker is None)
    assert not window.isVisible()


def test_early_custom_signal_does_not_release_worker_or_block_gui(
        application, window, monkeypatch, tmp_path):
    worker = _start(window, monkeypatch, tmp_path, early_signal=True)
    ticks = []
    QTimer.singleShot(0, lambda: ticks.append(True))
    try:
        _until(application, lambda: bool(ticks))
        assert window._worker is worker
        assert window.pack_btn.text() == "Cancel"
        assert worker.isRunning()
    finally:
        worker.release.set()
    _until(application, lambda: window._worker is None)
    assert window.isVisible()
    assert window.pack_btn.text() == "Pack"
    assert window.pack_btn.isEnabled()


def test_native_finished_cleans_up_without_custom_signal(
        application, window, monkeypatch, tmp_path):
    worker = _start(window, monkeypatch, tmp_path, emit_custom=False)
    worker.release.set()
    _until(application, lambda: window._worker is None)
    assert window.summary_label.text() == "done"
    assert window.isVisible()


def test_native_cleanup_join_is_polled_without_blocking(
        application, window, monkeypatch, tmp_path):
    worker = _start(window, monkeypatch, tmp_path)
    assert not window.close()
    original_wait = worker.wait
    waits = []

    def wait(timeout):
        assert timeout == 0
        waits.append(timeout)
        if len(waits) < 3:
            return False
        return original_wait(timeout)

    monkeypatch.setattr(worker, "wait", wait)
    worker.release.set()
    _until(application, lambda: window._worker is None)
    assert len(waits) >= 3
    assert not window.isVisible()


def test_close_cancels_later_jobs_but_finishes_current_file(
        application, window, monkeypatch, tmp_path):
    from packer import orchestrator

    started, release = threading.Event(), threading.Event()
    calls = []

    def pack_file(path, options, *, progress):
        calls.append(path)
        started.set()
        assert release.wait(10)
        return SimpleNamespace(ok=True, output_path=options.output_path,
                               original_size=1, packed_size=1, elapsed_ms=1)

    monkeypatch.setattr(orchestrator, "pack_file", pack_file)
    window._append_row(str(tmp_path / "first.exe"))
    window._append_row(str(tmp_path / "second.dll"))
    window._on_pack_clicked()
    worker = window._worker
    assert started.wait(3)
    try:
        assert not window.close()
        application.processEvents()
        assert window._worker is worker
    finally:
        release.set()
    _until(application, lambda: window._worker is None)
    assert calls == [str(tmp_path / "first.exe")]
    assert not window.isVisible()
    assert "OK →" in window.log.toPlainText()


def test_cancel_then_close_finishes_without_starting_new_batch(
        application, window, monkeypatch, tmp_path):
    worker = _start(window, monkeypatch, tmp_path)
    window._on_pack_clicked()
    assert worker._cancel
    assert not window.pack_btn.isEnabled()
    assert not window.close()
    worker.release.set()
    _until(application, lambda: window._worker is None)
    assert not window.isVisible()
