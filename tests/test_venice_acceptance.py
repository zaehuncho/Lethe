"""Venice result/worker acceptance, including the actual application QML."""
from __future__ import annotations

import builtins
import os
from pathlib import Path
import threading
import time
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_QUICK_BACKEND", "software")

import pytest

pytest.importorskip("PySide6")
from PySide6.QtCore import QCoreApplication, QEvent, QTimer, QUrl
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtWidgets import QApplication
import PySide6.QtQuick  # registers the real application's QML types
from PySide6.QtQuickControls2 import QQuickStyle
from shiboken6 import isValid

from gui import venice_backend as gui
from packer import report


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def application():
    QQuickStyle.setStyle("Basic")
    app = QApplication.instance() or QApplication([])
    app.setQuitOnLastWindowClosed(False)
    yield app
    app.processEvents()


def _until(app, predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(.002)
    assert predicate(), "Venice worker transition did not complete"


@pytest.fixture
def backend(application, monkeypatch, tmp_path):
    # Never load or overwrite the developer's real ~/.lethe/presets.json.
    monkeypatch.setattr(gui, "_load_user_presets", lambda: {})
    value = gui.VeniceBackend()
    path = tmp_path / "input.exe"
    path.write_bytes(b"Not an executable; never executed")
    value._file_model.addFiles([str(path)])
    yield value
    worker = value._worker
    if worker is not None:
        if hasattr(worker, "release"):
            worker.release.set()
        worker.cancel()
        assert worker.wait(15000)
        _until(application, lambda: value._worker is None)
    value.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


@pytest.fixture
def qml_window(application, backend):
    engine = QQmlApplicationEngine()
    engine.rootContext().setContextProperty("venice", backend)
    warnings = []
    engine.warnings.connect(lambda items: warnings.extend(str(item) for item in items))
    engine.load(QUrl.fromLocalFile(str(ROOT / "gui/qml/Main.qml")))
    assert engine.rootObjects(), "Actual Venice Main.qml failed to load"
    window = engine.rootObjects()[0]
    application.processEvents()
    assert window.isVisible()
    assert not warnings
    yield window
    worker = backend._worker
    if worker is not None:
        if hasattr(worker, "release"):
            worker.release.set()
        worker.cancel()
        assert worker.wait(15000)
        _until(application, lambda: backend._worker is None)
    window.close()
    window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    engine.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    assert not warnings


def _result(output="output.packed.exe", **overrides):
    fields = dict(ok=True, ratio=.5, elapsed_ms=2, output_path=output)
    fields.update(overrides)
    return SimpleNamespace(**fields)


def _status(backend):
    return backend._file_model._entries[0]["status"]


def _assert_rejected(backend):
    assert _status(backend) == "error"
    assert backend.doneCount == 0 and backend.failCount == 1
    assert "OK →" not in backend.logText


@pytest.mark.parametrize("exception", [OSError, ValueError, TypeError, RuntimeError])
def test_validation_exception_never_reports_success(backend, monkeypatch, exception):
    def fail(path):
        raise exception("controlled validator failure")
    monkeypatch.setattr(report, "validate_packed", fail)
    backend._on_file_finished(0, _result())
    _assert_rejected(backend)
    assert "UNVERIFIED" in backend._file_model._entries[0]["statusText"]


def test_validation_import_error_never_reports_success(backend, monkeypatch):
    original = builtins.__import__
    def importing(name, *args, **kwargs):
        if name == "packer.report":
            raise ImportError("controlled missing report dependency")
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", importing)
    backend._on_file_finished(0, _result())
    _assert_rejected(backend)


@pytest.mark.parametrize("output", ["", None])
def test_missing_output_is_unverified(backend, monkeypatch, output):
    calls = []
    monkeypatch.setattr(report, "validate_packed", lambda path: calls.append(path))
    backend._on_file_finished(0, _result(output))
    _assert_rejected(backend)
    assert not calls
    assert "packed output path is missing" in backend.logText


@pytest.mark.parametrize("invalid", [None, object(), SimpleNamespace(ok="yes", reason="bad", summary=lambda: "bad")])
def test_malformed_validator_result_never_reports_success(backend, monkeypatch, invalid):
    monkeypatch.setattr(report, "validate_packed", lambda path: invalid)
    backend._on_file_finished(0, _result())
    _assert_rejected(backend)


def test_validation_summary_failure_is_unverified(backend, monkeypatch):
    def fail_summary():
        raise ValueError("controlled broken summary")
    monkeypatch.setattr(report, "validate_packed", lambda path: SimpleNamespace(ok=True, summary=fail_summary))
    backend._on_file_finished(0, _result())
    _assert_rejected(backend)


def test_explicit_invalid_container_is_rejected(backend, monkeypatch):
    monkeypatch.setattr(report, "validate_packed", lambda path: report.ValidationResult(False, "bad container"))
    backend._on_file_finished(0, _result())
    _assert_rejected(backend)
    assert "INVALID" in backend._file_model._entries[0]["statusText"]


def test_real_structural_validator_rejects_corrupt_output(backend, tmp_path):
    corrupt = tmp_path / "corrupt.packed.exe"
    corrupt.write_bytes(b"MZ\0truncated output")
    backend._on_file_finished(0, _result(str(corrupt)))
    _assert_rejected(backend)


def test_validated_success_counts_once(backend, monkeypatch):
    monkeypatch.setattr(report, "validate_packed", lambda path: report.ValidationResult(True, ""))
    backend._on_file_finished(0, _result())
    assert _status(backend) == "done"
    assert backend.doneCount == 1 and backend.failCount == 0
    assert "validated" in backend._file_model._entries[0]["statusText"]


def test_explicit_disabled_validation_does_not_run_or_claim_validation(backend, monkeypatch):
    backend.validateAfterPack = False
    calls = []
    monkeypatch.setattr(report, "validate_packed", lambda path: calls.append(path))
    backend._on_file_finished(0, _result())
    assert _status(backend) == "done"
    assert not calls
    assert "validated" not in backend._file_model._entries[0]["statusText"]


def test_pack_failure_does_not_invoke_validator(backend, monkeypatch):
    calls = []
    monkeypatch.setattr(report, "validate_packed", lambda path: calls.append(path))
    backend._on_file_finished(0, _result(ok=False, error="pack failed"))
    _assert_rejected(backend)
    assert not calls


def _start(backend, monkeypatch, *, early_signal=False, emit_custom=True):
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
    backend.packAll()
    worker = backend._worker
    assert worker.started_event.wait(3)
    return worker


@pytest.mark.parametrize("selected", [True, False])
def test_validation_choice_is_fixed_for_batch(application, backend, monkeypatch, selected):
    backend.validateAfterPack = selected
    worker = _start(backend, monkeypatch)
    backend.validateAfterPack = not selected
    calls = []
    monkeypatch.setattr(report, "validate_packed", lambda path: (calls.append(path) or report.ValidationResult(False, "bad")))
    try:
        backend._on_file_finished(0, _result())
        assert bool(calls) == selected
        assert _status(backend) == ("error" if selected else "done")
    finally:
        worker.release.set()
    _until(application, lambda: backend._worker is None)
    assert backend._active_validate_after_pack is None
    worker2 = _start(backend, monkeypatch)
    assert backend._active_validate_after_pack == (not selected)
    worker2.release.set()
    _until(application, lambda: backend._worker is None)


def test_real_qml_idle_close_is_accepted(qml_window, backend):
    assert backend.requestClose()
    assert qml_window.close()
    assert not qml_window.isVisible()


def test_real_qml_close_defers_and_cancels_without_blocking(application, backend, qml_window, monkeypatch):
    worker = _start(backend, monkeypatch)
    before = time.monotonic()
    try:
        assert not qml_window.close()
        assert time.monotonic() - before < .5
        assert qml_window.isVisible() and backend.closePending
        assert backend._worker is worker and worker.isRunning() and worker._cancel
        assert not qml_window.close()
        assert backend.logText.count("Closing after") == 1
        backend.packAll()
        assert backend._worker is worker
    finally:
        worker.release.set()
    _until(application, lambda: backend._worker is None)
    assert not backend.isPacking and not qml_window.isVisible()
    backend.packAll()
    assert backend._worker is None  # pending close never starts another batch


def test_early_custom_signal_keeps_gui_responsive(application, backend, monkeypatch):
    worker = _start(backend, monkeypatch, early_signal=True)
    ticks = []
    QTimer.singleShot(0, lambda: ticks.append(True))
    try:
        _until(application, lambda: bool(ticks))
        assert backend._worker is worker and backend.isPacking and worker.isRunning()
    finally:
        worker.release.set()
    _until(application, lambda: backend._worker is None)
    assert not backend.isPacking


def test_finished_without_custom_signal_cleans_up(application, backend, monkeypatch):
    worker = _start(backend, monkeypatch, emit_custom=False)
    worker.release.set()
    _until(application, lambda: backend._worker is None)
    assert not backend.isPacking


def test_real_qml_close_waits_for_nonblocking_native_join(application, backend, qml_window, monkeypatch):
    worker = _start(backend, monkeypatch)
    assert not qml_window.close()
    original = worker.wait
    calls = []
    def wait(timeout):
        assert timeout == 0
        calls.append(timeout)
        return False if len(calls) < 3 else original(timeout)
    monkeypatch.setattr(worker, "wait", wait)
    worker.release.set()
    _until(application, lambda: backend._worker is None)
    assert len(calls) >= 3 and not qml_window.isVisible()


def test_close_cancels_later_jobs_not_active_pack(application, backend, qml_window, monkeypatch, tmp_path):
    from packer import orchestrator
    second = tmp_path / "second.dll"
    second.write_bytes(b"Not an executable; never executed")
    backend._file_model.addFiles([str(second)])
    backend.validateAfterPack = False
    started, release = threading.Event(), threading.Event()
    calls = []
    def pack_file(path, options, *, progress):
        calls.append(path);started.set()
        assert release.wait(10)
        return _result(options.output_path)
    monkeypatch.setattr(orchestrator, "pack_file", pack_file)
    backend.packAll();worker = backend._worker
    assert started.wait(3)
    try:
        assert not qml_window.close()
        assert backend._worker is worker
    finally:
        release.set()
    _until(application, lambda: backend._worker is None)
    assert len(calls) == 1 and backend.doneCount == 1
    assert not qml_window.isVisible()


def test_reentrant_close_before_worker_start_cancels_queued_jobs(application, backend, qml_window, monkeypatch):
    from packer import orchestrator
    calls, close_results = [], []
    monkeypatch.setattr(orchestrator, "pack_file", lambda *args, **kwargs: calls.append(True))
    def packing_changed():
        if backend.isPacking:
            close_results.append(qml_window.close())
    backend.isPackingChanged.connect(packing_changed)
    backend.packAll()
    _until(application, lambda: backend._worker is None)
    assert close_results == [False]
    assert not calls and not qml_window.isVisible()


def test_reentrant_stats_close_during_batch_setup_is_deferred(application, backend, qml_window, monkeypatch):
    from packer import orchestrator
    calls, close_results = [], []
    monkeypatch.setattr(orchestrator, "pack_file", lambda *args, **kwargs: calls.append(True))
    def stats_changed():
        if backend.isPacking and backend._worker is None:
            close_results.append(qml_window.close())
    backend.statsChanged.connect(stats_changed)
    backend.packAll()
    _until(application, lambda: backend._worker is None)
    assert close_results and all(result is False for result in close_results)
    assert not calls and not qml_window.isVisible()
