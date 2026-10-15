"""Real-filesystem disposable TMP contracts, not native compiler evidence."""
from pathlib import Path
from types import SimpleNamespace
import json
import os
import struct

import pytest

from lifter import runtime_coff_compile as runtime
from lifter import runtime_compiler_trace as trace

NAME = "{C01F8CE2-7C9A-4AFC-94B2-9AC5BB191A4A}"
RAW = b"-nologo -c -O2 -GL- -Z7 -Gy -Gw -GS -MD -guard:xfg -ZH:SHA_256 -Brepro -TC -X\r\n"


def state(tmp_path):
    s = object.__new__(runtime._State)
    w = tmp_path / "capsule"
    w.mkdir()
    for name in ("stub", "stub/src", "tmp", "logs", "out", "deps"):
        (w / name).mkdir()
    (w / ".runtime-compile.lease").write_bytes(b"")
    t = tmp_path / "tools"
    t.mkdir()
    helper = t / "vctip.exe"
    helper.write_bytes(b"controlled-helper")
    s.inputs = SimpleNamespace(capsule=w, tool_directory=t,
        tool_files=(runtime.RuntimeFilePin(helper, runtime._sha(helper.read_bytes())),))
    s.directories = {p: (p.stat().st_dev, p.stat().st_ino) for p in
                     (w, *(w / n for n in ("stub", "stub/src", "tmp", "logs", "out", "deps")))}
    s.source_pins, s.logs, s.temporary, s.known = {}, {}, {}, None
    return s


def result(s, with_helper=True):
    p = s.inputs.tool_directory / "vctip.exe"
    image = {"path": str(p), "sha256": runtime._sha(p.read_bytes()),
             "volume": 7, "index": p.stat().st_ino, "size": p.stat().st_size,
             "classification": "pinned_compiler_module", "pid": 2}
    processes = [{"pid": 1, "parent_pid": 999, "exit_code": 0,
                  "exit_continued": True, "wait_terminal": True}]
    events = []
    if with_helper:
        processes.append({"pid": 2, "parent_pid": 1, "exit_code": 0,
                          "exit_continued": True, "wait_terminal": True})
        events.append({"event": 3, "pid": 2, "image": image})
    return SimpleNamespace(processes=tuple(processes), trace_events=tuple(events))


def test_empty_tmp_can_be_checked_captured_and_cleared(tmp_path):
    s = state(tmp_path)
    s._check_temporary_outputs()
    observed = s._capture_temporary_outputs("000-control", result(s, False))
    assert observed["outputs"] == {} and observed["helper_associations"] == []
    assert not observed["file_writer_attribution_proven"]
    s._clear_temporary_outputs()
    assert not tuple((s.inputs.capsule / "tmp").iterdir())


def test_actual_marker_capture_retains_bytes_identity_and_then_clears_only_known(tmp_path):
    s = state(tmp_path)
    p = s.inputs.capsule / "tmp" / NAME
    p.write_bytes(RAW)
    observed = s._capture_temporary_outputs("000-control", result(s))
    assert set(observed["outputs"]) == {NAME}
    assert observed["outputs"][NAME]["inode"] == p.stat().st_ino
    assert observed["helper_associations"][0]["pid"] == 2
    assert not observed["transient_file_IO_closure_proven"]
    assert (s.inputs.capsule / "logs/000-control.tmp-0.bin").read_bytes() == RAW
    assert json.loads((s.inputs.capsule / "logs/000-control.tmp.json").read_bytes()) == observed
    s._clear_temporary_outputs()
    assert not p.exists() and s.temporary == {}
    assert (s.inputs.capsule / "logs/000-control.tmp-0.bin").read_bytes() == RAW


@pytest.mark.parametrize("kind", ["unknown", "modified", "removed", "replaced", "mtime", "directory", "hardlink"])
def test_full_preflight_rejects_unknown_changed_or_replaced_tmp_without_deletion(tmp_path, kind):
    s = state(tmp_path)
    p = s.inputs.capsule / "tmp" / NAME
    p.write_bytes(RAW)
    s._capture_temporary_outputs("000-control", result(s))
    if kind == "unknown":
        (p.parent / "unknown").write_bytes(b"preserve")
    elif kind == "modified":
        p.write_bytes(b"changed")
    elif kind == "removed":
        p.unlink()
    elif kind == "replaced":
        other = tmp_path / "replacement"
        other.write_bytes(RAW)
        os.utime(other, ns=(p.stat().st_atime_ns, p.stat().st_mtime_ns))
        os.replace(other, p)
    elif kind == "mtime":
        st = p.stat()
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
    elif kind == "directory":
        p.unlink()
        p.mkdir()
    elif kind == "hardlink":
        os.link(p, tmp_path / "other-link")
    before = {q.name: (q.is_dir(), q.read_bytes() if q.is_file() else None)
              for q in p.parent.iterdir()}
    with pytest.raises(runtime.RuntimeCompileError):
        s._clear_temporary_outputs()
    after = {q.name: (q.is_dir(), q.read_bytes() if q.is_file() else None)
             for q in p.parent.iterdir()}
    assert after == before


@pytest.mark.parametrize("kind", ["bad-name", "lowercase-name", "bad-bytes", "no-helper", "two-files", "directory", "hardlink"])
def test_unsupported_post_job_tmp_is_not_enrolled_or_deleted(tmp_path, kind):
    s = state(tmp_path)
    name = "unknown" if kind == "bad-name" else NAME.lower() if kind == "lowercase-name" else NAME
    p = s.inputs.capsule / "tmp" / name
    if kind == "directory":
        p.mkdir()
    else:
        p.write_bytes(b"unknown" if kind == "bad-bytes" else RAW)
    if kind == "two-files":
        (p.parent / "extra").write_bytes(RAW)
    elif kind == "hardlink":
        os.link(p, tmp_path / "other-link")
    before = sorted(q.name for q in p.parent.iterdir())
    with pytest.raises(runtime.RuntimeCompileError):
        s._capture_temporary_outputs("000-control", result(s, kind != "no-helper"))
    assert s.temporary == {} and sorted(q.name for q in p.parent.iterdir()) == before
    assert not tuple((s.inputs.capsule / "logs").iterdir())


@pytest.mark.parametrize("key,value", [
    ("path", "C:\\unknown\\vctip.exe"), ("sha256", "0" * 64),
    ("classification", "trusted_windows"), ("pid", 3),
    ("volume", 0), ("index", -1), ("size", 0),
])
def test_helper_event_must_match_exact_same_job_physical_pin(tmp_path, key, value):
    s = state(tmp_path)
    (s.inputs.capsule / "tmp" / NAME).write_bytes(RAW)
    r = result(s)
    r.trace_events[0]["image"][key] = value
    with pytest.raises(runtime.RuntimeCompileError):
        s._capture_temporary_outputs("000-control", r)
    assert s.temporary == {}


@pytest.mark.parametrize("key,value", [("exit_code", 1), ("exit_continued", False), ("wait_terminal", False), ("parent_pid", 999)])
def test_helper_must_have_a_terminal_owned_child_record(tmp_path, key, value):
    s = state(tmp_path)
    (s.inputs.capsule / "tmp" / NAME).write_bytes(RAW)
    r = result(s)
    r.processes[1][key] = value
    with pytest.raises(runtime.RuntimeCompileError):
        s._capture_temporary_outputs("000-control", r)
    assert s.temporary == {}


def test_replaced_tmp_directory_rejects_without_deleting_its_unknown_files(tmp_path):
    s = state(tmp_path)
    p = s.inputs.capsule / "tmp"
    p.rename(s.inputs.capsule / "old-tmp")
    p.mkdir()
    (p / "unknown").write_bytes(b"preserve")
    with pytest.raises(runtime.RuntimeCompileError, match="directory replaced"):
        s._clear_temporary_outputs()
    assert (p / "unknown").read_bytes() == b"preserve"


def test_log_failure_does_not_authorize_tmp_cleanup(tmp_path, monkeypatch):
    s = state(tmp_path)
    p = s.inputs.capsule / "tmp" / NAME
    p.write_bytes(RAW)
    def fail(*args):
        raise runtime.RuntimeCompileError("log creation failed")
    monkeypatch.setattr(s, "_log", fail)
    with pytest.raises(runtime.RuntimeCompileError, match="log creation failed"):
        s._capture_temporary_outputs("000-control", result(s))
    assert s.temporary == {} and p.read_bytes() == RAW
    with pytest.raises(runtime.RuntimeCompileError, match="unknown/missing"):
        s._clear_temporary_outputs()


@pytest.mark.parametrize("change", ["bytes", "remove", "same-byte-replace"])
def test_final_capture_failure_never_enrolls_staged_tmp_authority(tmp_path, monkeypatch, change):
    s = state(tmp_path)
    p = s.inputs.capsule / "tmp" / NAME
    p.write_bytes(RAW)
    log = s._log
    def change_after_log(name, raw):
        log(name, raw)
        if name.endswith(".tmp.json"):
            if change == "bytes":
                p.write_bytes(b"changed-after-log")
            elif change == "remove":
                p.unlink()
            else:
                replacement = tmp_path / "replacement"
                replacement.write_bytes(RAW)
                os.utime(replacement, ns=(p.stat().st_atime_ns, p.stat().st_mtime_ns))
                os.replace(replacement, p)
    monkeypatch.setattr(s, "_log", change_after_log)
    with pytest.raises(runtime.RuntimeCompileError):
        s._capture_temporary_outputs("000-control", result(s))
    assert s.temporary == {}
    assert (s.inputs.capsule / "logs/000-control.tmp-0.bin").read_bytes() == RAW
    if p.exists():
        before = p.read_bytes()
        with pytest.raises(runtime.RuntimeCompileError, match="unknown/missing"):
            s._clear_temporary_outputs()
        assert p.read_bytes() == before


def test_public_ready_rechecks_built_session_before_accepting(monkeypatch):
    calls = []
    s = SimpleNamespace(built=True, recheck=lambda: calls.append("recheck"))
    monkeypatch.setattr(runtime, "_session_state", lambda handle: s)
    runtime.require_runtime_compile_ready(object())
    assert calls == ["recheck"]


class _ModeledResult(SimpleNamespace):
    def to_record(self):
        return {"status": self.status, "exit_code": self.exit_code,
                "processes": list(self.processes), "trace_events": list(self.trace_events),
                "cleanup": self.cleanup, "model_only": True}


def _compile_model_state(tmp_path, monkeypatch, mode="valid"):
    """Exercise real orchestration/files, not a compiler or genuine COFF."""
    s = state(tmp_path)
    w, tool = s.inputs.capsule, s.inputs.tool_directory
    for name in ("cl.exe", "ml64.exe"):
        (tool / name).write_bytes(("controlled-not-executable-" + name).encode())
    s.inputs = SimpleNamespace(capsule=w, tool_directory=tool, include_roots=(),
        external_headers=(), support_files=(), native_image_pins=(), tool_files=tuple(runtime.RuntimeFilePin(p, runtime._sha(p.read_bytes()))
                                             for p in tool.iterdir()),
        ordered_includes=tuple((name, ()) for name, _ in runtime._ROLES[:4]))
    for name, suffix in runtime._ROLES:
        p = w / "stub/src" / (name + suffix)
        p.write_bytes(b"modeled source; no compiler execution")
        s.source_pins[p.relative_to(w).as_posix()] = runtime._sha(p.read_bytes())
    s.runs, s.exports, s.closed, s.built, s.failed = [], {}, False, True, False
    s.native_locks = {}
    # Retain actual recheck, tool-directory and TMP code. Only the executing
    # source inventory, dependency parser and native process are modeled.
    monkeypatch.setattr(runtime.source_link_build, "_source_tree_hashes",
                        lambda *a, **k: dict(s.source_pins))
    calls = []
    def native(argv, cwd, env, *, policy, timeout, max_log):
        index = len(calls)
        assert not tuple((w / "tmp").iterdir()), "TMP not empty at modeled dispatch"
        if index:
            prior = list((w / "logs").glob("*.tmp-0.bin"))
            assert len(prior) == index and all(p.read_bytes() == RAW for p in prior)
        output = Path(next(a[3:] for a in argv if a.startswith("/Fo")))
        output.write_bytes(b"\x64\x86" + struct.pack("<H", 0) + b"\0" * 16)
        if "/sourceDependencies" in argv:
            Path(argv[argv.index("/sourceDependencies") + 1]).write_bytes(b"{}")
        (w / "tmp" / NAME).write_bytes(RAW)
        calls.append({"index": index, "role": output.stem, "model_only": True})
        if mode == "trace-error":
            raise trace.CompilerTraceError("controlled trace failure", {"model_only": True},
                stdout=b"controlled stdout\n", stderr=b"controlled stderr\n")
        r = result(s)
        cleanup = {"reaped": mode != "not-reaped", "job_accounting": {
            "active_processes": 1 if mode == "active-job" else 0,
            "total_processes": 1 if mode == "wrong-total" else 2}}
        return _ModeledResult(status="exited", exit_code=0, stdout=b"controlled stdout\n",
            stderr=b"", processes=r.processes, trace_events=r.trace_events, cleanup=cleanup)
    monkeypatch.setattr(trace, "run_traced_compiler", native)
    monkeypatch.setattr(runtime, "_validate_report", lambda *a, **k: {"model_only": True})
    return s, calls


def test_modeled_two_runtime8_loops_start_every_role_with_empty_tmp(tmp_path, monkeypatch):
    s, calls = _compile_model_state(tmp_path, monkeypatch)
    first, second = s.compile(), s.compile()
    assert len(calls) == 16
    assert [row["role"] for row in calls] == [n for n, _ in runtime._ROLES] * 2
    assert len(first[0]) == len(second[0]) == len(first[2]) == len(second[2]) == 8
    assert len(s.runs) == len(list((s.inputs.capsule / "logs").glob("*.tmp-0.bin"))) == 16
    assert all(row["temporary_outputs"]["scope"] == "quiescent_same_job_interval_only"
               and not row["temporary_outputs"]["file_writer_attribution_proven"] for row in s.runs)
    assert len(s.temporary) == 1


@pytest.mark.parametrize("mode", ["not-reaped", "active-job", "wrong-total"])
def test_modeled_incomplete_job_keeps_tmp_unregistered(tmp_path, monkeypatch, mode):
    s, calls = _compile_model_state(tmp_path, monkeypatch, mode)
    with pytest.raises(runtime.RuntimeCompileError, match="physically terminal owned Job"):
        s.compile()
    assert len(calls) == 1 and s.failed and s.temporary == {}
    assert (s.inputs.capsule / "tmp" / NAME).read_bytes() == RAW
    assert not list((s.inputs.capsule / "logs").glob("*.tmp*"))
    assert list((s.inputs.capsule / "logs").glob("*.stdout"))


def test_modeled_failed_trace_preserves_raw_logs_and_rejects_retry(tmp_path, monkeypatch):
    s, calls = _compile_model_state(tmp_path, monkeypatch, "trace-error")
    with pytest.raises(runtime.RuntimeCompileError, match="controlled trace failure"):
        s.compile()
    assert s.failed and s.temporary == {}
    assert (s.inputs.capsule / "logs/000-daedalus_vm.stdout").read_bytes() == b"controlled stdout\n"
    assert (s.inputs.capsule / "logs/000-daedalus_vm.stderr").read_bytes() == b"controlled stderr\n"
    assert (s.inputs.capsule / "logs/000-daedalus_vm.trace-error.json").exists()
    with pytest.raises(runtime.RuntimeCompileError, match="failed"):
        s.compile()
    assert len(calls) == 1 and (s.inputs.capsule / "tmp" / NAME).read_bytes() == RAW


def test_modeled_caught_compile_failure_rejects_reuse_even_when_tmp_empty(tmp_path, monkeypatch):
    s, calls = _compile_model_state(tmp_path, monkeypatch)
    capture = s._capture_temporary_outputs
    def fail(label, result):
        (s.inputs.capsule / "tmp" / NAME).unlink()
        raise runtime.RuntimeCompileError("controlled removed-file capture failure")
    monkeypatch.setattr(s, "_capture_temporary_outputs", fail)
    with pytest.raises(runtime.RuntimeCompileError, match="removed-file capture failure"):
        s.compile()
    assert s.failed and s.temporary == {} and not tuple((s.inputs.capsule / "tmp").iterdir())
    monkeypatch.setattr(s, "_capture_temporary_outputs", capture)
    with pytest.raises(runtime.RuntimeCompileError, match="failed"):
        s.compile()
    with pytest.raises(runtime.RuntimeCompileError, match="failed"):
        s.recheck()
    assert len(calls) == 1
