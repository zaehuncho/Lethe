"""Debugger verdicts and timeout diagnostics must not hide native failures."""
import ctypes
import json
from types import SimpleNamespace

import pytest

from _native_debugger import (
    DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, DEBUGGER_FAULT_CODE,
    EXCEPTION_BREAKPOINT, NativeDebugProtocol, debug_wait_error,
)


def event(code=1, *, pid=101, tid=202, exception=EXCEPTION_BREAKPOINT, chance=1):
    raw = bytearray(160)
    if code == 1:
        raw[:4] = exception.to_bytes(4, "little")
        raw[152:156] = chance.to_bytes(4, "little")
    return SimpleNamespace(dwDebugEventCode=code, dwProcessId=pid,
                           dwThreadId=tid, payload=SimpleNamespace(raw=raw))


def test_only_one_primary_thread_initial_breakpoint_is_consumed():
    protocol = NativeDebugProtocol(101, 202)
    assert protocol.continue_status(event(code=3)) == DBG_CONTINUE
    assert protocol.continue_status(event(tid=303)) == DBG_EXCEPTION_NOT_HANDLED
    assert not protocol.initial_breakpoint_seen
    assert protocol.continue_status(event()) == DBG_CONTINUE
    assert protocol.initial_breakpoint_seen
    assert protocol.continue_status(event()) == DBG_EXCEPTION_NOT_HANDLED
    protocol.validate_exit(0)


@pytest.mark.parametrize("exception", [
    0xC0000005, 0xC000001D, 0xC0000094, 0xC0000409, DEBUGGER_FAULT_CODE,
])
@pytest.mark.parametrize("chance", [0, 1])
def test_application_exceptions_are_never_consumed(exception, chance):
    protocol = NativeDebugProtocol(101, 202)
    assert protocol.continue_status(event(exception=exception, chance=chance)) == DBG_EXCEPTION_NOT_HANDLED
    assert protocol.second_chance_count == (1 if chance == 0 else 0)


@pytest.mark.parametrize("code", range(2, 10))
def test_nonexception_events_continue_without_manufacturing_a_breakpoint(code):
    protocol = NativeDebugProtocol(101, 202)
    assert protocol.continue_status(event(code=code)) == DBG_CONTINUE
    assert not protocol.initial_breakpoint_seen


def test_missing_breakpoint_or_zero_exit_after_second_chance_is_rejected():
    protocol = NativeDebugProtocol(101, 202)
    with pytest.raises(AssertionError, match="initial loader breakpoint"):
        protocol.validate_exit(0)
    protocol.continue_status(event())
    protocol.continue_status(event(exception=DEBUGGER_FAULT_CODE, chance=0))
    with pytest.raises(AssertionError, match="fatal debug exception"):
        protocol.validate_exit(0)
    protocol.validate_exit(DEBUGGER_FAULT_CODE)


@pytest.mark.parametrize("chance", [0, 1])
def test_second_chance_or_later_breakpoint_is_not_swallowed(chance):
    protocol = NativeDebugProtocol(101, 202)
    protocol.continue_status(event())
    assert protocol.continue_status(event(chance=chance)) == DBG_EXCEPTION_NOT_HANDLED


def test_wrong_process_is_not_continued():
    protocol = NativeDebugProtocol(101, 202)
    with pytest.raises(AssertionError, match="another process"):
        protocol.continue_status(event(pid=999))


@pytest.mark.parametrize("code", [0, 10])
def test_unknown_event_is_not_continued(code):
    with pytest.raises(AssertionError, match="invalid debug event"):
        NativeDebugProtocol(101, 202).continue_status(event(code=code))


def test_bad_exception_payload_is_rejected():
    malformed = event()
    malformed.payload.raw = bytes(155)
    with pytest.raises(AssertionError, match="truncated"):
        NativeDebugProtocol(101, 202).continue_status(malformed)
    with pytest.raises(AssertionError, match="invalid exception chance"):
        NativeDebugProtocol(101, 202).continue_status(event(chance=2))


def test_history_stays_bounded_and_snapshots_are_independent():
    protocol = NativeDebugProtocol(101, 202)
    for _ in range(100):
        protocol.continue_status(event(code=6))
    snapshot = protocol.snapshot()
    assert snapshot["event_count"] == 100
    assert len(snapshot["last_events"]) == 32
    assert snapshot["last_events"][0]["index"] == 68
    snapshot["last_events"][-1]["event"] = 999
    assert protocol.snapshot()["last_events"][-1]["event"] == 6


class Probe:
    def __init__(self, value, error, last_error, *, raises=False):
        self.value = value
        self.error = error
        self.last_error = last_error
        self.raises = raises
        self.calls = []

    def __call__(self, handle, output):
        self.calls.append(handle)
        self.last_error[0] = self.error
        if self.raises:
            raise RuntimeError("injected diagnostic-only probe failure")
        output._obj.value = self.value
        return 0 if self.error else 1


@pytest.mark.parametrize("mode", ["active", "exited_main", "probe_failure", "probe_exception"])
def test_wait_failure_keeps_original_error_and_verdict(monkeypatch, mode):
    last_error = [121]
    monkeypatch.setattr(ctypes, "get_last_error", lambda: last_error[0], raising=False)
    monkeypatch.setattr(ctypes, "set_last_error", lambda value: last_error.__setitem__(0, value), raising=False)
    probes = {
        "GetExitCodeProcess": Probe(259, 0, last_error),
        "GetExitCodeThread": Probe(0 if mode == "exited_main" else 259,
                                  6 if mode == "probe_failure" else 0, last_error,
                                  raises=mode == "probe_exception"),
        "CheckRemoteDebuggerPresent": Probe(1, 0, last_error),
    }
    process = SimpleNamespace(hProcess=0x100000001, hThread=0x100000002)
    protocol = NativeDebugProtocol(101, 202)
    protocol.continue_status(event(code=3))
    protocol.continue_status(event())
    failure = debug_wait_error(SimpleNamespace(**probes), process, 29984, protocol)
    assert isinstance(failure, AssertionError)
    context = json.loads(str(failure).split(": ", 1)[1])
    assert context["winerror"] == 121 and context["remaining_ms"] == 29984
    assert context["pid"] == 101 and context["primary_tid"] == 202
    assert context["event_count"] == 2 and len(context["last_events"]) == 2
    assert context["process"]["value"] == 259
    assert context["debugger"]["value"] == 1
    assert context["primary_thread"]["probe_ok"] == (mode not in ("probe_failure", "probe_exception"))
    if mode == "exited_main":
        assert context["primary_thread"]["value"] == 0
    if mode == "probe_failure":
        assert context["primary_thread"]["winerror"] == 6
    if mode == "probe_exception":
        assert context["primary_thread"]["probe_exception"] == "RuntimeError"
    assert last_error[0] == 121
    assert probes["GetExitCodeProcess"].calls == [0x100000001]
    assert probes["GetExitCodeThread"].calls == [0x100000002]
    assert probes["CheckRemoteDebuggerPresent"].calls == [0x100000001]


@pytest.mark.parametrize("prior_events", [False, True])
def test_real_runner_wait_failure_reports_context_and_stays_failed(monkeypatch, tmp_path, prior_events):
    from test_native_runtime_hardening_stress import _run_packed_forced_aslr

    last_error = [0]
    monkeypatch.setattr(ctypes, "get_last_error", lambda: last_error[0], raising=False)
    monkeypatch.setattr(ctypes, "set_last_error", lambda value: last_error.__setitem__(0, value), raising=False)
    closed = []
    waits = []
    continued = []
    pending = [event(code=3), event()] if prior_events else []
    pipe_counter = [1000]

    class Function:
        def __init__(self, callback):
            self.callback = callback

        def __call__(self, *args):
            return self.callback(*args)

    def create_pipe(read, write, *_):
        read._obj.value = pipe_counter[0]
        write._obj.value = pipe_counter[0] + 1
        pipe_counter[0] += 2
        return 1

    def attributes(_storage, _count, _flags, size):
        size._obj.value = 64
        return 1

    def create_process(*args):
        process = args[-1]._obj
        process.hProcess, process.hThread = 0x100000001, 0x100000002
        process.dwProcessId, process.dwThreadId = 101, 202
        return 1

    def wait(output, timeout_ms):
        waits.append(timeout_ms)
        if pending:
            current = pending.pop(0)
            target = output._obj
            target.dwDebugEventCode = current.dwDebugEventCode
            target.dwProcessId, target.dwThreadId = 101, 202
            ctypes.memmove(ctypes.addressof(target.payload), bytes(current.payload.raw), 160)
            return 1
        last_error[0] = 121
        return 0

    def close(handle):
        closed.append(handle.value if hasattr(handle, "value") else handle)
        return 1

    library = SimpleNamespace(**{
        "CreatePipe": Function(create_pipe),
        "InitializeProcThreadAttributeList": Function(attributes),
        "UpdateProcThreadAttribute": Function(lambda *_: 1),
        "SetHandleInformation": Function(lambda *_: 1),
        "CreateProcessW": Function(create_process),
        "CloseHandle": Function(close),
        "GetStdHandle": Function(lambda *_: 123),
        "WaitForSingleObject": Function(lambda *_: pytest.fail("unexpected extra wait")),
        "WaitForDebugEvent": Function(wait),
        "ContinueDebugEvent": Function(lambda *args: continued.append(args) or 1),
        "GetExitCodeProcess": Probe(259, 0, last_error),
        "GetExitCodeThread": Probe(0, 0, last_error),
        "CheckRemoteDebuggerPresent": Probe(1, 0, last_error),
        "DeleteProcThreadAttributeList": Function(lambda *_: None),
    })
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: library, raising=False)
    with pytest.raises(AssertionError, match="debugged child wait failed") as failure:
        _run_packed_forced_aslr(tmp_path / "owned-fixture.exe", memory_guard=False,
                                process_hardening=False, debugged=True)
    context = json.loads(str(failure.value).split(": ", 1)[1])
    assert context["winerror"] == 121
    assert context["event_count"] == (2 if prior_events else 0)
    assert context["initial_breakpoint_seen"] == prior_events
    assert context["process"]["value"] == 259
    assert context["primary_thread"]["value"] == 0
    assert 0 < context["remaining_ms"] <= 30000
    assert len(waits) == (3 if prior_events else 1)  # No retry after failed wait.
    assert len(continued) == (2 if prior_events else 0)
    assert 0x100000001 in closed and 0x100000002 in closed
    assert len(closed) == 6
    assert last_error[0] == 121
