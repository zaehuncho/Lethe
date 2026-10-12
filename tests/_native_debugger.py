"""Strict, bounded event protocol for the owned Win64 native test debugger.

This module is test infrastructure, not part of the protected runtime. Only the
initial primary-thread loader breakpoint is consumed; application exceptions
must retain Windows exception dispatch and fatal exits must never look green.
"""
from __future__ import annotations

from collections import deque
import json


DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
EXCEPTION_BREAKPOINT = 0x80000003
DEBUGGER_FAULT_CODE = 0xE04C5448


class NativeDebugProtocol:
    def __init__(self, process_id: int, primary_thread_id: int) -> None:
        self.process_id = process_id
        self.primary_thread_id = primary_thread_id
        self.initial_breakpoint_seen = False
        self.second_chance_count = 0
        self.event_count = 0
        self.history: deque[dict[str, int]] = deque(maxlen=32)

    def continue_status(self, event: object) -> int:
        code = event.dwDebugEventCode
        row = {
            "index": self.event_count,
            "event": code,
            "pid": event.dwProcessId,
            "tid": event.dwThreadId,
        }
        self.event_count += 1
        self.history.append(row)
        assert row["pid"] == self.process_id, (
            "debug event belongs to another process", self.snapshot()
        )
        assert 1 <= code <= 9, ("invalid debug event", self.snapshot())
        if code != 1:  # EXCEPTION_DEBUG_EVENT
            return DBG_CONTINUE

        raw = bytes(event.payload.raw)
        assert len(raw) >= 156, "truncated Win64 EXCEPTION_DEBUG_INFO"
        exception = int.from_bytes(raw[:4], "little")
        first_chance = int.from_bytes(raw[152:156], "little")
        row.update(exception=exception, first_chance=first_chance)
        assert first_chance in (0, 1), ("invalid exception chance", self.snapshot())
        if (exception == EXCEPTION_BREAKPOINT and first_chance == 1
                and not self.initial_breakpoint_seen
                and row["tid"] == self.primary_thread_id):
            self.initial_breakpoint_seen = True
            return DBG_CONTINUE
        if first_chance == 0:
            self.second_chance_count += 1
        # Continuing as handled can skip an application fault or suppress SEH.
        return DBG_EXCEPTION_NOT_HANDLED

    def validate_exit(self, exit_code: int) -> None:
        assert self.initial_breakpoint_seen, (
            "debugger did not observe the initial loader breakpoint", self.snapshot()
        )
        assert not (self.second_chance_count and exit_code == 0), (
            "fatal debug exception reported a successful exit", self.snapshot()
        )

    def snapshot(self) -> dict:
        return {
            "pid": self.process_id,
            "primary_tid": self.primary_thread_id,
            "event_count": self.event_count,
            "initial_breakpoint_seen": self.initial_breakpoint_seen,
            "second_chance_count": self.second_chance_count,
            "last_events": [dict(row) for row in self.history],
        }


def debug_wait_error(kernel32: object, process: object, remaining_ms: int,
                     protocol: NativeDebugProtocol) -> AssertionError:
    """Read owned-child status only after failure; preserve the original error.

    Probe failure never changes a failed wait into success. No retry, additional
    wait, process manipulation, environment capture or file I/O occurs here.
    """
    import ctypes
    from ctypes import wintypes

    error = ctypes.get_last_error()
    context = protocol.snapshot()
    context.update(winerror=error, remaining_ms=remaining_ms)
    try:
        for name, handle, value_type, label in (
            ("GetExitCodeProcess", process.hProcess, wintypes.DWORD, "process"),
            ("GetExitCodeThread", process.hThread, wintypes.DWORD, "primary_thread"),
            ("CheckRemoteDebuggerPresent", process.hProcess, wintypes.BOOL, "debugger"),
        ):
            try:
                function = getattr(kernel32, name)
                function.argtypes = (wintypes.HANDLE, ctypes.POINTER(value_type))
                function.restype = wintypes.BOOL
                value = value_type()
                ok = bool(function(handle, ctypes.byref(value)))
                context[label] = {
                    "probe_ok": ok,
                    "value": value.value if ok else None,
                    "winerror": None if ok else ctypes.get_last_error(),
                }
            except Exception as probe_error:
                context[label] = {"probe_ok": False,
                                  "probe_exception": type(probe_error).__name__}
    finally:
        ctypes.set_last_error(error)
    return AssertionError("debugged child wait failed: " + json.dumps(context, sort_keys=True))
