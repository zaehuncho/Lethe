"""Failure-only lifetime cleanup for an exact CreateProcess-owned test child.

Debug events are serviced on the creating thread. This is not a child-tree or
pipe-writer lifetime guarantee. A cleanup report never changes the test verdict.
"""
from __future__ import annotations

import ctypes
import time

from _native_debugger import DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED


CLEANUP_EXIT_CODE = 0xE014
CLEANUP_TIMEOUT_MS = 5000


def reap_failed_native_child(kernel32, process, *, debugged, event_factory,
                             pending_event=None, pending_status=None,
                             close_event_file):
    """Terminate/reap only the retained owned process handle within one budget.

    The caller retains and closes PROCESS_INFORMATION handles. Event-supplied
    process/thread handles belong to Windows; only event hFiles are closed here.
    Application exceptions are never consumed, including during shutdown.
    """
    report = {"pid": int(process.dwProcessId), "terminate_requested": False,
              "debug_events_continued": 0, "exit_event_continued": False,
              "detached": False, "reaped": False, "errors": []}
    deadline = time.monotonic() + CLEANUP_TIMEOUT_MS / 1000

    def error(message):
        if len(report["errors"]) < 32:
            report["errors"].append(message)

    def remaining():
        return max(0, int((deadline - time.monotonic()) * 1000))

    def call(name, *args):
        try:
            return getattr(kernel32, name)(*args)
        except BaseException as exc:
            error(f"{name} raised {type(exc).__name__}: {exc}")
            return None

    def wait(milliseconds):
        result = call("WaitForSingleObject", process.hProcess, milliseconds)
        if result not in (0, 258):
            error(f"owned process wait result={result} winerror={ctypes.get_last_error()}")
        return result

    initial = wait(0)
    report["initial_wait_result"] = initial
    if initial != 0:
        terminated = call("TerminateProcess", process.hProcess, CLEANUP_EXIT_CODE)
        report["terminate_requested"] = bool(terminated)
        if not terminated:
            error(f"TerminateProcess failed winerror={ctypes.get_last_error()}")

    def service(event, status=None):
        code = int(event.dwDebugEventCode)
        if int(event.dwProcessId) != int(process.dwProcessId):
            error("refused to continue debug event for another process")
            return False
        if not 1 <= code <= 9:
            error(f"refused invalid debug event code={code}")
            return False
        try:
            close_event_file(event)
        except BaseException as exc:
            error(f"debug event hFile cleanup raised {type(exc).__name__}: {exc}")
        # Preserve a status already decided by the normal protocol. Newly
        # drained exceptions are passed through, never DBG_CONTINUE-masked.
        if status is None:
            status = DBG_EXCEPTION_NOT_HANDLED if code == 1 else DBG_CONTINUE
        if code == 1 and status not in (DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED):
            error("refused invalid pending exception continuation status")
            return False
        continued = call("ContinueDebugEvent", event.dwProcessId,
                         event.dwThreadId, status)
        if not continued:
            error(f"ContinueDebugEvent failed winerror={ctypes.get_last_error()}")
            return False
        report["debug_events_continued"] += 1
        if code == 5:
            report["exit_event_continued"] = True
        return True

    debug_ok = True
    if debugged:
        if pending_event is not None:
            debug_ok = service(pending_event, pending_status)
        while debug_ok and not report["exit_event_continued"] and remaining():
            if initial == 0 and pending_event is None:
                break
            event = event_factory()
            delivered = call("WaitForDebugEvent", ctypes.byref(event),
                             min(100, remaining()))
            if not delivered:
                code = ctypes.get_last_error()
                if code == 121:  # Bounded debug-event timeout, not a retry of the test.
                    if wait(0) == 0:
                        break
                    continue
                error(f"shutdown WaitForDebugEvent failed winerror={code}")
                debug_ok = False
                break
            debug_ok = service(event)
        # A failed/undeliverable pending event can keep kernel shutdown blocked.
        # Detach only this exact still-owned PID, after requesting termination.
        if not report["exit_event_continued"] and wait(0) != 0:
            detached = call("DebugActiveProcessStop", process.dwProcessId)
            report["detached"] = bool(detached)
            if not detached:
                error(f"DebugActiveProcessStop failed winerror={ctypes.get_last_error()}")
    final = wait(remaining())
    report["final_wait_result"] = final
    report["reaped"] = final == 0
    if not report["reaped"]:
        error("owned child was not proven terminal within cleanup budget")
    return report
