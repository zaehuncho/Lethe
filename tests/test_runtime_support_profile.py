"""Closed support-profile input contracts, not native compilation evidence."""
from dataclasses import replace
from pathlib import Path
import os
from types import SimpleNamespace

import pytest

from lifter import runtime_coff_compile as runtime

pytestmark = pytest.mark.skipif(os.name != "nt", reason="exact closed Win64 compiler profile")
T = Path(r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64")
SDK = Path(r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0")
SUPPORT = Path(r"C:\ProgramData\Microsoft\VisualStudio\Setup\x64\Microsoft.VisualStudio.Setup.Configuration.Native.dll")


def inputs():
    header = SDK / "ucrt/stdio.h"
    return runtime.RuntimeCompileInputs(Path(r"D:\a\support_shape_capsule"), T,
        (T.parents[2] / "include", *(SDK / name for name in ("ucrt", "shared", "um", "winrt", "cppwinrt"))),
        tuple(runtime.RuntimeFilePin(T / name, "a" * 64) for name in ("cl.exe", "ml64.exe", "vctip.exe")),
        (runtime.RuntimeFilePin(header, "b" * 64),),
        tuple((role, (str(header),)) for role, _ in runtime._ROLES[:4]),
        support_files=(runtime.RuntimeFilePin(SUPPORT, "c" * 64),))


def test_exact_support_profile_shape_needs_no_filesystem_or_child(monkeypatch):
    monkeypatch.setattr(runtime, "_ordinary", lambda *a, **k: pytest.fail("shape validator performed I/O"))
    value = inputs()
    runtime.validate_runtime_compile_inputs(value)
    assert value.profile == "msvc-14.44.35207-sdk-10.0.26100.0-raw-v2"


@pytest.mark.parametrize("support", [
    None, [], {}, True, (),
    (None,), (SimpleNamespace(path=SUPPORT, sha256="c" * 64),),
    (runtime.RuntimeFilePin(SUPPORT, "c" * 64),) * 2,
    (runtime.RuntimeFilePin(SUPPORT, "c" * 64), runtime.RuntimeFilePin(SUPPORT.parent / "other.dll", "d" * 64)),
    (runtime.RuntimeFilePin(SUPPORT.parent / "other.dll", "c" * 64),),
    (runtime.RuntimeFilePin(T / SUPPORT.name, "c" * 64),),
    (runtime.RuntimeFilePin(Path(r"C:\Windows\System32") / SUPPORT.name, "c" * 64),),
    (runtime.RuntimeFilePin(Path(r"C:\ProgramData\Microsoft\VisualStudio\Setup\x86") / SUPPORT.name, "c" * 64),),
    (runtime.RuntimeFilePin(Path("relative.dll"), "c" * 64),),
    (runtime.RuntimeFilePin(str(SUPPORT), "c" * 64),),
    (runtime.RuntimeFilePin(SUPPORT, None),),
    (runtime.RuntimeFilePin(SUPPORT, "C" * 64),),
    (runtime.RuntimeFilePin(SUPPORT, "c" * 63),),
    (runtime.RuntimeFilePin(SUPPORT, "g" * 64),),
])
def test_missing_extra_stale_or_malformed_support_profile_rejects_before_effects(support, monkeypatch):
    monkeypatch.setattr(runtime, "_ordinary", lambda *a, **k: pytest.fail("invalid support performed I/O"))
    value = replace(inputs(), support_files=support)
    with pytest.raises(runtime.RuntimeCompileError):
        runtime.validate_runtime_compile_inputs(value)
    with pytest.raises(runtime.RuntimeCompileError):
        with runtime.runtime_compile_session(value):
            pytest.fail("invalid support created active session")


@pytest.mark.parametrize("profile", ["msvc-14.44.35207-sdk-10.0.26100.0-raw-v1", "unknown", None, True])
def test_legacy_or_untyped_profile_cannot_opt_in_to_new_support(profile, monkeypatch):
    monkeypatch.setattr(runtime, "_ordinary", lambda *a, **k: pytest.fail("legacy profile performed I/O"))
    with pytest.raises(runtime.RuntimeCompileError, match="supported RuntimeCompileInputs"):
        runtime.validate_runtime_compile_inputs(replace(inputs(), profile=profile))


def test_state_deepcopies_support_record_and_tuple_authority():
    value = inputs()
    original = value.support_files[0]
    state = runtime._State(value)
    original.__dict__["sha256"] = "d" * 64
    original.__dict__["path"] = SUPPORT.parent / "elsewhere.dll"
    value.__dict__["support_files"] = ()
    assert state.inputs.support_files[0].sha256 == "c" * 64
    assert state.inputs.support_files[0].path == SUPPORT
    assert state.inputs.support_files is not value.support_files
    assert state.inputs.support_files[0] is not original


def test_support_is_not_silently_folded_into_tool_directory_inventory(monkeypatch):
    value = inputs()
    monkeypatch.setattr(runtime, "_ordinary", lambda *a, **k: pytest.fail("shape validator performed I/O"))
    with pytest.raises(runtime.RuntimeCompileError, match="escapes compiler directory"):
        runtime.validate_runtime_compile_inputs(replace(value, tool_files=value.tool_files + value.support_files))


def test_support_constructor_preserves_existing_positional_profile_field():
    value = inputs()
    positional = runtime.RuntimeCompileInputs(value.capsule, value.tool_directory, value.include_roots,
        value.tool_files, value.external_headers, value.ordered_includes, value.profile, value.support_files)
    assert positional == value


@pytest.mark.parametrize("operation", ["validate", "build", "prove", "ready"])
def test_failed_session_support_cannot_be_reused_before_any_io(operation, monkeypatch):
    value = inputs()
    state = runtime._State(value)
    state.failed = True
    handle = runtime._RuntimeCompileSession()
    monkeypatch.setattr(runtime, "_ordinary", lambda *a, **k: pytest.fail("failed handle performed I/O"))
    runtime._ACTIVE[id(handle)] = (handle, state)
    try:
        with pytest.raises(runtime.RuntimeCompileError, match="failed compiler session"):
            if operation == "validate":
                runtime.validate_runtime_compile_session(handle)
            elif operation == "build":
                runtime.build_runtime_objects(handle, Path(r"D:\a\unused"))
            elif operation == "ready":
                runtime.require_runtime_compile_ready(handle)
            else:
                runtime.prove_runtime_coff_compilation(handle, (), Path(r"D:\a\unused"))
    finally:
        runtime._ACTIVE.pop(id(handle), None)
