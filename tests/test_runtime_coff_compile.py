"""Early contracts, not evidence of successful native runtime compilation."""
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from lifter import product_fixture_link_verify as public
from lifter import runtime_coff_compile as runtime


def _selected():
    return public.SelectedWrapperLinkInputs(
        Path("original"), tuple(Path(f"generated{i}.obj") for i in range(11)))


@pytest.mark.parametrize("session", [None, {}, True, object(), SimpleNamespace(),
                                   runtime._RuntimeCompileSession()])
def test_public_rejects_absent_or_constructed_session_before_effects(session, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("public verifier performed work before session admission")
    monkeypatch.setattr(public, "emit_product_fixture", forbidden)
    monkeypatch.setattr(public, "_read", forbidden)
    with pytest.raises(public.ProductLinkProofError, match="runtime compilation preflight"):
        public.verify_product_fixture_final_link(
            None, None, None, None, synthetic_fixture_key=b"x" * 32,
            selected_reference_inputs=_selected(), runtime_compile_session=session)


def test_old_call_without_compilation_session_is_not_accepted(monkeypatch):
    monkeypatch.setattr(public, "emit_product_fixture", lambda *a, **k: pytest.fail("unexpected emit"))
    with pytest.raises(public.ProductLinkProofError, match="active factory-owned"):
        public.verify_product_fixture_final_link(
            None, None, None, None, synthetic_fixture_key=b"x" * 32,
            selected_reference_inputs=_selected())


@pytest.mark.parametrize("session", [None, {}, True, object(),
                                   runtime._RuntimeCompileSession()])
@pytest.mark.parametrize("operation", ["validate", "build", "prove", "ready"])
def test_inactive_handle_never_performs_filesystem_or_compiler_work(
        session, operation, monkeypatch):
    monkeypatch.setattr(runtime, "_ordinary", lambda *a, **k: pytest.fail("unexpected I/O"))
    with pytest.raises(runtime.RuntimeCompileError, match="active factory-owned"):
        if operation == "validate":
            runtime.validate_runtime_compile_session(session)
        elif operation == "build":
            runtime.build_runtime_objects(session, Path("untrusted"))
        elif operation == "ready":
            runtime.require_runtime_compile_ready(session)
        else:
            runtime.prove_runtime_coff_compilation(session, (), Path("untrusted"))


def test_session_handle_has_no_mutable_configuration_or_proof_fields():
    session = runtime._RuntimeCompileSession()
    assert session.__dataclass_fields__ == {}
    with pytest.raises(FrozenInstanceError):
        session.capsule = Path("elsewhere")


@pytest.mark.parametrize("inputs", [
    None, {}, True, SimpleNamespace(), (),
    runtime.RuntimeCompileInputs(None, None, (), (), (), ()),
    runtime.RuntimeCompileInputs(Path("relative"), Path("relative"), (), (), (), ()),
])
def test_invalid_input_shape_rejects_before_effects(inputs, monkeypatch):
    monkeypatch.setattr(runtime, "_ordinary", lambda *a, **k: pytest.fail("unexpected I/O"))
    with pytest.raises(runtime.RuntimeCompileError):
        runtime.validate_runtime_compile_inputs(inputs)
    with pytest.raises(runtime.RuntimeCompileError):
        with runtime.runtime_compile_session(inputs):
            pytest.fail("invalid inputs entered a session")


@pytest.mark.parametrize("raw", [
    b"", b"x", b"\xff",
    b"[]", b"null", b"true",
    b'{"Version":"1.2","Version":"1.2","Data":{}}',
    b'{"Version":"9","Data":{}}',
    b'{"Version":"1.2","Data":null}',
    b'{"Version":"1.2","Data":{"Source":[],"ProvidedModule":"","Includes":[]}}',
    b'{"Version":"1.2","Data":{"Source":"C:\\\\x.c","ProvidedModule":"hidden","Includes":[]}}',
    b'{"Version":"1.2","Data":{"Source":"C:\\\\x.c","ProvidedModule":"","Includes":[],"PCH":"x"}}',
    b"[" * 10000 + b"0" + b"]" * 10000,
])
def test_malformed_or_unsupported_dependency_reports_are_typed_without_io(raw, monkeypatch):
    monkeypatch.setattr(runtime, "_ordinary", lambda *a, **k: pytest.fail("unexpected I/O"))
    with pytest.raises(runtime.RuntimeCompileError):
        runtime._validate_report(raw, Path("source"), (), {})


@pytest.mark.parametrize("raw", [
    b'{"Version":"1.2","Data":{"Source":null,"ProvidedModule":"","Includes":[]}}',
    b'{"Version":"1.2","Data":{"Source":7,"ProvidedModule":"","Includes":[]}}',
    b'{"Version":"1.2","Data":{"Source":"relative.c","ProvidedModule":"","Includes":[]}}',
    b'{"Version":"1.2","Data":{"Source":"C:/source.c","ProvidedModule":"","Includes":[]}}',
])
def test_dependency_source_path_has_original_canonical_spelling(raw, monkeypatch):
    monkeypatch.setattr(runtime, "_ordinary", lambda *a, **k: pytest.fail("unexpected I/O"))
    with pytest.raises(runtime.RuntimeCompileError):
        runtime._validate_report(raw, Path("source"), (), {})
