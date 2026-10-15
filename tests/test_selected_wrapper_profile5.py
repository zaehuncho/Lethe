"""Portable schema-5 consumer regressions; no installed NI or native evidence.

The actual maintained consumer is imported. Every launch entrypoint is a
tripwire; generated JSON and synthetic dictionaries exercise only its contract.
"""
from __future__ import annotations

from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys

import pytest

_D = "1" * 64
_V4 = "msvc-14.44.35207-sdk-10.0.26100.0-raw-v4"
_V5 = "msvc-14.44.35207-sdk-10.0.26100.0-raw-v5"
_REMOTE = (r"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.V8f370856#"
           + "\\" + "a" * 32 + r"\Microsoft.VisualStudio.RemoteControl.ni.dll")
_NEWTON = (r"C:\Windows\assembly\NativeImages_v4.0.30319_64\Newtonsoft.Json"
           + "\\" + "b" * 32 + r"\Newtonsoft.Json.ni.dll")
_FRAMEWORK = (r"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Runteb92aa12#"
              + "\\" + "c" * 32 + r"\System.Runtime.Serialization.ni.dll")
_ILS = ("Microsoft.VisualStudio.RemoteControl.dll", "Newtonsoft.Json.dll")
_FALSE = ("NI_compilation_authenticity_proven", "IL_native_semantic_equivalence_proven",
          "NGEN_dependency_closure_proven", "JIT_closure_proven",
          "managed_assembly_closure_proven", "loaded_memory_attestation_proven",
          "full_OS_attestation_proven")


@pytest.fixture
def subject(pytestconfig, monkeypatch):
    path = Path(pytestconfig.rootpath) / "tests/test_selected_wrapper_materialized.py"
    digest = sha256(path.read_bytes()).hexdigest()
    spec = importlib.util.spec_from_file_location("_selected_wrapper_profile5_subject", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    assert Path(module.__file__) == path and module.__spec__.origin == str(path)
    assert sha256(path.read_bytes()).hexdigest() == digest
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("native-entrypoint")
        raise AssertionError("schema-5 consumer controls attempted native effects")

    for target, name in ((module, "_command"), (module, "emit_product_fixture"),
                         (module.bounded, "_run_bounded"),
                         (module.public, "verify_product_fixture_final_link"),
                         (module.runtime, "runtime_compile_session"),
                         (module.runtime, "build_runtime_objects"),
                         (module.runtime, "prove_runtime_coff_compilation")):
        monkeypatch.setattr(target, name, forbidden)
    yield module
    assert calls == []
    assert sha256(path.read_bytes()).hexdigest() == digest


def _inputs(subject):
    tool = Path(r"C:\fixture-model\tool")
    tools = {str(tool / ("tool-%02d.dll" % i)): _D for i in range(89)}
    tools.update({str(tool / name): _D for name in _ILS})
    headers = {str(Path(r"C:\fixture-model\include") / ("h%03d.h" % i)): _D
               for i in range(160)}
    plan = {"schema": 5, "profile": _V5, "tool_directory": str(tool),
            "include_roots": [str(Path(r"C:\fixture-model") / ("include%d" % i))
                              for i in range(6)],
            "tool_pins": tools, "external_headers": headers,
            "ordered_includes": [[role, [next(iter(headers))]]
                                 for role in subject._ROLES[:4]],
            "support_files": {str(subject._SETUP_SUPPORT): _D},
            "native_image_pins": {_REMOTE: _D, _NEWTON: "2" * 64},
            "framework_native_image_pins": {_FRAMEWORK: "3" * 64}}
    pins = {Path(name): digest
            for inventory in (plan["support_files"], plan["native_image_pins"],
                              plan["framework_native_image_pins"])
            for name, digest in inventory.items()}
    return plan, pins


def _file(tmp_path, plan, pins, raw=None):
    path = tmp_path / "runtime-profile5.json"
    raw = (json.dumps(plan, sort_keys=True) + "\n").encode("utf8") if raw is None else raw
    path.write_bytes(raw)
    digest = sha256(raw).hexdigest()
    return {"path": str(path), "sha256": digest}, digest, {**pins, path: digest}


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode("ascii")).hexdigest()


def _compiled(plan):
    native = {"profile": plan["profile"],
              "allowed_role": "direct_child_vctip_LOAD_DLL_with_active_exact_pinned_IL",
              "native_image_pins": plan["native_image_pins"],
              "required_IL_tool_pin": {
                  str(Path(plan["tool_directory"]) / name):
                      plan["tool_pins"][str(Path(plan["tool_directory"]) / name)]
                  for name in _ILS}}
    support = {"profile": plan["profile"], "allowed_role": "direct_child_vctip_LOAD_DLL",
               "support_files": plan["support_files"]}
    framework = {"profile": plan["profile"],
                 "allowed_role": "direct_child_vctip_LOAD_DLL_with_operator_pinned_framework_NI",
                 "framework_native_image_pins": plan["framework_native_image_pins"]}
    return {"profile": plan["profile"], "support_file_sha256": dict(plan["support_files"]),
            "support_profile_sha256": _digest(support),
            "native_image_sha256": dict(plan["native_image_pins"]),
            "native_image_profile_sha256": _digest(native),
            "framework_native_image_sha256": dict(plan["framework_native_image_pins"]),
            "framework_native_image_profile_sha256": _digest(framework),
            "framework_IL_binding_proven": False,
            "managed_resource_reference_closure_proven": False,
            **{name: False for name in _FALSE}}


def test_schema5_exact_profile_positive(subject):
    plan, pins = _inputs(subject)
    assert subject._runtime_profile_plan(plan, pins) == plan


def test_schema5_independently_pinned_json_positive(subject, tmp_path):
    plan, pins = _inputs(subject)
    record, digest, pins = _file(tmp_path, plan, pins)
    assert subject._load_runtime_profile(record, digest, pins) == plan


@pytest.mark.parametrize("schema,profile", [
    (4, _V5), (5, _V4), (3, _V5), (2, _V5), (True, _V5), (5.0, _V5),
    ("5", _V5), (None, _V5), (5, None), (5, _V5 + " "),
    (5, "msvc-14.44.35207-sdk-10.0.26100.0-raw-v6")])
def test_schema_profile_pair_is_closed(subject, schema, profile):
    plan, pins = _inputs(subject)
    plan.update(schema=schema, profile=profile)
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("field", [
    "schema", "profile", "tool_directory", "tool_pins", "external_headers",
    "include_roots", "ordered_includes", "support_files", "native_image_pins",
    "framework_native_image_pins"])
def test_schema5_missing_field_reject(subject, field):
    plan, pins = _inputs(subject)
    del plan[field]
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("field", ["allow_native_namespace", "telemetry",
                                   "framework_resource_closure"])
def test_schema5_extra_field_reject(subject, field):
    plan, pins = _inputs(subject)
    plan[field] = True
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("name", [
    _FRAMEWORK.replace("System.Runteb92aa12", "system.Runteb92aa12"),
    _FRAMEWORK.replace("Runteb92aa12", "Runteb92aa13"),
    _FRAMEWORK.replace("System.Runtime.Serialization.ni.dll", "System.Runtime.Serialization.dll"),
    _FRAMEWORK.replace("c" * 32, "C" * 32),
    _FRAMEWORK.replace("c" * 32, "c" * 31),
    _FRAMEWORK.replace("NativeImages_v4.0.30319_64", "NativeImages_v4.0.30319_32"),
    _FRAMEWORK.replace("C:\\Windows", "C:\\Temp"),
    _FRAMEWORK.replace("C:\\", "D:\\", 1),
    _FRAMEWORK.replace("\\assembly\\", "\\assembly\\..\\assembly\\"),
    _FRAMEWORK.replace("\\", "/"), _FRAMEWORK + ":stream",
    _FRAMEWORK + " ", _FRAMEWORK + ".", "relative.ni.dll",
    None, True, Path(_FRAMEWORK)])
def test_framework_path_is_exact_and_closed(subject, name):
    plan, pins = _inputs(subject)
    plan["framework_native_image_pins"] = {name: "3" * 64}
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("value", [None, True, 1, "F" * 64, "3" * 63, "g" * 64])
def test_framework_digest_shape_is_closed(subject, value):
    plan, pins = _inputs(subject)
    plan["framework_native_image_pins"][_FRAMEWORK] = value
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("value", [None, [], (), {}, {_FRAMEWORK: _D, _FRAMEWORK + ".copy": _D}])
def test_framework_pin_container_and_cardinality_are_closed(subject, value):
    plan, pins = _inputs(subject)
    plan["framework_native_image_pins"] = value
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("change", ["missing", "different", "case-mismatch"])
def test_framework_outer_pin_must_match_exact_plan(subject, change):
    plan, pins = _inputs(subject)
    path = Path(_FRAMEWORK)
    if change == "missing":
        del pins[path]
    elif change == "different":
        pins[path] = "9" * 64
    else:
        del pins[path]
        pins[Path(_FRAMEWORK.upper())] = plan["framework_native_image_pins"][_FRAMEWORK]
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("inventory", [
    "tool_pins", "external_headers", "support_files", "native_image_pins"])
def test_framework_role_cannot_overlap_another_input_role(subject, inventory):
    plan, pins = _inputs(subject)
    target = plan[inventory]
    if inventory in ("tool_pins", "external_headers"):
        del target[next(iter(target))]
        target[_FRAMEWORK] = "3" * 64
    else:
        target[_FRAMEWORK] = "3" * 64
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


def test_framework_proof_binds_exact_separate_role_and_scope(subject):
    plan, pins = _inputs(subject)
    compiled = _compiled(plan)
    subject._verify_runtime_profile_proof(compiled, plan)
    assert compiled["framework_native_image_sha256"] == plan["framework_native_image_pins"]
    assert compiled["framework_IL_binding_proven"] is False
    assert compiled["managed_resource_reference_closure_proven"] is False


@pytest.mark.parametrize("field,value", [
    ("framework_native_image_sha256", {_FRAMEWORK: "4" * 64}),
    ("framework_native_image_profile_sha256", "0" * 64),
    ("framework_IL_binding_proven", True),
    ("managed_resource_reference_closure_proven", True)])
def test_framework_proof_rejects_mismatch_or_scope_expansion(subject, field, value):
    plan, pins = _inputs(subject)
    compiled = _compiled(plan)
    compiled[field] = value
    with pytest.raises(pytest.fail.Exception):
        subject._verify_runtime_profile_proof(compiled, plan)


def test_v5_role_mutation_changes_independent_profile_hash(subject, tmp_path):
    plan, pins = _inputs(subject)
    record, digest, pins = _file(tmp_path, plan, pins)
    plan["framework_native_image_pins"][_FRAMEWORK] = "4" * 64
    Path(record["path"]).write_bytes(json.dumps(plan).encode("ascii"))
    with pytest.raises(pytest.fail.Exception, match="profile bytes differ"):
        subject._load_runtime_profile(record, digest, pins)
