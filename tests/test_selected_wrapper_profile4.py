"""Portable schema4 consumer regressions; no installed NI or native evidence.

The actual maintained native subject is imported. Every launch entrypoint is a
tripwire; generated JSON and synthetic dictionaries exercise only its consumer.
"""
from __future__ import annotations

from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest

_D = "1" * 64
_V4 = "msvc-14.44.35207-sdk-10.0.26100.0-raw-v4"
_REMOTE = (r"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.V8f370856#"
           + "\\" + "a" * 32 + r"\Microsoft.VisualStudio.RemoteControl.ni.dll")
_NEWTON = (r"C:\Windows\assembly\NativeImages_v4.0.30319_64\Newtonsoft.Json"
           + "\\" + "b" * 32 + r"\Newtonsoft.Json.ni.dll")
_ILS = ("Microsoft.VisualStudio.RemoteControl.dll", "Newtonsoft.Json.dll")
_FALSE = ("NI_compilation_authenticity_proven", "IL_native_semantic_equivalence_proven",
          "NGEN_dependency_closure_proven", "JIT_closure_proven",
          "managed_assembly_closure_proven", "loaded_memory_attestation_proven", "full_OS_attestation_proven")


@pytest.fixture
def subject(pytestconfig, monkeypatch):
    path = Path(pytestconfig.rootpath) / "tests/test_selected_wrapper_materialized.py"
    digest = sha256(path.read_bytes()).hexdigest()
    spec = importlib.util.spec_from_file_location("_selected_wrapper_profile4_subject", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    assert Path(module.__file__) == path and module.__spec__.origin == str(path)
    assert sha256(path.read_bytes()).hexdigest() == digest
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("native-entrypoint")
        raise AssertionError("schema4 consumer controls attempted native effects")

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
    headers = {str(Path(r"C:\fixture-model\include") / ("h%03d.h" % i)): _D for i in range(160)}
    plan = {"schema": 4, "profile": _V4, "tool_directory": str(tool),
            "include_roots": [str(Path(r"C:\fixture-model") / ("include%d" % i)) for i in range(6)],
            "tool_pins": tools, "external_headers": headers,
            "ordered_includes": [[role, [next(iter(headers))]] for role in subject._ROLES[:4]],
            "support_files": {str(subject._SETUP_SUPPORT): _D},
            "native_image_pins": {_REMOTE: _D, _NEWTON: "2" * 64}}
    pins = {Path(name): digest for inventory in (plan["support_files"], plan["native_image_pins"])
            for name, digest in inventory.items()}
    return plan, pins


def _file(tmp_path, plan, pins, raw=None):
    path = tmp_path / "runtime-profile4.json"
    raw = (json.dumps(plan, sort_keys=True) + "\n").encode("utf8") if raw is None else raw
    path.write_bytes(raw)
    digest = sha256(raw).hexdigest()
    return {"path": str(path), "sha256": digest}, digest, {**pins, path: digest}


def _compiled(plan):
    native = {"profile": plan["profile"],
              "allowed_role": "direct_child_vctip_LOAD_DLL_with_active_exact_pinned_IL",
              "native_image_pins": plan["native_image_pins"],
              "required_IL_tool_pin": {str(Path(plan["tool_directory"]) / name):
                  plan["tool_pins"][str(Path(plan["tool_directory"]) / name)] for name in _ILS}}
    support = {"profile": plan["profile"], "allowed_role": "direct_child_vctip_LOAD_DLL",
               "support_files": plan["support_files"]}
    digest = lambda value: sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
    return {"profile": plan["profile"], "support_file_sha256": dict(plan["support_files"]),
            "support_profile_sha256": digest(support), "native_image_sha256": dict(plan["native_image_pins"]),
            "native_image_profile_sha256": digest(native), **{name: False for name in _FALSE}}


def test_schema4_exact_pair_positive(subject):
    plan, pins = _inputs(subject)
    assert subject._runtime_profile_plan(plan, pins) == plan


def test_schema4_independently_pinned_real_json_positive(subject, tmp_path):
    plan, pins = _inputs(subject)
    record, digest, pins = _file(tmp_path, plan, pins)
    assert subject._load_runtime_profile(record, digest, pins) == plan


@pytest.mark.parametrize("schema,profile", [(4, "msvc-14.44.35207-sdk-10.0.26100.0-raw-v3"),
    (3, _V4), (2, _V4), (True, _V4), (4.0, _V4), ("4", _V4), (None, _V4),
    (4, None), (4, _V4 + " "), (4, "msvc-14.44.35207-sdk-10.0.26100.0-raw-v5")])
def test_schema_profile_pair_is_closed(subject, schema, profile):
    plan, pins = _inputs(subject)
    plan.update(schema=schema, profile=profile)
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("field", ["schema", "profile", "tool_directory", "tool_pins", "external_headers",
    "include_roots", "ordered_includes", "support_files", "native_image_pins"])
def test_schema4_missing_field_reject(subject, field):
    plan, pins = _inputs(subject)
    del plan[field]
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("field", ["allow_native_namespace", "telemetry", "required_IL_tool_pin"])
def test_schema4_extra_field_reject(subject, field):
    plan, pins = _inputs(subject)
    plan[field] = True
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("field,value", [("native_image_pins", None), ("native_image_pins", []),
    ("native_image_pins", {}), ("support_files", {}), ("tool_pins", []),
    ("external_headers", {}), ("include_roots", ()), ("ordered_includes", []),
    ("tool_directory", None)])
def test_schema4_role_type_and_missing_pair_reject(subject, field, value):
    plan, pins = _inputs(subject)
    plan[field] = value
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("field,delta", [("tool_pins", -1), ("tool_pins", 1),
    ("external_headers", -1), ("external_headers", 1), ("include_roots", -1), ("include_roots", 1)])
def test_schema4_recursive_counts_remain_exact(subject, field, delta):
    plan, pins = _inputs(subject)
    value = plan[field]
    if type(value) is dict:
        if delta < 0:
            del value[next(iter(value))]
        else:
            value["extra"] = _D
    elif delta < 0:
        value.pop()
    else:
        value.append("extra")
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("change", ["one", "three", "two-remote", "two-newton"])
def test_exact_two_distinct_families_not_generic_ni_count(subject, change):
    plan, pins = _inputs(subject)
    if change == "one":
        del plan["native_image_pins"][_NEWTON]
    elif change == "three":
        plan["native_image_pins"][_NEWTON.replace("b" * 32, "c" * 32)] = _D
    else:
        original, removed = (_REMOTE, _NEWTON) if change == "two-remote" else (_NEWTON, _REMOTE)
        del plan["native_image_pins"][removed]
        duplicate = original.replace("a" * 32 if change == "two-remote" else "b" * 32, "c" * 32)
        plan["native_image_pins"][duplicate] = _D
        pins[Path(duplicate)] = _D
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("name", [_NEWTON.replace("b" * 32, "B" * 32),
    _NEWTON.replace("b" * 32, "b" * 31), _NEWTON.replace("b" * 32, "g" * 32),
    _NEWTON.replace("Newtonsoft.Json", "Newtonsoft.Json.Other", 1),
    _NEWTON.replace("Newtonsoft.Json.ni.dll", "Newtonsoft.Json.dll"),
    _NEWTON.replace("Newtonsoft.Json.ni.dll", "Microsoft.VisualStudio.Telemetry.ni.dll"),
    _NEWTON.replace("NativeImages_v4.0.30319_64", "NativeImages_v4.0.30319_32"),
    _NEWTON.replace("C:\\Windows", "C:\\Temp"), _NEWTON.replace("C:\\", "D:\\", 1),
    _NEWTON.replace("\\assembly\\", "\\assembly\\..\\assembly\\"),
    _NEWTON.replace("\\", "/"), _NEWTON + ":stream", _NEWTON + " ", _NEWTON + ".",
    "relative.ni.dll", None, True, Path(_NEWTON)])
def test_newton_strict_path_no_namespace_telemetry_or_alias(subject, name):
    plan, pins = _inputs(subject)
    del plan["native_image_pins"][_NEWTON]
    plan["native_image_pins"][name] = _D
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("name", [_REMOTE, _NEWTON])
@pytest.mark.parametrize("value", [None, True, 1, "F" * 64, "1" * 63, "g" * 64])
def test_each_ni_digest_shape_is_closed(subject, name, value):
    plan, pins = _inputs(subject)
    plan["native_image_pins"][name] = value
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("role", ["remote", "newton", "setup"])
@pytest.mark.parametrize("change", ["missing", "different"])
def test_each_ni_and_setup_outer_pin_must_match(subject, role, change):
    plan, pins = _inputs(subject)
    path = Path({"remote": _REMOTE, "newton": _NEWTON, "setup": str(subject._SETUP_SUPPORT)}[role])
    if change == "missing":
        del pins[path]
    else:
        pins[path] = "9" * 64
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("name", [_REMOTE, _NEWTON])
@pytest.mark.parametrize("role", ["tool_pins", "external_headers"])
def test_each_ni_role_stays_separate_from_compiler_and_headers(subject, name, role):
    plan, pins = _inputs(subject)
    del plan[role][next(iter(plan[role]))]
    plan[role][name] = _D
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("basename", _ILS)
@pytest.mark.parametrize("change", ["missing", "wrong-basename", "wrong-case", "digest", "ambiguous-case"])
def test_corresponding_exact_il_pair_required(subject, basename, change):
    plan, pins = _inputs(subject)
    il = str(Path(plan["tool_directory"]) / basename)
    if change == "digest":
        plan["tool_pins"][il] = "F" * 64
    elif change == "ambiguous-case":
        del plan["tool_pins"][next(iter(plan["tool_pins"]))]
        plan["tool_pins"][il.upper()] = _D
    else:
        del plan["tool_pins"][il]
        replacement = il + ".other" if change == "wrong-basename" else il.upper() if change == "wrong-case" else "absent-il.dll"
        plan["tool_pins"][replacement] = _D
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("inventory", ["tool_pins", "external_headers", "support_files", "native_image_pins"])
def test_each_role_mutation_needs_new_independent_profile_digest(subject, tmp_path, inventory):
    plan, pins = _inputs(subject)
    record, digest, pins = _file(tmp_path, plan, pins)
    name = next(iter(plan[inventory]))
    plan[inventory][name] = "8" * 64
    Path(record["path"]).write_bytes(json.dumps(plan).encode("ascii"))
    with pytest.raises(pytest.fail.Exception, match="profile bytes differ"):
        subject._load_runtime_profile(record, digest, pins)


@pytest.mark.parametrize("change", ["independent", "record", "bytes", "missing-pin", "extra-record-key"])
def test_v4_independent_record_digest_and_outer_pin_reject(subject, tmp_path, change):
    plan, pins = _inputs(subject)
    record, digest, pins = _file(tmp_path, plan, pins)
    if change == "independent":
        digest = "2" * 64
    elif change == "record":
        record["sha256"] = "2" * 64
    elif change == "bytes":
        Path(record["path"]).write_bytes(b"{}\n")
    elif change == "missing-pin":
        del pins[Path(record["path"])]
    else:
        record["allow_stale"] = True
    with pytest.raises(pytest.fail.Exception):
        subject._load_runtime_profile(record, digest, pins)


@pytest.mark.parametrize("location", ["outer", "native_image_pins", "tool_pins", "support_files"])
def test_v4_duplicate_json_key_reject_at_each_trust_role(subject, tmp_path, location):
    plan, pins = _inputs(subject)
    if location == "outer":
        raw = b'{"schema":4,"schema":4}\n'
    else:
        raw = json.dumps(plan, sort_keys=True).encode("ascii")
        key = next(iter(plan[location]))
        pair = json.dumps(key).encode("ascii") + b": " + json.dumps(plan[location][key]).encode("ascii")
        raw = raw.replace(pair, pair + b", " + pair, 1)
    record, digest, pins = _file(tmp_path, plan, pins, raw)
    with pytest.raises(pytest.fail.Exception, match="duplicate JSON"):
        subject._load_runtime_profile(record, digest, pins)


def _observe_reads(monkeypatch, path, mutation=None):
    original = Path.open
    requests = []

    class Reader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            if mutation == "grow-before-read":
                with original(path, "ab") as writer:
                    writer.write(b"x" * (512 * 1024 + 1))
            return self

        def read(self, size=-1):
            requests.append(size)
            assert size == 512 * 1024 + 1
            return self.stream.read(size)

        def __exit__(self, kind, value, traceback):
            result = self.stream.__exit__(kind, value, traceback)
            if kind is not None:
                return result
            if mutation == "mtime-after-read":
                metadata = path.stat()
                os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000))
            elif mutation == "replace-after-read":
                replacement = path.parent / "replacement-profile.json"
                with original(path, "rb") as reader:
                    contents = reader.read()
                with original(replacement, "xb") as writer:
                    writer.write(contents)
                os.replace(replacement, path)
            elif mutation == "hardlink-after-read":
                os.link(path, path.parent / "late-alias.json")
            elif mutation == "truncate-after-read":
                with original(path, "wb") as writer:
                    writer.write(b"{}\n")
            return result

    def observed(candidate, *args, **kwargs):
        stream = original(candidate, *args, **kwargs)
        mode = args[0] if args else kwargs.get("mode", "r")
        return Reader(stream) if candidate == path and mode == "rb" else stream

    monkeypatch.setattr(Path, "open", observed)
    return requests


def test_v4_actual_profile_read_has_same_explicit_byte_bound(subject, monkeypatch, tmp_path):
    plan, pins = _inputs(subject)
    record, digest, pins = _file(tmp_path, plan, pins)
    requests = _observe_reads(monkeypatch, Path(record["path"]))
    assert subject._load_runtime_profile(record, digest, pins) == plan
    assert requests == [512 * 1024 + 1]


def test_v4_initial_oversize_rejects_before_open(subject, monkeypatch, tmp_path):
    plan, pins = _inputs(subject)
    record, digest, pins = _file(tmp_path, plan, pins, b"x" * (512 * 1024 + 1))
    requests = _observe_reads(monkeypatch, Path(record["path"]))
    with pytest.raises(pytest.fail.Exception, match="excessive"):
        subject._load_runtime_profile(record, digest, pins)
    assert requests == []


@pytest.mark.parametrize("mutation", ["grow-before-read", "mtime-after-read", "replace-after-read",
    "hardlink-after-read", "truncate-after-read"])
def test_v4_freshness_and_identity_mutation_during_read_reject(subject, monkeypatch, tmp_path, mutation):
    plan, pins = _inputs(subject)
    record, digest, pins = _file(tmp_path, plan, pins)
    path = Path(record["path"])
    if mutation == "hardlink-after-read":
        probe = path.parent / "probe-alias.json"
        try:
            os.link(path, probe)
        except OSError as exc:
            pytest.skip("generated-file hardlink unavailable: " + str(exc))
        probe.unlink()
    requests = _observe_reads(monkeypatch, path, mutation)
    with pytest.raises(pytest.fail.Exception, match="bounded read changed"):
        subject._load_runtime_profile(record, digest, pins)
    assert requests == [512 * 1024 + 1]


def test_v4_proof_binds_both_pairs_exact_role_and_profile(subject):
    plan, pins = _inputs(subject)
    subject._runtime_profile_plan(plan, pins)
    subject._verify_runtime_profile_proof(_compiled(plan), plan)


def test_v4_profile_and_digest_are_inventory_order_independent(subject):
    plan, pins = _inputs(subject)
    compiled = _compiled(plan)
    plan["native_image_pins"] = dict(reversed(tuple(plan["native_image_pins"].items())))
    subject._runtime_profile_plan(plan, pins)
    subject._verify_runtime_profile_proof(compiled, plan)


def test_legacy_v3_singleton_proof_remains_deliberate(subject):
    plan, pins = _inputs(subject)
    plan["schema"], plan["profile"] = 3, subject._RUNTIME_PROFILE
    del plan["native_image_pins"][_NEWTON]
    del pins[Path(_NEWTON)]
    subject._runtime_profile_plan(plan, pins)
    compiled = _compiled(plan)
    native = {"profile": plan["profile"],
              "allowed_role": "direct_child_vctip_LOAD_DLL_with_active_exact_pinned_IL",
              "native_image_pins": plan["native_image_pins"],
              "required_IL_tool_pin": {str(Path(plan["tool_directory"]) / _ILS[0]): _D}}
    compiled["native_image_profile_sha256"] = sha256(json.dumps(
        native, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
    subject._verify_runtime_profile_proof(compiled, plan)


@pytest.mark.parametrize("role", ["remote-ni", "newton-ni", "remote-il", "newton-il", "setup"])
def test_v4_each_pair_pin_changes_proof_digest(subject, role):
    plan, pins = _inputs(subject)
    compiled = _compiled(plan)
    if role.endswith("-ni"):
        plan["native_image_pins"][_REMOTE if role == "remote-ni" else _NEWTON] = "9" * 64
    elif role.endswith("-il"):
        basename = _ILS[0 if role == "remote-il" else 1]
        plan["tool_pins"][str(Path(plan["tool_directory"]) / basename)] = "9" * 64
    else:
        plan["support_files"][str(subject._SETUP_SUPPORT)] = "9" * 64
    with pytest.raises(pytest.fail.Exception):
        subject._verify_runtime_profile_proof(compiled, plan)


@pytest.mark.parametrize("field", ["profile", "native_image_sha256", "native_image_profile_sha256",
    "support_file_sha256", "support_profile_sha256"])
def test_v4_mismatched_proof_fields_reject(subject, field):
    plan, pins = _inputs(subject)
    compiled = _compiled(plan)
    compiled[field] = {} if field.endswith("sha256") and isinstance(compiled[field], dict) else "9" * 64
    with pytest.raises(pytest.fail.Exception):
        subject._verify_runtime_profile_proof(compiled, plan)


@pytest.mark.parametrize("field", _FALSE)
@pytest.mark.parametrize("value", [True, 0])
def test_v4_no_ni_semantic_or_platform_claim_expansion(subject, field, value):
    plan, pins = _inputs(subject)
    compiled = _compiled(plan)
    compiled[field] = value
    with pytest.raises(pytest.fail.Exception):
        subject._verify_runtime_profile_proof(compiled, plan)
