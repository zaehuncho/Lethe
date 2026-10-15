"""Portable structural profile-consumer controls, not physical NI/native proof.

The real maintained module is imported. All launch entrypoints are tripwires.
Synthetic pin dictionaries model only already-byte-pinned outer fixture input;
these tests never claim installed tool/NI identities or factory/trace admission.
"""
from __future__ import annotations
import importlib.util
import json
import os
from hashlib import sha256
from pathlib import Path
import sys

import pytest

_DIGEST = "1" * 64
_NI = (r"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.V8f370856#"
       + "\\" + "a" * 32 + r"\Microsoft.VisualStudio.RemoteControl.ni.dll")


@pytest.fixture
def subject(pytestconfig, monkeypatch):
    path = Path(pytestconfig.rootpath) / "tests/test_selected_wrapper_materialized.py"
    spec = importlib.util.spec_from_file_location("_selected_wrapper_profile_subject", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    assert Path(module.__file__) == path and module.__spec__.origin == str(path)
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("native-entrypoint")
        raise AssertionError("structural profile controls attempted native effects")

    for target, name in ((module, "_command"), (module, "emit_product_fixture"),
                         (module.bounded, "_run_bounded"),
                         (module.public, "verify_product_fixture_final_link"),
                         (module.runtime, "runtime_compile_session"),
                         (module.runtime, "build_runtime_objects"),
                         (module.runtime, "prove_runtime_coff_compilation")):
        monkeypatch.setattr(target, name, forbidden)
    yield module
    assert calls == []


def _inputs(subject):
    tool = Path(r"C:\fixture-model\tool")
    tools = {str(tool / ("tool-%02d.dll" % i)): _DIGEST for i in range(90)}
    tools[str(tool / "Microsoft.VisualStudio.RemoteControl.dll")] = _DIGEST
    headers = {str(Path(r"C:\fixture-model\include") / ("h%03d.h" % i)): _DIGEST for i in range(160)}
    plan = {"schema": 3, "profile": subject._RUNTIME_PROFILE, "tool_directory": str(tool),
            "include_roots": [str(Path(r"C:\fixture-model") / ("include%d" % i)) for i in range(6)],
            "tool_pins": tools, "external_headers": headers,
            "ordered_includes": [[role, [next(iter(headers))]] for role in subject._ROLES[:4]],
            "support_files": {str(subject._SETUP_SUPPORT): _DIGEST},
            "native_image_pins": {_NI: _DIGEST}}
    pins = {Path(name): digest for inventory in (plan["support_files"], plan["native_image_pins"])
            for name, digest in inventory.items()}
    return plan, pins


def _profile_file(tmp_path, plan, pins):
    path = tmp_path / "runtime-profile.json"
    raw = (json.dumps(plan, sort_keys=True) + "\n").encode("utf8")
    path.write_bytes(raw)
    digest = sha256(raw).hexdigest()
    pins = dict(pins)
    pins[path] = digest
    return {"path": str(path), "sha256": digest}, digest, pins


def test_closed_schema3_structural_positive(subject):
    plan, pins = _inputs(subject)
    assert subject._runtime_profile_plan(plan, pins) == plan


def test_real_profile_file_independent_digest_positive(subject, tmp_path):
    plan, pins = _inputs(subject)
    record, digest, pins = _profile_file(tmp_path, plan, pins)
    assert subject._load_runtime_profile(record, digest, pins) == plan


@pytest.mark.parametrize("key,value", [
    ("schema", 2), ("schema", True), ("profile", "msvc-14.44.35207-sdk-10.0.26100.0-raw-v2"),
    ("profile", None), ("native_image_pins", None), ("native_image_pins", []),
    ("native_image_pins", {}), ("support_files", {}), ("include_roots", ()),
    ("ordered_includes", []), ("tool_pins", []), ("external_headers", {}),
])
def test_profile_type_schema_and_missing_role_reject(subject, key, value):
    plan, pins = _inputs(subject)
    plan[key] = value
    with pytest.raises(pytest.fail.Exception):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("field", ["native_image_pins", "support_files", "schema", "profile"])
def test_closed_profile_missing_key_reject(subject, field):
    plan, pins = _inputs(subject)
    del plan[field]
    with pytest.raises(pytest.fail.Exception, match="schema-3"):
        subject._runtime_profile_plan(plan, pins)


def test_closed_profile_extra_key_reject(subject):
    plan, pins = _inputs(subject)
    plan["allow_native_namespace"] = True
    with pytest.raises(pytest.fail.Exception, match="schema-3"):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("name", [
    _NI.replace("a" * 32, "A" * 32), _NI.replace("a" * 32, "a" * 31),
    _NI.replace("a" * 32, "g" * 32), _NI.replace("Microsoft.V8f370856#", "Other#"),
    _NI.replace("NativeImages_v4.0.30319_64", "NativeImages_v4.0.30319_32"),
    _NI.replace("RemoteControl.ni.dll", "RemoteControl.dll"), _NI + ":stream",
    _NI.replace("C:\\Windows", "C:\\Temp"), _NI.replace("C:\\", "D:\\", 1),
    _NI.replace("\\assembly\\", "\\assembly\\..\\assembly\\"), _NI.replace("\\", "/"),
    _NI + " ", _NI + ".", "relative.ni.dll", None, 1, Path(_NI),
])
def test_strict_native_image_path_reject(subject, name):
    with pytest.raises(pytest.fail.Exception, match="native-image path"):
        subject._native_image_path(name)


@pytest.mark.parametrize("value", [None, True, 1, "F" * 64, "1" * 63, "g" * 64])
def test_native_image_digest_shape_reject(subject, value):
    plan, pins = _inputs(subject)
    plan["native_image_pins"][_NI] = value
    with pytest.raises(pytest.fail.Exception, match="SHA256 shape"):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("change", ["missing", "different"])
def test_native_image_outer_fixture_pin_required(subject, change):
    plan, pins = _inputs(subject)
    if change == "missing":
        del pins[Path(_NI)]
    else:
        pins[Path(_NI)] = "2" * 64
    with pytest.raises(pytest.fail.Exception, match="native-image pin differs"):
        subject._runtime_profile_plan(plan, pins)


def test_extra_native_image_reject(subject):
    plan, pins = _inputs(subject)
    plan["native_image_pins"][_NI.replace("a" * 32, "b" * 32)] = _DIGEST
    with pytest.raises(pytest.fail.Exception, match="singleton"):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("role", ["tool_pins", "external_headers"])
def test_native_image_cannot_overlap_other_profile_role(subject, role):
    plan, pins = _inputs(subject)
    inventory = plan[role]
    del inventory[next(iter(inventory))]
    inventory[_NI] = _DIGEST
    with pytest.raises(pytest.fail.Exception, match="overlaps"):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("change", ["absent-tool-role", "invalid-IL-digest", "wrong-IL-basename"])
def test_active_IL_prerequisite_input_is_explicit(subject, change):
    plan, pins = _inputs(subject)
    il = Path(plan["tool_directory"]) / "Microsoft.VisualStudio.RemoteControl.dll"
    if change == "absent-tool-role":
        del plan["tool_pins"][str(il)]
        plan["tool_pins"][str(il.parent / "other.dll")] = _DIGEST
    elif change == "invalid-IL-digest":
        plan["tool_pins"][str(il)] = "F" * 64
    else:
        del plan["tool_pins"][str(il)]
        plan["tool_pins"][str(il.parent / "Microsoft.VisualStudio.RemoteControl.ni.dll")] = _DIGEST
    with pytest.raises(pytest.fail.Exception, match="RemoteControl IL|runtime pin shape"):
        subject._runtime_profile_plan(plan, pins)


@pytest.mark.parametrize("inventory", ["tool_pins", "external_headers", "support_files"])
def test_separate_profile_role_tampering_requires_new_independent_digest(subject, tmp_path, inventory):
    plan, pins = _inputs(subject)
    record, digest, pins = _profile_file(tmp_path, plan, pins)
    name = next(iter(plan[inventory]))
    plan[inventory][name] = "2" * 64
    Path(record["path"]).write_text(json.dumps(plan), encoding="utf8")
    with pytest.raises(pytest.fail.Exception, match="profile bytes differ"):
        subject._load_runtime_profile(record, digest, pins)


@pytest.mark.parametrize("change", ["independent", "record", "bytes", "missing-fixture-pin", "extra-record-key"])
def test_independent_profile_digest_and_record_reject(subject, tmp_path, change):
    plan, pins = _inputs(subject)
    record, digest, pins = _profile_file(tmp_path, plan, pins)
    if change == "independent":
        digest = "2" * 64
    elif change == "record":
        record["sha256"] = "2" * 64
    elif change == "bytes":
        Path(record["path"]).write_bytes(b"{}\n")
    elif change == "missing-fixture-pin":
        del pins[Path(record["path"])]
    else:
        record["allow_stale"] = True
    with pytest.raises(pytest.fail.Exception):
        subject._load_runtime_profile(record, digest, pins)


def test_duplicate_profile_JSON_key_reject(subject, tmp_path):
    path = tmp_path / "duplicate-profile.json"
    raw = b'{"schema":3,"schema":2}\n'
    path.write_bytes(raw)
    digest = sha256(raw).hexdigest()
    with pytest.raises(pytest.fail.Exception, match="duplicate JSON"):
        subject._load_runtime_profile({"path": str(path), "sha256": digest}, digest, {path: digest})


def test_generated_profile_hardlink_reject(subject, tmp_path):
    plan, pins = _inputs(subject)
    record, digest, pins = _profile_file(tmp_path, plan, pins)
    alias = tmp_path / "profile-alias.json"
    try:
        os.link(record["path"], alias)
    except OSError as exc:
        pytest.skip("generated-file hardlink unavailable: " + str(exc))
    with pytest.raises(pytest.fail.Exception, match="aliased"):
        subject._load_runtime_profile(record, digest, pins)


@pytest.mark.parametrize("bad_field", ["manifest", "profile", "source"])
def test_independent_digest_shape_rejects_before_file_effects(subject, monkeypatch, tmp_path, bad_field):
    names = {"manifest": subject._ENV + "_SHA256",
             "profile": "LETHE_SELECTED_WRAPPER_RUNTIME_PROFILE_SHA256",
             "source": subject._SOURCE_ENV}
    monkeypatch.setenv("LETHE_SELECTED_WRAPPER_REQUIRE_NATIVE", "1")
    monkeypatch.setenv(subject._ENV, str(tmp_path / "not-created-manifest.json"))
    for name in names.values():
        monkeypatch.setenv(name, "1" * 64)
    monkeypatch.setenv(names[bad_field], "g" * 64)
    with pytest.raises(pytest.fail.Exception, match="SHA256 malformed"):
        subject._manifest()


def test_missing_required_native_manifest_stops_before_effects(subject, monkeypatch):
    for name in (subject._ENV, subject._ENV + "_SHA256", "LETHE_SELECTED_WRAPPER_RUNTIME_PROFILE_SHA256", subject._SOURCE_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LETHE_SELECTED_WRAPPER_REQUIRE_NATIVE", "1")
    with pytest.raises(pytest.fail.Exception, match="SHA256 missing"):
        subject._manifest()
def _observe_generated_profile_reads(monkeypatch, path, mutation=None):
    """Wrap only a generated file's actual stream; never replace its guards."""
    original_open = Path.open
    requests = []
    parent = path.parent.resolve()

    class Reader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            if mutation == "grow-before-read":
                with original_open(path, "ab") as writer:
                    writer.write(b"x" * (512 * 1024 + 1))
            return self

        def read(self, size=-1):
            requests.append(size)
            assert size == 512 * 1024 + 1, "profile reader used an unbounded/wrong-size read"
            return self.stream.read(size)

        def __exit__(self, kind, value, traceback):
            result = self.stream.__exit__(kind, value, traceback)
            if kind is not None:
                return result
            if mutation == "mtime-after-read":
                metadata = path.stat()
                os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000))
            elif mutation == "replace-after-read":
                replacement = parent / "replacement-profile.json"
                assert replacement.parent.resolve() == parent and path.parent.resolve() == parent
                with original_open(path, "rb") as reader:
                    contents = reader.read()
                with original_open(replacement, "xb") as writer:
                    writer.write(contents)
                os.replace(replacement, path)
            elif mutation == "hardlink-after-read":
                alias = parent / "late-profile-alias.json"
                assert alias.parent.resolve() == parent
                os.link(path, alias)
            elif mutation == "truncate-after-read":
                with original_open(path, "wb") as writer:
                    writer.write(b"{}\n")
            return result

    def observed_open(candidate, *args, **kwargs):
        stream = original_open(candidate, *args, **kwargs)
        mode = args[0] if args else kwargs.get("mode", "r")
        return Reader(stream) if candidate == path and mode == "rb" else stream

    monkeypatch.setattr(Path, "open", observed_open)
    return requests


def test_generated_profile_actual_read_has_explicit_byte_bound(subject, monkeypatch, tmp_path):
    plan, pins = _inputs(subject)
    record, digest, pins = _profile_file(tmp_path, plan, pins)
    requests = _observe_generated_profile_reads(monkeypatch, Path(record["path"]))
    assert subject._load_runtime_profile(record, digest, pins) == plan
    assert requests == [512 * 1024 + 1]


def test_generated_profile_initial_oversize_rejects_before_open(subject, monkeypatch, tmp_path):
    path = tmp_path / "oversized-profile.json"
    raw = b"x" * (512 * 1024 + 1)
    path.write_bytes(raw)
    digest = sha256(raw).hexdigest()
    requests = _observe_generated_profile_reads(monkeypatch, path)
    with pytest.raises(pytest.fail.Exception, match="excessive"):
        subject._load_runtime_profile({"path": str(path), "sha256": digest}, digest, {path: digest})
    assert requests == []


@pytest.mark.parametrize("mutation", [
    "grow-before-read", "mtime-after-read", "replace-after-read", "hardlink-after-read", "truncate-after-read",
])
def test_generated_profile_mutation_during_bounded_read_rejects(subject, monkeypatch, tmp_path, mutation):
    plan, pins = _inputs(subject)
    record, digest, pins = _profile_file(tmp_path, plan, pins)
    path = Path(record["path"])
    # The alias control needs a real generated-file hardlink, not an assumed
    # platform capability. A missing privilege is an explicit skip only.
    if mutation == "hardlink-after-read":
        probe = tmp_path / "hardlink-probe"
        try:
            os.link(path, probe)
        except OSError as exc:
            pytest.skip("generated-file hardlink unavailable: " + str(exc))
        probe.unlink()
    requests = _observe_generated_profile_reads(monkeypatch, path, mutation)
    with pytest.raises(pytest.fail.Exception, match="bounded read changed"):
        subject._load_runtime_profile(record, digest, pins)
    assert requests == [512 * 1024 + 1]
