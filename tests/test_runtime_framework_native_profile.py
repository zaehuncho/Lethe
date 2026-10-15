"""Schema-v5 framework NativeImage role: exact pin, opaque resources, no IL/closure claims."""
from dataclasses import replace, FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
import hashlib
import json
import os
import struct

import pytest
from lifter import runtime_coff_compile as r
from lifter import runtime_compiler_trace as t

pytestmark = pytest.mark.skipif(os.name != "nt", reason="closed Win64 profile")
T = Path(r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64")
SDK = Path(r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0")
NI_REMOTE = Path(r"C:\Windows\assembly\NativeImages_v4.0.30319_64\Microsoft.V8f370856#\c4c9d7fd5bf04be34be80f649b419ccd\Microsoft.VisualStudio.RemoteControl.ni.dll")
NI_NEWTON = Path(r"C:\Windows\assembly\NativeImages_v4.0.30319_64\Newtonsoft.Json\bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\Newtonsoft.Json.ni.dll")
NI_FRAMEWORK = Path(r"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Runteb92aa12#\db3c0fed2cb26a39b6902192d5a00db8\System.Runtime.Serialization.ni.dll")
IL_REMOTE = T / "Microsoft.VisualStudio.RemoteControl.dll"
IL_NEWTON = T / "Newtonsoft.Json.dll"
REMOTE_SHA = "a" * 64
NEWTON_SHA = "b" * 64
FRAMEWORK_SHA = "849ea91e3983c3ff5286d72de6b8d61d9e76df6cbc85e02cf9d0595ce9ed9890"
V5 = "msvc-14.44.35207-sdk-10.0.26100.0-raw-v5"


def need(value, message="contract failed"):
    if not value:
        raise AssertionError(message)


def inputs_v3():
    h = SDK / "ucrt/stdio.h"
    return r.RuntimeCompileInputs(Path(r"D:\a\framework_model_capsule"), T,
        (T.parents[2] / "include", *(SDK / n for n in ("ucrt", "shared", "um", "winrt", "cppwinrt"))),
        tuple(r.RuntimeFilePin(T / n, "c" * 64) for n in ("cl.exe", "ml64.exe", "vctip.exe"))
            + (r.RuntimeFilePin(IL_REMOTE, "d" * 64),),
        (r.RuntimeFilePin(h, "e" * 64),),
        tuple((role, (str(h),)) for role, _ in r._ROLES[:4]), r._PROFILE_V3,
        (r.RuntimeFilePin(r._SETUP_SUPPORT, "f" * 64),),
        (r.RuntimeFilePin(NI_REMOTE, REMOTE_SHA),))


def inputs_v5():
    base = inputs_v3()
    tools = base.tool_files + (r.RuntimeFilePin(IL_NEWTON, "1" * 64),)
    return replace(base, profile=V5, tool_files=tools,
        native_image_pins=(r.RuntimeFilePin(NI_REMOTE, REMOTE_SHA),
                           r.RuntimeFilePin(NI_NEWTON, NEWTON_SHA)),
        framework_native_image_pins=(r.RuntimeFilePin(NI_FRAMEWORK, FRAMEWORK_SHA),))


def no_effect(*args, **kwargs):
    raise AssertionError("unexpected I/O/compiler/process effect")


def test_v5_input_shape_is_separate_and_legacy_defaults_stay_empty(monkeypatch):
    value = inputs_v5()
    monkeypatch.setattr(r, "_ordinary", no_effect)
    r.validate_runtime_compile_inputs(value)
    need(r.RuntimeCompileInputs.__dataclass_fields__["framework_native_image_pins"].default == ())
    need(t.CompilerTracePolicy.__dataclass_fields__["framework_native_image_pins"].default == ())
    with pytest.raises(FrozenInstanceError):
        value.framework_native_image_pins = ()
    old = inputs_v3()
    r.validate_runtime_compile_inputs(old)
    need(old.framework_native_image_pins == ())


@pytest.mark.parametrize("bad", [None, [], {}, True, (), (None,),
    ((NI_FRAMEWORK, FRAMEWORK_SHA),),
    (r.RuntimeFilePin(str(NI_FRAMEWORK), FRAMEWORK_SHA),),
    (r.RuntimeFilePin(NI_FRAMEWORK, None),),
    (r.RuntimeFilePin(NI_FRAMEWORK, "F" * 64),),
    (r.RuntimeFilePin(NI_FRAMEWORK, "g" * 64),),
    (r.RuntimeFilePin(NI_FRAMEWORK, FRAMEWORK_SHA),) * 2])
def test_framework_pin_shape_rejects_before_effects(monkeypatch, bad):
    monkeypatch.setattr(r, "_ordinary", no_effect)
    value = replace(inputs_v5(), framework_native_image_pins=bad)
    with pytest.raises(r.RuntimeCompileError):
        r.validate_runtime_compile_inputs(value)


@pytest.mark.parametrize("name", [
    str(NI_FRAMEWORK).replace("C:\\Windows", "c:\\Windows"),
    str(NI_FRAMEWORK).replace("Windows", "WINDOWS"),
    str(NI_FRAMEWORK).replace("System.Runteb92aa12#", "System.Other#"),
    str(NI_FRAMEWORK).replace("db3c0fed", "DB3c0fed"),
    str(NI_FRAMEWORK).replace("db3c0fed2cb26a39b6902192d5a00db8", "db3c0fed2cb26a39b6902192d5a00db"),
    str(NI_FRAMEWORK).replace("System.Runtime.Serialization.ni.dll", "System.Runtime.Serialization.dll"),
    str(NI_FRAMEWORK).replace("NativeImages_v4.0.30319_64", "NativeImages_v4.0.30319_32"),
    str(NI_FRAMEWORK).replace("C:\\", "D:\\", 1),
    str(NI_FRAMEWORK).replace("\\assembly\\", "\\assembly\\..\\assembly\\"),
    str(NI_FRAMEWORK) + ":stream", "relative.ni.dll", None, True])
def test_framework_path_grammar_is_not_generic(monkeypatch, name):
    monkeypatch.setattr(r, "_ordinary", no_effect)
    path = Path(name) if type(name) is str else name
    with pytest.raises(r.RuntimeCompileError):
        r.validate_runtime_compile_inputs(replace(inputs_v5(),
            framework_native_image_pins=(r.RuntimeFilePin(path, FRAMEWORK_SHA),)))


@pytest.mark.parametrize("profile", [r._PROFILE, r._PROFILE_V3, r._PROFILE_V4])
def test_legacy_profiles_cannot_opt_into_framework_NI(monkeypatch, profile):
    monkeypatch.setattr(r, "_ordinary", no_effect)
    value = replace(inputs_v5(), profile=profile)
    with pytest.raises(r.RuntimeCompileError):
        r.validate_runtime_compile_inputs(value)


def native_raw(resources=None, resource_size=8, extra_directory=None, strong_name=None):
    raw = bytearray(1536)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 60, 128)
    raw[128:132] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", raw, 132, 0x8664, 1, 0, 0, 0, 240, 0x2022)
    opt = 152
    struct.pack_into("<H", raw, opt, 0x20B)
    struct.pack_into("<II", raw, opt + 32, 4096, 512)
    struct.pack_into("<II", raw, opt + 56, 8192, 512)
    struct.pack_into("<I", raw, opt + 108, 16)
    struct.pack_into("<II", raw, opt + 112 + 14 * 8, 4096, 72)
    if extra_directory is not None:
        index, rva, size = extra_directory
        struct.pack_into("<II", raw, opt + 112 + index * 8, rva, size)
    struct.pack_into("<8sIIIIIIHHI", raw, opt + 240, b".text", 1024, 4096,
                     1024, 512, 0, 0, 0, 0, 0x60000020)
    struct.pack_into("<IHHIIII", raw, 512, 72, 2, 5, 4352, 32, 4, 0)
    if resources is not None:
        struct.pack_into("<II", raw, 512 + 24, resources, resource_size)
        off = 512 + resources - 4096
        if 0 <= off and off + min(resource_size, 8) <= len(raw):
            raw[off:off + min(resource_size, 8)] = b"opaque!!"[:min(resource_size, 8)]
    if strong_name is not None:
        struct.pack_into("<II", raw, 512 + 32, strong_name, 8)
    struct.pack_into("<II", raw, 512 + 64, 4416, 168)
    raw[768:772] = b"BSJB"
    raw[832:836] = b"NGE\0"
    struct.pack_into("<HH", raw, 836, 1, 0)
    return bytes(raw)


def test_framework_resource_parser_is_separate_bounded_and_opaque():
    baseline = native_raw()
    with pytest.raises(t.CompilerTraceError):
        t._recognize_framework_native_image(baseline)
    positive = native_raw(5008, 8)
    record = t._recognize_framework_native_image(positive)
    need(record["envelope"] == "operator_pinned_framework_AMD64_NGEN_PE32plus_DLL")
    need(record["framework_IL_binding_proven"] is False)
    need(record["managed_resource_reference_closure_proven"] is False)
    # Existing Tool-NI parser remains unchanged and rejects this auxiliary CLI span.
    with pytest.raises(t.CompilerTraceError):
        t._recognize_native_tool_image(positive)


@pytest.mark.parametrize("raw", [
    native_raw(5008, 0),                    # absent declared resource span
    native_raw(5001, 8),                    # unaligned RVA
    native_raw(5008, 7),                    # unaligned length
    native_raw(8192, 8),                    # not file-backed
    native_raw(4352, 8),                    # metadata overlap
    native_raw(4416, 8),                    # NGE header overlap
    native_raw(4096, 8),                    # CLI header overlap
    native_raw(5008, 8, extra_directory=(5, 5008, 8)),  # loader directory overlap
    native_raw(5008, 8, strong_name=5008),  # CLI strong-name signature overlap
])
def test_framework_resource_span_mutations_fail_closed(raw):
    with pytest.raises(t.CompilerTraceError):
        t._recognize_framework_native_image(raw)


def test_framework_NI_classifier_is_a_separate_operator_pin_role(monkeypatch):
    raw = native_raw(5008, 8)
    digest = hashlib.sha256(raw).hexdigest()
    policy = object.__new__(t._LockedPolicy)
    policy.k = None
    policy.windows = Path(r"C:\Windows")
    policy.allowed = (T / "vctip.exe",)
    policy.rows = {"cl.exe": [{"path": T / "cl.exe"}]}
    policy.support = {}
    policy.native_images = {}
    policy.framework_native_images = {
        t._FRAMEWORK_NATIVE_IMAGE_NAME: {"path": NI_FRAMEWORK, "sha256": digest,
            "identity": (1, 20), "info": {"volume": 1, "index": 20, "size": len(raw),
            "links": 1, "attributes": 32, "write": 99}, "envelope": {}}}
    row = {"path": str(NI_FRAMEWORK), "volume": 1, "index": 20, "size": len(raw),
        "links": 1, "attributes": 32, "write": 99, "sha256": digest,
        "machine": "AMD64", "image_size": 8192, "_native_raw": raw}
    monkeypatch.setattr(t, "_read_image", lambda *args, **kwargs: (NI_FRAMEWORK, dict(row)))
    _, result = policy.classify(123, managed_tool_root=T)
    need(result["classification"] == "pinned_vctip_framework_native_image")
    need(result["framework_IL_binding_proven"] is False)
    need(result["managed_resource_reference_closure_proven"] is False)
    need("active_pinned_IL_binding" not in result and "_native_raw" not in result)
    record = t.CompilerTraceResult(0, b"", b"", "exited", (), (result,), (), {}).to_record()
    need(record["operator_pinned_NGEN_image_observed"] is True)


@pytest.mark.parametrize("kind", ["unbound", "wrong-role", "wrong-root", "wrong-path",
    "wrong-hash", "wrong-identity", "links", "size", "attrs", "wrong-machine"])
def test_framework_NI_classifier_requires_exact_current_role_and_pin(monkeypatch, kind):
    raw = native_raw(5008, 8)
    digest = hashlib.sha256(raw).hexdigest()
    policy = object.__new__(t._LockedPolicy)
    policy.k = None
    policy.windows = Path(r"C:\Windows")
    policy.allowed = (T / "vctip.exe",)
    policy.rows = {"cl.exe": [{"path": T / "cl.exe"}]}
    policy.support = {}
    policy.native_images = {}
    policy.framework_native_images = {
        t._FRAMEWORK_NATIVE_IMAGE_NAME: {"path": NI_FRAMEWORK, "sha256": digest,
            "identity": (1, 20), "info": {"volume": 1, "index": 20, "size": len(raw),
            "links": 1, "attributes": 32, "write": 99}, "envelope": {}}}
    path = NI_FRAMEWORK
    context = T
    row = {"path": str(path), "volume": 1, "index": 20, "size": len(raw),
        "links": 1, "attributes": 32, "write": 99, "sha256": digest,
        "machine": "AMD64", "image_size": 8192, "_native_raw": raw}
    if kind == "unbound": policy.framework_native_images = {}
    elif kind == "wrong-role": context = None
    elif kind == "wrong-root": context = T.parent
    elif kind == "wrong-path": path = NI_FRAMEWORK.parent / "Other.ni.dll"; row["path"] = str(path)
    elif kind == "wrong-hash": row["sha256"] = "0" * 64
    elif kind == "wrong-identity": row["index"] = 21
    elif kind == "links": row["links"] = 2
    elif kind == "size": row["size"] += 1
    elif kind == "attrs": row["attributes"] = 0x400
    elif kind == "wrong-machine": row["machine"] = "I386"
    monkeypatch.setattr(t, "_read_image", lambda *args, **kwargs: (path, dict(row)))
    with pytest.raises(t.CompilerTraceError):
        policy.classify(123, managed_tool_root=context)


def test_framework_policy_pin_shapes_fail_before_any_windows_API():
    class NoAPI:
        def __getattr__(self, name):
            return no_effect
    good = ((NI_FRAMEWORK, FRAMEWORK_SHA),)
    bad = [None, [], {}, True, ((NI_FRAMEWORK,),), ((str(NI_FRAMEWORK), FRAMEWORK_SHA),),
           ((NI_FRAMEWORK, "F" * 64),), good * 2]
    for pins in bad:
        policy = t.CompilerTracePolicy(((T / "cl.exe", "1" * 64),), Path(r"C:\Windows"),
                                       framework_native_image_pins=pins)
        with pytest.raises(t.CompilerTraceError):
            t._LockedPolicy(policy, NoAPI())


def test_v5_runtime_proof_binds_exact_framework_role_and_no_semantics(monkeypatch):
    value = inputs_v5()
    state = r._State(value)
    state.built = True
    raw = {name + ".obj": b"object-" + name.encode() for name, _ in r._ROLES}
    generated = (tuple(Path(r"D:\a\model_export") / n for n in raw)
                 + tuple(Path(r"D:\a\model_export") / ("extra" + str(i) + ".obj") for i in range(3)))
    state.exports = {r._key(path): r._sha(raw[path.name]) for path in generated
                     if path.name in raw}
    state.source_pins = {"stub/src/model.c": "a" * 64}
    state._lock = lambda path, *args, **kwargs: raw[path.name]
    state.compile = lambda: (raw, {}, [{}] * 8)
    state.recheck = lambda: None
    monkeypatch.setattr(r, "_session_state", lambda handle: state)
    monkeypatch.setattr(r, "_ordinary", lambda *args, **kwargs: None)
    result = r.prove_runtime_coff_compilation(object(), generated, Path(r"D:\a\model_capture"))
    framework = {str(NI_FRAMEWORK): FRAMEWORK_SHA}
    payload = {"profile": V5,
        "allowed_role": "direct_child_vctip_LOAD_DLL_with_operator_pinned_framework_NI",
        "framework_native_image_pins": framework}
    expected = r._sha(json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=True).encode("ascii"))
    need(result["framework_native_image_sha256"] == framework)
    need(result["framework_native_image_profile_sha256"] == expected)
    need(result["framework_IL_binding_proven"] is False)
    need(result["managed_resource_reference_closure_proven"] is False)


def test_framework_pin_lock_blocks_mutation_and_rechecks_identity(tmp_path, monkeypatch):
    path = tmp_path / "framework.ni.dll"
    path.write_bytes(b"pinned framework image bytes")
    value = inputs_v5()
    state = r._State(value)
    monkeypatch.setattr(r, "_framework_native_image_path", lambda p: p)
    monkeypatch.setattr(r, "_ordinary_framework_native_image", lambda p: p.stat())
    state.inputs = replace(value, framework_native_image_pins=(
        r.RuntimeFilePin(path, r._sha(path.read_bytes())),))
    state._lock(path, state.inputs.framework_native_image_pins[0].sha256,
                framework_native_image=True)
    try:
        state._check_framework_native_images()
        with pytest.raises(OSError):
            path.write_bytes(b"changed")
        old = state.framework_native_locks[path]
        state.framework_native_locks[path] = (old[0], old[1], "0" * 64)
        with pytest.raises(r.RuntimeCompileError):
            state._check_framework_native_images()
        state.framework_native_locks[path] = old
        changed = list(old[1]); changed[1] += 1
        state.framework_native_locks[path] = (old[0], tuple(changed), old[2])
        with pytest.raises(r.RuntimeCompileError):
            state._check_framework_native_images()
    finally:
        state.stack.close()


def test_framework_lock_failure_precedes_capsule_creation(tmp_path, monkeypatch):
    value = replace(inputs_v5(), capsule=tmp_path / "absentCapsule")
    state = r._State(value)
    monkeypatch.setattr(r, "_ordinary", lambda *args, **kwargs: None)
    monkeypatch.setattr(r, "_tool_inventory", lambda root: {pin.path for pin in value.tool_files})
    monkeypatch.setattr(r.source_link_build, "_source_tree_hashes", lambda *args, **kwargs: {})
    seen = []
    def lock(path, *args, **kwargs):
        seen.append((path, kwargs))
        need(not value.capsule.exists())
        if kwargs.get("framework_native_image"):
            raise r.RuntimeCompileError("modeled framework lock failure")
        return b"native-image-bytes"
    state._lock = lock
    with pytest.raises(r.RuntimeCompileError, match="framework lock failure"):
        state.prepare()
    need(seen[-1] == (NI_FRAMEWORK, {"framework_native_image": True}))
    need(not value.capsule.exists())


def _require_actual_framework_probe():
    if os.environ.get("LETHE_FRAMEWORK_NI_READONLY_PROBE") != "1":
        pytest.skip("explicit read-only framework NativeImage probe not requested")
    need(os.environ.get("LETHE_FRAMEWORK_NI_READONLY_PIN_SHA256") == FRAMEWORK_SHA,
         "independent framework NI pin differs/missing")


def test_actual_framework_NI_opaque_resource_envelope_only():
    _require_actual_framework_probe()
    raw = NI_FRAMEWORK.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == FRAMEWORK_SHA)
    result = t._recognize_framework_native_image(raw)
    need(result["framework_IL_binding_proven"] is False)
    need(result["managed_resource_reference_closure_proven"] is False)


def test_framework_trace_field_is_appended_and_frozen():
    policy = t.CompilerTracePolicy(((T / "cl.exe", "1" * 64),), Path(r"C:\Windows"))
    need(policy.framework_native_image_pins == ())
    with pytest.raises(FrozenInstanceError):
        policy.framework_native_image_pins = ()
