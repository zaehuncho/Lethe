"""Real maintained-module components; no native fixture execution.

An owned managed copy derives from pytest rootpath. Producer excludes Git,
venv/build/cache outputs; these exclusions are not waivers in the source gate.
"""
from pathlib import Path
from hashlib import sha256
import ctypes
import importlib.util
import json
import os
import stat
import struct
import sys
import types
import pytest

_PREFIXES = ("lifter", "packer", "daedalus")
_EXCLUDED = {".git", ".venv", "venv", "env", "build", "__pycache__", ".pytest_cache"}
_TEST = "tests/test_selected_wrapper_materialized.py"


def _hash(path):
    return sha256(path.read_bytes()).hexdigest()


def _managed_files(root):
    # Only these explicit metadata/output names are excluded. Never descend or
    # read excluded contents; no source-gate waiver is inferred from this copy.
    root = Path(root)
    if not root.is_absolute() or len(root.parents) > 64:
        raise RuntimeError("producer root is not bounded absolute path")
    for path in (root, *root.parents):
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400:
            raise RuntimeError("producer root reparse path")
    if root.resolve() != root or not stat.S_ISDIR(root.lstat().st_mode):
        raise RuntimeError("producer root is not canonical directory")
    result, pending, entries, total = {}, [(root, ())], 0, 0
    logical_names = set()
    while pending:
        directory, relative = pending.pop()
        with os.scandir(directory) as children:
            for child in children:
                entries += 1
                if entries > 8192:
                    raise RuntimeError("producer entry bound exceeded")
                name = child.name
                if name == ".git":  # Both ordinary .git files and directories are metadata.
                    continue
                parts = (*relative, name)
                st = Path(child.path).lstat()  # Fresh Windows link/inode metadata, not DirEntry cache.
                if (stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400) and (name in _EXCLUDED or name.startswith(("build_", ".codex-test-tmp", ".test-tmp", ".test-"))):
                    continue  # Link metadata only; never inspect excluded contents.
                if stat.S_ISREG(st.st_mode) and name.endswith((".pyc", ".pyo")):
                    continue
                if len(parts) > 16:
                    raise RuntimeError("producer depth bound exceeded")
                if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400:
                    raise RuntimeError("producer refuses included reparse input")
                path = Path(child.path)
                if stat.S_ISDIR(st.st_mode):
                    pending.append((path, parts))
                    if len(pending) > 2048:
                        raise RuntimeError("producer directory work bound exceeded")
                    continue
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise RuntimeError("producer refuses file physical alias or nonordinary input")
                if st.st_size > 32 * 1024 * 1024:
                    raise RuntimeError("producer file size bound exceeded")
                total += st.st_size
                if total > 256 * 1024 * 1024:
                    raise RuntimeError("producer aggregate size bound exceeded")
                rel = "/".join(parts)
                if rel.casefold() in logical_names or len(result) >= 2048:
                    raise RuntimeError("producer file inventory bound/alias exceeded")
                logical_names.add(rel.casefold())
                result[rel] = path
    return result


def _copy_managed_files(files, target_root):
    # Full metadata/size work is completed before any file content is copied.
    # Recheck immediately and use a bounded read, not unbounded read_bytes.
    total = 0
    for rel, path in files.items():
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or getattr(st, "st_file_attributes", 0) & 0x400:
            raise RuntimeError("producer copy input changed type/alias")
        if st.st_size > 32 * 1024 * 1024:
            raise RuntimeError("producer copy size bound exceeded")
        total += st.st_size
        if total > 256 * 1024 * 1024:
            raise RuntimeError("producer copy aggregate bound exceeded")
    copied = 0
    for rel, path in files.items():
        # Stable ordinary filesystem contract: no continuous lock or transient
        # I/O provenance claim. A post-preflight content growth stays bounded.
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or getattr(st, "st_file_attributes", 0) & 0x400:
            raise RuntimeError("producer copy input changed type/alias")
        with path.open("rb") as stream:
            raw = stream.read(32 * 1024 * 1024 + 1)
        if len(raw) > 32 * 1024 * 1024:
            raise RuntimeError("producer copy read bound exceeded")
        copied += len(raw)
        if copied > 256 * 1024 * 1024:
            raise RuntimeError("producer copied aggregate bound exceeded")
        target = target_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)


def _import_actual(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf8")
    return _hash(path)


@pytest.fixture(scope="module")
def bound(tmp_path_factory, request):
    input_root = Path(request.config.rootpath).resolve()
    files = _managed_files(input_root)
    assert _TEST in files
    owned = tmp_path_factory.mktemp("source-gate-owned")
    source = owned / "source"
    source.mkdir()
    _copy_managed_files(files, source)
    pins = {rel: _hash(source / rel) for rel in files}
    manifest = owned / "full-source.json"
    digest = _write_json(manifest, pins)
    saved = {n: m for n, m in sys.modules.items() if any(n == p or n.startswith(p + ".") for p in _PREFIXES)}
    old_path = list(sys.path)
    for name in saved:
        del sys.modules[name]
    sys.path[:] = [str(source)] + [p for p in old_path if not any((Path(p or os.getcwd()) / role).is_dir() for role in _PREFIXES)]
    gate = _import_actual(source / _TEST, "selected_wrapper_source_gate_actual")
    calls = []
    patch = pytest.MonkeyPatch()
    def forbidden(*args, **kwargs):
        calls.append("native entrypoint")
        raise RuntimeError("COMPONENT_NATIVE_LAUNCH_TRIPWIRE")
    for obj, names in ((gate, ("emit_product_fixture",)), (gate.bounded, ("_run_bounded",)),
            (gate.runtime, ("runtime_compile_session", "build_runtime_objects", "prove_runtime_coff_compilation")),
            (gate.public, ("verify_product_fixture_final_link",))):
        for name in names:
            patch.setattr(obj, name, forbidden)
    context = gate._source_manifest({"path": str(manifest), "sha256": digest}, digest, source)
    record = {"input_root": str(input_root), "owned_source": str(source), "manifest": str(manifest),
              "manifest_sha256": digest, "files": len(pins), "test_sha256": _hash(source / _TEST),
              "actual_module_file": gate.__file__, "actual_module_spec_origin": gate.__spec__.origin,
              "producer_excluded_directory_names": sorted(_EXCLUDED), "native_entrypoint_calls": calls,
              "memory_attestation": False}
    yield gate, context, owned, pins
    assert calls == []
    assert {n: _hash(source / n) for n in pins} == pins
    record["native_entrypoint_calls"] = list(calls)
    record["actual_source_bytes_unchanged"] = True
    _write_json(owned / "component-binding.json", record)
    if os.environ.get("SG14_BINDING_RECEIPT"):
        _write_json(Path(os.environ["SG14_BINDING_RECEIPT"]), record)
    patch.undo()
    for name, module in tuple(sys.modules.items()):
        file = getattr(module, "__file__", None)
        if any(name == p or name.startswith(p + ".") for p in _PREFIXES) or (type(file) is str and Path(file).is_relative_to(source)):
            sys.modules.pop(name, None)
    sys.modules.update(saved)
    sys.path[:] = old_path


@pytest.fixture
def generated(bound, tmp_path):
    _, context, _, pins = bound
    root = tmp_path / "source"
    root.mkdir()
    _copy_managed_files(_managed_files(context["root"]), root)
    module = _import_actual(root / _TEST, "source_gate_generated_" + tmp_path.name.replace("-", "_"))
    manifest = tmp_path / "full-source.json"
    digest = _write_json(manifest, pins)
    return module, root, manifest, digest, dict(pins)


@pytest.mark.parametrize("name", ("README.md", ".github/workflows/ci.yml", "lifter/runtime_coff_compile.py", "tests/a-b_1 (copy).txt"))
def test_relative_positive(bound, name):
    assert bound[0]._source_relative(name) == name.split("/")


@pytest.mark.parametrize("name", (None, 1, "", "/root.py", "../a", "a/../b", "a//b", "a/./b", "C:/a", "C:a", "a\\b", "x:stream", "a/", "a.", "a ", "CON", "nul.txt", "x/COM1.py", "__pycache__/x.py", ".pytest_cache/x", "x\ny", "x" * 241, "/".join(["x"] * 17)))
def test_relative_negative(bound, name):
    with pytest.raises(pytest.fail.Exception):
        bound[0]._source_relative(name)


def test_positive_full_freeze_and_provenance(bound, tmp_path):
    gate, context, _, pins = bound
    assert set(gate._source_files(context)) == set(pins)
    gate._source_provenance(context, tmp_path, "positive")
    row = json.loads((tmp_path / "source-positive.json").read_bytes())
    assert row["managed_file_count"] == len(pins)
    assert row["current_test"]["sha256"] == pins[_TEST]
    assert row["source_manifest"]["sha256"] == context["manifest_sha256"]
    assert row["loaded_python_memory_attestation_proven"] is False
    assert gate._SOURCE_REQUIRED_MODULES <= {r["name"] for r in row["loaded_project_modules"]}
    for module in row["loaded_project_modules"]:
        if module["kind"] == "file":
            assert Path(module["file"]).is_relative_to(context["root"])
            assert Path(module["spec_origin"]) == Path(module["file"])
            assert _hash(Path(module["file"])) == module["sha256"]


@pytest.mark.parametrize("record", ({}, {"path": "x"}, {"path": "x", "sha256": "x", "extra": 1}, [], None))
def test_manifest_record_closed(bound, record):
    gate, context, _, _ = bound
    with pytest.raises(pytest.fail.Exception):
        gate._source_manifest(record, context["manifest_sha256"], context["root"])


@pytest.mark.parametrize("mode", ("wrong_digest", "omitted_test", "omitted_file", "added_pin", "case_alias", "bad_digest", "duplicate_key", "traversal"))
def test_manifest_inventory_mutations(generated, mode):
    gate, root, manifest, digest, pins = generated
    if mode == "wrong_digest": digest = "0" * 64
    elif mode == "omitted_test": pins.pop(_TEST)
    elif mode == "omitted_file": pins.pop("README.md")
    elif mode == "added_pin": pins["not-present.txt"] = "0" * 64
    elif mode == "case_alias": pins["readme.md"] = pins["README.md"]
    elif mode == "bad_digest": pins["README.md"] = "a" * 63
    elif mode == "traversal": pins["../escape"] = "0" * 64
    if mode == "duplicate_key":
        manifest.write_bytes(b'{"README.md":"' + b"0" * 64 + b'","README.md":"' + b"1" * 64 + b'"}')
        digest = _hash(manifest)
    elif mode != "wrong_digest": digest = _write_json(manifest, pins)
    with pytest.raises(pytest.fail.Exception):
        gate._source_manifest({"path": str(manifest), "sha256": digest}, digest, root)


@pytest.mark.parametrize("mode", ("added_file", "missing_file", "changed_file", "changed_test", "wrong_test_pin", "manifest_inside_root", "changed_manifest"))
def test_source_files_mutations(generated, mode):
    gate, root, manifest, digest, pins = generated
    if mode == "added_file": (root / "new-generated.txt").write_bytes(b"generated")
    elif mode == "missing_file": (root / "README.md").unlink()
    elif mode == "changed_file": (root / "README.md").write_bytes(b"changed generated source copy")
    elif mode == "changed_test": (root / _TEST).write_bytes((root / _TEST).read_bytes() + b"\n# changed\n")
    elif mode == "wrong_test_pin":
        pins[_TEST] = "0" * 64
        digest = _write_json(manifest, pins)
    elif mode == "manifest_inside_root":
        manifest = root / "freeze.json"
        digest = _write_json(manifest, pins)
    elif mode == "changed_manifest": manifest.write_bytes(manifest.read_bytes() + b" ")
    with pytest.raises(pytest.fail.Exception):
        gate._source_manifest({"path": str(manifest), "sha256": digest}, digest, root)


def test_actual_generated_hardlink_rejects(generated):
    gate, root, manifest, digest, _ = generated
    first, second = root / "owned-first.txt", root / "owned-second.txt"
    first.write_bytes(b"only generated file bytes")
    os.link(first, second)
    assert first.stat().st_nlink == second.stat().st_nlink == 2
    with pytest.raises(pytest.fail.Exception, match="alias/size"):
        gate._source_manifest({"path": str(manifest), "sha256": digest}, digest, root)


def test_actual_generated_reparse_parent_rejects(generated, tmp_path):
    gate, root, manifest, digest, _ = generated
    target = tmp_path / "junction-target"
    target.mkdir()
    (target / "generated.txt").write_bytes(b"only generated bytes")
    junction = root / "owned-junction"
    junction.mkdir()
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.argtypes=(ctypes.c_wchar_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p)
    k.CreateFileW.restype=ctypes.c_void_p
    k.DeviceIoControl.argtypes=(ctypes.c_void_p,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint32),ctypes.c_void_p)
    k.DeviceIoControl.restype=ctypes.c_int
    k.CloseHandle.argtypes=(ctypes.c_void_p,)
    k.CloseHandle.restype=ctypes.c_int
    handle=k.CreateFileW(str(junction),0x40000000,0,None,3,0x02200000,None)
    if handle == ctypes.c_void_p(-1).value:
        junction.rmdir()
        pytest.skip("generated junction CreateFileW unavailable: " + str(ctypes.get_last_error()))
    substitute=("\\??\\" + str(target)).encode("utf-16-le")
    printed=str(target).encode("utf-16-le")
    payload=substitute+b"\x00\x00"+printed+b"\x00\x00"
    raw=struct.pack("<IHHHHHH",0xA0000003,8+len(payload),0,0,len(substitute),len(substitute)+2,len(printed))+payload
    buffer=ctypes.create_string_buffer(raw)
    returned=ctypes.c_uint32()
    ok=k.DeviceIoControl(handle,0x900A4,buffer,len(raw),None,0,ctypes.byref(returned),None)
    error=ctypes.get_last_error()
    assert k.CloseHandle(handle)
    if not ok:
        junction.rmdir()
        pytest.skip("generated junction reparse unavailable: " + str(error))
    try:
        assert junction.stat(follow_symlinks=False).st_file_attributes & 0x400
        with pytest.raises((pytest.fail.Exception, sys.modules["lifter.source_link_product_admission"].ProductSourceProofError), match="reparse|symlink"):
            gate._source_manifest({"path": str(manifest), "sha256": digest}, digest, root)
    finally:
        junction.rmdir()  # Exact generated junction only, never recursive target deletion.


@pytest.mark.parametrize("mode", ("wrong_file", "wrong_spec_origin", "missing_file", "missing_spec", "wrong_spec_name", "wrong_hash_pin"))
def test_loaded_module_metadata_rejects(bound, tmp_path, monkeypatch, mode):
    gate, context, _, _ = bound
    module = sys.modules["lifter.runtime_coff_compile"]
    other = context["root"] / "lifter/structured_vm_thunk.py"
    if mode == "wrong_file": monkeypatch.setattr(module, "__file__", str(other))
    elif mode == "wrong_spec_origin": monkeypatch.setattr(module.__spec__, "origin", str(other))
    elif mode == "missing_file": monkeypatch.setattr(module, "__file__", None)
    elif mode == "missing_spec": monkeypatch.setattr(module, "__spec__", None)
    elif mode == "wrong_spec_name": monkeypatch.setattr(module.__spec__, "name", "lifter.wrong")
    elif mode == "wrong_hash_pin":
        context = dict(context, pins=dict(context["pins"]))
        context["pins"]["lifter/runtime_coff_compile.py"] = "0" * 64
    with pytest.raises(pytest.fail.Exception): gate._source_provenance(context, tmp_path, "negative")
    assert not (tmp_path / "source-negative.json").exists()


@pytest.mark.parametrize("mode", ("missing_required", "unknown_module", "cross_namespace_path", "cross_namespace_spec", "cross_regular_package"))
def test_loaded_inventory_search_paths_rejects(bound, tmp_path, monkeypatch, mode):
    gate, context, _, _ = bound
    outside = tmp_path / "outside"
    outside.mkdir()
    if mode == "missing_required": monkeypatch.delitem(sys.modules, "lifter.runtime_coff_compile")
    elif mode == "unknown_module":
        module=types.ModuleType("lifter.not_frozen")
        module.__spec__=importlib.util.spec_from_loader("lifter.not_frozen", loader=None)
        monkeypatch.setitem(sys.modules,"lifter.not_frozen",module)
    elif mode == "cross_namespace_path": monkeypatch.setattr(sys.modules["lifter"],"__path__",[str(context["root"] / "lifter"),str(outside)])
    elif mode == "cross_namespace_spec": monkeypatch.setattr(sys.modules["lifter"].__spec__,"submodule_search_locations",[str(outside)])
    elif mode == "cross_regular_package": monkeypatch.setattr(sys.modules["packer"],"__path__",[str(context["root"] / "packer"),str(outside)])
    error_type = (sys.modules["lifter.source_link_product_admission"].ProductSourceProofError
                  if mode == "unknown_module" else pytest.fail.Exception)
    message = "source proof path component is missing" if mode == "unknown_module" else None
    with pytest.raises(error_type, match=message): gate._source_provenance(context, tmp_path, "negative")


def test_current_test_spec_origin_rejects(bound, tmp_path, monkeypatch):
    gate, context, _, _ = bound
    monkeypatch.setattr(gate.__spec__, "origin", str(context["root"] / "README.md"))
    with pytest.raises(pytest.fail.Exception, match="test spec origin"):
        gate._source_provenance(context, tmp_path, "negative")


@pytest.mark.parametrize("mode", ("all_missing", "source_missing", "source_malformed"))
def test_required_native_early_preflight_stays_before_launch(bound, monkeypatch, mode):
    gate = bound[0]
    for name in tuple(os.environ):
        if name.startswith("LETHE_SELECTED_WRAPPER"): monkeypatch.delenv(name)
    monkeypatch.setenv("LETHE_SELECTED_WRAPPER_REQUIRE_NATIVE", "1")
    if mode != "all_missing":
        monkeypatch.setenv("LETHE_SELECTED_WRAPPER_FIXTURE_MANIFEST", "not-opened")
        monkeypatch.setenv("LETHE_SELECTED_WRAPPER_FIXTURE_MANIFEST_SHA256", "0" * 64)
        monkeypatch.setenv("LETHE_SELECTED_WRAPPER_RUNTIME_PROFILE_SHA256", "0" * 64)
    if mode == "source_malformed": monkeypatch.setenv("LETHE_SELECTED_WRAPPER_SOURCE_MANIFEST_SHA256", "not-a-sha")
    with pytest.raises(pytest.fail.Exception, match="missing|malformed"): gate._manifest()


def test_provenance_multiple_checkpoints_and_no_overwrite(bound, tmp_path):
    gate, context, _, _ = bound
    gate._source_provenance(context, tmp_path, "first")
    gate._source_provenance(context, tmp_path, "second")
    with pytest.raises(pytest.fail.Exception, match="overwrite"):
        gate._source_provenance(context, tmp_path, "second")



def _producer_generated_junction(junction, target):
    junction.mkdir()
    substitute=(chr(92)+"??"+chr(92)+str(target)).encode("utf-16-le")
    printed=str(target).encode("utf-16-le")
    payload=substitute+b"\x00\x00"+printed+b"\x00\x00"
    raw=struct.pack("<IHHHHHH",0xA0000003,8+len(payload),0,0,len(substitute),len(substitute)+2,len(printed))+payload
    k=ctypes.WinDLL("kernel32",use_last_error=True)
    k.CreateFileW.argtypes=(ctypes.c_wchar_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p)
    k.CreateFileW.restype=ctypes.c_void_p
    k.DeviceIoControl.argtypes=(ctypes.c_void_p,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint32),ctypes.c_void_p)
    k.DeviceIoControl.restype=ctypes.c_int
    k.CloseHandle.argtypes=(ctypes.c_void_p,);k.CloseHandle.restype=ctypes.c_int
    handle=k.CreateFileW(str(junction),0x40000000,0,None,3,0x02200000,None)
    if handle==ctypes.c_void_p(-1).value:
        junction.rmdir()
        pytest.skip("generated producer junction CreateFileW: "+str(ctypes.get_last_error()))
    try:
        buffer=ctypes.create_string_buffer(raw);returned=ctypes.c_uint32()
        ok=k.DeviceIoControl(handle,0x900A4,buffer,len(raw),None,0,ctypes.byref(returned),None)
        error=ctypes.get_last_error()
    finally:
        assert k.CloseHandle(handle)
    if not ok:
        junction.rmdir()
        pytest.skip("generated producer junction reparse: "+str(error))
    assert junction.lstat().st_file_attributes & 0x400


def test_producer_small_positive(tmp_path):
    root=tmp_path/"input";root.mkdir();(root/"sub").mkdir()
    (root/"a.txt").write_bytes(b"a");(root/"sub/b.txt").write_bytes(b"bb");(root/"build_notes.txt").write_bytes(b"source, not a directory")
    files=_managed_files(root)
    assert set(files)=={"a.txt","sub/b.txt","build_notes.txt"}
    out=tmp_path/"copied";out.mkdir();_copy_managed_files(files,out)
    assert (out/"a.txt").read_bytes()==b"a" and (out/"sub/b.txt").read_bytes()==b"bb"


@pytest.mark.skipif(os.name!="nt",reason="actual generated Win32 junction")
def test_producer_included_junction_rejects_before_descent(tmp_path,monkeypatch):
    root=tmp_path/"input";root.mkdir();outside=tmp_path/"outside";outside.mkdir()
    (outside/"not-an-input.txt").write_bytes(b"outside generated bytes")
    junction=root/"included";_producer_generated_junction(junction,outside)
    calls=[];original=os.scandir
    def observer(path):
        if Path(path)==junction or Path(path).is_relative_to(outside):
            calls.append(str(path))
            raise AssertionError("producer descended into outside junction")
        return original(path)
    monkeypatch.setattr(os,"scandir",observer)
    try:
        with pytest.raises(RuntimeError,match="reparse"):_managed_files(root)
        assert calls==[]
    finally:junction.rmdir()


@pytest.mark.skipif(os.name!="nt",reason="actual generated Win32 junction")
def test_producer_excluded_metadata_junction_is_not_read(tmp_path,monkeypatch):
    root=tmp_path/"input";root.mkdir();outside=tmp_path/"outside";outside.mkdir()
    (root/"a.txt").write_bytes(b"a");(outside/"not-an-input.txt").write_bytes(b"outside")
    junction=root/".venv";_producer_generated_junction(junction,outside)
    calls=[];original=os.scandir
    def observer(path):
        if Path(path)==junction or Path(path).is_relative_to(outside):
            calls.append(str(path));raise AssertionError("excluded metadata content read")
        return original(path)
    monkeypatch.setattr(os,"scandir",observer)
    try:
        assert set(_managed_files(root))=={"a.txt"} and calls==[]
    finally:junction.rmdir()


def test_producer_hardlink_rejects(tmp_path):
    root=tmp_path/"input";root.mkdir();a=root/"a.txt";a.write_bytes(b"generated")
    os.link(a,root/"b.txt")
    assert a.stat().st_nlink==2
    with pytest.raises(RuntimeError,match="physical alias"):_managed_files(root)


def test_producer_depth_rejects(tmp_path):
    root=tmp_path/"input";root.mkdir();deep=root
    for _ in range(17):deep=deep/"d";deep.mkdir()
    with pytest.raises(RuntimeError,match="depth"):_managed_files(root)


def test_producer_file_size_rejects_before_content_read(tmp_path,monkeypatch):
    root=tmp_path/"input";root.mkdir()
    with (root/"large.bin").open("wb") as stream:stream.truncate(32*1024*1024+1)
    calls=[]
    def forbidden(*args,**kwargs):calls.append(True);raise AssertionError("content read before producer size rejection")
    monkeypatch.setattr(Path,"read_bytes",forbidden)
    with pytest.raises(RuntimeError,match="file size"):_managed_files(root)
    assert calls==[]


def test_producer_aggregate_rejects_before_content_read(tmp_path,monkeypatch):
    root=tmp_path/"input";root.mkdir()
    for i in range(9):
        with (root/(str(i)+".bin")).open("wb") as stream:stream.truncate(32*1024*1024)
    calls=[]
    def forbidden(*args,**kwargs):calls.append(True);raise AssertionError("content read before producer aggregate rejection")
    monkeypatch.setattr(Path,"read_bytes",forbidden)
    with pytest.raises(RuntimeError,match="aggregate size"):_managed_files(root)
    assert calls==[]
