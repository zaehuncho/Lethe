"""Required current-source synthetic EXE/DLL lane; default offline run skips.

Configure a schema-2 fixture envelope with a closed schema-3, schema-4 or schema-5 runtime profile,
its SHA256, and the independently explicit
LETHE_SELECTED_WRAPPER_RUNTIME_PROFILE_SHA256 plus the independently explicit
LETHE_SELECTED_WRAPPER_SOURCE_MANIFEST_SHA256. REQUIRE_NATIVE=1 makes missing
prerequisites fail. No supplied runtime objects or supplied final-link receipts
can satisfy the positive path. Both cases share one active factory session.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys

import pytest

from lifter import product_fixture_link_verify as public
from lifter import selected_wrapper_binding, structured_vm_thunk
from lifter import runtime_coff_compile as runtime
from lifter import link_capture_final_callsites as bounded
from lifter.link_capture_response_pair import _environment_profile
from lifter.source_link_product_admission import ProductSourceInputs, _reject_reparse_components
from lifter.source_link_product_fixture import emit_product_fixture


_ENV = "LETHE_SELECTED_WRAPPER_FIXTURE_MANIFEST"
_SOURCE_ENV = "LETHE_SELECTED_WRAPPER_SOURCE_MANIFEST_SHA256"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_RUNTIME_PROFILE = "msvc-14.44.35207-sdk-10.0.26100.0-raw-v3"
_LEGACY_PROFILE = "msvc-14.44.35207-sdk-10.0.26100.0-raw-v2"
_RUNTIME_PROFILE_V4 = "msvc-14.44.35207-sdk-10.0.26100.0-raw-v4"
_RUNTIME_PROFILE_V5 = "msvc-14.44.35207-sdk-10.0.26100.0-raw-v5"
_NATIVE_IMAGE_PATTERN = re.compile(r"C:\\Windows\\assembly\\NativeImages_v4\.0\.30319_64\\Microsoft\.V8f370856#\\[0-9a-f]{32}\\Microsoft\.VisualStudio\.RemoteControl\.ni\.dll\Z")
_NEWTON_IMAGE_PATTERN = re.compile(r"C:\\Windows\\assembly\\NativeImages_v4\.0\.30319_64\\Newtonsoft\.Json\\[0-9a-f]{32}\\Newtonsoft\.Json\.ni\.dll\Z")
_FRAMEWORK_IMAGE_PATTERN = re.compile(r"C:\\Windows\\assembly\\NativeImages_v4\.0\.30319_64\\System\.Runteb92aa12#\\[0-9a-f]{32}\\System\.Runtime\.Serialization\.ni\.dll\Z")
_SETUP_SUPPORT = Path(r"C:\ProgramData\Microsoft\VisualStudio\Setup\x64\Microsoft.VisualStudio.Setup.Configuration.Native.dll")
_ROLES = ("daedalus_vm", "crypto", "bytecode_pages", "key_scatter",
          "daedalus_x64_thunk", "daedalus_store128", "daedalus_call_frame",
          "daedalus_trampoline")
_TOOLS = {"cl", "ml64", "link_exe", "vsdevcmd", "dia_helper", "msdia", "typed_abi_helper"}
_EXPECTED = {"policy": (32, b"policy_bits=CECECCCE passed=true\r\n"),
             "lease": (20, b"lease_bits=2B663 passed=true\r\n")}
_FLAGS = ("/NOLOGO", "/DEBUG:FULL", "/INCREMENTAL:NO", "/OPT:REF", "/OPT:NOICF",
          "/BREPRO", "/MAP", "/CETCOMPAT", "/GUARD:CF", "/GUARD:XFG",
          "/MACHINE:X64", "/MANIFEST", "/MANIFEST:EMBED", "/SUBSYSTEM:CONSOLE", "/VERBOSE:LIB")
_CFLAGS = ("/nologo", "/c", "/O2", "/GL-", "/Z7", "/Gy", "/Gw", "/GS", "/MD",
           "/guard:cf", "/guard:xfg", "/ZH:SHA_256", "/DDVM_PAGED_RUNTIME", "/Brepro")
_CASE_KEYS = {"source_image", "source_pdb", "source_map", "source_helper_object", "source_header",
              "original_capture", "caller_object", "native_initializer_object", "symbol", "abi",
              "prefix", "image_name", "vector_count", "expected_stdout", "host_image"}
_TRUE = ("final_link_byte_binding_proven", "linked_fixture_structure_verified",
         "original_helper_object_omission_proven", "authenticated_selected_wrapper_reference_binding_proven",
         "selected_direct_source_output_equivalence_proven", "runtime_source_compile_binding_proven")
_FALSE = ("source_reference_closure_proven", "global_source_output_reference_equivalence_proven",
          "indirect_target_closure_proven", "xfg_enforcement_proven", "production_key_service_configured",
          "production_admitted")


def _require(value, reason):
    if not value:
        pytest.fail(reason)


def _hash(path):
    result = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def _ordinary(name, *, directory=False):
    _require(type(name) is str, "fixture paths must be exact strings")
    path = Path(name)
    _require(path.is_absolute() and path.resolve() == path, "fixture path is not canonical/absolute")
    _reject_reparse_components(path)
    _require(path.is_dir() if directory else path.is_file(), "fixture path has wrong type")
    return path


def _pairs(items):
    result = {}
    for key, value in items:
        _require(key not in result, "duplicate JSON key in fixture trust inputs")
        result[key] = value
    return result


def _json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_pairs)
    except (ValueError, UnicodeError, RecursionError) as exc:
        pytest.fail("invalid fixture trust-input JSON: " + str(exc))


def _check_pins(pins):
    for path, digest in pins.items():
        _ordinary(str(path))
        _require(_hash(path) == digest, "fixture input changed: " + str(path))



_SOURCE_PREFIXES = ("lifter", "packer", "daedalus")
_SOURCE_REQUIRED_MODULES = {
    "lifter.product_fixture_link_verify", "lifter.selected_wrapper_binding",
    "lifter.structured_vm_thunk", "lifter.runtime_coff_compile",
    "lifter.link_capture_final_callsites", "lifter.link_capture_response_pair",
    "lifter.source_link_product_admission", "lifter.source_link_product_fixture",
}
_SOURCE_CACHE_DIRECTORIES = {"__pycache__", ".pytest_cache"}
_SOURCE_TEST = "tests/test_selected_wrapper_materialized.py"


def _source_relative(name):
    _require(type(name) is str and 1 <= len(name) <= 240 and
             re.fullmatch(r"[A-Za-z0-9_./ ()-]+", name) is not None,
             "source inventory name is not a bounded portable relative path")
    parts = name.split("/")
    _require(1 <= len(parts) <= 16 and all(p and p not in (".", "..") and
             not p.endswith((".", " ")) and p not in _SOURCE_CACHE_DIRECTORIES and
             re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", p, re.I) is None
             for p in parts) and not PurePosixPath(name).is_absolute(),
             "unsafe/ambiguous source inventory path")
    return parts


def _source_inventory(source_root):
    # This is an isolated managed-source copy, not an arbitrary checkout with
    # a .git, venv, build directory or evidence outputs. Only named caches are
    # excluded. A loaded project module can never be sourced from a cache.
    found, pending, entries = {}, [(source_root, ())], 0
    while pending:
        directory, relative = pending.pop()
        _ordinary(str(directory), directory=True)
        _require(len(relative) <= 16, "source directory depth exceeds bound")
        with os.scandir(directory) as children:
            for child in children:
                entries += 1
                _require(entries <= 8192, "source tree entry count exceeds bound")
                path = Path(child.path)
                _reject_reparse_components(path)
                if child.is_dir(follow_symlinks=False):
                    if child.name not in _SOURCE_CACHE_DIRECTORIES:
                        pending.append((path, (*relative, child.name)))
                        _require(len(pending) <= 2048, "source directory work bound exceeded")
                    continue
                name = "/".join((*relative, child.name))
                _source_relative(name)
                _ordinary(str(path))
                st = path.stat()
                _require(st.st_nlink == 1 and st.st_size <= 32 * 1024 * 1024,
                         "source file has alias/size outside managed-copy contract")
                _require(name not in found and len(found) < 2048, "source inventory exceeds bound")
                found[name] = path
    return found


def _source_manifest(record, digest, source_root):
    _require(type(record) is dict and set(record) == {"path", "sha256"} and
             type(digest) is str and _HEX.fullmatch(digest) is not None and record["sha256"] == digest,
             "explicit full-source manifest SHA256 differs/missing")
    path = _ordinary(record["path"])
    _require(not path.is_relative_to(source_root) and path.stat().st_nlink == 1 and
             path.stat().st_size <= 1024 * 1024, "source manifest must be bounded external ordinary file")
    raw = path.read_bytes()
    _require(sha256(raw).hexdigest() == digest, "full-source manifest bytes differ")
    pins = _json(raw)
    _require(type(pins) is dict and 1 <= len(pins) <= 2048, "bounded full-source inventory required")
    names = set()
    for name, value in pins.items():
        _source_relative(name)
        _require(name.casefold() not in names and type(value) is str and _HEX.fullmatch(value) is not None,
                 "case-aliased source path or malformed source digest")
        names.add(name.casefold())
    _require(_SOURCE_TEST in pins, "current maintained test absent from source freeze")
    context = {"root": source_root, "manifest_path": path, "manifest_sha256": digest, "pins": dict(pins)}
    _source_files(context)
    return context


def _source_files(context):
    path = _ordinary(str(context["manifest_path"]))
    _require(path.stat().st_nlink == 1 and path.stat().st_size <= 1024 * 1024 and
             _hash(path) == context["manifest_sha256"], "source manifest changed")
    actual = _source_inventory(context["root"])
    _require(set(actual) == set(context["pins"]), "full-source inventory omitted/added a managed file")
    total = 0
    for name, path in actual.items():
        total += path.stat().st_size
        _require(total <= 256 * 1024 * 1024, "aggregate source size exceeds bound")
        _require(_hash(path) == context["pins"][name], "managed source file changed: " + name)
    test = _ordinary(str(Path(__file__)))
    _require(test == context["root"] / _SOURCE_TEST and _hash(test) == context["pins"][_SOURCE_TEST],
             "current test file is not exact frozen maintained test")
    _require(__spec__ is not None and type(__spec__.origin) is str and
             _ordinary(__spec__.origin) == test, "current test spec origin differs")
    return actual


def _source_provenance(context, logs, label):
    actual = _source_files(context)
    loaded = tuple(sys.modules.items())
    _require(len(loaded) <= 65536, "loaded-module work bound exceeded")
    rows, present = [], set()
    for name, module in loaded:
        if not any(name == p or name.startswith(p + ".") for p in _SOURCE_PREFIXES):
            continue
        _require(type(name) is str and all(part.isidentifier() for part in name.split(".")) and
                 len(name) <= 240 and module is not None and len(rows) < 2048,
                 "malformed/oversized loaded project-module inventory")
        relative = name.replace(".", "/")
        candidates = tuple(p for p in (relative + ".py", relative + "/__init__.py") if p in actual)
        spec = getattr(module, "__spec__", None)
        _require(spec is not None and spec.name == name, "loaded project-module spec name differs")
        if not candidates:
            directory = context["root"] / relative
            _ordinary(str(directory), directory=True)
            _require(getattr(module, "__file__", None) is None and spec.origin is None and
                     any(p.startswith(relative + "/") for p in actual), "unfrozen/non-namespace project module")
            paths = tuple(getattr(module, "__path__", ()))
            searches = tuple(spec.submodule_search_locations or ())
            _require(1 <= len(paths) <= 32 and 1 <= len(searches) <= 32 and
                     all(type(p) is str and _ordinary(p, directory=True) == directory for p in (*paths, *searches)),
                     "namespace project module has another source search location")
            rows.append({"name": name, "kind": "namespace", "directory": str(directory),
                         "file": None, "spec_origin": None, "search_paths": list(paths),
                         "spec_search_paths": list(searches)})
        else:
            _require(len(candidates) == 1, "ambiguous package/module source in freeze")
            source = actual[candidates[0]]
            file = getattr(module, "__file__", None)
            _require(type(file) is str and type(spec.origin) is str and
                     _ordinary(file) == source and _ordinary(spec.origin) == source,
                     "loaded project module file/spec origin differs from exact freeze")
            digest = _hash(source)
            _require(digest == context["pins"][candidates[0]], "loaded project-module raw hash differs")
            if candidates[0].endswith("/__init__.py"):
                searches = tuple(spec.submodule_search_locations or ())
                paths = tuple(getattr(module, "__path__", ()))
                _require(1 <= len(paths) <= 32 and 1 <= len(searches) <= 32 and
                         all(type(p) is str and _ordinary(p, directory=True) == source.parent for p in (*paths, *searches)),
                         "regular project package has another search location")
            else:
                _require(spec.submodule_search_locations is None and not hasattr(module, "__path__"),
                         "project source module was replaced with package")
            rows.append({"name": name, "kind": "file", "file": str(source),
                         "spec_origin": spec.origin, "sha256": digest})
        present.add(name)
    _require(_SOURCE_REQUIRED_MODULES <= present, "required direct project imports missing from provenance")
    _record(logs / ("source-" + label + ".json"), {
        "checkpoint": label, "source_root": str(context["root"]),
        "source_manifest": {"path": str(context["manifest_path"]), "sha256": context["manifest_sha256"]},
        "managed_file_count": len(actual), "current_test": {"path": str(context["root"] / _SOURCE_TEST),
        "sha256": context["pins"][_SOURCE_TEST]}, "loaded_project_modules": sorted(rows, key=lambda r: r["name"]),
        "loaded_python_memory_attestation_proven": False,
        "excluded_cache_directory_names": sorted(_SOURCE_CACHE_DIRECTORIES)})


def _native_image_path(name):
    _require(type(name) is str and len(name) <= 512 and _NATIVE_IMAGE_PATTERN.fullmatch(name) is not None,
             "strict RemoteControl native-image path differs")
    return Path(name)


def _runtime_profile_plan(plan, pins):
    if type(plan) is dict and type(plan.get("schema")) is int and plan["schema"] == 5:
        return _runtime_profile_plan_v5(plan, pins)
    if type(plan) is dict and type(plan.get("schema")) is int and plan["schema"] == 4:
        return _runtime_profile_plan_v4(plan, pins)
    profile_keys = {"schema", "profile", "tool_directory", "include_roots", "tool_pins", "external_headers", "ordered_includes", "support_files", "native_image_pins"}
    _require(type(plan) is dict and set(plan) == profile_keys and type(plan["schema"]) is int and plan["schema"] == 3,
             "closed schema-3 runtime trust-input profile required; legacy/missing-native profiles reject")
    _require(type(plan["tool_pins"]) is dict and len(plan["tool_pins"]) == 91 and
             type(plan["external_headers"]) is dict and len(plan["external_headers"]) == 160 and
             type(plan["include_roots"]) is list and len(plan["include_roots"]) == 6 and
             all(type(p) is str for p in plan["include_roots"]) and
             type(plan["profile"]) is str and plan["profile"] == _RUNTIME_PROFILE and type(plan["tool_directory"]) is str and
             type(plan["ordered_includes"]) is list and len(plan["ordered_includes"]) == 4,
             "reviewed recursive compiler/header profile differs")
    _require(all(type(p) is str and type(d) is str and _HEX.fullmatch(d) is not None
                 for inventory in (plan["tool_pins"], plan["external_headers"]) for p, d in inventory.items()),
             "runtime pin shape differs")
    _require(all(type(row) is list and len(row) == 2 and row[0] == role and type(row[1]) is list
                 and 1 <= len(row[1]) <= 1000 and all(type(name) is str for name in row[1])
                 for row, role in zip(plan["ordered_includes"], _ROLES[:4])), "ordered runtime include shape differs")
    _require(type(plan["support_files"]) is dict and set(plan["support_files"]) == {str(_SETUP_SUPPORT)}
             and type(plan["support_files"][str(_SETUP_SUPPORT)]) is str
             and _HEX.fullmatch(plan["support_files"][str(_SETUP_SUPPORT)]) is not None,
             "exact explicit singleton external Setup support pin required; no support-directory waiver")
    _require(_SETUP_SUPPORT in pins and pins[_SETUP_SUPPORT] == plan["support_files"][str(_SETUP_SUPPORT)],
             "Setup support pin differs between fixture and explicit runtime profile")

    native = plan["native_image_pins"]
    _require(type(native) is dict and len(native) == 1,
             "exact explicit singleton native-image pin required")
    native_name, native_digest = next(iter(native.items()))
    native_path = _native_image_path(native_name)
    _require(type(native_digest) is str and _HEX.fullmatch(native_digest) is not None,
             "native-image SHA256 shape differs")
    _require(native_path in pins and pins[native_path] == native_digest,
             "native-image pin differs between fixture and runtime profile")
    for inventory in (plan["tool_pins"], plan["external_headers"], plan["support_files"]):
        _require(native_path not in {Path(name) for name in inventory},
                 "native-image role overlaps another runtime input role")
    il_path = Path(plan["tool_directory"]) / "Microsoft.VisualStudio.RemoteControl.dll"
    _require(str(il_path) in plan["tool_pins"] and
             type(plan["tool_pins"][str(il_path)]) is str and
             _HEX.fullmatch(plan["tool_pins"][str(il_path)]) is not None,
             "exact RemoteControl IL tool pin is missing/different")
    # Compiler/header pins retain the existing independently SHA-bound profile
    # route and are freshly held/rechecked by the core. Only the separate NI
    # role and existing Setup role also duplicate pins in the outer fixture.
    return plan


def _native_image_path_v4(name):
    _require(type(name) is str and len(name) <= 512 and
             (_NATIVE_IMAGE_PATTERN.fullmatch(name) is not None or
              _NEWTON_IMAGE_PATTERN.fullmatch(name) is not None),
             "strict explicit v4 native-image path differs")
    return Path(name)


def _runtime_profile_plan_v4(plan, pins):
    profile_keys = {"schema", "profile", "tool_directory", "include_roots", "tool_pins", "external_headers", "ordered_includes", "support_files", "native_image_pins"}
    _require(type(plan) is dict and set(plan) == profile_keys and
             type(plan["schema"]) is int and plan["schema"] == 4 and
             type(plan["profile"]) is str and plan["profile"] == _RUNTIME_PROFILE_V4,
             "closed schema-4 exact v4 runtime trust-input profile required")
    _require(type(plan["tool_pins"]) is dict and len(plan["tool_pins"]) == 91 and
             type(plan["external_headers"]) is dict and len(plan["external_headers"]) == 160 and
             type(plan["include_roots"]) is list and len(plan["include_roots"]) == 6 and
             all(type(p) is str for p in plan["include_roots"]) and
             type(plan["tool_directory"]) is str and
             type(plan["ordered_includes"]) is list and len(plan["ordered_includes"]) == 4,
             "reviewed recursive compiler/header v4 profile differs")
    _require(all(type(p) is str and type(d) is str and _HEX.fullmatch(d) is not None
                 for inventory in (plan["tool_pins"], plan["external_headers"]) for p, d in inventory.items()),
             "runtime pin shape differs")
    _require(all(len({p.casefold() for p in inventory}) == len(inventory)
                 for inventory in (plan["tool_pins"], plan["external_headers"])),
             "ambiguous case-aliased runtime pin path")
    _require(all(type(row) is list and len(row) == 2 and row[0] == role and type(row[1]) is list
                 and 1 <= len(row[1]) <= 1000 and all(type(name) is str for name in row[1])
                 for row, role in zip(plan["ordered_includes"], _ROLES[:4])), "ordered runtime include shape differs")
    _require(type(plan["support_files"]) is dict and set(plan["support_files"]) == {str(_SETUP_SUPPORT)}
             and type(plan["support_files"][str(_SETUP_SUPPORT)]) is str
             and _HEX.fullmatch(plan["support_files"][str(_SETUP_SUPPORT)]) is not None,
             "exact explicit singleton external Setup support pin required; no support-directory waiver")
    _require(_SETUP_SUPPORT in pins and pins[_SETUP_SUPPORT] == plan["support_files"][str(_SETUP_SUPPORT)],
             "Setup support pin differs between fixture and explicit runtime profile")
    native = plan["native_image_pins"]
    _require(type(native) is dict and len(native) == 2, "v4 requires exactly two explicit native-image pins")
    families = set()
    for name, digest in native.items():
        path = _native_image_path_v4(name)
        family = "RemoteControl" if _NATIVE_IMAGE_PATTERN.fullmatch(name) is not None else "Newtonsoft"
        _require(family not in families, "duplicate/ambiguous v4 native-image family")
        families.add(family)
        _require(type(digest) is str and _HEX.fullmatch(digest) is not None, "native-image SHA256 shape differs")
        _require(path in pins and pins[path] == digest, "native-image pin differs between fixture and runtime profile")
        for inventory in (plan["tool_pins"], plan["external_headers"], plan["support_files"]):
            _require(path not in {Path(p) for p in inventory}, "native-image role overlaps another runtime input role")
    _require(families == {"RemoteControl", "Newtonsoft"}, "exact v4 native-image family pair required")
    for family, basename in (("RemoteControl", "Microsoft.VisualStudio.RemoteControl.dll"),
                             ("Newtonsoft", "Newtonsoft.Json.dll")):
        il_name = str(Path(plan["tool_directory"]) / basename)
        _require(il_name in plan["tool_pins"] and type(plan["tool_pins"][il_name]) is str and
                 _HEX.fullmatch(plan["tool_pins"][il_name]) is not None,
                 "exact " + family + " IL tool pin is missing/different")
     # The exact framework NI is an additional separate role; it is not part
     # of the two compiler NI paths or the Setup support pin.
    return plan


def _framework_native_image_path(name):
    _require(type(name) is str and len(name) <= 512 and _FRAMEWORK_IMAGE_PATTERN.fullmatch(name) is not None,
             "strict explicit singleton Serialization framework native-image path differs")
    return Path(name)


def _runtime_profile_plan_v5(plan, pins):
    profile_keys = {"schema", "profile", "tool_directory", "include_roots", "tool_pins", "external_headers", "ordered_includes", "support_files", "native_image_pins", "framework_native_image_pins"}
    _require(type(plan) is dict and set(plan) == profile_keys and
             type(plan["schema"]) is int and plan["schema"] == 5 and
             type(plan["profile"]) is str and plan["profile"] == _RUNTIME_PROFILE_V5,
             "closed schema-5 exact v5 runtime trust-input profile required")
    _require(type(plan["tool_pins"]) is dict and len(plan["tool_pins"]) == 91 and
             type(plan["external_headers"]) is dict and len(plan["external_headers"]) == 160 and
             type(plan["include_roots"]) is list and len(plan["include_roots"]) == 6 and
             all(type(p) is str for p in plan["include_roots"]) and
             type(plan["tool_directory"]) is str and
             type(plan["ordered_includes"]) is list and len(plan["ordered_includes"]) == 4,
             "reviewed recursive compiler/header v5 profile differs")
    _require(all(type(p) is str and type(d) is str and _HEX.fullmatch(d) is not None
                 for inventory in (plan["tool_pins"], plan["external_headers"]) for p, d in inventory.items()),
             "runtime pin shape differs")
    _require(all(len({p.casefold() for p in inventory}) == len(inventory)
                 for inventory in (plan["tool_pins"], plan["external_headers"])),
             "ambiguous case-aliased runtime pin path")
    _require(all(type(row) is list and len(row) == 2 and row[0] == role and type(row[1]) is list
                 and 1 <= len(row[1]) <= 1000 and all(type(name) is str for name in row[1])
                 for row, role in zip(plan["ordered_includes"], _ROLES[:4])), "ordered runtime include shape differs")
    _require(type(plan["support_files"]) is dict and set(plan["support_files"]) == {str(_SETUP_SUPPORT)}
             and type(plan["support_files"][str(_SETUP_SUPPORT)]) is str
             and _HEX.fullmatch(plan["support_files"][str(_SETUP_SUPPORT)]) is not None,
             "exact explicit singleton external Setup support pin required; no support-directory waiver")
    _require(_SETUP_SUPPORT in pins and pins[_SETUP_SUPPORT] == plan["support_files"][str(_SETUP_SUPPORT)],
             "Setup support pin differs between fixture and explicit runtime profile")
    native = plan["native_image_pins"]
    _require(type(native) is dict and len(native) == 2,
             "v5 requires exactly two explicit compiler native-image pins")
    families = set()
    for name, digest in native.items():
        path = _native_image_path_v4(name)
        family = "RemoteControl" if _NATIVE_IMAGE_PATTERN.fullmatch(name) is not None else "Newtonsoft"
        _require(family not in families, "duplicate/ambiguous v5 native-image family")
        families.add(family)
        _require(type(digest) is str and _HEX.fullmatch(digest) is not None, "native-image SHA256 shape differs")
        _require(path in pins and pins[path] == digest, "native-image pin differs between fixture and runtime profile")
        for inventory in (plan["tool_pins"], plan["external_headers"], plan["support_files"]):
            _require(path not in {Path(p) for p in inventory}, "native-image role overlaps another runtime input role")
    _require(families == {"RemoteControl", "Newtonsoft"}, "exact v5 native-image family pair required")
    for family, basename in (("RemoteControl", "Microsoft.VisualStudio.RemoteControl.dll"),
                             ("Newtonsoft", "Newtonsoft.Json.dll")):
        il_name = str(Path(plan["tool_directory"]) / basename)
        _require(il_name in plan["tool_pins"] and type(plan["tool_pins"][il_name]) is str and
                 _HEX.fullmatch(plan["tool_pins"][il_name]) is not None,
                 "exact " + family + " IL tool pin is missing/different")
    # The exact framework NI is a separate role, not a third compiler NI or
    # part of the Setup support pin.
    framework = plan["framework_native_image_pins"]
    _require(type(framework) is dict and len(framework) == 1,
             "exact separate singleton framework native-image pin required")
    framework_name, framework_digest = next(iter(framework.items()))
    framework_path = _framework_native_image_path(framework_name)
    _require(type(framework_digest) is str and _HEX.fullmatch(framework_digest) is not None,
             "framework native-image SHA256 shape differs")
    _require(any(type(path) is type(framework_path) and str(path) == framework_name and
                 digest == framework_digest for path, digest in pins.items()),
             "framework native-image path/digest differs exactly between fixture and runtime profile")
    for inventory in (plan["tool_pins"], plan["external_headers"], plan["support_files"], plan["native_image_pins"]):
        _require(framework_path not in {Path(name) for name in inventory},
                 "framework native-image role overlaps another runtime input role")
    return plan


def _verify_framework_native_image_proof(compiled, plan):
    required = {"profile", "framework_native_image_sha256", "framework_native_image_profile_sha256",
                "framework_IL_binding_proven", "managed_resource_reference_closure_proven"}
    _require(type(compiled) is dict and required <= set(compiled) and
             plan["profile"] == _RUNTIME_PROFILE_V5 and compiled["profile"] == plan["profile"],
             "explicit v5 framework proof fields/profile are missing or different")
    framework_profile = {"profile": plan["profile"],
        "allowed_role": "direct_child_vctip_LOAD_DLL_with_operator_pinned_framework_NI",
        "framework_native_image_pins": plan["framework_native_image_pins"]}
    framework_digest = sha256(json.dumps(framework_profile, sort_keys=True,
        separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
    _require(compiled["framework_native_image_sha256"] == plan["framework_native_image_pins"] and
             compiled["framework_native_image_profile_sha256"] == framework_digest,
             "fresh runtime proof did not bind the exact separate operator-pinned framework NI role")
    _require(compiled["framework_IL_binding_proven"] is False and
             compiled["managed_resource_reference_closure_proven"] is False,
             "framework proof overclaimed IL binding or opaque managed-resource reference closure")


def _verify_runtime_profile_proof(compiled, plan):
    support_profile = {"profile": plan["profile"], "allowed_role": "direct_child_vctip_LOAD_DLL",
                       "support_files": plan["support_files"]}
    support_digest = sha256(json.dumps(support_profile, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
    _require(compiled["profile"] == plan["profile"] and compiled["support_file_sha256"] == plan["support_files"]
             and compiled["support_profile_sha256"] == support_digest,
             "fresh runtime proof did not bind the exact singleton support profile")
    basenames = ("Microsoft.VisualStudio.RemoteControl.dll",)
    if plan["profile"] in (_RUNTIME_PROFILE_V4, _RUNTIME_PROFILE_V5):
        basenames += ("Newtonsoft.Json.dll",)
    required_il = {str(Path(plan["tool_directory"]) / name):
                   plan["tool_pins"][str(Path(plan["tool_directory"]) / name)] for name in basenames}
    native_profile = {"profile": plan["profile"],
        "allowed_role": "direct_child_vctip_LOAD_DLL_with_active_exact_pinned_IL",
        "native_image_pins": plan["native_image_pins"], "required_IL_tool_pin": required_il}
    native_digest = sha256(json.dumps(native_profile, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
    _require(compiled["native_image_sha256"] == plan["native_image_pins"] and
             compiled["native_image_profile_sha256"] == native_digest,
             "fresh runtime proof did not bind exact separate NI/active-IL role profile")
    _require(all(compiled[f] is False for f in ("NI_compilation_authenticity_proven",
             "IL_native_semantic_equivalence_proven", "NGEN_dependency_closure_proven", "JIT_closure_proven")),
             "runtime proof expanded native-image/managed semantics")
    _require(all(compiled[f] is False for f in ("managed_assembly_closure_proven",
             "loaded_memory_attestation_proven", "full_OS_attestation_proven")),
             "runtime proof expanded platform/managed scope")
    if plan["profile"] == _RUNTIME_PROFILE_V5:
        _verify_framework_native_image_proof(compiled, plan)


def _load_runtime_profile(record, digest, pins):
    _require(type(record) is dict and set(record) == {"path", "sha256"} and
             type(digest) is str and _HEX.fullmatch(digest) is not None and record["sha256"] == digest,
             "explicit runtime-profile SHA256 differs/missing")
    profile_path = _ordinary(record["path"])
    before = profile_path.stat()
    limit = 512 * 1024
    _require(profile_path in pins and pins[profile_path] == digest and
             before.st_nlink == 1 and 0 <= before.st_size <= limit,
             "runtime profile is unpinned/excessive/aliased")
    # Bound the actual read even if the ordinary file grows after preflight.
    # These are point-in-time path/identity checks, not a held read lock or
    # a claim of hostile-filesystem race freedom. The independent digest is
    # still required before parsing any profile content.
    with profile_path.open("rb") as stream:
        raw = stream.read(limit + 1)
    after = _ordinary(str(profile_path)).stat()

    def stamp(metadata):
        return (metadata.st_dev, metadata.st_ino, metadata.st_size,
                metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_nlink,
                getattr(metadata, "st_file_attributes", 0))

    _require(len(raw) <= limit and len(raw) == before.st_size and
             stamp(before) == stamp(after),
             "runtime profile bounded read changed/exceeded stable metadata")
    _require(sha256(raw).hexdigest() == digest, "runtime profile bytes differ")
    return _runtime_profile_plan(_json(raw), pins)


def _manifest():
    required = os.environ.get("LETHE_SELECTED_WRAPPER_REQUIRE_NATIVE") == "1"
    name, digest = os.environ.get(_ENV), os.environ.get(_ENV + "_SHA256")
    profile_digest = os.environ.get("LETHE_SELECTED_WRAPPER_RUNTIME_PROFILE_SHA256")
    source_digest = os.environ.get(_SOURCE_ENV)
    if os.name != "nt" or not name or not digest or not profile_digest or not source_digest:
        if required:
            pytest.fail("required Windows native manifest, manifest/profile/full-source SHA256 missing")
        pytest.skip("current-source selected-wrapper native lane not configured")
    _require(_HEX.fullmatch(digest) is not None and _HEX.fullmatch(profile_digest) is not None and _HEX.fullmatch(source_digest) is not None,
             "native fixture manifest/profile/full-source SHA256 malformed")
    path = _ordinary(name)
    _require(path.stat().st_size <= 8 * 1024 * 1024, "fixture manifest exceeds limit")
    raw = path.read_bytes()
    _require(sha256(raw).hexdigest() == digest, "fixture manifest SHA256 differs")
    data = _json(raw)
    keys = {"schema", "key_mode", "synthetic_fixture_key_hex", "origin", "tools", "runtime_profile",
            "legacy_runtime_objects", "cases", "file_sha256", "source_manifest"}
    _require(type(data) is dict and set(data) == keys and type(data["schema"]) is int and data["schema"] == 2
             and data["key_mode"] == "synthetic_fixture", "exact schema-2 native fixture required")
    _require(type(data["synthetic_fixture_key_hex"]) is str and
             _HEX.fullmatch(data["synthetic_fixture_key_hex"]) is not None, "synthetic key shape differs")
    _require(type(data["file_sha256"]) is dict and 1 <= len(data["file_sha256"]) <= 4096,
             "bounded fixture pin inventory required")
    pins = {path: digest}
    for name, value in data["file_sha256"].items():
        _require(type(value) is str and _HEX.fullmatch(value) is not None, "invalid fixture file SHA256")
        item = _ordinary(name)
        _require(item not in pins and _hash(item) == value, "duplicate/stale fixture file")
        pins[item] = value
    _require(type(data["origin"]) is dict and set(data["origin"]) == {"path", "sha256"}, "origin record differs")
    origin = _ordinary(data["origin"]["path"])
    _require(origin in pins and pins[origin] == data["origin"]["sha256"], "old F4 manifest is not bound")
    _require(type(data["tools"]) is dict and set(data["tools"]) == _TOOLS, "fixed tool roles required")
    _require(type(data["cases"]) is dict and set(data["cases"]) == set(_EXPECTED), "both native case roles required")
    for case, item in data["cases"].items():
        _require(type(item) is dict and set(item) == _CASE_KEYS, "closed native case schema differs")
        _require(item["prefix"] == case + "_vm" and item["image_name"] == case + (".exe" if case == "policy" else ".dll")
                 and type(item["vector_count"]) is int and item["vector_count"] == _EXPECTED[case][0]
                 and item["expected_stdout"] == _EXPECTED[case][1].decode("ascii"), "fixed native oracle differs")
        _require(type(item["symbol"]) is str and type(item["abi"]) is str and
                 (item["host_image"] is None if case == "policy" else type(item["host_image"]) is str),
                 "source ABI/symbol or DLL-host shape differs")
    plan = _load_runtime_profile(data["runtime_profile"], profile_digest, pins)
    source_root = _ordinary(str(Path(__file__).resolve().parents[1]), directory=True)
    source = _source_manifest(data["source_manifest"], source_digest, source_root)
    return data, plan, pins, source


def _record(path, value):
    _require(not path.exists(), "refuse evidence overwrite")
    with path.open("xb") as stream:
        stream.write((json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf8"))


def _command(label, argv, cwd, env, logs, *, timeout=90, diagnostic_check=False):
    result = bounded._run_bounded(tuple(str(p) for p in argv), cwd, env, timeout=timeout, limit=4 * 1024 * 1024)
    for suffix, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
        with (logs / (label + "." + suffix)).open("xb") as stream:
            stream.write(raw)
    # Never serialize the captured ambient LINK environment or secret-bearing values.
    env_hash = sha256(json.dumps(sorted(env.items()), separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    _record(logs / (label + ".json"), {"command": list(map(str, argv)), "cwd": str(cwd), "status": result.status,
            "exit_status": result.returncode, "environment_projection_sha256": env_hash,
            "raw_environment_retained": False, "stdout_sha256": sha256(result.stdout).hexdigest(),
            "stderr_sha256": sha256(result.stderr).hexdigest()})
    _require(result.status == "exited" and result.returncode == 0 and result.stderr == b"", "bounded native command failed: " + label)
    if diagnostic_check:
        _require(re.search(br"\b(?:warning|error|ignoring|unrecognized|unknown option)\b", result.stdout + result.stderr, re.I) is None,
                 "unreviewed compiler/LINK diagnostic: " + label)
    return result


def _link_environment(capture, cwd, output_capture):
    raw = (capture / "env.setting").read_bytes()
    _require(0 < len(raw) <= 65536 and raw.endswith(b"\r\n"), "original LINK environment bounds")
    result = {}
    for line in raw.decode("utf8").split("\r\n")[:-1]:
        at = line.find("=", 1) if line.startswith("=") else line.find("=")
        _require(at > 0, "original LINK environment separator")
        key, value = line[:at], line[at + 1:]
        _require(key.casefold() not in {k.casefold() for k in result}, "ambiguous original LINK environment")
        if key.casefold() == "link_repro":
            value = str(output_capture)
        elif len(key) == 3 and key.startswith("=") and key[2] == ":" and key[1].casefold() == cwd.drive[0].casefold():
            value = str(cwd)
        result[key] = value
    _require(not any(k.casefold() in ("link", "_link_") for k in result), "original LINK option override")
    return result


def _materialize_case(case, item, tools, runtime_objects, capsule, root, env, logs, pins, key):
    def pinned(name):
        path = _ordinary(name)
        _require(path in pins, "case input absent from fixture pins")
        return path

    source = ProductSourceInputs(pinned(item["source_image"]), pinned(item["source_pdb"]), pinned(item["source_map"]),
              pinned(item["source_helper_object"]), item["symbol"], item["abi"], tools["dia_helper"], tools["msdia"], tools["typed_abi_helper"])
    header, original = pinned(item["source_header"]), _ordinary(item["original_capture"], directory=True)
    files = tuple(p for p in original.rglob("*") if p.is_file())
    _require(files and all(p in pins for p in files), "original capture contains unpinned inputs")
    generated = root / (case + "-generated")
    emitted = emit_product_fixture(source, header, generated, key_mode="synthetic_fixture", synthetic_fixture_key=key)
    _record(logs / (case + "-emission.json"), emitted)
    out = root / (case + "-compiled")
    out.mkdir()
    prefix = item["prefix"]
    wrapper, entry, data = out / (prefix + "_wrapper.obj"), out / (prefix + ".obj"), out / (prefix + "_data.obj")
    include = ("/I" + str(capsule / "stub/src"), "/I" + str(header.parent))
    _command(case + "-wrapper", (tools["cl"], *_CFLAGS, "/std:c++17", *include, "/Fo" + str(wrapper), generated / (prefix + "_wrapper.cpp")), root, env, logs, diagnostic_check=True)
    _command(case + "-entry", (tools["ml64"], "/nologo", "/c", "/Zi", "/Brepro", "/Fo" + str(entry), generated / (prefix + ".asm")), root, env, logs, diagnostic_check=True)
    _command(case + "-data", (tools["cl"], *_CFLAGS, *include, "/Fo" + str(data), generated / (prefix + "_data.c")), root, env, logs, diagnostic_check=True)
    ordered = (wrapper, entry, data, *runtime_objects)
    final = root / (case + "-final")
    final.mkdir()
    capture = final / "capture"
    capture.mkdir()
    image = final / item["image_name"]
    caller = pinned(item["caller_object"])
    libraries = tuple(pinned(str(original / name)) for name in ("bcrypt.lib", "kernel32.lib", "uuid.lib"))
    argv = (tools["link_exe"], *_FLAGS, *(("/DLL",) if case == "lease" else ()), "/OUT:" + str(image),
            "/PDB:" + str(image.with_suffix(".pdb")), "/LINKREPRO:" + str(capture), caller, *ordered, *libraries)
    _command(case + "-link", argv, final, _link_environment(original, final, capture), logs, timeout=180, diagnostic_check=True)
    _require(_environment_profile(original)[1] == _environment_profile(capture)[1], "material LINK environment changed")
    _require(_hash(caller) == _hash(capture / caller.name), "caller bytes changed at final LINK")
    _require(all(_hash(p) == _hash(capture / p.name) for p in ordered), "final captured generated bytes differ")
    baseline = root / (case + "-original")
    baseline.mkdir()
    original_copy = baseline / item["image_name"]
    with original_copy.open("xb") as stream:
        stream.write(source.image.read_bytes())
    _require(_hash(original_copy) == pins[source.image], "original executable/DLL copy differs")
    host = None
    if case == "lease":
        host = root / "lease_host.exe"
        with host.open("xb") as stream:
            stream.write(pinned(item["host_image"]).read_bytes())
        _require(_hash(host) == pins[Path(item["host_image"])], "DLL host copy differs")
    return {"source": source, "header": header, "generated": generated, "ordered": ordered,
            "original_capture": original, "init": pinned(item["native_initializer_object"]),
            "capture": capture, "image": image, "original_copy": original_copy, "host": host}


@pytest.fixture(scope="module")
def _current_native_pair(tmp_path_factory):
    manifest, plan, pins, source = _manifest()
    root = tmp_path_factory.mktemp("selected-wrapper-current")
    logs = root / "evidence"
    logs.mkdir()
    capsule = root / "runtime-capsule"  # Absent; only the factory may create it.
    gen_tmp = root / "gen-tmp"          # Distinct, owned, OUTSIDE capsule/tmp.
    gen_tmp.mkdir()
    _require(not gen_tmp.is_relative_to(capsule), "generated compilation TEMP overlaps runtime capsule")
    inputs = runtime.RuntimeCompileInputs(capsule, Path(plan["tool_directory"]), tuple(Path(p) for p in plan["include_roots"]),
             tuple(runtime.RuntimeFilePin(Path(p), d) for p, d in plan["tool_pins"].items()),
             tuple(runtime.RuntimeFilePin(Path(p), d) for p, d in plan["external_headers"].items()),
             tuple((role, tuple(names)) for role, names in plan["ordered_includes"]), profile=plan["profile"],
             support_files=tuple(runtime.RuntimeFilePin(Path(p), d) for p, d in plan["support_files"].items()),
             native_image_pins=tuple(runtime.RuntimeFilePin(Path(p), d) for p, d in plan["native_image_pins"].items()),
             framework_native_image_pins=tuple(runtime.RuntimeFilePin(Path(p), d) for p, d in plan.get("framework_native_image_pins", {}).items()))
    runtime.validate_runtime_compile_inputs(inputs)
    # Missing support cannot silently select the formerly accepted legacy
    # profile/default. These are pure preflight controls, before capsule creation.
    six = (capsule, inputs.tool_directory, inputs.include_roots, inputs.tool_files,
           inputs.external_headers, inputs.ordered_includes)
    with pytest.raises(runtime.RuntimeCompileError, match="Setup support"):
        runtime.validate_runtime_compile_inputs(runtime.RuntimeCompileInputs(*six, profile=plan["profile"],
            native_image_pins=inputs.native_image_pins, framework_native_image_pins=inputs.framework_native_image_pins))
    with pytest.raises(runtime.RuntimeCompileError, match="native.image|native image"):
        runtime.validate_runtime_compile_inputs(runtime.RuntimeCompileInputs(*six, profile=plan["profile"],
            support_files=inputs.support_files, framework_native_image_pins=inputs.framework_native_image_pins))
    with pytest.raises(runtime.RuntimeCompileError, match="native.image|native image"):
        runtime.validate_runtime_compile_inputs(runtime.RuntimeCompileInputs(*six, profile=_LEGACY_PROFILE,
            support_files=inputs.support_files, native_image_pins=inputs.native_image_pins))
    with pytest.raises(runtime.RuntimeCompileError, match="exact supported"):
        runtime.validate_runtime_compile_inputs(runtime.RuntimeCompileInputs(*six,
            profile="msvc-14.44.35207-sdk-10.0.26100.0-raw-v1", support_files=inputs.support_files))
    _require(not capsule.exists(), "legacy/missing-support/native-image preflight created a capsule")
    tools = {name: _ordinary(path) for name, path in manifest["tools"].items()}
    _require(all(path in pins for path in tools.values()), "native tool role is not pinned")
    _require(tools["cl"] == inputs.tool_directory / "cl.exe" and tools["ml64"] == inputs.tool_directory / "ml64.exe"
             and tools["link_exe"] == inputs.tool_directory / "link.exe", "native compiler/LINK tools differ from profile")
    env = {"SystemRoot": r"C:\Windows", "WINDIR": r"C:\Windows", "PATH": str(inputs.tool_directory) + r";C:\Windows\System32;C:\Windows",
           "TEMP": str(gen_tmp), "TMP": str(gen_tmp), "INCLUDE": ";".join(map(str, inputs.include_roots)), "VSLANG": "1033",
           "PROCESSOR_ARCHITECTURE": "AMD64", "NUMBER_OF_PROCESSORS": "16"}
    key = bytes.fromhex(manifest["synthetic_fixture_key_hex"])
    _check_pins(pins)
    _source_provenance(source, logs, "before-builder")
    try:
        with runtime.runtime_compile_session(inputs) as session:
            objects = runtime.build_runtime_objects(session, root / "runtime-export")
            _require(tuple(p.name for p in objects) == tuple(role + ".obj" for role in _ROLES), "runtime role ordering differs")
            pair = {case: _materialize_case(case, manifest["cases"][case], tools, objects, capsule, root, env, logs, pins, key)
                    for case in ("policy", "lease")}
            _check_pins(pins)
            q = pair["policy"]
            selected = public.SelectedWrapperLinkInputs(q["original_capture"], q["ordered"], q["init"])
            replay = public.ReplayInputs(q["capture"], q["image"], q["image"].with_suffix(".pdb"), q["image"].with_suffix(".map"),
                                        root / "missing-session-replay", tools["link_exe"], tools["vsdevcmd"])
            before = {p.name: _hash(p) for p in (capsule / "logs").iterdir()}
            with pytest.raises(public.ProductLinkProofError, match="runtime compilation preflight failed"):
                public.verify_product_fixture_final_link(q["source"], q["header"], q["generated"], replay,
                    synthetic_fixture_key=key, selected_reference_inputs=selected)
            _require(not replay.replay_dir.exists(), "missing-session public negative produced replay output")
            legacy = manifest["legacy_runtime_objects"]
            _require(type(legacy) is list and len(legacy) == 8, "legacy negative requires exactly eight ordered old objects")
            legacy = tuple(_ordinary(path) for path in legacy)
            _require(all(p in pins for p in legacy) and tuple(p.name for p in legacy) == tuple(p.name for p in objects),
                     "legacy runtime negative is not fully pinned/ordered")
            with pytest.raises(runtime.RuntimeCompileError, match="not exported by this active build"):
                runtime.prove_runtime_coff_compilation(session, (*q["ordered"][:3], *legacy), q["capture"])
            _require(before == {p.name: _hash(p) for p in (capsule / "logs").iterdir()}, "negative unexpectedly launched compilation")
            for case, q in pair.items():
                replay = public.ReplayInputs(q["capture"], q["image"], q["image"].with_suffix(".pdb"), q["image"].with_suffix(".map"),
                           root / (case + "-public-proof"), tools["link_exe"], tools["vsdevcmd"])
                proof = public.verify_product_fixture_final_link(q["source"], q["header"], q["generated"], replay, synthetic_fixture_key=key,
                           selected_reference_inputs=public.SelectedWrapperLinkInputs(q["original_capture"], q["ordered"], q["init"]),
                           runtime_compile_session=session)
                _require(all(proof[field] is True for field in _TRUE) and all(proof[field] is False for field in _FALSE),
                         "public positive/limited-scope claims differ")
                compiled = proof["runtime_compilation"]
                _require(compiled["fresh_compiler_invocations"] == 8 and set(compiled["raw_equal_roles"]) == {r + ".obj" for r in _ROLES},
                         "public proof did not consume exact fresh runtime8")
                _verify_runtime_profile_proof(compiled, plan)
                binding = proof["selected_reference_binding"]
                _require(binding["original"]["source_relocation_count"] >= 1 and
                         binding["original"]["retained_direct_calls"] == binding["replacement"]["retained_direct_calls"],
                         "selected direct caller equivalence changed")
                _require(proof["final_pe_sha256"] == _hash(q["image"]), "public final image binding differs")
                _record(logs / (case + "-public-proof.json"), proof)
                q["proof"] = proof
                _check_pins(pins)
                _source_provenance(source, logs, "after-" + case + "-public-proof")
            # TMP observation JSONs are separate preserved evidence, not compiler
            # invocations. Never count every JSON as a compiler job.
            records = tuple(p for p in (capsule / "logs").iterdir()
                            if re.fullmatch(r"[0-9]{3}-(?:" + "|".join(_ROLES) + r")\.json", p.name))
            expected_records = {f"{i:03d}-{_ROLES[i % 8]}.json" for i in range(24)}
            _require({p.name for p in records} == expected_records, "expected 8 builder + 8 + 8 public runtime compilations")
            for path in records:
                record = _json(path.read_bytes())
                _require(record["status"] == "exited" and record["exit_code"] == 0 and record["cleanup"]["reaped"] is True
                         and record["cleanup"]["job_accounting"]["active_processes"] == 0
                         and record["cleanup"]["job_accounting"]["total_processes"] == len(record["processes"])
                         and all(p["exit_code"] == 0 and p["exit_continued"] is True and p["wait_terminal"] is True
                                 for p in record["processes"]), "root/helper compiler lifetime evidence differs")
            # Yield only after BOTH current public proofs have succeeded.
            try:
                yield pair, root, env, logs, pins, source
            finally:
                _source_provenance(source, logs, "teardown-before-session-close")
                runtime.require_runtime_compile_ready(session)
        with pytest.raises(runtime.RuntimeCompileError, match="active factory-owned"):
            runtime.validate_runtime_compile_session(session)
        _check_pins(pins)
    finally:
        _source_provenance(source, logs, "teardown-after-session-context")


@pytest.mark.parametrize("case", ("policy", "lease"), ids=("exe", "dll"))
def test_materialized_selected_wrapper_requires_consumed_caller_binding(case, _current_native_pair):
    pair, root, env, logs, pins, source = _current_native_pair
    q = pair[case]
    stdout = []
    for role, image in (("original", q["original_copy"]), ("current", q["image"])):
        command = (image,) if case == "policy" else (q["host"], image)
        digest = _hash(image)
        _source_provenance(source, logs, "before-" + case + "-" + role + "-oracle")
        try:
            result = _command(case + "-" + role, command, root, env, logs, timeout=30)
        finally:
            _source_provenance(source, logs, "after-" + case + "-" + role + "-oracle")
        _require(result.stdout == _EXPECTED[case][1] and _hash(image) == digest, "exact original/current native oracle differs")
        stdout.append(result.stdout)
    _require(stdout[0] == stdout[1], "original/current stdout bytes differ")
    _check_pins(pins)
