"""Required native lane for source-bound synthetic selected-wrapper EXE/DLLs.

Set LETHE_SELECTED_WRAPPER_FIXTURE_MANIFEST and its SHA256, and set
LETHE_SELECTED_WRAPPER_REQUIRE_NATIVE=1 to make missing prerequisites fail.
The default offline suite skips this separate native lane.  No product, guest,
signing, global target closure or runtime-source compilation claim is made.
"""

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess

import pytest

from lifter import product_fixture_link_verify as public
from lifter import selected_wrapper_binding, structured_vm_thunk
from lifter.source_link_product_admission import ProductSourceInputs, _reject_reparse_components


_ENV = "LETHE_SELECTED_WRAPPER_FIXTURE_MANIFEST"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_EXPECTED = {
    "policy": b"policy_bits=CECECCCE passed=true\n",
    "lease": b"lease_bits=2B663 passed=true\n",
}


def _hash(path):
    result = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def _ordinary(path):
    if type(path) is not str:
        pytest.fail("fixture paths must be exact strings")
    value = Path(path)
    if not value.is_absolute():
        pytest.fail("fixture requires absolute paths")
    _reject_reparse_components(value)
    if not value.is_file() or value.resolve() != value:
        pytest.fail("fixture input is not an ordinary canonical file")
    return value


def _manifest():
    required = os.environ.get("LETHE_SELECTED_WRAPPER_REQUIRE_NATIVE") == "1"
    if os.name != "nt":
        if required:
            pytest.fail("selected-wrapper required native lane needs Windows")
        pytest.skip("selected-wrapper native lane requires Windows")
    name, expected = os.environ.get(_ENV), os.environ.get(_ENV + "_SHA256")
    if not name or not expected:
        if required:
            pytest.fail("selected-wrapper required native manifest and SHA256 are missing")
        pytest.skip("selected-wrapper synthetic native fixture manifest not configured")
    if not _HEX.fullmatch(expected):
        pytest.fail("selected-wrapper fixture manifest SHA256 is malformed")
    path = _ordinary(name)
    if path.stat().st_size > 8 * 1024 * 1024:
        pytest.fail("selected-wrapper fixture manifest is excessive")
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != expected:
        pytest.fail("selected-wrapper fixture manifest SHA256 differs")
    data = json.loads(raw)
    if (type(data) is not dict or data.get("schema") != 1 or
            data.get("key_mode") != "synthetic_fixture" or
            type(data.get("cases")) is not dict or set(data["cases"]) != {"policy", "lease"} or
            type(data.get("file_sha256")) is not dict or
            not 1 <= len(data["file_sha256"]) <= 1024):
        pytest.fail("selected-wrapper fixture manifest contract differs")
    pins = {}
    for name, digest in data["file_sha256"].items():
        if type(digest) is not str or not _HEX.fullmatch(digest):
            pytest.fail("fixture input SHA256 is malformed")
        value = _ordinary(name)
        if value in pins or _hash(value) != digest:
            pytest.fail("fixture input identity or SHA256 differs")
        pins[value] = digest
    return path, raw, data, pins


@pytest.mark.parametrize("case", ("policy", "lease"), ids=("exe", "dll"))
def test_materialized_selected_wrapper_requires_consumed_caller_binding(case, tmp_path):
    manifest_path, manifest_raw, manifest, pins = _manifest()
    source_root = Path(__file__).resolve().parents[1]
    for module in (public, selected_wrapper_binding, structured_vm_thunk):
        if not Path(module.__file__).resolve().is_relative_to(source_root):
            pytest.fail("selected-wrapper test imported a different source tree")
    item, tools = manifest["cases"][case], manifest["tools"]

    def pinned(name):
        value = _ordinary(name)
        if value not in pins:
            pytest.fail("required fixture input is absent from the pin inventory")
        return value

    generated = tuple(pinned(name) for name in item["generated_inputs"])
    # Directory trees are also pinned, not merely their path strings. The
    # consumed verifier independently inventories/replays both capture trees.
    for name in ("original_capture", "final_capture", "generated_dir"):
        root = Path(item[name])
        _reject_reparse_components(root)
        if not root.is_dir() or not root.is_absolute():
            pytest.fail("fixture directory is missing or noncanonical")
        files = [path for path in root.rglob("*") if path.is_file()]
        if not files or any(path not in pins for path in files):
            pytest.fail("fixture directory contains unpinned files")
    source = ProductSourceInputs(
        pinned(item["source_image"]), pinned(item["source_pdb"]),
        pinned(item["source_map"]), pinned(item["source_helper_object"]),
        item["symbol"], item["abi"], pinned(tools["dia_helper"]),
        pinned(tools["msdia"]), pinned(tools["typed_abi_helper"]),
    )
    replay = public.ReplayInputs(
        Path(item["final_capture"]), pinned(item["final_image"]),
        pinned(item["final_pdb"]), pinned(item["final_map"]),
        tmp_path / "fresh_public_proof", pinned(tools["link_exe"]),
        pinned(tools["vsdevcmd"]),
    )
    selected = public.SelectedWrapperLinkInputs(
        Path(item["original_capture"]), generated,
        pinned(item["native_initializer_object"]),
    )
    key = bytes.fromhex(manifest["synthetic_fixture_key_hex"])
    result = public.verify_product_fixture_final_link(
        source, pinned(item["source_header"]), Path(item["generated_dir"]),
        replay, synthetic_fixture_key=key, selected_reference_inputs=selected,
    )
    for field in ("final_link_byte_binding_proven", "linked_fixture_structure_verified",
                  "original_helper_object_omission_proven",
                  "authenticated_selected_wrapper_reference_binding_proven",
                  "selected_direct_source_output_equivalence_proven"):
        assert result[field] is True, field
    for field in ("source_reference_closure_proven", "global_source_output_reference_equivalence_proven",
                  "runtime_source_compile_binding_proven", "indirect_target_closure_proven",
                  "xfg_enforcement_proven", "production_key_service_configured", "production_admitted"):
        assert result[field] is False, field
    binding = result["selected_reference_binding"]
    assert binding["original"]["source_relocation_count"] >= 1
    assert binding["original"]["retained_direct_calls"] == binding["replacement"]["retained_direct_calls"]
    assert result["final_pe_sha256"] == pins[replay.built_image]
    if case == "policy":
        commands = ((str(source.image),), (str(replay.built_image),))
    else:
        host = pinned(item["host_image"])
        commands = ((str(host), str(source.image)), (str(host), str(replay.built_image)))
    runs = []
    for command in commands:
        child = subprocess.run(command, cwd=tmp_path, capture_output=True, timeout=30, check=False)
        assert child.returncode == 0, (command, child.returncode, child.stdout, child.stderr)
        assert child.stderr == b"", (command, child.stderr)
        assert child.stdout.replace(b"\r\n", b"\n") == _EXPECTED[case], (command, child.stdout)
        runs.append(child.stdout)
    assert runs[0] == runs[1]
    assert manifest_path.read_bytes() == manifest_raw
    for path, digest in pins.items():
        assert _hash(path) == digest, str(path)
