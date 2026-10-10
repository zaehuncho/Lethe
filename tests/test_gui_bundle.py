"""Copy-only GUI resource closure regressions. No compiler, GUI or native image runs.

Existing release fixture builders supply synthetic evidence and fresh temporary
Ed25519 keys; only their generation seams are mocked. The release verifier is
never replaced. Recipe tests below are source contracts, not PowerShell runs.
"""
from __future__ import annotations
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from packer import assemble, pe_content_id, release_attestation as release
from tools import production_gate

SOURCE_ROOT = Path(release.__file__).resolve().parents[1]
TRANSACTION = Path(__file__).resolve().parents[2]
STUB_DEST = "stub/prebuilt/lethe_stub_x64.dll"
RECIPE = SOURCE_ROOT / "gui/build_gui.ps1"
VARIANT = os.environ.get("LETHE_GUI_CLOSURE_VARIANT", "modified")


def _json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree(root):
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in root.rglob("*") if p.is_file()}


@pytest.fixture(autouse=True)
def no_external_actions(monkeypatch):
    def prohibited(*_args, **_kwargs):
        pytest.fail("external process/network action is outside this fixture")
    monkeypatch.setattr(subprocess, "Popen", prohibited)
    monkeypatch.setattr(socket, "socket", prohibited)
    monkeypatch.setattr(socket, "create_connection", prohibited)


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    assert SOURCE_ROOT.is_relative_to(TRANSACTION)
    spec = importlib.util.spec_from_file_location(
        "_gui_closure_release_fixtures", SOURCE_ROOT / "tests/test_release_attestation.py")
    fixture = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = fixture
    spec.loader.exec_module(fixture)
    # Existing source/rebuild/replay/Authenticode fixture-generation seams only.
    fixture._release_source_fixture.__wrapped__(monkeypatch)
    build = tmp_path / "fixture"
    build.mkdir()
    output, trust, matrix, _fresh_test_key, evidence_trust = fixture._release(build)
    repo = tmp_path / "repository"
    repo.mkdir()
    matrix_doc = json.loads(matrix.read_text(encoding="utf-8"))
    for feature in matrix_doc["features"]:
        for item in feature["evidence"]:
            relative = item["path"]
            target = repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE_ROOT / relative, target)
    for source, relative in [(trust, "packer/release_trust.json"),
                             (evidence_trust, "packer/evidence_trust.json"),
                             (matrix, "docs/production_compatibility.json")]:
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    monkeypatch.setattr(production_gate, "ROOT", repo)
    expected = {"stub/prebuilt/" + p.relative_to(output).as_posix(): p.read_bytes()
                for p in output.rglob("*") if p.is_file()}
    for relative in ["packer/release_trust.json", "packer/evidence_trust.json",
                     "docs/production_compatibility.json"]:
        expected[relative] = (repo / relative).read_bytes()
    for feature in matrix_doc["features"]:
        for item in feature["evidence"]:
            expected.setdefault(item["path"], (repo / item["path"]).read_bytes())
    stub = output / "lethe_stub_x64.dll"
    assert release.verify_release_bundle(
        stub, trust_store_path=repo / "packer/release_trust.json",
        evidence_trust_store_path=repo / "packer/evidence_trust.json",
        matrix_path=repo / "docs/production_compatibility.json")["production_ready"]
    return SimpleNamespace(root=tmp_path, repo=repo, release=output, stub=stub,
                           expected=expected)


@pytest.fixture
def helper():
    return importlib.import_module("tools.gui_bundle")


def _materialize(mapping, root):
    root.mkdir()
    for relative, data in mapping.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def _verify_relocated_defaults(root, monkeypatch):
    # Model the same module-relative defaults in an extracted/standalone tree.
    # The real verifier and assembler path function remain unmocked.
    monkeypatch.setattr(assemble, "__file__", str(root / "packer/assemble.py"))
    monkeypatch.setattr(release, "ROOT", root)
    monkeypatch.setattr(release, "DEFAULT_TRUST_STORE", root / "packer/release_trust.json")
    monkeypatch.setattr(release, "DEFAULT_EVIDENCE_TRUST_STORE", root / "packer/evidence_trust.json")
    monkeypatch.setattr(release, "DEFAULT_MATRIX", root / "docs/production_compatibility.json")
    monkeypatch.setattr(production_gate, "ROOT", root)
    stub = Path(assemble._default_stub_path())
    assert stub == root / STUB_DEST
    return release.verify_release_bundle(stub)


def test_distribution_closure_survives_relocation(bundle, monkeypatch):
    """One identical semantic regression for baseline, modified and rollback."""
    assert VARIANT in {"baseline", "modified", "rollback"}
    recipe = RECIPE.read_text(encoding="utf-8-sig")
    if VARIANT in {"baseline", "rollback"}:
        # Derive the DLL-only map from the saved actual recipe, not ImportError.
        matches = re.findall(
            r'^\s*\$NuitkaArgs \+= "--include-data-files=\$StubPath=([^"]+)"',
            recipe, re.M)
        assert matches == [STUB_DEST]
        mapping = {matches[0]: bundle.stub.read_bytes()}
    else:
        helper = importlib.import_module("tools.gui_bundle")
        mapping = {r.destination: r.snapshot.data for r in
                   helper.collect_resources(bundle.stub, repository_root=bundle.repo)}
        assert mapping == bundle.expected
    relocated = bundle.root / "relocated"
    _materialize(mapping, relocated)
    # Baseline/rollback intentionally FAIL HERE on missing candidate/evidence
    # resources. Do not turn the expected baseline failure into a passing skip.
    assert _verify_relocated_defaults(relocated, monkeypatch)["production_ready"]


def test_exact_resource_map_retains_backing_bytes_without_private_or_unused_files(bundle, helper):
    (bundle.release / "UNREFERENCED.txt").write_text("not authenticated", encoding="utf-8")
    before = _tree(bundle.root)
    resources = helper.collect_resources(bundle.stub, repository_root=bundle.repo)
    actual = {r.destination: r.snapshot.data for r in resources}
    assert len(actual) == len(resources) and actual == bundle.expected
    assert any(p.endswith("candidate-promoter.py") for p in actual)
    assert any("/provider-signatures/" in p for p in actual)
    assert any("/scanner/" in p and p.endswith(".json") for p in actual)
    assert any("/application/" in p and p.endswith(".log") for p in actual)
    assert any("/vm/" in p and p.endswith(".log") for p in actual)
    assert any("/subjects/" in p and p.endswith(".dll") for p in actual)
    assert not any(p.endswith(".pem") or "UNREFERENCED" in p for p in actual)
    assert _tree(bundle.root) == before


@pytest.mark.parametrize("layout", ["standalone.dist", "onefile-extracted"])
def test_staging_and_relocated_defaults_for_both_layouts(bundle, helper, monkeypatch, layout):
    result = helper.prepare_resources(bundle.stub, bundle.root / "stage",
                                      repository_root=bundle.repo)
    checked = helper.validate_resources(Path(result["plan_path"]),
                                        expected_sha256=result["plan_sha256"])
    assert checked["include_modules"] == ["tools.production_gate"]
    staged = Path(checked["staged_root"])
    assert _tree(staged) == bundle.expected
    relocated = bundle.root / layout
    shutil.copytree(staged, relocated)
    assert _verify_relocated_defaults(relocated, monkeypatch)["production_ready"]


@pytest.mark.parametrize("part", ["stub", "candidate", "release", "candidate-data",
                                  "provider", "scanner", "vm", "application",
                                  "release-trust", "evidence-trust", "matrix"])
@pytest.mark.parametrize("mutation", ["missing", "changed"])
def test_bad_inputs_reject_before_staging_or_mock_compiler(bundle, helper, part, mutation):
    paths = {
        "stub": bundle.stub,
        "candidate": bundle.release / "lethe_stub_x64.manifest.json",
        "release": bundle.release / "lethe_stub_x64.release.json",
        "candidate-data": next(bundle.release.rglob("candidate-promoter.py")),
        "provider": next(bundle.release.rglob("provider-signatures/*.json")),
        "scanner": next(bundle.release.rglob("scanner/**/*.receipt.json")),
        "vm": next(bundle.release.rglob("vm/**/*.log")),
        "application": next(bundle.release.rglob("application/**/*.log")),
        "release-trust": bundle.repo / "packer/release_trust.json",
        "evidence-trust": bundle.repo / "packer/evidence_trust.json",
        "matrix": bundle.repo / "docs/production_compatibility.json",
    }
    path = paths[part]
    if mutation == "missing":
        path.unlink()
    else:
        path.write_bytes(path.read_bytes() + b"\nchanged-fixture\n")
    before = _tree(bundle.root)
    compiler = Mock()
    with pytest.raises((ValueError, OSError)):
        plan = helper.prepare_resources(bundle.stub, bundle.root / "rejected-stage",
                                        repository_root=bundle.repo)
        helper.validate_resources(Path(plan["plan_path"]), expected_sha256=plan["plan_sha256"])
        compiler(plan)
    compiler.assert_not_called()
    assert not (bundle.root / "rejected-stage").exists()
    assert _tree(bundle.root) == before


@pytest.mark.parametrize("trust_case", ["unknown-release", "revoked-release", "revoked-provider"])
def test_untrusted_fixture_roles_rejected_without_outputs(bundle, helper, trust_case):
    path = bundle.repo / "packer" / ("evidence_trust.json" if trust_case == "revoked-provider"
                                     else "release_trust.json")
    doc = json.loads(path.read_text())
    if trust_case == "unknown-release":
        doc["keys"] = []
    elif trust_case == "revoked-release":
        doc["keys"][0]["revoked"] = True
    else:
        doc["providers"][0]["revoked"] = True
    _json(path, doc)
    before = _tree(bundle.root)
    with pytest.raises((ValueError, OSError)):
        helper.prepare_resources(bundle.stub, bundle.root / "rejected", repository_root=bundle.repo)
    assert _tree(bundle.root) == before


@pytest.mark.parametrize("bad", ["../outside", "/absolute", "a\\b", "a:b", "a*b", "a?b",
                                 "a[b", "a]b", "a=b", "a\nb", "a\rb", "a\tb",
                                 "a\x00b", "a\x1fb", "a\x7fb", 'a"b', "a<b", "a>b",
                                 "a|b", "NUL.txt", "tail.", "tail "],
                         ids=["parent", "absolute", "backslash", "colon", "star", "question",
                              "open-bracket", "close-bracket", "equals", "lf", "cr", "tab",
                              "nul", "c0", "del", "quote", "less", "greater", "pipe",
                              "reserved", "trailing-dot", "trailing-space"])
def test_destination_literals_reject_escape_patterns_controls_and_collisions(helper, bad):
    with pytest.raises(ValueError):
        helper._destination(bad)


@pytest.mark.parametrize("bad", ["source=ambiguous", "source[pattern]", "source\nline",
                                 "source\x7fdelete", "source|pipe"],
                         ids=["equals", "pattern", "lf", "del", "pipe"])
def test_source_literal_rejected_without_opening(tmp_path, helper, monkeypatch, bad):
    opened = Mock(side_effect=AssertionError("snapshot must not be attempted"))
    monkeypatch.setattr(helper, "snapshot_file", opened)
    with pytest.raises(ValueError):
        helper._snapshot(tmp_path / bad)
    opened.assert_not_called()


def test_real_owned_hardlink_is_rejected_without_stage(bundle, helper):
    alias = bundle.root / "owned-alias.dll"
    os.link(bundle.stub, alias)
    assert bundle.stub.stat().st_nlink > 1
    before = _tree(bundle.root)
    with pytest.raises(ValueError):
        helper.prepare_resources(bundle.stub, bundle.root / "rejected", repository_root=bundle.repo)
    assert _tree(bundle.root) == before


def test_linklike_ancestor_predicate_is_rejected_before_snapshot(bundle, helper, monkeypatch):
    original = pe_content_id._is_linklike
    monkeypatch.setattr(pe_content_id, "_is_linklike",
                        lambda p: p.absolute() == bundle.release.absolute() or original(p))
    before = _tree(bundle.root)
    with pytest.raises(ValueError):
        helper.prepare_resources(bundle.stub, bundle.root / "rejected", repository_root=bundle.repo)
    assert _tree(bundle.root) == before


@pytest.mark.parametrize("mutation", ["missing", "changed", "extra", "case-collision",
                                     "escape", "plan-hash", "original-changed"])
def test_staged_rejection_precedes_in_process_mock_compiler(bundle, helper, mutation):
    result = helper.prepare_resources(bundle.stub, bundle.root / "stage", repository_root=bundle.repo)
    path = Path(result["plan_path"])
    plan = json.loads(path.read_text())
    data = Path(plan["staged_root"])
    row = plan["resources"][0]
    digest = result["plan_sha256"]
    if mutation == "missing":
        (data / row["destination"]).unlink()
    elif mutation == "changed":
        (data / row["destination"]).write_bytes(b"changed")
    elif mutation == "extra":
        (data / "unexpected.txt").write_bytes(b"extra")
    elif mutation == "original-changed":
        Path(row["source"]).write_bytes(b"original changed")
    elif mutation == "plan-hash":
        digest = "0" * 64
    else:
        duplicate = dict(row)
        duplicate["destination"] = (row["destination"].upper() if mutation == "case-collision"
                                     else "../outside")
        plan["resources"].append(duplicate)
        _json(path, plan)
        digest = _digest(path)
    before = _tree(bundle.root)
    compiler = Mock()
    with pytest.raises((ValueError, OSError)):
        validated = helper.validate_resources(path, expected_sha256=digest)
        compiler(validated)
    compiler.assert_not_called()
    assert _tree(bundle.root) == before


def test_existing_stage_is_not_replaced(bundle, helper):
    out = bundle.root / "existing"
    out.mkdir()
    (out / "sentinel").write_bytes(b"preserve")
    before = _tree(bundle.root)
    with pytest.raises(ValueError):
        helper.prepare_resources(bundle.stub, out, repository_root=bundle.repo)
    assert _tree(bundle.root) == before


def test_recipe_source_contract_modes_explicit_ui_only_and_preflight_order():
    text = RECIPE.read_text(encoding="utf-8-sig")
    executable = text[text.index("[CmdletBinding()]"):]
    assert '"--standalone"' in executable
    assert re.search(r'if \(-not \$NoOnefile\)\s*{\s*\$NuitkaArgs \+= "--onefile"', executable)
    assert re.search(r'if \(-not \(Test-Path \$StubPath\)\)\s*{\s*if \(\$SkipStubCheck\)', executable)
    assert executable.count("$IncludeStub = $false") == 1
    assert 'if ($IncludeStub) {' in executable
    assert "--include-module=tools.production_gate" in executable
    assert '--include-data-files=$DataSource=$($Resource.destination)' in executable
    assert "--include-data-dir" not in executable
    prepare = executable.index("$BundleHelper prepare")
    first_validate = executable.index("\nAssert-ResourcePlan\n")
    mkdir = executable.index("New-Item -ItemType Directory -Force -Path $OutputDir")
    compile_at = executable.index("& $PythonExe @NuitkaArgs")
    assert prepare < first_validate < mkdir < compile_at
    assert "Assert-ResourcePlan" in executable[mkdir:compile_at]
    assert "Assert-ResourcePlan" in executable[compile_at:]
    assert "$OutputDir = Get-InvocationPath $OutputDir" in executable
    assert "$StubPath = Get-InvocationPath $StubPath" in executable


@pytest.mark.parametrize("onefile", [False, True])
def test_full_fixture_quoted_windows_argv_budget(bundle, helper, onefile, record_property):
    result = helper.prepare_resources(bundle.stub, bundle.root / "stage", repository_root=bundle.repo)
    args = [str(Path(sys.executable)), "-m", "nuitka", "--standalone",
            "--assume-yes-for-downloads", "--enable-plugin=pyside6", "--windows-console-mode=disable",
            "--include-package=packer", "--include-package=lief", "--include-package=cryptography",
            "--include-module=tools.production_gate", "--company-name=Orion", "--product-name=Lethe",
            "--file-description=Lethe x64 PE packer (internal build tool)", "--file-version=0.1.0",
            "--product-version=0.1.0", "--output-filename=Lethe.exe",
            "--output-dir=" + str(bundle.root / "build output"), "--remove-output"]
    if onefile:
        args.append("--onefile")
    # Measure both actual test staging and the recipe's GetTempPath/GUID layout.
    # The latter is only a string: no additional directory or process is created.
    prefixes = {
        "fixture": Path(result["staged_root"]),
        "recipe": Path(os.environ["TEMP"]) / ("lethe-gui-bundle-" + "0" * 32) / "data",
    }
    record_property("resource_count", len(result["resources"]))
    for label, prefix in prefixes.items():
        mapped_args = args + ["--include-data-files=" + str(prefix / row["destination"])
                              + "=" + row["destination"] for row in result["resources"]]
        mapped_args.append(str(SOURCE_ROOT / "gui/app.py"))
        encoded = subprocess.list2cmdline(mapped_args).encode("utf-16-le")
        units_with_terminator = len(encoded) // 2 + 1
        record_property(label + "_quoted_utf16_units_including_terminator", units_with_terminator)
        record_property(label + "_stage_prefix", str(prefix))
        assert units_with_terminator <= 32767, (label, len(result["resources"]), units_with_terminator)
