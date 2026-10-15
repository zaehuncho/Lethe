"""Default diagnostic and release-document contracts, with real pytest probes."""
from __future__ import annotations

import ast
import configparser
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest


_CALLEE_NODE = (
    "tests/test_native_virtualization_runtime.py::"
    "test_retained_native_callee_discovery_rejects_forced_aslr_exe"
)
_PROBE_PLUGIN = r'''
from pathlib import Path
import faulthandler,json,os,sys
import pytest
from _pytest.faulthandler import fault_handler_stderr_fd_key
@pytest.hookimpl(trylast=True)
def pytest_sessionstart(session):
    config=session.config
    result={"schema":1,"phase":"session_start_after_configuration",
            "pid":os.getpid(),"rootpath":str(config.rootpath),
            "pytest_faulthandler_plugin_enabled":config.pluginmanager.hasplugin("faulthandler"),
            "pytest_faulthandler_configured":fault_handler_stderr_fd_key in config.stash,
            "python_faulthandler_enabled":faulthandler.is_enabled(),
            "pytest_addopts":config.getini("addopts"),"argv":list(sys.argv),
            "optimize":sys.flags.optimize,
            "inherited_pythonfaulthandler":os.environ.get("PYTHONFAULTHANDLER"),
            "inherited_pythonoptimize":os.environ.get("PYTHONOPTIMIZE"),
            "inherited_pythonhome":os.environ.get("PYTHONHOME"),
            "plugin_autoload_disabled":os.environ.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD"),
            "inherited_pytest_addopts":os.environ.get("PYTEST_ADDOPTS"),
            "inherited_pytest_plugins":os.environ.get("PYTEST_PLUGINS"),
            "inherited_lethe_names":sorted(n for n in os.environ if n.upper().startswith("LETHE_"))}
    with Path(os.environ["DIAGNOSTIC_PROBE_RECORD"]).open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2,sort_keys=True)
'''


def _root(request):
    return Path(request.config.rootpath).resolve()


def _assignment(tree, name):
    return next(node.value for node in tree.body
                if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == name
                        for target in node.targets))


def _native_inventory(root):
    source = (root / "tools/promote_stub.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    nodes = ast.literal_eval(_assignment(tree, "REQUIRED_NATIVE_RUNTIME_NODE_IDS"))
    assert isinstance(nodes, tuple) and nodes and len(nodes) == len(set(nodes))
    assert all(isinstance(node, str) and "::" in node for node in nodes)
    count = _assignment(tree, "REQUIRED_NATIVE_RUNTIME_PASS_COUNT")
    assert (isinstance(count, ast.Call) and isinstance(count.func, ast.Name)
            and count.func.id == "len" and len(count.args) == 1
            and isinstance(count.args[0], ast.Name)
            and count.args[0].id == "REQUIRED_NATIVE_RUNTIME_NODE_IDS")
    return nodes


def test_default_configuration_does_not_disable_faulthandler(request):
    config = configparser.ConfigParser(interpolation=None)
    config.read(_root(request) / "pytest.ini", encoding="utf-8")
    assert "no:faulthandler" not in config["pytest"].get("addopts", "").casefold()


def _probe(root, tmp_path, optimized):
    plugin = tmp_path / "diagnostic_probe.py"
    plugin.write_text(_PROBE_PLUGIN, encoding="utf-8")
    case = tmp_path / "probe_case.py"
    case.write_text("def test_session_probe():\n    return None\n", encoding="utf-8")
    state_path = tmp_path / "session-state.json"
    env = os.environ.copy()
    cleared = sorted(name for name in env
                     if name.upper().startswith(("PYTEST_", "LETHE_"))
                     or name.upper() in ("PYTHONFAULTHANDLER", "PYTHONPATH", "PYTHONOPTIMIZE", "PYTHONHOME"))
    for name in cleared:
        env.pop(name, None)
    env.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONDONTWRITEBYTECODE="1",
               PYTHONPATH=str(tmp_path), DIAGNOSTIC_PROBE_RECORD=str(state_path))
    command = [sys.executable, "-OO" if optimized else "-B", "-m", "pytest",
               "-q", "-p", "no:cacheprovider", "-p", "diagnostic_probe",
               "-c", str(root / "pytest.ini"), "--rootdir", str(root), str(case)]
    stdout_path, stderr_path = tmp_path / "child.stdout.txt", tmp_path / "child.stderr.txt"
    operation_path = tmp_path / "child-operation.json"
    row = {"schema": 1, "command": command.copy(), "cwd": str(root),
           "started_utc": datetime.now(timezone.utc).isoformat(),
           "cleared_inherited_environment_names": cleared,
           "explicit_plugin_autoload_disabled": True,
           "test_probe_sha256": sha256(plugin.read_bytes()).hexdigest()}
    with stdout_path.open("xb") as out, stderr_path.open("xb") as err:
        child = subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                 stdout=out, stderr=err)
        row.update(pid=child.pid, state="running")
        operation_path.write_text(json.dumps(row, indent=2, sort_keys=True) + "\n")
        try:
            code = child.wait(timeout=60)
        except subprocess.TimeoutExpired:
            if os.name == "nt" and child.poll() is None:
                cleanup = subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"],
                                         capture_output=True, timeout=15, check=False)
                row["timeout_owned_tree_cleanup"] = {
                    "exit_status": cleanup.returncode,
                    "literal_stdout": cleanup.stdout.decode(errors="replace"),
                    "literal_stderr": cleanup.stderr.decode(errors="replace")}
            elif child.poll() is None:
                child.kill()
            child.wait(timeout=15)
            row.update(state="timeout", exit_status=child.returncode)
            operation_path.write_text(json.dumps(row, indent=2, sort_keys=True) + "\n")
            pytest.fail(f"owned pytest diagnostic probe timed out; evidence: {operation_path}")
    state = json.loads(state_path.read_text()) if state_path.exists() else None
    row.update(state="terminal", exit_status=code,
               completed_utc=datetime.now(timezone.utc).isoformat(),
               literal_stdout=stdout_path.read_text(encoding="utf-8", errors="replace"),
               literal_stderr=stderr_path.read_text(encoding="utf-8", errors="replace"),
               session_state=state, physical_launcher_handle_terminal=child.poll() is not None)
    operation_path.write_text(json.dumps(row, indent=2, sort_keys=True) + "\n")
    assert code == 0, row
    assert state is not None, row
    assert state["rootpath"] == str(root)
    assert state["optimize"] == (2 if optimized else 0)
    assert state["phase"] == "session_start_after_configuration"
    assert state["inherited_pythonfaulthandler"] is None
    assert state["inherited_pythonoptimize"] is None
    assert state["inherited_pythonhome"] is None
    assert state["plugin_autoload_disabled"] == "1"
    assert state["inherited_pytest_addopts"] is None
    assert state["inherited_pytest_plugins"] is None
    assert state["inherited_lethe_names"] == []
    assert state["argv"][1:] == command[4:]
    return state, operation_path


@pytest.mark.parametrize("optimized", (False, True), ids=("normal", "optimized_oo"))
def test_default_faulthandler_is_actually_enabled_in_owned_pytest_subprocess(
        request, tmp_path, optimized, monkeypatch):
    # Poison inherited controls deliberately; the owned child must clear them.
    for name, value in {"PYTEST_ADDOPTS":"-p no:faulthandler",
                        "PYTEST_PLUGINS":"intentionally_missing_diagnostic_plugin",
                        "PYTEST_DEBUG":"1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD":"0",
                        "LETHE_DIAGNOSTIC_INHERITED_POISON":"must-not-reach-child",
                        "PYTHONFAULTHANDLER":"1", "PYTHONOPTIMIZE":"2",
                        "PYTHONHOME":str(tmp_path / "not-a-python-home")}.items():
        monkeypatch.setenv(name, value)
    state, operation = _probe(_root(request), tmp_path, optimized)
    assert state["pytest_faulthandler_plugin_enabled"], (state, operation)
    assert state["pytest_faulthandler_configured"], (state, operation)
    assert state["python_faulthandler_enabled"], (state, operation)


def test_release_checklist_commands_retain_default_diagnostics(request):
    text = (_root(request) / "docs/RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
    commands = []
    for block in re.findall(r"```powershell\s*\n(.*?)```", text, re.S):
        commands.extend(line.strip() for line in block.replace("`\n", " ").splitlines()
                        if "pytest" in line and not line.lstrip().startswith("#"))
    assert len(commands) >= 3
    assert all("no:faulthandler" not in command for command in commands), commands
    assert all("-o addopts=" in command for command in commands), commands


def test_production_runtime_documentation_references_actual_required_inventory(request):
    root = _root(request)
    nodes = _native_inventory(root)
    text = (root / "docs/PRODUCTION_COMPATIBILITY.md").read_text(encoding="utf-8")
    assert "REQUIRED_NATIVE_RUNTIME_NODE_IDS" in text
    assert "tools/promote_stub.py" in text
    assert "all thirty" not in text.casefold()
    assert _CALLEE_NODE in nodes


def test_retained_callee_documentation_describes_rejection_not_admission(request):
    root = _root(request)
    text = (root / "docs/PRODUCTION_COMPATIBILITY.md").read_text(encoding="utf-8")
    module = ast.parse((root / "tests/test_native_virtualization_runtime.py").read_text())
    name = _CALLEE_NODE.split("::")[1]
    function = next(node for node in module.body
                    if isinstance(node, ast.FunctionDef) and node.name == name)
    diagnostic = next(ast.literal_eval(node.value) for node in ast.walk(function)
                      if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "diagnostic"
                              for target in node.targets))
    assert any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
               and node.func.id == "_run_forced_aslr" for node in ast.walk(function))
    assert any(isinstance(node, ast.Constant) and node.value == b"vm-answer=42\r\n"
               for node in ast.walk(function))
    assert any(isinstance(node, ast.Assert) and isinstance(node.test, ast.UnaryOp)
               and isinstance(node.test.op, ast.Not) and isinstance(node.test.operand, ast.Call)
               and isinstance(node.test.operand.func, ast.Attribute)
               and node.test.operand.func.attr == "exists" for node in ast.walk(function))
    assert _CALLEE_NODE in text and diagnostic in text
    assert "vm-answer=42" in text and "no packed output" in text
    assert "does not admit" in text
    assert "then proves forced-ASLR packed parity" not in text


def test_dependency_diagnostic_status_is_not_claimed_fixed(request):
    for name in ("RELEASE_CHECKLIST.md", "PRODUCTION_COMPATIBILITY.md"):
        text = (_root(request) / "docs" / name).read_text(encoding="utf-8").casefold()
        assert "internal root cause remains unidentified" in text
        assert "stderr" in text and "not fixed" in text
