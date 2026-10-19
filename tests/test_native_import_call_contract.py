"""Contracts for exact imported leaf calls and their materialized consumers."""
from __future__ import annotations

import pytest

from lifter import native_tail_calls, virtualization_plan as plan
from packer import native_import_contract


_EXEC = 0x60000020
_DATA = 0x40000040


_QT_LEAF = bytes.fromhex(
    "4c8b02"      # mov r8, [rdx]
    "4c8901"      # mov [rcx], r8
    "488b4208"    # mov rax, [rdx+8]
    "48894108"    # mov [rcx+8], rax
    "488b4210"    # mov rax, [rdx+16]
    "48894110"    # mov [rcx+16], rax
    "488bc1"      # mov rax, rcx
    "4d85c0"      # test r8, r8
    "7404"        # je ret
    "f041ff00"    # lock inc dword ptr [r8]
    "c3"          # ret
)


def test_qt_copy_constructor_leaf_cfg_is_forward_and_stack_neutral() -> None:
    native_import_contract._prove_leaf(_QT_LEAF, 0xDD30)


@pytest.mark.parametrize("code", [
    bytes.fromhex("4889e0c3"),          # reads RSP
    bytes.fromhex("4889cbc3"),          # clobbers RBX
    bytes.fromhex("e800000000c3"),      # direct CALL
    bytes.fromhex("ffd0c3"),            # indirect CALL
    bytes.fromhex("ebfec3"),            # backward edge
    bytes.fromhex("c20800"),            # RET with stack adjustment
    bytes.fromhex("488b04c3"),          # stack-indexed memory
    bytes.fromhex("0fae11c3"),          # LDMXCSR changes nonvolatile control bits
    bytes.fromhex("d92fc3"),            # FLDCW changes the nonvolatile x87 control word
    bytes.fromhex("d9eec3"),            # x87 state is outside the modeled ABI proof
])
def test_leaf_contract_rejects_unmodeled_abi_side_effects(code: bytes) -> None:
    with pytest.raises(native_import_contract.NativeImportContractError):
        native_import_contract._prove_leaf(code, 0x1000)


def _source_call() -> tuple[bytes, tuple[plan.SectionBytes, ...], plan.SourceExceptionMetadata]:
    code = bytes.fromhex(
        "4883ec28"              # sub rsp, 28h
        "ff1500000000"          # call qword ptr [rip+disp32]
        "4883c428"              # add rsp, 28h
        "c3"
    )
    # The direct encoding is patched below to target the exact 0x2010 slot.
    disp = 0x2010 - (0x1000 + 4 + 6)
    code = code[:6] + disp.to_bytes(4, "little", signed=True) + code[10:]
    sections = (
        plan.SectionBytes(".text", 0x1000, 0x100, code + b"\xCC" * (0x100 - len(code)), _EXEC),
        plan.SectionBytes(".idata", 0x2000, 0x40, bytes(0x40), _DATA),
    )
    exception = plan.SourceExceptionMetadata(
        0x3000, (plan.SourceRuntimeFunction(0x1000, 0x1000 + len(code), 0x4000),)
    )
    return code, sections, exception


def test_plan_requires_verified_proof_and_matches_its_exact_call_site() -> None:
    code, sections, exception = _source_call()
    reader = plan.SectionImage(sections)
    spec = plan.FunctionSpec("caller", 0x1000, len(code))
    imports = (0x2010,)
    with pytest.raises(plan.FunctionRejected, match="opaque native CALL lacks physical"):
        plan.compile_virtualization_manifest(
            (spec,), reader, generated_text_rva=0x5000, generated_data_rva=0x7000,
            source_exception_metadata=exception, source_import_iat_rvas=imports,
        )

    proof = native_tail_calls.VerifiedNativeImportCallProof(
        0x1000, 0x1004, 0x2010, "leaf.dll", "leaf",
        "a" * 64, 0x1000, 1, 3, "b" * 64,
    )
    manifest = plan.compile_virtualization_manifest(
        (spec,), reader, generated_text_rva=0x5000, generated_data_rva=0x7000,
        source_exception_metadata=exception, source_import_iat_rvas=imports,
        native_import_call_proofs=(proof,),
    )
    assert manifest.native_import_call_proofs == (proof,)
    assert manifest.to_dict()["native_import_call_proofs"] == [proof.to_dict()]
    from daedalus import daedalus_disasm
    assert "n_call_frame_span" in daedalus_disasm.disassemble(
        manifest.functions[0].program
    )

    wrong_slot = native_tail_calls.VerifiedNativeImportCallProof(
        0x1000, 0x1004, 0x2018, "leaf.dll", "leaf",
        "a" * 64, 0x1000, 1, 3, "b" * 64,
    )
    with pytest.raises(plan.VirtualizationPlanError, match="does not match the source CALL"):
        plan.compile_virtualization_manifest(
            (spec,), reader, generated_text_rva=0x5000, generated_data_rva=0x7000,
            source_exception_metadata=exception, source_import_iat_rvas=(0x2010, 0x2018),
            native_import_call_proofs=(wrong_slot,),
        )


def test_plan_does_not_let_one_proof_admit_a_second_native_call() -> None:
    code = bytes.fromhex(
        "4883ec28ff1506100000ff15081000004883c428c3"
    )
    sections = (
        plan.SectionBytes(".text", 0x1000, 0x100, code + b"\xCC" * (0x100 - len(code)), _EXEC),
        plan.SectionBytes(".idata", 0x2000, 0x40, bytes(0x40), _DATA),
    )
    exception = plan.SourceExceptionMetadata(
        0x3000, (plan.SourceRuntimeFunction(0x1000, 0x1000 + len(code), 0x4000),)
    )
    spec = plan.FunctionSpec("caller", 0x1000, len(code))
    proof = native_tail_calls.VerifiedNativeImportCallProof(
        0x1000, 0x1004, 0x2010, "leaf.dll", "leaf",
        "a" * 64, 0x1000, 1, 3, "b" * 64,
    )
    with pytest.raises(plan.FunctionRejected, match="opaque native CALL lacks physical"):
        plan.compile_virtualization_manifest(
            (spec,), plan.SectionImage(sections),
            generated_text_rva=0x5000, generated_data_rva=0x7000,
            source_exception_metadata=exception, source_import_iat_rvas=(0x2010,0x2018),
            native_import_call_proofs=(proof,),
        )



# The generated native EXE/DLL regression is opt-in because it needs the
# released strict stub candidate and the VS2022 x64 toolchain.
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pefile
from iced_x86 import Decoder, FlowControl, Mnemonic

from lifter import direct_control_flow, function_discovery, x64_lifter
from packer import orchestrator, pe_analyze


_ROOT = Path(__file__).resolve().parents[1]
_LEAF_FIXTURE = _ROOT / "tests" / "fixtures" / "native_import_contract" / "normal_leaf"


def _run(argv: list[str], cwd: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=180, check=False)


def _make_contract(source: Path, dependency: Path, output: Path) -> tuple[
    plan.FunctionSpec, Path,
]:
    parsed = pe_analyze.analyze_pe(str(source))
    export = next(item for item in function_discovery.parse_pe_exports(parsed)
                  if item.name == "vm_probe")
    runtime = next(item for item in parsed.runtime_functions
                   if item.begin_rva == export.rva)
    spec = plan.FunctionSpec(
        "vm_probe", runtime.begin_rva, runtime.end_rva - runtime.begin_rva
    )
    source_body = plan.SectionImage.from_parsed_sections(
        parsed.sections
    ).read_file_backed_executable(spec.rva, spec.body_size)
    calls = []
    imported = {
        function.iat_rva: (dll.name, function.name)
        for dll in parsed.imports for function in dll.funcs
        if not function.by_ordinal
    }
    for instruction in Decoder(64, source_body, ip=spec.rva):
        if instruction.mnemonic != Mnemonic.CALL:
            continue
        iat_rva = native_tail_calls.rip_relative_import_call_target(
            source_body, base=spec.rva, call_rva=instruction.ip
        )
        if iat_rva in imported and imported[iat_rva][1] == "helper_leaf":
            module, symbol = imported[iat_rva]
            calls.append((instruction.ip, iat_rva, module, symbol))
    assert len(calls) == 1, calls

    dep_bytes = dependency.read_bytes()
    dep_parsed = pe_analyze.analyze_pe(str(dependency))
    pe = pefile.PE(str(dependency), fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    )
    exported = [item for item in pe.DIRECTORY_ENTRY_EXPORT.symbols
                if item.name == b"helper_leaf"]
    assert len(exported) == 1 and exported[0].forwarder is None
    export_rva = int(exported[0].address)
    section = next(section for section in dep_parsed.sections
                   if section.rva <= export_rva < section.rva + len(section.raw))
    offset = export_rva - section.rva
    code = section.raw[offset:]
    cursor = export_rva
    for instruction in Decoder(64, code, ip=export_rva):
        cursor += instruction.len
        if instruction.flow_control == FlowControl.RETURN:
            assert instruction.mnemonic == Mnemonic.RET and instruction.op_count == 0
            break
    else:
        raise AssertionError("helper leaf has no bounded RET")
    body_size = cursor - export_rva
    assert export_rva + body_size <= section.rva + len(section.raw)
    body = section.raw[export_rva - section.rva:
                       export_rva - section.rva + body_size]
    call_rva, iat_rva, module, symbol = calls[0]
    record = {
        "function_rva": spec.rva,
        "call_rva": call_rva,
        "iat_rva": iat_rva,
        "module": module,
        "symbol": symbol,
        "dependency_path": str(dependency.resolve()),
        "dependency_sha256": hashlib.sha256(dep_bytes).hexdigest(),
        "export_rva": export_rva,
        "export_ordinal": int(exported[0].ordinal),
        "body_size": body_size,
        "body_sha256": hashlib.sha256(body).hexdigest(),
    }
    contract = {
        "schema": native_import_contract.SCHEMA,
        "version": native_import_contract.VERSION,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "calls": [record],
    }
    output.write_text(
        json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return spec, output


@pytest.mark.skipif(
    os.name != "nt"
    or os.environ.get("LETHE_RUN_NATIVE_IMPORT_CALL_E2E") != "1",
    reason="opt-in generated strict-candidate EXE/DLL import-leaf regression",
)
@pytest.mark.parametrize("kind", ("exe", "dll"))
def test_materialized_generated_import_leaf_exe_and_dll(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not shutil.which("cmake"):
        pytest.skip("CMake and Visual Studio x64 toolchain required")
    stub_text = (os.environ.get("LETHE_STRICT_REFERENCE_STUB_PATH") or
                 os.environ.get("LETHE_NATIVE_RUNTIME_STUB_PATH"))
    assert stub_text, "strict verified stub path required"
    stub = Path(stub_text).resolve()
    assert stub.is_file() and stub.with_suffix(".manifest.json").is_file()
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION", "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")

    build_source = tmp_path / "source"
    shutil.copytree(_LEAF_FIXTURE, build_source)
    build = tmp_path / "build"
    for command in (
        ["cmake", "-S", str(build_source), "-B", str(build),
         "-G", "Visual Studio 17 2022", "-A", "x64"],
        ["cmake", "--build", str(build), "--config", "Release"],
    ):
        result = _run(command, tmp_path)
        assert result.returncode == 0, (command, result.stdout, result.stderr)

    release = build / "Release"
    original = release / ("import_leaf_exe.exe" if kind == "exe"
                          else "import_leaf_dll.dll")
    helper = release / "import_leaf_helper.dll"
    host = release / "reference_host.exe"
    original_bytes = original.read_bytes()
    original_run = _run([str(original)] if kind == "exe"
                        else [str(host), str(original)], release)
    assert (original_run.returncode, original_run.stdout, original_run.stderr) == (
        0, b"IMPORT_LEAF value=42 passed=true\n", b""
    )

    parsed = pe_analyze.analyze_pe(str(original))
    exported = next(item for item in function_discovery.parse_pe_exports(parsed)
                    if item.name == "vm_probe")
    runtime = next(item for item in parsed.runtime_functions
                   if item.begin_rva == exported.rva)
    spec, contract = _make_contract(
        original, helper, tmp_path / f"{kind}-native-import-contract.json"
    )
    gaps = direct_control_flow._compute_coverage_gaps(
        direct_control_flow._normalize_sections(parsed),
        tuple((item.begin_rva, item.end_rva)
              for item in parsed.runtime_functions),
    )
    output_dir = tmp_path / f"packed-{kind}"
    output_dir.mkdir()
    output = output_dir / original.name
    shutil.copyfile(helper, output_dir / helper.name)
    result = orchestrator.pack_file(
        str(original),
        orchestrator.PackOptions(
            output_path=str(output),
            is_dll=(kind == "dll"),
            stub_path=str(stub),
            virtualization_specs=(orchestrator.VirtualizationSpec(
                "vm_probe", spec.rva, spec.size, spec.body_size),),
            virtualization_gap_acknowledgements=tuple(
                orchestrator.VirtualizationGapAcknowledgement(
                    gap.rva, gap.size, "exact generated fixture gap")
                for gap in gaps
            ),
            acknowledge_unproven_indirect_targets=True,
            virtualization_native_import_contract_path=str(contract),
            _allow_unverified_stub_for_tests=False,
        ),
    )
    assert result.ok, result.error
    assert output.is_file() and original.read_bytes() == original_bytes
    packed_run = _run([str(output)] if kind == "exe"
                      else [str(host), str(output)], output_dir)
    assert (packed_run.returncode, packed_run.stdout, packed_run.stderr) == (
        0, b"IMPORT_LEAF value=42 passed=true\n", b""
    )
    assert hashlib.sha256((output_dir / helper.name).read_bytes()).hexdigest() == \
        hashlib.sha256(helper.read_bytes()).hexdigest()
