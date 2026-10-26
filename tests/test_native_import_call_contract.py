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


def test_missing_pinned_dependency_is_a_typed_contract_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing dependency path must not leak a filesystem exception."""
    source = tmp_path / "source.dll"
    source.write_bytes(b"exact source identity")
    spec = plan.FunctionSpec("caller", 0x1000, 1)
    contract = {
        "schema": native_import_contract.SCHEMA,
        "version": native_import_contract.VERSION,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "calls": [{
            "function_rva": spec.rva,
            "call_rva": spec.rva,
            "iat_rva": 0x2010,
            "module": "leaf.dll",
            "symbol": "leaf",
            "dependency_path": "missing.dll",
            "dependency_sha256": "a" * 64,
            "export_rva": 0x1000,
            "export_ordinal": 1,
            "body_size": 1,
            "body_sha256": "b" * 64,
        }],
    }
    contract_path = tmp_path / "contract.json"
    contract_path.write_text(
        json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    parsed = type("Parsed", (), {"path": str(source)})()
    monkeypatch.setattr(
        native_import_contract, "_call_target", lambda *_args: 0x2010
    )
    monkeypatch.setattr(
        native_import_contract, "_import_identity",
        lambda *_args: ("leaf.dll", "leaf"),
    )
    with pytest.raises(native_import_contract.NativeImportContractError,
                       match="cannot resolve pinned dependency"):
        native_import_contract.load_and_verify(
            str(contract_path), parsed=parsed, specs=(spec,)
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
from iced_x86 import Decoder, FlowControl, Mnemonic, OpKind, Register

from lifter import direct_control_flow, function_discovery, x64_lifter
from packer import assemble, cfg_preservation, orchestrator, pe_analyze, virtualize


_ROOT = Path(__file__).resolve().parents[1]
_LEAF_FIXTURE = _ROOT / "tests" / "fixtures" / "native_import_contract" / "normal_leaf"
_FP_LEAF_FIXTURE = _ROOT / "tests" / "fixtures" / "native_import_contract" / "fp_leaf"
_MEMBER_FIXTURE = _ROOT / "tests" / "fixtures" / "native_import_contract" / "member_sret"
_PROMOTION_CAPABILITY_PATH_ENV = "LETHE_PROMOTION_RUNTIME_CAPABILITY_PATH"
_PROMOTION_CAPABILITY_NONCE_ENV = "LETHE_PROMOTION_RUNTIME_CAPABILITY_NONCE"


def _promotion_runtime_capability() -> tuple[str | None, str | None]:
    """Return the promoter's explicit pre-final-manifest capability, if any."""
    path = os.environ.get(_PROMOTION_CAPABILITY_PATH_ENV) or None
    nonce = os.environ.get(_PROMOTION_CAPABILITY_NONCE_ENV) or None
    assert (path is None) == (nonce is None), (
        "promotion runtime capability path and nonce must be paired"
    )
    return path, nonce


def _run(argv: list[str], cwd: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=180, check=False)


def _make_contract(
    source: Path,
    dependency: Path,
    output: Path,
    *,
    selected_export: str = "vm_probe",
    dependency_export: str = "helper_leaf",
) -> tuple[plan.FunctionSpec, Path]:
    parsed = pe_analyze.analyze_pe(str(source))
    export = next(item for item in function_discovery.parse_pe_exports(parsed)
                  if item.name == selected_export)
    runtime = next(item for item in parsed.runtime_functions
                   if item.begin_rva == export.rva)
    spec = plan.FunctionSpec(
        selected_export, runtime.begin_rva, runtime.end_rva - runtime.begin_rva
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
        if iat_rva in imported and imported[iat_rva][1] == dependency_export:
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
                if item.name == dependency_export.encode("ascii")]
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
    promotion_capability_path, promotion_capability_nonce = (
        _promotion_runtime_capability())
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
            _promotion_runtime_capability_path=promotion_capability_path,
            _promotion_runtime_capability_nonce=promotion_capability_nonce,
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


@pytest.mark.skipif(
    os.name != "nt"
    or os.environ.get("LETHE_RUN_NATIVE_IMPORT_CALL_E2E") != "1",
    reason="opt-in generated strict-candidate FP/XMM span import-leaf regression",
)
@pytest.mark.parametrize("kind", ("exe", "dll"))
def test_materialized_generated_fp_import_leaf_exe_and_dll(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Round-trip volatile XMM arguments and XMM0 output through a span call.

    The selected caller sets positional double arguments in XMM0/XMM1, calls a
    source-pinned, stack-neutral imported leaf, and consumes the XMM0 return.
    This is deliberately not a generic floating-point admission: the helper is
    independently leaf-proven and the materialized EXE/DLL must match its
    original bit result exactly.
    """
    if not shutil.which("cmake"):
        pytest.skip("CMake and Visual Studio x64 toolchain required")
    stub_text = (os.environ.get("LETHE_STRICT_REFERENCE_STUB_PATH") or
                 os.environ.get("LETHE_NATIVE_RUNTIME_STUB_PATH"))
    assert stub_text, "strict verified stub path required"
    stub = Path(stub_text).resolve()
    assert stub.is_file() and stub.with_suffix(".manifest.json").is_file()
    promotion_capability_path, promotion_capability_nonce = (
        _promotion_runtime_capability())
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION", "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")

    build_source = tmp_path / "source"
    shutil.copytree(_FP_LEAF_FIXTURE, build_source)
    build = tmp_path / "build"
    for command in (
        ["cmake", "-S", str(build_source), "-B", str(build),
         "-G", "Visual Studio 17 2022", "-A", "x64"],
        ["cmake", "--build", str(build), "--config", "Release"],
    ):
        built = _run(command, tmp_path)
        assert built.returncode == 0, (command, built.stdout, built.stderr)

    release = build / "Release"
    original = release / ("import_fp_leaf_exe.exe" if kind == "exe"
                          else "import_fp_leaf_dll.dll")
    helper = release / "import_fp_leaf_helper.dll"
    host = release / "reference_host.exe"
    assert original.is_file() and helper.is_file() and host.is_file()
    original_bytes = original.read_bytes()
    expected = b"IMPORT_FP_SPAN bits=bff0000000000000 passed=true\n"
    original_run = _run([str(original)] if kind == "exe"
                        else [str(host), str(original)], release)
    assert (original_run.returncode, original_run.stdout, original_run.stderr) == (
        0, expected, b""
    )

    spec, contract = _make_contract(
        original, helper, tmp_path / f"{kind}-fp-native-import-contract.json",
        selected_export="vm_fp_probe", dependency_export="helper_fp",
    )
    parsed = pe_analyze.analyze_pe(str(original))
    gaps = direct_control_flow._compute_coverage_gaps(
        direct_control_flow._normalize_sections(parsed),
        tuple((item.begin_rva, item.end_rva)
              for item in parsed.runtime_functions),
    )
    captured: dict[str, object] = {}
    materialize = virtualize.materialize_selected_functions

    def capture_materialization(*args, **kwargs):
        captured["page_master_key"] = bytes(kwargs["page_master_key"])
        captured["opcode_table"] = kwargs["opcode_table"]
        result = materialize(*args, **kwargs)
        captured["result"] = result
        return result

    monkeypatch.setattr(
        virtualize, "materialize_selected_functions", capture_materialization
    )
    output_dir = tmp_path / f"packed-fp-{kind}"
    output_dir.mkdir()
    output = output_dir / original.name
    shutil.copyfile(helper, output_dir / helper.name)
    packed = orchestrator.pack_file(
        str(original),
        orchestrator.PackOptions(
            output_path=str(output), is_dll=(kind == "dll"), stub_path=str(stub),
            virtualization_specs=(orchestrator.VirtualizationSpec(
                spec.name, spec.rva, spec.size, spec.body_size
            ),),
            virtualization_gap_acknowledgements=tuple(
                orchestrator.VirtualizationGapAcknowledgement(
                    gap.rva, gap.size, "exact generated FP import fixture gap"
                )
                for gap in gaps
            ),
            acknowledge_unproven_indirect_targets=True,
            virtualization_native_import_contract_path=str(contract),
            _allow_unverified_stub_for_tests=False,
            _promotion_runtime_capability_path=promotion_capability_path,
            _promotion_runtime_capability_nonce=promotion_capability_nonce,
        ),
    )
    assert packed.ok, packed.error
    assert output.is_file() and original.read_bytes() == original_bytes
    packed_run = _run([str(output)] if kind == "exe"
                      else [str(host), str(output)], output_dir)
    assert (packed_run.returncode, packed_run.stdout, packed_run.stderr) == (
        0, expected, b""
    )
    assert hashlib.sha256((output_dir / helper.name).read_bytes()).hexdigest() == \
        hashlib.sha256(helper.read_bytes()).hexdigest()

    import struct

    from daedalus import daedalus_ref
    from packer import bytecode_pages

    materialized = captured["result"]
    function = materialized.manifest.functions[0]
    assert len(materialized.manifest.native_import_call_proofs) == 1
    assert function.program_format == "paged-v1"
    envelope = bytecode_pages.parse_envelope(function.program)
    assert envelope.program_id == function.program_id
    plain_program = bytecode_pages.open_program(
        function.program, captured["page_master_key"]
    )
    (data_size,) = struct.unpack_from("<H", plain_program)
    assert 2 + data_size <= len(plain_program)
    native_call_frame_ops = [
        mnemonic
        for _offset, mnemonic, _width, _kind, _operand in
        daedalus_ref.iter_instructions(
            plain_program[2 + data_size:],
            captured["opcode_table"].decoder_mapping(),
        )
        if mnemonic in {"n_call_frame", "n_call_frame_span"}
    ]
    assert native_call_frame_ops == ["n_call_frame_span"]


@pytest.mark.skipif(
    os.name != "nt"
    or os.environ.get("LETHE_RUN_NATIVE_IMPORT_CALL_E2E") != "1",
    reason="opt-in strict-candidate XFG member-return import-leaf regression",
)
def test_materialized_xfg_member_hidden_sret_import_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep the XFG hidden-sret/``this`` import-call bridge exact and typed.

    The selected C++ member uses the Win64 ABI shape exercised by the product
    ``MeterDetector::config`` path: hidden output storage in RCX, ``this`` in
    RDX, and one normal IAT call to a pinned, stack-neutral dependency leaf.
    Nothing in this regression treats an arbitrary indirect target as proven.
    """
    if not shutil.which("cmake"):
        pytest.skip("CMake and Visual Studio x64 toolchain required")
    stub_text = (os.environ.get("LETHE_STRICT_REFERENCE_STUB_PATH") or
                 os.environ.get("LETHE_NATIVE_RUNTIME_STUB_PATH"))
    assert stub_text, "strict verified stub path required"
    stub = Path(stub_text).resolve()
    assert stub.is_file() and stub.with_suffix(".manifest.json").is_file()
    promotion_capability_path, promotion_capability_nonce = (
        _promotion_runtime_capability())
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION", "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")

    build_source = tmp_path / "source"
    shutil.copytree(_MEMBER_FIXTURE, build_source)
    build = tmp_path / "build"
    for command in (
        ["cmake", "-S", str(build_source), "-B", str(build),
         "-G", "Visual Studio 17 2022", "-A", "x64"],
        ["cmake", "--build", str(build), "--config", "Release"],
    ):
        built = _run(command, tmp_path)
        assert built.returncode == 0, (command, built.stdout, built.stderr)

    release = build / "Release"
    original = release / "xfg_member.dll"
    helper = release / "xfg_member_support.dll"
    host = release / "xfg_member_host.exe"
    assert original.is_file() and helper.is_file() and host.is_file()
    original_bytes = original.read_bytes()
    original_run = _run([str(host), str(original)], release)
    assert (original_run.returncode, original_run.stdout, original_run.stderr) == (
        0, b"XFG_MEMBER_IMPORT passed=true\r\n", b""
    )

    parsed = pe_analyze.analyze_pe(str(original))
    assert parsed.is_dll is True
    assert parsed.load_config is not None and parsed.load_config.xfg_present is True
    member_exports = [item for item in function_discovery.parse_pe_exports(parsed)
                      if item.name.startswith("?config@DetectorLike@@")]
    assert len(member_exports) == 1
    selected_export = member_exports[0].name
    runtime = next(item for item in parsed.runtime_functions
                   if item.begin_rva == member_exports[0].rva)
    spec = plan.FunctionSpec(
        selected_export, runtime.begin_rva, runtime.end_rva - runtime.begin_rva
    )
    source_body = plan.SectionImage.from_parsed_sections(parsed.sections).read_file_backed_executable(
        spec.rva, spec.body_size
    )
    instructions = tuple(Decoder(64, source_body, ip=spec.rva))
    assert instructions
    assert any(
        instruction.memory_base == Register.RDX
        or any(
            instruction.op_kind(index) == OpKind.REGISTER
            and instruction.op_register(index) == Register.RDX
            for index in range(instruction.op_count)
        )
        for instruction in instructions
    ), "selected member must consume its Win64 this pointer"
    assert any(
        instruction.op_kind(index) == OpKind.REGISTER
        and instruction.op_register(index) == Register.RCX
        for instruction in instructions
        for index in range(instruction.op_count)
    ), "selected member must consume hidden return storage"
    imports = {
        function.iat_rva: (dll.name, function.name)
        for dll in parsed.imports for function in dll.funcs
        if not function.by_ordinal
    }
    imported_calls = []
    for instruction in instructions:
        if instruction.mnemonic != Mnemonic.CALL:
            continue
        iat_rva = native_tail_calls.rip_relative_import_call_target(
            source_body, base=spec.rva, call_rva=instruction.ip
        )
        if iat_rva in imports and imports[iat_rva][1] == "xfg_copy_config":
            imported_calls.append((instruction.ip, iat_rva))
    assert len(imported_calls) == 1, imported_calls
    source_gfid = next(
        target for target in parsed.load_config.guard_cf_targets
        if target.rva == spec.rva
    )

    discovery = direct_control_flow.analyze_direct_control_flow(
        parsed, (spec,), production=False
    )
    # The generated DLL has unrelated compiler/import regions outside this
    # PDATA member body.  Those exact global gaps are acknowledged below, but
    # the selected ABI body itself must remain fully covered.
    assert all(
        gap.rva + gap.size <= spec.rva
        or spec.rva + spec.size <= gap.rva
        for gap in discovery.coverage_gaps
    ), discovery.coverage_gaps
    contract_path = tmp_path / "xfg-member-native-import-contract.json"
    exact_spec, contract_path = _make_contract(
        original, helper, contract_path,
        selected_export=selected_export,
        dependency_export="xfg_copy_config",
    )
    assert exact_spec == spec
    contract_doc = json.loads(contract_path.read_text(encoding="utf-8"))
    assert len(contract_doc["calls"]) == 1
    record = contract_doc["calls"][0]
    assert (record["function_rva"], record["call_rva"], record["iat_rva"]) == (
        spec.rva, imported_calls[0][0], imported_calls[0][1]
    )

    # Each binding is independently required before output can be materialized.
    mutations = {
        ("root", "source_sha256"): "0" * 64,
        ("call", "function_rva"): spec.rva + 1,
        ("call", "call_rva"): record["call_rva"] + 1,
        ("call", "iat_rva"): record["iat_rva"] + 8,
        ("call", "module"): "wrong.dll",
        ("call", "symbol"): "wrong_symbol",
        ("call", "dependency_path"): str(tmp_path / "wrong.dll"),
        ("call", "dependency_sha256"): "0" * 64,
        ("call", "export_rva"): record["export_rva"] + 1,
        ("call", "export_ordinal"): record["export_ordinal"] + 1,
        ("call", "body_size"): record["body_size"] + 1,
        ("call", "body_sha256"): "0" * 64,
    }
    for index, ((scope, field), value) in enumerate(mutations.items()):
        mutated = json.loads(json.dumps(contract_doc))
        target = mutated if scope == "root" else mutated["calls"][0]
        target[field] = value
        bad_contract = tmp_path / f"xfg-member-bad-{index}.json"
        bad_contract.write_text(
            json.dumps(mutated, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        with pytest.raises(native_import_contract.NativeImportContractError):
            native_import_contract.load_and_verify(
                str(bad_contract), parsed=parsed, specs=(spec,)
            )

    gaps = direct_control_flow._compute_coverage_gaps(
        direct_control_flow._normalize_sections(parsed),
        tuple((item.begin_rva, item.end_rva)
              for item in parsed.runtime_functions),
    )
    captured: dict[str, object] = {}
    materialize = virtualize.materialize_selected_functions

    def capture_materialization(*args, **kwargs):
        result = materialize(*args, **kwargs)
        captured["result"] = result
        return result

    monkeypatch.setattr(
        virtualize, "materialize_selected_functions", capture_materialization
    )
    output_dir = tmp_path / "packed-member"
    output_dir.mkdir()
    output = output_dir / original.name
    shutil.copyfile(helper, output_dir / helper.name)
    result = orchestrator.pack_file(
        str(original),
        orchestrator.PackOptions(
            output_path=str(output), is_dll=True, stub_path=str(stub),
            virtualization_specs=(orchestrator.VirtualizationSpec(
                spec.name, spec.rva, spec.size, spec.body_size
            ),),
            virtualization_gap_acknowledgements=tuple(
                orchestrator.VirtualizationGapAcknowledgement(
                    gap.rva, gap.size,
                    "exact generated XFG member/import fixture gap",
                )
                for gap in gaps
            ),
            acknowledge_unproven_indirect_targets=True,
            virtualization_native_import_contract_path=str(contract_path),
            _allow_unverified_stub_for_tests=False,
            _promotion_runtime_capability_path=promotion_capability_path,
            _promotion_runtime_capability_nonce=promotion_capability_nonce,
        ),
    )
    assert result.ok, result.error
    assert output.is_file() and original.read_bytes() == original_bytes
    packed_run = _run([str(host), str(output)], output_dir)
    assert (packed_run.returncode, packed_run.stdout, packed_run.stderr) == (
        original_run.returncode, original_run.stdout, original_run.stderr,
    )
    assert hashlib.sha256((output_dir / helper.name).read_bytes()).hexdigest() == \
        hashlib.sha256(helper.read_bytes()).hexdigest()

    materialized = captured["result"]
    assert materialized.manifest.native_import_call_proofs[0].to_dict() == {
        field: record[field]
        for field in (
            "function_rva", "call_rva", "iat_rva", "module", "symbol",
            "dependency_sha256", "export_rva", "export_ordinal", "body_size",
            "body_sha256",
        )
    }
    function = materialized.manifest.functions[0]
    assert function.target_rva == spec.rva
    assert function.capabilities["direct_only_thunk"] is True
    assert function.capabilities["cfg_target_declared"] is False
    assert function.capabilities["xfg_function_hash_emitted"] is False
    thunk_rva = function.generated_executable_ranges[0].rva
    assert materialized.parsed.generated_cfg_targets == ()
    assert materialized.parsed.load_config == parsed.load_config
    preserved_plan = cfg_preservation.build_cfg_preservation_plan(
        materialized.parsed, materialized.manifest
    )
    assert preserved_plan.preservation_supported is True
    assert preserved_plan.generated_thunk_targets == ()
    assert any(
        target.rva == source_gfid.rva and target.metadata == source_gfid.metadata
        for target in preserved_plan.merged_declared_targets
    )

    # A packed Lethe image deliberately has raw-empty conventional sections, so
    # source-image analysis must not be reused to inspect its serialized PE
    # metadata.  Read the emitted load-config directory through the packer's
    # mapped-image reader, as the XFG materialization regressions do.
    packed_image = assemble._StubImage(output.read_bytes())
    load_config_rva, load_config_size = packed_image.dir(assemble.DIR_LOAD_CONFIG)
    assert load_config_rva and load_config_size >= 148
    packed_load_config = packed_image.read_at_rva(
        load_config_rva, load_config_size
    )
    table_va = int.from_bytes(packed_load_config[128:136], "little")
    table_count = int.from_bytes(packed_load_config[136:144], "little")
    guard_flags = int.from_bytes(packed_load_config[144:148], "little")
    assert guard_flags & 0x00800000
    metadata_size = (guard_flags >> 28) & 0xF
    stride = 4 + metadata_size
    assert table_count and metadata_size
    table = packed_image.read_at_rva(
        table_va - packed_image.image_base, table_count * stride
    )
    packed_targets = {
        int.from_bytes(table[offset:offset + 4], "little"):
            table[offset + 4:offset + stride]
        for offset in range(0, len(table), stride)
    }
    assert packed_targets[spec.rva] == source_gfid.metadata
    assert thunk_rva not in packed_targets
    entry = pe_analyze._slice_at_rva(
        materialized.parsed.sections, spec.rva, 5,
        what="materialized XFG member entry",
    )
    assert entry[0] == 0xE9
    displacement = int.from_bytes(entry[1:5], "little", signed=True)
    assert spec.rva + 5 + displacement == thunk_rva

    bad_output = tmp_path / "must-not-exist.dll"
    rejected = orchestrator.pack_file(
        str(original),
        orchestrator.PackOptions(
            output_path=str(bad_output), is_dll=True, stub_path=str(stub),
            virtualization_specs=(orchestrator.VirtualizationSpec(
                spec.name, spec.rva, spec.size, spec.body_size
            ),),
            virtualization_gap_acknowledgements=tuple(
                orchestrator.VirtualizationGapAcknowledgement(
                    gap.rva, gap.size,
                    "exact generated XFG member/import fixture gap",
                )
                for gap in gaps
            ),
            acknowledge_unproven_indirect_targets=True,
            virtualization_native_import_contract_path=str(
                tmp_path / "xfg-member-bad-0.json"
            ),
            _allow_unverified_stub_for_tests=False,
            _promotion_runtime_capability_path=promotion_capability_path,
            _promotion_runtime_capability_nonce=promotion_capability_nonce,
        ),
    )
    assert not rejected.ok and not bad_output.exists()
