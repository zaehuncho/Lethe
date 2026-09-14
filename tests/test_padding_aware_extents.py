"""Conservative two-length function virtualization contract tests."""
from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest


pytest.importorskip("iced_x86")
pytest.importorskip("keystone")

from keystone import KS_ARCH_X86, KS_MODE_64, Ks
from lifter import direct_control_flow, function_discovery, virtualization_plan, x64_lifter
from packer import pe_analyze, virtualize


_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_EXEC = 0x60000020


def _asm(source: str, rva: int = 0x1000) -> bytes:
    encoded, _ = _KS.asm(source, addr=rva)
    return bytes(encoded)


def _parsed(
    source: bytes,
    *,
    rva: int = 0x1000,
    unwind_info_rva: int = 0x3000,
    relocations: tuple[int, ...] = (),
    load_config=None,
) -> SimpleNamespace:
    return SimpleNamespace(
        path="synthetic.exe",
        image_base=0x140000000,
        size_of_image=0x5000,
        oep_rva=rva,
        tls=None,
        sections=(
            SimpleNamespace(
                name=".text",
                rva=rva,
                virtual_size=len(source),
                raw=source,
                characteristics=_EXEC,
            ),
        ),
        pdata_rva=0x2000,
        pdata_count=1,
        runtime_functions=(
            SimpleNamespace(
                begin_rva=rva,
                end_rva=rva + len(source),
                unwind_info_rva=unwind_info_rva,
                unwind_flags=0,
            ),
        ),
        dir64_relocations=tuple(
            SimpleNamespace(target_rva=target) for target in relocations
        ),
        export_directory_rva=0,
        export_directory_size=0,
        rsrc_directory_rva=0,
        rsrc_directory_size=0,
        delay_import_rva=0,
        delay_import_size=0,
        load_config=load_config,
    )


@pytest.mark.parametrize(
    "suffix",
    (
        b"\xCC",
        b"\xCC\xCC\xCC",
        b"\x90",
        b"\x66\x90",
        b"\x0F\x1F\x00",
        b"\x0F\x1F\x40\x00",
        b"\x0F\x1F\x44\x00\x00",
        b"\x66\x0F\x1F\x44\x00\x00",
        b"\x0F\x1F\x80\x00\x00\x00\x00",
        b"\x0F\x1F\x84\x00\x00\x00\x00\x00",
        b"\x66\x0F\x1F\x84\x00\x00\x00\x00\x00",
        b"\xCC\x0F\x1F\x00\x66\x90",
    ),
)
def test_only_enumerated_canonical_suffixes_trim_after_plain_ret(suffix: bytes) -> None:
    body = _asm("mov eax, 42; ret")
    assert x64_lifter.canonical_lifted_body_size(body + suffix) == len(body)


@pytest.mark.parametrize(
    "source",
    (
        _asm("mov eax, 42; ret") + b"\x00\x00",
        _asm("mov eax, 42; ret") + b"\x66\x66\x90",
        _asm("mov eax, 42; ret 8") + b"\xCC",
        _asm("mov eax, 42; nop") + b"\xCC",
    ),
)
def test_arbitrary_zero_prefixed_nop_and_nonplain_ret_never_trim(source: bytes) -> None:
    try:
        body_size = x64_lifter.canonical_lifted_body_size(source)
    except x64_lifter.LiftUnsupported:
        return
    assert body_size == len(source)


def test_discovery_reports_two_lengths_but_keeps_selection_v1_equal_extent() -> None:
    body = _asm("mov eax, 42; ret")
    source = body + b"\xCC\xCC"
    report = function_discovery.discover_functions(_parsed(source), exports=())
    candidate = report.candidates[0]

    assert report.version == 2
    assert candidate.source_extent_size == len(source)
    assert candidate.lifted_body_size == len(body)
    assert candidate.liftable is True
    assert candidate.to_dict()["source_extent_size"] == len(source)
    assert candidate.to_dict()["lifted_body_size"] == len(body)
    assert report.starter_selection_manifest()["version"] == 1
    assert report.starter_selection_manifest()["functions"] == []


def test_discovery_rejects_relocation_and_unwind_metadata_in_suffix() -> None:
    body = _asm("mov eax, 42; ret")
    source = body + b"\xCC" * 8
    suffix_rva = 0x1000 + len(body)

    relocated = function_discovery.discover_functions(
        _parsed(source, relocations=(suffix_rva - 4,)), exports=()
    ).candidates[0]
    assert relocated.liftable is False
    assert "DIR64 relocation" in relocated.rejection_reason

    unwind = function_discovery.discover_functions(
        _parsed(source, unwind_info_rva=suffix_rva), exports=()
    ).candidates[0]
    assert unwind.liftable is False
    assert "unwind info" in unwind.rejection_reason


def test_discovery_rejects_export_entry_in_padding_suffix() -> None:
    body = _asm("mov eax, 42; ret")
    source = body + b"\xCC"
    with pytest.raises(function_discovery.FunctionDiscoveryError, match="interior"):
        function_discovery.discover_functions(
            _parsed(source),
            exports=(
                function_discovery.ExportSymbol(
                    "padding_alias", 1, 0x1000 + len(body)
                ),
            ),
        )


def test_padding_requires_one_exact_pdata_owner_at_every_gate() -> None:
    body = _asm("mov eax, 42; ret")
    source = body + b"\xCC"
    spec = virtualization_plan.FunctionSpec(
        "no_pdata_owner", 0x1000, len(source), len(body)
    )
    parsed = _parsed(source)
    parsed.runtime_functions = ()
    parsed.pdata_count = 0
    parsed.pdata_rva = 0

    with pytest.raises(
        direct_control_flow.DirectControlFlowError,
        match="must exactly match one runtime-function range",
    ):
        direct_control_flow.analyze_direct_control_flow(
            parsed, (spec,), production=False
        )

    reader = virtualization_plan.SectionImage.from_parsed_sections(parsed.sections)
    with pytest.raises(
        virtualization_plan.FunctionRejected,
        match="requires complete source exception metadata",
    ):
        virtualization_plan.compile_virtualization_manifest(
            (spec,),
            reader,
            generated_text_rva=0x5000,
            generated_data_rva=0x7000,
        )

    with pytest.raises(
        virtualization_plan.FunctionRejected,
        match="exactly match one runtime-function record",
    ):
        virtualization_plan.compile_virtualization_manifest(
            (spec,),
            reader,
            generated_text_rva=0x5000,
            generated_data_rva=0x7000,
            source_exception_metadata=virtualization_plan.SourceExceptionMetadata(
                0, ()
            ),
            require_source_exception_metadata=True,
        )

    mismatched = virtualization_plan.SourceExceptionMetadata(
        0x3000,
        (
            virtualization_plan.SourceRuntimeFunction(
                0x1100, 0x1100 + len(source), 0x4000, 0
            ),
        ),
    )
    with pytest.raises(
        virtualization_plan.FunctionRejected,
        match="exactly match one runtime-function record",
    ):
        virtualization_plan.compile_virtualization_manifest(
            (spec,),
            reader,
            generated_text_rva=0x5000,
            generated_data_rva=0x7000,
            source_exception_metadata=mismatched,
        )

    duplicate = virtualization_plan.SourceRuntimeFunction(
        0x1000, 0x1000 + len(source), 0x4000, 0
    )
    with pytest.raises(
        virtualization_plan.VirtualizationPlanError,
        match="ranges overlap",
    ):
        virtualization_plan.compile_virtualization_manifest(
            (spec,),
            reader,
            generated_text_rva=0x5000,
            generated_data_rva=0x7000,
            source_exception_metadata=virtualization_plan.SourceExceptionMetadata(
                0x3000, (duplicate, duplicate)
            ),
        )

    with pytest.raises(
        virtualize.VirtualizationMaterializationError,
        match="exactly match one runtime-function record",
    ):
        virtualize._validate_padding_suffix_bindings(parsed, (spec,))

    record = SimpleNamespace(
        begin_rva=0x1000,
        end_rva=0x1000 + len(source),
        unwind_info_rva=0x3000,
        unwind_flags=0,
    )
    parsed.runtime_functions = (record, record)
    with pytest.raises(
        virtualize.VirtualizationMaterializationError,
        match="exactly match one runtime-function record",
    ):
        virtualize._validate_padding_suffix_bindings(parsed, (spec,))


def test_exact_export_directory_range_rejects_padding_overlap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = _asm("mov eax, 42; ret")
    source = body + b"\xCC" * 40
    suffix_rva = 0x1000 + len(body)
    parsed = _parsed(source)
    parsed.export_directory_rva = suffix_rva
    parsed.export_directory_size = 40
    candidate = function_discovery.discover_functions(
        parsed, exports=()
    ).candidates[0]
    assert candidate.liftable is False
    assert "export directory" in candidate.rejection_reason

    monkeypatch.setattr(function_discovery, "parse_pe_exports", lambda _parsed: ())
    spec = virtualization_plan.FunctionSpec(
        "export_overlap", 0x1000, len(source), len(body)
    )
    with pytest.raises(
        virtualize.VirtualizationMaterializationError,
        match="source export directory",
    ):
        virtualize._validate_padding_suffix_bindings(parsed, (spec,))


def test_direct_control_flow_rejects_branch_into_padding_suffix() -> None:
    source = _asm("test eax, eax; je 0x1005; ret") + b"\xCC"
    body_size = x64_lifter.canonical_lifted_body_size(source)
    assert body_size == len(source) - 1
    spec = virtualization_plan.FunctionSpec(
        "branch_to_padding", 0x1000, len(source), body_size
    )

    with pytest.raises(direct_control_flow.DirectControlFlowError, match="padding suffix"):
        direct_control_flow.analyze_direct_control_flow(
            _parsed(source), (spec,), production=False
        )


def test_planner_lifts_body_hashes_full_extent_and_tombstones_all_bytes() -> None:
    body = _asm("mov eax, 42; ret")
    source = body + b"\xCC\x0F\x1F\x00"
    spec = virtualization_plan.FunctionSpec(
        "padded", 0x1000, len(source), len(body)
    )
    sections = virtualization_plan.SectionImage(
        (
            virtualization_plan.SectionBytes(
                ".text", 0x1000, len(source), source, _EXEC
            ),
        )
    )
    exceptions = virtualization_plan.SourceExceptionMetadata(
        table_rva=0x3000,
        records=(
            virtualization_plan.SourceRuntimeFunction(
                0x1000, 0x1000 + len(source), 0x4000, 0
            ),
        ),
    )
    manifest = virtualization_plan.compile_virtualization_manifest(
        (spec,),
        sections,
        generated_text_rva=0x5000,
        generated_data_rva=0x7000,
        source_dir64_relocations=(),
        source_exception_metadata=exceptions,
    )
    equal_manifest = virtualization_plan.compile_virtualization_manifest(
        (
            virtualization_plan.FunctionSpec(
                "body_only", 0x1000, len(body), len(body)
            ),
        ),
        virtualization_plan.SectionImage(
            (
                virtualization_plan.SectionBytes(
                    ".text", 0x1000, len(body), body, _EXEC
                ),
            )
        ),
        generated_text_rva=0x5000,
        generated_data_rva=0x7000,
    )

    function = manifest.functions[0]
    assert manifest.version == virtualization_plan.MANIFEST_VERSION == 3
    assert function.target_size == len(source)
    assert function.lifted_body_size == len(body)
    assert function.original_sha256 == hashlib.sha256(source).hexdigest()
    assert function.lifted_body_sha256 == hashlib.sha256(body).hexdigest()
    assert function.capabilities["source_extent_fully_tombstoned"] is True
    assert function.capabilities["canonical_padding_suffix_trimmed"] is True
    assert function.program == equal_manifest.functions[0].program
    assert len(function.target_entry_patch.patch) == len(source)
    assert function.target_entry_patch.patch[5:] == b"\xCC" * (len(source) - 5)
    assert manifest.exception_table.removed[0].end_rva == 0x1000 + len(source)


def test_materializer_preflight_rejects_gfid_xfg_and_direct_suffix_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = _asm("test eax, eax; je 0x1005; ret") + b"\xCC"
    body_size = x64_lifter.canonical_lifted_body_size(body)
    suffix_rva = 0x1000 + body_size
    target = pe_analyze.ParsedGuardTarget(suffix_rva, b"\x08")
    load_config = SimpleNamespace(
        directory_rva=0x3000,
        directory_size=0x94,
        guard_flags=0x10000000,
        guard_cf_function_table_rva=0x3200,
        guard_cf_targets=(target,),
        guard_address_taken_iat_entry_table_rva=0,
        guard_address_taken_iat_entries=(),
        guard_long_jump_target_table_rva=0,
        guard_long_jump_targets=(),
        guard_eh_continuation_table_rva=0,
        guard_eh_continuation_targets=(),
        volatile_metadata=None,
    )
    parsed = _parsed(body, load_config=load_config)
    parsed.is_dll = False
    parsed.imports = []
    parsed.reloc_blob = b""
    parsed.rsrc_rva = 0
    parsed.rsrc_directory_rva = 0
    parsed.rsrc_directory_size = 0
    parsed.delay_import_rva = 0
    parsed.delay_import_size = 0
    parsed.file_characteristics = 0x22
    parsed.dll_characteristics = 0x140
    monkeypatch.setattr(function_discovery, "parse_pe_exports", lambda _parsed: ())
    spec = virtualization_plan.FunctionSpec(
        "blocked", 0x1000, len(body), body_size
    )

    with pytest.raises(
        virtualize.VirtualizationMaterializationError,
        match="Guard CF function table target",
    ):
        virtualize._validate_padding_suffix_bindings(parsed, (spec,))

    xfg_body = _asm("mov eax, 42; ret")
    xfg_source = xfg_body + b"\xCC" * 8
    load_config.guard_cf_targets = (
        pe_analyze.ParsedGuardTarget(0x1000 + len(xfg_source), b"\x08"),
    )
    xfg_parsed = _parsed(xfg_source, load_config=load_config)
    for name, value in (
        ("is_dll", False),
        ("imports", []),
        ("reloc_blob", b""),
        ("rsrc_rva", 0),
        ("rsrc_directory_rva", 0),
        ("rsrc_directory_size", 0),
        ("delay_import_rva", 0),
        ("delay_import_size", 0),
        ("file_characteristics", 0x22),
        ("dll_characteristics", 0x140),
    ):
        setattr(xfg_parsed, name, value)
    xfg_spec = virtualization_plan.FunctionSpec(
        "xfg_hash_blocked", 0x1000, len(xfg_source), len(xfg_body)
    )
    with pytest.raises(
        virtualize.VirtualizationMaterializationError,
        match="XFG function hash",
    ):
        virtualize._validate_padding_suffix_bindings(xfg_parsed, (xfg_spec,))

    parsed.load_config = None
    with pytest.raises(
        virtualize.VirtualizationMaterializationError,
        match="decoded direct-control target",
    ):
        virtualize._validate_padding_suffix_bindings(parsed, (spec,))
