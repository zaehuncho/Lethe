"""Bounded state-neutral tail thunks, using the public materialization planner."""
from dataclasses import replace
import inspect
import struct
from types import SimpleNamespace

import pytest

from tests.test_virtualization_plan import plan, _asm


def _fixture(kind="pdata", hops=2):
    entry, terminal, slot = 0x1800, 0x2600, 0x3000
    caller = _asm(f"sub rsp,0x48; call {entry:#x}; add rsp,0x48; ret")
    raw = bytearray(b"\xCC" * 0x1800)
    raw[:len(caller)] = caller
    chain = [entry + 8 * i for i in range(hops)]
    end = terminal if kind == "pdata" else entry + 8 * hops
    for i, rva in enumerate(chain):
        target = chain[i + 1] if i + 1 < hops else end
        raw[rva - 0x1000:rva - 0x1000 + 5] = b"\xE9" + struct.pack("<i", target - rva - 5)
    native = _asm("sub rsp,8; mov eax,83; add rsp,8; ret", rva=terminal)
    raw[terminal - 0x1000:terminal - 0x1000 + len(native)] = native
    if kind == "iat":
        raw[end - 0x1000:end - 0x1000 + 6] = b"\xFF\x25" + struct.pack("<i", slot - end - 6)
    elif hops == 0:
        # A direct native PDATA call is the original supported control case.
        caller = _asm(f"sub rsp,0x48; call {terminal:#x}; add rsp,0x48; ret")
        raw[:len(caller)] = caller
    sections = [plan.SectionBytes(".text", 0x1000, len(raw), bytes(raw), 0x60000020),
                plan.SectionBytes(".rdata", slot, 0x40, bytes(0x40), 0x40000040)]
    records = (plan.SourceRuntimeFunction(0x1000, 0x1000 + len(caller), 0x4000),
               plan.SourceRuntimeFunction(terminal, terminal + len(native), 0x4010))
    return dict(caller=caller, sections=sections, records=records, entry=entry, terminal=end, slot=slot)


def _compile(f, rolling=False):
    kwargs = {}
    # The same held-out positives exercise the baseline's real out-of-extent
    # rejection instead of failing at a newly added Python keyword.
    if "source_import_iat_rvas" in inspect.signature(plan.compile_virtualization_manifest).parameters:
        kwargs["source_import_iat_rvas"] = f.get("imports", (f["slot"],))
    return plan.compile_virtualization_manifest(
        [plan.FunctionSpec("caller", 0x1000, len(f["caller"]))],
        plan.SectionImage(f["sections"]), generated_text_rva=0x6000, generated_data_rva=0x8000,
        source_exception_metadata=plan.SourceExceptionMetadata(0x5000, f["records"]),
        rolling=rolling, rolling_seed=bytes(range(16)) if rolling else None, **kwargs)


@pytest.mark.parametrize("rolling", [False, True])
@pytest.mark.parametrize(("kind", "hops"),
                         [("pdata", n) for n in (0, 1, 2, 4, 15, 16)] +
                         [("iat", n) for n in (0, 1, 2, 14, 15)])
def test_integration_tail_alias_admission_contract(kind, hops, rolling):
    fixture = _fixture(kind, hops)
    if kind == "pdata":
        # Neutral E9 links cannot make a retained PDATA CALL frame equivalent
        # to the source return site. Preserve each former positive as a typed
        # fail-closed regression, including the direct zero-hop target.
        with pytest.raises(plan.FunctionRejected, match="retained PDATA native CALL lacks physical return-slot"):
            _compile(fixture, rolling)
    else:
        manifest = _compile(fixture, rolling)
        assert [function.name for function in manifest.functions] == ["caller"]


@pytest.mark.parametrize("kind", ["pdata", "iat"])
@pytest.mark.parametrize("failure", ["cycle", "too-deep", "short-jump", "prefix", "register-jump",
                                      "state-change", "call-instead", "unmapped", "discardable",
                                      "nonexec", "inside-body", "selected-terminal", "truncated"])
def test_integration_tail_alias_negative(kind, failure):
    f = _fixture(kind, 17 if failure == "too-deep" else 2)
    section = f["sections"][0]
    raw = bytearray(section.raw)
    rva, target = f["entry"], f["terminal"]
    change = None
    if failure == "cycle": change = b"\xE9\xFB\xFF\xFF\xFF"
    elif failure == "short-jump": change = b"\xEB\x06"
    elif failure == "prefix": change = b"\xF2\xE9" + struct.pack("<i", target - rva - 6)
    elif failure == "register-jump": change = b"\xFF\xE0"
    elif failure == "state-change": change = b"\x50\xE9" + struct.pack("<i", target - rva - 6)
    elif failure == "call-instead": change = b"\xE8" + struct.pack("<i", target - rva - 5)
    elif failure == "unmapped": change = b"\xE9" + struct.pack("<i", 0x200000 - rva - 5)
    elif failure == "discardable": section = replace(section, characteristics=0x62000020)
    elif failure == "nonexec": section = replace(section, characteristics=0x40000040)
    elif failure == "inside-body":
        f["records"] += (plan.SourceRuntimeFunction(rva - 1, rva + 5, 0x4020),)
        f["records"] = tuple(sorted(f["records"], key=lambda record: record.begin_rva))
    elif failure == "selected-terminal": change = b"\xE9" + struct.pack("<i", 0x1000 - rva - 5)
    elif failure == "truncated": raw = raw[:rva - 0x1000 + 4]
    if change is not None: raw[rva - 0x1000:rva - 0x1000 + len(change)] = change
    f["sections"][0] = replace(section, raw=bytes(raw))
    with pytest.raises(plan.FunctionRejected):
        _compile(f)


@pytest.mark.parametrize("failure", ["no-import", "adjacent", "header", "exec-slot", "discardable-slot",
                                      "truncated-slot", "negative-slot", "prefixed-iat"])
def test_integration_import_tail_metadata_negative(failure):
    f = _fixture("iat")
    if failure == "no-import": f["imports"] = ()
    elif failure == "adjacent": f["imports"] = (f["slot"] + 8,)
    elif failure in ("header", "negative-slot", "prefixed-iat"):
        section=f["sections"][0];raw=bytearray(section.raw);rva=f["terminal"]
        target=0x100 if failure == "header" else -1
        if failure == "prefixed-iat": code=b"\xF2\xFF\x25"+struct.pack("<i",f["slot"]-rva-7)
        else: code=b"\xFF\x25"+struct.pack("<i",target-rva-6)
        raw[rva-0x1000:rva-0x1000+len(code)]=code;f["sections"][0]=replace(section,raw=bytes(raw))
        f["imports"]=(target,) if target>0 else ()
    elif failure == "exec-slot": f["sections"][1]=replace(f["sections"][1],characteristics=0x60000020)
    elif failure == "discardable-slot": f["sections"][1]=replace(f["sections"][1],characteristics=0x42000040)
    elif failure == "truncated-slot": f["sections"][1]=replace(f["sections"][1],raw=bytes(7))
    with pytest.raises(plan.FunctionRejected): _compile(f)


@pytest.mark.parametrize("kind", ["pdata", "iat"])
@pytest.mark.parametrize("overlap", ["first-byte", "last-byte", "second-link", "terminal"])
def test_pure_proof_rejects_any_selected_overlap(kind, overlap):
    f=_fixture(kind);module=plan.native_tail_calls
    location={"first-byte":f["entry"],"last-byte":f["entry"]+4,
              "second-link":f["entry"]+8,"terminal":f["terminal"]}[overlap]
    result=module.proven_tail_call_targets(f["caller"],base=0x1000,sections=f["sections"],
        retained_entries=frozenset({0x2600}),runtime_ranges=tuple((v.begin_rva,v.end_rva) for v in f["records"]),
        selected_extents=((0x1000,len(f["caller"])),(location,1)),import_iat_rvas=frozenset({f["slot"]}))
    assert result==frozenset()


@pytest.mark.parametrize("kind", ["pdata", "iat"])
def test_integration_discovery_and_planner_agree(kind):
    from lifter import function_discovery as discovery
    f=_fixture(kind)
    parsed=SimpleNamespace(path="owned-tail-fixture.exe",image_base=0x140000000,size_of_image=0x6000,
        sections=f["sections"],pdata_rva=0x5000,pdata_count=2,runtime_functions=f["records"],
        imports=(SimpleNamespace(funcs=(SimpleNamespace(iat_rva=f["slot"]),)),))
    report=discovery.discover_functions(parsed,exports=())
    caller=next(row for row in report.candidates if row.rva==0x1000)
    if kind == "pdata":
        assert not caller.liftable
        assert "retained PDATA native CALL lacks physical return-slot" in caller.rejection_reason
    else:
        assert caller.liftable, caller.rejection_reason
    assert caller.indirect_target_closure_proven is False
    assert caller.direct_reference_gate_passed is False
    if kind == "pdata":
        with pytest.raises(plan.FunctionRejected, match="retained PDATA native CALL lacks physical return-slot"):
            _compile(f)
    else:
        assert [function.name for function in _compile(f).functions]==["caller"]


@pytest.mark.parametrize("entries", [None, [], {}, "", (True,), (0,), (-1,), (0x100000000,),
                                     (0xfffffff9,), (0x3000,0x3000), (0x3000,0x3004)])
def test_import_metadata_types_and_spans_fail_closed(entries):
    f=_fixture()
    with pytest.raises(plan.VirtualizationPlanError,match="source import IAT entries"):
        plan.compile_virtualization_manifest(
            [plan.FunctionSpec("caller",0x1000,len(f["caller"]))],plan.SectionImage(f["sections"]),
            generated_text_rva=0x6000,generated_data_rva=0x8000,source_import_iat_rvas=entries)


def test_retained_pdata_call_rejects_before_pointer_escape_proof():
    f=_fixture()
    caller=_asm(f"sub rsp,0x48; lea rcx,[rsp+0x20]; call {f['entry']:#x}; add rsp,0x48; ret")
    section=f["sections"][0];raw=bytearray(section.raw);raw[:len(caller)]=caller
    f["caller"]=caller;f["sections"][0]=replace(section,raw=bytes(raw))
    f["records"]=(replace(f["records"][0],end_rva=0x1000+len(caller)),f["records"][1])
    with pytest.raises(plan.FunctionRejected,match="retained PDATA native CALL lacks physical return-slot"):
        _compile(f)
