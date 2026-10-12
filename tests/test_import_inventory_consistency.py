"""Discovery and planning must agree on the complete source import inventory."""
from types import SimpleNamespace

import pytest

from lifter import function_discovery as discovery
from tests.test_native_tail_call_proof import _compile, _fixture, plan


def _parsed(f, entries, split=False):
    functions=tuple(SimpleNamespace(iat_rva=rva) for rva in entries)
    dlls=(tuple(SimpleNamespace(funcs=(function,)) for function in functions)
          if split else (SimpleNamespace(funcs=functions),))
    return SimpleNamespace(path="import-inventory-fixture.exe",image_base=0x140000000,
        size_of_image=0x6000,sections=f["sections"],pdata_rva=0x5000,pdata_count=2,
        runtime_functions=f["records"],imports=dlls)


INVALID_ENTRIES=[
    (0x3000,0x3000), (0x3000,0x3004), (0x3004,0x3000), (0x3000,0x3007),
    (0x3000,0x3008,0x3008), (0x3000,True), (0x3000,False), (0x3000,0),
    (0x3000,-1), (0x3000,1.5), (0x3000,"0x3010"), (0x3000,None),
    (0x3000,0x100000000), (0x3000,0xfffffff9),
]


@pytest.mark.parametrize("kind",["pdata","iat"])
@pytest.mark.parametrize("split",[False,True])
@pytest.mark.parametrize("entries",INVALID_ENTRIES)
def test_discovery_rejects_every_inventory_the_planner_rejects(kind,split,entries):
    f=_fixture(kind);f["imports"]=entries
    with pytest.raises(plan.VirtualizationPlanError,match="source import IAT entries"):
        _compile(f)
    with pytest.raises(discovery.FunctionDiscoveryError,match="source import IAT entries"):
        discovery.discover_functions(_parsed(f,entries,split),exports=())


@pytest.mark.parametrize("kind",["pdata","iat"])
@pytest.mark.parametrize("split",[False,True])
@pytest.mark.parametrize("entries",[
    (), (0x3000,), (0x3000,0x3008), (0x3008,0x3000),
    (0x3000,0x3009), (0x3000,0xfffffff8), (1,0x3000),
])
def test_valid_inventory_keeps_exact_previous_tail_admission(kind,split,entries):
    f=_fixture(kind);f["imports"]=entries
    report=discovery.discover_functions(_parsed(f,entries,split),exports=())
    caller=next(c for c in report.candidates if c.rva==0x1000)
    expected=kind=="pdata" or 0x3000 in entries
    assert caller.liftable is expected
    assert caller.indirect_target_closure_proven is False
    assert caller.direct_reference_gate_passed is False
    if expected:
        assert [v.name for v in _compile(f).functions]==["caller"]
    else:
        with pytest.raises(plan.FunctionRejected,match="call target outside"):
            _compile(f)


@pytest.mark.parametrize("imports",[
    None, 42, (object(),), (SimpleNamespace(funcs=None),),
    (SimpleNamespace(funcs=42),), (SimpleNamespace(funcs=(object(),)),),
])
def test_malformed_import_records_have_typed_discovery_diagnostics(imports):
    f=_fixture("pdata");parsed=_parsed(f,())
    parsed.imports=imports
    with pytest.raises(discovery.FunctionDiscoveryError,match="source import IAT inventory"):
        discovery.discover_functions(parsed,exports=())


@pytest.mark.parametrize("kind",["pdata","iat"])
def test_absent_optional_import_inventory_preserves_previous_behavior(kind):
    f=_fixture(kind);f["imports"]=()
    parsed=_parsed(f,());del parsed.imports
    report=discovery.discover_functions(parsed,exports=())
    caller=next(c for c in report.candidates if c.rva==0x1000)
    assert caller.liftable is (kind=="pdata")


@pytest.mark.parametrize("delta",[0,4,7])
def test_parser_extracted_cross_descriptor_alias_is_rejected_by_both_paths(delta):
    from packer import pe_analyze
    f=_fixture("iat")
    def descriptor(base,name):
        entry=SimpleNamespace(is_ordinal=False,name="NativeCall")
        return SimpleNamespace(name=name,import_address_table_rva=base,entries=[entry])
    binary=SimpleNamespace(imports=[descriptor(f["slot"],"one.dll"),
                                    descriptor(f["slot"]+delta,"two.dll")])
    imports=pe_analyze._extract_imports(binary,0x140000000)
    entries=tuple(function.iat_rva for dll in imports for function in dll.funcs)
    assert entries==(f["slot"],f["slot"]+delta)
    f["imports"]=entries
    parsed=_parsed(f,());parsed.imports=imports
    with pytest.raises(plan.VirtualizationPlanError,match="source import IAT entries overlap"):
        _compile(f)
    with pytest.raises(discovery.FunctionDiscoveryError,match="source import IAT entries overlap"):
        discovery.discover_functions(parsed,exports=())
