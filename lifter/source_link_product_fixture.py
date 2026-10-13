"""Opt-in synthetic-key VM emitter for two exact product-shaped scalar helpers.

This module has no CLI or packer hook. Its output is a materialized test fixture,
not a production admission: final-link byte binding, whole-image references,
indirect/XFG target closure and a production key service are deliberately open.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path

import pefile

from daedalus import daedalus_asm
from packer.pe_analyze import analyze_pe
from . import source_link_build, win64_thunk, x64_lifter
from .source_link_product_admission import (
    ProductSourceInputs, ProductSourceProofError, _reject_reparse_components,
    inspect_source,
)


class ProductFixtureError(ValueError):
    """The exact synthetic product-helper fixture contract was not met."""


@dataclass(frozen=True)
class _Spec:
    abi: str
    body_sha256: str
    header_name: str
    header_sha256: str
    vm_symbol: str
    wrapper: str


# Deliberately not a generic decorated-symbol parser. Any source/body/header
# change needs an explicit review before another synthetic fixture is emitted.
_SPECS = {
    "?allowedRuntime@AutomationAccessPolicy@orion@@SA_N_N0000@Z": _Spec(
        abi="win64:bool(bool,bool,bool,bool,bool)",
        body_sha256="201f56d6b41a5dd7318da35558184fef0155918198512033571e3f88b86f4eb5",
        header_name="AutomationAccessPolicy.h",
        header_sha256="2735ec38f484f6547b05746e3ab23140e383fa2829f14ac9bd8093affe3aae0d",
        vm_symbol="policy_vm",
        wrapper='''/* SYNTHETIC FIXTURE ONLY: exact compiler-typed C++ entry. */
#include "AutomationAccessPolicy.h"
extern "C" bool __cdecl policy_vm(bool, bool, bool, bool, bool) noexcept;
namespace orion {
__declspec(noinline) bool AutomationAccessPolicy::allowedRuntime(
    bool authenticated, bool localDevBypass, bool securityLockActive,
    bool leaseGateEnabled, bool leaseFireAllowed) noexcept {
    return policy_vm(authenticated, localDevBypass, securityLockActive,
                     leaseGateEnabled, leaseFireAllowed);
}
}
''',
    ),
    "?leaseFireAllowedScalar@orion@@YA_N_N0_J1111@Z": _Spec(
        abi="win64:bool(bool,bool,i64,i64,i64,i64,i64)",
        body_sha256="1902ed4cf584facc3ee957482dd5c2449591202bb8a089725722a95d537b3947",
        header_name="LeaseFireAllowedScalar.h",
        header_sha256="d6505190d6bcbcdf4957d3f50da336679a5d05de79c0ebb5a93e4aab0389ed7a",
        vm_symbol="lease_vm",
        wrapper='''/* SYNTHETIC FIXTURE ONLY: exact compiler-typed C++ entry. */
#include "LeaseFireAllowedScalar.h"
extern "C" bool __cdecl lease_vm(bool, bool, std::int64_t, std::int64_t,
                                  std::int64_t, std::int64_t, std::int64_t) noexcept;
namespace orion {
__declspec(noinline) bool leaseFireAllowedScalar(
    bool enabled, bool leaseOk, std::int64_t lastRefreshMonotonicMs,
    std::int64_t maxStalenessMs, std::int64_t leaseValidUntilEpochS,
    std::int64_t nowMonotonicMs, std::int64_t nowEpochS) noexcept {
    return lease_vm(enabled, leaseOk, lastRefreshMonotonicMs,
                    maxStalenessMs, leaseValidUntilEpochS,
                    nowMonotonicMs, nowEpochS);
}
}
''',
    ),
}


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _header_bytes(path: Path, spec: _Spec) -> bytes:
    path = Path(path)
    if path.name != spec.header_name:
        raise ProductFixtureError("exact product helper header name required")
    try:
        _reject_reparse_components(path)
        data = path.read_bytes()
    except (ProductSourceProofError, OSError) as exc:
        raise ProductFixtureError("product helper header is missing or redirected") from exc
    if _sha(data) != spec.header_sha256:
        raise ProductFixtureError("product helper header differs from exact reviewed declaration")
    return data


def emit_product_fixture(
    inputs: ProductSourceInputs, source_header: Path, output_dir: Path, *,
    key_mode: str = "production", synthetic_fixture_key: bytes | None = None,
) -> dict[str, object]:
    """Emit only a source-proven, authenticated synthetic-key EXE/DLL fixture.

    The caller must compile the generated C++ wrapper against ``source_header``,
    omit the original helper COFF, and independently prove final PE linkage.
    This function does not perform or assert those final-link steps.
    """
    if key_mode != "synthetic_fixture":
        raise ProductFixtureError("production key provisioning is not configured")
    if type(synthetic_fixture_key) is not bytes or len(synthetic_fixture_key) != 32:
        raise ProductFixtureError("synthetic fixture key must be exactly 32 bytes")
    if type(inputs) is not ProductSourceInputs:
        raise ProductFixtureError("exact ProductSourceInputs required")
    spec = _SPECS.get(inputs.symbol)
    if spec is None or inputs.abi != spec.abi:
        raise ProductFixtureError("only the two exact reviewed helper symbols and ABIs are supported")
    header = _header_bytes(source_header, spec)
    output_dir = Path(output_dir)
    if output_dir.exists():
        _reject_reparse_components(output_dir)
        if not output_dir.is_dir() or any(output_dir.iterdir()):
            raise ProductFixtureError("output directory must be empty")
    else:
        if not output_dir.parent.is_dir():
            raise ProductFixtureError("output parent must be an existing ordinary directory")
        try:
            _reject_reparse_components(output_dir.parent)
        except ProductSourceProofError as exc:
            raise ProductFixtureError("output parent is redirected") from exc

    try:
        proof = inspect_source(inputs)
    except ProductSourceProofError as exc:
        raise ProductFixtureError(f"exact source proof failed: {exc}") from exc
    if (proof.get("source_body_sha256") != spec.body_sha256
            or proof.get("abi") != spec.abi
            or proof.get("symbol") != inputs.symbol
            or proof.get("source_body_and_abi_verified") is not True
            or any(proof.get(field) is not False for field in (
                "source_reference_closure_proven", "original_helper_object_omission_proven",
                "indirect_target_closure_proven", "xfg_enforcement_proven",
                "production_admitted",
            ))):
        raise ProductFixtureError("source proof differs from exact synthetic fixture contract")

    try:
        source_pe = Path(inputs.image).read_bytes()
        if _sha(source_pe) != proof["source_pe_sha256"]:
            raise ProductFixtureError("source PE changed after source proof")
        parsed = analyze_pe(str(inputs.image))
        if parsed.load_config is None or not parsed.load_config.xfg_present:
            raise ProductFixtureError("source PE lacks required XFG metadata")
        pe = pefile.PE(data=source_pe, fast_load=False)
        body = pe.get_data(proof["rva"], proof["size"])
        if len(body) != proof["size"] or _sha(body) != spec.body_sha256:
            raise ProductFixtureError("source helper body changed after source proof")
        depth = x64_lifter.validate_materialized_stack_window(
            body, base=proof["rva"], window_size=win64_thunk.STACK_WINDOW_SIZE)
        assembly = x64_lifter.lift_function(
            body, base=proof["rva"], selected_extents=((proof["rva"], len(body)),))
        bytecode = daedalus_asm.assemble(assembly)
        if _sha(bytecode) != proof["lifted_bytecode_sha256"]:
            raise ProductFixtureError("regenerated bytecode differs from exact source proof")
        source_root = Path(__file__).resolve().parents[1]
        runtime_hashes = source_link_build._source_tree_hashes(source_root, runtime=True)
        compiler_hashes = source_link_build._source_tree_hashes(source_root, runtime=False)
        opcode_sha = _sha(json.dumps(daedalus_asm.OPCODES, sort_keys=True,
                                     separators=(",", ":")).encode())
        program_id, envelope = source_link_build._fixture_envelope(
            proof["source_pe_sha256"], body, bytecode, inputs.abi,
            runtime_hashes["stub/src/daedalus_vm.c"], opcode_sha,
            synthetic_fixture_key,
        )
    except (source_link_build.SourceLinkError, x64_lifter.LiftUnsupported,
            SyntaxError, ValueError) as exc:
        if isinstance(exc, ProductFixtureError):
            raise
        raise ProductFixtureError(f"synthetic fixture generation failed: {exc}") from exc

    name = spec.vm_symbol
    emitted = {
        name + ".asm": win64_thunk.render_entry_thunk(
            name, name + "_descriptor").encode("ascii"),
        name + "_data.c": source_link_build._render_fixture_data(
            name, envelope, program_id, synthetic_fixture_key),
        name + "_wrapper.cpp": spec.wrapper.encode("ascii"),
    }
    manifest: dict[str, object] = {
        "schema": 1, "mode": "synthetic_fixture_only", "symbol": inputs.symbol,
        "abi": inputs.abi, "omit_source_object": Path(inputs.helper_object).name,
        "source_proof": proof, "source_header_name": spec.header_name,
        "source_header_sha256": _sha(header),
        "source_stack_depth": depth, "bytecode_sha256": _sha(bytecode),
        "bytecode_size": len(bytecode), "program_id": program_id.hex(),
        "envelope_sha256": _sha(envelope), "envelope_size": len(envelope),
        "descriptor_version": 4,
        "synthetic_key_sha256": _sha(synthetic_fixture_key),
        "runtime_source_sha256": runtime_hashes,
        "compiler_source_sha256": compiler_hashes,
        "opcode_mapping_sha256": opcode_sha,
        "thunk_template_sha256": _sha(win64_thunk.THUNK_TEMPLATE),
        "thunk_unwind_sha256": _sha(win64_thunk.THUNK_UNWIND_INFO),
        "emitted_sha256": {name: _sha(data) for name, data in sorted(emitted.items())},
        "include_runtime": list(source_link_build.RUNTIME_SOURCES[:8]),
        "required_flags": ["/guard:cf", "/guard:xfg", "/GUARD:CF",
                           "/GUARD:XFG", "/CETCOMPAT", "/DEBUG:FULL", "/MAP"],
        "production_key_service_configured": False,
        "source_reference_closure_proven": False,
        "original_helper_object_omission_proven": False,
        "indirect_target_closure_proven": False,
        "xfg_enforcement_proven": False,
        "final_link_byte_binding_proven": False,
        "production_admitted": False,
    }
    # The proof and all inputs are pinned again immediately before any output.
    for path, field in ((inputs.image, "source_pe_sha256"),
                        (inputs.pdb, "source_pdb_sha256"),
                        (inputs.link_map, "source_map_sha256"),
                        (inputs.helper_object, "source_coff_sha256")):
        if _sha(Path(path).read_bytes()) != proof[field]:
            raise ProductFixtureError("source proof input changed before fixture write")
    if _header_bytes(source_header, spec) != header:
        raise ProductFixtureError("product helper header changed before fixture write")
    if (source_link_build._source_tree_hashes(source_root, runtime=True) != runtime_hashes
            or source_link_build._source_tree_hashes(source_root, runtime=False) != compiler_hashes):
        raise ProductFixtureError("compiler or runtime source changed before fixture write")

    output_dir.mkdir(exist_ok=True)
    for filename, data in sorted(emitted.items()):
        (output_dir / filename).write_bytes(data)
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return manifest


__all__ = ["ProductFixtureError", "emit_product_fixture"]
