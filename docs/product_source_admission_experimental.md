# Product-shaped source helper admission (read-only)

`lifter.source_link_product_admission.inspect_source` is an opt-in source
*inspection* primitive. It accepts an internal, exact decorated C++ symbol only
when the PE, RSDS-bound PDB, linker MAP and ordinary AMD64 COFF object agree on
one 512-byte-or-smaller leaf body. The exact decorated public symbol at the
selected PDB RVA must equal the COFF/MAP symbol, with no same-RVA alias; a
matching extent and type alone are insufficient. A separate DIA helper proves a `bool`
return and an ordered sequence of one to eight `bool` or signed 64-bit scalar
arguments. It rejects hidden object pointers, wrong types/order, stale or
ambiguous PDB ranges, aliasing, additional defined externals, and a COFF text
body that differs from the linked PE. The executable COFF section must have
no relocation records or relocation-overflow marker. Guard CF/XFG targets
anywhere in the helper span reject, including interior bytes. Every encoded instruction must belong to
an acyclic, closed conditional-branch graph whose paths terminate in `RET`;
calls, indirect control, non-RSP data memory, `LEA`, dynamic/unsafe stack use,
and unliftable instructions reject.

Input paths are checked component by component with `lstat` to reject observed
symlinks and Windows junction/reparse points before reads. This is a
best-effort precheck, not an atomic handle-based traversal: a concurrent path
replacement between check and open remains a TOCTOU limitation. The final
source proof hashes inputs before and after external helper queries; it is not
a security boundary against hostile concurrent filesystem mutation.

The function performs the existing exact PDB executable-coverage and direct
reference proof after the narrow helper checks. It never emits a wrapper,
bytecode file, key, protected binary, or release artifact. Its result always
sets `source_reference_closure_proven=false`,
`original_helper_object_omission_proven=false`,
`indirect_target_closure_proven=false`, `xfg_enforcement_proven=false`, and
`production_admitted=false`. A successful source proof does not relax the
existing `source_link_build.emit_fixture`/`verify_final` contract or the packer.

The two isolated product-shaped helpers used for evidence are not the shipped
package. The launcher policy helper uses five `bool` arguments; the security
core lease helper uses two `bool` then five signed `int64_t` arguments. Their
machine bodies have internal branches and multiple returns; the common lifter
already handles those exact bodies. This lane proves source identity and ABI,
not equivalent XFG enforcement, final-link object/archive relocation closure,
original-object omission, signed release, or runtime product acceptance.

To build the helper on Windows, compile `tools/source_link_typed_abi_dump.cpp`
with the pinned MSVC/DIA SDK and link `diaguids.lib`, `ole32.lib`, and
`oleaut32.lib`. Pass the compiled helper, the exact `msdia140.dll`, and the
existing PDB inventory helper in `ProductSourceInputs`; the inspection pins
their file hashes. No helper executable is checked into the repository.
