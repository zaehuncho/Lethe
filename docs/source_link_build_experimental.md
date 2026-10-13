# Experimental source-link VM lane

`lifter.source_link_build` is a fixture-only compiler boundary for one exported,
call-free Win64 scalar helper in its own COFF object. The sample final-build
recipe removes that object from declared inputs and defines the same symbol in
a generated MASM object; the verifier has not proved the complete actual linker
input set. This module does **not** yet prove complete final-link
input inventory or source-reference closure. Its production key mode fails
before emission. The post-link patcher and its indirect-target gate are not
relaxed.

## Input contract

- AMD64 PE32+ `/guard:cf`, `/GUARD:CF`, `/CETCOMPAT`, exact PDB and linker MAP.
- One direct export and one matching DIA function extent of multiplicity one;
  an unchained PDATA extent may match it, or a PDB-only leaf must have no
  overlapping PDATA. Exact-PDB executable coverage and direct-edge analysis
  must pass without a handwritten gap acknowledgement.
- DIA type metadata proves `win64:u64(u64,...)` with at most eight scalar `u64`
  arguments and `u64` return. This fixture ABI does not cover pointers, FP,
  structs, variadics, or C++ member functions.
- The helper object has one defined external symbol and one executable COFF
  section whose bytes exactly equal the PE/PDB function body. Other retained
  symbols, export aliases, DIR64 address escapes, recognized literal interior
  aliases, calls, branches, non-RSP data memory, and dynamic/ambiguous stack
  use are rejected. XFG is admitted only by the explicit narrow typed-XFG
  synthetic fixture contract; other unsupported load-config features reject.
- Runtime C/H/ASM and lifter/packer/Daedalus Python source trees, opcode
  mapping, PE/PDB, COFF/MAP, DIA tools, and emitted sources are SHA-256 pinned
  in schema 1. The compiler/linker executable identity and complete library
  member selection are not yet bound.

`emit_fixture(..., key_mode="synthetic_fixture", synthetic_fixture_key=<32
bytes>)` writes `<symbol>.asm`, `<symbol>_data.c`, a link recipe, and manifest.
The fixture key is embedded in C and is **not** a release key. The default
production path rejects before writing anything. It requires an authenticated
per-build key provider plus a secure runtime delivery contract before release.

The sample final-build recipe names the generated objects and listed runtime
C/MASM sources in place of the original helper object. `verify_final_bound`
requires the original synthetic key as a trusted explicit input. It re-lifts
source bytecode, re-derives and authenticates the final envelope, compares
canonical generated C/ASM bytes (including the embedded test key), rechecks
source trees, and checks the final PE/PDB/MAP, exact 46-byte thunk, unique PDB
thunk extent, Guard CF target, bridge call, descriptor v4, CET declaration,
PDATA/xdata and ASLR sites. The old body is absent from the final PE/PDB and
no original-helper public MAP row remains. MAP row absence alone does not prove
the object was not linked; `original_helper_object_omission_proven` is false.
Hardware CET and exceptional unwind paths are not exercised.

## Current integration boundary

The exact product-shaped policy and lease leaves are internal decorated C++
symbols, not exported C test helpers. They cannot use this API: it requires a
direct export, simple MASM-compatible symbol, and a `u64`-only ABI. Dedicated
translation units exist in a separate isolated product-source prototype, but
decorated-symbol handling, bool/signed-argument ABI, complete final-link COFF
relocation inventory, archive-member selection, and computed indirect target
closure remain unresolved. A successful strict pack-only synthetic fixture is
not a source-link release gate or product acceptance.

Earlier generated EXE/DLL runtime parity and strict pack-only acceptance used
CRT-built synthetic binaries before the XFG gate was added. Those images carry
XFG load-config fields and **now reject** under the current source/final
admission contract. They are historical experiment data, not current-positive
generator validation or a release candidate. The current fixture tests prove
typed fail-closed behavior; the narrow five-u64 typed-XFG source/final EXE and
host-loaded DLL fixtures now pass differential runtime checks. The linked
selected target still has CFG-only GFID metadata and no matching XFG tag, so
Windows XFG policy and hardware CET execution remain unproven. A valid no-XFG
`/guard:cf` source/final fixture has not yet been rebuilt and reverified.

The strict final report sets `source_bytecode_bound_to_current_inputs=true`
only after re-lifting the current source and matching the authenticated final
bytecode. It does not claim full source semantics or reference closure;
`source_reference_closure_proven=false` and `production_admitted=false` remain
explicit. The selected target's XFG status derives from its linked tag and
unique unsuppressed GFID row, not from a fixed fixture label. Even a matching
tag does not establish that the OS enforced XFG.

The next compiler contract would invoke and bind a trusted final link with an
exact object/archive-member inventory (MSVC `/LINKREPRO` can capture linker
inputs, but this module does not validate or replay it), check every AMD64
relocation/addend to the helper, and bind compiled runtime objects. Until then
`source_reference_closure_proven=false` and `production_admitted=false` are
deliberate verifier results. Authenticated per-build production key delivery,
hardware-enforced CET, exceptional unwind tests, and exact product EXE/DLL-host
acceptance also remain outside this fixture lane. No release manifest or
signing material is consumed by this module.
