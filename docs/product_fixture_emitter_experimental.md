# Exact product-helper synthetic fixture emitter (experimental)

`lifter.source_link_product_fixture.emit_product_fixture` is an opt-in Python
API, not a packer or command-line mode. It accepts only the reviewed decorated
policy and lease scalar helpers with exact bool/i64 ABIs, source bodies and
headers. It re-runs the read-only PE/PDB/MAP/COFF/DIA source proof, regenerates
the lifted bytecode, validates a bounded virtual stack and seals the bytecode
with an explicitly supplied 32-byte **synthetic test key**.

The emitted files are a compiler-typed C++ wrapper, internal MASM VM thunk,
synthetic-key data C file and manifest. The caller must omit the original
helper object, compile the wrapper against the pinned source header and
independently validate the resulting EXE/DLL and full link inputs. The manifest
sets `final_link_byte_binding_proven`, source-reference closure, indirect/XFG
target closure, production key service and `production_admitted` to `false`.
The emitter does not modify a product package, configure a production key,
sign a release, or integrate with Lethe's default CLI or packer.

The isolated materialized EXE/DLL acceptance harness tests the exact generated
policy wrapper over all 32 Boolean combinations and the lease wrapper over 20
defined-behavior boundary vectors. These fixture results do not prove product
workflow acceptance or general DLL/EXE support. A prior LINKREPRO replay of
the isolated prototype produced functional parity but not byte-identical PEs;
that failed final-link binding check remains open.
