# Experimental selected-symbol LINKREPRO reference proof

This opt-in inspector is a prerequisite, not a production packing gate. It binds
one exact source PE, PDB, MAP and conventional helper COFF through the existing
`inspect_source` contract. It then re-reads every explicit COFF input and every
member of every archive in an exact conventional `/LINKREPRO` capture. The
archive indexes, member offsets and captured paths are validated by the
non-admitting diagnostic reader. No member-extraction decision is assumed.

For the selected symbol, an executable relocation is accepted only when it is
zero-addend AMD64 REL32 to a reachable five-byte `CALL rel32` at a decoded
instruction boundary in a completely reachable section CFG. A reference from
non-executable data, a different relocation, an interior addend, a weak
alternative, a linker option or an alias-bearing `.drectve` is rejected. The
selected helper's own `.debug$S` SECREL/SECTION records are reported separately
as debug metadata; the inspector does not claim these are absent from every
final-link product effect. Other weak symbols and non-selected relocations are
counted, not promoted as global closure evidence.

`inspect_replacement_omission` compares separately captured replacement-link
material inputs. It requires the original helper COFF SHA-256 to be absent from
all top-level objects and archive members, a changed same-name selected-symbol
definition, and byte-identical non-helper inputs. This is only an exact material
input-omission result. It does not prove replacement output equivalence.

The observed conventional EXE/DLL captures classify 9/2 selected executable
calls, 14/18 helper debug relocations and 0 selected archive-member references.
A first isolated replacement replay without `/BREPRO` differed from its built
PE by 20 EXE bytes (PE/debug timestamps and RSDS GUID) and five DLL bytes
(PE/debug timestamps). The initial placeholder COFFs lacked CodeView function
records. Recompiling the same-symbol placeholders with `/Z7` produced unique
three-byte DIA extents; adding `/BREPRO` to copied responses and recapturing
then yielded byte-exact fresh replacement PE replays for both targets. The
built/replay PDB DIA ranges and MAP symbol rows agree, and the replacement
COFF body matches each PE helper entry. These are synthetic-stub link
prerequisites, not a source-equal-original PE expectation or a VM product
acceptance. Archive extraction, `/OPT:REF`/`/OPT:ICF` source-to-output
mapping, final-image direct and indirect target closure, XFG enforcement,
production key provision and production admission remain false. Any VM or
product packaging use needs separate full-link and runtime acceptance.

