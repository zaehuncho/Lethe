#!/usr/bin/env python3
"""
gen_check_vm3.py -- ROUND 3: exponentially-harder virtualized check.

Round 2 shipped the check as PLAINTEXT bytecode with a trivial LCG XOR. Fable
dumped it, statically decoded all 281 bytes, recovered the 21-opcode ISA, and
reconstructed FNV in ~81 min. Round 3 removes the thing that made that possible:
there is NO statically-decodable bytecode.

Layers applied to the SAME proven check program (cipher/check_vm.vasm, verified
by gen_check_vm.py against the reference interpreter):

  1. PER-BUILD OPCODE SHUFFLE -- the 0..0x37 opcode bytes are permuted by a
     per-build seed, so the ISA must be re-derived every build (no transfer).
  2. HISTORY-KEYED ROLLING ENCRYPT -- each instruction is XORed with a keystream
     folded from (seed, block-leader, running accumulator over executed bytes).
     At rest the code is ciphertext; a static disassembler sees noise. The mini-
     VM reconstructs ONE instruction at a time as it executes -- so an analyst
     must TRACE the live decode, not dump-and-decode. This alone breaks Fable's
     round-2 method.
  3. The container ([2 'VR'][16 seed][u16 ds][data][u16 nlead][u32 leaders][ct])
     is then emitted XOR-veiled as before, but the veil is the least of it now.

Correctness is PROVEN in Python here (shuffle+roll round-trips to the wire code,
and running the decoded stream in the reference VM grants for the real password
and denies otherwise) BEFORE any C ships.
"""
from __future__ import annotations
import hashlib
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PKG = HERE.parent
sys.path.insert(0, str(PKG / "venice"))
import venice_asm            # noqa: E402
import venice_rolling as vr  # noqa: E402
from venice_ref import RefVM  # noqa: E402
from venice_disasm import OPCODE_TABLE  # noqa: E402

sys.path.insert(0, str(HERE))
import gen_check_vm as g     # noqa: E402  (reuse the proven builder + run_check)

BASIS, PRIME, MASK64 = g.BASIS, g.PRIME, g.MASK64
FLAG_OFF = g.FLAG_OFF


def make_shuffle(seed: bytes):
    """Per-build permutation of opcode bytes 0..0x37 (Fisher-Yates from seed).
    Returns (enc_map: canonical->wire, shuffled_optable: wire->(mnem,w,kind))."""
    ids = list(range(0x38))
    stream = bytearray(hashlib.sha256(b"check-shuffle|" + seed).digest())
    while len(stream) < len(ids):
        stream += hashlib.sha256(bytes(stream)).digest()
    perm = ids[:]
    for i in range(len(perm) - 1, 0, -1):
        r = stream[i] % (i + 1)
        perm[i], perm[r] = perm[r], perm[i]
    enc_map = {canon: perm[canon] for canon in ids}     # canonical byte -> wire byte
    # wire optable: wire_byte -> (mnemonic, width, kind) using canonical table
    shuffled_optable = {}
    for canon, (mnem, w, kind) in OPCODE_TABLE.items():
        if canon <= 0x37:
            shuffled_optable[enc_map[canon]] = (mnem, w, kind)
    return enc_map, shuffled_optable


def apply_shuffle_to_code(code: bytes, enc_map: dict, optable_canon=OPCODE_TABLE):
    """Rewrite each opcode byte to its wire value (operands unchanged). Uses the
    canonical table to walk instruction boundaries."""
    out = bytearray(code)
    pc = 0
    while pc < len(code):
        canon = code[pc]
        mnem, w, kind = optable_canon[canon]
        out[pc] = enc_map[canon]
        pc += 1 + w
    return bytes(out)


def build_round3(seed: bytes):
    # 1. the proven plaintext check program (canonical ISA)
    PASSWORD = b"REDACTED"
    FLAG = b"REDACTED"

    def fnv(s):
        h = BASIS
        for c in s:
            h = ((h ^ c) * PRIME) & MASK64
        return h

    def ksb(pw, i, H):
        return (pw[i % len(pw)] ^ ((i * 0x25 + 0x0D) & 0xFF) ^ ((H >> ((i & 7) * 8)) & 0xFF)) & 0xFF

    H = fnv(PASSWORD)
    ct = bytes(FLAG[i] ^ ksb(PASSWORD, i, H) for i in range(len(FLAG)))
    src = g.build_vasm(ct, H, len(FLAG))
    blob = venice_asm.assemble(src)          # [u16 ds][data][canonical code]
    ds = struct.unpack_from("<H", blob, 0)[0]
    data = blob[2:2 + ds]
    canon_code = blob[2 + ds:]

    # 2. per-build opcode shuffle -> wire code
    enc_map, wire_optable = make_shuffle(seed)
    wire_code = apply_shuffle_to_code(canon_code, enc_map)

    # 3. history-keyed rolling encrypt (decode boundaries via the WIRE optable)
    roll_seed = hashlib.sha256(b"check-roll|" + seed).digest()[:16]
    ct_code, leaders = vr.encrypt_code(wire_code, roll_seed, optable=wire_optable)

    # container: [2 'VR'][16 roll_seed][u16 ds][data][u16 nlead][u32 leaders][ct]
    cont = bytearray()
    cont += b"VR"
    cont += roll_seed
    cont += struct.pack("<H", ds)
    cont += data
    cont += struct.pack("<H", len(leaders))
    for L in leaders:
        cont += struct.pack("<I", L)
    cont += ct_code
    return bytes(cont), enc_map, wire_optable, roll_seed, (PASSWORD, FLAG, H, data, canon_code, wire_code)


def prove(seed: bytes):
    cont, enc_map, wire_optable, roll_seed, gold = build_round3(seed)
    PASSWORD, FLAG, H, data, canon_code, wire_code = gold

    # --- decode the container back to wire_code, then to canonical, then RUN ---
    assert cont[:2] == b"VR"
    off = 2
    rs = cont[off:off + 16]; off += 16
    ds = struct.unpack_from("<H", cont, off)[0]; off += 2
    d = cont[off:off + ds]; off += ds
    nlead = struct.unpack_from("<H", cont, off)[0]; off += 2
    leaders = list(struct.unpack_from("<%dI" % nlead, cont, off)); off += 4 * nlead
    ct_code = cont[off:]
    assert rs == roll_seed and d == data

    decoded_wire = vr.decode_stream(ct_code, rs, leaders, optable=wire_optable)
    assert decoded_wire == wire_code, "rolling round-trip (wire) mismatch"

    # unshuffle wire->canonical to run in the reference VM
    dec_map = {v: k for k, v in enc_map.items()}
    canon = bytearray(decoded_wire)
    pc = 0
    while pc < len(decoded_wire):
        wb = decoded_wire[pc]
        mnem, w, kind = wire_optable[wb]
        canon[pc] = dec_map[wb]
        pc += 1 + w
    assert bytes(canon) == canon_code, "unshuffle mismatch"

    # run the recovered canonical program in the reference interpreter
    plain_blob = struct.pack("<H", ds) + data + bytes(canon)
    rc_ok, flag_ok = g.run_check(plain_blob, PASSWORD, len(FLAG))
    rc_bad, _ = g.run_check(plain_blob, b"wrongpass", len(FLAG))
    return cont, (rc_ok == 0 and flag_ok == FLAG and rc_bad == 1), flag_ok


if __name__ == "__main__":
    seed = bytes.fromhex("a3f10b7c9d2e4f5061728394a5b6c7d8")
    cont, ok, flag = prove(seed)
    print(f"container = {len(cont)} bytes  (rolling+shuffle, no static bytecode)")
    print(f"proven: correct-pw grant+exact-flag+wrong-pw-deny  -> {'OK' if ok else '*** FAIL ***'}")
    if ok:
        print(f"  flag = {flag!r}")
        import struct as _s
        leaks = 0
        for name, pat in [("FNV basis", _s.pack("<Q", BASIS)),
                          ("FNV prime", _s.pack("<Q", PRIME)),
                          ("target H", _s.pack("<Q", 0xCCE6FCACC03B4421))]:
            if pat in cont:
                print(f"  LEAK: {name} present in container"); leaks += 1
        print(f"  static-constant leaks in container: {leaks} (want 0)")

        # Emit C header: the rolling container (XOR-veiled) + the per-build
        # shuffle UNMAP table (wire->canonical) the mini-VM needs at dispatch.
        _, enc_map, wire_optable, roll_seed, gold = build_round3(seed)
        _PASSWORD, FLAG, _H, _data, _cc, _wc = gold
        dec_map = {v: k for k, v in enc_map.items()}   # wire -> canonical
        unmap = [0] * 256
        for wire, canon in dec_map.items():
            unmap[wire] = canon
        # obfuscate the container with the same rolling XOR as round 2
        xseed = 0x5A
        k = xseed
        obf = bytearray()
        for b in cont:
            obf.append(b ^ k)
            k = (k * 33 + 7) & 0xFF
        def carr(bs):
            return ", ".join(f"0x{b:02X}" for b in bs)
        hdr = (
            "/* check_vm3_blob.h -- generated by gen_check_vm3.py.\n"
            " * ROUND 3: the check runs as history-keyed ROLLING bytecode with a\n"
            " * per-build shuffled ISA. No statically-decodable bytecode exists;\n"
            " * the mini-VM reconstructs one instruction at a time as it runs. */\n"
            "#pragma once\n"
            f"#define CV3_CONT_LEN {len(cont)}\n"
            f"#define CV3_XOR_SEED 0x{xseed:02X}\n"
            f"#define CV3_FLAG_OFF {FLAG_OFF}\n"
            f"#define CV3_FLAG_LEN {len(FLAG)}\n"
            f"static const unsigned char CV3_CONT_OBF[CV3_CONT_LEN] = {{ {carr(obf)} }};\n"
            f"static const unsigned char CV3_UNMAP[256] = {{ {carr(unmap)} }};\n"
        )
        (HERE / "check_vm3_blob.h").write_text(hdr, encoding="utf-8")
        print(f"  wrote check_vm3_blob.h ({len(cont)}-byte container, unmap table)")
    sys.exit(0 if ok else 1)
