#!/usr/bin/env python3
"""
Differential harness for history-keyed self-decrypting Venice bytecode
(venice/venice_rolling.py) + the reference interpreter (venice/venice_ref.py).

This is the SP5 gate for the rolling-bytecode technique. It proves, before any
C ships:

  1. CODEC ROUND-TRIP -- for every real .vasm crypto program and many random
     per-build seeds, decode(encrypt(code)) == code, byte-for-byte. So the
     runtime, walking the true path, always reconstructs the exact plaintext.

  2. INTERPRETER EQUIVALENCE -- for synthetic programs over the pure ISA subset
     (arithmetic, branches, call/ret, locals), running the reference VM on the
     plaintext and on the rolling ciphertext yields the IDENTICAL halt value and
     the IDENTICAL dispatch trace. So virtualization semantics are unchanged.

  3. SELF-POISONING -- (a) a decoder that assumes a mid-block offset is a block
     start (wrong accumulator) reconstructs the wrong instruction; (b) flipping
     one ciphertext byte corrupts not just that instruction but the rest of its
     block (accumulator avalanche); (c) the wrong per-build seed decodes garbage.

Run: python -m pytest tests/test_rolling_bytecode.py -q
 or: python tests/test_rolling_bytecode.py
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
import venice_ref            # noqa: E402
import venice_rolling as vr  # noqa: E402
from venice_ref import RefVM, run_plaintext, compute_leaders, iter_instructions  # noqa: E402

PROGRAMS_DIR = PKG / "venice" / "programs"


def _seed(i: int) -> bytes:
    return hashlib.sha256(b"seed" + struct.pack("<I", i)).digest()[: vr.SEED_LEN]


def _split(blob):
    ds = struct.unpack_from("<H", blob, 0)[0]
    return blob[2 : 2 + ds], blob[2 + ds :]


# ---------------------------------------------------------------------------
# 1. Codec round-trip on the real crypto programs
# ---------------------------------------------------------------------------
def _real_program_blobs():
    out = {}
    for vasm in sorted(PROGRAMS_DIR.glob("*.vasm")):
        out[vasm.name] = venice_asm.assemble(vasm.read_text(encoding="utf-8"))
    return out


def test_real_programs_present():
    blobs = _real_program_blobs()
    assert len(blobs) >= 8, f"expected the real .vasm corpus, found {len(blobs)}"


def test_codec_roundtrip_real_programs():
    """decode(encrypt(code)) == code for every real program and 16 seeds."""
    blobs = _real_program_blobs()
    assert blobs
    for name, blob in blobs.items():
        data, code = _split(blob)
        for s in range(16):
            seed = _seed(s)
            rolling = vr.pack_rolling_blob(blob, seed)
            r_seed, r_data, r_ct, leaders = vr.unpack_rolling_blob(rolling)
            assert r_seed == seed and r_data == data, name
            recovered = vr.decode_stream(r_ct, r_seed, leaders)
            assert recovered == code, f"{name}: round-trip mismatch @seed {s}"


def test_ciphertext_actually_differs():
    """The stored code must not equal the plaintext (it is really encrypted),
    and two seeds must produce different ciphertext (per-build uniqueness)."""
    blobs = _real_program_blobs()
    for name, blob in blobs.items():
        _data, code = _split(blob)
        ct0, _ = vr.encrypt_code(code, _seed(0))
        ct1, _ = vr.encrypt_code(code, _seed(1))
        # allow tiny programs a pass, but every real program here is >1 instr
        if len(code) >= 4:
            assert ct0 != code, f"{name}: ciphertext == plaintext"
            assert ct0 != ct1, f"{name}: two seeds gave identical ciphertext"


# ---------------------------------------------------------------------------
# 2. Interpreter equivalence on synthetic pure-subset programs
# ---------------------------------------------------------------------------
# Each entry: (name, vasm source, args, expected_halt)
SYNTH = [
    (
        "arith",
        """
        .code
          push_imm32 0x11111111
          push_imm32 0x22222222
          xor
          push_imm8 7
          add
          halt
        """,
        [],
        (0x11111111 ^ 0x22222222) + 7,
    ),
    (
        "forward_branch_taken",
        """
        .code
          push_imm8 0
          jz  is_zero
          push_imm8 99
          halt
        is_zero:
          push_imm8 7
          halt
        """,
        [],
        7,
    ),
    (
        "forward_branch_untaken",
        """
        .code
          push_imm8 1
          jz  is_zero
          push_imm8 42
          halt
        is_zero:
          push_imm8 7
          halt
        """,
        [],
        42,
    ),
    (
        "loop_countdown",
        """
        .code
          push_arg 0        ; n
        loop:
          dup
          jz done
          push_imm8 1
          sub
          jmp loop
        done:
          halt              ; halts with 0
        """,
        [5],
        0,
    ),
    (
        "call_ret",
        """
        .code
          push_imm8 10
          call dbl
          halt
        dbl:
          dup
          add
          ret
        """,
        [],
        20,
    ),
    (
        "locals_store_load",
        """
        .code
          local_addr 0
          push_imm32 0xDEADBEEF
          store32
          local_addr 0
          load32
          halt
        """,
        [],
        0xDEADBEEF,
    ),
    (
        "pick_rot3",
        """
        .code
          push_imm8 1
          push_imm8 2
          push_imm8 3
          rot3          ; [1 2 3]->[3 1 2] top=2
          pick 2        ; copy stack[sp-3]=3 -> top
          halt
        """,
        [],
        3,
    ),
]


def _run_rolling(blob, args, seed):
    data, code = _split(blob)
    ct, leaders = vr.encrypt_code(code, seed)
    dec = vr.RollingDecoder(ct, seed, leaders)
    vm = RefVM(code, data, args, decoder=dec)
    val = vm.run()
    return val, vm.trace


def test_interpreter_equivalence_synthetic():
    for name, src, args, expected in SYNTH:
        blob = venice_asm.assemble(src)
        plain_val, plain_trace = run_plaintext(blob, args)
        assert plain_val == expected, f"{name}: plaintext got {plain_val}, want {expected}"
        for s in range(8):
            roll_val, roll_trace = _run_rolling(blob, args, _seed(s))
            assert roll_val == plain_val, f"{name}: rolling halt {roll_val} != {plain_val} @seed {s}"
            assert roll_trace == plain_trace, f"{name}: trace diverged @seed {s}"


# ---------------------------------------------------------------------------
# 3. Self-poisoning properties
# ---------------------------------------------------------------------------
def _first_nonleader_offset(code):
    leaders = set(compute_leaders(code))
    for off, _m, _w, _k, _o in iter_instructions(code):
        if off not in leaders:
            return off
    return None


def test_midblock_decode_is_wrong():
    """An analyst who resyncs at a mid-block offset (assuming it is a block
    start) reconstructs the wrong instruction bytes -- the true accumulator is a
    folded value, not resync(seed, off)."""
    blobs = _real_program_blobs()
    checked = 0
    for name, blob in blobs.items():
        _data, code = _split(blob)
        off = _first_nonleader_offset(code)
        if off is None:
            continue
        seed = _seed(3)
        ct, leaders = vr.encrypt_code(code, seed)
        # true plaintext of the instruction at `off`
        for o, _m, w, _k, _o in iter_instructions(code):
            if o == off:
                width = w
                break
        true_plain = code[off : off + 1 + width]
        # attacker assumes `off` is a block leader -> wrong accumulator. The
        # poison succeeds either by reconstructing different bytes OR by
        # decoding an invalid opcode/width (a decode fault) -- both mean the
        # attacker did not recover the real instruction.
        attacker = vr.RollingDecoder(ct, seed, leaders={off})
        try:
            _m, _w, _k, _o, wrong_plain = attacker.fetch(off)
            assert wrong_plain != true_plain, f"{name}: mid-block decode matched at 0x{off:04X}"
        except venice_ref.VeniceError:
            pass  # garbage opcode under the wrong accumulator is a stronger poison
        checked += 1
    assert checked >= 3, "expected several multi-instruction blocks to test"


def test_byte_flip_avalanches_within_block():
    """Flipping one ciphertext byte corrupts the rest of its basic block: the
    wrong plaintext folds into the accumulator, desyncing every later
    instruction in the block."""
    # a single straight-line block of several instructions
    src = """
    .code
      push_imm32 0x01020304
      push_imm32 0x05060708
      add
      push_imm8 9
      xor
      halt
    """
    blob = venice_asm.assemble(src)
    _data, code = _split(blob)
    seed = _seed(5)
    ct, leaders = vr.encrypt_code(code, seed)
    assert leaders == [0], "expected a single block"
    offs = venice_ref.instruction_offsets(code)
    # flip the opcode byte of the 2nd instruction
    flip_at = offs[1]
    tampered = bytearray(ct)
    tampered[flip_at] ^= 0x01
    dec = vr.RollingDecoder(bytes(tampered), seed, leaders)
    # decode the whole stream; a later instruction must diverge from plaintext
    diverged_after = False
    pc = 0
    while pc < len(tampered):
        try:
            _m, width, _k, _o, plain = dec.fetch(pc)
        except venice_ref.VeniceError:
            diverged_after = True  # a corrupt opcode/width is itself divergence
            break
        true_plain = code[pc : pc + 1 + width]
        if pc > flip_at and plain != true_plain:
            diverged_after = True
            break
        pc += 1 + width
    assert diverged_after, "byte flip did not avalanche into the rest of the block"


def test_wrong_seed_decodes_garbage():
    """The per-build seed is load-bearing: decoding with the wrong seed does not
    reproduce the program."""
    blob = venice_asm.assemble(SYNTH[0][1])
    _data, code = _split(blob)
    ct, leaders = vr.encrypt_code(code, _seed(0))
    recovered_right = vr.decode_stream(ct, _seed(0), leaders)
    assert recovered_right == code
    # wrong seed: either a structural fault or a different byte stream
    try:
        recovered_wrong = vr.decode_stream(ct, _seed(1), leaders)
        assert recovered_wrong != code, "wrong seed reproduced the program"
    except venice_ref.VeniceError:
        pass  # bad opcode / truncation under the wrong seed is a valid outcome


# ---------------------------------------------------------------------------
# 4. Primitive determinism (bit-exactness anchor for the future C mirror)
# ---------------------------------------------------------------------------
def test_primitive_vectors_stable():
    """Pin the primitives so the C port has fixed vectors to match."""
    seed = bytes(range(16))
    assert vr.resync(seed, 0) == int.from_bytes(
        hashlib.sha256(seed + b"R" + b"\x00\x00\x00\x00").digest()[:8], "little"
    )
    assert vr.rotl64(1, 1) == 2
    assert vr.rotl64(1 << 63, 1) == 1
    # fold is order-sensitive and pc-sensitive
    assert vr.fold(0, b"\x01\x02", 0) != vr.fold(0, b"\x02\x01", 0)
    assert vr.fold(0, b"\x01", 0) != vr.fold(0, b"\x01", 1)


def _main():
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
            passed += 1
        except Exception:
            print(f"  FAIL  {fn.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_main())
