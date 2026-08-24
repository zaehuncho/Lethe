#!/usr/bin/env python3
"""
venice_rolling.py -- History-keyed self-decrypting bytecode for the Venice VM.

THE IDEA
--------
At rest the Venice bytecode is ciphertext. There is no decodable program image:
each instruction's plaintext exists only for the instant the VM is about to
execute it, reconstructed from a keystream that folds the *execution history*
(the accumulator) of the basic block that reached it. Immediately behind the PC
the plaintext is gone. A static tool holding the blob cannot random-access-decode
any instruction (it lacks the block's live accumulator), and a windowed decoder
that starts mid-block, or a tracer that flips one byte, desynchronizes the
accumulator and decodes garbage from that point on.

v1 SCHEME -- per-basic-block resync (path-independent, provably correct)
------------------------------------------------------------------------
The accumulator is *reseeded* from (seed, block-leader-offset) at every basic
block leader, then chained over the plaintext bytes of the instructions inside
that block, in order. Because a block is straight-line (no internal control
flow) its runtime execution order equals its static offset order, so the
encoder -- walking the plaintext in offset order and resyncing at leaders --
computes the exact accumulator the runtime will hold at each instruction. And
because each block's encryption depends only on (seed, its leader offset, its
own plaintext bytes) and NOTHING about which control-flow path reached it, the
codec is correct for every reachable path with zero build-time path analysis
and zero risk of a data-dependent-branch miscompile. Loops work for free: a loop
header is a leader, so every iteration re-enters with the same reseeded
accumulator.

Cross-block accumulator chaining and an environment-fold (so observation itself
corrupts the next block) are deliberately deferred to a hardened v2 -- v1 is the
correct-and-strong floor the SP5 differential harness can prove today.

PRIMITIVES (bit-exactly mirrorable in the no-CRT stub via crypto_sha256)
------------------------------------------------------------------------
  resync(seed, leader) = u64le( SHA256(seed16 ‖ 'R' ‖ u32le(leader))[0:8] )
  keystream(seed, pc, acc) = SHA256(seed16 ‖ 'K' ‖ u32le(pc) ‖ u64le(acc))
  fold(acc, plain_bytes, pc):
      for x in plain_bytes: acc = rotl64(acc ^ x, 7) + 0x9E3779B97F4A7C15  (mod 2^64)
      acc ^= u32(pc)
SHA-256 is already in the stub (crypto_sha256); rotl64/add are one instruction
each. No new crypto primitive is introduced.

CONTAINER
---------
A rolling program is serialized as:
  [2 'VR' magic][u16 data_size][data][u16 n_leaders][u32 leader ...][code_ct]
so the stub can reseed at the right offsets without decoding (it cannot decode
without the leaders -- the leaders are the one plaintext index it needs).
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from venice_disasm import OPCODE_TABLE  # noqa: E402
from venice_ref import (  # noqa: E402
    compute_leaders, iter_instructions, VeniceError, MAX_INSTR_LEN,
)

MASK64 = (1 << 64) - 1
GOLDEN = 0x9E3779B97F4A7C15
ROLLING_MAGIC = b'VR'
SEED_LEN = 16


def rotl64(v: int, r: int) -> int:
    v &= MASK64
    r &= 63
    return ((v << r) | (v >> (64 - r))) & MASK64


def resync(seed: bytes, leader: int) -> int:
    h = hashlib.sha256(seed + b'R' + struct.pack('<I', leader & 0xFFFFFFFF)).digest()
    return int.from_bytes(h[:8], 'little')


def keystream(seed: bytes, pc: int, acc: int) -> bytes:
    return hashlib.sha256(
        seed + b'K' + struct.pack('<I', pc & 0xFFFFFFFF)
        + struct.pack('<Q', acc & MASK64)
    ).digest()  # 32 bytes; instructions are <= MAX_INSTR_LEN (9)


def fold(acc: int, plain_bytes: bytes, pc: int) -> int:
    acc &= MASK64
    for x in plain_bytes:
        acc = rotl64(acc ^ x, 7)
        acc = (acc + GOLDEN) & MASK64
    acc ^= (pc & 0xFFFFFFFF)
    return acc & MASK64


# --------------------------------------------------------------------------
# Encoder
# --------------------------------------------------------------------------
def encrypt_code(code: bytes, seed: bytes, optable=None):
    """Return (ciphertext_code, sorted_leaders).

    Walks the plaintext in offset order, reseeding the accumulator at each basic
    block leader and chaining it through the block. Each instruction's bytes are
    XORed with keystream(seed, pc, acc_before_this_instruction). `optable`
    selects the canonical or a shuffled decode table (the code being encrypted
    is the wire bytecode, so under opcode shuffling pass the shuffled table).
    """
    if len(seed) != SEED_LEN:
        raise ValueError(f"seed must be {SEED_LEN} bytes")
    leaders = compute_leaders(code, optable)
    leaderset = set(leaders)
    out = bytearray(code)
    acc = 0
    for off, _m, width, _k, _o in iter_instructions(code, optable):
        if off in leaderset:
            acc = resync(seed, off)
        ilen = 1 + width
        plain = bytes(code[off:off + ilen])
        ks = keystream(seed, off, acc)
        out[off:off + ilen] = bytes(p ^ ks[i] for i, p in enumerate(plain))
        acc = fold(acc, plain, off)
    return bytes(out), leaders


def pack_rolling_blob(plain_blob: bytes, seed: bytes, optable=None) -> bytes:
    """Convert a plaintext [u16 ds][data][code] blob into a rolling container.

    Container: [2 'VR'][16 seed][u16 data_size][data][u16 n_leaders]
               [u32 leader…][code_ct]
    The seed is self-contained so venice_vm_exec needs no cross-TU global.
    `optable` selects the decode table for the wire bytecode (shuffled builds).
    """
    if len(seed) != SEED_LEN:
        raise ValueError(f"seed must be {SEED_LEN} bytes")
    ds = struct.unpack_from('<H', plain_blob, 0)[0]
    data = plain_blob[2:2 + ds]
    code = plain_blob[2 + ds:]
    ct, leaders = encrypt_code(code, seed, optable)
    out = bytearray()
    out += ROLLING_MAGIC
    out += seed
    out += struct.pack('<H', ds)
    out += data
    out += struct.pack('<H', len(leaders))
    for L in leaders:
        out += struct.pack('<I', L)
    out += ct
    return bytes(out)


def unpack_rolling_blob(blob: bytes):
    """Return (seed, data, ciphertext_code, leaders) from a rolling container."""
    if blob[:2] != ROLLING_MAGIC:
        raise ValueError("not a rolling blob")
    off = 2
    seed = blob[off:off + SEED_LEN]; off += SEED_LEN
    ds = struct.unpack_from('<H', blob, off)[0]; off += 2
    data = blob[off:off + ds]; off += ds
    n = struct.unpack_from('<H', blob, off)[0]; off += 2
    leaders = list(struct.unpack_from('<%dI' % n, blob, off)); off += 4 * n
    code_ct = blob[off:]
    return seed, data, code_ct, leaders


# --------------------------------------------------------------------------
# Decoder (runtime side; mirrors the intended venice_vm.c fetch path)
# --------------------------------------------------------------------------
class RollingDecoder:
    """Reconstructs one plaintext instruction at a time from the ciphertext.

    Mirrors what the C fetch site does: at a leader, reseed the accumulator;
    generate keystream(seed, pc, acc); decrypt the opcode byte, look up its
    width, decrypt the operand bytes, decode the operand, then fold the
    plaintext into the accumulator so the next instruction in the block chains.
    """

    def __init__(self, code_ct: bytes, seed: bytes, leaders, optable=None):
        self.ct = code_ct
        self.seed = seed
        self.leaders = set(leaders)
        self.optable = optable if optable is not None else OPCODE_TABLE
        self.acc = 0

    def fetch(self, pc: int):
        if pc >= len(self.ct):
            raise VeniceError("fetch past end")
        if pc in self.leaders:
            self.acc = resync(self.seed, pc)
        ks = keystream(self.seed, pc, self.acc)
        opc = self.ct[pc] ^ ks[0]
        if opc not in self.optable:
            raise VeniceError(f"rolling: bad opcode 0x{opc:02X} at 0x{pc:04X}")
        mnemonic, width, kind = self.optable[opc]
        ilen = 1 + width
        if pc + ilen > len(self.ct):
            raise VeniceError("rolling: truncated instruction")
        plain = bytes(self.ct[pc + i] ^ ks[i] for i in range(ilen))
        operand = None
        if width == 1:
            operand = plain[1]
        elif width == 2:
            operand = struct.unpack_from('<H', plain, 1)[0]
        elif width == 4:
            operand = struct.unpack_from('<I', plain, 1)[0]
        elif width == 8:
            operand = struct.unpack_from('<Q', plain, 1)[0]
        # chain within the block
        self.acc = fold(self.acc, plain, pc)
        return mnemonic, width, kind, operand, plain


def decode_stream(code_ct: bytes, seed: bytes, leaders, optable=None) -> bytes:
    """Decode a rolling ciphertext back to the full plaintext code stream by
    walking every instruction boundary. Used by the codec round-trip test:
    decode_stream(encrypt_code(code)) must equal `code`.
    """
    dec = RollingDecoder(code_ct, seed, leaders, optable)
    out = bytearray()
    pc = 0
    while pc < len(code_ct):
        _m, width, _k, _o, plain = dec.fetch(pc)
        out += plain
        pc += 1 + width
    return bytes(out)
