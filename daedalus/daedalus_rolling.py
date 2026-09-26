#!/usr/bin/env python3
"""
daedalus_rolling.py -- History-keyed self-decrypting bytecode for the Daedalus VM.

THE IDEA
--------
At rest the Daedalus bytecode is ciphertext. There is no decodable program image:
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
from daedalus_disasm import OPCODE_TABLE  # noqa: E402
from daedalus_ref import (  # noqa: E402
    compute_leaders, iter_instructions, DaedalusError, MAX_INSTR_LEN,
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
    The seed is self-contained so daedalus_vm_exec needs no cross-TU global.
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
# Decoder (runtime side; mirrors the intended daedalus_vm.c fetch path)
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
            raise DaedalusError("fetch past end")
        if pc in self.leaders:
            self.acc = resync(self.seed, pc)
        ks = keystream(self.seed, pc, self.acc)
        opc = self.ct[pc] ^ ks[0]
        if opc not in self.optable:
            raise DaedalusError(f"rolling: bad opcode 0x{opc:02X} at 0x{pc:04X}")
        mnemonic, width, kind = self.optable[opc]
        ilen = 1 + width
        if pc + ilen > len(self.ct):
            raise DaedalusError("rolling: truncated instruction")
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


# ==========================================================================
# ROLLING v2 -- whole-program integrity chaining ('VS' container)
# ==========================================================================
# v1 reseeds each basic block from (seed, leader) alone, so a single ciphertext
# byte flip only corrupts decode inside that one block. v2 threads a *chain*
# value through the blocks, in static offset order, computed over the CIPHERTEXT
# (never the plaintext) of every preceding block. That chain feeds the per-block
# reseed (resync2), so flipping one ciphertext byte in block j changes the chain
# handed to block j+1, j+2, ... -- every later block reseeds wrong and decodes
# garbage. The whole remaining program avalanches, not just one block.
#
# Because the chain is a function of the ciphertext blocks in *static offset
# order* (not the runtime path), the runtime precomputes the whole chain array
# at init from the ciphertext + the baked leaders -- without decoding anything --
# and looks up chain[i] whenever it (re-)enters leader i by any path. So v2 keeps
# v1's path-independence and zero-build-time-path-analysis correctness guarantee.
#
# An optional 16-byte `whiten` XORs the seed into an *effective seed* used by the
# keystream and resync2 (extra per-build domain separation); the shipped stub
# uses a zero whiten (dvm_prepare synthesizes it), so container bytes stay
# self-contained. A wrong whiten mis-keys the very first block and faults.
#
# PRIMITIVES (bit-exactly mirrored in stub/src/daedalus_rolling.c under
# DVM_ROLLING_V2):
#   effective_seed(seed, whiten) = seed XOR whiten           (byte-wise, 16B)
#   chain_digest(seed, prev, ct_block) =
#       u64le( SHA256(seed16 ‖ 'C' ‖ u64le(prev) ‖ ct_block)[0:8] )
#   resync2(eff_seed, leader, chain) =
#       u64le( SHA256(eff16 ‖ 'R' ‖ u32le(leader) ‖ u64le(chain))[0:8] )
#   keystream / fold : IDENTICAL to v1 (reused verbatim, on the effective seed).
ROLLING_MAGIC_V2 = b'VS'
ZERO_WHITEN = b'\x00' * SEED_LEN


def _norm_whiten(whiten) -> bytes:
    """Normalize a whiten argument to a 16-byte value. `0`/None -> zero whiten;
    otherwise a 16-byte value (bytes/bytearray, or a hex string)."""
    if whiten is None or (isinstance(whiten, int) and whiten == 0):
        return ZERO_WHITEN
    if isinstance(whiten, int):
        raise ValueError("whiten int must be 0; pass 16 bytes (or hex) otherwise")
    if isinstance(whiten, str):
        whiten = bytes.fromhex(whiten)
    w = bytes(whiten)
    if len(w) != SEED_LEN:
        raise ValueError(f"whiten must be {SEED_LEN} bytes")
    return w


def effective_seed(seed: bytes, whiten=0) -> bytes:
    """Per-build effective seed = seed XOR whiten (byte-wise). With the default
    zero whiten this is `seed` unchanged."""
    if len(seed) != SEED_LEN:
        raise ValueError(f"seed must be {SEED_LEN} bytes")
    w = _norm_whiten(whiten)
    return bytes(s ^ x for s, x in zip(seed, w))


def chain_digest(seed: bytes, prev_chain: int, ct_block: bytes) -> int:
    """Fold one ciphertext block into the running chain. Domain tag 'C'. Never
    references plaintext -- the runtime can precompute the whole chain from the
    stored ciphertext alone, so decode stays path-independent.

    Construction (freestanding-mirrorable: one fixed-size SHA, no unbounded
    buffer): byte-loop-fold the block into a 64-bit accumulator seeded with
    prev_chain (same rotl/golden mixing as fold()), then bind it with a single
      u64le( SHA256(seed16 ‖ 'C' ‖ u64le(prev_chain) ‖ u64le(fold_acc))[0:8] ).
    A one-byte change anywhere in ct_block perturbs fold_acc deterministically,
    so the digest -- and every later chain value -- changes."""
    acc = prev_chain & MASK64
    for x in ct_block:
        acc = rotl64(acc ^ x, 7)
        acc = (acc + GOLDEN) & MASK64
    h = hashlib.sha256(
        seed + b'C' + struct.pack('<Q', prev_chain & MASK64)
        + struct.pack('<Q', acc)
    ).digest()
    return int.from_bytes(h[:8], 'little')


def resync2(seed: bytes, leader: int, chain: int) -> int:
    """v2 block reseed: like v1 resync but also folds the whole-program chain.
    `seed` here is the EFFECTIVE seed (seed XOR whiten)."""
    h = hashlib.sha256(
        seed + b'R' + struct.pack('<I', leader & 0xFFFFFFFF)
        + struct.pack('<Q', chain & MASK64)
    ).digest()
    return int.from_bytes(h[:8], 'little')


def compute_chain(seed: bytes, code_ct: bytes, leaders) -> list[int]:
    """Return chain[i] for every block i (one per sorted leader).

      chain[0] = 0
      chain[i] = chain_digest(seed, chain[i-1], ct_block[i-1])

    ct_block[j] is the ciphertext span [leaders[j], leaders[j+1]) (the last block
    runs to the end of the code). References only ciphertext -- this is exactly
    what the runtime recomputes at init, and it is a static (path-independent)
    function of the stored blob.
    """
    ls = sorted(leaders)
    n = len(ls)
    chain = [0] * n
    acc = 0
    for i in range(n):
        chain[i] = acc
        start = ls[i]
        end = ls[i + 1] if i + 1 < n else len(code_ct)
        acc = chain_digest(seed, acc, code_ct[start:end])
    return chain


# --------------------------------------------------------------------------
# v2 Encoder
# --------------------------------------------------------------------------
def encrypt_code_v2(code: bytes, seed: bytes, whiten=0, optable=None):
    """Return (ciphertext_code, sorted_leaders) for the v2 chained codec.

    Walks the plaintext in offset order. At each basic-block leader it folds the
    just-finished previous block's *ciphertext* into the running chain, then
    reseeds the accumulator with resync2(eff_seed, leader, chain). Instruction
    bytes are XORed with keystream(eff_seed, pc, acc) and the plaintext is folded
    into the accumulator exactly as in v1 -- so within a block v2 == v1 behavior,
    and across blocks the chain couples every block to all preceding ciphertext.

    Processing in offset order is sound: block i's ciphertext depends only on the
    chain over blocks < i (already finalized) plus block i's own plaintext.
    """
    if len(seed) != SEED_LEN:
        raise ValueError(f"seed must be {SEED_LEN} bytes")
    eff = effective_seed(seed, whiten)
    leaders = compute_leaders(code, optable)
    leaderset = set(leaders)
    out = bytearray(code)
    acc = 0
    chain_acc = 0
    prev_block_start = None
    for off, _m, width, _k, _o in iter_instructions(code, optable):
        if off in leaderset:
            if prev_block_start is not None:
                chain_acc = chain_digest(
                    seed, chain_acc, bytes(out[prev_block_start:off]))
            prev_block_start = off
            acc = resync2(eff, off, chain_acc)
        ilen = 1 + width
        plain = bytes(code[off:off + ilen])
        ks = keystream(eff, off, acc)
        out[off:off + ilen] = bytes(p ^ ks[i] for i, p in enumerate(plain))
        acc = fold(acc, plain, off)
    return bytes(out), leaders


def pack_rolling_blob_v2(plain_blob: bytes, seed: bytes, whiten=0,
                         optable=None) -> bytes:
    """Convert a plaintext [u16 ds][data][code] blob into a v2 rolling container.

    Container: [2 'VS'][16 seed][u16 data_size][data][u16 n_leaders]
               [u32 leader…][code_ct]
    Layout matches the v1 'VR' container byte-for-byte except the magic, so
    dvm_prepare reuses the same structural bounds checks. The whiten is NOT
    serialized: the shipped stub decodes with a zero whiten (dvm_prepare
    synthesizes it), so real containers are packed with whiten == 0.
    """
    if len(seed) != SEED_LEN:
        raise ValueError(f"seed must be {SEED_LEN} bytes")
    ds = struct.unpack_from('<H', plain_blob, 0)[0]
    data = plain_blob[2:2 + ds]
    code = plain_blob[2 + ds:]
    ct, leaders = encrypt_code_v2(code, seed, whiten, optable)
    out = bytearray()
    out += ROLLING_MAGIC_V2
    out += seed
    out += struct.pack('<H', ds)
    out += data
    out += struct.pack('<H', len(leaders))
    for L in leaders:
        out += struct.pack('<I', L)
    out += ct
    return bytes(out)


def unpack_rolling_blob_v2(blob: bytes):
    """Return (seed, data, ciphertext_code, leaders) from a v2 'VS' container."""
    if blob[:2] != ROLLING_MAGIC_V2:
        raise ValueError("not a v2 rolling blob")
    off = 2
    seed = blob[off:off + SEED_LEN]; off += SEED_LEN
    ds = struct.unpack_from('<H', blob, off)[0]; off += 2
    data = blob[off:off + ds]; off += ds
    n = struct.unpack_from('<H', blob, off)[0]; off += 2
    leaders = list(struct.unpack_from('<%dI' % n, blob, off)); off += 4 * n
    code_ct = blob[off:]
    return seed, data, code_ct, leaders


# --------------------------------------------------------------------------
# v2 Decoder (runtime side; mirrors daedalus_vm.c dvm_rolling_fetch_v2)
# --------------------------------------------------------------------------
class RollingDecoderV2:
    """Reconstructs one plaintext instruction at a time from a v2 ciphertext.

    At construction it precomputes the whole-program chain from the ciphertext +
    leaders (no decoding needed). At a leader it reseeds acc = resync2(eff_seed,
    pc, chain[leader_index]); otherwise it is v1's within-block chaining.
    """

    def __init__(self, code_ct: bytes, seed: bytes, leaders, whiten=0,
                 optable=None):
        self.ct = code_ct
        self.seed = seed
        self.eff = effective_seed(seed, whiten)
        self.leaders_sorted = sorted(leaders)
        self.leader_index = {L: i for i, L in enumerate(self.leaders_sorted)}
        self.optable = optable if optable is not None else OPCODE_TABLE
        self.chain = compute_chain(seed, code_ct, self.leaders_sorted)
        self.acc = 0

    def fetch(self, pc: int):
        if pc >= len(self.ct):
            raise DaedalusError("fetch past end")
        if pc in self.leader_index:
            self.acc = resync2(self.eff, pc, self.chain[self.leader_index[pc]])
        ks = keystream(self.eff, pc, self.acc)
        opc = self.ct[pc] ^ ks[0]
        if opc not in self.optable:
            raise DaedalusError(f"rolling v2: bad opcode 0x{opc:02X} at 0x{pc:04X}")
        mnemonic, width, kind = self.optable[opc]
        ilen = 1 + width
        if pc + ilen > len(self.ct):
            raise DaedalusError("rolling v2: truncated instruction")
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
        self.acc = fold(self.acc, plain, pc)
        return mnemonic, width, kind, operand, plain


def decode_stream_v2(code_ct: bytes, seed: bytes, leaders, whiten=0,
                     optable=None) -> bytes:
    """Decode a v2 rolling ciphertext back to the full plaintext code stream.
    decode_stream_v2(encrypt_code_v2(code, seed, whiten)[0], seed, leaders,
    whiten) must equal `code`."""
    dec = RollingDecoderV2(code_ct, seed, leaders, whiten, optable)
    out = bytearray()
    pc = 0
    while pc < len(code_ct):
        _m, width, _k, _o, plain = dec.fetch(pc)
        out += plain
        pc += 1 + width
    return bytes(out)
