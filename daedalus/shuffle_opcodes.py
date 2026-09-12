#!/usr/bin/env python3
"""
shuffle_opcodes.py -- Per-build opcode shuffling for Daedalus VM bytecode protection.

Generates a random permutation of the Daedalus VM opcode map so that each build
uses different opcode assignments.  An attacker's disassembler from build N is
useless on build N+1.

This is a BUILD-TIME tool.  It runs once per build and produces:
  1. A C header (#include'd by daedalus_vm.c) with:
     - DVM_SHUFFLED_* defines for each opcode's wire byte
     - DVM_OPCODE_UNMAP[256] reverse-lookup table  (wire -> canonical)
     - DVM_DECOY_CASES macro with decoy handler case statements
     - DVM_HANDLER_VARIANT_* selections for native semantic diversity
  2. A Python dict (imported by daedalus_asm.py) with:
     - SHUFFLED_OPCODES: mnemonic -> (wire_byte, operand_width, operand_kind)
     - DECOY_WIRE_BYTES: list of decoy instruction bytes for noise insertion
     - NOISE_RATIO: assembler noise insertion ratio
     - HANDLER_VARIANTS plus a stable provenance hash

The interpreter dispatches on OPCODE_UNMAP[wire_byte] so the switch cases stay
canonical.  The assembler maps mnemonic -> shuffled wire byte.

Usage:
    python shuffle_opcodes.py generate --c-header out.h --py-dict out.py
    python shuffle_opcodes.py generate --seed <hex> --c-header out.h --py-dict out.py
    python shuffle_opcodes.py verify
    python shuffle_opcodes.py verify --seed <hex>
"""

import argparse
import hashlib
import json
import random
import secrets
import sys
from collections import OrderedDict

# ---------------------------------------------------------------------------
# Canonical opcode table  (must match daedalus_vm.h / daedalus_asm.py exactly)
# name -> (canonical_byte, operand_width, operand_kind)
# ---------------------------------------------------------------------------
CANONICAL_OPCODES = OrderedDict([
    # -- stack manipulation --
    ('halt',           (0x00, 0, 'none')),
    ('nop',            (0x01, 0, 'none')),
    ('push_imm8',      (0x02, 1, 'imm')),
    ('push_imm32',     (0x03, 4, 'imm')),
    ('push_imm64',     (0x04, 8, 'imm')),
    ('pop',            (0x05, 0, 'none')),
    ('dup',            (0x06, 0, 'none')),
    ('swap',           (0x07, 0, 'none')),
    # -- arithmetic --
    ('add',            (0x08, 0, 'none')),
    ('sub',            (0x09, 0, 'none')),
    ('xor',            (0x0A, 0, 'none')),
    ('and',            (0x0B, 0, 'none')),
    ('or',             (0x0C, 0, 'none')),
    ('shl',            (0x0D, 0, 'none')),
    ('shr',            (0x0E, 0, 'none')),
    ('mul',            (0x0F, 0, 'none')),
    # -- memory --
    ('load8',          (0x10, 0, 'none')),
    ('load32',         (0x11, 0, 'none')),
    ('load64',         (0x12, 0, 'none')),
    ('store8',         (0x13, 0, 'none')),
    ('store32',        (0x14, 0, 'none')),
    ('store64',        (0x15, 0, 'none')),
    # -- comparison --
    ('cmp_eq',         (0x16, 0, 'none')),
    ('cmp_lt',         (0x17, 0, 'none')),
    # -- control flow --
    ('jmp',            (0x18, 4, 'label')),
    ('jz',             (0x19, 4, 'label')),
    ('jnz',            (0x1A, 4, 'label')),
    ('call',           (0x1B, 4, 'label')),
    # -- data access --
    ('push_arg',       (0x1C, 1, 'imm')),
    ('local_addr',     (0x1D, 2, 'imm')),
    ('data_addr',      (0x1E, 2, 'imm')),
    # -- return --
    ('ret',            (0x1F, 0, 'none')),
    # -- native ops --
    ('n_sha256',       (0x20, 0, 'none')),
    ('n_hkdf',         (0x21, 0, 'none')),
    ('n_xor_buf',      (0x22, 0, 'none')),
    ('n_getenv',       (0x23, 0, 'none')),
    ('n_setenv_null',  (0x24, 0, 'none')),
    ('n_hex_decode',   (0x25, 0, 'none')),
    ('n_zero_mem',     (0x26, 0, 'none')),
    ('n_scatter_init', (0x27, 0, 'none')),
    ('n_copy_mem',     (0x28, 0, 'none')),
    ('n_xor_repeat',   (0x29, 0, 'none')),
    ('n_xor_const',    (0x2A, 0, 'none')),
    ('n_call_ptr',     (0x2B, 0, 'none')),
    # -- v2 arithmetic --
    ('div',            (0x2C, 0, 'none')),
    ('mod',            (0x2D, 0, 'none')),
    ('neg',            (0x2E, 0, 'none')),
    ('not',            (0x2F, 0, 'none')),
    # -- v2 comparison --
    ('cmp_gt',         (0x30, 0, 'none')),
    ('cmp_ge',         (0x31, 0, 'none')),
    ('cmp_ne',         (0x32, 0, 'none')),
    # -- v2 data/stack --
    ('push_imm16',     (0x33, 2, 'imm')),
    ('load16',         (0x34, 0, 'none')),
    ('store16',        (0x35, 0, 'none')),
    ('rot3',           (0x36, 0, 'none')),
    ('pick',           (0x37, 1, 'imm')),
])

NUM_REAL = len(CANONICAL_OPCODES)       # 56
NUM_DECOYS = 17                         # ~30% of real count
DECOY_CANONICAL_BASE = 0x80             # canonical IDs 0x80..0x90
TRAP_CANONICAL = 0xFF                   # unmap value for trap slots

# Native handler-body diversification is independent from wire-byte shuffling.
# Each entry names a VM semantic whose C implementation has the given number of
# bit-exact, machine-code-distinct variants proven by
# ``tools/handler_shape_audit.py`` under the release MSVC optimizer.  Source
# formulas that collapse to the same native body count as one variant here. The
# selected profile is emitted into both generated artifacts and carries its own
# hash so build provenance can distinguish "same ISA mapping, different
# handlers" without overstating effective native diversity.
HANDLER_VARIANT_COUNTS = OrderedDict([
    ('add', 2),
    ('sub', 2),
    ('xor', 2),
    ('and', 2),
    ('or', 2),
    # ``~a + 1`` and ``0 - a`` both become the same x64 NEG instruction at
    # /O2, so only the canonical form is currently eligible for generation.
    ('neg', 1),
    ('cmp_eq', 2),
    ('cmp_ne', 2),
])

# ---------------------------------------------------------------------------
# Decoy handler templates -- semantically no-ops that look like real work.
# Each (name, c_body) pair becomes a case in the DVM_DECOY_CASES macro.
# All handlers advance pc by 1 and preserve VM state exactly.
# ---------------------------------------------------------------------------
DECOY_TEMPLATES = [
    ("stack_bounce",
     "if (vm->sp > 0 && vm->sp < DVM_STACK_SIZE) {\n"
     "    vm->stack[vm->sp] = 0;\n"
     "    vm->sp++;\n"
     "    vm->sp--;\n"
     "}"),

    ("xor_identity",
     "if (vm->sp > 0) vm->stack[vm->sp - 1] ^= 0;"),

    ("and_identity",
     "if (vm->sp > 0) vm->stack[vm->sp - 1] &= 0xFFFFFFFFFFFFFFFFULL;"),

    ("or_identity",
     "if (vm->sp > 0) vm->stack[vm->sp - 1] |= 0;"),

    ("add_zero",
     "if (vm->sp > 0) vm->stack[vm->sp - 1] += 0;"),

    ("sub_zero",
     "if (vm->sp > 0) vm->stack[vm->sp - 1] -= 0;"),

    ("shl_zero",
     "if (vm->sp > 0) vm->stack[vm->sp - 1] <<= 0;"),

    ("shr_zero",
     "if (vm->sp > 0) vm->stack[vm->sp - 1] >>= 0;"),

    ("double_not",
     "if (vm->sp > 0) {\n"
     "    vm->stack[vm->sp - 1] = ~vm->stack[vm->sp - 1];\n"
     "    vm->stack[vm->sp - 1] = ~vm->stack[vm->sp - 1];\n"
     "}"),

    ("double_neg",
     "if (vm->sp > 0) {\n"
     "    vm->stack[vm->sp - 1] = ~vm->stack[vm->sp - 1] + 1;\n"
     "    vm->stack[vm->sp - 1] = ~vm->stack[vm->sp - 1] + 1;\n"
     "}"),

    ("swap_swap",
     "if (vm->sp >= 2) {\n"
     "    uint64_t _t = vm->stack[vm->sp - 1];\n"
     "    vm->stack[vm->sp - 1] = vm->stack[vm->sp - 2];\n"
     "    vm->stack[vm->sp - 2] = _t;\n"
     "    _t = vm->stack[vm->sp - 1];\n"
     "    vm->stack[vm->sp - 1] = vm->stack[vm->sp - 2];\n"
     "    vm->stack[vm->sp - 2] = _t;\n"
     "}"),

    ("dup_pop",
     "if (vm->sp > 0 && vm->sp < DVM_STACK_SIZE) {\n"
     "    vm->stack[vm->sp] = vm->stack[vm->sp - 1];\n"
     "    vm->sp++;\n"
     "    vm->sp--;\n"
     "}"),

    ("push_noise",
     "if (vm->sp > 0 && vm->sp < DVM_STACK_SIZE) {\n"
     "    vm->stack[vm->sp] = 0x42;\n"
     "    vm->sp++;\n"
     "    vm->sp--;\n"
     "}"),

    ("add_sub_roundtrip",
     "if (vm->sp > 0) {\n"
     "    vm->stack[vm->sp - 1] += 1;\n"
     "    vm->stack[vm->sp - 1] -= 1;\n"
     "}"),

    ("xor_roundtrip",
     "if (vm->sp > 0) {\n"
     "    vm->stack[vm->sp - 1] ^= 0xA5A5A5A5A5A5A5A5ULL;\n"
     "    vm->stack[vm->sp - 1] ^= 0xA5A5A5A5A5A5A5A5ULL;\n"
     "}"),

    ("mul_one",
     "if (vm->sp > 0) vm->stack[vm->sp - 1] *= 1;"),

    ("touch_locals",
     "{\n"
     "    volatile uint8_t *_p = (volatile uint8_t *)&vm->locals[0];\n"
     "    uint8_t _t = *_p;\n"
     "    *_p = 0;\n"
     "    *_p = _t;\n"
     "}"),
]

assert len(DECOY_TEMPLATES) == NUM_DECOYS, \
    f"expected {NUM_DECOYS} decoy templates, got {len(DECOY_TEMPLATES)}"

# ---------------------------------------------------------------------------
# Shuffle generation
# ---------------------------------------------------------------------------

def opcode_mapping_sha256(real_map):
    """Stable hash shared with the planner's immutable OpcodeTable schema."""
    entries = sorted(
        [name, wire, CANONICAL_OPCODES[name][1], CANONICAL_OPCODES[name][2]]
        for name, wire in real_map.items()
    )
    encoded = json.dumps(
        entries, separators=(',', ':'), ensure_ascii=True
    ).encode('ascii')
    return hashlib.sha256(encoded).hexdigest()


def handler_variant_sha256(handler_variants):
    """Stable identity for the native handler implementation profile."""
    entries = sorted([name, int(variant)]
                     for name, variant in handler_variants.items())
    encoded = json.dumps(
        entries, separators=(',', ':'), ensure_ascii=True
    ).encode('ascii')
    return hashlib.sha256(encoded).hexdigest()

def generate_shuffle(seed_bytes=None):
    """Generate a shuffled opcode mapping.

    Args:
        seed_bytes: Optional bytes for reproducible output.
                    If None, generates a fresh 32-byte secret.

    Returns:
        dict containing the opcode permutation, reverse map, decoys, and the
        independently hashed native handler-variant profile.
    """
    if seed_bytes is None:
        seed_bytes = secrets.token_bytes(32)

    # Derive a deterministic integer seed via SHA-256 so the result is
    # reproducible across Python versions (avoids hash-randomization).
    seed_int = int.from_bytes(hashlib.sha256(seed_bytes).digest(), 'big')
    rng = random.Random(seed_int)

    # Shuffle the full 0x00..0xFF pool.
    pool = list(range(256))
    rng.shuffle(pool)

    # First NUM_REAL slots -> real opcodes (shuffled wire bytes).
    real_map = OrderedDict()
    for i, name in enumerate(CANONICAL_OPCODES):
        real_map[name] = pool[i]

    # Next NUM_DECOYS slots -> decoy opcodes.
    decoy_wire = [pool[NUM_REAL + i] for i in range(NUM_DECOYS)]

    # Remainder -> trap slots (halt -1 on execution).
    trap_wire = pool[NUM_REAL + NUM_DECOYS:]

    # Build the 256-entry reverse-lookup table.
    unmap = [TRAP_CANONICAL] * 256
    for name, wire in real_map.items():
        canonical = CANONICAL_OPCODES[name][0]
        unmap[wire] = canonical
    for i, wire in enumerate(decoy_wire):
        unmap[wire] = DECOY_CANONICAL_BASE + i

    handler_variants = OrderedDict(
        (name, rng.randrange(count))
        for name, count in HANDLER_VARIANT_COUNTS.items()
    )

    return {
        'seed_hex':   seed_bytes.hex(),
        'real_map':   real_map,
        'decoy_wire': decoy_wire,
        'trap_wire':  trap_wire,
        'unmap':      unmap,
        'mapping_sha256': opcode_mapping_sha256(real_map),
        'handler_variants': handler_variants,
        'handler_variant_sha256': handler_variant_sha256(handler_variants),
    }

# ---------------------------------------------------------------------------
# C header emitter
# ---------------------------------------------------------------------------

def _build_decoy_macro():
    """Build the DVM_DECOY_CASES macro body (case statements for decoys)."""
    all_lines = []
    for i, (name, body) in enumerate(DECOY_TEMPLATES):
        canonical = DECOY_CANONICAL_BASE + i
        all_lines.append(f"    case 0x{canonical:02X}: {{ /* {name} */")
        for bline in body.split('\n'):
            all_lines.append(f"        {bline}")
        all_lines.append("        vm->pc += 1;")
        all_lines.append("        break;")
        all_lines.append("    }")
    # Wrap in a #define with backslash-newline continuations.
    result = ["#define DVM_DECOY_CASES \\"]
    for i, line in enumerate(all_lines):
        if i < len(all_lines) - 1:
            result.append(f"{line} \\")
        else:
            result.append(line)
    return '\n'.join(result)


def emit_c_header(result):
    """Render the shuffled opcode map as a C header string."""
    seed_hex = result['seed_hex']
    real_map = result['real_map']
    unmap = result['unmap']

    lines = []
    lines.append("/*")
    lines.append(" * daedalus_opcodes_shuffled.h")
    lines.append(" * Auto-generated by shuffle_opcodes.py -- DO NOT EDIT")
    lines.append(f" * Build seed: {seed_hex}")
    lines.append(" *")
    lines.append(" * Integration:")
    lines.append(" *   #include \"daedalus_opcodes_shuffled.h\"")
    lines.append(" *   ...")
    lines.append(" *   uint8_t op = DVM_OPCODE_UNMAP[vm->code[vm->pc]];")
    lines.append(" *   switch (op) {")
    lines.append(" *       case DVM_HALT: ... // existing canonical cases")
    lines.append(" *       DVM_DECOY_CASES    // expands to decoy case handlers")
    lines.append(" *       default: return -1; // trap")
    lines.append(" *   }")
    lines.append(" */")
    lines.append("#pragma once")
    lines.append("")
    lines.append("#include <stdint.h>")
    lines.append("")
    lines.append(
        f'#define DVM_OPCODE_MAPPING_SHA256 "{result["mapping_sha256"]}"')
    lines.append(
        f'#define DVM_HANDLER_VARIANT_SHA256 "{result["handler_variant_sha256"]}"')
    lines.append("")

    lines.append(
        "/* ---- Native semantic handler variants --------------------------- */")
    lines.append(
        "/* Values select bit-exact C implementations; they do not change ABI. */")
    for name, variant in result['handler_variants'].items():
        lines.append(
            f"#define DVM_HANDLER_VARIANT_{name.upper():<6} {variant}")
    lines.append("")

    # --- Shuffled wire-byte defines ----------------------------------------
    lines.append(
        "/* ---- Shuffled opcode wire bytes ---------------------------------- */")
    lines.append(
        "/* Each real opcode's byte value in this build's bytecode encoding.   */")
    lines.append("")
    max_def = max(len(f"DVM_SHUFFLED_{n.upper()}") for n in real_map)
    for name, wire in real_map.items():
        dname = f"DVM_SHUFFLED_{name.upper()}"
        canonical = CANONICAL_OPCODES[name][0]
        lines.append(
            f"#define {dname:<{max_def}}  0x{wire:02X}"
            f"  /* canonical 0x{canonical:02X} */")
    lines.append("")

    # --- Decoy canonical-ID defines ----------------------------------------
    lines.append(
        "/* ---- Decoy opcode canonical IDs ---------------------------------- */")
    lines.append("")
    decoy_wire = result['decoy_wire']
    for i in range(NUM_DECOYS):
        name = DECOY_TEMPLATES[i][0]
        canonical = DECOY_CANONICAL_BASE + i
        wire = decoy_wire[i]
        lines.append(
            f"#define DVM_DECOY_{i:<2d}  0x{canonical:02X}"
            f"  /* wire 0x{wire:02X}, {name} */")
    lines.append("")

    # --- OPCODE_UNMAP[256] -------------------------------------------------
    lines.append(
        "/* ---- Opcode unmap table ------------------------------------------ */")
    lines.append(
        "/* Maps wire byte -> canonical byte for dispatch.                     */")
    lines.append(
        "/*   0x00..0x37 = real opcode  |  0x80..0x90 = decoy  |  0xFF = trap */")
    lines.append("")
    lines.append("static const uint8_t DVM_OPCODE_UNMAP[256] = {")
    for row in range(16):
        offset = row * 16
        vals = unmap[offset : offset + 16]
        hex_str = ', '.join(f"0x{v:02X}" for v in vals)
        lines.append(f"    /* 0x{offset:02X} */ {hex_str},")
    lines.append("};")
    lines.append("")

    # --- Decoy handler macro -----------------------------------------------
    lines.append(
        "/* ---- Decoy handler cases ----------------------------------------- */")
    lines.append(
        "/* Expand DVM_DECOY_CASES inside the switch(canonical_op) block.      */")
    lines.append(
        "/* All handlers are semantically no-ops that preserve VM state.       */")
    lines.append("")
    lines.append(_build_decoy_macro())
    lines.append("")

    return '\n'.join(lines) + '\n'

# ---------------------------------------------------------------------------
# Python dict emitter
# ---------------------------------------------------------------------------

def emit_py_dict(result, noise_ratio):
    """Render the shuffled opcode map as an importable Python module string."""
    seed_hex = result['seed_hex']
    real_map = result['real_map']
    decoy_wire = result['decoy_wire']

    lines = []
    lines.append('"""')
    lines.append('daedalus_opcodes_shuffled.py')
    lines.append('Auto-generated by shuffle_opcodes.py -- DO NOT EDIT')
    lines.append(f'Build seed: {seed_hex}')
    lines.append('"""')
    lines.append('')

    # Shuffled opcode table
    lines.append(
        '# Shuffled opcode table: mnemonic -> (wire_byte, operand_width, operand_kind)')
    lines.append(
        '# Drop-in replacement for daedalus_asm.OPCODES with per-build wire bytes.')
    lines.append('SHUFFLED_OPCODES = {')
    max_name = max(len(repr(n)) for n in real_map)
    for name, wire in real_map.items():
        _, width, kind = CANONICAL_OPCODES[name]
        lines.append(
            f"    {name!r:<{max_name}}: (0x{wire:02X}, {width}, {kind!r}),")
    lines.append('}')
    lines.append('')

    # Decoy wire bytes
    lines.append(
        '# Decoy wire bytes (single-byte no-op instructions for noise insertion)')
    hex_list = ', '.join(f'0x{w:02X}' for w in decoy_wire)
    lines.append(f'DECOY_WIRE_BYTES = [{hex_list}]')
    lines.append('')

    # Noise ratio
    lines.append(
        '# Fraction of real instructions to pad with randomly-inserted decoy bytes')
    lines.append(f'NOISE_RATIO = {noise_ratio}')
    lines.append('')

    # Build seed
    lines.append('# Reproducible build seed (hex)')
    lines.append(f'BUILD_SEED = {seed_hex!r}')
    lines.append(f'OPCODE_MAPPING_SHA256 = {result["mapping_sha256"]!r}')
    lines.append(f'HANDLER_VARIANTS = {dict(result["handler_variants"])!r}')
    lines.append(
        f'HANDLER_VARIANT_SHA256 = {result["handler_variant_sha256"]!r}')
    lines.append('')

    return '\n'.join(lines) + '\n'

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_shuffle(result):
    """Run integrity checks on a generated shuffle.  Returns list of errors."""
    real_map = result['real_map']
    decoy_wire = result['decoy_wire']
    unmap = result['unmap']
    handler_variants = result.get('handler_variants')
    errors = []

    if not isinstance(handler_variants, (dict, OrderedDict)):
        errors.append("FAIL: handler variant profile is missing")
    else:
        if tuple(handler_variants) != tuple(HANDLER_VARIANT_COUNTS):
            errors.append("FAIL: handler variant profile has wrong keys/order")
        for name, count in HANDLER_VARIANT_COUNTS.items():
            variant = handler_variants.get(name)
            if not isinstance(variant, int) or not 0 <= variant < count:
                errors.append(
                    f"FAIL: handler variant {name!r} is outside 0..{count - 1}")
        if result.get('handler_variant_sha256') != handler_variant_sha256(
                handler_variants):
            errors.append("FAIL: handler variant profile hash mismatch")

    # 1. All 56 real opcodes must have unique wire bytes.
    real_wires = list(real_map.values())
    if len(real_wires) != len(set(real_wires)):
        dups = [w for w in real_wires if real_wires.count(w) > 1]
        errors.append(f"FAIL: duplicate wire bytes among real opcodes: {dups}")

    # 2. All 17 decoys must have unique wire bytes.
    if len(decoy_wire) != len(set(decoy_wire)):
        dups = [w for w in decoy_wire if decoy_wire.count(w) > 1]
        errors.append(f"FAIL: duplicate wire bytes among decoys: {dups}")

    # 3. No collision between real and decoy wire bytes.
    real_set = set(real_wires)
    decoy_set = set(decoy_wire)
    overlap = real_set & decoy_set
    if overlap:
        errors.append(
            f"FAIL: wire-byte collision between real and decoy: "
            f"{sorted(overlap)}")

    # 4. Total coverage must be exactly 256.
    all_assigned = real_set | decoy_set
    trap_wire = result['trap_wire']
    total = len(real_set) + len(decoy_set) + len(trap_wire)
    if total != 256:
        errors.append(f"FAIL: pool coverage is {total}, expected 256")
    if all_assigned | set(trap_wire) != set(range(256)):
        errors.append("FAIL: pool does not cover full 0x00..0xFF range")

    # 5. UNMAP consistency for real opcodes.
    for name, wire in real_map.items():
        canonical = CANONICAL_OPCODES[name][0]
        if unmap[wire] != canonical:
            errors.append(
                f"FAIL: UNMAP[0x{wire:02X}] = 0x{unmap[wire]:02X}, "
                f"expected 0x{canonical:02X} ({name})")

    # 6. UNMAP consistency for decoys.
    for i, wire in enumerate(decoy_wire):
        expected = DECOY_CANONICAL_BASE + i
        if unmap[wire] != expected:
            errors.append(
                f"FAIL: UNMAP[0x{wire:02X}] = 0x{unmap[wire]:02X}, "
                f"expected 0x{expected:02X} (decoy_{i})")

    # 7. All non-assigned wire bytes must map to TRAP_CANONICAL.
    for v in range(256):
        if v not in all_assigned and unmap[v] != TRAP_CANONICAL:
            errors.append(
                f"FAIL: UNMAP[0x{v:02X}] = 0x{unmap[v]:02X}, "
                f"expected 0x{TRAP_CANONICAL:02X} (trap)")

    # 8. Trap count sanity.
    expected_traps = 256 - NUM_REAL - NUM_DECOYS
    actual_traps = sum(1 for v in unmap if v == TRAP_CANONICAL)
    if actual_traps != expected_traps:
        errors.append(
            f"FAIL: expected {expected_traps} trap slots, "
            f"got {actual_traps}")

    return errors

# ---------------------------------------------------------------------------
# CLI subcommands
# ---------------------------------------------------------------------------

def _parse_seed(seed_str):
    """Parse and validate a hex seed string.  Returns bytes or exits."""
    try:
        seed_bytes = bytes.fromhex(seed_str)
    except ValueError:
        print(f"error: --seed must be a valid hex string, got {seed_str!r}",
              file=sys.stderr)
        sys.exit(1)
    if len(seed_bytes) < 1:
        print("error: --seed must not be empty", file=sys.stderr)
        sys.exit(1)
    return seed_bytes


def cmd_generate(args):
    """Generate shuffled opcode map and emit output files."""
    seed_bytes = _parse_seed(args.seed) if args.seed else None
    result = generate_shuffle(seed_bytes)

    # Verify before writing (never emit a broken shuffle).
    errors = verify_shuffle(result)
    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        print(f"\nFATAL: generated shuffle failed verification "
              f"({len(errors)} errors)", file=sys.stderr)
        sys.exit(1)

    if args.c_header:
        header_text = emit_c_header(result)
        with open(args.c_header, 'w', newline='\n') as f:
            f.write(header_text)
        print(f"  C header: {args.c_header}")

    if args.py_dict:
        py_text = emit_py_dict(result, args.noise_ratio)
        with open(args.py_dict, 'w', newline='\n') as f:
            f.write(py_text)
        print(f"  Python dict: {args.py_dict}")

    print(f"  Build seed: {result['seed_hex']}")
    print(f"  Real opcodes: {NUM_REAL}")
    print(f"  Decoy opcodes: {NUM_DECOYS}")
    print(f"  Trap opcodes: {256 - NUM_REAL - NUM_DECOYS}")
    print(f"  Noise ratio: {args.noise_ratio}")


def cmd_verify(args):
    """Generate a shuffle and verify its integrity."""
    seed_bytes = _parse_seed(args.seed) if args.seed else None
    result = generate_shuffle(seed_bytes)
    errors = verify_shuffle(result)

    if errors:
        for e in errors:
            print(e)
        print(f"\nVERIFY FAILED ({len(errors)} errors)")
        return 1

    print(f"Build seed: {result['seed_hex']}")
    print()

    # Print real opcode mapping.
    print(f"Real opcode mapping ({NUM_REAL} opcodes):")
    print(f"  {'Mnemonic':<20s} {'Canonical':>10s} {'Wire':>10s}")
    print(f"  {'-' * 42}")
    for name, wire in result['real_map'].items():
        canonical = CANONICAL_OPCODES[name][0]
        print(f"  {name:<20s}     0x{canonical:02X}       0x{wire:02X}")
    print()

    # Print decoy mapping.
    print(f"Decoy mapping ({NUM_DECOYS} opcodes):")
    for i, wire in enumerate(result['decoy_wire']):
        dname = DECOY_TEMPLATES[i][0]
        canonical = DECOY_CANONICAL_BASE + i
        print(f"  decoy_{i:02d}  ({dname:<22s})  "
              f"canonical=0x{canonical:02X}  wire=0x{wire:02X}")
    print()

    # Summary.
    print(f"Trap slots: {256 - NUM_REAL - NUM_DECOYS}")
    print()
    print("VERIFY PASSED -- all checks OK")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description='Per-build opcode shuffling for Daedalus VM bytecode protection')
    sub = parser.add_subparsers(dest='command')

    # -- generate -----------------------------------------------------------
    gen_parser = sub.add_parser(
        'generate',
        help='Generate a shuffled opcode map and emit output files')
    gen_parser.add_argument(
        '--c-header',
        help='Output path for the C header file')
    gen_parser.add_argument(
        '--py-dict',
        help='Output path for the Python dict file')
    gen_parser.add_argument(
        '--seed',
        help='Hex seed for reproducible builds (omit for random)')
    gen_parser.add_argument(
        '--noise-ratio', type=float, default=0.15,
        help='Decoy insertion ratio for the assembler (default: 0.15)')

    # -- verify -------------------------------------------------------------
    ver_parser = sub.add_parser(
        'verify',
        help='Generate and verify a shuffle (prints mapping)')
    ver_parser.add_argument(
        '--seed',
        help='Hex seed to verify (omit for random)')

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == 'generate':
        if not args.c_header and not args.py_dict:
            print("error: generate requires at least one of "
                  "--c-header or --py-dict", file=sys.stderr)
            sys.exit(1)
        cmd_generate(args)
    elif args.command == 'verify':
        sys.exit(cmd_verify(args))


if __name__ == '__main__':
    main()
