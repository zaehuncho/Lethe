#!/usr/bin/env python3
"""
daedalus_asm.py -- Two-pass assembler for the Daedalus VM bytecode ISA.

Input:  .vasm text file
Output: binary blob [u16_LE data_size][data_bytes][code_bytes]
        or C header array (--format header)

Usage:
    python daedalus_asm.py input.vasm -o out.bin
    python daedalus_asm.py input.vasm --format header -o out.h
    python daedalus_asm.py input.vasm --format header --name DVM_PROG_FOO
"""

import argparse
import os
import re
import struct
import sys

# ---------------------------------------------------------------------------
# Opcode table: mnemonic -> (opcode_byte, operand_width, operand_kind)
#   operand_kind: 'none' | 'imm' | 'label'
# ---------------------------------------------------------------------------
OPCODES = {
    # -- stack manipulation --
    'halt':           (0x00, 0, 'none'),
    'nop':            (0x01, 0, 'none'),
    'push_imm8':      (0x02, 1, 'imm'),
    'push_imm32':     (0x03, 4, 'imm'),
    'push_imm64':     (0x04, 8, 'imm'),
    'pop':            (0x05, 0, 'none'),
    'dup':            (0x06, 0, 'none'),
    'swap':           (0x07, 0, 'none'),
    # -- arithmetic --
    'add':            (0x08, 0, 'none'),
    'sub':            (0x09, 0, 'none'),
    'xor':            (0x0A, 0, 'none'),
    'and':            (0x0B, 0, 'none'),
    'or':             (0x0C, 0, 'none'),
    'shl':            (0x0D, 0, 'none'),
    'shr':            (0x0E, 0, 'none'),
    'mul':            (0x0F, 0, 'none'),
    # -- memory --
    'load8':          (0x10, 0, 'none'),
    'load32':         (0x11, 0, 'none'),
    'load64':         (0x12, 0, 'none'),
    'store8':         (0x13, 0, 'none'),
    'store32':        (0x14, 0, 'none'),
    'store64':        (0x15, 0, 'none'),
    # -- comparison --
    'cmp_eq':         (0x16, 0, 'none'),
    'cmp_lt':         (0x17, 0, 'none'),
    # -- control flow --
    'jmp':            (0x18, 4, 'label'),
    'jz':             (0x19, 4, 'label'),
    'jnz':            (0x1A, 4, 'label'),
    'call':           (0x1B, 4, 'label'),
    # -- data access --
    'push_arg':       (0x1C, 1, 'imm'),
    'local_addr':     (0x1D, 2, 'imm'),
    'data_addr':      (0x1E, 2, 'imm'),
    # -- return --
    'ret':            (0x1F, 0, 'none'),
    # -- native ops (0 inline operands) --
    'n_sha256':       (0x20, 0, 'none'),
    'n_hkdf':         (0x21, 0, 'none'),
    'n_xor_buf':      (0x22, 0, 'none'),
    'n_getenv':       (0x23, 0, 'none'),
    'n_setenv_null':  (0x24, 0, 'none'),
    'n_hex_decode':   (0x25, 0, 'none'),
    'n_zero_mem':     (0x26, 0, 'none'),
    'n_scatter_init': (0x27, 0, 'none'),
    'n_copy_mem':     (0x28, 0, 'none'),
    'n_xor_repeat':   (0x29, 0, 'none'),
    'n_xor_const':    (0x2A, 0, 'none'),
    'n_call_ptr':     (0x2B, 0, 'none'),
    # -- v2 arithmetic --
    'div':            (0x2C, 0, 'none'),
    'mod':            (0x2D, 0, 'none'),
    'neg':            (0x2E, 0, 'none'),
    'not':            (0x2F, 0, 'none'),
    # -- v2 comparison --
    'cmp_gt':         (0x30, 0, 'none'),
    'cmp_ge':         (0x31, 0, 'none'),
    'cmp_ne':         (0x32, 0, 'none'),
    # -- v2 data/stack --
    'push_imm16':     (0x33, 2, 'imm'),
    'load16':         (0x34, 0, 'none'),
    'store16':        (0x35, 0, 'none'),
    'rot3':           (0x36, 0, 'none'),
    'pick':           (0x37, 1, 'imm'),
}


def _parse_int(s):
    """Parse a decimal or hex integer string."""
    s = s.strip()
    if s.startswith('0x') or s.startswith('0X'):
        return int(s, 16)
    return int(s)


def assemble(source, opcodes=None):
    """
    Two-pass assembly of Daedalus .vasm source.

    Returns bytes: [u16_LE data_size][data_bytes][code_bytes]. ``opcodes`` may
    supply an immutable per-build mnemonic mapping; the module canonical table
    is only the backward-compatible default and is never mutated here.
    """
    opcode_table = OPCODES if opcodes is None else opcodes
    lines = source.split('\n')
    constants = {}
    data_bytes = bytearray()

    # Code items: interleaved labels and instructions.
    # ('label', name, line_no) | ('inst', mnemonic, operand_str|None, line_no)
    code_items = []

    section = None  # None | 'data' | 'code'

    # ---- Lexing / parsing ------------------------------------------------
    for idx, raw in enumerate(lines):
        ln = idx + 1
        line = raw.split(';')[0].strip()
        if not line:
            continue

        # .const NAME value
        if line.startswith('.const '):
            parts = line.split(None, 2)
            if len(parts) < 3:
                raise SyntaxError(f"line {ln}: malformed .const directive")
            constants[parts[1]] = _parse_int(parts[2])
            continue

        # Section switches
        if line == '.data':
            section = 'data'
            continue
        if line == '.code':
            section = 'code'
            continue

        # ---- .data section -----------------------------------------------
        if section == 'data':
            m = re.match(r'^(\w+)\s*:\s*(.*)', line)
            if m:
                rest = m.group(2).strip()
                if not rest:
                    continue
                line = rest
            if line.lower().startswith('db ') or line.lower().startswith('db\t'):
                for tok in line[3:].split(','):
                    tok = tok.strip()
                    if tok:
                        data_bytes.append(_parse_int(tok) & 0xFF)
            else:
                raise SyntaxError(f"line {ln}: unexpected in .data: {line}")
            continue

        # ---- .code section -----------------------------------------------
        if section == 'code':
            # Label (possibly followed by an instruction on the same line)
            m = re.match(r'^(\w+)\s*:\s*(.*)', line)
            if m:
                code_items.append(('label', m.group(1), ln))
                rest = m.group(2).strip()
                if not rest:
                    continue
                line = rest

            parts = line.split(None, 1)
            mnemonic = parts[0].lower()
            operand = parts[1].strip() if len(parts) > 1 else None

            if mnemonic not in opcode_table:
                raise SyntaxError(f"line {ln}: unknown opcode '{mnemonic}'")

            code_items.append(('inst', mnemonic, operand, ln))
            continue

        raise SyntaxError(f"line {ln}: content outside .data/.code section")

    # ---- Pass 1: compute label -> code byte offset -----------------------
    code_labels = {}
    offset = 0
    for item in code_items:
        if item[0] == 'label':
            name = item[1]
            if name in code_labels:
                raise SyntaxError(f"line {item[2]}: duplicate label '{name}'")
            code_labels[name] = offset
        else:
            _, mnemonic, _, _ = item
            _, width, _ = opcode_table[mnemonic]
            offset += 1 + width

    # ---- Pass 2: emit code bytes -----------------------------------------
    code = bytearray()
    for item in code_items:
        if item[0] == 'label':
            continue

        _, mnemonic, operand_str, ln = item
        opcode, width, kind = opcode_table[mnemonic]

        code.append(opcode)

        if kind == 'none':
            if operand_str is not None:
                raise SyntaxError(f"line {ln}: {mnemonic} takes no operand")

        elif kind == 'imm':
            if operand_str is None:
                raise SyntaxError(f"line {ln}: {mnemonic} requires an operand")
            val = constants[operand_str] if operand_str in constants else _parse_int(operand_str)
            if width == 1:
                code.append(val & 0xFF)
            elif width == 2:
                code.extend(struct.pack('<H', val & 0xFFFF))
            elif width == 4:
                code.extend(struct.pack('<I', val & 0xFFFFFFFF))
            elif width == 8:
                code.extend(struct.pack('<Q', val & 0xFFFFFFFFFFFFFFFF))

        elif kind == 'label':
            if operand_str is None:
                raise SyntaxError(f"line {ln}: {mnemonic} requires a label")
            if operand_str not in code_labels:
                raise SyntaxError(f"line {ln}: undefined label '{operand_str}'")
            code.extend(struct.pack('<I', code_labels[operand_str]))

    # ---- Build blob: [u16_LE data_size][data][code] ----------------------
    ds = len(data_bytes)
    if ds > 0xFFFF:
        raise ValueError(f"data section too large: {ds} bytes")

    blob = bytearray()
    blob.extend(struct.pack('<H', ds))
    blob.extend(data_bytes)
    blob.extend(code)
    return bytes(blob)


def _format_header(blob, name, opcodes=None):
    """Render blob as a C static-const uint8_t array."""
    opcode_table = OPCODES if opcodes is None else opcodes
    # Reverse-lookup table: opcode_byte -> operand width
    op_width = {}
    for _, (opc, w, _) in opcode_table.items():
        op_width[opc] = w

    ds = struct.unpack_from('<H', blob, 0)[0]
    out = []
    out.append(f'static const uint8_t {name}[] = {{')
    out.append(f'    /* header: data_size = {ds} (u16 LE) */')
    out.append(f'    0x{blob[0]:02X}, 0x{blob[1]:02X},')

    if ds > 0:
        out.append(f'    /* data[0..{ds - 1}] */')
        out.append('    ' + ', '.join(f'0x{b:02X}' for b in blob[2:2 + ds]) + ',')

    code_start = 2 + ds
    out.append('    /* code */')
    i = code_start
    code_off = 0
    while i < len(blob):
        opc = blob[i]
        w = op_width.get(opc, 0)
        end = i + 1 + w
        hex_frag = ', '.join(f'0x{blob[j]:02X}' for j in range(i, min(end, len(blob))))
        trail = ',' if end < len(blob) else ','
        out.append(f'    /* 0x{code_off:02X} */ {hex_frag}{trail}')
        code_off += 1 + w
        i = end

    out.append('};')
    out.append(f'static const uint32_t {name}_SIZE = sizeof({name});')
    return '\n'.join(out) + '\n'


def _load_shuffled_opcodes(path):
    """Load a shuffled opcode map generated by shuffle_opcodes.py."""
    import importlib.util
    spec = importlib.util.spec_from_file_location('_shuffled', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SHUFFLED_OPCODES


def main():
    ap = argparse.ArgumentParser(description='Daedalus VM assembler')
    ap.add_argument('input', help='Input .vasm file')
    ap.add_argument('--format', choices=['bin', 'header'], default='bin',
                    help='Output format (default: bin)')
    ap.add_argument('--output', '-o', help='Output file path')
    ap.add_argument('--name', default=None,
                    help='C array name for --format header')
    ap.add_argument('--shuffled-map', default=None,
                    help='Path to daedalus_opcodes_shuffled.py for per-build opcode randomization')
    args = ap.parse_args()

    opcode_table = (
        _load_shuffled_opcodes(args.shuffled_map)
        if args.shuffled_map
        else OPCODES
    )

    with open(args.input, 'r') as f:
        source = f.read()

    blob = assemble(source, opcodes=opcode_table)

    if args.format == 'bin':
        if args.output:
            with open(args.output, 'wb') as f:
                f.write(blob)
        else:
            sys.stdout.buffer.write(blob)
    else:
        name = args.name
        if name is None:
            base = os.path.splitext(os.path.basename(args.input))[0].upper()
            name = 'DVM_PROG_' + base
        text = _format_header(blob, name, opcodes=opcode_table)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(text)
        else:
            sys.stdout.write(text)


if __name__ == '__main__':
    main()
