#!/usr/bin/env python3
"""
daedalus_disasm.py -- Disassembler for Daedalus VM bytecode blobs.

Reads a binary blob ([u16_LE data_size][data][code]) and emits
human-readable .vasm text with byte-offset comments.

Usage:
    python daedalus_disasm.py input.bin
    python daedalus_disasm.py input.bin -o output.vasm
"""

import argparse
import struct
import sys

# ---------------------------------------------------------------------------
# Opcode table: opcode_byte -> (mnemonic, operand_width, operand_kind)
# ---------------------------------------------------------------------------
OPCODE_TABLE = {
    0x00: ('halt',           0, 'none'),
    0x01: ('nop',            0, 'none'),
    0x02: ('push_imm8',      1, 'imm'),
    0x03: ('push_imm32',     4, 'imm'),
    0x04: ('push_imm64',     8, 'imm'),
    0x05: ('pop',            0, 'none'),
    0x06: ('dup',            0, 'none'),
    0x07: ('swap',           0, 'none'),
    0x08: ('add',            0, 'none'),
    0x09: ('sub',            0, 'none'),
    0x0A: ('xor',            0, 'none'),
    0x0B: ('and',            0, 'none'),
    0x0C: ('or',             0, 'none'),
    0x0D: ('shl',            0, 'none'),
    0x0E: ('shr',            0, 'none'),
    0x0F: ('mul',            0, 'none'),
    0x10: ('load8',          0, 'none'),
    0x11: ('load32',         0, 'none'),
    0x12: ('load64',         0, 'none'),
    0x13: ('store8',         0, 'none'),
    0x14: ('store32',        0, 'none'),
    0x15: ('store64',        0, 'none'),
    0x16: ('cmp_eq',         0, 'none'),
    0x17: ('cmp_lt',         0, 'none'),
    0x18: ('jmp',            4, 'label'),
    0x19: ('jz',             4, 'label'),
    0x1A: ('jnz',            4, 'label'),
    0x1B: ('call',           4, 'label'),
    0x1C: ('push_arg',       1, 'imm'),
    0x1D: ('local_addr',     2, 'imm'),
    0x1E: ('data_addr',      2, 'imm'),
    0x1F: ('ret',            0, 'none'),
    0x20: ('n_sha256',       0, 'none'),
    0x21: ('n_hkdf',         0, 'none'),
    0x22: ('n_xor_buf',      0, 'none'),
    0x23: ('n_getenv',       0, 'none'),
    0x24: ('n_setenv_null',  0, 'none'),
    0x25: ('n_hex_decode',   0, 'none'),
    0x26: ('n_zero_mem',     0, 'none'),
    0x27: ('n_scatter_init', 0, 'none'),
    0x28: ('n_copy_mem',     0, 'none'),
    0x29: ('n_xor_repeat',   0, 'none'),
    0x2A: ('n_xor_const',    0, 'none'),
    0x2B: ('n_call_ptr',     0, 'none'),
    0x2C: ('div',            0, 'none'),
    0x2D: ('mod',            0, 'none'),
    0x2E: ('neg',            0, 'none'),
    0x2F: ('not',            0, 'none'),
    0x30: ('cmp_gt',         0, 'none'),
    0x31: ('cmp_ge',         0, 'none'),
    0x32: ('cmp_ne',         0, 'none'),
    0x33: ('push_imm16',     2, 'imm'),
    0x34: ('load16',         0, 'none'),
    0x35: ('store16',        0, 'none'),
    0x36: ('rot3',           0, 'none'),
    0x37: ('pick',           1, 'imm'),
}


def disassemble(blob):
    """
    Disassemble a Daedalus VM binary blob into .vasm text.

    Returns the text as a string, with byte-offset comments on each line
    and synthetic labels for branch/call targets.
    """
    if len(blob) < 2:
        raise ValueError("blob too short for u16 data_size header")

    data_size = struct.unpack_from('<H', blob, 0)[0]
    if 2 + data_size > len(blob):
        raise ValueError(
            f"data_size ({data_size}) exceeds blob ({len(blob)} bytes)")

    data = blob[2:2 + data_size]
    code = blob[2 + data_size:]

    # -- First pass: decode instructions, collect branch targets -----------
    jump_targets = set()
    instructions = []  # (code_offset, mnemonic, operand|None, width, kind)

    pc = 0
    while pc < len(code):
        opc = code[pc]
        if opc not in OPCODE_TABLE:
            raise ValueError(
                f"unknown opcode 0x{opc:02X} at code offset 0x{pc:02X}")
        mnemonic, width, kind = OPCODE_TABLE[opc]

        if pc + 1 + width > len(code):
            raise ValueError(
                f"truncated operand for {mnemonic} at code offset 0x{pc:02X}")

        operand = None
        if width == 1:
            operand = code[pc + 1]
        elif width == 2:
            operand = struct.unpack_from('<H', code, pc + 1)[0]
        elif width == 4:
            operand = struct.unpack_from('<I', code, pc + 1)[0]
        elif width == 8:
            operand = struct.unpack_from('<Q', code, pc + 1)[0]

        if kind == 'label' and operand is not None:
            jump_targets.add(operand)

        instructions.append((pc, mnemonic, operand, width, kind))
        pc += 1 + width

    # -- Assign labels to targets ------------------------------------------
    label_map = {t: f"L_{t:04X}" for t in sorted(jump_targets)}

    # -- Render output -----------------------------------------------------
    out = []
    out.append('; Daedalus VM disassembly')
    out.append(f'; blob size: {len(blob)} bytes  '
               f'(data: {data_size}, code: {len(code)})')
    out.append('')
    out.append('.data')
    if data_size > 0:
        hex_str = ', '.join(f'0x{b:02X}' for b in data)
        out.append(f'  dat: db {hex_str}')
    out.append('')
    out.append('.code')

    for off, mnemonic, operand, width, kind in instructions:
        # Emit label if this offset is a target
        if off in label_map:
            out.append(f'{label_map[off]}:')

        # Format the instruction text
        if kind == 'none':
            inst_text = f'  {mnemonic}'
        elif kind == 'imm':
            if width == 8:
                inst_text = f'  {mnemonic} 0x{operand:016X}'
            elif width == 4:
                inst_text = f'  {mnemonic} {operand}'
            elif width == 2:
                inst_text = f'  {mnemonic} {operand}'
            else:  # 1
                inst_text = f'  {mnemonic} 0x{operand:02X}'
        elif kind == 'label':
            lbl = label_map.get(operand, f'??? (0x{operand:04X})')
            inst_text = f'  {mnemonic} {lbl}'
        else:
            inst_text = f'  {mnemonic}'

        # Raw bytes comment
        byte_len = 1 + width
        raw = ' '.join(f'{code[off + j]:02X}' for j in range(byte_len))
        out.append(f'{inst_text:<36s}; 0x{off:04X}  {raw}')

    out.append('')
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser(description='Daedalus VM disassembler')
    ap.add_argument('input', help='Input binary blob file')
    ap.add_argument('--output', '-o', help='Output .vasm file (default: stdout)')
    args = ap.parse_args()

    with open(args.input, 'rb') as f:
        blob = f.read()

    text = disassemble(blob)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(text)
    else:
        sys.stdout.write(text)


if __name__ == '__main__':
    main()
