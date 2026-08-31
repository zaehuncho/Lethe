#!/usr/bin/env python3
"""
daedalus_strenc.py -- build-time string encryption for Lethe stub.

Encrypts API name strings so they are not visible in the compiled binary.
Encryption: enc[i] = plaintext_byte[i] ^ (key ^ (i * mul))

Each string gets its own random (key, mul) pair so that recovering one
key/plaintext pair does not compromise the rest.

Usage:
  python daedalus_strenc.py "ntdll.dll" --key 0x5A
  python daedalus_strenc.py "ntdll.dll" --key 0x5A --mul 0x37
  python daedalus_strenc.py "ntdll.dll" --wide --key 0x5A
  python daedalus_strenc.py --generate-header
"""

import argparse
import secrets
import sys


def encrypt_bytes(data: bytes, key: int, mul: int = 0x37) -> list[int]:
    """Encrypt raw bytes with position-dependent XOR."""
    return [b ^ (key ^ ((i * mul) & 0xFF)) for i, b in enumerate(data)]


def format_c_array(encrypted: list[int], per_line: int = 12) -> str:
    """Format encrypted bytes as a C initializer list."""
    parts = []
    for i in range(0, len(encrypted), per_line):
        chunk = encrypted[i:i + per_line]
        parts.append(",".join(f"0x{b:02X}" for b in chunk))
    return ",\n    ".join(parts)


def encrypt_narrow(plaintext: str, key: int, mul: int = 0x37) -> list[int]:
    """Encrypt a narrow (char) string."""
    return encrypt_bytes(plaintext.encode("ascii"), key, mul)


def encrypt_wide(plaintext: str, key: int, mul: int = 0x37) -> list[int]:
    """Encrypt a wide (wchar_t) string as UTF-16LE bytes."""
    return encrypt_bytes(plaintext.encode("utf-16-le"), key, mul)


def _rand_key() -> int:
    """Random XOR key in [1, 255] (nonzero avoids degenerate identity)."""
    return secrets.randbelow(255) + 1


def _rand_mul() -> int:
    """Random position multiplier -- always odd so (i*mul) mod 256 cycles through
    all 256 values, maximizing positional diffusion."""
    return secrets.randbelow(128) * 2 + 1


# ---------------------------------------------------------------------------
# Predefined strings for --generate-header
# ---------------------------------------------------------------------------

NARROW_STRINGS = [
    {
        "plain": "NtQueryInformationProcess",
        "var": "_vs_nqip",
        "len_macro": "VSTR_NQIP_LEN",
        "key_macro": "VSTR_NQIP_KEY",
        "mul_macro": "VSTR_NQIP_MUL",
    },
    # --- CSPRNG resolution (was stack-assembled, but MSVC's optimizer coalesced
    #     the byte-by-byte writes into a memcpy from an .rdata constant --
    #     the plaintext "BCryptGenRandom" appeared in the stub image). Use
    #     vstr_dec's volatile decrypt loop, which the compiler can't hoist. ---
    {"plain": "bcrypt.dll",      "var": "_vs_bcrypt_dll",  "len_macro": "VSTR_BCRYPT_DLL_LEN",
     "key_macro": "VSTR_BCRYPT_DLL_KEY", "mul_macro": "VSTR_BCRYPT_DLL_MUL"},
    {"plain": "BCryptGenRandom", "var": "_vs_bcrypt_genrandom", "len_macro": "VSTR_BCRYPT_GENRANDOM_LEN",
     "key_macro": "VSTR_BCRYPT_GENRANDOM_KEY", "mul_macro": "VSTR_BCRYPT_GENRANDOM_MUL"},
    # --- DBI / instrumentation framework module names (check_instrumentation) ---
    {"plain": "frida-agent.dll",    "var": "_vs_frida_agent",  "len_macro": "VSTR_FRIDA_AGENT_LEN",
     "key_macro": "VSTR_FRIDA_AGENT_KEY",  "mul_macro": "VSTR_FRIDA_AGENT_MUL"},
    {"plain": "frida-gadget.dll",   "var": "_vs_frida_gadget", "len_macro": "VSTR_FRIDA_GADGET_LEN",
     "key_macro": "VSTR_FRIDA_GADGET_KEY", "mul_macro": "VSTR_FRIDA_GADGET_MUL"},
    {"plain": "dynamorio.dll",      "var": "_vs_dynamorio",    "len_macro": "VSTR_DYNAMORIO_LEN",
     "key_macro": "VSTR_DYNAMORIO_KEY",    "mul_macro": "VSTR_DYNAMORIO_MUL"},
    {"plain": "pinvm.dll",          "var": "_vs_pinvm",        "len_macro": "VSTR_PINVM_LEN",
     "key_macro": "VSTR_PINVM_KEY",        "mul_macro": "VSTR_PINVM_MUL"},
    {"plain": "x64dbg.dll",         "var": "_vs_x64dbg_dll",   "len_macro": "VSTR_X64DBG_DLL_LEN",
     "key_macro": "VSTR_X64DBG_DLL_KEY",   "mul_macro": "VSTR_X64DBG_DLL_MUL"},
    {"plain": "x32dbg.dll",         "var": "_vs_x32dbg_dll",   "len_macro": "VSTR_X32DBG_DLL_LEN",
     "key_macro": "VSTR_X32DBG_DLL_KEY",   "mul_macro": "VSTR_X32DBG_DLL_MUL"},
    {"plain": "HookLibraryx64.dll", "var": "_vs_hooklib",      "len_macro": "VSTR_HOOKLIB_LEN",
     "key_macro": "VSTR_HOOKLIB_KEY",      "mul_macro": "VSTR_HOOKLIB_MUL"},
    # --- Known-debugger parent process basenames (check_parent_process) ---
    {"plain": "x64dbg.exe",  "var": "_vs_x64dbg_exe",  "len_macro": "VSTR_X64DBG_EXE_LEN",
     "key_macro": "VSTR_X64DBG_EXE_KEY",  "mul_macro": "VSTR_X64DBG_EXE_MUL"},
    {"plain": "x32dbg.exe",  "var": "_vs_x32dbg_exe",  "len_macro": "VSTR_X32DBG_EXE_LEN",
     "key_macro": "VSTR_X32DBG_EXE_KEY",  "mul_macro": "VSTR_X32DBG_EXE_MUL"},
    {"plain": "x96dbg.exe",  "var": "_vs_x96dbg_exe",  "len_macro": "VSTR_X96DBG_EXE_LEN",
     "key_macro": "VSTR_X96DBG_EXE_KEY",  "mul_macro": "VSTR_X96DBG_EXE_MUL"},
    {"plain": "ollydbg.exe", "var": "_vs_ollydbg_exe", "len_macro": "VSTR_OLLYDBG_EXE_LEN",
     "key_macro": "VSTR_OLLYDBG_EXE_KEY", "mul_macro": "VSTR_OLLYDBG_EXE_MUL"},
    {"plain": "windbg.exe",  "var": "_vs_windbg_exe",  "len_macro": "VSTR_WINDBG_EXE_LEN",
     "key_macro": "VSTR_WINDBG_EXE_KEY",  "mul_macro": "VSTR_WINDBG_EXE_MUL"},
    {"plain": "devenv.exe",  "var": "_vs_devenv_exe",  "len_macro": "VSTR_DEVENV_EXE_LEN",
     "key_macro": "VSTR_DEVENV_EXE_KEY",  "mul_macro": "VSTR_DEVENV_EXE_MUL"},
    {"plain": "ida.exe",     "var": "_vs_ida_exe",     "len_macro": "VSTR_IDA_EXE_LEN",
     "key_macro": "VSTR_IDA_EXE_KEY",     "mul_macro": "VSTR_IDA_EXE_MUL"},
    {"plain": "ida64.exe",   "var": "_vs_ida64_exe",   "len_macro": "VSTR_IDA64_EXE_LEN",
     "key_macro": "VSTR_IDA64_EXE_KEY",   "mul_macro": "VSTR_IDA64_EXE_MUL"},
]

WIDE_STRINGS = [
    {
        "plain": "ntdll.dll",
        "var": "_vs_ntdll_w",
        "len_macro": "VSTR_NTDLL_W_LEN",
        "key_macro": "VSTR_NTDLL_W_KEY",
        "mul_macro": "VSTR_NTDLL_W_MUL",
    },
]


def generate_header() -> str:
    """Generate daedalus_str_data.h with per-string random keys and multipliers."""
    lines = [
        "/* daedalus_str_data.h -- generated by daedalus_strenc.py */",
        "#pragma once",
        "#include <stdint.h>",
        "",
    ]

    for entry in NARROW_STRINGS:
        plain = entry["plain"]
        var = entry["var"]
        length = len(plain)
        key = _rand_key()
        mul = _rand_mul()
        enc = encrypt_narrow(plain, key, mul)
        arr = format_c_array(enc)
        lines.append(f'/* "{plain}" ({length} chars) */')
        lines.append(f"static const uint8_t {var}[] = {{")
        lines.append(f"    {arr}}};")
        lines.append(f"#define {entry['len_macro']} {length}")
        lines.append(f"#define {entry['key_macro']} 0x{key:02X}u")
        lines.append(f"#define {entry['mul_macro']} 0x{mul:02X}u")
        lines.append("")

    for entry in WIDE_STRINGS:
        plain = entry["plain"]
        var = entry["var"]
        char_count = len(plain)
        byte_count = char_count * 2
        key = _rand_key()
        mul = _rand_mul()
        enc = encrypt_wide(plain, key, mul)
        arr = format_c_array(enc)
        lines.append(f'/* L"{plain}" ({char_count} wchars = {byte_count} bytes) */')
        lines.append(f"static const uint8_t {var}[] = {{")
        lines.append(f"    {arr}}};")
        lines.append(f"#define {entry['len_macro']} {char_count}")
        lines.append(f"#define {entry['key_macro']} 0x{key:02X}u")
        lines.append(f"#define {entry['mul_macro']} 0x{mul:02X}u")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Lethe string encryption tool")
    parser.add_argument("string", nargs="?", help="String to encrypt")
    parser.add_argument("--key",
                        help="XOR key (e.g. 0x5A); required for single-string mode")
    parser.add_argument("--mul", default="0x37",
                        help="Position multiplier (e.g. 0x37, default); single-string mode only")
    parser.add_argument("--wide", action="store_true",
                        help="Encrypt as UTF-16LE (wide string)")
    parser.add_argument("--generate-header", action="store_true",
                        help="Generate daedalus_str_data.h with per-string random keys")
    args = parser.parse_args()

    if args.generate_header:
        print(generate_header())
        return

    if not args.string:
        parser.error("string is required unless --generate-header is used")
    if not args.key:
        parser.error("--key is required for single-string mode")

    key = int(args.key, 0)
    mul = int(args.mul, 0)
    if not (0 <= key <= 255):
        print("Error: key must be 0x00..0xFF", file=sys.stderr)
        sys.exit(1)
    if not (0 <= mul <= 255):
        print("Error: mul must be 0x00..0xFF", file=sys.stderr)
        sys.exit(1)

    if args.wide:
        enc = encrypt_wide(args.string, key, mul)
        byte_count = len(enc)
        char_count = len(args.string)
        arr = format_c_array(enc)
        print(f'/* L"{args.string}" ({char_count} wchars = {byte_count} bytes) */')
        print(f"static const uint8_t enc[] = {{")
        print(f"    {arr}}};")
        print(f"/* char_count = {char_count}, key = 0x{key:02X}, mul = 0x{mul:02X} */")
    else:
        enc = encrypt_narrow(args.string, key, mul)
        length = len(enc)
        arr = format_c_array(enc)
        print(f'/* "{args.string}" ({length} chars) */')
        print(f"static const uint8_t enc[] = {{")
        print(f"    {arr}}};")
        print(f"/* len = {length}, key = 0x{key:02X}, mul = 0x{mul:02X} */")


if __name__ == "__main__":
    main()
