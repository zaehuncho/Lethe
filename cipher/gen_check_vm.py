#!/usr/bin/env python3
"""
gen_check_vm.py -- emit + verify the VIRTUALIZED password check as Venice VM
bytecode (Logic Mortaring for the crackme).

Instead of a native FNV->XOR check that any decompiler reads off, the crackme's
gate runs inside the Venice VM: an analyst who fully unpacks the binary sees the
interpreter + an opaque bytecode blob, not the formula.

The program (stack machine, 64-bit) does exactly what the C crackme did:
  h = FNV1a64(pw)                       ; over pw bytes in locals[0..n-1]
  if h != EXPECTED: return 1 (DENY)
  for i in 0..FLAGLEN-1:                ; decrypt into locals[FLAG_OFF..]
    flag[i] = ct[i] ^ pw[i % n]
                  ^ ((h >> ((i & 7)*8)) & 0xFF)
                  ^ ((0x25*i + 0x0D) & 0xFF)
  return 0 (GRANT)

Locals layout (caller/C contract):
  [0..63]      password bytes (caller pre-loads; arg0 = length n)
  [64..71]     h (FNV accumulator)
  [72..79]     i (loop counter)
  [80..87]     scratch t
  [128..]      decrypted flag output (caller reads it)
Data: ct[FLAGLEN].

Emitted via a tiny helper-based emitter (reliable > hand juggling), then PROVEN
correct against the reference interpreter for the real password (grant + exact
flag) and a wrong password (deny).
"""
from __future__ import annotations
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PKG = HERE.parent
sys.path.insert(0, str(PKG / "venice"))
import venice_asm      # noqa: E402
from venice_ref import RefVM, _LOCAL_BASE  # noqa: E402

BASIS = 0xCBF29CE484222325
PRIME = 0x100000001B3
MASK64 = (1 << 64) - 1

H_OFF, I_OFF, T_OFF, FLAG_OFF = 64, 72, 80, 128


class Emit:
    def __init__(self):
        self.lines = []

    def __call__(self, s):
        self.lines.append("  " + s)

    def label(self, name):
        self.lines.append(name + ":")

    # --- helpers (each documents its net stack effect) ---
    def push64(self, v):          # -> [v]
        self(f"push_imm64 0x{v & MASK64:016X}")

    def load_local64(self, off):  # -> [*(locals+off)]
        self(f"local_addr {off}"); self("load64")

    def store_local64(self, off):  # [val] -> [] ; locals[off]=val
        self(f"local_addr {off}"); self("swap"); self("store64")

    def load_local8_at(self, off):  # -> [locals[off] as byte]  (off is a local index literal)
        self(f"local_addr {off}"); self("load8")

    def text(self):
        return "\n".join([".code"] + self.lines) + "\n"


def build_vasm(ct: bytes, expected_h: int, flag_len: int) -> str:
    e = Emit()
    # data section: ct bytes
    data = ".data\n  ct: db " + ", ".join(f"0x{b:02X}" for b in ct) + "\n"

    # h = BASIS
    e.push64(BASIS); e.store_local64(H_OFF)
    # i = 0
    e.push64(0); e.store_local64(I_OFF)

    e.label("L_fnv")
    # if !(i < n) goto done
    e.load_local64(I_OFF)
    e("push_arg 0")             # n
    e("cmp_lt")
    e("jz L_fnv_done")
    # h = (h ^ pw[i]) * PRIME
    e.load_local64(H_OFF)       # [h]
    e("local_addr 0")           # [h, &locals0]
    e.load_local64(I_OFF)       # [h, &locals0, i]
    e("add")                    # [h, &pw_i]
    e("load8")                  # [h, pw_i]
    e("xor")                    # [h^pw_i]
    e.push64(PRIME)             # [.., PRIME]
    e("mul")                    # [(h^pw_i)*PRIME]
    e.store_local64(H_OFF)
    # i++
    e.load_local64(I_OFF); e("push_imm8 1"); e("add"); e.store_local64(I_OFF)
    e("jmp L_fnv")

    e.label("L_fnv_done")
    e.load_local64(H_OFF)
    e.push64(expected_h)
    e("cmp_eq")
    e("jz L_deny")

    # ---- decrypt loop ----
    e.push64(0); e.store_local64(I_OFF)
    e.label("L_dec")
    e.load_local64(I_OFF)
    e(f"push_imm8 {flag_len}")
    e("cmp_lt")
    e("jz L_grant")
    # t = ct[i]
    e("data_addr 0"); e.load_local64(I_OFF); e("add"); e("load8")   # [ct_i]
    # ^ pw[i % n]
    e("local_addr 0")                     # [ct_i, &locals0]
    e.load_local64(I_OFF); e("push_arg 0"); e("mod")   # [ct_i, &locals0, i%n]
    e("add"); e("load8")                  # [ct_i, pw_(i%n)]
    e("xor")                              # [ct_i ^ pw]
    # ^ ((h >> ((i & 7)*8)) & 0xFF)
    e.load_local64(H_OFF)                 # [.., h]
    e.load_local64(I_OFF); e("push_imm8 7"); e("and")  # [.., h, i&7]
    e("push_imm8 8"); e("mul")            # [.., h, (i&7)*8]
    e("shr")                              # [.., h>>shift]
    e("push_imm8 0xFF"); e("and")         # [.., byte]
    e("xor")                              # [running ^ that]
    # ^ ((0x25*i + 0x0D) & 0xFF)
    e.load_local64(I_OFF); e("push_imm8 0x25"); e("mul")
    e("push_imm8 0x0D"); e("add")
    e("push_imm8 0xFF"); e("and")
    e("xor")                              # [flag_i]
    # store flag[i] into locals[FLAG_OFF + i]  (byte)
    # need [addr, val] for store8: compute &locals[FLAG_OFF+i], then val, store8
    e.store_local64(T_OFF)                # stash flag_i in T (64), we'll re-load
    e("local_addr " + str(FLAG_OFF))      # [&flag0]
    e.load_local64(I_OFF); e("add")       # [&flag_i]
    e.load_local64(T_OFF)                 # [&flag_i, flag_i]
    e("store8")
    # i++
    e.load_local64(I_OFF); e("push_imm8 1"); e("add"); e.store_local64(I_OFF)
    e("jmp L_dec")

    e.label("L_grant")
    e("push_imm8 0"); e("halt")
    e.label("L_deny")
    e("push_imm8 1"); e("halt")

    return data + "\n" + e.text()


# --------------------------------------------------------------------------
# reference-run helper: preload pw into locals, ct into data, run, read flag
# --------------------------------------------------------------------------
def run_check(blob, pw: bytes, flag_len: int):
    ds = struct.unpack_from("<H", blob, 0)[0]
    data = blob[2:2 + ds]
    code = blob[2 + ds:]
    vm = RefVM(code, data, args=[len(pw)])
    for j, b in enumerate(pw):
        vm.locals[j] = b
    rc = vm.run()
    flag = bytes(vm.locals[FLAG_OFF:FLAG_OFF + flag_len])
    return rc, flag


if __name__ == "__main__":
    # the real crackme parameters
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

    src = build_vasm(ct, H, len(FLAG))
    out_vasm = HERE / "check_vm.vasm"
    out_vasm.write_text(src, encoding="utf-8")
    blob = venice_asm.assemble(src)

    # PROVE correctness in the reference interpreter
    rc_ok, flag_ok = run_check(blob, PASSWORD, len(FLAG))
    rc_bad, _ = run_check(blob, b"wrongpass", len(FLAG))

    print(f"EXPECTED_H = 0x{H:016X}  ct_len={len(ct)}  blob={len(blob)} bytes")
    print(f"correct pw -> rc={rc_ok}  flag={flag_ok!r}")
    print(f"wrong pw   -> rc={rc_bad}")

    ok = (rc_ok == 0 and flag_ok == FLAG and rc_bad == 1)
    print("VM CHECK CORRECT" if ok else "*** MISMATCH ***")

    if ok:
        # Emit the blob + contract as a C header for the VM-crackme. The blob is
        # XOR-obfuscated with a rolling byte so it is not plaintext-readable in
        # the binary; the crackme decodes it at runtime before executing.
        xkey = 0x5A
        obf = bytearray()
        k = xkey
        for b in blob:
            obf.append(b ^ k)
            k = (k * 33 + 7) & 0xFF
        arr = ", ".join(f"0x{b:02X}" for b in obf)
        hdr = (
            "/* check_vm_blob.h -- generated by gen_check_vm.py. The password\n"
            " * check runs as Venice VM bytecode (Logic Mortaring), XOR-obfuscated.*/\n"
            "#pragma once\n"
            f"#define CHECK_VM_LEN {len(blob)}\n"
            f"#define CHECK_FLAG_OFF {FLAG_OFF}\n"
            f"#define CHECK_FLAG_LEN {len(FLAG)}\n"
            f"#define CHECK_XOR_SEED 0x{xkey:02X}\n"
            f"static const unsigned char CHECK_VM_OBF[CHECK_VM_LEN] = {{ {arr} }};\n"
        )
        (HERE / "check_vm_blob.h").write_text(hdr, encoding="utf-8")
        print(f"wrote check_vm_blob.h ({len(blob)} bytes, obfuscated)")
    sys.exit(0 if ok else 1)
