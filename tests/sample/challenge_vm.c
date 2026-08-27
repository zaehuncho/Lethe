/*
 * challenge_vm.c -- Lethe red-team crackme, VIRTUALIZED edition.
 *
 * The password check is NOT native code -- it runs as Daedalus VM bytecode
 * (Logic Mortaring). A fully-unpacked dump reveals a tiny stack-VM interpreter
 * plus an XOR-obfuscated bytecode blob, NOT the FNV/XOR formula. To recover the
 * check an analyst must first devirtualize the embedded VM. The flag is still
 * keyed to the real password bytes (a hash collision yields a garbage flag).
 *
 * (This whole payload is then packed by Lethe: AES-GCM sections, VM-derived
 * rolling key, anti-debug, anti-dump, observation-poison.)
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "check_vm_blob.h"

/* Minimal Daedalus VM (pure-ISA subset). Raw-pointer memory model, like the real
 * interpreter: local_addr/data_addr push real addresses, load/store deref them. */
static int run_vm(const unsigned char *prog, uint32_t prog_len,
                  uint8_t *locals, const uint64_t *args)
{
    uint16_t ds = (uint16_t)(prog[0] | (prog[1] << 8));
    const unsigned char *data = prog + 2;
    const unsigned char *code = prog + 2 + ds;
    uint32_t code_len = prog_len - 2u - ds;
    uint64_t st[64];
    int sp = 0;
    uint32_t pc = 0;
#define PUSH(v) do { if (sp >= 64) return -1; st[sp++] = (uint64_t)(v); } while (0)
#define POP()   (st[--sp])
    while (pc < code_len) {
        unsigned char op = code[pc];
        switch (op) {
        case 0x00: return sp ? (int)st[sp - 1] : -1;                 /* halt */
        case 0x02: PUSH(code[pc + 1]); pc += 2; break;               /* push_imm8 */
        case 0x04: { uint64_t v = 0; int k; for (k = 0; k < 8; k++) v |= (uint64_t)code[pc + 1 + k] << (8 * k); PUSH(v); pc += 9; } break; /* push_imm64 */
        case 0x07: { uint64_t a = POP(), b = POP(); PUSH(a); PUSH(b); } pc += 1; break; /* swap */
        case 0x08: { uint64_t b = POP(), a = POP(); PUSH(a + b); } pc += 1; break;      /* add */
        case 0x0A: { uint64_t b = POP(), a = POP(); PUSH(a ^ b); } pc += 1; break;      /* xor */
        case 0x0B: { uint64_t b = POP(), a = POP(); PUSH(a & b); } pc += 1; break;      /* and */
        case 0x0E: { uint64_t b = POP(), a = POP(); PUSH(a >> (b & 63)); } pc += 1; break; /* shr */
        case 0x0F: { uint64_t b = POP(), a = POP(); PUSH(a * b); } pc += 1; break;      /* mul */
        case 0x10: { uint64_t ad = POP(); PUSH(*(uint8_t *)(uintptr_t)ad); } pc += 1; break;  /* load8 */
        case 0x12: { uint64_t ad = POP(); PUSH(*(uint64_t *)(uintptr_t)ad); } pc += 1; break; /* load64 */
        case 0x13: { uint64_t v = POP(), ad = POP(); *(uint8_t *)(uintptr_t)ad = (uint8_t)v; } pc += 1; break;  /* store8 */
        case 0x15: { uint64_t v = POP(), ad = POP(); *(uint64_t *)(uintptr_t)ad = v; } pc += 1; break;          /* store64 */
        case 0x16: { uint64_t b = POP(), a = POP(); PUSH(a == b ? 1 : 0); } pc += 1; break;   /* cmp_eq */
        case 0x17: { uint64_t b = POP(), a = POP(); PUSH(a < b ? 1 : 0); } pc += 1; break;    /* cmp_lt */
        case 0x18: { uint32_t t = (uint32_t)(code[pc+1] | (code[pc+2]<<8) | (code[pc+3]<<16) | ((uint32_t)code[pc+4]<<24)); pc = t; } break; /* jmp */
        case 0x19: { uint64_t c = POP(); uint32_t t = (uint32_t)(code[pc+1] | (code[pc+2]<<8) | (code[pc+3]<<16) | ((uint32_t)code[pc+4]<<24)); pc = (c == 0) ? t : pc + 5; } break; /* jz */
        case 0x1C: PUSH(args[code[pc + 1]]); pc += 2; break;         /* push_arg */
        case 0x1D: { uint16_t off = (uint16_t)(code[pc+1] | (code[pc+2]<<8)); PUSH((uintptr_t)&locals[off]); pc += 3; } break; /* local_addr */
        case 0x1E: { uint16_t off = (uint16_t)(code[pc+1] | (code[pc+2]<<8)); PUSH((uintptr_t)&data[off]); pc += 3; } break;   /* data_addr */
        case 0x2D: { uint64_t b = POP(), a = POP(); if (!b) return -1; PUSH(a % b); } pc += 1; break; /* mod */
        default: return -1;
        }
    }
    return -1;
#undef PUSH
#undef POP
}

int main(int argc, char **argv)
{
    unsigned char prog[CHECK_VM_LEN];
    uint8_t locals[1024];
    uint64_t args[1];
    unsigned char k;
    int i, n, rc;

    if (argc < 2) { printf("usage: challenge <password>\n"); return 2; }

    /* de-obfuscate the embedded VM program (rolling XOR) */
    k = CHECK_XOR_SEED;
    for (i = 0; i < CHECK_VM_LEN; i++) {
        prog[i] = (unsigned char)(CHECK_VM_OBF[i] ^ k);
        k = (unsigned char)(k * 33 + 7);
    }

    memset(locals, 0, sizeof(locals));
    n = (int)strlen(argv[1]);
    if (n <= 0 || n > 63) { printf("ACCESS DENIED\n"); return 1; }
    memcpy(locals, argv[1], (size_t)n);      /* password -> locals[0..n-1] */
    args[0] = (uint64_t)n;

    rc = run_vm(prog, CHECK_VM_LEN, locals, args);
    if (rc == 0) {
        char flag[CHECK_FLAG_LEN + 1];
        memcpy(flag, locals + CHECK_FLAG_OFF, CHECK_FLAG_LEN);
        flag[CHECK_FLAG_LEN] = 0;
        printf("ACCESS GRANTED: %s\n", flag);
        return 0;
    }
    printf("ACCESS DENIED\n");
    return 1;
}
