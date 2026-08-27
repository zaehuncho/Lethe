/*
 * challenge.c -- Lethe red-team crackme (the owner's own binary, built for
 * a red-team exercise). Objective for the analyst: recover the flag, or the
 * password, or force ACCESS GRANTED. The flag is never stored in plaintext
 * (XOR-veiled with a password-derived keystream); the password is never stored
 * (only its 64-bit FNV-1a digest). A digest collision passes the gate but
 * decodes a GARBAGE flag -- only the real password yields the real flag.
 *
 * This ships inside the Lethe-protected payload: sections AES-256-GCM
 * encrypted at rest, the section key derived by a history-keyed self-decrypting
 * Daedalus VM program (rolling bytecode + MBA arithmetic + per-build opcode
 * shuffle), with anti-debug + anti-dump active.
 */
#include <stdio.h>
#include <string.h>

typedef unsigned long long u64;
typedef unsigned char      u8;

static u64 fnv1a(const u8 *s, int n) {
    u64 h = 0xcbf29ce484222325ULL;
    int i; for (i = 0; i < n; i++) { h ^= s[i]; h *= 0x100000001b3ULL; }
    return h;
}

static u8 ksbyte(const u8 *pw, int n, int i, u64 H) {
    return (u8)(pw[i % n] ^ (u8)(i*37 + 13) ^ (u8)(H >> ((i % 8) * 8)));
}

static const u8  ENC_FLAG[] = { 0x52, 0x41, 0x05, 0xD9, 0x30, 0x6C, 0x09, 0x9A, 0x15, 0x5F, 0x47, 0x65, 0x30, 0x7B, 0xAB, 0xE4, 0x7B, 0xC4, 0xA5, 0x58, 0x1C, 0xB8, 0x9F, 0xBB, 0xF9, 0xEC, 0xDD, 0x2F, 0xF5, 0xDB, 0xA7, 0x34, 0xFB, 0x90, 0x9C, 0xDF, 0xFC, 0x9A, 0x3B, 0x62, 0xA0, 0xD1, 0x2B, 0xC5, 0xDF, 0x5B, 0x4B, 0x09, 0x9B, 0x67, 0x2A, 0xE7 };
static const int FLAG_LEN   = 52;
static const u64 EXPECTED_H = 0xCCE6FCACC03B4421ULL;

int main(int argc, char **argv) {
    if (argc < 2) { printf("usage: challenge <password>\n"); return 2; }
    {
        const u8 *pw = (const u8 *)argv[1];
        int n = (int)strlen(argv[1]);
        u64 H;
        if (n <= 0) { printf("ACCESS DENIED\n"); return 1; }
        H = fnv1a(pw, n);
        if (H != EXPECTED_H) { printf("ACCESS DENIED\n"); return 1; }
        {
            u8 out[128]; int i;
            for (i = 0; i < FLAG_LEN && i < 127; i++)
                out[i] = (u8)(ENC_FLAG[i] ^ ksbyte(pw, n, i, H));
            out[i] = 0;
            printf("ACCESS GRANTED: %s\n", out);
        }
    }
    return 0;
}
