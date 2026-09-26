/*
 * daedalus_rolling.c -- runtime decoder for history-keyed self-decrypting Daedalus
 * bytecode. See daedalus_rolling.h and the pack-time oracle
 * daedalus/daedalus_rolling.py.
 *
 * Bit-exact primitives (mirror of the .py):
 *   resync(seed, leader)    = u64le( SHA256(seed16 ‖ 'R' ‖ u32le(leader))[0:8] )
 *   keystream(seed, pc, acc)= SHA256(seed16 ‖ 'K' ‖ u32le(pc) ‖ u64le(acc))
 *   fold(acc, plain, pc):
 *       for x in plain: acc = rotl64(acc ^ x, 7) + 0x9E3779B97F4A7C15  (mod 2^64)
 *       acc ^= u32(pc)
 *
 * Freestanding / no-CRT: crypto_sha256 + local byte loops only.
 *
 * Compiled only when DVM_ROLLING is defined (see CMakeLists.txt gate).
 */
#ifdef DVM_ROLLING

#include "daedalus_rolling.h"
#include "crypto.h"   /* crypto_sha256 */
#ifdef DVM_ROLL_POISON
#include <intrin.h>   /* __readgsqword for the PEB read */
#endif

#define DVM_ROLL_GOLDEN 0x9E3779B97F4A7C15ULL

/* Operand width by CANONICAL opcode byte (post-unmap). Everything not listed
 * is 0. Must match daedalus_disasm.OPCODE_TABLE widths. A switch (not a
 * designated-initializer table) keeps this portable across every MSVC C mode. */
static uint32_t dvm_roll_width(uint8_t canon_op)
{
    switch (canon_op) {
    case 0x02: return 1;  /* push_imm8  */
    case 0x03: return 4;  /* push_imm32 */
    case 0x04: return 8;  /* push_imm64 */
    case 0x18: return 4;  /* jmp   */
    case 0x19: return 4;  /* jz    */
    case 0x1A: return 4;  /* jnz   */
    case 0x1B: return 4;  /* call  */
    case 0x1C: return 1;  /* push_arg   */
    case 0x1D: return 2;  /* local_addr */
    case 0x1E: return 2;  /* data_addr  */
    case 0x33: return 2;  /* push_imm16 */
    case 0x37: return 1;  /* pick  */
    default:   return 0;
    }
}

/* 1 iff `op` is a defined opcode (canonical byte). Range-based: the ISA is a
 * contiguous 0x00..0x38 today; a byte outside that is a decode fault.
 *
 * NOTE (rolling vs decoys): shuffled builds can mint DECOY opcodes that unmap to
 * canonical 0x80..0x90. Those are NOT supported inside a rolling container --
 * both sides fail CLOSED: the pack-time encoder (generate_programs) omits decoys
 * from its optable and raises on an unknown wire byte, and this runtime check
 * returns -1 (bad opcode) rather than executing one. Rolling and decoy-insertion
 * are therefore mutually exclusive; enabling both must widen this range and the
 * encoder optable together. */
static int dvm_roll_opcode_valid(uint8_t op)
{
    return op <= 0x38;
}

#ifdef DVM_SHUFFLED
#include "daedalus_opcodes_shuffled.h"   /* DVM_OPCODE_UNMAP[256] */
#endif

static uint64_t rotl64(uint64_t v, unsigned r)
{
    r &= 63u;
    return (v << r) | (v >> ((64u - r) & 63u));
}

static void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void put_u64le(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t load_u64le(const uint8_t *p)
{
    uint64_t v = 0; int i;
    for (i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

uint64_t dvm_roll_resync(const uint8_t seed[DVM_ROLL_SEED_LEN], uint32_t leader)
{
    uint8_t buf[DVM_ROLL_SEED_LEN + 1 + 4];
    uint8_t dig[32];
    int i;
    for (i = 0; i < DVM_ROLL_SEED_LEN; i++) buf[i] = seed[i];
    buf[DVM_ROLL_SEED_LEN] = 'R';
    put_u32le(buf + DVM_ROLL_SEED_LEN + 1, leader);
    if (crypto_sha256(buf, sizeof(buf), dig) != 0) return 0;
    return load_u64le(dig);
}

/* keystream(seed, pc, acc) -> first DVM_ROLL_MAX_INSTR bytes of the SHA256. */
static int dvm_roll_keystream(const uint8_t seed[DVM_ROLL_SEED_LEN],
                              uint32_t pc, uint64_t acc,
                              uint8_t out[DVM_ROLL_MAX_INSTR])
{
    uint8_t buf[DVM_ROLL_SEED_LEN + 1 + 4 + 8];
    uint8_t dig[32];
    int i;
    for (i = 0; i < DVM_ROLL_SEED_LEN; i++) buf[i] = seed[i];
    buf[DVM_ROLL_SEED_LEN] = 'K';
    put_u32le(buf + DVM_ROLL_SEED_LEN + 1, pc);
    put_u64le(buf + DVM_ROLL_SEED_LEN + 1 + 4, acc);
    if (crypto_sha256(buf, sizeof(buf), dig) != 0) return -1;
    for (i = 0; i < DVM_ROLL_MAX_INSTR; i++) out[i] = dig[i];
    return 0;
}

uint64_t dvm_roll_fold(uint64_t acc, const uint8_t *plain, uint32_t len,
                       uint32_t pc)
{
    uint32_t i;
    for (i = 0; i < len; i++) {
        acc = rotl64(acc ^ (uint64_t)plain[i], 7);
        acc = acc + DVM_ROLL_GOLDEN;
    }
    acc ^= (uint64_t)pc;
    return acc;
}

void dvm_rolling_init(VvmRolling *r, const uint8_t *code_ct, uint32_t ct_len,
                      const uint8_t seed[DVM_ROLL_SEED_LEN],
                      const uint8_t *leaders, uint16_t n_leaders)
{
    int i;
    r->ct = code_ct;
    r->ct_len = ct_len;
    for (i = 0; i < DVM_ROLL_SEED_LEN; i++) r->seed[i] = seed[i];
    r->leaders = leaders;
    r->n_leaders = n_leaders;
    r->acc = 0;
}

/* leaders is a packed LE u32 array, possibly unaligned -> byte-wise load. */
static uint32_t dvm_roll_leader_at(const VvmRolling *r, uint16_t i)
{
    const uint8_t *p = r->leaders + (size_t)i * 4u;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int dvm_roll_is_leader(const VvmRolling *r, uint32_t pc)
{
    uint16_t i;
    for (i = 0; i < r->n_leaders; i++) {
        if (dvm_roll_leader_at(r, i) == pc) return 1;
    }
    return 0;
}

/*
 * OBSERVATION-POISON (DVM_ROLL_POISON): fold an anti-instrumentation signal into
 * the per-block accumulator so it corrupts decode -- the "beyond VMProtect" move.
 *
 * The signal is ZERO on every honest run, so a clean execution is byte-identical
 * to the pack-time encoder (which assumes 0) and works normally. Under a
 * user-mode debugger the signal is non-zero; it is avalanche-spread across all
 * 64 bits and XORed into the block seed, so EVERY instruction in the block
 * decodes to garbage -> the VM computes the wrong key -> section decrypt fails,
 * with NO branch to NOP (the check is arithmetic, folded into the key path).
 *
 * Zero-FP by construction: PEB->BeingDebugged is 0 in normal execution and is
 * only set while a user-mode debugger is attached. (Stealth debuggers that clear
 * it win this check -- the honest limitation, same as any anti-debug -- but a
 * naive x64dbg/Frida-spawn session silently mis-keys with nothing to patch.)
 * Kill-switch: the whole thing compiles out when DVM_ROLL_POISON is undefined.
 */
static uint64_t dvm_roll_env_poison(void)
{
#ifdef DVM_ROLL_POISON
    const unsigned char *peb = (const unsigned char *)__readgsqword(0x60);
    uint64_t p = 0;
    if (peb)
        p |= (uint64_t)peb[0x002];          /* BeingDebugged: 0 on a clean run */
    if (p) {                                /* avalanche a 1-bit signal to 64b  */
        p ^= 0x9E3779B97F4A7C15ULL;
        p *= 0xFF51AFD7ED558CCDULL;
        p ^= (p >> 33);
    }
    return p;                               /* 0 clean -> no effect on decode   */
#else
    return 0;
#endif
}

int dvm_rolling_fetch(VvmRolling *r, uint32_t pc,
                      uint8_t out_plain[DVM_ROLL_MAX_INSTR], uint32_t *out_len)
{
    uint8_t ks[DVM_ROLL_MAX_INSTR];
    uint8_t wire_op, canon_op;
    uint32_t width, ilen, i;

    if (pc >= r->ct_len) return -1;
    if (dvm_roll_is_leader(r, pc))
        r->acc = dvm_roll_resync(r->seed, pc) ^ dvm_roll_env_poison();
    if (dvm_roll_keystream(r->seed, pc, r->acc, ks) != 0) return -1;

    /* decrypt the opcode first, determine width, then the operands */
    wire_op = (uint8_t)(r->ct[pc] ^ ks[0]);
#ifdef DVM_SHUFFLED
    canon_op = DVM_OPCODE_UNMAP[wire_op];
#else
    canon_op = wire_op;
#endif
    if (!dvm_roll_opcode_valid(canon_op)) return -1;
    width = dvm_roll_width(canon_op);
    ilen = 1u + width;
    if ((uint64_t)pc + ilen > (uint64_t)r->ct_len) return -1;

    for (i = 0; i < ilen; i++)
        out_plain[i] = (uint8_t)(r->ct[pc + i] ^ ks[i]);

    /* fold this instruction's plaintext so the next fetch in the block chains */
    r->acc = dvm_roll_fold(r->acc, out_plain, ilen, pc);
    *out_len = ilen;
    /* wipe the local keystream (derived material) -- not elided (volatile). */
    {
        volatile uint8_t *z = (volatile uint8_t *)ks;
        uint32_t i2;
        for (i2 = 0; i2 < DVM_ROLL_MAX_INSTR; i2++) z[i2] = 0;
    }
    return 0;
}

#ifdef DVM_ROLLING_V2
/* ====================================================================== *
 *  ROLLING v2 -- whole-program integrity chaining ('VS' container)        *
 *  Bit-exact mirror of daedalus/daedalus_rolling.py (chain_digest,        *
 *  resync2, effective_seed, compute_chain, RollingDecoderV2).             *
 * ====================================================================== */

/* Domain 'C'. Byte-loop-fold the ciphertext block into a 64-bit accumulator
 * seeded with prev_chain, then bind with one SHA256 over a fixed-size buffer
 * (no unbounded stack buffer in the freestanding stub). */
uint64_t dvm_roll_chain(const uint8_t seed[DVM_ROLL_SEED_LEN],
                        uint64_t prev_chain,
                        const uint8_t *ct_block, uint32_t block_len)
{
    uint8_t buf[DVM_ROLL_SEED_LEN + 1 + 8 + 8];
    uint8_t dig[32];
    uint64_t acc = prev_chain;
    uint32_t i;
    for (i = 0; i < block_len; i++) {
        acc = rotl64(acc ^ (uint64_t)ct_block[i], 7);
        acc = acc + DVM_ROLL_GOLDEN;
    }
    for (i = 0; i < DVM_ROLL_SEED_LEN; i++) buf[i] = seed[i];
    buf[DVM_ROLL_SEED_LEN] = 'C';
    put_u64le(buf + DVM_ROLL_SEED_LEN + 1, prev_chain);
    put_u64le(buf + DVM_ROLL_SEED_LEN + 1 + 8, acc);
    if (crypto_sha256(buf, sizeof(buf), dig) != 0) return 0;
    return load_u64le(dig);
}

/* v1 resync plus the whole-program chain. `seed` is the effective seed. */
uint64_t dvm_roll_resync2(const uint8_t seed[DVM_ROLL_SEED_LEN],
                          uint32_t leader, uint64_t chain)
{
    uint8_t buf[DVM_ROLL_SEED_LEN + 1 + 4 + 8];
    uint8_t dig[32];
    int i;
    for (i = 0; i < DVM_ROLL_SEED_LEN; i++) buf[i] = seed[i];
    buf[DVM_ROLL_SEED_LEN] = 'R';
    put_u32le(buf + DVM_ROLL_SEED_LEN + 1, leader);
    put_u64le(buf + DVM_ROLL_SEED_LEN + 1 + 4, chain);
    if (crypto_sha256(buf, sizeof(buf), dig) != 0) return 0;
    return load_u64le(dig);
}

int dvm_rolling_init_v2(VvmRolling *r, const uint8_t *code_ct, uint32_t ct_len,
                        const uint8_t seed[DVM_ROLL_SEED_LEN],
                        const uint8_t whiten[DVM_ROLL_SEED_LEN],
                        const uint8_t *leaders, uint16_t n_leaders)
{
    uint32_t i;
    uint64_t acc;

    dvm_rolling_init(r, code_ct, ct_len, seed, leaders, n_leaders);
    r->v2 = 1;
    for (i = 0; i < DVM_ROLL_SEED_LEN; i++) r->whiten[i] = whiten[i];

    /* fail closed if the container declares more leaders than the compile cap */
    if ((uint32_t)n_leaders > DVM_ROLL_MAX_LEADERS) return -1;

    /* precompute chain[i] over the CIPHERTEXT blocks in static offset order --
     * a path-independent function of the stored blob, no decoding required. */
    acc = 0;
    for (i = 0; i < (uint32_t)n_leaders; i++) {
        uint32_t start = dvm_roll_leader_at(r, (uint16_t)i);
        uint32_t end = ((i + 1u) < (uint32_t)n_leaders)
                       ? dvm_roll_leader_at(r, (uint16_t)(i + 1u))
                       : ct_len;
        r->chain[i] = acc;
        if (start > ct_len || end > ct_len || start > end)
            return -1;                 /* malformed leader -> fail closed */
        acc = dvm_roll_chain(r->seed, acc, code_ct + start, end - start);
    }
    return 0;
}

int dvm_rolling_fetch_v2(VvmRolling *r, uint32_t pc,
                         uint8_t out_plain[DVM_ROLL_MAX_INSTR],
                         uint32_t *out_len)
{
    uint8_t ks[DVM_ROLL_MAX_INSTR];
    uint8_t eff[DVM_ROLL_SEED_LEN];
    uint8_t wire_op, canon_op;
    uint32_t width, ilen, i;

    if (pc >= r->ct_len) return -1;

    for (i = 0; i < DVM_ROLL_SEED_LEN; i++)
        eff[i] = (uint8_t)(r->seed[i] ^ r->whiten[i]);

    if (dvm_roll_is_leader(r, pc)) {
        uint16_t li;
        int found = 0;
        uint64_t ch = 0;
        for (li = 0; li < r->n_leaders; li++) {
            if (dvm_roll_leader_at(r, li) == pc) {
                ch = r->chain[li];
                found = 1;
                break;
            }
        }
        if (!found) return -1;         /* leader index lost -> fail closed */
        r->acc = dvm_roll_resync2(eff, pc, ch) ^ dvm_roll_env_poison();
    }
    if (dvm_roll_keystream(eff, pc, r->acc, ks) != 0) return -1;

    wire_op = (uint8_t)(r->ct[pc] ^ ks[0]);
#ifdef DVM_SHUFFLED
    canon_op = DVM_OPCODE_UNMAP[wire_op];
#else
    canon_op = wire_op;
#endif
    if (!dvm_roll_opcode_valid(canon_op)) return -1;
    width = dvm_roll_width(canon_op);
    ilen = 1u + width;
    if ((uint64_t)pc + ilen > (uint64_t)r->ct_len) return -1;

    for (i = 0; i < ilen; i++)
        out_plain[i] = (uint8_t)(r->ct[pc + i] ^ ks[i]);

    r->acc = dvm_roll_fold(r->acc, out_plain, ilen, pc);
    *out_len = ilen;

    /* wipe derived material (keystream + effective seed) -- not elided. */
    {
        volatile uint8_t *z = (volatile uint8_t *)ks;
        volatile uint8_t *ze = (volatile uint8_t *)eff;
        uint32_t i2;
        for (i2 = 0; i2 < DVM_ROLL_MAX_INSTR; i2++) z[i2] = 0;
        for (i2 = 0; i2 < DVM_ROLL_SEED_LEN; i2++) ze[i2] = 0;
    }
    return 0;
}
#endif /* DVM_ROLLING_V2 */

/* ---- self-test: bit-exact agreement with the Python oracle -------------- */
int dvm_rolling_selftest(void)
{
    uint8_t seed[16];
    int i;
    for (i = 0; i < 16; i++) seed[i] = (uint8_t)i;

    /* pinned vectors (see daedalus_rolling.py output baked into the harness) */
    if (dvm_roll_resync(seed, 0) != 0x0E17E9881DD39855ULL) return -1;
    if (dvm_roll_resync(seed, 7) != 0xA30D3A759BCBB752ULL) return -1;
    {
        uint8_t two[2]; two[0] = 1; two[1] = 2;
        if (dvm_roll_fold(0, two, 2, 0) != 0xB9F456792488C7E4ULL) return -1;
    }
    {
        uint8_t thr[3]; thr[0] = 2; thr[1] = 9; thr[2] = 9;
        if (dvm_roll_fold(dvm_roll_resync(seed, 0), thr, 3, 0)
            != 0xC96670BECE6DEDEFULL) return -1;
    }
    {
        uint8_t ks[DVM_ROLL_MAX_INSTR];
        if (dvm_roll_keystream(seed, 0, dvm_roll_resync(seed, 0), ks) != 0)
            return -1;
        if (ks[0] != 0x26 || ks[1] != 0x19 || ks[2] != 0x83 || ks[3] != 0xB3)
            return -1;
    }
#ifdef DVM_ROLLING_V2
    /* pinned v2 vectors (seed = 0..15; mirror daedalus_rolling.py exactly).
     * Any drift here bricks the build at init (fail-fast in stub_main.c),
     * so a ported primitive can never silently mis-decode. */
    {
        uint8_t blk3[3];
        uint8_t blk2[2];
        uint64_t c0, c1;
        blk3[0] = 1; blk3[1] = 2; blk3[2] = 3;
        blk2[0] = 4; blk2[1] = 5;
        c0 = dvm_roll_chain(seed, 0, blk3, 3);
        if (c0 != 0x4E6E010263A69610ULL) return -1;
        c1 = dvm_roll_chain(seed, c0, blk2, 2);
        if (c1 != 0xD3CCB4E0E11B886DULL) return -1;
        if (dvm_roll_resync2(seed, 0, 0) != 0xB021B17DF773C886ULL) return -1;
        if (dvm_roll_resync2(seed, 7, c0) != 0x70B929A49C334A8DULL) return -1;
        /* effective seed (seed XOR whiten=0xF0..) + a v2 keystream tie-in */
        {
            uint8_t eff[DVM_ROLL_SEED_LEN];
            uint8_t ks2[DVM_ROLL_MAX_INSTR];
            uint64_t r2b = dvm_roll_resync2(seed, 7, c0);
            int j;
            for (j = 0; j < DVM_ROLL_SEED_LEN; j++)
                eff[j] = (uint8_t)(seed[j] ^ 0xF0);
            if (eff[0] != 0xF0 || eff[1] != 0xF1 ||
                eff[2] != 0xF2 || eff[3] != 0xF3) return -1;
            if (dvm_roll_keystream(eff, 7, r2b, ks2) != 0) return -1;
            if (ks2[0] != 0x4B || ks2[1] != 0x9A ||
                ks2[2] != 0xB2 || ks2[3] != 0xD0) return -1;
        }
    }
#endif
    return 0;
}

#endif /* DVM_ROLLING */
