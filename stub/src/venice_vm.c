/*
 * venice_vm.c -- Venice VM (VVM) interpreter for the Lethe stub.
 *
 * A stack-based bytecode machine used to virtualize the stub's crypto-critical
 * paths (key derivation, shard XOR fold, key scattering). The dispatch loop is
 * intentionally generic: all domain knowledge lives in the (encrypted) bytecode
 * a builder emits, not in readable x64 here.
 *
 * Freestanding / no-CRT context (mirrors crypto.c / key_scatter.c):
 *   - No memcpy/memset/malloc/printf. Copies and zeroing are byte loops.
 *   - Sensitive wipes use `volatile uint8_t *` so the compiler cannot elide
 *     them (dead-store elimination).
 *   - All VM state is stack-allocated (the VeniceVM struct is ~0.8 KB).
 *   - The VM trusts its own bytecode for pointer/length values: memory ops
 *     just cast and dereference. Only structural invariants (stack depth, code
 *     bounds, jump targets, div-by-zero) are checked; on violation exec fails.
 */

#include "venice_vm.h"
#include "crypto.h"       /* crypto_sha256, crypto_hkdf_sha256 (pulls pack_info.h) */
#include "key_scatter.h"  /* key_scatter_init                                      */

#ifdef VVM_SHUFFLED
#include "venice_opcodes_shuffled.h"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>      /* GetEnvironmentVariableA, SetEnvironmentVariableA      */

/* Forward-declare the MASM trampoline for N_CALL_PTR (venice_trampoline.asm). */
extern uint64_t venice_trampoline_call(void *func, int argc, const uint64_t *argv);

/* ---- tiny local helpers (no CRT) ---------------------------------------- */

/* Push v onto the operand stack. Returns 0 on success, 1 on overflow. */
static __forceinline int vvm_push(VeniceVM *vm, uint64_t v)
{
    if (vm->sp >= VVM_STACK_SIZE)
        return 1;
    vm->stack[vm->sp++] = v;
    return 0;
}

/* Pop TOS into *out. Returns 0 on success, 1 on underflow. */
static __forceinline int vvm_pop(VeniceVM *vm, uint64_t *out)
{
    if (vm->sp <= 0)
        return 1;
    *out = vm->stack[--vm->sp];
    return 0;
}

/* 1 if the instruction at pc has `total_len` bytes (opcode + operands) in
 * range; 0 if reading its operands would run past the end of code. */
static __forceinline int vvm_have(const VeniceVM *vm, uint32_t total_len)
{
    return ((uint64_t)vm->pc + total_len) <= (uint64_t)vm->code_size;
}

static __forceinline uint16_t vvm_rd_u16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static __forceinline uint32_t vvm_rd_u32(const uint8_t *p)
{
    return  (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static __forceinline uint64_t vvm_rd_u64(const uint8_t *p)
{
    return (uint64_t)vvm_rd_u32(p) | ((uint64_t)vvm_rd_u32(p + 4) << 32);
}

/* ---- interpreter -------------------------------------------------------- */

static int vvm_run(VeniceVM *vm)
{
    while (1) {
        uint8_t op;
        const uint8_t *ip;   /* plaintext of the CURRENT instruction         */
#ifdef VVM_ROLLING
        uint8_t vvm_win[VVM_ROLL_MAX_INSTR];
#endif

        if (vm->pc >= vm->code_size)
            return -1;                       /* ran past code without HALT   */

#ifdef VVM_ROLLING
        if (vm->rolling) {
            uint32_t vvm_ilen;
            /* Reconstruct just this instruction from the history-keyed
             * ciphertext; a mid-block start, byte flip or wrong seed faults. */
            if (vvm_rolling_fetch(&vm->roll, vm->pc, vvm_win, &vvm_ilen) != 0)
                return -1;
            ip = vvm_win;
        } else {
            ip = vm->code + vm->pc;
        }
#else
        ip = vm->code + vm->pc;
#endif
        op = ip[0];
#ifdef VVM_SHUFFLED
        op = VVM_OPCODE_UNMAP[op];
#endif

        switch (op) {

        /* ---- stack manipulation --------------------------------------- */
        case VVM_HALT: {
            uint64_t v;
            if (vvm_pop(vm, &v)) return -1;
#ifdef VVM_ROLLING
            /* wipe the last decoded instruction's plaintext window on the way
             * out (the normal exit) so no instruction plaintext lingers. */
            {
                volatile uint8_t *z = (volatile uint8_t *)vvm_win;
                int wi;
                for (wi = 0; wi < VVM_ROLL_MAX_INSTR; wi++) z[wi] = 0;
            }
#endif
            return (int)v;
        }
        case VVM_NOP:
            vm->pc += 1;
            break;
        case VVM_PUSH_IMM8:
            if (!vvm_have(vm, 2)) return -1;
            if (vvm_push(vm, (uint64_t)ip[1])) return -1;
            vm->pc += 2;
            break;
        case VVM_PUSH_IMM32:
            if (!vvm_have(vm, 5)) return -1;
            if (vvm_push(vm, (uint64_t)vvm_rd_u32(ip + 1)))
                return -1;
            vm->pc += 5;
            break;
        case VVM_PUSH_IMM64:
            if (!vvm_have(vm, 9)) return -1;
            if (vvm_push(vm, vvm_rd_u64(ip + 1))) return -1;
            vm->pc += 9;
            break;
        case VVM_POP: {
            uint64_t t;
            if (vvm_pop(vm, &t)) return -1;
            vm->pc += 1;
            break;
        }
        case VVM_DUP: {
            uint64_t t;
            if (vvm_pop(vm, &t)) return -1;
            if (vvm_push(vm, t)) return -1;
            if (vvm_push(vm, t)) return -1;
            vm->pc += 1;
            break;
        }
        case VVM_SWAP: {
            uint64_t a, b;
            if (vvm_pop(vm, &b) || vvm_pop(vm, &a)) return -1;
            if (vvm_push(vm, b) || vvm_push(vm, a)) return -1;
            vm->pc += 1;
            break;
        }

        /* ---- arithmetic ----------------------------------------------- */
        case VVM_ADD: case VVM_SUB: case VVM_XOR: case VVM_AND:
        case VVM_OR:  case VVM_SHL: case VVM_SHR: case VVM_MUL: {
            uint64_t a, b, r;
            if (vvm_pop(vm, &b) || vvm_pop(vm, &a)) return -1;
            switch (op) {
            case VVM_ADD: r = a + b;  break;
            case VVM_SUB: r = a - b;  break;
            case VVM_XOR: r = a ^ b;  break;
            case VVM_AND: r = a & b;  break;
            case VVM_OR:  r = a | b;  break;
            /* Mask the shift count to 6 bits: shifting a uint64_t by >= 64 is
             * C undefined behavior, and the reference oracle (venice_ref.py)
             * masks with (b & 63) -- match it so C and Python never diverge. */
            case VVM_SHL: r = a << (b & 63); break;
            case VVM_SHR: r = a >> (b & 63); break;
            default:      r = a * b;  break;    /* VVM_MUL */
            }
            if (vvm_push(vm, r)) return -1;
            vm->pc += 1;
            break;
        }

        /* ---- memory --------------------------------------------------- */
        case VVM_LOAD8: {
            uint64_t addr;
            if (vvm_pop(vm, &addr)) return -1;
            if (vvm_push(vm, (uint64_t)*(const uint8_t *)(uintptr_t)addr))
                return -1;
            vm->pc += 1;
            break;
        }
        case VVM_LOAD32: {
            uint64_t addr;
            if (vvm_pop(vm, &addr)) return -1;
            if (vvm_push(vm, (uint64_t)*(const uint32_t *)(uintptr_t)addr))
                return -1;
            vm->pc += 1;
            break;
        }
        case VVM_LOAD64: {
            uint64_t addr;
            if (vvm_pop(vm, &addr)) return -1;
            if (vvm_push(vm, *(const uint64_t *)(uintptr_t)addr)) return -1;
            vm->pc += 1;
            break;
        }
        case VVM_STORE8: {
            uint64_t addr, val;
            if (vvm_pop(vm, &val) || vvm_pop(vm, &addr)) return -1;
            *(uint8_t *)(uintptr_t)addr = (uint8_t)val;
            vm->pc += 1;
            break;
        }
        case VVM_STORE32: {
            uint64_t addr, val;
            if (vvm_pop(vm, &val) || vvm_pop(vm, &addr)) return -1;
            *(uint32_t *)(uintptr_t)addr = (uint32_t)val;
            vm->pc += 1;
            break;
        }
        case VVM_STORE64: {
            uint64_t addr, val;
            if (vvm_pop(vm, &val) || vvm_pop(vm, &addr)) return -1;
            *(uint64_t *)(uintptr_t)addr = val;
            vm->pc += 1;
            break;
        }

        /* ---- comparison ----------------------------------------------- */
        case VVM_CMP_EQ: {
            uint64_t a, b;
            if (vvm_pop(vm, &b) || vvm_pop(vm, &a)) return -1;
            if (vvm_push(vm, (uint64_t)(a == b ? 1u : 0u))) return -1;
            vm->pc += 1;
            break;
        }
        case VVM_CMP_LT: {
            uint64_t a, b;
            if (vvm_pop(vm, &b) || vvm_pop(vm, &a)) return -1;
            if (vvm_push(vm, (uint64_t)(a < b ? 1u : 0u))) return -1;
            vm->pc += 1;
            break;
        }

        /* ---- control flow --------------------------------------------- */
        case VVM_JMP: {
            uint32_t target;
            if (!vvm_have(vm, 5)) return -1;
            target = vvm_rd_u32(ip + 1);
            if (target >= vm->code_size) return -1;
            vm->pc = target;
            break;
        }
        case VVM_JZ: {
            uint64_t cond;
            uint32_t target;
            if (!vvm_have(vm, 5)) return -1;
            if (vvm_pop(vm, &cond)) return -1;
            target = vvm_rd_u32(ip + 1);
            if (target >= vm->code_size) return -1;
            if (cond == 0) vm->pc = target;
            else           vm->pc += 5;
            break;
        }
        case VVM_JNZ: {
            uint64_t cond;
            uint32_t target;
            if (!vvm_have(vm, 5)) return -1;
            if (vvm_pop(vm, &cond)) return -1;
            target = vvm_rd_u32(ip + 1);
            if (target >= vm->code_size) return -1;
            if (cond != 0) vm->pc = target;
            else           vm->pc += 5;
            break;
        }

        /* ---- data access ---------------------------------------------- */
        case VVM_PUSH_ARG: {
            uint8_t idx;
            if (!vvm_have(vm, 2)) return -1;
            idx = ip[1];
            if (idx >= 8 || (int)idx >= vm->arg_count) return -1;
            if (vvm_push(vm, vm->args[idx])) return -1;
            vm->pc += 2;
            break;
        }
        case VVM_LOCAL_ADDR: {
            uint16_t off;
            if (!vvm_have(vm, 3)) return -1;
            off = vvm_rd_u16(ip + 1);
            if (off >= VVM_LOCAL_SIZE) return -1;
            if (vvm_push(vm, (uint64_t)(uintptr_t)&vm->locals[off])) return -1;
            vm->pc += 3;
            break;
        }
        case VVM_DATA_ADDR: {
            uint16_t off;
            if (!vvm_have(vm, 3)) return -1;
            off = vvm_rd_u16(ip + 1);
            if (off >= vm->data_size) return -1;
            if (vvm_push(vm, (uint64_t)(uintptr_t)&vm->data[off])) return -1;
            vm->pc += 3;
            break;
        }

        /* ---- native crypto operations --------------------------------- */
        case VVM_N_SHA256: {
            uint64_t data, len, out;
            int r;
            if (vvm_pop(vm, &out) || vvm_pop(vm, &len) || vvm_pop(vm, &data))
                return -1;
            r = crypto_sha256((const void *)(uintptr_t)data, (size_t)len,
                              (uint8_t *)(uintptr_t)out);
            if (vvm_push(vm, (uint64_t)r)) return -1;
            vm->pc += 1;
            break;
        }
        case VVM_N_HKDF: {
            uint64_t ikm, ikm_len, salt, salt_len, info, info_len, out, out_len;
            int r;
            if (vvm_pop(vm, &out_len) || vvm_pop(vm, &out) ||
                vvm_pop(vm, &info_len) || vvm_pop(vm, &info) ||
                vvm_pop(vm, &salt_len) || vvm_pop(vm, &salt) ||
                vvm_pop(vm, &ikm_len) || vvm_pop(vm, &ikm))
                return -1;
            r = crypto_hkdf_sha256(
                    (const uint8_t *)(uintptr_t)ikm,  (size_t)ikm_len,
                    (const uint8_t *)(uintptr_t)salt, (size_t)salt_len,
                    (const uint8_t *)(uintptr_t)info, (size_t)info_len,
                    (uint8_t *)(uintptr_t)out,        (size_t)out_len);
            if (vvm_push(vm, (uint64_t)r)) return -1;
            vm->pc += 1;
            break;
        }
        case VVM_N_XOR_BUF: {
            uint64_t dst, src_a, src_b, len, i;
            uint8_t *d;
            const uint8_t *a, *b;
            if (vvm_pop(vm, &len) || vvm_pop(vm, &src_b) ||
                vvm_pop(vm, &src_a) || vvm_pop(vm, &dst))
                return -1;
            d = (uint8_t *)(uintptr_t)dst;
            a = (const uint8_t *)(uintptr_t)src_a;
            b = (const uint8_t *)(uintptr_t)src_b;
            for (i = 0; i < len; i++)
                d[i] = (uint8_t)(a[i] ^ b[i]);
            vm->pc += 1;
            break;
        }
        case VVM_N_GETENV: {
            uint64_t name, buf, bufsize;
            DWORD written;
            if (vvm_pop(vm, &bufsize) || vvm_pop(vm, &buf) || vvm_pop(vm, &name))
                return -1;
            written = GetEnvironmentVariableA((LPCSTR)(uintptr_t)name,
                                              (LPSTR)(uintptr_t)buf,
                                              (DWORD)bufsize);
            if (vvm_push(vm, (uint64_t)written)) return -1;
            vm->pc += 1;
            break;
        }
        case VVM_N_SETENV_NULL: {
            uint64_t name;
            if (vvm_pop(vm, &name)) return -1;
            SetEnvironmentVariableA((LPCSTR)(uintptr_t)name, NULL);
            vm->pc += 1;
            break;
        }
        case VVM_N_HEX_DECODE: {
            uint64_t hex, hex_len, out, i;
            const uint8_t *h;
            uint8_t *o;
            if (vvm_pop(vm, &out) || vvm_pop(vm, &hex_len) || vvm_pop(vm, &hex))
                return -1;
            h = (const uint8_t *)(uintptr_t)hex;
            o = (uint8_t *)(uintptr_t)out;
            for (i = 0; i < hex_len / 2; i++) {
                uint8_t hi = h[2 * i];
                uint8_t lo = h[2 * i + 1];
                hi = (uint8_t)((hi >= 'a') ? hi - 'a' + 10 :
                               (hi >= 'A') ? hi - 'A' + 10 : hi - '0');
                lo = (uint8_t)((lo >= 'a') ? lo - 'a' + 10 :
                               (lo >= 'A') ? lo - 'A' + 10 : lo - '0');
                o[i] = (uint8_t)((hi << 4) | lo);
            }
            vm->pc += 1;
            break;
        }
        case VVM_N_ZERO_MEM: {
            uint64_t ptr, len, i;
            volatile uint8_t *p;
            if (vvm_pop(vm, &len) || vvm_pop(vm, &ptr)) return -1;
            p = (volatile uint8_t *)(uintptr_t)ptr;
            for (i = 0; i < len; i++)
                p[i] = 0;
            vm->pc += 1;
            break;
        }
        case VVM_N_SCATTER_INIT: {
            uint64_t key;
            int r;
            if (vvm_pop(vm, &key)) return -1;
            r = key_scatter_init((uint8_t *)(uintptr_t)key);
            if (vvm_push(vm, (uint64_t)r)) return -1;
            vm->pc += 1;
            break;
        }
        case VVM_N_COPY_MEM: {
            uint64_t dst, src, len, i;
            uint8_t *d;
            const uint8_t *s;
            if (vvm_pop(vm, &len) || vvm_pop(vm, &src) || vvm_pop(vm, &dst))
                return -1;
            d = (uint8_t *)(uintptr_t)dst;
            s = (const uint8_t *)(uintptr_t)src;
            for (i = 0; i < len; i++)
                d[i] = s[i];
            vm->pc += 1;
            break;
        }
        case VVM_N_XOR_REPEAT: {
            uint64_t dst, src, repeat_len, total_len, i;
            uint8_t *d;
            const uint8_t *s;
            if (vvm_pop(vm, &total_len) || vvm_pop(vm, &repeat_len) ||
                vvm_pop(vm, &src) || vvm_pop(vm, &dst))
                return -1;
            if (repeat_len == 0) return -1;         /* guard % by zero */
            d = (uint8_t *)(uintptr_t)dst;
            s = (const uint8_t *)(uintptr_t)src;
            for (i = 0; i < total_len; i++)
                d[i] = (uint8_t)(d[i] ^ s[i % repeat_len]);
            vm->pc += 1;
            break;
        }
        case VVM_N_XOR_CONST: {
            uint64_t buf, len, byte_val, i;
            uint8_t *b;
            uint8_t bv;
            if (vvm_pop(vm, &byte_val) || vvm_pop(vm, &len) || vvm_pop(vm, &buf))
                return -1;
            b  = (uint8_t *)(uintptr_t)buf;
            bv = (uint8_t)byte_val;
            for (i = 0; i < len; i++)
                b[i] = (uint8_t)(b[i] ^ bv);
            vm->pc += 1;
            break;
        }

        /* ---- v2: CALL / RET (separate return stack) ---------------------- */
        case VVM_CALL: {
            uint32_t target;
            if (!vvm_have(vm, 5)) return -1;
            target = vvm_rd_u32(ip + 1);
            if (target >= vm->code_size) return -1;
            if (vm->rsp >= VVM_RET_STACK_SIZE) return -1;   /* overflow */
            vm->ret_stack[vm->rsp++] = vm->pc + 5;
            vm->pc = target;
            break;
        }
        case VVM_RET: {
            if (vm->rsp <= 0) return -1;                    /* underflow */
            vm->pc = vm->ret_stack[--vm->rsp];
            break;
        }

        /* ---- v2: native call via trampoline ------------------------------ */
        case VVM_N_CALL_PTR: {
            uint64_t func_ptr, ac, argv_local[8], result;
            int argc, i;
            if (vvm_pop(vm, &func_ptr)) return -1;
            if (vvm_pop(vm, &ac)) return -1;
            argc = (int)ac;
            if (argc < 0 || argc > 8) return -1;
            for (i = argc - 1; i >= 0; i--) {
                if (vvm_pop(vm, &argv_local[i])) return -1;
            }
            result = venice_trampoline_call((void *)(uintptr_t)func_ptr,
                                            argc, argv_local);
            if (vvm_push(vm, result)) return -1;
            vm->pc += 1;
            break;
        }

        /* ---- v2: div / mod (with zero check) ----------------------------- */
        case VVM_DIV: {
            uint64_t a, b;
            if (vvm_pop(vm, &b) || vvm_pop(vm, &a)) return -1;
            if (b == 0) return -1;
            if (vvm_push(vm, a / b)) return -1;
            vm->pc += 1;
            break;
        }
        case VVM_MOD: {
            uint64_t a, b;
            if (vvm_pop(vm, &b) || vvm_pop(vm, &a)) return -1;
            if (b == 0) return -1;
            if (vvm_push(vm, a % b)) return -1;
            vm->pc += 1;
            break;
        }

        /* ---- v2: unary ops ----------------------------------------------- */
        case VVM_NEG: {
            uint64_t a;
            if (vvm_pop(vm, &a)) return -1;
            if (vvm_push(vm, ~a + 1)) return -1;
            vm->pc += 1;
            break;
        }
        case VVM_NOT: {
            uint64_t a;
            if (vvm_pop(vm, &a)) return -1;
            if (vvm_push(vm, ~a)) return -1;
            vm->pc += 1;
            break;
        }

        /* ---- v2: additional comparisons ---------------------------------- */
        case VVM_CMP_GT: {
            uint64_t a, b;
            if (vvm_pop(vm, &b) || vvm_pop(vm, &a)) return -1;
            if (vvm_push(vm, (uint64_t)(a > b ? 1u : 0u))) return -1;
            vm->pc += 1;
            break;
        }
        case VVM_CMP_GE: {
            uint64_t a, b;
            if (vvm_pop(vm, &b) || vvm_pop(vm, &a)) return -1;
            if (vvm_push(vm, (uint64_t)(a >= b ? 1u : 0u))) return -1;
            vm->pc += 1;
            break;
        }
        case VVM_CMP_NE: {
            uint64_t a, b;
            if (vvm_pop(vm, &b) || vvm_pop(vm, &a)) return -1;
            if (vvm_push(vm, (uint64_t)(a != b ? 1u : 0u))) return -1;
            vm->pc += 1;
            break;
        }

        /* ---- v2: PUSH_IMM16 --------------------------------------------- */
        case VVM_PUSH_IMM16:
            if (!vvm_have(vm, 3)) return -1;
            if (vvm_push(vm, (uint64_t)vvm_rd_u16(ip + 1)))
                return -1;
            vm->pc += 3;
            break;

        /* ---- v2: 16-bit memory ------------------------------------------- */
        case VVM_LOAD16: {
            uint64_t addr;
            if (vvm_pop(vm, &addr)) return -1;
            if (vvm_push(vm, (uint64_t)*(const uint16_t *)(uintptr_t)addr))
                return -1;
            vm->pc += 1;
            break;
        }
        case VVM_STORE16: {
            uint64_t addr, val;
            if (vvm_pop(vm, &val) || vvm_pop(vm, &addr)) return -1;
            *(uint16_t *)(uintptr_t)addr = (uint16_t)val;
            vm->pc += 1;
            break;
        }

        /* ---- v2: ROT3 / PICK -------------------------------------------- */
        case VVM_ROT3: {
            uint64_t a, b, c;
            if (vvm_pop(vm, &a) || vvm_pop(vm, &b) || vvm_pop(vm, &c))
                return -1;
            if (vvm_push(vm, a) || vvm_push(vm, c) || vvm_push(vm, b))
                return -1;
            vm->pc += 1;
            break;
        }
        case VVM_PICK: {
            uint8_t n;
            int idx;
            if (!vvm_have(vm, 2)) return -1;
            n = ip[1];
            idx = vm->sp - 1 - (int)n;
            if (idx < 0) return -1;
            if (vvm_push(vm, vm->stack[idx])) return -1;
            vm->pc += 2;
            break;
        }

#ifdef VVM_SHUFFLED
        VVM_DECOY_CASES
#endif

        default:
            return -1;                       /* unknown / trap opcode */
        }
    }
}

/* ---- public API --------------------------------------------------------- */

int venice_vm_exec(const uint8_t *program, uint32_t program_size,
                   const uint64_t *args, int arg_count)
{
    VeniceVM vm;
    int rc;

    if (!program || program_size < 2u)
        return -1;

    /* Zero the whole VM state up front (no CRT memset; volatile byte loop). */
    {
        volatile uint8_t *z = (volatile uint8_t *)&vm;
        uint32_t n;
        for (n = 0; n < (uint32_t)sizeof(vm); n++)
            z[n] = 0;
    }

#ifdef VVM_ROLLING
    /*
     * Rolling container: [2 'VR'][16 seed][u16 ds][data][u16 nlead]
     *                    [u32 leader…][code_ct]. History-keyed self-decrypting
     * bytecode -- one instruction is reconstructed at a time in vvm_run.
     */
    if (program_size >= (uint32_t)(2 + VVM_ROLL_SEED_LEN + 2)
        && program[0] == (uint8_t)VVM_ROLL_MAGIC0
        && program[1] == (uint8_t)VVM_ROLL_MAGIC1) {
        uint32_t off = 2;
        const uint8_t *seed = program + off; off += VVM_ROLL_SEED_LEN;
        uint16_t ds = (uint16_t)(program[off] | (program[off + 1] << 8));
        uint16_t nlead;
        const uint8_t *leaders;
        off += 2;
        if ((uint32_t)off + ds + 2u > program_size) return -1;
        vm.data = program + off; vm.data_size = ds; off += ds;
        nlead = (uint16_t)(program[off] | (program[off + 1] << 8)); off += 2;
        if ((uint64_t)off + (uint64_t)nlead * 4u > (uint64_t)program_size)
            return -1;
        leaders = program + off; off += (uint32_t)nlead * 4u;
        vm.code = program + off;
        vm.code_size = program_size - off;
        vm.pc = 0;
        vm.sp = 0;
        vm.rolling = 1;
        vvm_rolling_init(&vm.roll, vm.code, vm.code_size, seed, leaders, nlead);
    } else
#endif
    {
    /* Header: u16 data_size (little-endian), followed by data[], then code[]. */
    vm.data_size = (uint16_t)(program[0] | (program[1] << 8));
    if ((uint32_t)2u + vm.data_size > program_size)
        return -1;                           /* data runs past the blob */

    vm.data      = program + 2;
    vm.code      = program + 2 + vm.data_size;
    vm.code_size = program_size - 2u - vm.data_size;
    vm.pc        = 0;
    vm.sp        = 0;
#ifdef VVM_ROLLING
    vm.rolling   = 0;
#endif
    }

    /* Copy up to 8 caller arguments (the rest of args[] stays zeroed). */
    vm.arg_count = 0;
    if (args && arg_count > 0) {
        int c = (arg_count > 8) ? 8 : arg_count;
        for (int i = 0; i < c; i++)
            vm.args[i] = args[i];
        vm.arg_count = c;
    }

    rc = vvm_run(&vm);

    /*
     * Wipe the ENTIRE VM state (not just locals/stack/ret_stack): args[] may
     * hold key pointers/derived values, and under VVM_ROLLING vm.roll holds a
     * copy of the rolling seed + the live accumulator. Zeroing the whole struct
     * after capturing rc honors the "behind the PC the plaintext is gone" claim
     * and leaves no key material on the frame. volatile => not elided.
     */
    {
        volatile uint8_t *z = (volatile uint8_t *)&vm;
        uint32_t n;
        for (n = 0; n < (uint32_t)sizeof(vm); n++)
            z[n] = 0;
    }

    return rc;
}
