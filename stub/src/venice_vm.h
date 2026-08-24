/*
 * venice_vm.h -- Venice VM (VVM): a tiny stack-based bytecode interpreter for
 * the Lethe PE packer stub.
 *
 * The VM virtualizes the stub's most sensitive crypto paths (runtime key
 * derivation, shard XOR fold, key scattering). A reverse engineer stepping
 * through the packed binary sees this one generic dispatch loop plus an opaque
 * bytecode blob instead of a readable x64 crypto routine.
 *
 * ISA summary:
 *   - Stack machine, 64-bit values, little-endian instruction encoding.
 *   - Program format:
 *       u16 data_size            embedded read-only constant data
 *       u8  data[data_size]      (encrypted strings, labels, scratch seeds, ...)
 *       u8  code[]               bytecode, executed until HALT
 *
 * Freestanding / no-CRT: the interpreter (venice_vm.c) is implemented with byte
 * loops and the stub's own crypto helpers only.
 *
 * NOTE: this header is deliberately self-contained -- just <stdint.h> plus the
 * ISA. It must NOT include pack_info.h; crypto.h already pulls that in, and
 * venice_vm.c includes crypto.h, so re-including it here would be redundant.
 */
#pragma once

#include <stdint.h>

#ifdef VVM_ROLLING
#include "venice_rolling.h"   /* VvmRolling (history-keyed decode context) */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ---- VM limits ---------------------------------------------------------- */

#define VVM_STACK_SIZE  64
#define VVM_LOCAL_SIZE  1024
#define VVM_RET_STACK_SIZE 32

/* ---- opcodes ------------------------------------------------------------ */

typedef enum VvmOpcode {
    /* stack manipulation */
    VVM_HALT        = 0x00, /* pop TOS -> return value; stop                 */
    VVM_NOP         = 0x01,
    VVM_PUSH_IMM8   = 0x02, /* 1 byte follows  (zero-extended to u64)        */
    VVM_PUSH_IMM32  = 0x03, /* 4 LE bytes follow (zero-extended)             */
    VVM_PUSH_IMM64  = 0x04, /* 8 LE bytes follow                             */
    VVM_POP         = 0x05, /* discard TOS                                   */
    VVM_DUP         = 0x06, /* duplicate TOS                                 */
    VVM_SWAP        = 0x07, /* swap top two                                  */

    /* arithmetic: pop b = TOS, pop a, push (a OP b) */
    VVM_ADD         = 0x08,
    VVM_SUB         = 0x09,
    VVM_XOR         = 0x0A,
    VVM_AND         = 0x0B,
    VVM_OR          = 0x0C,
    VVM_SHL         = 0x0D,
    VVM_SHR         = 0x0E,
    VVM_MUL         = 0x0F, /* pop b, pop a, push a*b unsigned wrapping       */

    /* memory */
    VVM_LOAD8       = 0x10, /* pop addr -> push *(uint8_t  *)addr (zero-ext) */
    VVM_LOAD32      = 0x11, /* pop addr -> push *(uint32_t *)addr (zero-ext) */
    VVM_LOAD64      = 0x12, /* pop addr -> push *(uint64_t *)addr            */
    VVM_STORE8      = 0x13, /* pop val, pop addr -> *(uint8_t  *)addr = val  */
    VVM_STORE32     = 0x14, /* pop val, pop addr -> *(uint32_t *)addr = val  */
    VVM_STORE64     = 0x15, /* pop val, pop addr -> *(uint64_t *)addr = val  */

    /* comparison: pop b, pop a */
    VVM_CMP_EQ      = 0x16, /* push (a == b ? 1 : 0)                         */
    VVM_CMP_LT      = 0x17, /* push (a <  b ? 1 : 0)  (unsigned)             */

    /* control flow */
    VVM_JMP         = 0x18, /* 4 LE bytes: absolute code offset              */
    VVM_JZ          = 0x19, /* pop cond; 4 LE bytes: jump if cond == 0       */
    VVM_JNZ         = 0x1A, /* pop cond; 4 LE bytes: jump if cond != 0       */
    VVM_CALL        = 0x1B, /* 4 LE bytes: push pc+5 onto ret stack, jump    */

    /* data access */
    VVM_PUSH_ARG    = 0x1C, /* 1 byte: push args[index]                      */
    VVM_LOCAL_ADDR  = 0x1D, /* 2 LE bytes: push &locals[offset]              */
    VVM_DATA_ADDR   = 0x1E, /* 2 LE bytes: push &data[offset]                */
    VVM_RET         = 0x1F, /* pop return stack, jump to saved address       */

    /*
     * Native crypto operations (domain-specific).
     *
     * Arguments are pushed LEFT-TO-RIGHT (the first argument is pushed first,
     * the last argument ends up as TOS). The VM pops them in reverse and calls
     * the underlying function with the original argument order. "-> push" means
     * the op leaves a return value on the stack; "void" pushes nothing.
     */
    VVM_N_SHA256      = 0x20, /* (data,len,out)                        -> 0/1 */
    VVM_N_HKDF        = 0x21, /* (ikm,ikm_len,salt,salt_len,info,
                                  info_len,out,out_len)                -> 0/1 */
    VVM_N_XOR_BUF     = 0x22, /* (dst,src_a,src_b,len)  void; d[i]=a[i]^b[i]  */
    VVM_N_GETENV      = 0x23, /* (name,buf,bufsize)     -> DWORD chars written*/
    VVM_N_SETENV_NULL = 0x24, /* (name)                 void; setenv(name,0)  */
    VVM_N_HEX_DECODE  = 0x25, /* (hex,hex_len,out)      void; hex -> bytes    */
    VVM_N_ZERO_MEM    = 0x26, /* (ptr,len)              void; volatile zero   */
    VVM_N_SCATTER_INIT= 0x27, /* (key32)                -> 0/1                */
    VVM_N_COPY_MEM    = 0x28, /* (dst,src,len)          void; byte copy       */
    VVM_N_XOR_REPEAT  = 0x29, /* (dst,src,repeat_len,total_len)
                                  void; d[i]^=src[i % repeat_len]             */
    VVM_N_XOR_CONST   = 0x2A, /* (buf,len,byte_val)     void; b[i]^=byte_val  */

    /* v2 opcodes --------------------------------------------------------- */
    VVM_N_CALL_PTR  = 0x2B, /* pop func_ptr, pop argc, pop args; trampoline  */
    VVM_DIV         = 0x2C, /* pop b, pop a, push a/b unsigned (b==0->halt)  */
    VVM_MOD         = 0x2D, /* pop b, pop a, push a%b unsigned (b==0->halt)  */
    VVM_NEG         = 0x2E, /* pop a, push twos-complement negate            */
    VVM_NOT         = 0x2F, /* pop a, push bitwise NOT (~a)                  */
    VVM_CMP_GT      = 0x30, /* pop b, pop a, push (a >  b) unsigned          */
    VVM_CMP_GE      = 0x31, /* pop b, pop a, push (a >= b) unsigned          */
    VVM_CMP_NE      = 0x32, /* pop b, pop a, push (a != b)                   */
    VVM_PUSH_IMM16  = 0x33, /* 2 LE bytes follow (zero-extended to u64)      */
    VVM_LOAD16      = 0x34, /* pop addr -> push *(uint16_t *)addr (zero-ext) */
    VVM_STORE16     = 0x35, /* pop val, pop addr -> *(uint16_t *)addr = val  */
    VVM_ROT3        = 0x36, /* rotate top 3: [c b a] -> [a c b] (top=b)     */
    VVM_PICK        = 0x37  /* 1 byte n: copy stack[sp-1-n] to top (0=DUP)  */
} VvmOpcode;

/* ---- VM state ----------------------------------------------------------- */

typedef struct VeniceVM {
    uint64_t       stack[VVM_STACK_SIZE];
    int            sp;                       /* next free slot (0 = empty)   */
    uint32_t       ret_stack[VVM_RET_STACK_SIZE]; /* CALL/RET return addrs   */
    int            rsp;                      /* return stack ptr (0 = empty) */
    uint8_t        locals[VVM_LOCAL_SIZE];   /* scratch; wiped after exec    */
    const uint8_t *code;
    uint32_t       code_size;
    uint32_t       pc;
    const uint8_t *data;
    uint16_t       data_size;
    uint64_t       args[8];
    int            arg_count;
#ifdef VVM_ROLLING
    int            rolling;    /* 1 => code is a rolling ('VR') container    */
    VvmRolling     roll;       /* history-keyed decode state (per-run)       */
#endif
} VeniceVM;

/* ---- public API --------------------------------------------------------- */

/*
 * Execute a Venice VM program.
 *
 *   program      pointer to [u16 data_size][data][code] blob
 *   program_size total blob length in bytes
 *   args         up to 8 caller arguments (may be NULL if arg_count <= 0)
 *   arg_count    number of arguments supplied (values past 8 are ignored)
 *
 * Returns the HALT value (0 = success, by convention), or -1 on any VM error
 * (stack under/overflow, out-of-range jump, unknown opcode, malformed header).
 * The locals and operand stack are volatile-zeroed before returning.
 */
int venice_vm_exec(const uint8_t *program, uint32_t program_size,
                   const uint64_t *args, int arg_count);

#ifdef __cplusplus
}
#endif
