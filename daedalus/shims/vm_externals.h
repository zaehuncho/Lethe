/*
 * vm_externals.h -- VmExternals struct and init function.
 *
 * Pure C-compatible header.  Safe to include from both C and C++.
 * Bytecode programs receive a pointer to VmExternals as arg[0] and
 * resolve individual entries via push_arg 0 / push_imm8 OFFSET / add /
 * load64 / n_call_ptr.
 */
#ifndef VM_EXTERNALS_H
#define VM_EXTERNALS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Function-pointer table passed to Daedalus VM programs as arg[0].
 *
 * Layout (byte offset : name : C signature):
 *   0:  get_hostname          int(char*, uint32_t)
 *   8:  get_machine_guid      int(char*, uint32_t)
 *  16:  get_machine_unique_id int(uint8_t*, uint32_t)
 *  24:  get_username           int(char*, uint32_t)
 *  32:  sha256_self_exe        int(uint8_t out[32])
 *  40:  sha256_buf             int(const void*, uint32_t, uint8_t out[32])
 *  48:  dpapi_protect          int(const uint8_t*, uint32_t, const uint8_t*, uint32_t, uint8_t*, uint32_t)
 *  56:  dpapi_unprotect        int(const uint8_t*, uint32_t, const uint8_t*, uint32_t, uint8_t*, uint32_t)
 *  64:  base64url_decode       int(const char*, uint32_t, uint8_t*, uint32_t)
 *  72:  ed25519_verify         int(const uint8_t pk[32], const uint8_t*, uint32_t, const uint8_t sig[64])
 */
typedef struct VmExternals {
    /* 0  */ int (*get_hostname)(char *buf, uint32_t bufsize);
    /* 8  */ int (*get_machine_guid)(char *buf, uint32_t bufsize);
    /* 16 */ int (*get_machine_unique_id)(uint8_t *buf, uint32_t bufsize);
    /* 24 */ int (*get_username)(char *buf, uint32_t bufsize);
    /* 32 */ int (*sha256_self_exe)(uint8_t out[32]);
    /* 40 */ int (*sha256_buf)(const void *data, uint32_t len, uint8_t out[32]);
    /* 48 */ int (*dpapi_protect)(const uint8_t *in, uint32_t in_len,
                                  const uint8_t *entropy, uint32_t ent_len,
                                  uint8_t *out, uint32_t out_max);
    /* 56 */ int (*dpapi_unprotect)(const uint8_t *in, uint32_t in_len,
                                    const uint8_t *entropy, uint32_t ent_len,
                                    uint8_t *out, uint32_t out_max);
    /* 64 */ int (*base64url_decode)(const char *in, uint32_t in_len,
                                     uint8_t *out, uint32_t out_max);
    /* 72 */ int (*ed25519_verify)(const uint8_t pk[32], const uint8_t *msg,
                                   uint32_t msg_len, const uint8_t sig[64]);
} VmExternals;

/* Populate every slot in |ext| with the concrete shim functions. */
void vm_externals_init(VmExternals *ext);

#ifdef __cplusplus
}
#endif

#endif /* VM_EXTERNALS_H */
