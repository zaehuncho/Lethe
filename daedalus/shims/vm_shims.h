/*
 * vm_shims.h -- Declarations for all Daedalus VM shim functions.
 *
 * Each function is extern "C" with a flat ABI (scalar / pointer args only)
 * so that Daedalus bytecode can invoke them through N_CALL_PTR.
 *
 * Include vm_externals.h for the VmExternals struct and init helper.
 */
#ifndef VM_SHIMS_H
#define VM_SHIMS_H

#include "vm_externals.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- identity --------------------------------------------------------- */

/* Win32 computer name -> buf.  Returns chars written, 0 on failure. */
int vm_get_hostname(char *buf, uint32_t bufsize);

/* HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid -> buf (UTF-8).
 * Returns chars written, 0 on failure. */
int vm_get_machine_guid(char *buf, uint32_t bufsize);

/* QSysInfo::machineUniqueId() raw bytes -> buf.
 * Returns bytes written, 0 on failure. */
int vm_get_machine_unique_id(uint8_t *buf, uint32_t bufsize);

/* Current user name -> buf.  Tries GetUserNameA, then %USERNAME%,
 * then %USER%.  Returns chars written, 0 on failure. */
int vm_get_username(char *buf, uint32_t bufsize);

/* ---- hashing ---------------------------------------------------------- */

/* SHA-256 of the running executable.  out must be >= 32 bytes.
 * Returns 0 on success, 1 on failure. */
int vm_sha256_self_exe(uint8_t out[32]);

/* SHA-256 of an arbitrary buffer.  out must be >= 32 bytes.
 * Returns 0 on success, 1 on failure. */
int vm_sha256_buf(const void *data, uint32_t len, uint8_t out[32]);

/* ---- DPAPI ------------------------------------------------------------ */

/* DPAPI CryptProtectData with CRYPTPROTECT_UI_FORBIDDEN.
 * Returns bytes written to |out|, or -1 on failure. */
int vm_dpapi_protect(const uint8_t *in, uint32_t in_len,
                     const uint8_t *entropy, uint32_t ent_len,
                     uint8_t *out, uint32_t out_max);

/* DPAPI CryptUnprotectData with CRYPTPROTECT_UI_FORBIDDEN.
 * Returns bytes written to |out|, or -1 on failure. */
int vm_dpapi_unprotect(const uint8_t *in, uint32_t in_len,
                       const uint8_t *entropy, uint32_t ent_len,
                       uint8_t *out, uint32_t out_max);

/* ---- encoding --------------------------------------------------------- */

/* Base64url decode (RFC 4648 ss5, no padding).
 * Returns bytes written to |out|, or -1 on failure. */
int vm_base64url_decode(const char *in, uint32_t in_len,
                        uint8_t *out, uint32_t out_max);

/* ---- crypto ----------------------------------------------------------- */

/* Ed25519 signature verification.
 * pk: 32-byte public key, sig: 64-byte signature.
 * Returns 1 if valid, 0 if invalid or on error. */
int vm_ed25519_verify(const uint8_t pk[32], const uint8_t *msg,
                      uint32_t msg_len, const uint8_t sig[64]);

#ifdef __cplusplus
}
#endif

#endif /* VM_SHIMS_H */
