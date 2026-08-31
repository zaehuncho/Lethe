/*
 * Lethe stub crypto -- thin, standard wrappers over Windows CNG (BCrypt).
 *
 * Provides AES-256-GCM decryption, SHA-256, and HKDF-SHA256 for the runtime
 * loader and the memory-guard module. Uses the OS-provided bcrypt.dll only (no
 * third-party crypto, and deliberately NOT the hash-pinned libcrypto used by the
 * host app's Ed25519 path).
 *
 * All functions return 0 on success, nonzero on failure.
 */
#ifndef LETHE_CRYPTO_H
#define LETHE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include "pack_info.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SHA-256 one-shot: out[32] = SHA256(data[0..len)). */
int crypto_sha256(const void *data, size_t len, uint8_t out[32]);

/* RFC 5869 HKDF-SHA256 (extract + expand). out_len bytes of key material. */
int crypto_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len);

/* AES-256-GCM authenticated decrypt. Writes ct_len bytes to out_pt and returns
 * nonzero if the tag does not verify (out_pt must have room for ct_len bytes).
 * aad/aad_len supply additional authenticated data (may be NULL/0). */
int crypto_aes256gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *ct, size_t ct_len,
                             const uint8_t tag[16], uint8_t *out_pt,
                             const void *aad, size_t aad_len);

/* Derive the runtime AES key, binding it to the stub's own .text bytes:
 *   mask    = HKDF-SHA256(ikm = SHA256(stub .text region), salt = pi->kdf_salt,
 *                         info = "Lethe-v1")
 *   out_key = pi->aes_key_enc XOR mask
 * The .text region is [image_base + pi->stub_text_rva, pi->stub_text_size].
 * If the stub's code is modified, the hash changes and the key is wrong, so
 * decryption fails -- integrity and decryption are tied together. */
int crypto_derive_key(const PackInfo *pi, const void *image_base,
                      uint8_t out_key[32]);

/* --- per-unit subkey derivation (defense in depth) -------------------------
 * Distinct AES-256 subkeys derived from the master key that crypto_derive_key()
 * recovers, so recovering one unit's key never exposes the master key or the
 * other units. Mirror the Python builder byte-for-byte (packer/payload.py
 * _derive_section_key / _derive_meta_key; labels canonical in
 * packer/container.py). Return 0 on success, nonzero on failure. */

/* Per-section subkey:
 *   HKDF-SHA256(ikm = master_key, salt, info = "Lethe-v1-section" || rva_LE).
 * Pass the section's ORIGINAL RVA (SectionDesc.rva) -- the same value the builder
 * used and that is bound as the section's GCM AAD. */
int lethe_derive_section_key(const uint8_t master_key[32], const uint8_t salt[16],
                             uint32_t section_rva, uint8_t out_key[32]);

/* Metadata-envelope subkey:
 *   HKDF-SHA256(ikm = master_key, salt, info = "Lethe-v1-meta"). */
int lethe_derive_meta_key(const uint8_t master_key[32], const uint8_t salt[16],
                          uint8_t out_key[32]);

/* Secure zeroization (volatile; not optimized away). Wipe recovered master keys
 * and derived subkeys after use. */
void orion_secure_wipe(void *ptr, size_t len);

/* Fill buf[0..len) with cryptographically secure random bytes. Resolves
 * BCryptGenRandom dynamically (no static bcrypt import). 0 on success. */
int crypto_csprng(void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LETHE_CRYPTO_H */
