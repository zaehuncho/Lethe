#ifndef LETHE_KEY_RELEASE_CRYPTO_H
#define LETHE_KEY_RELEASE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "key_release_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KR2_RELEASE_SHARE_SIZE 32u
#define KR2_AES_KEY_SIZE       32u
#define KR2_GCM_TAG_SIZE       16u
#define KR2_P256_SCALAR_SIZE   32u

typedef enum kr2_crypto_status {
    KR2_CRYPTO_OK = 0,
    KR2_CRYPTO_ERROR_ARGUMENT,
    KR2_CRYPTO_ERROR_PROTOCOL,
    KR2_CRYPTO_ERROR_BINDING,
    KR2_CRYPTO_ERROR_BUFFER,
    KR2_CRYPTO_ERROR_TIME,
    KR2_CRYPTO_ERROR_SIGNATURE_FORMAT,
    KR2_CRYPTO_ERROR_SIGNING_KEY,
    KR2_CRYPTO_ERROR_SIGNATURE,
    KR2_CRYPTO_ERROR_CLIENT_KEY,
    KR2_CRYPTO_ERROR_CLIENT_KEY_MISMATCH,
    KR2_CRYPTO_ERROR_SERVER_KEY,
    KR2_CRYPTO_ERROR_HASH,
    KR2_CRYPTO_ERROR_HKDF_HASH,
    KR2_CRYPTO_ERROR_HKDF_EXTRACT,
    KR2_CRYPTO_ERROR_HKDF_EXPAND,
    KR2_CRYPTO_ERROR_CIPHERTEXT,
    KR2_CRYPTO_ERROR_AUTHENTICATION
} kr2_crypto_status;

/* Canonical encoders used by both the authenticated open path and native
 * parity tests. Outputs are modified only on success. */
kr2_crypto_status kr2_crypto_build_transcript(
    const uint8_t *request_frame, size_t request_size,
    const uint8_t *grant_frame, size_t grant_size,
    uint8_t *out, size_t out_capacity, size_t *out_size);

kr2_crypto_status kr2_crypto_build_grant_aad(
    const kr2_request_view *request, const kr2_grant_view *grant,
    uint8_t *out, size_t out_capacity, size_t *out_size);

/* Low-level parity primitive. The caller must authenticate the grant before
 * using this directly; kr2_cng_open_release_share enforces that ordering. */
kr2_crypto_status kr2_cng_derive_release_key(
    const kr2_request_view *request, const kr2_grant_view *grant,
    const uint8_t *client_private_scalar, size_t private_scalar_size,
    uint8_t *key_out, size_t key_out_size);

/* Parse, bind, verify the canonical low-S signature, enforce caller-supplied
 * trusted time, derive the bound key, and open exactly one 32-byte share. */
kr2_crypto_status kr2_cng_open_release_share(
    const uint8_t *request_frame, size_t request_size,
    const uint8_t *response_frame, size_t response_size,
    const uint8_t *client_private_scalar, size_t private_scalar_size,
    const uint8_t *signing_public_sec1, size_t signing_public_size,
    uint64_t trusted_epoch,
    uint8_t *share_out, size_t share_out_size);

const char *kr2_crypto_status_string(kr2_crypto_status status);

#ifdef __cplusplus
}
#endif

#endif
