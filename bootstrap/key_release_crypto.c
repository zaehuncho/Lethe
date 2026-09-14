#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <limits.h>

#include "key_release_crypto.h"

#define KR2_FRAME_HEADER_SIZE 12u
#define KR2_FIELD_HEADER_SIZE  5u
#define KR2_KIND_TRANSCRIPT     3u
#define KR2_KIND_GRANT_AAD      5u
#define KR2_MAX_SIGNED_I64 0x7fffffffffffffffULL

typedef struct kr2_ecc_public_blob {
    BCRYPT_ECCKEY_BLOB header;
    uint8_t x[KR2_P256_SCALAR_SIZE];
    uint8_t y[KR2_P256_SCALAR_SIZE];
} kr2_ecc_public_blob;

typedef struct kr2_ecc_private_blob {
    BCRYPT_ECCKEY_BLOB header;
    uint8_t x[KR2_P256_SCALAR_SIZE];
    uint8_t y[KR2_P256_SCALAR_SIZE];
    uint8_t d[KR2_P256_SCALAR_SIZE];
} kr2_ecc_private_blob;

static const uint8_t g_magic[4] = {'L', 'K', 'R', '2'};
static const uint8_t g_p256_order[KR2_P256_SCALAR_SIZE] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};
static const uint8_t g_p256_half_order[KR2_P256_SCALAR_SIZE] = {
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
    0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8
};
static const uint8_t g_hkdf_salt_domain[] = "LETHE-KR2-HKDF-SALT";
static const uint8_t g_hkdf_info_domain[] =
    "LETHE-KR2-RELEASE-SHARE-AES256GCM";

_Static_assert(sizeof(kr2_ecc_public_blob) == 72u,
               "unexpected CNG public-key blob layout");
_Static_assert(sizeof(kr2_ecc_private_blob) == 104u,
               "unexpected CNG private-key blob layout");

static void zero_bytes(void *data, size_t size)
{
    if (data != NULL && size != 0)
        SecureZeroMemory(data, size);
}

static void copy_bytes(uint8_t *out, const uint8_t *input, size_t size)
{
    size_t i;
    for (i = 0; i < size; ++i)
        out[i] = input[i];
}

static int bytes_equal(const uint8_t *left, const uint8_t *right, size_t size)
{
    size_t i;
    uint8_t difference = 0;
    for (i = 0; i < size; ++i)
        difference |= (uint8_t)(left[i] ^ right[i]);
    return difference == 0;
}

static int compare_be(const uint8_t *left, const uint8_t *right, size_t size)
{
    size_t i;
    for (i = 0; i < size; ++i) {
        if (left[i] < right[i])
            return -1;
        if (left[i] > right[i])
            return 1;
    }
    return 0;
}

static int scalar_is_valid(const uint8_t *scalar)
{
    uint8_t nonzero = 0;
    size_t i;
    for (i = 0; i < KR2_P256_SCALAR_SIZE; ++i)
        nonzero |= scalar[i];
    return nonzero != 0 &&
           compare_be(scalar, g_p256_order, KR2_P256_SCALAR_SIZE) < 0;
}

static int signature_is_canonical(kr2_slice signature)
{
    const uint8_t *r;
    const uint8_t *s;
    if (signature.data == NULL || signature.size != KR2_SIGNATURE_SIZE)
        return 0;
    r = signature.data;
    s = signature.data + KR2_P256_SCALAR_SIZE;
    return scalar_is_valid(r) && scalar_is_valid(s) &&
           compare_be(s, g_p256_half_order, KR2_P256_SCALAR_SIZE) <= 0;
}

static void write_be16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void write_be32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void write_be64(uint8_t *out, uint64_t value)
{
    out[0] = (uint8_t)(value >> 56);
    out[1] = (uint8_t)(value >> 48);
    out[2] = (uint8_t)(value >> 40);
    out[3] = (uint8_t)(value >> 32);
    out[4] = (uint8_t)(value >> 24);
    out[5] = (uint8_t)(value >> 16);
    out[6] = (uint8_t)(value >> 8);
    out[7] = (uint8_t)value;
}

static kr2_crypto_status start_frame(uint8_t *out, size_t capacity,
                                     uint8_t kind, uint16_t field_count,
                                     size_t *cursor)
{
    if (out == NULL || cursor == NULL)
        return KR2_CRYPTO_ERROR_ARGUMENT;
    if (capacity < KR2_FRAME_HEADER_SIZE)
        return KR2_CRYPTO_ERROR_BUFFER;
    copy_bytes(out, g_magic, sizeof(g_magic));
    out[4] = KR2_PROTOCOL_VERSION;
    out[5] = kind;
    write_be16(out + 6, field_count);
    write_be32(out + 8, 0);
    *cursor = KR2_FRAME_HEADER_SIZE;
    return KR2_CRYPTO_OK;
}

static kr2_crypto_status append_field(uint8_t *out, size_t capacity,
                                      size_t *cursor, uint8_t tag,
                                      const uint8_t *value, size_t value_size)
{
    size_t current;
    if (out == NULL || cursor == NULL || value == NULL)
        return KR2_CRYPTO_ERROR_ARGUMENT;
    current = *cursor;
    if (value_size > UINT32_MAX || current > capacity ||
        capacity - current < KR2_FIELD_HEADER_SIZE)
        return KR2_CRYPTO_ERROR_BUFFER;
    if (value_size > capacity - current - KR2_FIELD_HEADER_SIZE)
        return KR2_CRYPTO_ERROR_BUFFER;
    out[current] = tag;
    write_be32(out + current + 1, (uint32_t)value_size);
    copy_bytes(out + current + KR2_FIELD_HEADER_SIZE, value, value_size);
    *cursor = current + KR2_FIELD_HEADER_SIZE + value_size;
    return KR2_CRYPTO_OK;
}

static kr2_crypto_status finish_frame(uint8_t *out, size_t cursor,
                                      size_t *out_size)
{
    size_t body_size;
    if (out == NULL || out_size == NULL || cursor < KR2_FRAME_HEADER_SIZE)
        return KR2_CRYPTO_ERROR_ARGUMENT;
    body_size = cursor - KR2_FRAME_HEADER_SIZE;
    if (body_size > UINT32_MAX)
        return KR2_CRYPTO_ERROR_BUFFER;
    write_be32(out + 8, (uint32_t)body_size);
    *out_size = cursor;
    return KR2_CRYPTO_OK;
}

static kr2_crypto_status build_transcript_internal(
    const uint8_t *request_frame, size_t request_size,
    const uint8_t *grant_frame, size_t grant_size,
    uint8_t *out, size_t capacity, size_t *out_size)
{
    kr2_crypto_status result;
    size_t cursor;
    result = start_frame(out, capacity, KR2_KIND_TRANSCRIPT, 2, &cursor);
    if (result == KR2_CRYPTO_OK)
        result = append_field(out, capacity, &cursor, 1,
                              request_frame, request_size);
    if (result == KR2_CRYPTO_OK)
        result = append_field(out, capacity, &cursor, 2,
                              grant_frame, grant_size);
    if (result == KR2_CRYPTO_OK)
        result = finish_frame(out, cursor, out_size);
    return result;
}

kr2_crypto_status kr2_crypto_build_transcript(
    const uint8_t *request_frame, size_t request_size,
    const uint8_t *grant_frame, size_t grant_size,
    uint8_t *out, size_t out_capacity, size_t *out_size)
{
    uint8_t encoded[KR2_MAX_TRANSCRIPT_SIZE];
    kr2_request_view request;
    kr2_grant_view grant;
    kr2_crypto_status result = KR2_CRYPTO_ERROR_PROTOCOL;
    size_t encoded_size = 0;

    if (request_frame == NULL || grant_frame == NULL || out == NULL ||
        out_size == NULL)
        return KR2_CRYPTO_ERROR_ARGUMENT;
    if (kr2_parse_request(request_frame, request_size, &request) != KR2_OK ||
        kr2_parse_grant(grant_frame, grant_size, &grant) != KR2_OK)
        goto cleanup;
    if (kr2_validate_binding(&request, &grant) != KR2_OK) {
        result = KR2_CRYPTO_ERROR_BINDING;
        goto cleanup;
    }
    result = build_transcript_internal(
        request_frame, request_size, grant_frame, grant_size,
        encoded, sizeof(encoded), &encoded_size);
    if (result != KR2_CRYPTO_OK)
        goto cleanup;
    if (encoded_size > out_capacity) {
        result = KR2_CRYPTO_ERROR_BUFFER;
        goto cleanup;
    }
    copy_bytes(out, encoded, encoded_size);
    *out_size = encoded_size;

cleanup:
    zero_bytes(encoded, sizeof(encoded));
    return result;
}

static int slice_has_size(kr2_slice value, size_t size)
{
    return value.data != NULL && value.size == size;
}

static kr2_crypto_status build_aad_internal(
    const kr2_request_view *request, const kr2_grant_view *grant,
    uint8_t *out, size_t capacity, size_t *out_size)
{
    uint8_t requested_at[8];
    uint8_t issued_at[8];
    uint8_t expires_at[8];
    kr2_crypto_status result;
    size_t cursor;

    if (request == NULL || grant == NULL || out == NULL || out_size == NULL)
        return KR2_CRYPTO_ERROR_ARGUMENT;
    if (kr2_validate_binding(request, grant) != KR2_OK)
        return KR2_CRYPTO_ERROR_BINDING;
    if (!slice_has_size(grant->build_id, KR2_BUILD_ID_SIZE) ||
        grant->license_id.data == NULL || grant->license_id.size == 0 ||
        grant->license_id.size > KR2_MAX_LICENSE_ID_SIZE ||
        !slice_has_size(grant->device_id, KR2_DEVICE_ID_SIZE) ||
        !slice_has_size(grant->challenge, KR2_CHALLENGE_SIZE) ||
        !slice_has_size(grant->client_ephemeral_key,
                        KR2_EPHEMERAL_KEY_SIZE) ||
        !slice_has_size(grant->server_ephemeral_key,
                        KR2_EPHEMERAL_KEY_SIZE) ||
        !slice_has_size(grant->launch_id, KR2_LAUNCH_ID_SIZE) ||
        !slice_has_size(grant->ciphertext_nonce, KR2_AEAD_NONCE_SIZE) ||
        request->requested_at > KR2_MAX_SIGNED_I64 ||
        grant->issued_at > KR2_MAX_SIGNED_I64 ||
        grant->expires_at > KR2_MAX_SIGNED_I64)
        return KR2_CRYPTO_ERROR_PROTOCOL;

    write_be64(requested_at, request->requested_at);
    write_be64(issued_at, grant->issued_at);
    write_be64(expires_at, grant->expires_at);
    result = start_frame(out, capacity, KR2_KIND_GRANT_AAD, 11, &cursor);
#define KR2_APPEND_AAD(tag_value, data_value, size_value)                 \
    do {                                                                 \
        if (result == KR2_CRYPTO_OK)                                     \
            result = append_field(out, capacity, &cursor, (tag_value),   \
                                  (data_value), (size_value));           \
    } while (0)
    KR2_APPEND_AAD(1, grant->build_id.data, grant->build_id.size);
    KR2_APPEND_AAD(2, grant->license_id.data, grant->license_id.size);
    KR2_APPEND_AAD(3, grant->device_id.data, grant->device_id.size);
    KR2_APPEND_AAD(4, grant->challenge.data, grant->challenge.size);
    KR2_APPEND_AAD(5, grant->client_ephemeral_key.data,
                   grant->client_ephemeral_key.size);
    KR2_APPEND_AAD(6, requested_at, sizeof(requested_at));
    KR2_APPEND_AAD(7, grant->server_ephemeral_key.data,
                   grant->server_ephemeral_key.size);
    KR2_APPEND_AAD(8, grant->launch_id.data, grant->launch_id.size);
    KR2_APPEND_AAD(9, issued_at, sizeof(issued_at));
    KR2_APPEND_AAD(10, expires_at, sizeof(expires_at));
    KR2_APPEND_AAD(11, grant->ciphertext_nonce.data,
                   grant->ciphertext_nonce.size);
#undef KR2_APPEND_AAD
    if (result == KR2_CRYPTO_OK)
        result = finish_frame(out, cursor, out_size);
    zero_bytes(requested_at, sizeof(requested_at));
    zero_bytes(issued_at, sizeof(issued_at));
    zero_bytes(expires_at, sizeof(expires_at));
    return result;
}

kr2_crypto_status kr2_crypto_build_grant_aad(
    const kr2_request_view *request, const kr2_grant_view *grant,
    uint8_t *out, size_t out_capacity, size_t *out_size)
{
    uint8_t encoded[KR2_MAX_GRANT_AAD_SIZE];
    kr2_crypto_status result;
    size_t encoded_size = 0;
    if (out == NULL || out_size == NULL)
        return KR2_CRYPTO_ERROR_ARGUMENT;
    result = build_aad_internal(request, grant, encoded, sizeof(encoded),
                                &encoded_size);
    if (result == KR2_CRYPTO_OK && encoded_size > out_capacity)
        result = KR2_CRYPTO_ERROR_BUFFER;
    if (result == KR2_CRYPTO_OK) {
        copy_bytes(out, encoded, encoded_size);
        *out_size = encoded_size;
    }
    zero_bytes(encoded, sizeof(encoded));
    return result;
}

static kr2_crypto_status sha256(const uint8_t *data, size_t size,
                                uint8_t out[32])
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS status;
    kr2_crypto_status result = KR2_CRYPTO_ERROR_HASH;
    if (data == NULL || out == NULL || size > ULONG_MAX)
        return KR2_CRYPTO_ERROR_ARGUMENT;
    status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status != 0)
        goto cleanup;
    status = BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0);
    if (status != 0)
        goto cleanup;
    status = BCryptHashData(hash, (PUCHAR)data, (ULONG)size, 0);
    if (status != 0)
        goto cleanup;
    status = BCryptFinishHash(hash, out, 32, 0);
    if (status == 0)
        result = KR2_CRYPTO_OK;

cleanup:
    if (hash != NULL)
        BCryptDestroyHash(hash);
    if (algorithm != NULL)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    return result;
}

static kr2_crypto_status import_public_key(
    BCRYPT_ALG_HANDLE algorithm, const uint8_t *sec1, size_t sec1_size,
    ULONG magic, BCRYPT_KEY_HANDLE *key_out,
    kr2_crypto_status invalid_status)
{
    kr2_ecc_public_blob blob;
    NTSTATUS status;
    if (algorithm == NULL || sec1 == NULL || key_out == NULL)
        return KR2_CRYPTO_ERROR_ARGUMENT;
    if (sec1_size != KR2_EPHEMERAL_KEY_SIZE || sec1[0] != 0x04)
        return invalid_status;
    zero_bytes(&blob, sizeof(blob));
    blob.header.dwMagic = magic;
    blob.header.cbKey = KR2_P256_SCALAR_SIZE;
    copy_bytes(blob.x, sec1 + 1, KR2_P256_SCALAR_SIZE);
    copy_bytes(blob.y, sec1 + 1 + KR2_P256_SCALAR_SIZE,
               KR2_P256_SCALAR_SIZE);
    status = BCryptImportKeyPair(
        algorithm, NULL, BCRYPT_ECCPUBLIC_BLOB, key_out,
        (PUCHAR)&blob, (ULONG)sizeof(blob), 0);
    zero_bytes(&blob, sizeof(blob));
    return status == 0 ? KR2_CRYPTO_OK : invalid_status;
}

static kr2_crypto_status import_client_private_key(
    BCRYPT_ALG_HANDLE algorithm, kr2_slice client_public,
    const uint8_t *private_scalar, size_t private_scalar_size,
    BCRYPT_KEY_HANDLE *key_out)
{
    kr2_ecc_private_blob blob;
    kr2_ecc_public_blob exported;
    ULONG written = 0;
    NTSTATUS status;
    kr2_crypto_status result = KR2_CRYPTO_ERROR_CLIENT_KEY;

    if (algorithm == NULL || private_scalar == NULL || key_out == NULL)
        return KR2_CRYPTO_ERROR_ARGUMENT;
    if (!slice_has_size(client_public, KR2_EPHEMERAL_KEY_SIZE) ||
        client_public.data[0] != 0x04 ||
        private_scalar_size != KR2_P256_SCALAR_SIZE ||
        !scalar_is_valid(private_scalar))
        return KR2_CRYPTO_ERROR_CLIENT_KEY;

    zero_bytes(&blob, sizeof(blob));
    zero_bytes(&exported, sizeof(exported));
    blob.header.dwMagic = BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC;
    blob.header.cbKey = KR2_P256_SCALAR_SIZE;
    copy_bytes(blob.x, client_public.data + 1, KR2_P256_SCALAR_SIZE);
    copy_bytes(blob.y, client_public.data + 1 + KR2_P256_SCALAR_SIZE,
               KR2_P256_SCALAR_SIZE);
    copy_bytes(blob.d, private_scalar, KR2_P256_SCALAR_SIZE);
    status = BCryptImportKeyPair(
        algorithm, NULL, BCRYPT_ECCPRIVATE_BLOB, key_out,
        (PUCHAR)&blob, (ULONG)sizeof(blob), 0);
    if (status != 0)
        goto cleanup;
    status = BCryptExportKey(
        *key_out, NULL, BCRYPT_ECCPUBLIC_BLOB,
        (PUCHAR)&exported, (ULONG)sizeof(exported), &written, 0);
    if (status != 0 || written != sizeof(exported))
        goto cleanup;
    if ((exported.header.dwMagic != BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC &&
         exported.header.dwMagic != BCRYPT_ECDH_PUBLIC_P256_MAGIC) ||
        exported.header.cbKey != KR2_P256_SCALAR_SIZE ||
        !bytes_equal(exported.x, client_public.data + 1,
                     KR2_P256_SCALAR_SIZE) ||
        !bytes_equal(exported.y,
                     client_public.data + 1 + KR2_P256_SCALAR_SIZE,
                     KR2_P256_SCALAR_SIZE)) {
        result = KR2_CRYPTO_ERROR_CLIENT_KEY_MISMATCH;
        goto cleanup;
    }
    result = KR2_CRYPTO_OK;

cleanup:
    if (result != KR2_CRYPTO_OK && *key_out != NULL) {
        BCryptDestroyKey(*key_out);
        *key_out = NULL;
    }
    zero_bytes(&blob, sizeof(blob));
    zero_bytes(&exported, sizeof(exported));
    return result;
}

kr2_crypto_status kr2_cng_derive_release_key(
    const kr2_request_view *request, const kr2_grant_view *grant,
    const uint8_t *client_private_scalar, size_t private_scalar_size,
    uint8_t *key_out, size_t key_out_size)
{
    BCRYPT_ALG_HANDLE ecdh_algorithm = NULL;
    BCRYPT_KEY_HANDLE client_key = NULL;
    BCRYPT_KEY_HANDLE server_key = NULL;
    BCRYPT_SECRET_HANDLE secret = NULL;
    BCRYPT_ALG_HANDLE hkdf_algorithm = NULL;
    BCRYPT_KEY_HANDLE hkdf_key = NULL;
    uint8_t aad[KR2_MAX_GRANT_AAD_SIZE];
    uint8_t context_hash[32];
    uint8_t salt_input[sizeof(g_hkdf_salt_domain) + 32u];
    uint8_t salt[32];
    uint8_t info[sizeof(g_hkdf_info_domain) + 32u];
    uint8_t raw_secret_le[KR2_P256_SCALAR_SIZE];
    uint8_t raw_secret_be[KR2_P256_SCALAR_SIZE];
    uint8_t derived[KR2_AES_KEY_SIZE];
    size_t aad_size = 0;
    BCryptBuffer info_buffer;
    BCryptBufferDesc parameters;
    ULONG written = 0;
    NTSTATUS status;
    kr2_crypto_status result = KR2_CRYPTO_ERROR_HKDF_EXPAND;

    if (request == NULL || grant == NULL || client_private_scalar == NULL ||
        key_out == NULL || key_out_size < KR2_AES_KEY_SIZE)
        return KR2_CRYPTO_ERROR_ARGUMENT;
    zero_bytes(key_out, KR2_AES_KEY_SIZE);
    zero_bytes(aad, sizeof(aad));
    zero_bytes(context_hash, sizeof(context_hash));
    zero_bytes(salt_input, sizeof(salt_input));
    zero_bytes(salt, sizeof(salt));
    zero_bytes(info, sizeof(info));
    zero_bytes(raw_secret_le, sizeof(raw_secret_le));
    zero_bytes(raw_secret_be, sizeof(raw_secret_be));
    zero_bytes(derived, sizeof(derived));
    if (kr2_validate_binding(request, grant) != KR2_OK) {
        result = KR2_CRYPTO_ERROR_BINDING;
        goto cleanup;
    }
    if (grant->issued_at < request->requested_at) {
        result = KR2_CRYPTO_ERROR_TIME;
        goto cleanup;
    }
    result = build_aad_internal(
        request, grant, aad, sizeof(aad), &aad_size);
    if (result != KR2_CRYPTO_OK)
        goto cleanup;
    result = sha256(aad, aad_size, context_hash);
    if (result != KR2_CRYPTO_OK)
        goto cleanup;

    status = BCryptOpenAlgorithmProvider(
        &ecdh_algorithm, BCRYPT_ECDH_ALGORITHM, NULL, 0);
    if (status != 0) {
        result = KR2_CRYPTO_ERROR_CLIENT_KEY;
        goto cleanup;
    }
    status = BCryptSetProperty(
        ecdh_algorithm, BCRYPT_ECC_CURVE_NAME,
        (PUCHAR)BCRYPT_ECC_CURVE_NISTP256,
        (ULONG)sizeof(BCRYPT_ECC_CURVE_NISTP256), 0);
    if (status != 0) {
        result = KR2_CRYPTO_ERROR_CLIENT_KEY;
        goto cleanup;
    }
    result = import_client_private_key(
        ecdh_algorithm, request->client_ephemeral_key,
        client_private_scalar, private_scalar_size, &client_key);
    if (result != KR2_CRYPTO_OK)
        goto cleanup;
    result = import_public_key(
        ecdh_algorithm, grant->server_ephemeral_key.data,
        grant->server_ephemeral_key.size, BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC,
        &server_key, KR2_CRYPTO_ERROR_SERVER_KEY);
    if (result != KR2_CRYPTO_OK)
        goto cleanup;
    status = BCryptSecretAgreement(client_key, server_key, &secret, 0);
    if (status != 0) {
        result = KR2_CRYPTO_ERROR_SERVER_KEY;
        goto cleanup;
    }

    result = KR2_CRYPTO_ERROR_HKDF_EXTRACT;
    status = BCryptDeriveKey(
        secret, BCRYPT_KDF_RAW_SECRET, NULL,
        raw_secret_le, (ULONG)sizeof(raw_secret_le), &written, 0);
    if (status != 0 || written != sizeof(raw_secret_le))
        goto cleanup;
    {
        size_t i;
        for (i = 0; i < sizeof(raw_secret_be); ++i)
            raw_secret_be[i] = raw_secret_le[sizeof(raw_secret_le) - 1u - i];
    }

    copy_bytes(salt_input, g_hkdf_salt_domain,
               sizeof(g_hkdf_salt_domain));
    copy_bytes(salt_input + sizeof(g_hkdf_salt_domain),
               context_hash, sizeof(context_hash));
    result = sha256(salt_input, sizeof(salt_input), salt);
    if (result != KR2_CRYPTO_OK)
        goto cleanup;
    copy_bytes(info, g_hkdf_info_domain, sizeof(g_hkdf_info_domain));
    copy_bytes(info + sizeof(g_hkdf_info_domain),
               context_hash, sizeof(context_hash));

    result = KR2_CRYPTO_ERROR_HKDF_HASH;
    status = BCryptOpenAlgorithmProvider(
        &hkdf_algorithm, BCRYPT_HKDF_ALGORITHM, NULL, 0);
    if (status != 0)
        goto cleanup;
    status = BCryptGenerateSymmetricKey(
        hkdf_algorithm, &hkdf_key, NULL, 0,
        raw_secret_be, (ULONG)sizeof(raw_secret_be), 0);
    if (status != 0)
        goto cleanup;
    status = BCryptSetProperty(
        hkdf_key, BCRYPT_HKDF_HASH_ALGORITHM,
        (PUCHAR)BCRYPT_SHA256_ALGORITHM,
        (ULONG)sizeof(BCRYPT_SHA256_ALGORITHM), 0);
    if (status != 0)
        goto cleanup;
    result = KR2_CRYPTO_ERROR_HKDF_EXTRACT;
    status = BCryptSetProperty(
        hkdf_key, BCRYPT_HKDF_SALT_AND_FINALIZE,
        salt, (ULONG)sizeof(salt), 0);
    if (status != 0)
        goto cleanup;
    result = KR2_CRYPTO_ERROR_HKDF_EXPAND;
    info_buffer.cbBuffer = (ULONG)sizeof(info);
    info_buffer.BufferType = KDF_HKDF_INFO;
    info_buffer.pvBuffer = info;
    parameters.ulVersion = BCRYPTBUFFER_VERSION;
    parameters.cBuffers = 1;
    parameters.pBuffers = &info_buffer;
    status = BCryptKeyDerivation(
        hkdf_key, &parameters,
        derived, (ULONG)sizeof(derived), &written, 0);
    if (status != 0 || written != sizeof(derived))
        goto cleanup;
    copy_bytes(key_out, derived, sizeof(derived));
    result = KR2_CRYPTO_OK;

cleanup:
    if (result != KR2_CRYPTO_OK)
        zero_bytes(key_out, KR2_AES_KEY_SIZE);
    if (hkdf_key != NULL)
        BCryptDestroyKey(hkdf_key);
    if (hkdf_algorithm != NULL)
        BCryptCloseAlgorithmProvider(hkdf_algorithm, 0);
    if (secret != NULL)
        BCryptDestroySecret(secret);
    if (server_key != NULL)
        BCryptDestroyKey(server_key);
    if (client_key != NULL)
        BCryptDestroyKey(client_key);
    if (ecdh_algorithm != NULL)
        BCryptCloseAlgorithmProvider(ecdh_algorithm, 0);
    zero_bytes(aad, sizeof(aad));
    zero_bytes(context_hash, sizeof(context_hash));
    zero_bytes(salt_input, sizeof(salt_input));
    zero_bytes(salt, sizeof(salt));
    zero_bytes(info, sizeof(info));
    zero_bytes(raw_secret_le, sizeof(raw_secret_le));
    zero_bytes(raw_secret_be, sizeof(raw_secret_be));
    zero_bytes(derived, sizeof(derived));
    return result;
}

static kr2_crypto_status verify_response_signature(
    const uint8_t *request_frame, size_t request_size,
    const kr2_response_view *response,
    const uint8_t *signing_public_sec1, size_t signing_public_size)
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE signing_key = NULL;
    uint8_t transcript[KR2_MAX_TRANSCRIPT_SIZE];
    uint8_t digest[32];
    size_t transcript_size = 0;
    NTSTATUS status;
    kr2_crypto_status result = KR2_CRYPTO_ERROR_SIGNATURE;

    zero_bytes(transcript, sizeof(transcript));
    zero_bytes(digest, sizeof(digest));
    if (!signature_is_canonical(response->signature)) {
        result = KR2_CRYPTO_ERROR_SIGNATURE_FORMAT;
        goto cleanup;
    }
    result = build_transcript_internal(
        request_frame, request_size,
        response->grant_frame.data, response->grant_frame.size,
        transcript, sizeof(transcript), &transcript_size);
    if (result != KR2_CRYPTO_OK)
        goto cleanup;
    result = sha256(transcript, transcript_size, digest);
    if (result != KR2_CRYPTO_OK)
        goto cleanup;
    status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (status != 0) {
        result = KR2_CRYPTO_ERROR_SIGNING_KEY;
        goto cleanup;
    }
    result = import_public_key(
        algorithm, signing_public_sec1, signing_public_size,
        BCRYPT_ECDSA_PUBLIC_P256_MAGIC, &signing_key,
        KR2_CRYPTO_ERROR_SIGNING_KEY);
    if (result != KR2_CRYPTO_OK)
        goto cleanup;
    status = BCryptVerifySignature(
        signing_key, NULL, digest, (ULONG)sizeof(digest),
        (PUCHAR)response->signature.data, (ULONG)response->signature.size, 0);
    result = status == 0 ? KR2_CRYPTO_OK : KR2_CRYPTO_ERROR_SIGNATURE;

cleanup:
    if (signing_key != NULL)
        BCryptDestroyKey(signing_key);
    if (algorithm != NULL)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    zero_bytes(transcript, sizeof(transcript));
    zero_bytes(digest, sizeof(digest));
    return result;
}

static kr2_crypto_status decrypt_share(
    const uint8_t key[KR2_AES_KEY_SIZE], const kr2_grant_view *grant,
    const uint8_t *aad, size_t aad_size,
    uint8_t share_out[KR2_RELEASE_SHARE_SIZE])
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE aes_key = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    uint8_t plaintext[KR2_RELEASE_SHARE_SIZE];
    ULONG written = 0;
    NTSTATUS status;
    kr2_crypto_status result = KR2_CRYPTO_ERROR_AUTHENTICATION;

    zero_bytes(plaintext, sizeof(plaintext));
    if (grant->ciphertext.data == NULL ||
        grant->ciphertext.size != KR2_RELEASE_SHARE_SIZE + KR2_GCM_TAG_SIZE ||
        !slice_has_size(grant->ciphertext_nonce, KR2_AEAD_NONCE_SIZE) ||
        aad == NULL || aad_size > ULONG_MAX) {
        result = KR2_CRYPTO_ERROR_CIPHERTEXT;
        goto cleanup;
    }
    status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0)
        goto cleanup;
    status = BCryptSetProperty(
        algorithm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status != 0)
        goto cleanup;
    status = BCryptGenerateSymmetricKey(
        algorithm, &aes_key, NULL, 0,
        (PUCHAR)key, KR2_AES_KEY_SIZE, 0);
    if (status != 0)
        goto cleanup;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = (PUCHAR)grant->ciphertext_nonce.data;
    auth_info.cbNonce = KR2_AEAD_NONCE_SIZE;
    auth_info.pbAuthData = (PUCHAR)aad;
    auth_info.cbAuthData = (ULONG)aad_size;
    auth_info.pbTag = (PUCHAR)(grant->ciphertext.data +
                              KR2_RELEASE_SHARE_SIZE);
    auth_info.cbTag = KR2_GCM_TAG_SIZE;
    status = BCryptDecrypt(
        aes_key, (PUCHAR)grant->ciphertext.data, KR2_RELEASE_SHARE_SIZE,
        &auth_info, NULL, 0, plaintext, (ULONG)sizeof(plaintext),
        &written, 0);
    if (status != 0 || written != sizeof(plaintext))
        goto cleanup;
    copy_bytes(share_out, plaintext, sizeof(plaintext));
    result = KR2_CRYPTO_OK;

cleanup:
    if (aes_key != NULL)
        BCryptDestroyKey(aes_key);
    if (algorithm != NULL)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    zero_bytes(plaintext, sizeof(plaintext));
    return result;
}

kr2_crypto_status kr2_cng_open_release_share(
    const uint8_t *request_frame, size_t request_size,
    const uint8_t *response_frame, size_t response_size,
    const uint8_t *client_private_scalar, size_t private_scalar_size,
    const uint8_t *signing_public_sec1, size_t signing_public_size,
    uint64_t trusted_epoch,
    uint8_t *share_out, size_t share_out_size)
{
    kr2_request_view request;
    kr2_response_view response;
    uint8_t key[KR2_AES_KEY_SIZE];
    uint8_t aad[KR2_MAX_GRANT_AAD_SIZE];
    uint8_t plaintext[KR2_RELEASE_SHARE_SIZE];
    size_t aad_size = 0;
    kr2_crypto_status result = KR2_CRYPTO_ERROR_PROTOCOL;

    if (request_frame == NULL || response_frame == NULL ||
        client_private_scalar == NULL || signing_public_sec1 == NULL ||
        share_out == NULL || share_out_size < KR2_RELEASE_SHARE_SIZE)
        return KR2_CRYPTO_ERROR_ARGUMENT;
    zero_bytes(share_out, KR2_RELEASE_SHARE_SIZE);
    zero_bytes(key, sizeof(key));
    zero_bytes(aad, sizeof(aad));
    zero_bytes(plaintext, sizeof(plaintext));

    if (kr2_parse_request(request_frame, request_size, &request) != KR2_OK ||
        kr2_parse_response(response_frame, response_size, &response) != KR2_OK)
        goto cleanup;
    if (kr2_validate_binding(&request, &response.grant) != KR2_OK) {
        result = KR2_CRYPTO_ERROR_BINDING;
        goto cleanup;
    }
    result = verify_response_signature(
        request_frame, request_size, &response,
        signing_public_sec1, signing_public_size);
    if (result != KR2_CRYPTO_OK)
        goto cleanup;
    if (trusted_epoch > KR2_MAX_SIGNED_I64 ||
        response.grant.issued_at < request.requested_at ||
        trusted_epoch < response.grant.issued_at ||
        trusted_epoch >= response.grant.expires_at) {
        result = KR2_CRYPTO_ERROR_TIME;
        goto cleanup;
    }
    if (response.grant.ciphertext.size !=
            KR2_RELEASE_SHARE_SIZE + KR2_GCM_TAG_SIZE) {
        result = KR2_CRYPTO_ERROR_CIPHERTEXT;
        goto cleanup;
    }
    result = kr2_cng_derive_release_key(
        &request, &response.grant,
        client_private_scalar, private_scalar_size,
        key, sizeof(key));
    if (result != KR2_CRYPTO_OK)
        goto cleanup;
    result = build_aad_internal(
        &request, &response.grant, aad, sizeof(aad), &aad_size);
    if (result != KR2_CRYPTO_OK)
        goto cleanup;
    result = decrypt_share(key, &response.grant, aad, aad_size, plaintext);
    if (result != KR2_CRYPTO_OK)
        goto cleanup;
    copy_bytes(share_out, plaintext, sizeof(plaintext));

cleanup:
    if (result != KR2_CRYPTO_OK)
        zero_bytes(share_out, KR2_RELEASE_SHARE_SIZE);
    zero_bytes(key, sizeof(key));
    zero_bytes(aad, sizeof(aad));
    zero_bytes(plaintext, sizeof(plaintext));
    return result;
}

const char *kr2_crypto_status_string(kr2_crypto_status status)
{
    switch (status) {
    case KR2_CRYPTO_OK: return "ok";
    case KR2_CRYPTO_ERROR_ARGUMENT: return "invalid argument";
    case KR2_CRYPTO_ERROR_PROTOCOL: return "invalid protocol frame";
    case KR2_CRYPTO_ERROR_BINDING: return "request/grant binding mismatch";
    case KR2_CRYPTO_ERROR_BUFFER: return "output buffer too small";
    case KR2_CRYPTO_ERROR_TIME: return "grant outside trusted time window";
    case KR2_CRYPTO_ERROR_SIGNATURE_FORMAT: return "noncanonical signature";
    case KR2_CRYPTO_ERROR_SIGNING_KEY: return "invalid signing key";
    case KR2_CRYPTO_ERROR_SIGNATURE: return "signature verification failed";
    case KR2_CRYPTO_ERROR_CLIENT_KEY: return "invalid client private key";
    case KR2_CRYPTO_ERROR_CLIENT_KEY_MISMATCH:
        return "client private key does not match request";
    case KR2_CRYPTO_ERROR_SERVER_KEY: return "invalid server ECDH key";
    case KR2_CRYPTO_ERROR_HASH: return "SHA-256 failed";
    case KR2_CRYPTO_ERROR_HKDF_HASH: return "HKDF SHA-256 selection failed";
    case KR2_CRYPTO_ERROR_HKDF_EXTRACT: return "HKDF extract failed";
    case KR2_CRYPTO_ERROR_HKDF_EXPAND: return "HKDF expand failed";
    case KR2_CRYPTO_ERROR_CIPHERTEXT: return "invalid ciphertext shape";
    case KR2_CRYPTO_ERROR_AUTHENTICATION: return "AES-GCM authentication failed";
    default: return "unknown crypto status";
    }
}
