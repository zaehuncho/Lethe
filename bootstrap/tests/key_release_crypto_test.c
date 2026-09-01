#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>

#include "key_release_crypto.h"

#include <stdio.h>
#include <string.h>

#define VECTOR_LINE_CAPACITY (KR2_MAX_TRANSCRIPT_SIZE * 2u + 128u)
#define EXPECTED_VECTOR_COUNT 15u

typedef struct vector_set {
    uint8_t request[KR2_MAX_REQUEST_SIZE];
    size_t request_size;
    uint8_t response[KR2_MAX_RESPONSE_SIZE];
    size_t response_size;
    uint8_t transcript[KR2_MAX_TRANSCRIPT_SIZE];
    size_t transcript_size;
    uint8_t aad[KR2_MAX_GRANT_AAD_SIZE];
    size_t aad_size;
    uint8_t client_private[KR2_P256_SCALAR_SIZE];
    size_t client_private_size;
    uint8_t client_public[KR2_EPHEMERAL_KEY_SIZE];
    size_t client_public_size;
    uint8_t server_public[KR2_EPHEMERAL_KEY_SIZE];
    size_t server_public_size;
    uint8_t signing_public[KR2_EPHEMERAL_KEY_SIZE];
    size_t signing_public_size;
    uint8_t aes_key[KR2_AES_KEY_SIZE];
    size_t aes_key_size;
    uint8_t nonce[KR2_AEAD_NONCE_SIZE];
    size_t nonce_size;
    uint8_t ciphertext[KR2_RELEASE_SHARE_SIZE + KR2_GCM_TAG_SIZE];
    size_t ciphertext_size;
    uint8_t signature[KR2_SIGNATURE_SIZE];
    size_t signature_size;
    uint8_t share[KR2_RELEASE_SHARE_SIZE];
    size_t share_size;
    uint8_t response_bad_tag_signed[KR2_MAX_RESPONSE_SIZE];
    size_t response_bad_tag_signed_size;
    uint8_t response_invalid_server_signed[KR2_MAX_RESPONSE_SIZE];
    size_t response_invalid_server_signed_size;
} vector_set;

typedef struct vector_target {
    const char *name;
    uint8_t *data;
    size_t capacity;
    size_t *size;
    unsigned bit;
} vector_target;

static const uint8_t g_p256_order[KR2_P256_SCALAR_SIZE] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};

static int fail_at(int line, const char *detail)
{
    fprintf(stderr, "KR2 native crypto test failed at line %d: %s\n",
            line, detail);
    return 1;
}

static int fail_status_at(int line, const char *detail,
                          kr2_crypto_status status)
{
    fprintf(stderr,
            "KR2 native crypto test failed at line %d: %s (%s)\n",
            line, detail, kr2_crypto_status_string(status));
    return 1;
}

#define CHECK(condition, detail) \
    do { if (!(condition)) return fail_at(__LINE__, (detail)); } while (0)
#define CHECK_CRYPTO(expression, detail)                                  \
    do {                                                                 \
        kr2_crypto_status check_status = (expression);                    \
        if (check_status != KR2_CRYPTO_OK)                                \
            return fail_status_at(__LINE__, (detail), check_status);      \
    } while (0)

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode_hex(const char *hex, uint8_t *out, size_t capacity,
                      size_t *out_size)
{
    size_t chars;
    size_t i;
    if (hex == NULL || out == NULL || out_size == NULL)
        return 0;
    chars = strlen(hex);
    if ((chars & 1u) != 0 || chars / 2u > capacity)
        return 0;
    for (i = 0; i < chars / 2u; ++i) {
        int high = hex_nibble(hex[i * 2u]);
        int low = hex_nibble(hex[i * 2u + 1u]);
        if (high < 0 || low < 0)
            return 0;
        out[i] = (uint8_t)((high << 4) | low);
    }
    *out_size = chars / 2u;
    return 1;
}

static int load_vectors(const char *path, vector_set *vectors)
{
    FILE *file;
    char line[VECTOR_LINE_CAPACITY];
    vector_target targets[EXPECTED_VECTOR_COUNT];
    unsigned seen = 0;
    size_t i;

    if (path == NULL || vectors == NULL)
        return 0;
    memset(vectors, 0, sizeof(*vectors));
#define KR2_VECTOR_TARGET(index, field)                                   \
    do {                                                                 \
        targets[(index)].name = #field;                                  \
        targets[(index)].data = vectors->field;                           \
        targets[(index)].capacity = sizeof(vectors->field);               \
        targets[(index)].size = &vectors->field##_size;                   \
        targets[(index)].bit = 1u << (index);                             \
    } while (0)
    KR2_VECTOR_TARGET(0, request);
    KR2_VECTOR_TARGET(1, response);
    KR2_VECTOR_TARGET(2, transcript);
    KR2_VECTOR_TARGET(3, aad);
    KR2_VECTOR_TARGET(4, client_private);
    KR2_VECTOR_TARGET(5, client_public);
    KR2_VECTOR_TARGET(6, server_public);
    KR2_VECTOR_TARGET(7, signing_public);
    KR2_VECTOR_TARGET(8, aes_key);
    KR2_VECTOR_TARGET(9, nonce);
    KR2_VECTOR_TARGET(10, ciphertext);
    KR2_VECTOR_TARGET(11, signature);
    KR2_VECTOR_TARGET(12, share);
    KR2_VECTOR_TARGET(13, response_bad_tag_signed);
    KR2_VECTOR_TARGET(14, response_invalid_server_signed);
#undef KR2_VECTOR_TARGET
    file = fopen(path, "rb");
    if (file == NULL)
        return 0;
    while (fgets(line, (int)sizeof(line), file) != NULL) {
        char *equals;
        size_t length = strlen(line);
        int matched = 0;
        while (length > 0 &&
               (line[length - 1] == '\r' || line[length - 1] == '\n'))
            line[--length] = '\0';
        if (length == 0 || line[0] == '#')
            continue;
        equals = strchr(line, '=');
        if (equals == NULL || equals == line || equals[1] == '\0') {
            fclose(file);
            return 0;
        }
        *equals++ = '\0';
        for (i = 0; i < EXPECTED_VECTOR_COUNT; ++i) {
            if (strcmp(line, targets[i].name) == 0) {
                if ((seen & targets[i].bit) != 0 ||
                    !decode_hex(equals, targets[i].data,
                                targets[i].capacity, targets[i].size)) {
                    fclose(file);
                    return 0;
                }
                seen |= targets[i].bit;
                matched = 1;
                break;
            }
        }
        if (!matched) {
            fclose(file);
            return 0;
        }
    }
    fclose(file);
    return seen == ((1u << EXPECTED_VECTOR_COUNT) - 1u);
}

static int all_zero(const uint8_t *data, size_t size)
{
    size_t i;
    uint8_t value = 0;
    for (i = 0; i < size; ++i)
        value |= data[i];
    return value == 0;
}

static void print_hex(const char *label, const uint8_t *data, size_t size)
{
    size_t i;
    fprintf(stderr, "%s=", label);
    for (i = 0; i < size; ++i)
        fprintf(stderr, "%02x", data[i]);
    fputc('\n', stderr);
}

static void subtract_be(const uint8_t *left, const uint8_t *right,
                        uint8_t *out, size_t size)
{
    size_t i = size;
    unsigned borrow = 0;
    while (i != 0) {
        unsigned minuend;
        unsigned subtrahend;
        --i;
        minuend = left[i];
        subtrahend = (unsigned)right[i] + borrow;
        out[i] = (uint8_t)(minuend - subtrahend);
        borrow = minuend < subtrahend;
    }
}

static int test_parity(const vector_set *vectors)
{
    kr2_request_view request;
    kr2_response_view response;
    uint8_t encoded[KR2_MAX_TRANSCRIPT_SIZE];
    uint8_t key[KR2_AES_KEY_SIZE];
    uint8_t share[KR2_RELEASE_SHARE_SIZE];
    size_t encoded_size = 0;

    CHECK(kr2_parse_request(vectors->request, vectors->request_size,
                            &request) == KR2_OK,
          "Python request vector did not parse");
    CHECK(kr2_parse_response(vectors->response, vectors->response_size,
                             &response) == KR2_OK,
          "Python response vector did not parse");
    CHECK_CRYPTO(kr2_crypto_build_transcript(
                     vectors->request, vectors->request_size,
                     response.grant_frame.data, response.grant_frame.size,
                     encoded, sizeof(encoded), &encoded_size),
                 "canonical transcript construction");
    CHECK(encoded_size == vectors->transcript_size &&
              memcmp(encoded, vectors->transcript, encoded_size) == 0,
          "native transcript differs from Python");
    CHECK_CRYPTO(kr2_crypto_build_grant_aad(
                     &request, &response.grant,
                     encoded, sizeof(encoded), &encoded_size),
                 "canonical grant AAD construction");
    CHECK(encoded_size == vectors->aad_size &&
              memcmp(encoded, vectors->aad, encoded_size) == 0,
          "native grant AAD differs from Python");
    CHECK(request.client_ephemeral_key.size == vectors->client_public_size &&
              memcmp(request.client_ephemeral_key.data,
                     vectors->client_public,
                     vectors->client_public_size) == 0,
          "client public-key vector mismatch");
    CHECK(response.grant.server_ephemeral_key.size ==
              vectors->server_public_size &&
              memcmp(response.grant.server_ephemeral_key.data,
                     vectors->server_public,
                     vectors->server_public_size) == 0,
          "server public-key vector mismatch");
    CHECK(response.grant.ciphertext_nonce.size == vectors->nonce_size &&
              memcmp(response.grant.ciphertext_nonce.data,
                     vectors->nonce, vectors->nonce_size) == 0,
          "nonce vector mismatch");
    CHECK(response.grant.ciphertext.size == vectors->ciphertext_size &&
              memcmp(response.grant.ciphertext.data,
                     vectors->ciphertext, vectors->ciphertext_size) == 0,
          "ciphertext vector mismatch");
    CHECK(response.signature.size == vectors->signature_size &&
              memcmp(response.signature.data,
                     vectors->signature, vectors->signature_size) == 0,
          "signature vector mismatch");
    CHECK_CRYPTO(kr2_cng_derive_release_key(
                     &request, &response.grant,
                     vectors->client_private, vectors->client_private_size,
                     key, sizeof(key)),
                 "CNG ECDH/HKDF derivation");
    if (vectors->aes_key_size != sizeof(key) ||
        memcmp(key, vectors->aes_key, sizeof(key)) != 0) {
        print_hex("native_key", key, sizeof(key));
        print_hex("python_key", vectors->aes_key, vectors->aes_key_size);
        return fail_at(__LINE__, "CNG derived key differs from Python");
    }
    CHECK_CRYPTO(kr2_cng_open_release_share(
                     vectors->request, vectors->request_size,
                     vectors->response, vectors->response_size,
                     vectors->client_private, vectors->client_private_size,
                     vectors->signing_public, vectors->signing_public_size,
                     response.grant.issued_at,
                     share, sizeof(share)),
                 "CNG authenticated release-share open");
    CHECK(vectors->share_size == sizeof(share) &&
              memcmp(share, vectors->share, sizeof(share)) == 0,
          "CNG plaintext differs from Python");
    SecureZeroMemory(key, sizeof(key));
    SecureZeroMemory(share, sizeof(share));
    SecureZeroMemory(encoded, sizeof(encoded));
    return 0;
}

static int expect_open_status(const vector_set *vectors,
                              const uint8_t *response_data,
                              size_t response_size,
                              const uint8_t *private_scalar,
                              const uint8_t *signing_public,
                              uint64_t trusted_epoch,
                              kr2_crypto_status expected,
                              const char *detail)
{
    uint8_t share[KR2_RELEASE_SHARE_SIZE];
    kr2_crypto_status status;
    memset(share, 0xa5, sizeof(share));
    status = kr2_cng_open_release_share(
        vectors->request, vectors->request_size,
        response_data, response_size,
        private_scalar, vectors->client_private_size,
        signing_public, vectors->signing_public_size,
        trusted_epoch, share, sizeof(share));
    if (status != expected)
        return fail_status_at(__LINE__, detail, status);
    if (!all_zero(share, sizeof(share)))
        return fail_at(__LINE__, "failed open leaked output bytes");
    return 0;
}

static int test_rejections(const vector_set *vectors)
{
    kr2_response_view response;
    uint8_t changed[KR2_MAX_RESPONSE_SIZE];
    uint8_t changed_private[KR2_P256_SCALAR_SIZE];
    uint8_t invalid_point[KR2_EPHEMERAL_KEY_SIZE];
    uint8_t high_s[KR2_P256_SCALAR_SIZE];
    size_t signature_offset;
    size_t ciphertext_offset;

    CHECK(kr2_parse_response(vectors->response, vectors->response_size,
                             &response) == KR2_OK,
          "response prerequisite");
    CHECK(expect_open_status(
              vectors, vectors->response, vectors->response_size,
              vectors->client_private, vectors->signing_public,
              response.grant.issued_at - 1u,
              KR2_CRYPTO_ERROR_TIME, "not-yet-valid grant accepted") == 0,
          "not-yet-valid status");
    CHECK(expect_open_status(
              vectors, vectors->response, vectors->response_size,
              vectors->client_private, vectors->signing_public,
              response.grant.expires_at,
              KR2_CRYPTO_ERROR_TIME, "expired grant accepted") == 0,
          "expired status");

    signature_offset = (size_t)(response.signature.data - vectors->response);
    ciphertext_offset =
        (size_t)(response.grant.ciphertext.data - vectors->response);
    memcpy(changed, vectors->response, vectors->response_size);
    changed[ciphertext_offset] ^= 1u;
    CHECK(expect_open_status(
              vectors, changed, vectors->response_size,
              vectors->client_private, vectors->signing_public,
              response.grant.issued_at,
              KR2_CRYPTO_ERROR_SIGNATURE,
              "unsigned ciphertext tamper reached AES-GCM") == 0,
          "unsigned ciphertext tamper status");

    memcpy(changed, vectors->response, vectors->response_size);
    subtract_be(g_p256_order,
                changed + signature_offset + KR2_P256_SCALAR_SIZE,
                high_s, sizeof(high_s));
    memcpy(changed + signature_offset + KR2_P256_SCALAR_SIZE,
           high_s, sizeof(high_s));
    CHECK(expect_open_status(
              vectors, changed, vectors->response_size,
              vectors->client_private, vectors->signing_public,
              response.grant.issued_at,
              KR2_CRYPTO_ERROR_SIGNATURE_FORMAT,
              "malleated high-S signature accepted") == 0,
          "high-S status");

    memcpy(changed, vectors->response, vectors->response_size);
    memset(changed + signature_offset, 0, KR2_P256_SCALAR_SIZE);
    CHECK(expect_open_status(
              vectors, changed, vectors->response_size,
              vectors->client_private, vectors->signing_public,
              response.grant.issued_at,
              KR2_CRYPTO_ERROR_SIGNATURE_FORMAT,
              "zero ECDSA scalar accepted") == 0,
          "zero scalar status");

    memset(invalid_point, 0, sizeof(invalid_point));
    invalid_point[0] = 0x04;
    CHECK(expect_open_status(
              vectors, vectors->response, vectors->response_size,
              vectors->client_private, invalid_point,
              response.grant.issued_at,
              KR2_CRYPTO_ERROR_SIGNING_KEY,
              "off-curve signing point accepted") == 0,
          "invalid signing point status");
    CHECK(expect_open_status(
              vectors, vectors->response, vectors->response_size,
              vectors->client_private, vectors->server_public,
              response.grant.issued_at,
              KR2_CRYPTO_ERROR_SIGNATURE,
              "wrong signing key accepted") == 0,
          "wrong signing key status");

    CHECK(expect_open_status(
              vectors,
              vectors->response_bad_tag_signed,
              vectors->response_bad_tag_signed_size,
              vectors->client_private, vectors->signing_public,
              response.grant.issued_at,
              KR2_CRYPTO_ERROR_AUTHENTICATION,
              "validly signed bad GCM tag accepted") == 0,
          "authenticated bad-tag status");
    CHECK(expect_open_status(
              vectors,
              vectors->response_invalid_server_signed,
              vectors->response_invalid_server_signed_size,
              vectors->client_private, vectors->signing_public,
              response.grant.issued_at,
              KR2_CRYPTO_ERROR_SERVER_KEY,
              "validly signed off-curve ECDH point accepted") == 0,
          "invalid server point status");

    memcpy(changed_private, vectors->client_private,
           sizeof(changed_private));
    changed_private[sizeof(changed_private) - 1u]++;
    CHECK(expect_open_status(
              vectors, vectors->response, vectors->response_size,
              changed_private, vectors->signing_public,
              response.grant.issued_at,
              KR2_CRYPTO_ERROR_CLIENT_KEY,
              "wrong client private scalar accepted") == 0,
          "wrong private scalar status");
    memset(changed_private, 0, sizeof(changed_private));
    CHECK(expect_open_status(
              vectors, vectors->response, vectors->response_size,
              changed_private, vectors->signing_public,
              response.grant.issued_at,
              KR2_CRYPTO_ERROR_CLIENT_KEY,
              "zero client private scalar accepted") == 0,
          "zero private scalar status");
    SecureZeroMemory(changed, sizeof(changed));
    SecureZeroMemory(changed_private, sizeof(changed_private));
    SecureZeroMemory(high_s, sizeof(high_s));
    return 0;
}

int main(int argc, char **argv)
{
    vector_set vectors;
    if (argc != 2)
        return fail_at(__LINE__, "expected golden-vector path");
    if (!load_vectors(argv[1], &vectors))
        return fail_at(__LINE__, "failed to load golden vectors");
    if (test_parity(&vectors) != 0)
        return 1;
    if (test_rejections(&vectors) != 0)
        return 1;
    SecureZeroMemory(&vectors, sizeof(vectors));
    puts("KR2 native CNG crypto vectors: PASS");
    return 0;
}
