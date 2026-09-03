#ifndef LETHE_KEY_RELEASE_PROTOCOL_H
#define LETHE_KEY_RELEASE_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KR2_PROTOCOL_VERSION              2u
#define KR2_BUILD_ID_SIZE                32u
#define KR2_DEVICE_ID_SIZE               32u
#define KR2_CHALLENGE_SIZE               32u
#define KR2_EPHEMERAL_KEY_SIZE           65u
#define KR2_LAUNCH_ID_SIZE               16u
#define KR2_AEAD_NONCE_SIZE              12u
#define KR2_SIGNATURE_SIZE               64u
#define KR2_MAX_LICENSE_ID_SIZE         128u
#define KR2_MAX_CIPHERTEXT_SIZE        1024u
#define KR2_MAX_GRANT_LIFETIME_SECONDS  300u
#define KR2_MAX_REQUEST_SIZE           1024u
#define KR2_MAX_GRANT_SIZE             2048u
#define KR2_MAX_RESPONSE_SIZE          2304u
#define KR2_MAX_TRANSCRIPT_SIZE        4096u
#define KR2_MAX_GRANT_AAD_SIZE         2048u

typedef enum kr2_status {
    KR2_OK = 0,
    KR2_ERROR_ARGUMENT,
    KR2_ERROR_TRUNCATED,
    KR2_ERROR_OVERSIZED,
    KR2_ERROR_MAGIC,
    KR2_ERROR_VERSION,
    KR2_ERROR_KIND,
    KR2_ERROR_FIELD_COUNT,
    KR2_ERROR_BODY_SIZE,
    KR2_ERROR_DUPLICATE_FIELD,
    KR2_ERROR_FIELD_ORDER,
    KR2_ERROR_UNKNOWN_FIELD,
    KR2_ERROR_FIELD_SET,
    KR2_ERROR_FIELD_VALUE,
    KR2_ERROR_TIME_RANGE,
    KR2_ERROR_BINDING
} kr2_status;

typedef struct kr2_slice {
    const uint8_t *data;
    size_t size;
} kr2_slice;

typedef struct kr2_request_view {
    kr2_slice build_id;
    kr2_slice license_id;
    kr2_slice device_id;
    kr2_slice challenge;
    kr2_slice client_ephemeral_key;
    uint64_t requested_at;
} kr2_request_view;

typedef struct kr2_grant_view {
    kr2_slice build_id;
    kr2_slice license_id;
    kr2_slice device_id;
    kr2_slice challenge;
    kr2_slice client_ephemeral_key;
    kr2_slice server_ephemeral_key;
    kr2_slice launch_id;
    uint64_t issued_at;
    uint64_t expires_at;
    kr2_slice ciphertext_nonce;
    kr2_slice ciphertext;
} kr2_grant_view;

typedef struct kr2_response_view {
    kr2_slice grant_frame;
    kr2_grant_view grant;
    kr2_slice signature;
} kr2_response_view;

typedef struct kr2_transcript_view {
    kr2_slice request_frame;
    kr2_request_view request;
    kr2_slice grant_frame;
    kr2_grant_view grant;
} kr2_transcript_view;

/* Parse outputs are borrowed slices into ``data`` and are modified only after
 * complete validation succeeds. The caller must keep the input frame alive. */
kr2_status kr2_parse_request(const uint8_t *data, size_t size,
                             kr2_request_view *out);
kr2_status kr2_parse_grant(const uint8_t *data, size_t size,
                           kr2_grant_view *out);
kr2_status kr2_parse_response(const uint8_t *data, size_t size,
                              kr2_response_view *out);
kr2_status kr2_parse_transcript(const uint8_t *data, size_t size,
                                kr2_transcript_view *out);

kr2_status kr2_validate_binding(const kr2_request_view *request,
                                const kr2_grant_view *grant);
const char *kr2_status_string(kr2_status status);

#ifdef __cplusplus
}
#endif

#endif
