#include "key_release_protocol.h"

#define KR2_HEADER_SIZE       12u
#define KR2_FIELD_HEADER_SIZE  5u
#define KR2_KIND_REQUEST       1u
#define KR2_KIND_RESPONSE      2u
#define KR2_KIND_TRANSCRIPT    3u
#define KR2_KIND_GRANT         4u
#define KR2_MAX_SIGNED_I64 0x7fffffffffffffffULL

typedef struct kr2_frame_spec {
    uint8_t kind;
    const uint8_t *tags;
    size_t field_count;
    size_t maximum_size;
} kr2_frame_spec;

static const uint8_t g_magic[4] = {'L', 'K', 'R', '2'};
static const uint8_t g_request_tags[] = {1, 2, 3, 4, 5, 6};
static const uint8_t g_grant_tags[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
static const uint8_t g_wrapper_tags[] = {1, 2};

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t read_be64(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

static int bytes_equal(const uint8_t *left, const uint8_t *right, size_t size)
{
    size_t i;
    for (i = 0; i < size; ++i) {
        if (left[i] != right[i])
            return 0;
    }
    return 1;
}

static int slice_equal(kr2_slice left, kr2_slice right)
{
    if (left.size != right.size)
        return 0;
    if (left.size == 0)
        return 1;
    if (left.data == NULL || right.data == NULL)
        return 0;
    return bytes_equal(left.data, right.data, left.size);
}

static int tag_is_known(uint8_t tag, const kr2_frame_spec *spec)
{
    size_t i;
    for (i = 0; i < spec->field_count; ++i) {
        if (spec->tags[i] == tag)
            return 1;
    }
    return 0;
}

static kr2_status parse_frame(const uint8_t *data, size_t size,
                              const kr2_frame_spec *spec,
                              kr2_slice *fields)
{
    uint16_t field_count;
    uint32_t body_size;
    size_t cursor;
    size_t i;
    uint8_t previous = 0;
    int field_set_error = 0;

    if (data == NULL || spec == NULL || fields == NULL)
        return KR2_ERROR_ARGUMENT;
    if (size > spec->maximum_size)
        return KR2_ERROR_OVERSIZED;
    if (size < KR2_HEADER_SIZE)
        return KR2_ERROR_TRUNCATED;
    if (!bytes_equal(data, g_magic, sizeof(g_magic)))
        return KR2_ERROR_MAGIC;
    if (data[4] != KR2_PROTOCOL_VERSION)
        return KR2_ERROR_VERSION;
    if (data[5] != spec->kind)
        return KR2_ERROR_KIND;

    field_count = read_be16(data + 6);
    body_size = read_be32(data + 8);
    if ((size_t)field_count != spec->field_count)
        return KR2_ERROR_FIELD_COUNT;
    if ((size_t)body_size != size - KR2_HEADER_SIZE)
        return KR2_ERROR_BODY_SIZE;

    cursor = KR2_HEADER_SIZE;
    for (i = 0; i < spec->field_count; ++i) {
        uint8_t tag;
        uint32_t value_size;
        size_t remaining = size - cursor;

        if (remaining < KR2_FIELD_HEADER_SIZE)
            return KR2_ERROR_TRUNCATED;
        tag = data[cursor];
        value_size = read_be32(data + cursor + 1);
        cursor += KR2_FIELD_HEADER_SIZE;

        if (i != 0 && tag == previous)
            return KR2_ERROR_DUPLICATE_FIELD;
        if (i != 0 && tag < previous)
            return KR2_ERROR_FIELD_ORDER;
        if (!tag_is_known(tag, spec))
            return KR2_ERROR_UNKNOWN_FIELD;
        if (tag != spec->tags[i])
            field_set_error = 1;
        if ((size_t)value_size > spec->maximum_size)
            return KR2_ERROR_OVERSIZED;
        if (size - cursor < (size_t)value_size)
            return KR2_ERROR_TRUNCATED;

        fields[i].data = data + cursor;
        fields[i].size = (size_t)value_size;
        cursor += (size_t)value_size;
        previous = tag;
    }

    if (cursor != size)
        return KR2_ERROR_BODY_SIZE;
    if (field_set_error)
        return KR2_ERROR_FIELD_SET;
    return KR2_OK;
}

static int identifier_is_canonical(kr2_slice value)
{
    size_t i;
    if (value.data == NULL || value.size == 0 ||
        value.size > KR2_MAX_LICENSE_ID_SIZE)
        return 0;
    for (i = 0; i < value.size; ++i) {
        uint8_t c = value.data[i];
        int valid = (c >= 'A' && c <= 'Z') ||
                    (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') ||
                    c == '.' || c == '_' || c == ':' || c == '-';
        if (!valid || (i == 0 && !((c >= 'A' && c <= 'Z') ||
                                   (c >= 'a' && c <= 'z') ||
                                   (c >= '0' && c <= '9'))))
            return 0;
    }
    return 1;
}

static int slice_has_size(kr2_slice value, size_t expected)
{
    return value.data != NULL && value.size == expected;
}

static int ephemeral_key_is_canonical(kr2_slice value)
{
    return slice_has_size(value, KR2_EPHEMERAL_KEY_SIZE) &&
           value.data[0] == 0x04;
}

static kr2_status decode_timestamp(kr2_slice value, uint64_t *out)
{
    uint64_t decoded;
    if (out == NULL)
        return KR2_ERROR_ARGUMENT;
    if (!slice_has_size(value, 8))
        return KR2_ERROR_FIELD_VALUE;
    decoded = read_be64(value.data);
    if (decoded > KR2_MAX_SIGNED_I64)
        return KR2_ERROR_TIME_RANGE;
    *out = decoded;
    return KR2_OK;
}

kr2_status kr2_parse_request(const uint8_t *data, size_t size,
                             kr2_request_view *out)
{
    static const kr2_frame_spec spec = {
        KR2_KIND_REQUEST, g_request_tags,
        sizeof(g_request_tags), KR2_MAX_REQUEST_SIZE
    };
    kr2_slice fields[sizeof(g_request_tags)];
    kr2_request_view parsed;
    kr2_status status;

    if (out == NULL)
        return KR2_ERROR_ARGUMENT;
    status = parse_frame(data, size, &spec, fields);
    if (status != KR2_OK)
        return status;
    if (!slice_has_size(fields[0], KR2_BUILD_ID_SIZE) ||
        !identifier_is_canonical(fields[1]) ||
        !slice_has_size(fields[2], KR2_DEVICE_ID_SIZE) ||
        !slice_has_size(fields[3], KR2_CHALLENGE_SIZE) ||
        !ephemeral_key_is_canonical(fields[4]))
        return KR2_ERROR_FIELD_VALUE;
    status = decode_timestamp(fields[5], &parsed.requested_at);
    if (status != KR2_OK)
        return status;

    parsed.build_id = fields[0];
    parsed.license_id = fields[1];
    parsed.device_id = fields[2];
    parsed.challenge = fields[3];
    parsed.client_ephemeral_key = fields[4];
    *out = parsed;
    return KR2_OK;
}

kr2_status kr2_parse_grant(const uint8_t *data, size_t size,
                           kr2_grant_view *out)
{
    static const kr2_frame_spec spec = {
        KR2_KIND_GRANT, g_grant_tags,
        sizeof(g_grant_tags), KR2_MAX_GRANT_SIZE
    };
    kr2_slice fields[sizeof(g_grant_tags)];
    kr2_grant_view parsed;
    kr2_status status;

    if (out == NULL)
        return KR2_ERROR_ARGUMENT;
    status = parse_frame(data, size, &spec, fields);
    if (status != KR2_OK)
        return status;
    if (!slice_has_size(fields[0], KR2_BUILD_ID_SIZE) ||
        !identifier_is_canonical(fields[1]) ||
        !slice_has_size(fields[2], KR2_DEVICE_ID_SIZE) ||
        !slice_has_size(fields[3], KR2_CHALLENGE_SIZE) ||
        !ephemeral_key_is_canonical(fields[4]) ||
        !ephemeral_key_is_canonical(fields[5]) ||
        !slice_has_size(fields[6], KR2_LAUNCH_ID_SIZE) ||
        !slice_has_size(fields[9], KR2_AEAD_NONCE_SIZE) ||
        fields[10].data == NULL || fields[10].size < 16 ||
        fields[10].size > KR2_MAX_CIPHERTEXT_SIZE)
        return KR2_ERROR_FIELD_VALUE;
    status = decode_timestamp(fields[7], &parsed.issued_at);
    if (status != KR2_OK)
        return status;
    status = decode_timestamp(fields[8], &parsed.expires_at);
    if (status != KR2_OK)
        return status;
    if (parsed.expires_at <= parsed.issued_at ||
        parsed.expires_at - parsed.issued_at >
            KR2_MAX_GRANT_LIFETIME_SECONDS)
        return KR2_ERROR_TIME_RANGE;

    parsed.build_id = fields[0];
    parsed.license_id = fields[1];
    parsed.device_id = fields[2];
    parsed.challenge = fields[3];
    parsed.client_ephemeral_key = fields[4];
    parsed.server_ephemeral_key = fields[5];
    parsed.launch_id = fields[6];
    parsed.ciphertext_nonce = fields[9];
    parsed.ciphertext = fields[10];
    *out = parsed;
    return KR2_OK;
}

kr2_status kr2_parse_response(const uint8_t *data, size_t size,
                              kr2_response_view *out)
{
    static const kr2_frame_spec spec = {
        KR2_KIND_RESPONSE, g_wrapper_tags,
        sizeof(g_wrapper_tags), KR2_MAX_RESPONSE_SIZE
    };
    kr2_slice fields[sizeof(g_wrapper_tags)];
    kr2_response_view parsed;
    kr2_status status;

    if (out == NULL)
        return KR2_ERROR_ARGUMENT;
    status = parse_frame(data, size, &spec, fields);
    if (status != KR2_OK)
        return status;
    if (!slice_has_size(fields[1], KR2_SIGNATURE_SIZE))
        return KR2_ERROR_FIELD_VALUE;
    status = kr2_parse_grant(fields[0].data, fields[0].size, &parsed.grant);
    if (status != KR2_OK)
        return status;
    parsed.grant_frame = fields[0];
    parsed.signature = fields[1];
    *out = parsed;
    return KR2_OK;
}

kr2_status kr2_validate_binding(const kr2_request_view *request,
                                const kr2_grant_view *grant)
{
    if (request == NULL || grant == NULL)
        return KR2_ERROR_ARGUMENT;
    if (!slice_equal(request->build_id, grant->build_id) ||
        !slice_equal(request->license_id, grant->license_id) ||
        !slice_equal(request->device_id, grant->device_id) ||
        !slice_equal(request->challenge, grant->challenge) ||
        !slice_equal(request->client_ephemeral_key,
                     grant->client_ephemeral_key))
        return KR2_ERROR_BINDING;
    return KR2_OK;
}

kr2_status kr2_parse_transcript(const uint8_t *data, size_t size,
                                kr2_transcript_view *out)
{
    static const kr2_frame_spec spec = {
        KR2_KIND_TRANSCRIPT, g_wrapper_tags,
        sizeof(g_wrapper_tags), KR2_MAX_TRANSCRIPT_SIZE
    };
    kr2_slice fields[sizeof(g_wrapper_tags)];
    kr2_transcript_view parsed;
    kr2_status status;

    if (out == NULL)
        return KR2_ERROR_ARGUMENT;
    status = parse_frame(data, size, &spec, fields);
    if (status != KR2_OK)
        return status;
    status = kr2_parse_request(fields[0].data, fields[0].size,
                               &parsed.request);
    if (status != KR2_OK)
        return status;
    status = kr2_parse_grant(fields[1].data, fields[1].size,
                             &parsed.grant);
    if (status != KR2_OK)
        return status;
    status = kr2_validate_binding(&parsed.request, &parsed.grant);
    if (status != KR2_OK)
        return status;

    parsed.request_frame = fields[0];
    parsed.grant_frame = fields[1];
    *out = parsed;
    return KR2_OK;
}

const char *kr2_status_string(kr2_status status)
{
    switch (status) {
    case KR2_OK:                    return "ok";
    case KR2_ERROR_ARGUMENT:        return "invalid argument";
    case KR2_ERROR_TRUNCATED:       return "truncated input";
    case KR2_ERROR_OVERSIZED:       return "oversized input";
    case KR2_ERROR_MAGIC:           return "bad magic";
    case KR2_ERROR_VERSION:         return "unsupported version";
    case KR2_ERROR_KIND:            return "unexpected message kind";
    case KR2_ERROR_FIELD_COUNT:     return "unexpected field count";
    case KR2_ERROR_BODY_SIZE:       return "noncanonical body size";
    case KR2_ERROR_DUPLICATE_FIELD: return "duplicate field";
    case KR2_ERROR_FIELD_ORDER:     return "noncanonical field order";
    case KR2_ERROR_UNKNOWN_FIELD:   return "unknown field";
    case KR2_ERROR_FIELD_SET:       return "unexpected field set";
    case KR2_ERROR_FIELD_VALUE:     return "invalid field value";
    case KR2_ERROR_TIME_RANGE:      return "invalid time range";
    case KR2_ERROR_BINDING:         return "request/grant binding mismatch";
    default:                        return "unknown parser status";
    }
}
