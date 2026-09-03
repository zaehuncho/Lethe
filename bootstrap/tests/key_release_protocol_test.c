#define _CRT_SECURE_NO_WARNINGS

#include "key_release_protocol.h"

#include <stdio.h>
#include <string.h>

#define VECTOR_LINE_CAPACITY (KR2_MAX_TRANSCRIPT_SIZE * 2u + 64u)

typedef struct vector_set {
    uint8_t request[KR2_MAX_REQUEST_SIZE];
    size_t request_size;
    uint8_t response[KR2_MAX_RESPONSE_SIZE];
    size_t response_size;
    uint8_t transcript[KR2_MAX_TRANSCRIPT_SIZE];
    size_t transcript_size;
} vector_set;

static int fail_at(int line, const char *detail)
{
    fprintf(stderr, "KR2 native test failed at line %d: %s\n", line, detail);
    return 1;
}

#define CHECK(condition, detail) \
    do { if (!(condition)) return fail_at(__LINE__, (detail)); } while (0)

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
    unsigned seen = 0;

    if (path == NULL || vectors == NULL)
        return 0;
    memset(vectors, 0, sizeof(*vectors));
    file = fopen(path, "rb");
    if (file == NULL)
        return 0;

    while (fgets(line, (int)sizeof(line), file) != NULL) {
        char *equals;
        size_t length = strlen(line);
        while (length > 0 && (line[length - 1] == '\r' ||
                              line[length - 1] == '\n'))
            line[--length] = '\0';
        if (length == 0 || line[0] == '#')
            continue;
        equals = strchr(line, '=');
        if (equals == NULL || equals == line || equals[1] == '\0') {
            fclose(file);
            return 0;
        }
        *equals++ = '\0';
        if (strcmp(line, "request") == 0) {
            if ((seen & 1u) != 0 ||
                !decode_hex(equals, vectors->request,
                            sizeof(vectors->request), &vectors->request_size)) {
                fclose(file);
                return 0;
            }
            seen |= 1u;
        } else if (strcmp(line, "response") == 0) {
            if ((seen & 2u) != 0 ||
                !decode_hex(equals, vectors->response,
                            sizeof(vectors->response), &vectors->response_size)) {
                fclose(file);
                return 0;
            }
            seen |= 2u;
        } else if (strcmp(line, "transcript") == 0) {
            if ((seen & 4u) != 0 ||
                !decode_hex(equals, vectors->transcript,
                            sizeof(vectors->transcript),
                            &vectors->transcript_size)) {
                fclose(file);
                return 0;
            }
            seen |= 4u;
        } else {
            fclose(file);
            return 0;
        }
    }
    fclose(file);
    return seen == 7u;
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void write_be32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static int field_tag_offset(const uint8_t *message, size_t size,
                            size_t index, size_t *out)
{
    size_t cursor = 12;
    size_t current;
    if (message == NULL || out == NULL || size < cursor)
        return 0;
    for (current = 0; current <= index; ++current) {
        uint32_t value_size;
        if (size - cursor < 5)
            return 0;
        if (current == index) {
            *out = cursor;
            return 1;
        }
        value_size = read_be32(message + cursor + 1);
        cursor += 5;
        if (size - cursor < (size_t)value_size)
            return 0;
        cursor += (size_t)value_size;
    }
    return 0;
}

static int slices_equal(kr2_slice left, kr2_slice right)
{
    return left.size == right.size &&
           (left.size == 0 || memcmp(left.data, right.data, left.size) == 0);
}

static int test_valid_vectors(const vector_set *vectors)
{
    static const char license_id[] = "LIC-2026_A";
    kr2_request_view request;
    kr2_response_view response;
    kr2_transcript_view transcript;
    kr2_status status;

    status = kr2_parse_request(
        vectors->request, vectors->request_size, &request);
    CHECK(status == KR2_OK, kr2_status_string(status));
    status = kr2_parse_response(
        vectors->response, vectors->response_size, &response);
    CHECK(status == KR2_OK, kr2_status_string(status));
    status = kr2_parse_transcript(
        vectors->transcript, vectors->transcript_size, &transcript);
    CHECK(status == KR2_OK, kr2_status_string(status));

    CHECK(request.build_id.size == KR2_BUILD_ID_SIZE, "request build ID size");
    CHECK(request.license_id.size == sizeof(license_id) - 1u,
          "request license size");
    CHECK(memcmp(request.license_id.data, license_id,
                 sizeof(license_id) - 1u) == 0, "request license bytes");
    CHECK(request.requested_at == 1770000000ULL, "request timestamp");
    CHECK(response.grant.issued_at == 1770000005ULL, "grant issued timestamp");
    CHECK(response.grant.expires_at == 1770000065ULL, "grant expiry timestamp");
    CHECK(response.signature.size == KR2_SIGNATURE_SIZE, "signature size");
    CHECK(response.grant.ciphertext.size == 32u, "ciphertext size");
    CHECK(transcript.request_frame.size == vectors->request_size,
          "transcript request frame size");
    CHECK(memcmp(transcript.request_frame.data, vectors->request,
                 vectors->request_size) == 0, "Python/native request parity");
    CHECK(slices_equal(transcript.grant_frame, response.grant_frame),
          "Python/native grant parity");
    CHECK(kr2_validate_binding(&request, &response.grant) == KR2_OK,
          "response binding");
    CHECK(kr2_validate_binding(&transcript.request,
                               &transcript.grant) == KR2_OK,
          "transcript binding");
    return 0;
}

static int test_malformed_vectors(const vector_set *vectors)
{
    uint8_t scratch[KR2_MAX_TRANSCRIPT_SIZE + 1u] = {0};
    kr2_request_view request;
    kr2_response_view response;
    kr2_transcript_view transcript;
    kr2_grant_view mismatched;
    uint8_t wrong_challenge[KR2_CHALLENGE_SIZE] = {0};
    size_t first_tag;
    size_t second_tag;
    size_t grant_start;

    CHECK(kr2_parse_request(vectors->request, vectors->request_size - 1u,
                            &request) != KR2_OK, "truncated request accepted");
    CHECK(kr2_parse_response(vectors->response, vectors->response_size - 1u,
                             &response) != KR2_OK, "truncated response accepted");
    CHECK(kr2_parse_transcript(
              vectors->transcript, vectors->transcript_size - 1u,
              &transcript) != KR2_OK, "truncated transcript accepted");

    CHECK(field_tag_offset(vectors->request, vectors->request_size,
                           0, &first_tag), "first request tag offset");
    CHECK(field_tag_offset(vectors->request, vectors->request_size,
                           1, &second_tag), "second request tag offset");

    memcpy(scratch, vectors->request, vectors->request_size);
    scratch[second_tag] = scratch[first_tag];
    CHECK(kr2_parse_request(scratch, vectors->request_size, &request) ==
              KR2_ERROR_DUPLICATE_FIELD, "duplicate request field accepted");

    memcpy(scratch, vectors->request, vectors->request_size);
    scratch[first_tag] = 2;
    scratch[second_tag] = 1;
    CHECK(kr2_parse_request(scratch, vectors->request_size, &request) ==
              KR2_ERROR_FIELD_ORDER, "out-of-order request accepted");

    memcpy(scratch, vectors->request, vectors->request_size);
    scratch[first_tag] = 127;
    CHECK(kr2_parse_request(scratch, vectors->request_size, &request) ==
              KR2_ERROR_UNKNOWN_FIELD, "unknown request field accepted");

    memcpy(scratch, vectors->request, vectors->request_size);
    write_be32(scratch + first_tag + 1u, KR2_MAX_REQUEST_SIZE + 1u);
    CHECK(kr2_parse_request(scratch, vectors->request_size, &request) ==
              KR2_ERROR_OVERSIZED, "oversized request field accepted");

    CHECK(kr2_parse_request(scratch, KR2_MAX_REQUEST_SIZE + 1u, &request) ==
              KR2_ERROR_OVERSIZED, "oversized request frame accepted");

    memcpy(scratch, vectors->request, vectors->request_size);
    scratch[second_tag + 5u] = '/';
    CHECK(kr2_parse_request(scratch, vectors->request_size, &request) ==
              KR2_ERROR_FIELD_VALUE, "noncanonical license accepted");

    memcpy(scratch, vectors->response, vectors->response_size);
    CHECK(field_tag_offset(scratch, vectors->response_size, 0, &grant_start),
          "response grant offset");
    grant_start += 5u;
    CHECK(vectors->response_size - grant_start > 12u,
          "response grant frame range");
    scratch[grant_start + 12u] = 127;
    CHECK(kr2_parse_response(scratch, vectors->response_size, &response) ==
              KR2_ERROR_UNKNOWN_FIELD, "unknown nested grant field accepted");

    CHECK(kr2_parse_transcript(
              vectors->transcript, vectors->transcript_size,
              &transcript) == KR2_OK, "valid transcript prerequisite");
    mismatched = transcript.grant;
    mismatched.challenge.data = wrong_challenge;
    CHECK(kr2_validate_binding(&transcript.request, &mismatched) ==
              KR2_ERROR_BINDING, "mismatched challenge accepted");
    return 0;
}

int main(int argc, char **argv)
{
    vector_set vectors;
    if (argc != 2)
        return fail_at(__LINE__, "expected golden-vector path");
    if (!load_vectors(argv[1], &vectors))
        return fail_at(__LINE__, "failed to load golden vectors");
    if (test_valid_vectors(&vectors) != 0)
        return 1;
    if (test_malformed_vectors(&vectors) != 0)
        return 1;
    puts("KR2 native parser vectors: PASS");
    return 0;
}
