#include "bytecode_pages.h"

#include <stddef.h>
#include <stdint.h>

#include "crypto.h"

#define DVM_PAGE_FLAGS_OFFSET          8u
#define DVM_PAGE_PAGE_SIZE_OFFSET     12u
#define DVM_PAGE_PLAINTEXT_OFFSET     16u
#define DVM_PAGE_COUNT_OFFSET         20u
#define DVM_PAGE_PROGRAM_ID_OFFSET    24u
#define DVM_PAGE_SALT_OFFSET          40u
#define DVM_PAGE_TABLE_OFFSET_OFFSET  56u
#define DVM_PAGE_DATA_OFFSET_OFFSET   60u
#define DVM_PAGE_TABLE_SIZE_OFFSET    64u
#define DVM_PAGE_DATA_SIZE_OFFSET     68u
#define DVM_PAGE_HEADER_PREFIX_SIZE   72u
#define DVM_PAGE_TABLE_HASH_OFFSET    72u
#define DVM_PAGE_META_TAG_OFFSET     104u
#define DVM_PAGE_RESERVED_OFFSET     120u
#define DVM_PAGE_NONCE_SIZE           12u
#define DVM_PAGE_MATERIAL_SIZE        44u

static const uint8_t DVM_META_INFO[] = "LetheDvmMetaKeyNonceV1";
static const uint8_t DVM_PAGE_INFO[] = "LetheDvmPageKeyNonceV1";
static const uint8_t DVM_META_AAD_DOMAIN[16] = {
    0x4c, 0x65, 0x74, 0x68, 0x65, 0x44, 0x76, 0x6d,
    0x4d, 0x65, 0x74, 0x61, 0x41, 0x41, 0x44, 0x31
};
static const uint8_t DVM_PAGE_AAD_DOMAIN[16] = {
    0x4c, 0x65, 0x74, 0x68, 0x65, 0x44, 0x76, 0x6d,
    0x50, 0x61, 0x67, 0x65, 0x41, 0x41, 0x44, 0x31
};

static uint16_t dvm_rd16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t dvm_rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void dvm_wr32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static void dvm_copy(uint8_t *out, const uint8_t *in, size_t size)
{
    size_t i;
    for (i = 0; i < size; ++i)
        out[i] = in[i];
}

static int dvm_equal(const uint8_t *left, const uint8_t *right, size_t size)
{
    uint8_t difference = 0;
    size_t i;
    for (i = 0; i < size; ++i)
        difference |= (uint8_t)(left[i] ^ right[i]);
    return difference == 0;
}

static int dvm_is_page_size(uint32_t value)
{
    return value >= DVM_PAGE_MIN_SIZE && value <= DVM_PAGE_MAX_SIZE &&
           (value & (value - 1u)) == 0;
}

static void dvm_evict(DvmPageCache *cache)
{
    orion_secure_wipe(cache->page, sizeof(cache->page));
    cache->cached_index = DVM_PAGE_NO_CACHE;
    cache->cached_size = 0;
}

static int dvm_derive_material(const uint8_t master_key[32],
                               const uint8_t salt[16],
                               const uint8_t *prefix, size_t prefix_size,
                               const uint8_t program_id[16],
                               uint32_t page_index, int include_index,
                               uint8_t material[DVM_PAGE_MATERIAL_SIZE])
{
    uint8_t info[sizeof(DVM_PAGE_INFO) - 1u +
                 DVM_PAGE_PROGRAM_ID_SIZE + sizeof(uint32_t)];
    size_t info_size = prefix_size + DVM_PAGE_PROGRAM_ID_SIZE;

    dvm_copy(info, prefix, prefix_size);
    dvm_copy(info + prefix_size, program_id, DVM_PAGE_PROGRAM_ID_SIZE);
    if (include_index) {
        dvm_wr32(info + info_size, page_index);
        info_size += sizeof(uint32_t);
    }
    if (crypto_hkdf_sha256(master_key, DVM_PAGE_MASTER_KEY_SIZE,
                           salt, DVM_PAGE_SALT_SIZE,
                           info, info_size,
                           material, DVM_PAGE_MATERIAL_SIZE) != 0) {
        orion_secure_wipe(info, sizeof(info));
        orion_secure_wipe(material, DVM_PAGE_MATERIAL_SIZE);
        return 0;
    }
    orion_secure_wipe(info, sizeof(info));
    return 1;
}

static void dvm_build_page_aad(const DvmPageEnvelopeView *view,
                               uint32_t page_index, uint32_t page_size,
                               uint32_t ciphertext_offset,
                               uint8_t out[100])
{
    dvm_copy(out, DVM_PAGE_AAD_DOMAIN, sizeof(DVM_PAGE_AAD_DOMAIN));
    dvm_copy(out + sizeof(DVM_PAGE_AAD_DOMAIN), view->blob,
             DVM_PAGE_HEADER_PREFIX_SIZE);
    dvm_wr32(out + 88u, page_index);
    dvm_wr32(out + 92u, page_size);
    dvm_wr32(out + 96u, ciphertext_offset);
}

DvmPageStatus dvm_page_envelope_parse(const uint8_t *blob, size_t blob_size,
                                      DvmPageEnvelopeView *out_view)
{
    DvmPageEnvelopeView view;
    uint32_t expected_count;
    uint32_t page_index;
    uint32_t remaining;
    uint64_t offset;
    size_t max_size = (size_t)DVM_PAGE_HEADER_SIZE +
                      (size_t)DVM_PAGE_MAX_COUNT * DVM_PAGE_RECORD_SIZE +
                      (size_t)DVM_PAGE_MAX_PLAINTEXT;
    size_t i;

    if (out_view != NULL)
        orion_secure_wipe(out_view, sizeof(*out_view));
    if (blob == NULL || out_view == NULL)
        return DVM_PAGE_ERROR_ARGUMENT;
    if (blob_size < DVM_PAGE_HEADER_SIZE || blob_size > max_size)
        return DVM_PAGE_ERROR_FORMAT;
    if (blob[0] != 'D' || blob[1] != 'V' ||
        blob[2] != 'P' || blob[3] != 'G' ||
        dvm_rd16(blob + 4u) != DVM_PAGE_VERSION ||
        dvm_rd16(blob + 6u) != DVM_PAGE_HEADER_SIZE ||
        dvm_rd32(blob + DVM_PAGE_FLAGS_OFFSET) != 0)
        return DVM_PAGE_ERROR_FORMAT;

    view.blob = blob;
    view.blob_size = blob_size;
    view.page_size = dvm_rd32(blob + DVM_PAGE_PAGE_SIZE_OFFSET);
    view.plaintext_size = dvm_rd32(blob + DVM_PAGE_PLAINTEXT_OFFSET);
    view.page_count = dvm_rd32(blob + DVM_PAGE_COUNT_OFFSET);
    view.program_id = blob + DVM_PAGE_PROGRAM_ID_OFFSET;
    view.salt = blob + DVM_PAGE_SALT_OFFSET;
    view.table_offset = dvm_rd32(blob + DVM_PAGE_TABLE_OFFSET_OFFSET);
    view.data_offset = dvm_rd32(blob + DVM_PAGE_DATA_OFFSET_OFFSET);
    view.table_size = dvm_rd32(blob + DVM_PAGE_TABLE_SIZE_OFFSET);
    view.data_size = dvm_rd32(blob + DVM_PAGE_DATA_SIZE_OFFSET);
    view.table_sha256 = blob + DVM_PAGE_TABLE_HASH_OFFSET;
    view.metadata_tag = blob + DVM_PAGE_META_TAG_OFFSET;

    if (!dvm_is_page_size(view.page_size) || view.plaintext_size == 0 ||
        view.plaintext_size > DVM_PAGE_MAX_PLAINTEXT)
        return DVM_PAGE_ERROR_FORMAT;
    expected_count = (view.plaintext_size + view.page_size - 1u) /
                     view.page_size;
    if (view.page_count != expected_count ||
        view.page_count > DVM_PAGE_MAX_COUNT)
        return DVM_PAGE_ERROR_FORMAT;
    if (view.table_offset != DVM_PAGE_HEADER_SIZE ||
        view.table_size != view.page_count * DVM_PAGE_RECORD_SIZE ||
        view.data_offset != view.table_offset + view.table_size ||
        view.data_size != view.plaintext_size ||
        (uint64_t)view.data_offset + view.data_size != (uint64_t)blob_size)
        return DVM_PAGE_ERROR_FORMAT;
    for (i = DVM_PAGE_RESERVED_OFFSET; i < DVM_PAGE_HEADER_SIZE; ++i) {
        if (blob[i] != 0)
            return DVM_PAGE_ERROR_FORMAT;
    }

    view.table = blob + view.table_offset;
    view.data = blob + view.data_offset;
    remaining = view.plaintext_size;
    offset = view.data_offset;
    for (page_index = 0; page_index < view.page_count; ++page_index) {
        const uint8_t *record = view.table +
                                page_index * DVM_PAGE_RECORD_SIZE;
        uint32_t expected_size = remaining < view.page_size ?
                                 remaining : view.page_size;
        if (dvm_rd32(record) != expected_size ||
            dvm_rd32(record + 4u) != offset)
            return DVM_PAGE_ERROR_FORMAT;
        remaining -= expected_size;
        offset += expected_size;
    }
    if (remaining != 0 || offset != blob_size)
        return DVM_PAGE_ERROR_FORMAT;
    *out_view = view;
    return DVM_PAGE_OK;
}

static DvmPageStatus dvm_authenticate_metadata(
    const DvmPageEnvelopeView *view, const uint8_t master_key[32])
{
    uint8_t table_hash[32];
    uint8_t material[DVM_PAGE_MATERIAL_SIZE];
    uint8_t aad[sizeof(DVM_META_AAD_DOMAIN) + DVM_PAGE_HEADER_SIZE];
    int ok;

    if (crypto_sha256(view->table, view->table_size, table_hash) != 0)
        return DVM_PAGE_ERROR_AUTHENTICATION;
    if (!dvm_equal(table_hash, view->table_sha256, sizeof(table_hash))) {
        orion_secure_wipe(table_hash, sizeof(table_hash));
        return DVM_PAGE_ERROR_AUTHENTICATION;
    }
    orion_secure_wipe(table_hash, sizeof(table_hash));
    if (!dvm_derive_material(master_key, view->salt,
                             DVM_META_INFO, sizeof(DVM_META_INFO) - 1u,
                             view->program_id, 0, 0, material))
        return DVM_PAGE_ERROR_AUTHENTICATION;

    dvm_copy(aad, DVM_META_AAD_DOMAIN, sizeof(DVM_META_AAD_DOMAIN));
    dvm_copy(aad + sizeof(DVM_META_AAD_DOMAIN), view->blob,
             DVM_PAGE_HEADER_SIZE);
    orion_secure_wipe(aad + sizeof(DVM_META_AAD_DOMAIN) +
                      DVM_PAGE_META_TAG_OFFSET, DVM_PAGE_TAG_SIZE);
    ok = crypto_aes256gcm_decrypt(
        material, material + DVM_PAGE_MASTER_KEY_SIZE,
        NULL, 0, view->metadata_tag, NULL, aad, sizeof(aad)) == 0;
    orion_secure_wipe(material, sizeof(material));
    orion_secure_wipe(aad, sizeof(aad));
    return ok ? DVM_PAGE_OK : DVM_PAGE_ERROR_AUTHENTICATION;
}

DvmPageStatus dvm_page_cache_init(DvmPageCache *cache,
                                  const uint8_t *blob, size_t blob_size,
                                  const uint8_t master_key[32])
{
    DvmPageStatus status;
    if (cache == NULL || master_key == NULL)
        return DVM_PAGE_ERROR_ARGUMENT;
    dvm_page_cache_wipe(cache);
    status = dvm_page_envelope_parse(blob, blob_size, &cache->view);
    if (status != DVM_PAGE_OK)
        return status;
    status = dvm_authenticate_metadata(&cache->view, master_key);
    if (status != DVM_PAGE_OK) {
        dvm_page_cache_wipe(cache);
        return status;
    }
    cache->cached_index = DVM_PAGE_NO_CACHE;
    return DVM_PAGE_OK;
}

DvmPageStatus dvm_page_cache_open(DvmPageCache *cache,
                                  const uint8_t master_key[32],
                                  uint32_t page_index,
                                  const uint8_t **out_page,
                                  uint32_t *out_size)
{
    const uint8_t *record;
    uint32_t size;
    uint32_t offset;
    uint8_t material[DVM_PAGE_MATERIAL_SIZE];
    uint8_t aad[100];
    int ok;

    if (out_page != NULL)
        *out_page = NULL;
    if (out_size != NULL)
        *out_size = 0;
    if (cache == NULL || master_key == NULL ||
        out_page == NULL || out_size == NULL)
        return DVM_PAGE_ERROR_ARGUMENT;
    if (cache->view.blob == NULL || page_index >= cache->view.page_count)
        return DVM_PAGE_ERROR_RANGE;
    if (cache->cached_index == page_index) {
        *out_page = cache->page;
        *out_size = cache->cached_size;
        return DVM_PAGE_OK;
    }

    record = cache->view.table + page_index * DVM_PAGE_RECORD_SIZE;
    offset = cache->view.data_offset + page_index * cache->view.page_size;
    size = cache->view.plaintext_size - page_index * cache->view.page_size;
    if (size > cache->view.page_size)
        size = cache->view.page_size;
    /* Geometry is derived from the authenticated, bounded view.  Requiring
     * the mutable record to remain canonical both detects post-init changes
     * and prevents attacker-controlled pointer arithmetic before GCM opens. */
    if (dvm_rd32(record) != size || dvm_rd32(record + 4u) != offset)
        return DVM_PAGE_ERROR_FORMAT;
    if (offset > cache->view.blob_size ||
        size > cache->view.blob_size - offset)
        return DVM_PAGE_ERROR_RANGE;
    dvm_evict(cache);
    if (!dvm_derive_material(master_key, cache->view.salt,
                             DVM_PAGE_INFO, sizeof(DVM_PAGE_INFO) - 1u,
                             cache->view.program_id, page_index, 1,
                             material))
        return DVM_PAGE_ERROR_AUTHENTICATION;
    dvm_build_page_aad(&cache->view, page_index, size, offset, aad);
    ok = crypto_aes256gcm_decrypt(
        material, material + DVM_PAGE_MASTER_KEY_SIZE,
        cache->view.blob + offset, size, record + 8u,
        cache->page, aad, sizeof(aad)) == 0;
    orion_secure_wipe(material, sizeof(material));
    orion_secure_wipe(aad, sizeof(aad));
    if (!ok) {
        dvm_evict(cache);
        return DVM_PAGE_ERROR_AUTHENTICATION;
    }
    cache->cached_index = page_index;
    cache->cached_size = size;
    *out_page = cache->page;
    *out_size = size;
    return DVM_PAGE_OK;
}

DvmPageStatus dvm_page_cache_read(DvmPageCache *cache,
                                  const uint8_t master_key[32],
                                  uint32_t offset, uint8_t *out,
                                  uint32_t size)
{
    uint32_t consumed = 0;
    if (cache == NULL || master_key == NULL || (out == NULL && size != 0))
        return DVM_PAGE_ERROR_ARGUMENT;
    if (cache->view.blob == NULL || offset > cache->view.plaintext_size ||
        size > cache->view.plaintext_size - offset)
        return DVM_PAGE_ERROR_RANGE;

    while (consumed < size) {
        const uint8_t *page = NULL;
        uint32_t available = 0;
        uint32_t absolute = offset + consumed;
        uint32_t page_index = absolute / cache->view.page_size;
        uint32_t within_page = absolute % cache->view.page_size;
        uint32_t take;
        DvmPageStatus status = dvm_page_cache_open(
            cache, master_key, page_index, &page, &available);
        if (status != DVM_PAGE_OK || within_page >= available) {
            orion_secure_wipe(out, size);
            return status == DVM_PAGE_OK ? DVM_PAGE_ERROR_FORMAT : status;
        }
        take = available - within_page;
        if (take > size - consumed)
            take = size - consumed;
        dvm_copy(out + consumed, page + within_page, take);
        consumed += take;
    }
    return DVM_PAGE_OK;
}

void dvm_page_cache_wipe(DvmPageCache *cache)
{
    if (cache != NULL) {
        orion_secure_wipe(cache, sizeof(*cache));
        cache->cached_index = DVM_PAGE_NO_CACHE;
    }
}
