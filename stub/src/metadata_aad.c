#include "metadata_aad.h"

static const uint8_t s_metadata_aad_domain[16] = {
    'L','E','T','H','E','-','M','E','T','A','-','A','A','D','2','\0'
};

static void store_u32_le(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

static void store_u64_le(uint8_t *out, uint64_t value)
{
    store_u32_le(out, (uint32_t)value);
    store_u32_le(out + 4, (uint32_t)(value >> 32));
}

int lethe_metadata_aad_build(
    const PackInfo *pi,
    uint8_t out[LETHE_METADATA_AAD_SIZE])
{
    uint32_t i;
    uint8_t *cursor;

    if (!pi || !out)
        return 1;

    for (i = 0; i < 16u; ++i)
        out[i] = s_metadata_aad_domain[i];
    cursor = out + 16u;

#define PUT_U32(field) do { store_u32_le(cursor, (field)); cursor += 4u; } while (0)
    PUT_U32(pi->format_ver);
    PUT_U32(pi->flags);
    store_u64_le(cursor, pi->original_image_base);
    cursor += 8u;
    PUT_U32(pi->original_size_of_image);
    PUT_U32(pi->oep_rva);
    PUT_U32(pi->is_dll);
    PUT_U32(pi->section_count);
    PUT_U32(pi->meta_rva);
    PUT_U32(pi->meta_stored_size);
    PUT_U32(pi->meta_uncompressed_size);
    PUT_U32(pi->sections_off);
    PUT_U32(pi->imports_off);
    PUT_U32(pi->imports_size);
    PUT_U32(pi->relocs_off);
    PUT_U32(pi->relocs_size);
    PUT_U32(pi->tls_off);
    PUT_U32(pi->pdata_rva);
    PUT_U32(pi->pdata_count);
    PUT_U32(pi->stub_text_rva);
    PUT_U32(pi->stub_text_size);
    PUT_U32(pi->dll_export_rva);
    PUT_U32(pi->dll_export_size);
#undef PUT_U32

    for (i = 0; i < 16u; ++i)
        *cursor++ = pi->dll_export_sha256_128[i];

    return cursor == out + LETHE_METADATA_AAD_SIZE ? 0 : 1;
}
