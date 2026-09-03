#include <stdint.h>

#include "metadata_aad.h"

static int hex_nibble(char value, uint8_t *out)
{
    if (value >= '0' && value <= '9') {
        *out = (uint8_t)(value - '0');
        return 0;
    }
    if (value >= 'a' && value <= 'f') {
        *out = (uint8_t)(value - 'a' + 10);
        return 0;
    }
    return 1;
}

int main(void)
{
    static const char expected_hex[] =
        "4c455448452d4d4554412d4141443200"
        "02000000040302018877665544332211"
        "ccbbaa9904030201010000000d0c0b0a"
        "4030201080706050c0b0a090100f0e0d"
        "14131211181716152423222128272625"
        "34333231383736354443424148474645"
        "545352516463626174737271"
        "808182838485868788898a8b8c8d8e8f";
    PackInfo pi = {0};
    uint8_t expected[LETHE_METADATA_AAD_SIZE];
    uint8_t actual[LETHE_METADATA_AAD_SIZE];
    uint32_t expected_chars;
    uint32_t i;

    pi.format_ver = LETHE_FORMAT_VERSION;
    pi.flags = 0x01020304u;
    pi.original_image_base = UINT64_C(0x1122334455667788);
    pi.original_size_of_image = 0x99AABBCCu;
    pi.oep_rva = 0x01020304u;
    pi.is_dll = 1u;
    pi.section_count = 0x0A0B0C0Du;
    pi.meta_rva = 0x10203040u;
    pi.meta_stored_size = 0x50607080u;
    pi.meta_uncompressed_size = 0x90A0B0C0u;
    pi.sections_off = 0x0D0E0F10u;
    pi.imports_off = 0x11121314u;
    pi.imports_size = 0x15161718u;
    pi.relocs_off = 0x21222324u;
    pi.relocs_size = 0x25262728u;
    pi.tls_off = 0x31323334u;
    pi.pdata_rva = 0x35363738u;
    pi.pdata_count = 0x41424344u;
    pi.stub_text_rva = 0x45464748u;
    pi.stub_text_size = 0x51525354u;
    pi.dll_export_rva = 0x61626364u;
    pi.dll_export_size = 0x71727374u;
    for (i = 0; i < 16u; ++i)
        pi.dll_export_sha256_128[i] = (uint8_t)(0x80u + i);

    expected_chars = (uint32_t)(sizeof(expected_hex) - 1u);
    if (expected_chars != LETHE_METADATA_AAD_SIZE * 2u)
        return __LINE__;
    for (i = 0; i < LETHE_METADATA_AAD_SIZE; ++i) {
        uint8_t high;
        uint8_t low;
        if (hex_nibble(expected_hex[i * 2u], &high) != 0 ||
            hex_nibble(expected_hex[i * 2u + 1u], &low) != 0)
            return __LINE__;
        expected[i] = (uint8_t)((high << 4) | low);
    }

    if (lethe_metadata_aad_build(&pi, actual) != 0)
        return __LINE__;
    for (i = 0; i < LETHE_METADATA_AAD_SIZE; ++i) {
        if (actual[i] != expected[i])
            return __LINE__;
    }
    if (lethe_metadata_aad_build(NULL, actual) == 0 ||
        lethe_metadata_aad_build(&pi, NULL) == 0)
        return __LINE__;
    return 0;
}
