#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <stdint.h>
#include <stddef.h>

#include "load_config_binding.h"
#include "crypto.h"

#define LCFG_RECIPE_RELOCATION_COUNT 20u
#define LCFG_RECIPE_DLL_CHARACTERISTICS 24u
#define LCFG_RECIPE_DIRECTORY_RVA 28u
#define LCFG_RECIPE_DIRECTORY_SIZE 32u
#define LCFG_RECIPE_SECTION_RVA 36u
#define LCFG_RECIPE_SECTION_SIZE 40u
#define LCFG_RECIPE_SECTION_CHARACTERISTICS 44u
#define LCFG_RECIPE_SHA256 48u

static uint16_t lcfg_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t lcfg_u32(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t lcfg_u64(const uint8_t *p)
{
    uint64_t value = 0;
    uint32_t i;
    for (i = 0; i < 8u; ++i)
        value |= (uint64_t)p[i] << (i * 8u);
    return value;
}

static void lcfg_put_u64(uint8_t *p, uint64_t value)
{
    uint32_t i;
    for (i = 0; i < 8u; ++i)
        p[i] = (uint8_t)(value >> (i * 8u));
}

static void lcfg_wipe(void *p, size_t size)
{
    volatile uint8_t *out = (volatile uint8_t *)p;
    while (size--)
        *out++ = 0;
}

static int lcfg_range(uint32_t start, uint32_t size, uint32_t bound)
{
    return size <= bound && start <= bound - size;
}

static int lcfg_name_matches(const uint8_t *name)
{
    static const uint8_t expected[8] = {
        '.', 'l', 'c', 'f', 'g', 0, 0, 0
    };
    uint32_t i;
    for (i = 0; i < 8u; ++i) {
        if (name[i] != expected[i])
            return 0;
    }
    return 1;
}

int lethe_load_config_slots_restore_verified(uint8_t *image,
                                             uint32_t original_image_size,
                                             uint32_t packed_image_size,
                                             const uint8_t *recipe,
                                             uint32_t recipe_size)
{
    uint32_t slot_count;
    uint32_t target_count;
    uint32_t relocation_count;
    uint32_t i;

    if (!image || !recipe || recipe_size < LETHE_LCFG_RUNTIME_HEADER_SIZE ||
        original_image_size > packed_image_size ||
        recipe[0] != 'L' || recipe[1] != 'C' || recipe[2] != 'F' ||
        recipe[3] != 'G' || recipe[4] != 'R' || recipe[5] != 'T' ||
        recipe[6] != '1' || recipe[7] != '\0' ||
        lcfg_u32(recipe + 8u) != LETHE_LCFG_RUNTIME_VERSION)
        return 1;
    slot_count = lcfg_u32(recipe + 12u);
    target_count = lcfg_u32(recipe + 16u);
    relocation_count = lcfg_u32(recipe + LCFG_RECIPE_RELOCATION_COUNT);
    if ((uint64_t)LETHE_LCFG_RUNTIME_HEADER_SIZE +
            (uint64_t)slot_count * LETHE_LCFG_RUNTIME_ENTRY_SIZE +
            (uint64_t)target_count * LETHE_LCFG_RUNTIME_TARGET_SIZE +
            (uint64_t)relocation_count * LETHE_LCFG_RUNTIME_RELOCATION_SIZE !=
        recipe_size)
        return 1;

    for (i = 0; i < slot_count; ++i) {
        const uint8_t *entry = recipe + LETHE_LCFG_RUNTIME_HEADER_SIZE +
                               (uint64_t)i * LETHE_LCFG_RUNTIME_ENTRY_SIZE;
        uint32_t source_rva = lcfg_u32(entry);
        uint32_t shadow_rva = lcfg_u32(entry + 4u);
        uint32_t j;
        if ((source_rva & 7u) != 0 || (shadow_rva & 7u) != 0 ||
            !lcfg_range(source_rva, 8u, original_image_size) ||
            !lcfg_range(shadow_rva, 8u, packed_image_size))
            return 1;
        for (j = 0; j < i; ++j) {
            const uint8_t *prior = recipe + LETHE_LCFG_RUNTIME_HEADER_SIZE +
                                   (uint64_t)j *
                                       LETHE_LCFG_RUNTIME_ENTRY_SIZE;
            if (lcfg_u32(prior) == source_rva ||
                lcfg_u32(prior + 4u) == shadow_rva)
                return 1;
        }
        lcfg_put_u64(image + source_rva, lcfg_u64(image + shadow_rva));
    }
    return 0;
}

static int lcfg_shadow_overlap(const uint8_t *recipe, uint32_t slot_count,
                               uint32_t relocation_rva,
                               int *out_exact_shadow)
{
    uint32_t i;
    *out_exact_shadow = 0;
    for (i = 0; i < slot_count; ++i) {
        const uint8_t *entry = recipe + LETHE_LCFG_RUNTIME_HEADER_SIZE +
                               (uint64_t)i * LETHE_LCFG_RUNTIME_ENTRY_SIZE;
        uint32_t shadow_rva = lcfg_u32(entry + 4u);
        if (shadow_rva == relocation_rva) {
            *out_exact_shadow = 1;
            return 0;
        }
        if ((uint64_t)shadow_rva < (uint64_t)relocation_rva + 8u &&
            (uint64_t)relocation_rva < (uint64_t)shadow_rva + 8u)
            return 1;
    }
    return 0;
}

int lethe_load_config_binding_verify(const uint8_t *image,
                                     uint32_t packed_image_size,
                                     const uint8_t *recipe,
                                     uint32_t recipe_size)
{
    uint32_t slot_count;
    uint32_t target_count;
    uint32_t relocation_count;
    uint32_t expected_dll_characteristics;
    uint32_t expected_directory_rva;
    uint32_t expected_directory_size;
    uint32_t expected_section_rva;
    uint32_t expected_section_size;
    uint32_t expected_section_characteristics;
    uint32_t pe_offset;
    uint32_t optional_offset;
    uint32_t optional_size;
    uint32_t section_table_offset;
    uint32_t section_count;
    uint32_t relocation_offset;
    uint32_t matching_sections = 0;
    uint32_t i;
    uint8_t *canonical = NULL;
    uint8_t digest[32];
    int result = 1;

    if (!image || !recipe || recipe_size < LETHE_LCFG_RUNTIME_HEADER_SIZE)
        return 1;
    if (recipe[0] != 'L' || recipe[1] != 'C' || recipe[2] != 'F' ||
        recipe[3] != 'G' || recipe[4] != 'R' || recipe[5] != 'T' ||
        recipe[6] != '1' || recipe[7] != '\0' ||
        lcfg_u32(recipe + 8u) != LETHE_LCFG_RUNTIME_VERSION)
        return 1;

    slot_count = lcfg_u32(recipe + 12u);
    target_count = lcfg_u32(recipe + 16u);
    relocation_count = lcfg_u32(recipe + LCFG_RECIPE_RELOCATION_COUNT);
    if ((uint64_t)LETHE_LCFG_RUNTIME_HEADER_SIZE +
            (uint64_t)slot_count * LETHE_LCFG_RUNTIME_ENTRY_SIZE +
            (uint64_t)target_count * LETHE_LCFG_RUNTIME_TARGET_SIZE +
            (uint64_t)relocation_count * LETHE_LCFG_RUNTIME_RELOCATION_SIZE !=
        recipe_size)
        return 1;

    expected_dll_characteristics =
        lcfg_u32(recipe + LCFG_RECIPE_DLL_CHARACTERISTICS);
    expected_directory_rva = lcfg_u32(recipe + LCFG_RECIPE_DIRECTORY_RVA);
    expected_directory_size = lcfg_u32(recipe + LCFG_RECIPE_DIRECTORY_SIZE);
    expected_section_rva = lcfg_u32(recipe + LCFG_RECIPE_SECTION_RVA);
    expected_section_size = lcfg_u32(recipe + LCFG_RECIPE_SECTION_SIZE);
    expected_section_characteristics =
        lcfg_u32(recipe + LCFG_RECIPE_SECTION_CHARACTERISTICS);
    if (expected_dll_characteristics > 0xFFFFu ||
        expected_section_rva == 0 || expected_section_size == 0 ||
        expected_directory_size == 0 ||
        !lcfg_range(expected_section_rva, expected_section_size,
                    packed_image_size) ||
        expected_directory_rva < expected_section_rva ||
        (uint64_t)expected_directory_rva + expected_directory_size >
            (uint64_t)expected_section_rva + expected_section_size)
        return 1;

    if (packed_image_size < 0x40u || image[0] != 'M' || image[1] != 'Z')
        return 1;
    pe_offset = lcfg_u32(image + 0x3Cu);
    if (!lcfg_range(pe_offset, 24u, packed_image_size) ||
        image[pe_offset] != 'P' || image[pe_offset + 1u] != 'E' ||
        image[pe_offset + 2u] != 0 || image[pe_offset + 3u] != 0)
        return 1;
    section_count = lcfg_u16(image + pe_offset + 6u);
    optional_size = lcfg_u16(image + pe_offset + 20u);
    optional_offset = pe_offset + 24u;
    if (optional_size < 0xF0u ||
        !lcfg_range(optional_offset, optional_size, packed_image_size) ||
        lcfg_u16(image + optional_offset) != 0x20Bu ||
        lcfg_u16(image + optional_offset + 0x46u) !=
            expected_dll_characteristics ||
        lcfg_u32(image + optional_offset + 0x6Cu) <= 10u ||
        lcfg_u32(image + optional_offset + 0xC0u) !=
            expected_directory_rva ||
        lcfg_u32(image + optional_offset + 0xC4u) !=
            expected_directory_size)
        return 1;

    section_table_offset = optional_offset + optional_size;
    if (section_count == 0 ||
        !lcfg_range(section_table_offset, section_count * 40u,
                    packed_image_size))
        return 1;
    for (i = 0; i < section_count; ++i) {
        const uint8_t *section = image + section_table_offset + i * 40u;
        if (!lcfg_name_matches(section))
            continue;
        ++matching_sections;
        if (lcfg_u32(section + 8u) != expected_section_size ||
            lcfg_u32(section + 12u) != expected_section_rva ||
            lcfg_u32(section + 36u) != expected_section_characteristics)
            return 1;
    }
    if (matching_sections != 1u)
        return 1;

    canonical = (uint8_t *)VirtualAlloc(
        NULL, expected_section_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!canonical)
        return 1;
    for (i = 0; i < expected_section_size; ++i)
        canonical[i] = image[expected_section_rva + i];

    for (i = 0; i < slot_count; ++i) {
        const uint8_t *entry = recipe + LETHE_LCFG_RUNTIME_HEADER_SIZE +
                               (uint64_t)i * LETHE_LCFG_RUNTIME_ENTRY_SIZE;
        uint32_t shadow_rva = lcfg_u32(entry + 4u);
        uint32_t j;
        if (shadow_rva < expected_section_rva ||
            (uint64_t)shadow_rva + 8u >
                (uint64_t)expected_section_rva + expected_section_size)
            goto done;
        for (j = 0; j < i; ++j) {
            const uint8_t *prior = recipe + LETHE_LCFG_RUNTIME_HEADER_SIZE +
                                   (uint64_t)j * LETHE_LCFG_RUNTIME_ENTRY_SIZE;
            if (lcfg_u32(prior + 4u) == shadow_rva)
                goto done;
        }
        lcfg_put_u64(canonical + shadow_rva - expected_section_rva, 0);
    }

    relocation_offset = LETHE_LCFG_RUNTIME_HEADER_SIZE +
                        slot_count * LETHE_LCFG_RUNTIME_ENTRY_SIZE +
                        target_count * LETHE_LCFG_RUNTIME_TARGET_SIZE;
    for (i = 0; i < relocation_count; ++i) {
        uint32_t relocation_rva = lcfg_u32(
            recipe + relocation_offset +
            (uint64_t)i * LETHE_LCFG_RUNTIME_RELOCATION_SIZE);
        uint32_t offset;
        uint64_t value;
        uint64_t runtime_base = (uint64_t)(uintptr_t)image;
        int exact_shadow;
        if (i > 0 && relocation_rva <= lcfg_u32(
                recipe + relocation_offset +
                (uint64_t)(i - 1u) * LETHE_LCFG_RUNTIME_RELOCATION_SIZE))
            goto done;
        if (relocation_rva < expected_section_rva ||
            (uint64_t)relocation_rva + 8u >
                (uint64_t)expected_section_rva + expected_section_size ||
            lcfg_shadow_overlap(recipe, slot_count, relocation_rva,
                                &exact_shadow) != 0)
            goto done;
        if (exact_shadow)
            continue;
        offset = relocation_rva - expected_section_rva;
        value = lcfg_u64(canonical + offset);
        if (value < runtime_base || value - runtime_base >= packed_image_size)
            goto done;
        lcfg_put_u64(canonical + offset, value - runtime_base);
    }

    if (crypto_sha256(canonical, expected_section_size, digest) != 0)
        goto done;
    result = 0;
    for (i = 0; i < sizeof(digest); ++i)
        result |= digest[i] ^ recipe[LCFG_RECIPE_SHA256 + i];
    result = result != 0;

done:
    lcfg_wipe(digest, sizeof(digest));
    lcfg_wipe(canonical, expected_section_size);
    VirtualFree(canonical, 0, MEM_RELEASE);
    return result;
}
