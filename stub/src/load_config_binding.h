#ifndef LETHE_LOAD_CONFIG_BINDING_H
#define LETHE_LOAD_CONFIG_BINDING_H

#include <stdint.h>

#define LETHE_LCFG_RUNTIME_HEADER_SIZE     80u
#define LETHE_LCFG_RUNTIME_ENTRY_SIZE       8u
#define LETHE_LCFG_RUNTIME_TARGET_SIZE      8u
#define LETHE_LCFG_RUNTIME_RELOCATION_SIZE  4u
#define LETHE_LCFG_RUNTIME_VERSION          3u

int lethe_load_config_binding_verify(const uint8_t *image,
                                     uint32_t packed_image_size,
                                     const uint8_t *recipe,
                                     uint32_t recipe_size);

#endif
