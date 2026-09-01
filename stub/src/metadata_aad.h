/* Canonical format-v2 metadata AES-GCM AAD serializer. */
#ifndef LETHE_METADATA_AAD_H
#define LETHE_METADATA_AAD_H

#include <stdint.h>
#include "pack_info.h"

#define LETHE_METADATA_AAD_SIZE 124u

/* Writes exactly LETHE_METADATA_AAD_SIZE canonical little-endian bytes. */
int lethe_metadata_aad_build(
    const PackInfo *pi,
    uint8_t out[LETHE_METADATA_AAD_SIZE]);

#endif /* LETHE_METADATA_AAD_H */
