/*
 * Lethe stub -- key_scatter.h
 *
 * Dynamic key-fragment scattering. After the runtime AES key is derived it is
 * split into 8 fragments that are scattered across independent, randomly-offset
 * VirtualAlloc'd pages (each fragment XOR-masked with its own pad, buried in a
 * page of random noise). The fragment table itself is kept XOR-encrypted at
 * rest. The intent: no single contiguous memory dump ever captures the whole
 * 32-byte key in the clear, and the fragments relocate between section decrypts.
 *
 * Freestanding / no-CRT: implemented with Win32 (VirtualAlloc/VirtualFree),
 * bcrypt (BCryptGenRandom) and MSVC intrinsics (__stosb/__movsb) only.
 */
#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize key scattering: splits the 32-byte key into 8 fragments,
   scatters them across random VirtualAlloc'd pages with XOR encryption.
   ZEROS the input key buffer after scattering. Returns 0 on success. */
int key_scatter_init(uint8_t key[32]);

/* Reassemble the key from scattered fragments into out_key.
   Caller MUST zero out_key after use. Returns 0 on success. */
int key_scatter_get(uint8_t out_key[32]);

/* Migrate all fragments to new random locations with new XOR pads.
   Call between section decrypts to keep fragments moving. */
void key_scatter_migrate(void);

/* Destroy all fragments: zero pages, free memory, wipe state. */
void key_scatter_destroy(void);

#ifdef __cplusplus
}
#endif
