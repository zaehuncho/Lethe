/*
 * venice_strings.h -- runtime string decryption for Lethe stub
 *
 * Position-dependent XOR: plaintext[i] = encrypted[i] ^ (key ^ (i * mul))
 * Each string uses its own random (key, mul) pair so that recovering one
 * key from known plaintext does not compromise the rest.
 *
 * Freestanding / no-CRT: no stdlib calls. All functions are __forceinline
 * so they compile directly into the caller with zero call overhead.
 */

#pragma once
#include <stdint.h>

/* Runtime narrow-string decryption.
 *   enc  -- encrypted byte array (from venice_str_data.h)
 *   out  -- caller-owned stack buffer (must hold len+1 bytes)
 *   len  -- character count (excluding NUL)
 *   key  -- per-string VSTR_xxx_KEY from venice_str_data.h
 *   mul  -- per-string VSTR_xxx_MUL from venice_str_data.h
 */
static __forceinline void vstr_dec(const uint8_t *enc, char *out,
                                   int len, uint8_t key, uint8_t mul)
{
    volatile uint8_t *d = (volatile uint8_t *)out;
    int i;
    for (i = 0; i < len; i++)
        d[i] = enc[i] ^ (key ^ (uint8_t)(i * mul));
    d[len] = '\0';
}

/* Runtime wide-string decryption.
 *   enc        -- encrypted byte array (UTF-16LE bytes, from venice_str_data.h)
 *   out        -- caller-owned stack buffer (must hold char_count+1 wchar_t)
 *   char_count -- number of wide characters (excluding NUL)
 *   key        -- per-string VSTR_xxx_KEY from venice_str_data.h
 *   mul        -- per-string VSTR_xxx_MUL from venice_str_data.h
 */
static __forceinline void vstr_dec_w(const uint8_t *enc, wchar_t *out,
                                      int char_count, uint8_t key, uint8_t mul)
{
    volatile uint8_t *d = (volatile uint8_t *)out;
    int total = char_count * 2;  /* wchar_t = 2 bytes on Windows */
    int i;
    for (i = 0; i < total; i++)
        d[i] = enc[i] ^ (key ^ (uint8_t)(i * mul));
    out[char_count] = L'\0';
}

/* Volatile zero -- prevents compiler from optimizing away the wipe. */
static __forceinline void vstr_zero(void *buf, int len)
{
    volatile uint8_t *d = (volatile uint8_t *)buf;
    int i;
    for (i = 0; i < len; i++) d[i] = 0;
}
