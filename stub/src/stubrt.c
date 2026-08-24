/*
 * Lethe stub -- freestanding C runtime shims.
 *
 * The stub links with /NODEFAULTLIB (no CRT), but MSVC and the bundled miniz
 * still emit references to a handful of standard functions (mem*, malloc/free/
 * realloc, _fltused). We satisfy them here with tiny Win32-backed definitions:
 *   - mem* via the __movsb/__stosb intrinsics (no libcall recursion) + byte loops
 *   - malloc/free/realloc backed by the process heap (HeapAlloc)
 * These are the only "libc" the stub needs; miniz's decompressor uses malloc for
 * its inflate state and mem* for buffer moves.
 */
#include <windows.h>
#include <stddef.h>

#ifndef __clang__
#pragma intrinsic(__movsb, __stosb)
#endif

/* Tell MSVC these are real function definitions, not intrinsic overrides. */
#pragma function(memset, memcpy, memmove, memcmp)

/* Suppress C4273: UCRT headers declare malloc/free/realloc as dllimport but
 * we provide our own definitions (no CRT is linked). */
#pragma warning(disable: 4273)

/* The compiler may lower struct copies / initializers to memcpy/memset calls,
 * so these must exist as real symbols. MSVC uses rep movs/stos intrinsics;
 * Clang uses byte loops (built with -fno-builtin to prevent recursion). */
#ifdef __clang__
__attribute__((no_builtin("memset")))
#endif
void *__cdecl memset(void *dst, int c, size_t n)
{
#ifdef __clang__
    unsigned char *d = (unsigned char *)dst;
    for (size_t i = 0; i < n; i++) d[i] = (unsigned char)c;
#else
    __stosb((unsigned char *)dst, (unsigned char)c, n);
#endif
    return dst;
}

#ifdef __clang__
__attribute__((no_builtin("memcpy")))
#endif
void *__cdecl memcpy(void *dst, const void *src, size_t n)
{
#ifdef __clang__
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
#else
    __movsb((unsigned char *)dst, (const unsigned char *)src, n);
#endif
    return dst;
}

void *__cdecl memmove(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d == s || n == 0)
        return dst;
    if (d < s)
        for (size_t i = 0; i < n; i++) d[i] = s[i];
    else
        for (size_t i = n; i > 0; i--) d[i - 1] = s[i - 1];
    return dst;
}

int __cdecl memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    for (size_t i = 0; i < n; i++)
        if (x[i] != y[i]) return (int)x[i] - (int)y[i];
    return 0;
}

void *__cdecl malloc(size_t n)
{
    return HeapAlloc(GetProcessHeap(), 0, n ? n : 1);
}

void __cdecl free(void *p)
{
    if (p) HeapFree(GetProcessHeap(), 0, p);
}

void *__cdecl realloc(void *p, size_t n)
{
    if (!p) return HeapAlloc(GetProcessHeap(), 0, n ? n : 1);
    if (!n) { HeapFree(GetProcessHeap(), 0, p); return NULL; }
    return HeapReAlloc(GetProcessHeap(), 0, p, n);
}

/* Referenced by the linker if any translation unit touches floating point. */
int _fltused = 1;
