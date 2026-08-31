#pragma once
/*
 * Clang 13 (heroims/obfuscator) declares __movsb in <intrin.h> as static
 * inline but OLLVM obfuscation passes can prevent the definition from being
 * emitted, causing an undefined symbol at link time.
 *
 * Fix: redirect __movsb calls to memcpy (stubrt.c provides the real symbol;
 * built with -fno-builtin so the byte loop won't recurse). __stosb is a Clang
 * builtin and links correctly — no override needed.
 *
 * Include AFTER <windows.h>/<intrin.h>.
 */
#ifdef __clang__
void *__cdecl memcpy(void *, const void *, size_t);
void *__cdecl memset(void *, int, size_t);
#define __movsb(d, s, n) memcpy((d), (s), (n))
#define __stosb(d, v, n) memset((d), (v), (n))
#else
#pragma intrinsic(__movsb, __stosb)
#endif
