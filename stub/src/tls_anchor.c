/* Minimal freestanding TLS directory for the grafted stub.
 *
 * This mirrors the small portion of the MSVC CRT's tlssup.c that a /NODEFAULTLIB
 * image needs. There are deliberately no stub TLS callbacks. Windows owns the
 * slot and per-thread blocks; pe_loader.c only initializes the reserved bytes
 * with the protected image's original TLS template.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdint.h>

#include "tls_anchor.h"

#pragma section(".tls$AAA", long, read, write)
#pragma section(".tls$ZZZ", long, read, write)
#pragma section(".rdata$T", long, read)

__declspec(allocate(".tls$AAA"))
static uint8_t s_orion_tls_reserve[ORION_STUB_TLS_CAPACITY] = {0};
__declspec(allocate(".tls$ZZZ"))
static uint8_t s_orion_tls_end = 0;

__declspec(allocate(".rdata$T"))
static PIMAGE_TLS_CALLBACK const s_orion_tls_callbacks[1] = {NULL};

DWORD _tls_index = 0;

__declspec(allocate(".rdata$T"))
const IMAGE_TLS_DIRECTORY64 _tls_used = {
    (ULONGLONG)(ULONG_PTR)&s_orion_tls_reserve[0],
    (ULONGLONG)(ULONG_PTR)&s_orion_tls_end,
    (ULONGLONG)(ULONG_PTR)&_tls_index,
    (ULONGLONG)(ULONG_PTR)&s_orion_tls_callbacks[0],
    0,
    0
};

#pragma comment(linker, "/INCLUDE:_tls_used")

DWORD lethe_stub_tls_index(void)
{
    return _tls_index;
}
