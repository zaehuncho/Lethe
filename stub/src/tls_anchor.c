/* Minimal freestanding TLS directory for the grafted stub.
 *
 * This mirrors the small portion of the MSVC CRT's tlssup.c that a /NODEFAULTLIB
 * image needs. The callback is always safe before unpack: its loader-side
 * dispatcher observes inactive zero-initialized state and returns. Once the
 * protected TLS recipe is committed, the same callback supplies the original
 * image's full process/thread lifecycle.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdint.h>

#include "tls_anchor.h"
#include "pe_loader.h"

#pragma section(".tls$AAA", long, read, write)
#pragma section(".tls$ZZZ", long, read, write)
#pragma section(".rdata$T", long, read)

static void NTAPI lethe_stub_tls_callback(PVOID module, DWORD reason,
                                          PVOID reserved)
{
    pe_loader_tls_anchor_dispatch(module, reason, reserved);
}

__declspec(allocate(".tls$AAA"))
static uint8_t s_orion_tls_reserve[ORION_STUB_TLS_ALLOCATION_SIZE] = {0};
__declspec(allocate(".tls$ZZZ"))
static uint8_t s_orion_tls_end = 0;

__declspec(allocate(".rdata$T"))
static PIMAGE_TLS_CALLBACK const s_orion_tls_callbacks[2] = {
    lethe_stub_tls_callback,
    NULL
};

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
