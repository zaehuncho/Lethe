/* OS-managed static TLS anchor used by packed images.
 *
 * The output PE preserves this stub TLS directory so Windows reserves one
 * real static-TLS index for every thread before StubDllMain runs. The manual
 * loader maps the original image's _tls_index to that slot and copies its
 * template into this capacity. This avoids guessing the size of the TEB TLS
 * vector or writing into an unreserved slot.
 */
#ifndef LETHE_TLS_ANCHOR_H
#define LETHE_TLS_ANCHOR_H

#include <windows.h>

#define ORION_STUB_TLS_CAPACITY 4096u

DWORD lethe_stub_tls_index(void);

#endif /* LETHE_TLS_ANCHOR_H */
