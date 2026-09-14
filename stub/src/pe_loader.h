#ifndef LETHE_PE_LOADER_H
#define LETHE_PE_LOADER_H

#include "pack_info.h"

#ifdef __cplusplus
extern "C" {
#endif

int pe_loader_run(void *image_base, volatile PackInfo *pi, void **out_oep);

void pe_loader_tls_anchor_dispatch(void *image_base, DWORD reason,
                                   void *reserved);
void pe_loader_tls_dll_detach(DWORD reason, void *reserved);

#ifdef __cplusplus
}
#endif

#endif /* LETHE_PE_LOADER_H */
