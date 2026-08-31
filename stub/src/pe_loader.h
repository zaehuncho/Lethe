#ifndef LETHE_PE_LOADER_H
#define LETHE_PE_LOADER_H

#include "pack_info.h"

#ifdef __cplusplus
extern "C" {
#endif

int pe_loader_run(void *image_base, volatile PackInfo *pi, void **out_oep);

int  pe_loader_tls_thread_init(void);
void pe_loader_tls_thread_free(void);

#ifdef __cplusplus
}
#endif

#endif /* LETHE_PE_LOADER_H */
