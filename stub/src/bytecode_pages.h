/* Authenticated paging ABI for selected-function Daedalus bytecode. */
#ifndef LETHE_BYTECODE_PAGES_H
#define LETHE_BYTECODE_PAGES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DVM_PAGE_MAGIC_SIZE          4u
#define DVM_PAGE_VERSION             1u
#define DVM_PAGE_HEADER_SIZE         128u
#define DVM_PAGE_RECORD_SIZE         24u
#define DVM_PAGE_MIN_SIZE            256u
#define DVM_PAGE_MAX_SIZE            4096u
#define DVM_PAGE_MAX_COUNT           4096u
#define DVM_PAGE_MAX_PLAINTEXT       (DVM_PAGE_MAX_SIZE * DVM_PAGE_MAX_COUNT)
#define DVM_PAGE_MASTER_KEY_SIZE     32u
#define DVM_PAGE_PROGRAM_ID_SIZE     16u
#define DVM_PAGE_SALT_SIZE           16u
#define DVM_PAGE_TAG_SIZE            16u
#define DVM_PAGE_NO_CACHE            UINT32_MAX

typedef enum DvmPageStatus {
    DVM_PAGE_OK = 0,
    DVM_PAGE_ERROR_ARGUMENT = 1,
    DVM_PAGE_ERROR_FORMAT = 2,
    DVM_PAGE_ERROR_AUTHENTICATION = 3,
    DVM_PAGE_ERROR_RANGE = 4,
    DVM_PAGE_ERROR_BUFFER = 5
} DvmPageStatus;

typedef struct DvmPageEnvelopeView {
    const uint8_t *blob;
    size_t blob_size;
    uint32_t page_size;
    uint32_t plaintext_size;
    uint32_t page_count;
    const uint8_t *program_id;
    const uint8_t *salt;
    const uint8_t *table;
    const uint8_t *data;
    const uint8_t *table_sha256;
    const uint8_t *metadata_tag;
    uint32_t table_offset;
    uint32_t data_offset;
    uint32_t table_size;
    uint32_t data_size;
} DvmPageEnvelopeView;

/* One caller-owned cache per active VM execution.  It never stores the master
 * key; the caller can reconstruct that key from key_scatter only on a miss and
 * wipe it immediately after this call returns. */
typedef struct DvmPageCache {
    DvmPageEnvelopeView view;
    uint8_t page[DVM_PAGE_MAX_SIZE];
    uint32_t cached_index;
    uint32_t cached_size;
} DvmPageCache;

/* Strict structural parse only.  Authentication happens during cache init. */
DvmPageStatus dvm_page_envelope_parse(const uint8_t *blob, size_t blob_size,
                                      DvmPageEnvelopeView *out_view);

/* Parse and authenticate the header plus complete page table. */
DvmPageStatus dvm_page_cache_init(DvmPageCache *cache,
                                  const uint8_t *blob, size_t blob_size,
                                  const uint8_t master_key[32]);

/* Authenticate and decrypt exactly one page on a miss.  A prior plaintext page
 * is volatile-wiped before any new page is opened. */
DvmPageStatus dvm_page_cache_open(DvmPageCache *cache,
                                  const uint8_t master_key[32],
                                  uint32_t page_index,
                                  const uint8_t **out_page,
                                  uint32_t *out_size);

/* Bounded cross-page read.  On failure, the complete output range is wiped. */
DvmPageStatus dvm_page_cache_read(DvmPageCache *cache,
                                  const uint8_t master_key[32],
                                  uint32_t offset, uint8_t *out,
                                  uint32_t size);

/* Wipe the cached plaintext and all parser state. */
void dvm_page_cache_wipe(DvmPageCache *cache);

#ifdef __cplusplus
}
#endif

#endif /* LETHE_BYTECODE_PAGES_H */
