/*
 * Lethe container ABI -- canonical C mirror of packer/container.py.
 *
 * Both files MUST stay byte-for-byte identical. Little-endian, x64. All *_rva
 * fields are RVAs within the packed module (add the runtime image base to
 * dereference). All *_off fields are byte offsets within the decrypted metadata
 * buffer. See container.py for the authoritative field docs.
 *
 * Do NOT edit this struct layout without editing container.py in lockstep; the
 * round-trip tests assert the two agree.
 */
#ifndef LETHE_PACK_INFO_H
#define LETHE_PACK_INFO_H

#include <stdint.h>

#define LETHE_MAGIC            "LETHE01"      /* 7 chars + implicit NUL = 8 bytes */
#define LETHE_MAGIC_LEN        8u
#define LETHE_FORMAT_VERSION   2u

/* PackInfo.flags bits */
#define LETHE_FLAG_HAS_TLS        0x01u
#define LETHE_FLAG_HAS_EXCEPTIONS 0x02u
#define LETHE_FLAG_ANTIDEBUG      0x04u
#define LETHE_FLAG_MEMGUARD       0x08u
#define LETHE_FLAG_PAGED_DVM      0x10u
#define LETHE_FLAG_LOAD_CONFIG    0x20u
#define LETHE_FLAG_DLL_PRELOAD_IAT 0x40u
#define LETHE_FLAG_PROCESS_HARDENING 0x80u

/* Import func entry: hint_or_ordinal == LETHE_IMPORT_BY_HASH means the function
 * is resolved by FNV-1a hash of its name (walking the export table); any other
 * value is a direct ordinal number. */
#define LETHE_IMPORT_BY_HASH     0xFFFFu

#pragma pack(push, 1)

typedef struct PackInfo {
    uint8_t  magic[8];                  /* "LETHE01\0" */
    uint32_t format_ver;                /* = LETHE_FORMAT_VERSION */
    uint32_t flags;                     /* LETHE_FLAG_* */
    uint64_t original_image_base;
    uint32_t original_size_of_image;
    uint32_t oep_rva;                   /* original entry / DllMain RVA */
    uint32_t is_dll;
    uint32_t section_count;
    /* metadata envelope locator (zlib/deflate-compressed then AES-256-GCM as one unit) */
    uint32_t meta_rva;                  /* module RVA of the encrypted envelope */
    uint32_t meta_stored_size;          /* encrypted+compressed byte count */
    uint32_t meta_uncompressed_size;
    uint8_t  meta_nonce[12];
    uint8_t  meta_tag[16];
    /* offsets within the decrypted metadata buffer */
    uint32_t sections_off;              /* -> SectionDesc[section_count] */
    uint32_t imports_off;
    uint32_t imports_size;
    uint32_t relocs_off;                /* verbatim IMAGE_BASE_RELOCATION blocks */
    uint32_t relocs_size;
    uint32_t tls_off;                   /* valid iff LETHE_FLAG_HAS_TLS */
    /* exception table: module RVA into the restored .pdata section */
    uint32_t pdata_rva;                 /* valid iff LETHE_FLAG_HAS_EXCEPTIONS */
    uint32_t pdata_count;               /* # of RUNTIME_FUNCTION */
    /* key material + tamper-evident binding */
    uint8_t  aes_key_enc[32];           /* key XOR HKDF(SHA256(stub .text)||salt) */
    uint8_t  kdf_salt[16];
    uint32_t stub_text_rva;             /* region hashed for the key binding */
    uint32_t stub_text_size;
    uint32_t dll_export_rva;            /* loader-visible export snapshot */
    uint32_t dll_export_size;
    uint8_t  dll_export_sha256_128[16]; /* authenticated SHA-256 prefix */
} PackInfo;                             /* 192 bytes */

typedef struct SectionDesc {
    uint32_t rva;
    uint32_t virtual_size;
    uint32_t stored_size;               /* compressed+encrypted byte count */
    uint32_t uncompressed_size;
    uint32_t stored_rva;                /* module RVA of the stored bytes */
    uint32_t characteristics;           /* IMAGE_SCN_* -> final page protection */
    uint8_t  gcm_nonce[12];
    uint8_t  gcm_tag[16];
} SectionDesc;                          /* 52 bytes */

#pragma pack(pop)

/* Byte-exactness guards -- must match container.py (compile-time failure if not). */
typedef char _lethe_assert_packinfo[(sizeof(PackInfo)   == 192) ? 1 : -1];
typedef char _lethe_assert_section [(sizeof(SectionDesc) ==  52) ? 1 : -1];

/*
 * Import blob (metadata buffer + imports_off, imports_size bytes):
 *   u32 enc_pool_size
 *   u8  enc_pool[enc_pool_size]      XOR-encrypted DLL name fallback strings
 *
 *   ImportEntry[] (terminated by dll_name_hash == 0):
 *     u32 dll_name_hash              FNV-1a of lowercase DLL name
 *     u8  dll_name_xor_key           random byte; XOR-decrypt pool entry
 *     u32 dll_name_enc_offset        offset into enc_pool
 *     u32 func_count
 *     FuncEntry[func_count]:
 *       u32 iat_rva                  write the resolved address here
 *       u16 hint_or_ordinal          LETHE_IMPORT_BY_HASH = by-hash; else ordinal
 *       u32 func_name_hash           FNV-1a of function name (case-sensitive)
 *       u32 preload_iat_rva          outer DLL IAT slot; zero for EXEs
 *   u32 terminator (0)
 *
 * Reloc blob (metadata buffer + relocs_off, relocs_size bytes):
 *   verbatim original .reloc: a run of IMAGE_BASE_RELOCATION blocks. Apply
 *   delta = actual_image_base - PackInfo.original_image_base to each entry.
 *
 * TLS blob (metadata buffer + tls_off, present iff LETHE_FLAG_HAS_TLS):
 *   u32 index_rva; u32 raw_start_rva; u32 raw_end_rva; u32 zero_fill;
 *   u32 callback_count; u32 callbacks[callback_count]   (callback RVAs)
 */

#endif /* LETHE_PACK_INFO_H */
