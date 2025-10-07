#pragma once

#include <cstdint>
#include <stdint.h>

#pragma pack(push, 1)
typedef struct {
    uint32_t signature;
    uint16_t version;
    uint16_t flags;
    uint16_t compression;
    uint16_t mod_time;
    uint16_t mod_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t filename_length;
    uint16_t extra_length;
} ZipHeader;
#pragma pack(pop)

bool extract_zip_header(const char *filename, uint8_t *encrypted_header,
                        uint8_t *check_byte);

void print_zip_info(const ZipHeader *header);
