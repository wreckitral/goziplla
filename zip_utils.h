#ifndef ZIP_UTILS_H
#define ZIP_UTILS_H

#include <stdint.h>
#include <stdbool.h>

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
} __attribute__((packed)) ZipHeader;

bool extract_zip_header(const char *filename, uint8_t *encrypted_header,
                        uint8_t *check_byte1, uint8_t *check_byte2);

void print_zip_info(const ZipHeader *header);

#endif
