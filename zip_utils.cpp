#include "zip_utils.h"
#include <stdio.h>

bool extract_zip_header(const char *filename, uint8_t *encrypted_header,
                        uint8_t *check_byte) {
    FILE *fp = fopen(filename, "rb");
    if(!fp) {
        printf("Error: Cannot open file '%s'\n", filename);
        return false;
    }

    ZipHeader header;
    if(fread(&header, sizeof(ZipHeader), 1, fp) != 1) {
        printf("Error: Cannot read ZIP header\n");
        fclose(fp);
        return false;
    }

    // check if zip file
    if(header.signature != 0x04034b50) {
        printf("Error: Not a valid ZIP file\n");
        fclose(fp);
        return false;
    }

    // check if encrypted
    if(!(header.flags & 0x0001)) {
        printf("Error: ZIP file is not encrypted\n");
        fclose(fp);
        return false;
    }

    print_zip_info(&header);

    fseek(fp, header.filename_length + header.extra_length, SEEK_CUR);

    // read encryption header
    if(fread(encrypted_header, 1, 12, fp) != 12) {
        printf("Error: Cannot read encryption header\n");
        fclose(fp);
        return false;
    }

    // determine check byte
    if(header.flags & 0x0008) {
        *check_byte = (header.mod_time >> 8) & 0xff;
    } else {
        *check_byte = (header.crc32 >> 24) & 0xff;
    }

    fclose(fp);
    return true;
}

void print_zip_info(const ZipHeader *header) {
    printf("\n=== ZIP File Information ===\n");
    printf("Compression: %d\n", header->compression);
    printf("Flags: 0x%04x\n", header->flags);
    printf("CRC32: 0x%08x\n", header->crc32);
    printf("Compressed size: %u bytes\n", header->compressed_size);
}
