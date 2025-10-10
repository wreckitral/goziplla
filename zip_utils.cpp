#include "zip_utils.h"
#include <stdio.h>
#include <stdbool.h>

bool extract_zip_header(const char *filename, uint8_t *encrypted_header,
                        uint8_t *check_byte1, uint8_t *check_byte2) {
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

    if(header.flags & 0x0008) {
        *check_byte1 = (header.mod_time) & 0xff;
        *check_byte2 = (header.mod_time >> 8) & 0xff;
        printf("\n[Using mod_time for check: 0x%04x]\n", header.mod_time);
        printf("Check byte 10: 0x%02x\n", *check_byte1);
        printf("Check byte 11: 0x%02x\n", *check_byte2);
    } else {
        *check_byte2 = (header.crc32 >> 24) & 0xff;  // byte 11
        *check_byte1 = (header.crc32 >> 16) & 0xff;  // byte 10

        printf("\n[Using CRC32 for check: 0x%08x]\n", header.crc32);
        printf("Check byte 10: 0x%02x (from bits 16-23)\n", *check_byte1);
        printf("Check byte 11: 0x%02x (from bits 24-31)\n", *check_byte2);

        // Also show alternative interpretation
        printf("\nAlternative (if above fails):\n");
        printf("  Could be byte 10: 0x%02x (bits 8-15)\n", (header.crc32 >> 8) & 0xff);
        printf("  Could be byte 11: 0x%02x (bits 16-23)\n", (header.crc32 >> 16) & 0xff);
    }

    printf("\nEncryption header (12 bytes): ");
    for(int i = 0; i < 12; i++) {
        printf("%02x ", encrypted_header[i]);
    }
    printf("\n");

    fclose(fp);
    return true;
}

void print_zip_info(const ZipHeader *header) {
    printf("\n=== ZIP File Information ===\n");
    printf("Compression: %d\n", header->compression);
    printf("Flags: 0x%04x\n", header->flags);
    printf("  Encrypted: %s\n", (header->flags & 0x01) ? "Yes" : "No");
    printf("  Data descriptor: %s\n", (header->flags & 0x08) ? "Yes" : "No");
    printf("CRC32: 0x%08x\n", header->crc32);
    printf("Compressed size: %u bytes\n", header->compressed_size);
    printf("Uncompressed size: %u bytes\n", header->uncompressed_size);
}
