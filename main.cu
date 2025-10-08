#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cuda_runtime.h>
#include "zip_utils.h"
#include "crc32.h"
#include "cracker.h"

int main(int argc, char **argv) {
    if(argc < 2) {
        printf("Usage: %s <zipfile> [min_length] [max_length]\n", argv[0]);
        printf("  Default: min_length=4, max_length=8\n");
        return 1;
    }

    const char *zipfile = argv[1];
    int min_len = (argc >= 3) ? atoi(argv[2]) : 4;
    int max_len = (argc >= 4) ? atoi(argv[3]) : 8;

    if(min_len < 1 || max_len > 15 || min_len > max_len) {
        printf("Error: Invalid length range (min: 1, max: 15, min <= max)\n");
        return 1;
    }

    uint8_t encrypted_header[12];
    uint8_t check_byte1, check_byte2;
    if(!extract_zip_header(zipfile, encrypted_header, &check_byte1, &check_byte2)) {
        return 1;
    }

    printf("\n=== Extracted Data ===\n");
    printf("Check bytes: 0x%02x 0x%02x\n", check_byte1, check_byte2);
    printf("Encrypted header: ");
    for(int i = 0; i < 12; i++) {
        printf("%02x ", encrypted_header[i]);
    }
    printf("\n");

    // setup charset
    const char *charset = "abcdefghijklmnopqrstuvwxyz0123456789";
    int charset_size = strlen(charset);

    printf("\n=== Starting Attack ===\n");
    printf("Password length range: %d - %d\n", min_len, max_len);
    printf("Charset size: %d\n\n", charset_size);

    // generate CRC32 table
    uint32_t h_crc32_table[256];
    generate_crc32_table(h_crc32_table);

    // copy to GPU
    copy_crc_table_to_device(h_crc32_table);
    copy_charset_to_device(charset, charset_size);

    // allocate device memory
    uint8_t *d_encrypted_header;
    int *d_found_flag;
    char *d_found_password;
    int h_found_flag = 0;
    char h_found_password[16] = {0};

    cudaMalloc(&d_encrypted_header, 12);
    cudaMalloc(&d_found_flag, sizeof(int));
    cudaMalloc(&d_found_password, 16);

    cudaMemcpy(d_encrypted_header, encrypted_header, 12, cudaMemcpyHostToDevice);

    int num_blocks = (BATCH_SIZE + BLOCK_SIZE - 1) / BLOCK_SIZE;

    bool password_found = false;

    for(int pwd_len = min_len; pwd_len <= max_len && !password_found; pwd_len++) {
        unsigned long long total = calc_total_combinations(pwd_len, charset_size);

        printf("=== Testing length %d ===\n", pwd_len);
        printf("Total combinations: %llu\n", total);

        h_found_flag = 0;
        cudaMemcpy(d_found_flag, &h_found_flag, sizeof(int), cudaMemcpyHostToDevice);

        for(unsigned long long offset = 0; offset < total; offset += BATCH_SIZE) {
            crack_password_kernel<<<num_blocks, BLOCK_SIZE>>>(
                d_encrypted_header, check_byte1, check_byte2, pwd_len, offset,
                d_found_flag, d_found_password
            );

            cudaDeviceSynchronize();

            cudaMemcpy(&h_found_flag, d_found_flag, sizeof(int), cudaMemcpyDeviceToHost);

            if(h_found_flag) {
                cudaMemcpy(h_found_password, d_found_password, 16, cudaMemcpyDeviceToHost);
                printf("\n✓ PASSWORD FOUND: '%s' (length: %d)\n", h_found_password, pwd_len);
                password_found = true;
                break;
            }

            if((offset / BATCH_SIZE) % 100 == 0 && offset > 0) {
                printf("Progress: %.2f%% | Tested: %llu/%llu\n",
                       (float)offset / total * 100.0f, offset, total);
            }
        }

        if(!password_found) {
            printf("No match found for length %d\n\n", pwd_len);
        }
    }

    if(!password_found) {
        printf("\n✗ Password not found in length range %d-%d\n", min_len, max_len);
    }

    // cleanup
    cudaFree(d_encrypted_header);
    cudaFree(d_found_flag);
    cudaFree(d_found_password);

    return 0;
}
