#include "cracker.h"
#include <stdio.h>

__constant__ uint32_t d_crc32_table[256];
__constant__ char d_charset[64];
__constant__ int d_charset_size;

void copy_crc_table_to_device(uint32_t *h_table) {
    cudaMemcpyToSymbol(d_crc32_table, h_table, 256 * sizeof(uint32_t));
}

void copy_charset_to_device(const char *h_charset, int size) {
    cudaMemcpyToSymbol(d_charset, h_charset, size + 1);
    cudaMemcpyToSymbol(d_charset_size, &size, sizeof(int));
}

__device__ void generate_password(unsigned long long idx, char *password,
                                  int length) {
    for(int i = length - 1; i >= 0; i--) {
        password[i] = d_charset[idx % d_charset_size];
        idx /= d_charset_size;
    }
    password[length] = '\0';
}

__global__ void crack_password_kernel(const uint8_t *encrypted_header,
                                      uint8_t check_byte1,
                                      uint8_t check_byte2,
                                      int pwd_len,
                                      unsigned long long start_idx,
                                      int *found_flag,
                                      char *found_password) {
    if(*found_flag) return;

    unsigned long long idx = start_idx + (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;

    char password[16];
    generate_password(idx, password, pwd_len);

    if(threadIdx.x == 0 && blockIdx.x == 0) {
        printf("Batch %llu: charset_size=%d, first_char='%c', password='%s'\n",
               start_idx, d_charset_size, d_charset[0], password);
    }

    if(zipcrypto_test_password(password, pwd_len, encrypted_header, check_byte1, check_byte2)) {
        int old = atomicCAS(found_flag, 0, 1);
        if(old == 0) {
            printf("\n*** GPU FOUND PASSWORD: '%s' at index %llu ***\n", password, idx);
            for(int i = 0; i <= pwd_len; i++) {
                found_password[i] = password[i];
            }
        }
    }
}

unsigned long long calc_total_combinations(int length, int charset_size) {
    unsigned long long result = 1;
    for(int i = 0; i < length; i++) {
        result *= charset_size;
    }
    return result;
}

__device__ void zipcrypto_init_keys(uint32_t *keys,
                                    const char *password,
                                    int length) {
    keys[0] = 305419896;
    keys[1] = 591751049;
    keys[2] = 878082192;

    for (int i = 0; i < length; i++) {
        zipcrypto_update_keys(keys, (uint8_t)password[i]);
    }
}

__device__ void zipcrypto_update_keys(uint32_t *keys, uint8_t c) {
    keys[0] = d_crc32_table[(keys[0] ^ c) & 0xff] ^ (keys[0] >> 8);
    keys[1] = (keys[1] + (keys[0] & 0xff)) * 134775813 + 1;
    keys[2] = d_crc32_table[(keys[2] ^ (keys[1] >> 24)) & 0xff] ^ (keys[2] >> 8);
}

__device__ uint8_t zipcrypto_decrypt_byte(uint32_t key2) {
    uint16_t temp = key2 | 2;
    return ((temp * (temp ^ 1)) >> 8) & 0xff;
}

__device__ bool zipcrypto_test_password(const char *password,
                                       int pwd_len,
                                       const uint8_t *encrypted_header,
                                       uint8_t check_byte1,
                                       uint8_t check_byte2) {
    uint32_t keys[3];
    zipcrypto_init_keys(keys, password, pwd_len);

    uint8_t decrypted[12];

    for(int i = 0; i < 12; i++) {
        decrypted[i] = encrypted_header[i] ^ zipcrypto_decrypt_byte(keys[2]);
        zipcrypto_update_keys(keys, decrypted[i]);
    }

    return (decrypted[10] == check_byte1 && decrypted[11] == check_byte2);
}
