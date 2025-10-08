#ifndef CRACKER_H
#define CRACKER_H

#include <stdint.h>
#include <stdbool.h>
#include <cuda_runtime.h>

#define BLOCK_SIZE 256
#define BATCH_SIZE (1024 * 1024)

// host functions
void copy_crc_table_to_device(uint32_t *h_table);
void copy_charset_to_device(const char *h_charset, int size);
unsigned long long calc_total_combinations(int length, int charset_size);

// kernel
__global__ void crack_password_kernel(const uint8_t *encrypted_header,
                                      uint8_t check_byte1,
                                      uint8_t check_byte2,
                                      int pwd_len,
                                      unsigned long long start_idx,
                                      int *found_flag,
                                      char *found_password);

// device functions
__device__ void zipcrypto_init_keys(uint32_t *keys, const char *password, int length);
__device__ void zipcrypto_update_keys(uint32_t *keys, uint8_t c);
__device__ uint8_t zipcrypto_decrypt_byte(uint32_t key2);
__device__ bool zipcrypto_test_password(const char *password, int pwd_len,
                                       const uint8_t *encrypted_header,
                                       uint8_t check_byte1, uint8_t check_byte2);

#endif
