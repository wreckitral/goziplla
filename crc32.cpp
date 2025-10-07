#include "crc32.h"

void generate_crc32_table(uint32_t *table) {
    for(uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for(int j = 0; j < 8; j++) {
            if(crc & 1) // if LSB is 1 then shift the bit and XOR
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
        table[i] = crc;
    }
}
