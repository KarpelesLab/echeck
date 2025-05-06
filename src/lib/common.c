#include "echeck/common.h"

/* Initialize global verbose flag */
int global_verbose_flag = 0;

/* Error handling utility */
void print_openssl_error(const char *msg) {
    fprintf(stderr, "%s: ", msg);
    ERR_print_errors_fp(stderr);
}

/* Helper to extract uint32 values from unaligned data */
uint32_t extract_uint32(const uint8_t *data) {
    return (uint32_t)data[0] | 
           ((uint32_t)data[1] << 8) | 
           ((uint32_t)data[2] << 16) | 
           ((uint32_t)data[3] << 24);
}

/* Helper to extract uint16 values from unaligned data */
uint16_t extract_uint16(const uint8_t *data) {
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

/* Helper function to print bytes in hex format */
void print_hex(const char *label, const uint8_t *data, size_t len) {
    if (global_verbose_flag) {
        fprintf(stderr, "%s: ", label);
        for (size_t i = 0; i < len; i++) {
            fprintf(stderr, "%02x", data[i]);
        }
        fprintf(stderr, "\n");
    }
}