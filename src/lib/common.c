#include "echeck.h"
#include "echeck_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Include OpenSSL headers in non-runtime mode */
#ifndef OPENSSL_RUNTIME_LINK
#include <openssl/err.h>
#endif

/* Initialize global verbose flag */
static int global_verbose_flag = 0;

/* Set verbose mode */
void set_verbose_mode(int verbose) {
    global_verbose_flag = verbose ? 1 : 0;
}

/* Check if verbose mode is enabled */
int is_verbose_mode(void) {
    return global_verbose_flag;
}

/* Static variable to track initialization status */
static int openssl_initialized = 0;

/* Initialize OpenSSL libraries */
int initialize_openssl(void) {
    if (openssl_initialized) {
        return 1;  /* Already initialized */
    }

#ifdef OPENSSL_RUNTIME_LINK
    /* Load OpenSSL functions dynamically */
    if (!init_openssl_runtime()) {
        fprintf(stderr, "Failed to initialize OpenSSL at runtime\n");
        return 0;
    }
    
    /* Register cleanup function to run at exit */
    atexit(cleanup_openssl_runtime);
#endif

    /* Modern OpenSSL initialization (3.0+) doesn't need explicit initialization calls
     * The deprecated functions were:
     * - OpenSSL_add_all_algorithms() 
     * - ERR_load_crypto_strings()
     * 
     * In OpenSSL 3.0+, these functions have been deprecated and OpenSSL
     * automatically initializes itself when needed.
     */
    
    openssl_initialized = 1;
    return 1;
}

/* Error handling utility */
void print_openssl_error(const char *msg) {
    /* Ensure OpenSSL is initialized */
    if (!initialize_openssl()) {
        fprintf(stderr, "Cannot print OpenSSL error: OpenSSL not initialized\n");
        return;
    }

    /* We will let all errors print normally, as the error handling code
     * in the specific functions will decide which errors to suppress */

    /* Print the error normally */
    fprintf(stderr, "%s: OpenSSL error occurred\n", msg);
#ifndef OPENSSL_RUNTIME_LINK
    ERR_print_errors_fp(stderr);
#endif
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
    if (is_verbose_mode()) {
        fprintf(stderr, "%s: ", label);
        for (size_t i = 0; i < len; i++) {
            fprintf(stderr, "%02x", data[i]);
        }
        fprintf(stderr, "\n");
    }
}