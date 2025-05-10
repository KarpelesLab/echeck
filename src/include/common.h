#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Include OpenSSL headers based on the build mode */
#ifdef OPENSSL_RUNTIME_LINK
#include "openssl_runtime.h"
#else
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#endif

/* Global flags for controlling output */
extern int global_verbose_flag;

/* OpenSSL initialization */
int initialize_openssl(void);

/* Error handling utility */
void print_openssl_error(const char *msg);

/* Helper functions for extracting integers from byte arrays */
uint32_t extract_uint32(const uint8_t *data);
uint16_t extract_uint16(const uint8_t *data);

/* Helper function to print bytes in hex format */
void print_hex(const char *label, const uint8_t *data, size_t len);

#endif /* COMMON_H */