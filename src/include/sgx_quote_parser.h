#ifndef SGX_QUOTE_PARSER_H
#define SGX_QUOTE_PARSER_H

/* SGX types included via echeck.h */

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

/* Result structure for quote extraction */
typedef struct {
    unsigned char *data;
    int length;
} sgx_quote_buffer_t;

/* Extract SGX quote extension from a certificate */
int extract_sgx_quote(void *cert_ptr, sgx_quote_buffer_t *quote_buffer);

/* Compute a hash of the SGX quote body for verification */
int compute_quote_hash(const sgx_quote_t *quote, unsigned char *hash, unsigned int *hash_len);

/* Parse PEM certificate from quote signature data */
X509 *parse_quote_cert(const uint8_t *cert_data, size_t cert_data_size);

/* Display quote information */
void display_quote_info(const sgx_quote_t *quote);

#endif /* SGX_QUOTE_PARSER_H */