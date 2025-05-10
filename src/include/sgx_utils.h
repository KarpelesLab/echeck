#ifndef SGX_UTILS_H
#define SGX_UTILS_H

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

/* Debug utility to dump a buffer with a name */
void dump_buffer(const char *name, const unsigned char *data, size_t len);

/* Extract the attestation key from the quote signature data */
int extract_attestation_key(const sgx_quote_t *quote, EVP_PKEY **out_key);

/* Extract and parse ECDSA signature from quote */
int extract_ecdsa_signature(const sgx_quote_t *quote, 
                          unsigned char **sig_r, unsigned int *sig_r_len,
                          unsigned char **sig_s, unsigned int *sig_s_len);

/* Function to compute the hash of the quote for signature verification */
int compute_quote_hash_for_sig(const sgx_quote_t *quote, unsigned char *hash, unsigned int *hash_len);

/* Verify ECDSA signature with extracted key and quote hash */
int verify_quote_signature_raw(const unsigned char *quote_hash, unsigned int quote_hash_len,
                             const unsigned char *sig_r, unsigned int sig_r_len,
                             const unsigned char *sig_s, unsigned int sig_s_len,
                             EVP_PKEY *pubkey);

#endif /* SGX_UTILS_H */