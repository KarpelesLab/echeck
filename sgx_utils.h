#ifndef SGX_UTILS_H
#define SGX_UTILS_H

#include "sgx_types.h"
#include <openssl/evp.h>

/* Debug utility to dump a buffer with a name */
void dump_buffer(const char *name, const unsigned char *data, size_t len);

/* Extract the attestation key from the quote signature data */
EVP_PKEY *extract_attestation_key(const sgx_quote_t *quote);

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