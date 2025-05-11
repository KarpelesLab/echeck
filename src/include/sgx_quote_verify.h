#ifndef SGX_QUOTE_VERIFY_H
#define SGX_QUOTE_VERIFY_H

/* SGX types included via echeck.h */

/* Include centralized OpenSSL header */
#include "echeck_openssl.h"
/* sgx_cert_verify.h declarations included via echeck_internal.h */

/* Using echeck_verification_result_t from public API */
typedef echeck_verification_result_t sgx_verification_result_t;

/* Verify SGX quote using built-in CA certificates */
int verify_sgx_quote(const unsigned char *quote_data, int quote_len,
                     echeck_verification_result_t *result);

/* Verify quote signature using public key from certificate */
int verify_quote_signature(const sgx_quote_t *quote, const unsigned char *quote_hash, 
                          unsigned int quote_hash_len, EVP_PKEY *pubkey);
                          
/* Verify report data matches certificate */
int verify_report_data(const sgx_quote_t *quote, const unsigned char *pubkey_hash, 
                      unsigned int pubkey_hash_len);

/* Parse and analyze ECDSA signature data from quote */
int analyze_quote_signature(const sgx_quote_t *quote, int signature_len);

#endif /* SGX_QUOTE_VERIFY_H */