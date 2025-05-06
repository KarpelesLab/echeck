#ifndef SGX_QUOTE_VERIFY_H
#define SGX_QUOTE_VERIFY_H

#include "sgx_types.h"
#include "sgx_cert_verify.h"
#include <openssl/evp.h>
#include <openssl/x509.h>

/* Result structure for verification checks */
typedef struct {
    int mr_enclave_valid;
    int mr_signer_valid;
    int signature_valid;
    int version_valid;
    int report_data_matches_cert;
    int cert_chain_valid;        /* Flag indicating if the certificate chain is valid */
    int attestation_key_valid;   /* Flag indicating if the attestation key is certified */
    int total_checks;
    int checks_passed;
    sgx_cert_verification_result_t cert_result; /* Certificate verification details */
} sgx_verification_result_t;

/* Verify SGX quote using built-in CA certificates */
int verify_sgx_quote(const unsigned char *quote_data, int quote_len,
                     sgx_verification_result_t *result);

/* Verify quote signature using public key from certificate */
int verify_quote_signature(const sgx_quote_t *quote, const unsigned char *quote_hash, 
                          unsigned int quote_hash_len, EVP_PKEY *pubkey);
                          
/* Verify report data matches certificate */
int verify_report_data(const sgx_quote_t *quote, const unsigned char *pubkey_hash, 
                      unsigned int pubkey_hash_len);

/* Parse and analyze ECDSA signature data from quote */
int analyze_quote_signature(const sgx_quote_t *quote, int signature_len);

#endif /* SGX_QUOTE_VERIFY_H */