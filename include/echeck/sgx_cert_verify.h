#ifndef SGX_CERT_VERIFY_H
#define SGX_CERT_VERIFY_H

#include "sgx_types.h"
#include "echeck/openssl_runtime.h"

/* Certificate verification result structure */
typedef struct {
    int chain_verified;       /* Flag indicating if the certificate chain verification passed */
    int cert_count;           /* Number of certificates in the chain */
    X509 *pck_cert;           /* PCK certificate (leaf certificate) */
    X509 *intermediate_cert;  /* Intermediate CA certificate */
    int attestation_key_verified; /* Flag indicating if the attestation key was verified */
} sgx_cert_verification_result_t;

/* Initialize the certificate verification result structure */
void init_cert_verification_result(sgx_cert_verification_result_t *result);

/* Extract the PCK certificate chain from the quote */
int extract_pck_cert_chain(const sgx_quote_t *quote, sgx_cert_verification_result_t *result);

/* Verify the PCK certificate chain against a trusted CA */
int verify_pck_cert_chain(sgx_cert_verification_result_t *result, STACK_OF(X509) *trusted_ca);

/* Verify that the attestation key is certified by the PCK certificate */
int verify_attestation_key(const sgx_quote_t *quote, sgx_cert_verification_result_t *result);

/* Free resources in the certificate verification result */
void free_cert_verification_result(sgx_cert_verification_result_t *result);

#endif /* SGX_CERT_VERIFY_H */