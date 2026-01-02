#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "echeck.h"
#include "echeck_internal.h"
#include "sgx_cert_verify.h"
/* OpenSSL headers are accessed through openssl_runtime.h included in common.h */

/* Initialize the certificate verification result structure */
void init_cert_verification_result(sgx_cert_verification_result_t *result) {
    result->chain_verified = 0;
    result->cert_count = 0;
    result->pck_cert = NULL;
    result->intermediate_cert = NULL;
    result->attestation_key_verified = 0;
}

/* Extract the PCK certificate chain from the quote */
int extract_pck_cert_chain(const sgx_quote_t *quote, sgx_cert_verification_result_t *result) {
    /* First, ensure this is a v3 ECDSA quote */
    if (quote->version != 3) {
        fprintf(stderr, "Error: PCK certificate chain extraction only supported for ECDSA Quote v3\n");
        return 0;
    }

    /* Get signature length and validate it's reasonable */
    uint32_t signature_len = quote->signature_len;

    /* Navigate to the authentication data section */
    /* 64 bytes sig + 64 bytes attest_pub_key + sizeof(sgx_report_body_t) + 64 bytes qe_report_sig */
    uint32_t auth_data_offset = 64 + 64 + sizeof(sgx_report_body_t) + 64;

    /* Bounds check: ensure signature_len is large enough to contain auth_data header */
    /* Auth data header: auth_data_size(2) + auth_data(32) + cert_type(2) + cert_data_size(4) = 40 bytes */
    uint32_t min_sig_len = auth_data_offset + 40;
    if (signature_len < min_sig_len) {
        fprintf(stderr, "Error: Signature data too short for auth data header: %u < %u\n",
                signature_len, min_sig_len);
        return 0;
    }

    /* Get the signature data (located after the quote body) */
    uint32_t sig_data_offset = offsetof(sgx_quote_t, signature_len) + sizeof(uint32_t);
    const sgx_ql_ecdsa_sig_data_t *sig_data = (const sgx_ql_ecdsa_sig_data_t *)(((const uint8_t *)quote) + sig_data_offset);

    /* Get the auth data structure */
    const sgx_ql_auth_data_t *auth_data = (const sgx_ql_auth_data_t *)(((const uint8_t *)sig_data) + auth_data_offset);

    /* Verify we have valid auth data */
    if (auth_data->auth_data_size != 0x20) {
        fprintf(stderr, "Error: Unexpected auth data size: 0x%04x (expected 0x0020)\n", auth_data->auth_data_size);
        return 0;
    }

    /* Check cert type */
    if (auth_data->cert_type != 0x0005) {
        fprintf(stderr, "Error: Unexpected certificate type: 0x%04x (expected 0x0005)\n", auth_data->cert_type);
        return 0;
    }

    /* Get the PCK certificate data size and validate bounds */
    uint32_t cert_data_size = auth_data->cert_data_size;

    /* Bounds check: ensure signature_len contains the full certificate data */
    uint32_t cert_data_end = auth_data_offset + 40 + cert_data_size;
    if (signature_len < cert_data_end) {
        fprintf(stderr, "Error: Signature data too short for certificate data: %u < %u\n",
                signature_len, cert_data_end);
        return 0;
    }

    const uint8_t *cert_data = auth_data->cert_data;
    
    if (is_verbose_mode()) {
        fprintf(stderr, "Found PCK certificate chain (%u bytes)\n", cert_data_size);
    }
    
    /* Create a BIO for reading the certificate data */
    BIO *bio = BIO_new_mem_buf(cert_data, cert_data_size);
    if (!bio) {
        print_openssl_error("Failed to create BIO for certificate data");
        return 0;
    }
    
    /* The certificate data contains a chain of PEM certificates */
    /* Read each certificate from the chain */
    X509 *cert = NULL;
    int cert_count = 0;
    
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        cert_count++;
        
        /* Get certificate subject name */
        char subject[256];
        X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
        if (is_verbose_mode()) {
            fprintf(stderr, "Certificate %d: %s\n", cert_count, subject);
        }
        
        /* Store the certificates based on their position in the chain */
        if (cert_count == 1) {
            /* First certificate is the leaf (PCK) certificate */
            result->pck_cert = cert;
        } else if (cert_count == 2) {
            /* Second certificate is the intermediate certificate */
            result->intermediate_cert = cert;
        } else {
            /* We don't need more than the leaf and intermediate certs */
            X509_free(cert);
        }
    }
    
    /* Check for errors */
    unsigned long err = ERR_peek_last_error();

    /* Don't print the error code at standard verbosity level */
    /* We don't need to print the error code */

    /* Extract library and reason using the proper OpenSSL macros */
    if (err == 0) {
        /* No error */
    } else if (ERR_GET_LIB(err) == ERR_LIB_PEM &&
               ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
        /* This is expected when we reach the end of the data */
        ERR_clear_error();
    } else {
        /* Some other error occurred */
        print_openssl_error("Error reading certificates");
        BIO_free(bio);
        return 0;
    }
    
    /* Clean up */
    BIO_free(bio);
    
    /* Update the result */
    result->cert_count = cert_count;
    
    if (is_verbose_mode()) {
        fprintf(stderr, "Successfully extracted %d certificates from the quote\n", cert_count);
    }
    return 1;
}

/* Verify the PCK certificate chain against a trusted CA */
int verify_pck_cert_chain_internal(sgx_cert_verification_result_t *result, STACK_OF(X509) *trusted_ca) {
    if (!result->pck_cert) {
        fprintf(stderr, "No PCK certificate to verify\n");
        return 0;
    }
    
    if (!trusted_ca) {
        fprintf(stderr, "No trusted CA certificates provided\n");
        return 0;
    }
    
    if (sk_X509_num(trusted_ca) == 0) {
        fprintf(stderr, "Trusted CA certificate stack is empty\n");
        return 0;
    }

    /* Create a verification context */
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) {
        print_openssl_error("Failed to create X509_STORE_CTX");
        return 0;
    }

    /* Create a certificate store */
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        print_openssl_error("Failed to create X509_STORE");
        X509_STORE_CTX_free(ctx);
        return 0;
    }

    /* Add the trusted CA certificates to the store */
    
    for (int i = 0; i < sk_X509_num(trusted_ca); i++) {
        X509 *ca_cert = sk_X509_value(trusted_ca, i);
        if (!ca_cert) {
            fprintf(stderr, "ERROR: Failed to get certificate at index %d\n", i);
            continue;
        }
        
        if (X509_STORE_add_cert(store, ca_cert) != 1) {
            /* Check if the error is just that the certificate already exists */
            unsigned long err = ERR_peek_last_error();

            /* We don't need to print the error code */

            /* Use the standard OpenSSL macros to get the library and reason codes */
            if (ERR_GET_LIB(err) == ERR_LIB_X509 &&
                ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                /* This is fine, just clear the error */
                ERR_clear_error();
            } else {
                print_openssl_error("Failed to add CA certificate to store");
                X509_STORE_free(store);
                X509_STORE_CTX_free(ctx);
                return 0;
            }
        }
    }
    
    /* Create a STACK for the untrusted certificates (those extracted from the quote) */
    STACK_OF(X509) *untrusted = sk_X509_new_null();
    if (!untrusted) {
        print_openssl_error("Failed to create certificate stack");
        X509_STORE_free(store);
        X509_STORE_CTX_free(ctx);
        return 0;
    }

    /* Add the intermediate certificate (if available) to the untrusted stack */
    if (result->intermediate_cert) {
        if (sk_X509_push(untrusted, result->intermediate_cert) != 1) {
            print_openssl_error("Failed to add intermediate certificate to stack");
            sk_X509_free(untrusted);
            X509_STORE_free(store);
            X509_STORE_CTX_free(ctx);
            return 0;
        }
    }

    /* Initialize the verification context */
    
    int init_result = X509_STORE_CTX_init(ctx, store, result->pck_cert, untrusted);

    if (init_result != 1) {
        print_openssl_error("Failed to initialize X509_STORE_CTX");
        sk_X509_free(untrusted);
        X509_STORE_free(store);
        X509_STORE_CTX_free(ctx);
        return 0;
    }

    /* Perform the verification */
    int verify_result = X509_verify_cert(ctx);

    if (verify_result == 1) {
        result->chain_verified = 1;
    } else {
        int error = X509_STORE_CTX_get_error(ctx);
        fprintf(stderr, "Error: PCK certificate chain verification failed: %s\n",
                X509_verify_cert_error_string(error));
    }

    /* Clean up */
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(untrusted);
    
    return result->chain_verified;
}

/* Verify that the attestation key is certified by the PCK certificate.
 *
 * This performs the critical cryptographic verification that links the attestation key
 * (which signs the quote) to Intel's chain of trust. The verification consists of:
 *
 * 1. QE Report Signature Verification:
 *    - The QE Report is signed by the PCK certificate's private key
 *    - This proves the QE Report was generated by genuine Intel SGX hardware
 *
 * 2. Attestation Key Binding Verification:
 *    - The QE Report's report_data contains SHA256(attestation_key || auth_data)
 *    - This proves the attestation key is bound to the certified QE Report
 *
 * Without these verifications, an attacker could substitute their own attestation key
 * and generate fake quotes that would appear valid.
 */
int verify_attestation_key_internal(const sgx_quote_t *quote, sgx_cert_verification_result_t *result) {
    if (!result->pck_cert) {
        fprintf(stderr, "Error: No PCK certificate to verify against\n");
        return 0;
    }

    if (quote->version != 3) {
        fprintf(stderr, "Error: Attestation key certification verification only supported for ECDSA Quote v3\n");
        return 0;
    }

    /* Get the public key from the PCK certificate */
    EVP_PKEY *pck_pubkey = X509_get_pubkey(result->pck_cert);
    if (!pck_pubkey) {
        print_openssl_error("Failed to get public key from PCK certificate");
        return 0;
    }

    /* Verify that the PCK key is an EC key (P-256) */
    if (EVP_PKEY_get_base_id(pck_pubkey) != EVP_PKEY_EC) {
        fprintf(stderr, "Error: PCK certificate public key is not an EC key\n");
        EVP_PKEY_free(pck_pubkey);
        return 0;
    }

    if (is_verbose_mode()) {
        fprintf(stderr, "\n[Attestation Key Certification Verification]\n");
    }

    /* Step 1: Verify the QE Report signature using the PCK certificate's public key
     * This proves the QE Report was generated by Intel SGX hardware certified by Intel */
    if (!verify_qe_report_signature(quote, pck_pubkey)) {
        fprintf(stderr, "Error: QE Report signature verification failed - "
                        "attestation key is NOT certified by Intel\n");
        EVP_PKEY_free(pck_pubkey);
        return 0;
    }

    /* Step 2: Verify that the attestation key is bound to the QE Report
     * This proves the attestation key hash is in the QE Report's report_data */
    if (!verify_qe_report_data(quote)) {
        fprintf(stderr, "Error: Attestation key binding verification failed - "
                        "attestation key is NOT bound to the certified QE Report\n");
        EVP_PKEY_free(pck_pubkey);
        return 0;
    }

    /* Both verifications passed - the attestation key is properly certified */
    result->attestation_key_verified = 1;

    if (is_verbose_mode()) {
        fprintf(stderr, "Attestation key certification: VERIFIED\n");
        fprintf(stderr, "  - QE Report signature verified using PCK certificate\n");
        fprintf(stderr, "  - Attestation key properly bound to QE Report\n");
    }

    EVP_PKEY_free(pck_pubkey);
    return 1;
}

/* Free resources in the certificate verification result */
void free_cert_verification_result(sgx_cert_verification_result_t *result) {
    if (result->pck_cert) {
        X509_free(result->pck_cert);
        result->pck_cert = NULL;
    }
    
    if (result->intermediate_cert) {
        X509_free(result->intermediate_cert);
        result->intermediate_cert = NULL;
    }
    
    result->chain_verified = 0;
    result->cert_count = 0;
    result->attestation_key_verified = 0;
}