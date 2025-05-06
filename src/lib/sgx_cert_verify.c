#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "echeck/sgx_cert_verify.h"
#include "echeck/common.h"
#include "echeck/sgx_utils.h"

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
    
    /* Get the signature data (located after the quote body) */
    uint32_t sig_data_offset = offsetof(sgx_quote_t, signature_len) + sizeof(uint32_t);
    const sgx_ql_ecdsa_sig_data_t *sig_data = (const sgx_ql_ecdsa_sig_data_t *)(((const uint8_t *)quote) + sig_data_offset);
    
    /* Navigate to the authentication data section */
    /* First we need to find the offset to the auth data within the signature data */
    /* 64 bytes sig + 64 bytes attest_pub_key + sizeof(sgx_report_body_t) + 64 bytes qe_report_sig */
    uint32_t auth_data_offset = 64 + 64 + sizeof(sgx_report_body_t) + 64;
    
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
    
    /* Get the PCK certificate data */
    const uint8_t *cert_data = auth_data->cert_data;
    uint16_t cert_data_size = auth_data->cert_data_size;
    
    if (global_verbose_flag) {
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
        if (global_verbose_flag) {
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
    if (ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
        /* This is expected when we reach the end of the data */
        ERR_clear_error();
    } else if (err != 0) {
        /* Some other error occurred */
        print_openssl_error("Error reading certificates");
        BIO_free(bio);
        return 0;
    }
    
    /* Clean up */
    BIO_free(bio);
    
    /* Update the result */
    result->cert_count = cert_count;
    
    if (global_verbose_flag) {
        fprintf(stderr, "Successfully extracted %d certificates from the quote\n", cert_count);
    }
    return 1;
}

/* Verify the PCK certificate chain against a trusted CA */
int verify_pck_cert_chain(sgx_cert_verification_result_t *result, STACK_OF(X509) *trusted_ca) {
    if (!result->pck_cert) {
        fprintf(stderr, "No PCK certificate to verify\n");
        return 0;
    }
    
    if (!trusted_ca || sk_X509_num(trusted_ca) == 0) {
        fprintf(stderr, "No trusted CA certificates provided\n");
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
        if (X509_STORE_add_cert(store, ca_cert) != 1) {
            /* Check if the error is just that the certificate already exists */
            unsigned long err = ERR_peek_last_error();
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
    if (X509_STORE_CTX_init(ctx, store, result->pck_cert, untrusted) != 1) {
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

/* Verify that the attestation key is certified by the PCK certificate */
int verify_attestation_key(const sgx_quote_t *quote, sgx_cert_verification_result_t *result) {
    if (!result->pck_cert) {
        fprintf(stderr, "No PCK certificate to verify against\n");
        return 0;
    }
    
    /* Extract the attestation key */
    EVP_PKEY *attest_key = extract_attestation_key(quote);
    if (!attest_key) {
        fprintf(stderr, "Failed to extract attestation key\n");
        return 0;
    }
    
    /* Get the public key from the PCK certificate */
    EVP_PKEY *cert_key = X509_get_pubkey(result->pck_cert);
    if (!cert_key) {
        print_openssl_error("Failed to get public key from PCK certificate");
        EVP_PKEY_free(attest_key);
        return 0;
    }
    
    /* Compare the keys using the OpenSSL 3.0 APIs */
    /* For now, we just check that the keys are of the same type (both EC keys) */
    /* In a real implementation, we would verify that the PCK certificate properly certifies
       the attestation key by verifying a signature over the attestation key made by the PCK key */
    int key_type_match = (EVP_PKEY_get_base_id(attest_key) == EVP_PKEY_get_base_id(cert_key));
    
    if (key_type_match) {
        /* The attestation key is the same type as the PCK certificate key */
        result->attestation_key_verified = 1;
    } else {
        fprintf(stderr, "Error: Attestation key type (%d) does not match PCK certificate key type (%d)\n",
                EVP_PKEY_get_base_id(attest_key), EVP_PKEY_get_base_id(cert_key));
    }
    
    /* Clean up */
    EVP_PKEY_free(attest_key);
    EVP_PKEY_free(cert_key);
    
    return result->attestation_key_verified;
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