#include "echeck.h"
#include "echeck_internal.h"
#include "echeck_quote.h"
#include "sgx_quote_parser.h"
#include "sgx_quote_verify.h"
#include "sgx_cert_verify.h"
#include "ca.h"  /* For get_trusted_ca_stack() */
#include <stdlib.h>
#include <string.h>
/* Don't include direct OpenSSL headers when we have runtime loading */

/**
 * Create a new quote structure from raw data
 */
echeck_quote_t* echeck_quote_create(unsigned char *data, size_t size) {
    if (!data || size < sizeof(sgx_quote_t)) {
        return NULL;
    }

    echeck_quote_t *quote = (echeck_quote_t*)malloc(sizeof(echeck_quote_t));
    if (!quote) {
        return NULL;
    }

    /* Allocate memory for the data and copy it */
    quote->data = (unsigned char*)malloc(size);
    if (!quote->data) {
        free(quote);
        return NULL;
    }

    memcpy(quote->data, data, size);
    quote->data_size = size;
    
    /* Set the quote pointer to point to our data */
    quote->quote = (sgx_quote_t*)quote->data;

    return quote;
}

/**
 * Free a quote structure
 */
void echeck_quote_free(echeck_quote_t *quote) {
    if (quote) {
        if (quote->data) {
            free(quote->data);
        }
        free(quote);
    }
}

/**
 * Public API implementation
 */

ECHECK_API echeck_quote_t* echeck_extract_quote(void *cert) {
    if (!cert) {
        return NULL;
    }

    /* Old implementation used sgx_quote_buffer_t structure */
    unsigned char *data = NULL;
    int data_size = 0;

    /* Temporary solution: reuse existing extract_sgx_quote function */
    /* When we fully implement the API, this will be rewritten properly */
    sgx_quote_buffer_t buffer = {NULL, 0};
    if (!extract_sgx_quote(cert, &buffer)) {
        return NULL;
    }

    /* Create a new quote structure */
    echeck_quote_t *quote = echeck_quote_create(buffer.data, buffer.length);

    /* Free the temporary buffer */
    free(buffer.data);

    return quote;
}

ECHECK_API void echeck_free_quote(echeck_quote_t *quote) {
    echeck_quote_free(quote);
}

ECHECK_API int echeck_get_quote_info(echeck_quote_t *quote, echeck_quote_info_t *info) {
    if (!quote || !info) {
        return 0;
    }

    /* Copy the quote information */
    memcpy(info->mr_enclave, quote->quote->report_body.mr_enclave, 32);
    memcpy(info->mr_signer, quote->quote->report_body.mr_signer, 32);
    info->isv_prod_id = quote->quote->report_body.isv_prod_id;
    info->isv_svn = quote->quote->report_body.isv_svn;

    return 1;
}

ECHECK_API int echeck_verify_quote_measurements(echeck_quote_t *quote,
                                        const uint8_t *expected_mrenclave,
                                        const uint8_t *expected_mrsigner) {
    if (!quote || (!expected_mrenclave && !expected_mrsigner)) {
        return 0;
    }

    /* Check MRENCLAVE if provided */
    if (expected_mrenclave) {
        if (memcmp(quote->quote->report_body.mr_enclave, expected_mrenclave, 32) != 0) {
            return 0;
        }
    }

    /* Check MRSIGNER if provided */
    if (expected_mrsigner) {
        if (memcmp(quote->quote->report_body.mr_signer, expected_mrsigner, 32) != 0) {
            return 0;
        }
    }

    return 1;
}

ECHECK_API void echeck_free_certificate(void *cert) {
    if (cert) {
        X509_free((X509*)cert);
    }
}

ECHECK_API int echeck_verify_quote(void *cert_ptr, echeck_quote_t *quote, echeck_verification_result_t *result) {
    if (!cert_ptr || !quote || !result) {
        return 0;
    }

    /* Cast cert to proper type */
    X509 *cert = (X509 *)cert_ptr;

    /* Initialize the result structure */
    memset(result, 0, sizeof(echeck_verification_result_t));

    /* First, compute the public key hash to verify the report data */
    unsigned char pubkey_hash[SHA256_DIGEST_LENGTH];
    unsigned int pubkey_hash_len = 0;

    /* We'll need to implement a compute_pubkey_hash wrapper that takes void* */
    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    if (!pubkey) {
        result->error_message = "Failed to get public key from certificate";
        return 0;
    }

    /* Compute hash of the public key */
    unsigned char *pubkey_data = NULL;
    int pubkey_len = i2d_PUBKEY(pubkey, &pubkey_data);

    if (pubkey_len <= 0 || !pubkey_data) {
        EVP_PKEY_free(pubkey);
        result->error_message = "Failed to serialize public key";
        return 0;
    }

    /* Hash the public key */
    if (!SHA256(pubkey_data, pubkey_len, pubkey_hash)) {
        OPENSSL_free(pubkey_data);
        EVP_PKEY_free(pubkey);
        result->error_message = "Failed to hash public key";
        return 0;
    }

    pubkey_hash_len = SHA256_DIGEST_LENGTH;
    OPENSSL_free(pubkey_data);
    EVP_PKEY_free(pubkey);

    /* Verify that the report data matches the certificate's public key hash */
    result->report_data_matches_cert = verify_report_data(quote->quote, pubkey_hash, pubkey_hash_len);

    if (is_verbose_mode()) {
        fprintf(stderr, "Report data match result: %d\n", result->report_data_matches_cert);
    }

    /* Continue verification even if report data doesn't match - this allows clients to see
     * the complete verification result set in raw mode */

    /* Verify the quote itself using the underlying verification function */
    int verify_result = verify_sgx_quote(quote->data, quote->data_size, result);

    if (is_verbose_mode()) {
        fprintf(stderr, "Report data match status: %d\n", result->report_data_matches_cert);
    }

    /* Now perform certificate chain verification - very important for security! */
    if (verify_result) {
        /* Get trusted CA certificates */
        STACK_OF(X509) *ca_stack = get_trusted_ca_stack();
        if (!ca_stack) {
            result->error_message = "Failed to load trusted CA certificates";
            result->valid = 0;
            return 0;
        }

        /* Initialize certificate verification result structure */
        sgx_cert_verification_result_t cert_result = {0};
        int cert_chain_valid = 0;
        int attest_key_valid = 0;

        /* Extract PCK certificate chain from the quote */
        if (extract_pck_cert_chain(quote->quote, &cert_result)) {
            /* Verify the certificate chain against trusted CAs */
            if (verify_pck_cert_chain_internal(&cert_result, ca_stack)) {
                cert_chain_valid = 1;
                result->cert_chain_valid = 1;

                /* Also verify the attestation key */
                if (verify_attestation_key_internal(quote->quote, &cert_result)) {
                    attest_key_valid = 1;
                }
            } else {
                result->error_message = "Certificate chain verification failed";
            }

            /* Free certificate verification resources */
            free_cert_verification_result(&cert_result);
        } else {
            result->error_message = "Failed to extract PCK certificate chain";
        }

        /* Free CA stack */
        sk_X509_pop_free(ca_stack, X509_free);

        /* Final validation - all components must be valid */
        result->valid = verify_result && cert_chain_valid && attest_key_valid && result->report_data_matches_cert;

        if (is_verbose_mode()) {
            fprintf(stderr, "Final validation components:\n");
            fprintf(stderr, "  - Quote verification: %d\n", verify_result);
            fprintf(stderr, "  - Certificate chain valid: %d\n", cert_chain_valid);
            fprintf(stderr, "  - Attestation key valid: %d\n", attest_key_valid);
            fprintf(stderr, "  - Report data matches cert: %d\n", result->report_data_matches_cert);
            fprintf(stderr, "  - Final valid result: %d\n", result->valid);
        }

        /* Set appropriate error message based on what failed */
        if (!attest_key_valid) {
            result->error_message = "Attestation key verification failed";
        } else if (!result->report_data_matches_cert) {
            result->error_message = "Report data does not match certificate public key hash";
        }
    } else {
        result->valid = 0;
    }

    return result->valid;
}