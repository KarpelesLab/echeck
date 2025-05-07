#include "echeck.h"
#include "echeck_internal.h"
#include "echeck_quote.h"
#include <stdlib.h>
#include <string.h>

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

ECHECK_API echeck_quote_t* extract_quote(void *cert) {
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

ECHECK_API void free_quote(echeck_quote_t *quote) {
    echeck_quote_free(quote);
}

ECHECK_API int get_quote_info(echeck_quote_t *quote, echeck_quote_info_t *info) {
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

ECHECK_API int verify_quote_measurements(echeck_quote_t *quote, 
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

ECHECK_API void free_certificate(void *cert) {
    if (cert) {
        X509_free((X509*)cert);
    }
}

ECHECK_API int verify_quote(void *cert, echeck_quote_t *quote, echeck_verification_result_t *result) {
    /* This is a placeholder function - we'll need to implement the full verification logic later */
    if (!cert || !quote || !result) {
        return 0;
    }

    /* Initialize the result structure */
    memset(result, 0, sizeof(echeck_verification_result_t));

    /* For now, just validate that the quote data exists */
    result->valid = 1;
    result->quote_valid = 1;
    result->checks_performed = 1;
    result->checks_passed = 1;

    return 1;
}