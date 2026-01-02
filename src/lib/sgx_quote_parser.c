#include "echeck.h"
#include "echeck_internal.h"
#include "sgx_quote_parser.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* All OpenSSL functions are accessed through openssl_runtime.h now */

/* Extract SGX quote extension from a certificate */
int extract_sgx_quote(void *cert_ptr, sgx_quote_buffer_t *quote_buffer) {
    X509 *cert = (X509 *)cert_ptr;
    int i, nid, ext_count;
    X509_EXTENSION *ext = NULL;
    ASN1_OCTET_STRING *ext_data = NULL;


    /* Initialize output */
    quote_buffer->data = NULL;
    quote_buffer->length = 0;

    /* Register the SGX OID (returns existing NID if already registered) */
    nid = OBJ_create(SGX_QUOTE_OID, "SGXQuote", "Intel SGX Quote Extension");
    if (nid == NID_undef) {
        /* NID_undef only returned on actual errors, not for already-registered OIDs */
        print_openssl_error("Failed to register SGX Quote OID");
        return 0;
    }


    /* Get the number of extensions */
    ext_count = X509_get_ext_count(cert);

    if (ext_count <= 0) {
        fprintf(stderr, "No extensions found in certificate\n");
        return 0;
    }

    /* Look for the SGX quote extension */
    for (i = 0; i < ext_count; i++) {
        ext = X509_get_ext(cert, i);
        if (!ext) {
            continue;
        }


        /* Check if this is the SGX quote extension */
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
        int ext_nid = OBJ_obj2nid(obj);

        if (ext_nid == nid) {
            /* Get the extension data */
            ext_data = X509_EXTENSION_get_data(ext);
            if (!ext_data) {
                fprintf(stderr, "SGX quote extension found but data is empty\n");
                return 0;
            }


            /* Get the raw data from the extension */
            
            const unsigned char *raw_data = ASN1_STRING_get0_data(ext_data);
            int raw_len = ASN1_STRING_length(ext_data);

            /* Check if we have at least enough data for the header */
            if (raw_len < sizeof(sgx_quote_header_t)) {
                fprintf(stderr, "SGX quote data too short for header: %d bytes\n", raw_len);
                return 0;
            }

            /* Parse the header */
            sgx_quote_header_t *header = (sgx_quote_header_t *)raw_data;
            uint32_t header_version = extract_uint32((uint8_t*)&header->version);
            uint32_t header_type = extract_uint32((uint8_t*)&header->type);
            uint32_t quote_size = extract_uint32((uint8_t*)&header->size);
            uint32_t reserved = extract_uint32((uint8_t*)&header->reserved);

            /* Process header information */

            /* Header information parsed (not printed in the updated Unix-like version) */

            /* Verify the size makes sense - reject if header claims more data than available */
            if (quote_size > raw_len - sizeof(sgx_quote_header_t)) {
                fprintf(stderr, "Error: SGX quote size in header (%u) exceeds available data (%zu)\n",
                        quote_size, raw_len - sizeof(sgx_quote_header_t));
                return 0;
            }

            /* Allocate memory for the quote data (excluding the header) */
            quote_buffer->length = quote_size;
            if (quote_size > 0) {
                quote_buffer->data = (unsigned char *)malloc(quote_buffer->length);
                if (!quote_buffer->data) {
                    fprintf(stderr, "Memory allocation failed\n");
                    return 0;
                }

                /* Copy just the quote data (after the header) */
                memcpy(quote_buffer->data, raw_data + sizeof(sgx_quote_header_t), quote_buffer->length);
            } else {
                fprintf(stderr, "ERROR: Zero or negative quote size: %u\n", quote_size);
                quote_buffer->data = NULL;
                return 0;
            }
            
            return 1;
        }
    }
    
    /* SGX quote extension not found */
    return 0;
}

/* Compute a hash of the SGX quote body for verification */
int compute_quote_hash(const sgx_quote_t *quote, unsigned char *hash, unsigned int *hash_len) {
    /* Create an EVP message digest context for SHA256 */
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        print_openssl_error("Error creating message digest context");
        return 0;
    }
    
    /* Initialize the digest context for SHA256 */
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        print_openssl_error("Error initializing message digest");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    
    /* For version 3 ECDSA quotes, we hash everything up to but not including the signature_len field */
    const size_t hash_size = offsetof(sgx_quote_t, signature_len);
    
    /* Add the quote data to the digest */
    if (EVP_DigestUpdate(mdctx, quote, hash_size) != 1) {
        print_openssl_error("Error updating message digest");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    
    /* Finalize and get the digest value */
    if (EVP_DigestFinal_ex(mdctx, hash, hash_len) != 1) {
        print_openssl_error("Error finalizing message digest");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    
    /* Free the message digest context */
    EVP_MD_CTX_free(mdctx);
    
    return 1;
}

/* Parse PEM certificate from quote signature data */
X509 *parse_quote_cert(const uint8_t *cert_data, size_t cert_data_size) {
    BIO *cert_bio;
    X509 *cert = NULL;

    /* Validate size before casting to int (BIO_new_mem_buf takes int) */
    if (cert_data_size == 0 || cert_data_size > INT_MAX) {
        fprintf(stderr, "Error: Invalid certificate data size: %zu\n", cert_data_size);
        return NULL;
    }

    /* Create a BIO for the certificate data using explicit size */
    cert_bio = BIO_new_mem_buf(cert_data, (int)cert_data_size);
    if (!cert_bio) {
        print_openssl_error("Error creating BIO for certificate data");
        return NULL;
    }
    
    /* Try to read the certificate */
    cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    if (!cert) {
        print_openssl_error("Error reading certificate from data");
    }
    
    BIO_free(cert_bio);
    return cert;
}