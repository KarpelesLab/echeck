#include "sgx_quote_parser.h"
#include "common.h"
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>  /* For PEM_read_bio_X509 */

/* Extract SGX quote extension from a certificate */
int extract_sgx_quote(X509 *cert, sgx_quote_buffer_t *quote_buffer) {
    int i, nid, ext_count;
    X509_EXTENSION *ext = NULL;
    ASN1_OCTET_STRING *ext_data = NULL;
    
    /* Initialize output */
    quote_buffer->data = NULL;
    quote_buffer->length = 0;
    
    /* Register the SGX OID if it's not already known */
    nid = OBJ_create(SGX_QUOTE_OID, "SGXQuote", "Intel SGX Quote Extension");
    if (nid == NID_undef) {
        print_openssl_error("Error creating SGX Quote OID");
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
        if (!ext) continue;
        
        /* Check if this is the SGX quote extension */
        if (OBJ_obj2nid(X509_EXTENSION_get_object(ext)) == nid) {
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
            
            /* Print header information */
            printf("Quote Header: Version=%u, Type=%u, Size=%u, Reserved=%u\n", 
                   header_version, header_type, quote_size, reserved);
            
            /* Verify the size makes sense */
            if (quote_size > raw_len - sizeof(sgx_quote_header_t)) {
                fprintf(stderr, "SGX quote size in header (%u) exceeds available data (%d)\n", 
                        quote_size, raw_len - (int)sizeof(sgx_quote_header_t));
                quote_size = raw_len - sizeof(sgx_quote_header_t);
                printf("Adjusted quote size to %u bytes\n", quote_size);
            }
            
            /* Allocate memory for the quote data (excluding the header) */
            quote_buffer->length = quote_size;
            quote_buffer->data = (unsigned char *)malloc(quote_buffer->length);
            if (!quote_buffer->data) {
                fprintf(stderr, "Memory allocation failed\n");
                return 0;
            }
            
            /* Copy just the quote data (after the header) */
            memcpy(quote_buffer->data, raw_data + sizeof(sgx_quote_header_t), quote_buffer->length);
            
            /* For debugging, also save the raw data with header */
            FILE *fp_raw = fopen("quote_with_header.bin", "wb");
            if (fp_raw) {
                fwrite(raw_data, 1, raw_len, fp_raw);
                fclose(fp_raw);
                printf("Full quote with header dumped to quote_with_header.bin (%d bytes)\n", raw_len);
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
    
    /* Create a BIO for the certificate data */
    cert_bio = BIO_new_mem_buf(cert_data, -1); /* -1 tells BIO to use strlen() for null-terminated data */
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

/* Display quote information */
void display_quote_info(const sgx_quote_t *quote) {
    printf("\n=====================================================\n");
    printf("                  SGX Quote Analysis                 \n");
    printf("=====================================================\n");
    
    printf("\n[Quote Header]\n");
    printf("Version:          %u\n", quote->version);
    printf("Sign Type:        %u\n", quote->sign_type);
    
    char epid_group_id_str[9] = {0}; /* 4 bytes to 8 hex chars + null */
    sprintf(epid_group_id_str, "%02x%02x%02x%02x", 
            quote->epid_group_id[0], quote->epid_group_id[1], 
            quote->epid_group_id[2], quote->epid_group_id[3]);
    printf("EPID Group ID:    0x%s\n", epid_group_id_str);
    
    printf("QE SVN:           %u\n", quote->qe_svn);
    printf("PCE SVN:          %u\n", quote->pce_svn);
    printf("XEID:             0x%08x\n", quote->xeid);
    printf("Basename:         ");
    for (int i = 0; i < 16 && i < 32; i++) {
        printf("%02x", quote->basename.name[i]);
    }
    printf("...\n");
    
    printf("\n[Report Body]\n");
    printf("CPU SVN:          ");
    for (int i = 0; i < SGX_CPUSVN_SIZE; i++) {
        printf("%02x", quote->report_body.cpu_svn.svn[i]);
    }
    printf("\n");
    printf("Misc Select:      0x%08x\n", quote->report_body.misc_select);
    
    /* Print ISV Extended Product ID */
    printf("ISV Ext Prod ID:  ");
    for (int i = 0; i < sizeof(sgx_isvext_prod_id_t); i++) {
        printf("%02x", quote->report_body.isv_ext_prod_id[i]);
    }
    printf("\n");
    
    /* Print Attributes */
    printf("Attributes:       ");
    for (int i = 0; i < sizeof(sgx_attributes_t); i++) {
        printf("%02x", quote->report_body.attributes[i]);
    }
    printf("\n");
    
    /* Print MR_ENCLAVE (hash of enclave contents) */
    print_hex("MR_ENCLAVE", quote->report_body.mr_enclave, sizeof(sgx_measurement_t));
    
    /* Print MR_SIGNER (hash of signer's public key) */
    print_hex("MR_SIGNER", quote->report_body.mr_signer, sizeof(sgx_measurement_t));
    
    /* Print CONFIG_ID (first 16 bytes) */
    printf("CONFIG_ID:        ");
    for (int i = 0; i < 16 && i < sizeof(sgx_config_id_t); i++) {
        printf("%02x", quote->report_body.config_id[i]);
    }
    printf("...\n");
    
    /* Print ISV details */
    printf("ISV Product ID:   %u\n", quote->report_body.isv_prod_id);
    printf("ISV SVN:          %u\n", quote->report_body.isv_svn);
    printf("CONFIG SVN:       %u\n", quote->report_body.config_svn);
    
    /* Print ISV Family ID */
    printf("ISV Family ID:    ");
    for (int i = 0; i < sizeof(sgx_isvfamily_id_t); i++) {
        printf("%02x", quote->report_body.isv_family_id[i]);
    }
    printf("\n");
    
    /* Print the full report data (user data) */
    printf("Report Data:      ");
    for (int i = 0; i < sizeof(sgx_report_data_t); i++) {
        printf("%02x", quote->report_body.report_data[i]);
    }
    printf("\n");
}