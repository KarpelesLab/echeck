#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#include "sgx_types.h"
#include "common.h"
#include "cert_utils.h"
#include "sgx_quote_parser.h"
#include "sgx_quote_verify.h"
#include "ca.h"

int main(int argc, char *argv[]) {
    /* Check command line arguments */
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <certificate.pem>\n", argv[0]);
        return 1;
    }
    
    const char *cert_file = argv[1];
    
    /* Initialize OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    /* Load certificate */
    X509 *cert = load_certificate(cert_file);
    if (!cert) {
        fprintf(stderr, "Failed to load certificate from %s\n", cert_file);
        return 1;
    }
    
    /* Extract SGX quote */
    sgx_quote_buffer_t quote_buffer = {0};
    
    if (extract_sgx_quote(cert, &quote_buffer)) {
        printf("SGX Quote extracted successfully, %d bytes\n", quote_buffer.length);
        
        /* Print some bytes as hex for debugging */
        printf("Quote data (first 16 bytes): ");
        for (int i = 0; i < quote_buffer.length && i < 16; i++) {
            printf("%02x ", quote_buffer.data[i]);
        }
        printf("\n");
        
        /* Save quote to file for analysis */
        FILE *fp = fopen("quote.bin", "wb");
        if (fp) {
            fwrite(quote_buffer.data, 1, quote_buffer.length, fp);
            fclose(fp);
            printf("Quote dumped to quote.bin for analysis\n");
        } else {
            fprintf(stderr, "Failed to create quote.bin file\n");
        }
        
        /* Before verification, calculate and display hash of the certificate's public key */
        printf("\n[Certificate Public Key Hash Analysis]\n");
        
        /* Calculate hash of certificate's public key */
        unsigned char pubkey_hash[SHA256_DIGEST_LENGTH];
        unsigned int pubkey_hash_len = 0;
        
        if (compute_pubkey_hash(cert, pubkey_hash, &pubkey_hash_len)) {
            /* Display hash value in hex */
            printf("Certificate Public Key Hash (SHA-256): ");
            for (int i = 0; i < pubkey_hash_len; i++) {
                printf("%02x", pubkey_hash[i]);
            }
            printf("\n");
            
            /* Get report data from quote for comparison */
            const sgx_quote_t *quote = (const sgx_quote_t *)quote_buffer.data;
            
            /* Display report data for verification */
            printf("Report Data (first 32 bytes): ");
            for (int i = 0; i < 32; i++) {
                printf("%02x", quote->report_body.report_data[i]);
            }
            printf("\n");
            
            /* Verify report data matches certificate public key hash */
            if (verify_report_data(quote, pubkey_hash, pubkey_hash_len)) {
                printf("✅ VERIFIED: Report data correctly contains padded SHA-256 hash of certificate's public key\n");
                printf("This confirms the enclave knew the public key of this certificate when generating the quote.\n");
            } else {
                printf("❌ FAILED: Report data does not match pad64(sha256(public key))\n");
                printf("This means the enclave that created this quote did not know this certificate's public key,\n");
                printf("or the certificate has been modified after the quote was created.\n");
                
                fprintf(stderr, "Quote verification failed: report data doesn't match certificate public key hash\n");
                free(quote_buffer.data);
                X509_free(cert);
                EVP_cleanup();
                ERR_free_strings();
                return 1;
            }
        } else {
            fprintf(stderr, "Failed to compute public key hash\n");
        }
        
        /* Verify the SGX quote with built-in CA */
        sgx_verification_result_t result;
        
        if (verify_sgx_quote(quote_buffer.data, quote_buffer.length, &result)) {
            printf("SGX quote verification successful\n");
        } else {
            fprintf(stderr, "SGX quote verification failed\n");
        }
        
        free(quote_buffer.data);
    } else {
        fprintf(stderr, "No SGX Quote extension found\n");
    }
    
    /* Cleanup */
    X509_free(cert);
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}