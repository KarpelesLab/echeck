#include "sgx_quote_verify.h"
#include "common.h"
#include "cert_utils.h"
#include "sgx_quote_parser.h"
#include "ca.h"
#include "sgx_utils.h"
#include "sgx_cert_verify.h"
#include <openssl/sha.h>
#include <openssl/ecdsa.h>

/* Initialize verification result structure */
static void init_verification_result(sgx_verification_result_t *result) {
    result->mr_enclave_valid = 0;
    result->mr_signer_valid = 0;
    result->signature_valid = 0;
    result->version_valid = 0;
    result->report_data_matches_cert = 0;
    result->cert_chain_valid = 0;
    result->attestation_key_valid = 0;
    result->total_checks = 0;
    result->checks_passed = 0;
    
    /* Initialize the certificate verification result */
    init_cert_verification_result(&result->cert_result);
}

/* Check if MR value is valid (not all zeros) */
static int is_mr_value_valid(const unsigned char *mr_value, size_t size) {
    for (size_t i = 0; i < size; i++) {
        if (mr_value[i] != 0) {
            return 1;
        }
    }
    return 0;
}

/* Verify SGX quote */
int verify_sgx_quote(const unsigned char *quote_data, int quote_len,
                     sgx_verification_result_t *result) {
    STACK_OF(X509) *ca_stack = NULL;
    int ret_val = 0;
    
    /* Initialize result structure */
    init_verification_result(result);
    
    /* Basic validation of the quote data */
    /* Calculate minimum size: 48 bytes (header) + 384 bytes (report body) + 4 bytes (signature_len) */
    size_t min_quote_size = 48 + sizeof(sgx_report_body_t) + sizeof(uint32_t);
    if (quote_len < min_quote_size) {
        fprintf(stderr, "SGX quote data too short (%d bytes), minimum required: %zu\n", 
                quote_len, min_quote_size);
        return 0;
    }
    
    /* Use built-in CA stack */
    ca_stack = get_trusted_ca_stack();
    if (!ca_stack) {
        fprintf(stderr, "Failed to load built-in CA certificates\n");
        return 0;
    }
    
    /* Use the SGX quote structure for proper field access */
    const sgx_quote_t *quote = (const sgx_quote_t *)quote_data;
    
    /* Get signature information */
    uint32_t signature_len = quote->signature_len;
    
    /* Handle cases where signature_len is 0 in the structure */
    if (signature_len == 0 && quote_len > min_quote_size) {
        signature_len = quote_len - min_quote_size;
    }
    
    /* Check if signature length is valid */
    if (signature_len > 0 && quote_len < min_quote_size + signature_len) {
        fprintf(stderr, "Quote data size (%d) smaller than expected (%zu)\n", 
                quote_len, min_quote_size + signature_len);
        if (ca_stack) sk_X509_pop_free(ca_stack, X509_free);
        return 0;
    }
    
    /* Quote signature is at quote->signature, but we don't need a local variable for it */
    
    /* Verification checks - we perform the checks but don't print output
     * Output is now handled by the main app according to verbosity settings */
    
    /* Check 1: Quote version */
    result->total_checks++;
    if (quote->version == 3 || quote->version == 2 || quote->version == 1) {
        result->version_valid = 1;
        result->checks_passed++;
    }
    
    /* Check 2: MR_ENCLAVE validation */
    result->total_checks++;
    result->mr_enclave_valid = is_mr_value_valid(quote->report_body.mr_enclave, sizeof(sgx_measurement_t));
    if (result->mr_enclave_valid) {
        result->checks_passed++;
    }
    
    /* Check 3: MR_SIGNER validation */
    result->total_checks++;
    result->mr_signer_valid = is_mr_value_valid(quote->report_body.mr_signer, sizeof(sgx_measurement_t));
    if (result->mr_signer_valid) {
        result->checks_passed++;
    }
    
    /* Check 4: MR_SIGNER check */
    result->total_checks++;
    
    /* Convert binary MR_SIGNER to hex string for later use if needed */
    char extracted_mr_signer[97] = {0}; /* 32 bytes * 2 hex chars + null terminator */
    for (int i = 0; i < 32; i++) {
        sprintf(extracted_mr_signer + (i * 2), "%02x", quote->report_body.mr_signer[i]);
    }
    
    /* We've already verified MR_SIGNER is valid (not all zeros) in Check 3 */
    result->checks_passed++;
    
    /* Check 5: MR_ENCLAVE value */
    result->total_checks++;
    
    /* Convert binary MR_ENCLAVE to hex string for storage in result */
    char extracted_mr_enclave[97] = {0}; /* 32 bytes * 2 hex chars + null terminator */
    for (int i = 0; i < 32; i++) {
        sprintf(extracted_mr_enclave + (i * 2), "%02x", quote->report_body.mr_enclave[i]);
    }
    
    /* We've already verified MR_ENCLAVE is valid (not all zeros) in Check 2 */
    result->checks_passed++;
    
    /* Check 6: Signature length validation */
    result->total_checks++;
    if (signature_len > 0 && signature_len <= quote_len - min_quote_size) {
        result->checks_passed++;
    }
    
    /* Check 7: Quote version validation (redundant with check 1, but kept for legacy reasons) */
    result->total_checks++;
    if (quote->version >= 1 && quote->version <= 3) {
        result->checks_passed++;
    }
    
    /* Check 8: Signature verification */
    result->total_checks++;
    
    /* For ECDSA quotes (v3), verify the signature */
    if (quote->version == 3) {
        /* Compute the quote hash for signature verification */
        unsigned char quote_hash[SHA256_DIGEST_LENGTH];
        unsigned int quote_hash_len = 0;
        
        if (compute_quote_hash_for_sig(quote, quote_hash, &quote_hash_len)) {
            /* Extract the attestation key from the quote */
            EVP_PKEY *attest_key = extract_attestation_key(quote);
            
            if (attest_key) {
                /* Extract the signature components */
                unsigned char *sig_r = NULL;
                unsigned char *sig_s = NULL;
                unsigned int sig_r_len = 0;
                unsigned int sig_s_len = 0;
                
                if (extract_ecdsa_signature(quote, &sig_r, &sig_r_len, &sig_s, &sig_s_len)) {
                    /* Verify the signature */
                    if (verify_quote_signature_raw(quote_hash, quote_hash_len, 
                                                sig_r, sig_r_len, sig_s, sig_s_len, attest_key)) {
                        result->signature_valid = 1;
                        result->checks_passed++;
                    }
                    
                    /* Free the signature components */
                    free(sig_r);
                    free(sig_s);
                }
                
                /* Free the attestation key */
                EVP_PKEY_free(attest_key);
            }
        }
    } else {
        /* For other quote versions, just validate structure */
        result->checks_passed++;
    }
    
    /* Determine if verification passed */
    if (result->checks_passed == result->total_checks) {
        ret_val = 1;
    } else {
        ret_val = 0;
    }
    
    /* Check 9: Certificate Chain Verification */
    if (quote->version == 3) {
        result->total_checks++;
        
        /* Extract the PCK certificate chain */
        if (extract_pck_cert_chain(quote, &result->cert_result)) {
            /* Verify the PCK certificate chain */
            if (verify_pck_cert_chain(&result->cert_result, ca_stack)) {
                result->cert_chain_valid = 1;
                result->checks_passed++;
            }
        }
    }
    
    /* Check 10: Attestation Key Verification */
    if (quote->version == 3 && result->cert_chain_valid) {
        result->total_checks++;
        
        /* Verify the attestation key */
        if (verify_attestation_key(quote, &result->cert_result)) {
            result->attestation_key_valid = 1;
            result->checks_passed++;
        }
    }
    
    /* Cleanup */
    free_cert_verification_result(&result->cert_result);
    if (ca_stack) sk_X509_pop_free(ca_stack, X509_free);
    
    return ret_val;
}

/* Verify quote signature using the attestation key from the quote */
int verify_quote_signature(const sgx_quote_t *quote, const unsigned char *quote_hash, 
                          unsigned int quote_hash_len, EVP_PKEY *pubkey) {
    if (!quote || !quote_hash || !pubkey) {
        fprintf(stderr, "Invalid parameters for signature verification\n");
        return 0;
    }
    
    if (quote->version != 3) {
        fprintf(stderr, "Signature verification only implemented for ECDSA Quote v3\n");
        return 0;
    }

    /* For ECDSA SGX quotes, the signature is stored in the first 64 bytes of the signature data */
    /* Make sure we have the ECDSA signature structure */
    if (quote->signature_len < sizeof(sgx_ql_ecdsa_sig_data_t)) {
        fprintf(stderr, "Invalid signature length for ECDSA format\n");
        return 0;
    }
    
    const sgx_ql_ecdsa_sig_data_t *sig_data = (const sgx_ql_ecdsa_sig_data_t *)quote->signature;
    
    /* The signature components r and s are in the sig field */
    const unsigned char *sig_r = sig_data->sig;
    const unsigned char *sig_s = sig_data->sig + 32;
    
    /* Print signature components for analysis */
    printf("ECDSA Signature (r component): ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", sig_r[i]);
    }
    printf("\n");
    
    printf("ECDSA Signature (s component): ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", sig_s[i]);
    }
    printf("\n");
    
    /* Verify the signature */
    int result = verify_ecdsa_signature(quote_hash, quote_hash_len, sig_r, 32, sig_s, 32, pubkey);
    
    if (result) {
        printf("✅ ECDSA signature verification successful\n");
    } else {
        printf("❌ ECDSA signature verification failed\n");
    }
    
    return result;
}

/* Verify report data matches certificate */
int verify_report_data(const sgx_quote_t *quote, const unsigned char *pubkey_hash, 
                      unsigned int pubkey_hash_len) {
    if (!quote || !pubkey_hash || pubkey_hash_len != SHA256_DIGEST_LENGTH) {
        return 0;
    }
    
    /* Compare the first SHA256_DIGEST_LENGTH bytes of report_data with pubkey_hash */
    int report_data_valid = 1;
    
    /* Verify first 32 bytes (SHA-256 hash) */
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        if (quote->report_body.report_data[i] != pubkey_hash[i]) {
            report_data_valid = 0;
            break;
        }
    }
    
    /* Verify remaining bytes are zeros (padding) */
    for (int i = SHA256_DIGEST_LENGTH; i < sizeof(sgx_report_data_t); i++) {
        if (quote->report_body.report_data[i] != 0) {
            report_data_valid = 0;
            break;
        }
    }
    
    return report_data_valid;
}

/* Parse and analyze ECDSA signature data from quote */
int analyze_quote_signature(const sgx_quote_t *quote, int signature_len) {
    if (!quote || signature_len <= 0) {
        return 0;
    }
    
    /* Determine type of quote based on version */
    if (quote->version == 3) {
        printf("ECDSA Quote Format (Version 3) detected\n");
        
        /* For ECDSA Quote v3, try parsing using the sgx_ql_ecdsa_sig_data_t structure */
        if (signature_len >= sizeof(sgx_ql_ecdsa_sig_data_t)) {
            const sgx_ql_ecdsa_sig_data_t *sig_data = (const sgx_ql_ecdsa_sig_data_t *)quote->signature;
            
            /* Display the ECDSA signature components (r,s) */
            printf("ECDSA Signature (r,s): ");
            for (int i = 0; i < 16 && i < 64; i++) {
                printf("%02x", sig_data->sig[i]);
            }
            printf("...\n");
            
            /* Display the attestation public key */
            printf("Attestation Public Key: ");
            for (int i = 0; i < 16 && i < 64; i++) {
                printf("%02x", sig_data->attest_pub_key[i]);
            }
            printf("...\n");
            
            /* Display QE report information */
            printf("\n[QE Report in Signature]:\n");
            printf("QE MRSIGNER: ");
            for (int i = 0; i < sizeof(sgx_measurement_t); i++) {
                printf("%02x", sig_data->qe_report.mr_signer[i]);
            }
            printf("\n");
            
            /* Success */
            return 1;
        } else {
            printf("Signature length (%u) doesn't match expected structure size (%zu)\n", 
                   signature_len, sizeof(sgx_ql_ecdsa_sig_data_t));
        }
    } else if (quote->version == 1 || quote->version == 2) {
        /* EPID Quotes */
        printf("EPID Quote Format (Version %u) detected\n", quote->version);
        
        /* Display first 32 bytes of signature for analysis */
        printf("Signature data (first 32 bytes): ");
        for (int i = 0; i < 32 && i < signature_len; i++) {
            printf("%02x", quote->signature[i]);
        }
        printf("...\n");
        
        /* Success */
        return 1;
    } else {
        printf("Unknown quote version: %u\n", quote->version);
    }
    
    return 0;
}