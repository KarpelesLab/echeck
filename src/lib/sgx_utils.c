#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "echeck.h"
#include "echeck_internal.h"
/* OpenSSL headers are accessed through openssl_runtime.h included in common.h */

/* Compute a hash of the quote for verification
 * This function only outputs when verbose mode is active */
void dump_buffer(const char *name, const unsigned char *data, size_t len) {
    if (is_verbose_mode()) {
        fprintf(stderr, "%s (%zu bytes): ", name, len);
        for (size_t i = 0; i < len && i < 32; i++) {
            fprintf(stderr, "%02x", data[i]);
        }
        if (len > 32) fprintf(stderr, "...");
        fprintf(stderr, "\n");
    }
}

/* Extract the attestation key from the quote signature data */
int extract_attestation_key(const sgx_quote_t *quote, EVP_PKEY **out_key) {
    /* First, ensure this is a v3 ECDSA quote */
    if (!quote || !out_key) {
        fprintf(stderr, "Invalid parameters for attestation key extraction\n");
        return 0;
    }

    if (quote->version != 3) {
        fprintf(stderr, "Attestation key extraction only supported for ECDSA Quote v3\n");
        return 0;
    }
    
    /* Get the signature data (located after the quote body) */
    uint32_t sig_data_offset = offsetof(sgx_quote_t, signature_len) + sizeof(uint32_t);
    const sgx_ql_ecdsa_sig_data_t *sig_data = (const sgx_ql_ecdsa_sig_data_t *)(((const uint8_t *)quote) + sig_data_offset);
    
    /* The attestation public key is in the attest_pub_key field */
    /* This is a 64-byte buffer containing the x,y coordinates of the EC point */
    const uint8_t *pub_key_raw = sig_data->attest_pub_key;
    
    /* Attestation key components processing (formerly debug output) */
    
    /* Create EVP_PKEY context for creating keys with the modern API */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        print_openssl_error("Failed to create EVP_PKEY_CTX");
        return 0;
    }
    
    /* Initialize key generation parameters */
    if (EVP_PKEY_paramgen_init(ctx) != 1) {
        print_openssl_error("Failed to initialize paramgen");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    
    /* Set curve to P-256 (same as NID_X9_62_prime256v1) */
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) != 1) {
        print_openssl_error("Failed to set curve parameters");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    
    /* Generate parameters */
    EVP_PKEY *params = NULL;
    if (EVP_PKEY_paramgen(ctx, &params) != 1) {
        print_openssl_error("Failed to generate parameters");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    
    /* Create a new EVP_PKEY for the final key */
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        print_openssl_error("Failed to create EVP_PKEY");
        EVP_PKEY_free(params);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    
    /* Clean up the parameter generation context */
    EVP_PKEY_CTX_free(ctx);
    
    /* Now we need to set the public key data */
    /* For OpenSSL 3.0+, we'll use the low-level APIs to set the key data */
    
    /* Create a temporary EC_KEY structure */
    /* Note: We're still using the deprecated EC_KEY functions here because
     * OpenSSL 3.0 doesn't yet provide a simple way to set raw coordinates
     * without using the EC_KEY API. In a future version, this should be
     * replaced with the newer APIs once they're available. */
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) {
        print_openssl_error("Failed to create temporary EC_KEY");
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(params);
        return 0;
    }
    
    /* Convert the raw X and Y coordinates to BIGNUMs */
    BIGNUM *x = BN_bin2bn(pub_key_raw, 32, NULL);
    BIGNUM *y = BN_bin2bn(pub_key_raw + 32, 32, NULL);
    
    if (!x || !y) {
        print_openssl_error("Failed to convert key coordinates to BIGNUMs");
        if (x) BN_free(x);
        if (y) BN_free(y);
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(params);
        return 0;
    }
    
    /* Set the public key coordinates */
    if (EC_KEY_set_public_key_affine_coordinates(ec_key, x, y) != 1) {
        print_openssl_error("Failed to set EC key coordinates");
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(params);
        return 0;
    }
    
    /* Set the EC_KEY into the EVP_PKEY */
    if (EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 1) {
        print_openssl_error("Failed to set EC key in EVP_PKEY");
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(params);
        return 0;
    }
    
    /* Clean up */
    BN_free(x);
    BN_free(y);
    EC_KEY_free(ec_key);
    EVP_PKEY_free(params);
    
    if (is_verbose_mode()) {
        fprintf(stderr, "Successfully extracted attestation public key\n");
    }

    /* Set the output parameter */
    *out_key = pkey;
    return 1;
}

/* Extract and parse ECDSA signature from quote */
int extract_ecdsa_signature(const sgx_quote_t *quote, 
                          unsigned char **sig_r, unsigned int *sig_r_len,
                          unsigned char **sig_s, unsigned int *sig_s_len) {
    /* First, ensure this is a v3 ECDSA quote */
    if (quote->version != 3) {
        fprintf(stderr, "Signature extraction only supported for ECDSA Quote v3\n");
        return 0;
    }
    
    /* Get the signature data (located after the quote body) */
    uint32_t sig_data_offset = offsetof(sgx_quote_t, signature_len) + sizeof(uint32_t);
    const sgx_ql_ecdsa_sig_data_t *sig_data = (const sgx_ql_ecdsa_sig_data_t *)(((const uint8_t *)quote) + sig_data_offset);
    
    /* The signature is in the sig field - first 32 bytes are R, next 32 bytes are S */
    const uint8_t *sig_raw = sig_data->sig;
    
    /* Print signature components for debugging */
    if (is_verbose_mode()) {
        fprintf(stderr, "[ECDSA Signature Components]\n");
        fprintf(stderr, "R: ");
        for (int i = 0; i < 32; i++) {
            fprintf(stderr, "%02x", sig_raw[i]);
        }
        fprintf(stderr, "\n");
    }

    if (is_verbose_mode()) {
        fprintf(stderr, "S: ");
        for (int i = 0; i < 32; i++) {
            fprintf(stderr, "%02x", sig_raw[i + 32]);
        }
        fprintf(stderr, "\n");
    }
    
    /* Allocate memory for the signature components */
    *sig_r = (unsigned char *)malloc(32);
    *sig_s = (unsigned char *)malloc(32);
    
    if (!*sig_r || !*sig_s) {
        fprintf(stderr, "Failed to allocate memory for signature components\n");
        if (*sig_r) free(*sig_r);
        if (*sig_s) free(*sig_s);
        *sig_r = *sig_s = NULL;
        return 0;
    }
    
    /* Copy the signature components */
    memcpy(*sig_r, sig_raw, 32);
    memcpy(*sig_s, sig_raw + 32, 32);
    *sig_r_len = *sig_s_len = 32;
    
    return 1;
}

/* Function to compute the hash of the quote for signature verification */
int compute_quote_hash_for_sig(const sgx_quote_t *quote, unsigned char *hash, unsigned int *hash_len) {
    /* Create a new hash context */
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        print_openssl_error("Failed to create hash context");
        return 0;
    }
    
    /* Initialize the hash context with SHA256 */
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        print_openssl_error("Failed to initialize hash context");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    
    /* In SGX ECDSA quote v3, the hash is computed over everything up to but not including the signature_len field */
    size_t data_len = offsetof(sgx_quote_t, signature_len);
    
    /* Add data to the hash */
    if (EVP_DigestUpdate(mdctx, quote, data_len) != 1) {
        print_openssl_error("Failed to update hash");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    
    /* Compute the final hash */
    if (EVP_DigestFinal_ex(mdctx, hash, hash_len) != 1) {
        print_openssl_error("Failed to finalize hash");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    
    /* Hash computation complete */
    
    /* Clean up */
    EVP_MD_CTX_free(mdctx);
    return 1;
}

/* Verify QE Report signature using the PCK certificate's public key
 * This is the critical step that links the attestation key to Intel's chain of trust.
 *
 * The QE Report signature proves that:
 * 1. The QE Report was generated by genuine Intel SGX hardware
 * 2. The PCK certificate (signed by Intel) vouches for this specific QE Report
 * 3. The attestation key hash in the QE Report's report_data is certified by Intel
 */
int verify_qe_report_signature(const sgx_quote_t *quote, EVP_PKEY *pck_pubkey) {
    if (!quote || !pck_pubkey) {
        fprintf(stderr, "Invalid parameters for QE report signature verification\n");
        return 0;
    }

    if (quote->version != 3) {
        fprintf(stderr, "QE report signature verification only supported for ECDSA Quote v3\n");
        return 0;
    }

    /* Bounds check: signature must contain at least the ECDSA sig data structure
     * 64 (sig) + 64 (attest_pub_key) + 384 (qe_report) + 64 (qe_report_sig) = 576 bytes */
    uint32_t min_sig_len = 64 + 64 + sizeof(sgx_report_body_t) + 64;
    if (quote->signature_len < min_sig_len) {
        fprintf(stderr, "Error: Signature data too short for QE report verification: %u < %u\n",
                quote->signature_len, min_sig_len);
        return 0;
    }

    /* Get the signature data structure */
    uint32_t sig_data_offset = offsetof(sgx_quote_t, signature_len) + sizeof(uint32_t);
    const sgx_ql_ecdsa_sig_data_t *sig_data = (const sgx_ql_ecdsa_sig_data_t *)(((const uint8_t *)quote) + sig_data_offset);

    /* Extract QE Report signature components (r, s) from qe_report_sig field */
    const uint8_t *qe_sig_r = sig_data->qe_report_sig;
    const uint8_t *qe_sig_s = sig_data->qe_report_sig + 32;

    if (is_verbose_mode()) {
        fprintf(stderr, "[QE Report Signature Verification]\n");
        fprintf(stderr, "QE Report Signature R: ");
        for (int i = 0; i < 32; i++) {
            fprintf(stderr, "%02x", qe_sig_r[i]);
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "QE Report Signature S: ");
        for (int i = 0; i < 32; i++) {
            fprintf(stderr, "%02x", qe_sig_s[i]);
        }
        fprintf(stderr, "\n");
    }

    /* Compute SHA-256 hash of the QE Report (384 bytes) */
    unsigned char qe_report_hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        print_openssl_error("Failed to create hash context for QE report");
        return 0;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, &sig_data->qe_report, sizeof(sgx_report_body_t)) != 1 ||
        EVP_DigestFinal_ex(mdctx, qe_report_hash, NULL) != 1) {
        print_openssl_error("Failed to compute QE report hash");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    EVP_MD_CTX_free(mdctx);

    if (is_verbose_mode()) {
        fprintf(stderr, "QE Report Hash: ");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            fprintf(stderr, "%02x", qe_report_hash[i]);
        }
        fprintf(stderr, "\n");
    }

    /* Create ECDSA_SIG from r,s components */
    ECDSA_SIG *qe_sig = ECDSA_SIG_new();
    if (!qe_sig) {
        print_openssl_error("Failed to create ECDSA_SIG for QE report");
        return 0;
    }

    BIGNUM *r = BN_bin2bn(qe_sig_r, 32, NULL);
    BIGNUM *s = BN_bin2bn(qe_sig_s, 32, NULL);

    if (!r || !s) {
        print_openssl_error("Failed to convert QE signature components to BIGNUMs");
        if (r) BN_free(r);
        if (s) BN_free(s);
        ECDSA_SIG_free(qe_sig);
        return 0;
    }

    if (ECDSA_SIG_set0(qe_sig, r, s) != 1) {
        print_openssl_error("Failed to set QE signature components");
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(qe_sig);
        return 0;
    }
    /* Note: r and s are now owned by qe_sig, don't free them separately */

    /* Verify using EC_KEY method */
    int result = 0;
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pck_pubkey);
    if (ec_key) {
        int ec_result = ECDSA_do_verify(qe_report_hash, SHA256_DIGEST_LENGTH, qe_sig, ec_key);
        if (ec_result == 1) {
            result = 1;
            if (is_verbose_mode()) {
                fprintf(stderr, "QE Report signature verification: PASSED\n");
            }
        } else if (ec_result == 0) {
            fprintf(stderr, "Error: QE Report signature verification FAILED - signature invalid\n");
        } else {
            print_openssl_error("Error during QE Report signature verification");
        }
        EC_KEY_free(ec_key);
    } else {
        print_openssl_error("Failed to extract EC_KEY from PCK certificate");
    }

    ECDSA_SIG_free(qe_sig);
    return result;
}

/* Verify that the QE Report's report_data contains the hash of (attestation_key || auth_data)
 * This proves the attestation key is bound to the QE Report certified by Intel
 */
int verify_qe_report_data(const sgx_quote_t *quote) {
    if (!quote) {
        fprintf(stderr, "Invalid parameters for QE report data verification\n");
        return 0;
    }

    if (quote->version != 3) {
        fprintf(stderr, "QE report data verification only supported for ECDSA Quote v3\n");
        return 0;
    }

    /* Navigate to auth data section */
    /* Offset: 64 (sig) + 64 (attest_pub_key) + 384 (qe_report) + 64 (qe_report_sig) = 576 */
    uint32_t auth_data_offset = 64 + 64 + sizeof(sgx_report_body_t) + 64;

    /* Bounds check: signature must contain at least auth_data header
     * auth_data_size(2) + auth_data(32) = 34 bytes minimum after offset */
    uint32_t min_sig_len = auth_data_offset + 34;
    if (quote->signature_len < min_sig_len) {
        fprintf(stderr, "Error: Signature data too short for auth data: %u < %u\n",
                quote->signature_len, min_sig_len);
        return 0;
    }

    /* Get the signature data structure */
    uint32_t sig_data_offset = offsetof(sgx_quote_t, signature_len) + sizeof(uint32_t);
    const sgx_ql_ecdsa_sig_data_t *sig_data = (const sgx_ql_ecdsa_sig_data_t *)(((const uint8_t *)quote) + sig_data_offset);

    const sgx_ql_auth_data_t *auth_data = (const sgx_ql_auth_data_t *)(((const uint8_t *)sig_data) + auth_data_offset);

    /* Verify auth data size */
    if (auth_data->auth_data_size != 0x20) {
        fprintf(stderr, "Error: Unexpected auth data size: 0x%04x (expected 0x0020)\n", auth_data->auth_data_size);
        return 0;
    }

    /* Compute SHA-256 hash of (attestation_public_key || auth_data) */
    unsigned char expected_hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        print_openssl_error("Failed to create hash context for attestation key binding");
        return 0;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, sig_data->attest_pub_key, 64) != 1 ||
        EVP_DigestUpdate(mdctx, auth_data->auth_data, 32) != 1 ||
        EVP_DigestFinal_ex(mdctx, expected_hash, NULL) != 1) {
        print_openssl_error("Failed to compute attestation key binding hash");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    EVP_MD_CTX_free(mdctx);

    if (is_verbose_mode()) {
        fprintf(stderr, "[QE Report Data Verification]\n");
        fprintf(stderr, "Expected hash (SHA256(attest_key||auth_data)): ");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            fprintf(stderr, "%02x", expected_hash[i]);
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "QE Report report_data (first 32 bytes): ");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            fprintf(stderr, "%02x", sig_data->qe_report.report_data[i]);
        }
        fprintf(stderr, "\n");
    }

    /* Compare with QE Report's report_data (first 32 bytes) */
    if (memcmp(expected_hash, sig_data->qe_report.report_data, SHA256_DIGEST_LENGTH) != 0) {
        fprintf(stderr, "Error: QE Report report_data does not match expected hash of attestation key\n");
        return 0;
    }

    if (is_verbose_mode()) {
        fprintf(stderr, "QE Report data verification: PASSED (attestation key is properly bound)\n");
    }

    return 1;
}

/* Verify ECDSA signature with extracted key and quote hash */
int verify_quote_signature_raw(const unsigned char *quote_hash, unsigned int quote_hash_len,
                             const unsigned char *sig_r, unsigned int sig_r_len,
                             const unsigned char *sig_s, unsigned int sig_s_len,
                             EVP_PKEY *pubkey) {
    /* For SGX quote signatures, we need to convert the r,s components to a DER-encoded
     * signature that OpenSSL can process, and then verify it against the quote hash */
    
    /* We'll try both verification methods: traditional EC_KEY and modern EVP */
    int result = 0;
    
    /* Method 1: Using low-level EC_KEY functions */
    /* This is less preferred but provides a fallback if the EVP method doesn't work */
    
    /* Create a temporary ECDSA_SIG object */
    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (!sig) {
        print_openssl_error("Failed to create ECDSA_SIG");
        return 0;
    }
    
    /* Set the R and S components */
    BIGNUM *r = BN_bin2bn(sig_r, sig_r_len, NULL);
    BIGNUM *s = BN_bin2bn(sig_s, sig_s_len, NULL);
    
    if (!r || !s) {
        print_openssl_error("Failed to convert signature components to BIGNUMs");
        if (r) BN_free(r);
        if (s) BN_free(s);
        ECDSA_SIG_free(sig);
        return 0;
    }
    
    /* Set the signature components in the ECDSA_SIG object */
    if (ECDSA_SIG_set0(sig, r, s) != 1) {
        print_openssl_error("Failed to set signature components");
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return 0;
    }
    
    /* Convert the ECDSA_SIG to DER format for the second method */
    unsigned char *sig_der = NULL;
    int sig_der_len = i2d_ECDSA_SIG(sig, &sig_der);
    
    /* Method 2: Using EC_KEY_get1_EC_KEY and ECDSA_do_verify */
    /* This is deprecated in OpenSSL 3.0 but more reliable for our specific case */
    /* We're knowingly working with the deprecated API here as a fallback */
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pubkey);
    if (ec_key) {
        /* Verify the signature directly using ECDSA_do_verify */
        int ec_result = ECDSA_do_verify(quote_hash, quote_hash_len, sig, ec_key);
        
        if (ec_result == 1) {
            result = 1;
        } else if (ec_result == 0) {
            /* We'll fall back to the EVP method if available */
        } else {
            print_openssl_error("Error during ECDSA signature verification (EC_KEY method)");
        }
        
        /* Clean up EC_KEY */
        EC_KEY_free(ec_key);
    }
    
    /* If the first method didn't produce a positive result and we have a valid DER signature, 
       try the second method */
    if (!result && sig_der != NULL && sig_der_len > 0) {
        /* Method 3: Using EVP APIs */
        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        if (md_ctx) {
            /* Initialize the verification operation */
            if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pubkey) == 1) {
                /* Update the verification context */
                if (EVP_DigestVerifyUpdate(md_ctx, quote_hash, quote_hash_len) == 1) {
                    /* Verify the signature */
                    int evp_result = EVP_DigestVerifyFinal(md_ctx, sig_der, sig_der_len);
                    
                    if (evp_result == 1) {
                        result = 1;
                    } else if (evp_result == 0) {
                        /* EVP verification failed */
                    } else {
                        print_openssl_error("Error during ECDSA signature verification (EVP method)");
                    }
                }
            }
            
            /* Clean up */
            EVP_MD_CTX_free(md_ctx);
        }
    }
    
    /* Clean up */
    if (sig_der) OPENSSL_free(sig_der);
    ECDSA_SIG_free(sig);
    
    /* Return the verification result */
    return result;
}