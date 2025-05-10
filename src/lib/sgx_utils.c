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