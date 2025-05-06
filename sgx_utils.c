#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>

#include "sgx_utils.h"
#include "common.h"

/* Compute a hash of the quote for verification */
void dump_buffer(const char *name, const unsigned char *data, size_t len) {
    printf("%s (%zu bytes): ", name, len);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
}

/* Extract the attestation key from the quote signature data */
EVP_PKEY *extract_attestation_key(const sgx_quote_t *quote) {
    /* First, ensure this is a v3 ECDSA quote */
    if (quote->version != 3) {
        fprintf(stderr, "Attestation key extraction only supported for ECDSA Quote v3\n");
        return NULL;
    }
    
    /* Get the signature data (located after the quote body) */
    uint32_t sig_data_offset = offsetof(sgx_quote_t, signature_len) + sizeof(uint32_t);
    const sgx_ql_ecdsa_sig_data_t *sig_data = (const sgx_ql_ecdsa_sig_data_t *)(((const uint8_t *)quote) + sig_data_offset);
    
    /* The attestation public key is in the attest_pub_key field */
    /* This is a 64-byte buffer containing the x,y coordinates of the EC point */
    const uint8_t *pub_key_raw = sig_data->attest_pub_key;
    
    /* Print attestation key components for debugging */
    printf("[Attestation Key Components]\n");
    printf("X: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", pub_key_raw[i]);
    }
    printf("\n");
    
    printf("Y: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", pub_key_raw[i + 32]);
    }
    printf("\n");
    
    /* Create a new key instance */
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) {
        print_openssl_error("Failed to create EC key");
        return NULL;
    }
    
    /* Convert the raw X and Y coordinates to BIGNUMs */
    BIGNUM *x = BN_bin2bn(pub_key_raw, 32, NULL);
    BIGNUM *y = BN_bin2bn(pub_key_raw + 32, 32, NULL);
    
    if (!x || !y) {
        print_openssl_error("Failed to convert key coordinates to BIGNUMs");
        if (x) BN_free(x);
        if (y) BN_free(y);
        EC_KEY_free(ec_key);
        return NULL;
    }
    
    /* Set the public key coordinates */
    if (EC_KEY_set_public_key_affine_coordinates(ec_key, x, y) != 1) {
        print_openssl_error("Failed to set EC key coordinates");
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec_key);
        return NULL;
    }
    
    /* Verify the key is valid */
    if (EC_KEY_check_key(ec_key) != 1) {
        print_openssl_error("EC key validation failed");
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec_key);
        return NULL;
    }
    
    /* Create an EVP_PKEY from the EC key */
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        print_openssl_error("Failed to create EVP_PKEY");
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec_key);
        return NULL;
    }
    
    if (EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 1) {
        print_openssl_error("Failed to set EC key in EVP_PKEY");
        EVP_PKEY_free(pkey);
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec_key);
        return NULL;
    }
    
    /* Clean up */
    BN_free(x);
    BN_free(y);
    EC_KEY_free(ec_key);
    
    printf("Successfully extracted attestation public key\n");
    return pkey;
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
    printf("[ECDSA Signature Components]\n");
    printf("R: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", sig_raw[i]);
    }
    printf("\n");
    
    printf("S: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", sig_raw[i + 32]);
    }
    printf("\n");
    
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
    
    /* Display hash for debugging */
    printf("Quote hash for verification: ");
    for (unsigned int i = 0; i < *hash_len; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    
    /* Clean up */
    EVP_MD_CTX_free(mdctx);
    return 1;
}

/* Verify ECDSA signature with extracted key and quote hash */
int verify_quote_signature_raw(const unsigned char *quote_hash, unsigned int quote_hash_len,
                             const unsigned char *sig_r, unsigned int sig_r_len,
                             const unsigned char *sig_s, unsigned int sig_s_len,
                             EVP_PKEY *pubkey) {
    int result = 0;
    
    /* Create a signature object */
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
    
    /* Get the EC key from the EVP_PKEY */
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pubkey);
    if (!ec_key) {
        print_openssl_error("Failed to get EC key from EVP_PKEY");
        ECDSA_SIG_free(sig);
        return 0;
    }
    
    /* Verify the signature */
    result = ECDSA_do_verify(quote_hash, quote_hash_len, sig, ec_key);
    
    /* Clean up */
    EC_KEY_free(ec_key);
    ECDSA_SIG_free(sig);
    
    if (result == 1) {
        printf("ECDSA signature verification succeeded\n");
        return 1;
    } else if (result == 0) {
        printf("ECDSA signature verification failed\n");
        return 0;
    } else {
        print_openssl_error("Error during ECDSA signature verification");
        return 0;
    }
}