#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>

#include "sgx_utils.h"
#include "common.h"

/* We're using compute_quote_hash from sgx_quote_parser.c */

/* Extract the attestation key from the quote signature data */
EVP_PKEY *extract_attestation_key(const sgx_quote_t *quote) {
    /* First, ensure this is a v3 ECDSA quote */
    if (quote->version != 3) {
        fprintf(stderr, "Attestation key extraction only supported for ECDSA Quote v3\n");
        return NULL;
    }
    
    /* Get the signature data structure (assuming it's properly formatted) */
    const sgx_ql_ecdsa_sig_data_t *sig_data = (const sgx_ql_ecdsa_sig_data_t *)quote->signature;
    
    /* The attestation public key is directly available in the signature data */
    const unsigned char *attest_pubkey = sig_data->attest_pub_key;
    
    /* Display the attestation public key for debugging */
    printf("Attestation Public Key: ");
    for (int i = 0; i < 64; i++) {
        printf("%02x", attest_pubkey[i]);
    }
    printf("\n");
    
    /* Let's use a simpler approach with OpenSSL 1.1.1+ API */
    EVP_PKEY *pkey = NULL;
    
    /* Create a new EC key with P-256 curve */
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) {
        print_openssl_error("Error creating EC key");
        return NULL;
    }
    
    /* Parse the public key components from the attestation key data */
    BIGNUM *x = BN_bin2bn(attest_pubkey, 32, NULL);
    BIGNUM *y = BN_bin2bn(attest_pubkey + 32, 32, NULL);
    
    if (!x || !y) {
        print_openssl_error("Error converting key components to BIGNUMs");
        if (x) BN_free(x);
        if (y) BN_free(y);
        EC_KEY_free(ec_key);
        return NULL;
    }
    
    /* Set the public key coordinates */
    if (EC_KEY_set_public_key_affine_coordinates(ec_key, x, y) != 1) {
        print_openssl_error("Error setting EC key coordinates");
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec_key);
        return NULL;
    }
    
    /* Create an EVP_PKEY from the EC key */
    pkey = EVP_PKEY_new();
    if (!pkey) {
        print_openssl_error("Error creating EVP_PKEY");
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec_key);
        return NULL;
    }
    
    /* Set the EC key in the EVP_PKEY */
    if (EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 1) {
        print_openssl_error("Error setting EC key in EVP_PKEY");
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
    
    /* If we got a valid key, print a message */
    if (pkey) {
        printf("Successfully extracted attestation key\n");
    } else {
        fprintf(stderr, "Failed to extract attestation key\n");
    }
    
    return pkey;
}