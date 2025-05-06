#include "cert_utils.h"
#include "common.h"

/* Load a certificate from a PEM file */
X509 *load_certificate(const char *file_path) {
    BIO *bio = NULL;
    X509 *cert = NULL;
    
    /* Create a BIO for reading the file */
    bio = BIO_new_file(file_path, "r");
    if (!bio) {
        print_openssl_error("Error opening certificate file");
        return NULL;
    }
    
    /* Read PEM formatted certificate */
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert) {
        print_openssl_error("Error reading certificate");
        BIO_free(bio);
        return NULL;
    }
    
    /* Free the BIO */
    BIO_free(bio);
    
    return cert;
}

/* Extract a public key hash from a certificate */
int compute_pubkey_hash(X509 *cert, unsigned char *hash, unsigned int *hash_len) {
    EVP_PKEY *pubkey = NULL;
    unsigned char *der_pubkey = NULL;
    int der_len;
    int result = 0;
    
    /* Extract public key from certificate */
    pubkey = X509_get_pubkey(cert);
    if (!pubkey) {
        print_openssl_error("Failed to extract public key from certificate");
        return 0;
    }
    
    /* Export public key in PKIX format */
    der_len = i2d_PUBKEY(pubkey, &der_pubkey);
    if (der_len <= 0 || !der_pubkey) {
        print_openssl_error("Failed to export public key to DER format");
        EVP_PKEY_free(pubkey);
        return 0;
    }
    
    /* Hash the public key with SHA-256 */
    if (!SHA256(der_pubkey, der_len, hash)) {
        print_openssl_error("SHA-256 hash computation failed");
    } else {
        *hash_len = SHA256_DIGEST_LENGTH;
        result = 1;
    }
    
    /* Cleanup */
    OPENSSL_free(der_pubkey);
    EVP_PKEY_free(pubkey);
    
    return result;
}

/* Function create_ca_stack has been removed as we now only use built-in CAs */

/* Verify an ECDSA signature */
int verify_ecdsa_signature(const unsigned char *data, size_t data_len, 
                         const unsigned char *sig_r, size_t sig_r_len,
                         const unsigned char *sig_s, size_t sig_s_len,
                         EVP_PKEY *pkey) {
    int result = 0;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    
    /* Create a message digest context */
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        print_openssl_error("Error creating message digest context");
        return 0;
    }
    
    /* Initialize the verification operation */
    if (EVP_DigestVerifyInit(md_ctx, &pkey_ctx, EVP_sha256(), NULL, pkey) != 1) {
        print_openssl_error("Error initializing digest verify");
        goto cleanup;
    }
    
    /* Create DER-encoded ECDSA signature from r and s components */
    ECDSA_SIG *sig_obj = ECDSA_SIG_new();
    if (!sig_obj) {
        print_openssl_error("Error creating ECDSA_SIG object");
        goto cleanup;
    }
    
    /* Convert raw r and s values to BIGNUMs and set them in the ECDSA_SIG object */
    BIGNUM *bn_r = BN_bin2bn(sig_r, sig_r_len, NULL);
    BIGNUM *bn_s = BN_bin2bn(sig_s, sig_s_len, NULL);
    
    if (!bn_r || !bn_s) {
        print_openssl_error("Error converting signature components to BIGNUMs");
        if (bn_r) BN_free(bn_r);
        if (bn_s) BN_free(bn_s);
        ECDSA_SIG_free(sig_obj);
        goto cleanup;
    }
    
    /* Set the r and s values in the ECDSA_SIG structure */
    /* Note: This function transfers ownership of bn_r and bn_s to sig_obj */
    if (ECDSA_SIG_set0(sig_obj, bn_r, bn_s) != 1) {
        print_openssl_error("Error setting r and s in ECDSA_SIG");
        BN_free(bn_r);
        BN_free(bn_s);
        ECDSA_SIG_free(sig_obj);
        goto cleanup;
    }
    
    /* Convert the ECDSA_SIG object to DER format */
    unsigned char *der_sig = NULL;
    int der_sig_len = i2d_ECDSA_SIG(sig_obj, &der_sig);
    ECDSA_SIG_free(sig_obj);
    
    if (der_sig_len <= 0 || !der_sig) {
        print_openssl_error("Error encoding ECDSA signature to DER");
        goto cleanup;
    }
    
    /* Update with the data to be verified */
    if (EVP_DigestVerifyUpdate(md_ctx, data, data_len) != 1) {
        print_openssl_error("Error updating digest verify");
        OPENSSL_free(der_sig);
        goto cleanup;
    }
    
    /* Verify the signature */
    int verify_result = EVP_DigestVerifyFinal(md_ctx, der_sig, der_sig_len);
    OPENSSL_free(der_sig);
    
    if (verify_result == 1) {
        result = 1; /* Signature verified */
    } else if (verify_result == 0) {
        /* Try again with flipped components (sometimes signatures are (s,r) instead of (r,s)) */
        /* Create new signature with flipped components */
        sig_obj = ECDSA_SIG_new();
        if (!sig_obj) {
            print_openssl_error("Error creating ECDSA_SIG object for retry");
            goto cleanup;
        }
        
        /* Convert raw s and r values (flipped) to BIGNUMs */
        bn_r = BN_bin2bn(sig_s, sig_s_len, NULL);
        bn_s = BN_bin2bn(sig_r, sig_r_len, NULL);
        
        if (!bn_r || !bn_s) {
            print_openssl_error("Error converting flipped signature components to BIGNUMs");
            if (bn_r) BN_free(bn_r);
            if (bn_s) BN_free(bn_s);
            ECDSA_SIG_free(sig_obj);
            goto cleanup;
        }
        
        /* Set the r and s values in the ECDSA_SIG structure */
        if (ECDSA_SIG_set0(sig_obj, bn_r, bn_s) != 1) {
            print_openssl_error("Error setting flipped r and s in ECDSA_SIG");
            BN_free(bn_r);
            BN_free(bn_s);
            ECDSA_SIG_free(sig_obj);
            goto cleanup;
        }
        
        /* Convert the ECDSA_SIG object to DER format */
        der_sig = NULL;
        der_sig_len = i2d_ECDSA_SIG(sig_obj, &der_sig);
        ECDSA_SIG_free(sig_obj);
        
        if (der_sig_len <= 0 || !der_sig) {
            print_openssl_error("Error encoding flipped ECDSA signature to DER");
            goto cleanup;
        }
        
        /* Initialize a new context for verification with flipped components */
        EVP_MD_CTX_free(md_ctx);
        md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            print_openssl_error("Error creating new message digest context");
            OPENSSL_free(der_sig);
            goto cleanup;
        }
        
        /* Initialize the verification operation again */
        if (EVP_DigestVerifyInit(md_ctx, &pkey_ctx, EVP_sha256(), NULL, pkey) != 1) {
            print_openssl_error("Error initializing digest verify for retry");
            OPENSSL_free(der_sig);
            goto cleanup;
        }
        
        /* Update with the data to be verified */
        if (EVP_DigestVerifyUpdate(md_ctx, data, data_len) != 1) {
            print_openssl_error("Error updating digest verify for retry");
            OPENSSL_free(der_sig);
            goto cleanup;
        }
        
        /* Verify the flipped signature */
        verify_result = EVP_DigestVerifyFinal(md_ctx, der_sig, der_sig_len);
        OPENSSL_free(der_sig);
        
        if (verify_result == 1) {
            printf("Signature verified with flipped r and s components\n");
            result = 1; /* Signature verified with flipped components */
        } else if (verify_result == 0) {
            printf("Signature verification failed - invalid signature (tried both component orders)\n");
        } else {
            print_openssl_error("Error in signature verification retry");
        }
    } else {
        print_openssl_error("Error in signature verification");
    }
    
cleanup:
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    
    return result;
}