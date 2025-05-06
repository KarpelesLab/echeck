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

/* Create a CA stack from CA file */
STACK_OF(X509) *create_ca_stack(const char *ca_file) {
    BIO *ca_bio = NULL;
    X509 *ca_cert = NULL;
    STACK_OF(X509) *ca_stack = NULL;
    
    /* Create a new certificate stack for CA certificates */
    ca_stack = sk_X509_new_null();
    if (!ca_stack) {
        print_openssl_error("Error creating CA certificate stack");
        return NULL;
    }
    
    /* Load CA certificates from the CA file */
    ca_bio = BIO_new_file(ca_file, "r");
    if (!ca_bio) {
        print_openssl_error("Error opening CA file");
        sk_X509_pop_free(ca_stack, X509_free);
        return NULL;
    }
    
    /* Read all certificates from the CA file */
    while ((ca_cert = PEM_read_bio_X509(ca_bio, NULL, NULL, NULL)) != NULL) {
        /* Add the CA certificate to the stack */
        if (!sk_X509_push(ca_stack, ca_cert)) {
            print_openssl_error("Error adding CA certificate to stack");
            X509_free(ca_cert);
            BIO_free(ca_bio);
            sk_X509_pop_free(ca_stack, X509_free);
            return NULL;
        }
    }
    
    /* Check if any CA certificates were loaded */
    if (sk_X509_num(ca_stack) == 0) {
        fprintf(stderr, "No CA certificates loaded from %s\n", ca_file);
        BIO_free(ca_bio);
        sk_X509_pop_free(ca_stack, X509_free);
        return NULL;
    }
    
    /* Free the BIO */
    BIO_free(ca_bio);
    
    return ca_stack;
}

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
    
    /* For ECDSA, we need to set the signature format to r/s pair */
    if (EVP_PKEY_CTX_set_signature_md(pkey_ctx, EVP_sha256()) != 1) {
        print_openssl_error("Error setting signature digest");
        goto cleanup;
    }
    
    /* Convert r and s values to DER format (required by OpenSSL) */
    unsigned char *der_sig = NULL;
    size_t der_sig_len = 0;
    
    /* Allocate memory for DER signature (rough estimate) */
    der_sig_len = 2 + 2 + sig_r_len + 2 + sig_s_len;
    der_sig = OPENSSL_malloc(der_sig_len);
    if (!der_sig) {
        print_openssl_error("Error allocating memory for DER signature");
        goto cleanup;
    }
    
    /* Create DER signature manually */
    unsigned char *p = der_sig;
    
    /* Sequence tag and length */
    *p++ = 0x30; /* SEQUENCE */
    *p++ = (unsigned char)(2 + sig_r_len + 2 + sig_s_len); /* Length */
    
    /* Integer r */
    *p++ = 0x02; /* INTEGER */
    *p++ = (unsigned char)sig_r_len; /* Length */
    memcpy(p, sig_r, sig_r_len);
    p += sig_r_len;
    
    /* Integer s */
    *p++ = 0x02; /* INTEGER */
    *p++ = (unsigned char)sig_s_len; /* Length */
    memcpy(p, sig_s, sig_s_len);
    p += sig_s_len;
    
    /* Update the actual DER signature length */
    der_sig_len = p - der_sig;
    
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
        printf("Signature verification failed - invalid signature\n");
    } else {
        print_openssl_error("Error in signature verification");
    }
    
cleanup:
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    
    return result;
}