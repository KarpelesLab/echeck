#ifndef CERT_UTILS_H
#define CERT_UTILS_H

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>

/* Load a certificate from a PEM file */
X509 *load_certificate(const char *file_path);

/* Extract a public key hash from a certificate */
int compute_pubkey_hash(X509 *cert, unsigned char *hash, unsigned int *hash_len);

/* This line intentionally removed */

/* Verify an ECDSA signature */
int verify_ecdsa_signature(const unsigned char *data, size_t data_len, 
                          const unsigned char *sig_r, size_t sig_r_len,
                          const unsigned char *sig_s, size_t sig_s_len,
                          EVP_PKEY *pkey);

#endif /* CERT_UTILS_H */