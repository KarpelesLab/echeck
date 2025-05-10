#ifndef CA_H
#define CA_H

/* Include OpenSSL headers based on the build mode */
#ifdef OPENSSL_RUNTIME_LINK
#include "openssl_runtime.h"
#else
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#endif

/**
 * Get a stack of trusted CA certificates for SGX validation.
 * This function loads the built-in Intel SGX Root CA certificates automatically.
 *
 * @return A pointer to a stack of X509 certificates, or NULL on error.
 *         The caller is responsible for freeing the stack with sk_X509_pop_free().
 */
STACK_OF(X509) *get_trusted_ca_stack(void);

#endif /* CA_H */