#ifndef CA_H
#define CA_H

#include "openssl_runtime.h"

/**
 * Get a stack of trusted CA certificates for SGX validation.
 * This function loads the built-in Intel SGX Root CA certificates automatically.
 *
 * @return A pointer to a stack of X509 certificates, or NULL on error.
 *         The caller is responsible for freeing the stack with sk_X509_pop_free().
 */
STACK_OF(X509) *get_trusted_ca_stack(void);

#endif /* CA_H */