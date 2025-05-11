#ifndef ECHECK_OPENSSL_H
#define ECHECK_OPENSSL_H

/**
 * @file echeck_openssl.h
 * @brief Centralized OpenSSL header inclusion for the echeck library
 *
 * This header provides a centralized way to include OpenSSL headers.
 * It handles both static linking and runtime linking modes.
 */

#ifdef OPENSSL_RUNTIME_LINK
/* In runtime mode, include runtime loading declarations */
#include "openssl_runtime.h"
#else
/* In static mode, include standard OpenSSL headers */
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#endif /* OPENSSL_RUNTIME_LINK */

#endif /* ECHECK_OPENSSL_H */