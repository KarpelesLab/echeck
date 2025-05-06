#ifndef SGX_UTILS_H
#define SGX_UTILS_H

#include "sgx_types.h"
#include <openssl/evp.h>

/* We already have compute_quote_hash in sgx_quote_parser.h */

/* Extract the attestation key from the quote signature data */
EVP_PKEY *extract_attestation_key(const sgx_quote_t *quote);

#endif /* SGX_UTILS_H */