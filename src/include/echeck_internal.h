/**
 * @file echeck_internal.h
 * @brief Intel SGX Quote Verification Library - Internal API
 *
 * This file contains internal functions and structures used by the library.
 * Not intended for public use.
 */

#ifndef ECHECK_INTERNAL_H
#define ECHECK_INTERNAL_H

#include "echeck.h"
#include "echeck_quote.h"

/* Include centralized OpenSSL header */
#include "echeck_openssl.h"

/* Internal functions from ca.c */
STACK_OF(X509)* get_trusted_ca_certificates(void);

/* Internal functions from sgx_quote_parser.c */
int parse_ecdsa_signature(const unsigned char *sig_data, size_t sig_size, ECDSA_SIG **out_sig);
int extract_pck_certs(const sgx_quote_t *quote, STACK_OF(X509) **out_cert_stack);
int extract_qe_report(const sgx_quote_t *quote, unsigned char **out_report, size_t *out_report_size);
int extract_attestation_key(const sgx_quote_t *quote, EVP_PKEY **out_key);

/* Internal functions from sgx_quote_verify.c */
int verify_qe_report_signature(const unsigned char *report_data, size_t report_size,
                            const ECDSA_SIG *signature, EVP_PKEY *attestation_key);
int verify_pck_cert_chain(STACK_OF(X509) *cert_stack);
int verify_attestation_key(const sgx_quote_t *quote, EVP_PKEY *attestation_key, 
                        STACK_OF(X509) *cert_stack);

/* Internal functions from sgx_cert_verify.c */
int verify_certificate_chain(X509 *leaf_cert, STACK_OF(X509) *chain,
                            STACK_OF(X509) *trusted_certs,
                            echeck_verification_result_t *result);

/* Internal functions from sgx_utils.c */
void dump_buffer(const char *name, const unsigned char *data, size_t len);
int print_x509_name(X509_NAME *name);

/* Error handling utility (from common.c) */
void print_openssl_error(const char *msg);

/* Utility functions from common.c */
uint32_t extract_uint32(const uint8_t *data);
uint16_t extract_uint16(const uint8_t *data);
void print_hex(const char *label, const uint8_t *data, size_t len);
int is_verbose_mode(void);

#endif /* ECHECK_INTERNAL_H */