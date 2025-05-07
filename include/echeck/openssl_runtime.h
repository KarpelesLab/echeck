#ifndef ECHECK_OPENSSL_RUNTIME_H
#define ECHECK_OPENSSL_RUNTIME_H

/* 
 * This header provides two modes of operation:
 * 1. In normal mode (OPENSSL_RUNTIME_LINK not defined), it simply includes the required OpenSSL headers
 * 2. In runtime mode, it defines all OpenSSL types and function pointers for dynamic loading
 */

#ifdef OPENSSL_RUNTIME_LINK

#include <stdio.h>
#include <stddef.h>

/* Prevent OpenSSL headers from being included during runtime linking */
#define OPENSSL_INCLUDED
#define HEADER_BIO_H
#define HEADER_X509_H
#define HEADER_EVP_H
#define HEADER_ERR_H
#define HEADER_PEM_H
#define HEADER_ASN1_H
#define HEADER_ECDSA_H
#define HEADER_EC_H
#define HEADER_BN_H
#define HEADER_CRYPTO_H
#define HEADER_SAFESTACK_H
#define HEADER_STACK_H

/* OpenSSL constants needed for the code */
#define SHA256_DIGEST_LENGTH 32
#define NID_X9_62_prime256v1 415
#define EVP_PKEY_EC 408
#define PEM_R_NO_START_LINE 108
#define ERR_LIB_PEM 9
#define ERR_LIB_X509 11
#define ERR_LIB_SYS 1
#define EVP_MAX_MD_SIZE 64
#define NID_undef 0
#define X509_V_OK 0

/* X509 Verification Flags */
#define X509_V_FLAG_CRL_CHECK 0x4
#define X509_V_FLAG_CRL_CHECK_ALL 0x8
#define X509_V_FLAG_IGNORE_CRITICAL 0x10
#define X509_V_FLAG_X509_STRICT 0x20
#define X509_V_FLAG_ALLOW_PROXY_CERTS 0x40

/* X509 Error codes */
#define X509_R_CERT_ALREADY_IN_HASH_TABLE 101

/* OpenSSL error handling macros - Matching OpenSSL 3.0's definitions */
#define ERR_LIB_OFFSET           23L
#define ERR_LIB_MASK             0xFF
#define ERR_REASON_MASK          0X7FFFFF
#define ERR_SYSTEM_ERROR(e)      (((unsigned long)(e)) & ERR_SYSTEM_FLAG)
#define ERR_SYSTEM_FLAG          ((unsigned long)1 << 30)
#define ERR_SYSTEM_MASK          0x1FFFFFFFL

/* Define ERR_GET_LIB and ERR_GET_REASON to match OpenSSL's implementation */
#define ERR_GET_LIB(e) (ERR_SYSTEM_ERROR(e) ? ERR_LIB_SYS : (((e) >> ERR_LIB_OFFSET) & ERR_LIB_MASK))
#define ERR_GET_REASON(e) (ERR_SYSTEM_ERROR(e) ? ((e) & ERR_SYSTEM_MASK) : ((e) & ERR_REASON_MASK))

/* Forward declare all OpenSSL types */
struct bio_st;
struct x509_st;
struct evp_pkey_st;
struct evp_md_ctx_st;
struct evp_pkey_ctx_st;
struct evp_md_st;
struct asn1_object_st;
struct asn1_string_st;
struct x509_store_st;
struct x509_store_ctx_st;
struct x509_name_st;
struct engine_st;
struct bignum_st;
struct ec_key_st;
struct ecdsa_sig_st;
struct x509_extension_st;
struct stack_st;
struct stack_st_X509;
struct x509_verify_param_st;

/* Define OpenSSL types */
typedef struct bio_st BIO;
typedef struct x509_st X509;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct evp_md_st EVP_MD;
typedef struct asn1_object_st ASN1_OBJECT;
typedef struct asn1_string_st ASN1_STRING;
typedef struct asn1_string_st ASN1_OCTET_STRING; /* ASN1_OCTET_STRING is an ASN1_STRING */
typedef struct x509_store_st X509_STORE;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct x509_name_st X509_NAME;
typedef struct engine_st ENGINE;
typedef struct bignum_st BIGNUM;
typedef struct ec_key_st EC_KEY;
typedef struct ecdsa_sig_st ECDSA_SIG;
typedef struct x509_extension_st X509_EXTENSION;
typedef struct stack_st STACK;
typedef struct x509_verify_param_st X509_VERIFY_PARAM;

/* Define STACK_OF macro, which is used throughout OpenSSL */
#define STACK_OF(type) struct stack_st_##type

/* Password callback type definition */
typedef int (*pem_password_cb)(char *buf, int size, int rwflag, void *u);

/* BIO Functions */
extern BIO* (*BIO_new_file)(const char *filename, const char *mode);
extern BIO* (*BIO_new_mem_buf)(const void *buf, int len);
extern int (*BIO_free)(BIO *bio);
extern X509* (*PEM_read_bio_X509)(BIO *bp, X509 **x, pem_password_cb *cb, void *u);

/* X509 Functions */
extern void (*X509_free)(X509 *a);
extern X509_NAME* (*X509_get_subject_name)(const X509 *x);
extern char* (*X509_NAME_oneline)(const X509_NAME *a, char *buf, int size);
extern EVP_PKEY* (*X509_get_pubkey)(X509 *x);
extern int (*X509_get_ext_count)(const X509 *x);
extern X509_EXTENSION* (*X509_get_ext)(const X509 *x, int loc);
extern ASN1_OBJECT* (*X509_EXTENSION_get_object)(X509_EXTENSION *ex);
extern ASN1_OCTET_STRING* (*X509_EXTENSION_get_data)(X509_EXTENSION *ex);
extern int (*X509_verify_cert)(X509_STORE_CTX *ctx);
extern const char* (*X509_verify_cert_error_string)(long n);
extern X509_STORE* (*X509_STORE_new)(void);
extern void (*X509_STORE_free)(X509_STORE *v);
extern int (*X509_STORE_add_cert)(X509_STORE *ctx, X509 *x);
extern X509_STORE_CTX* (*X509_STORE_CTX_new)(void);
extern void (*X509_STORE_CTX_free)(X509_STORE_CTX *ctx);
extern int (*X509_STORE_CTX_init)(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x, STACK_OF(X509) *chain);
extern int (*X509_STORE_CTX_get_error)(X509_STORE_CTX *ctx);
extern X509_VERIFY_PARAM *(*X509_STORE_get0_param)(X509_STORE *ctx);
extern int (*X509_VERIFY_PARAM_set_flags)(X509_VERIFY_PARAM *param, unsigned long flags);

/* EVP Functions */
extern void (*EVP_PKEY_free)(EVP_PKEY *pkey);
extern int (*EVP_PKEY_get_base_id)(const EVP_PKEY *pkey);
extern EVP_PKEY* (*EVP_PKEY_new)(void);
extern int (*EVP_PKEY_set1_EC_KEY)(EVP_PKEY *pkey, EC_KEY *key);
extern EVP_PKEY_CTX* (*EVP_PKEY_CTX_new_id)(int id, ENGINE *e);
extern void (*EVP_PKEY_CTX_free)(EVP_PKEY_CTX *ctx);
extern int (*EVP_PKEY_paramgen_init)(EVP_PKEY_CTX *ctx);
extern int (*EVP_PKEY_CTX_set_ec_paramgen_curve_nid)(EVP_PKEY_CTX *ctx, int nid);
extern int (*EVP_PKEY_paramgen)(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
extern EVP_PKEY* (*EVP_PKEY_get1_EC_KEY)(EVP_PKEY *pkey);
extern const EVP_MD* (*EVP_sha256)(void);
extern EVP_MD_CTX* (*EVP_MD_CTX_new)(void);
extern void (*EVP_MD_CTX_free)(EVP_MD_CTX *ctx);
extern int (*EVP_DigestInit_ex)(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
extern int (*EVP_DigestUpdate)(EVP_MD_CTX *ctx, const void *d, size_t cnt);
extern int (*EVP_DigestFinal_ex)(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
extern int (*EVP_DigestVerifyInit)(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
extern int (*EVP_DigestVerifyUpdate)(EVP_MD_CTX *ctx, const void *d, size_t cnt);
extern int (*EVP_DigestVerifyFinal)(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen);

/* EC Functions */
extern EC_KEY* (*EC_KEY_new_by_curve_name)(int nid);
extern void (*EC_KEY_free)(EC_KEY* key);
extern int (*EC_KEY_set_public_key_affine_coordinates)(EC_KEY *key, BIGNUM *x, BIGNUM *y);
extern ECDSA_SIG* (*ECDSA_SIG_new)(void);
extern void (*ECDSA_SIG_free)(ECDSA_SIG *sig);
extern int (*ECDSA_SIG_set0)(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);
extern int (*ECDSA_do_verify)(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig, EC_KEY *eckey);
extern int (*i2d_ECDSA_SIG)(const ECDSA_SIG *sig, unsigned char **pp);
extern int (*i2d_PUBKEY)(EVP_PKEY *a, unsigned char **pp);

/* BIGNUM Functions */
extern BIGNUM* (*BN_bin2bn)(const unsigned char *s, int len, BIGNUM *ret);
extern void (*BN_free)(BIGNUM *a);

/* STACK Functions - in OpenSSL 3.0, the sk_X509_* functions are macros that redirect to OPENSSL_sk_* */
/* Define generic OPENSSL_sk type to replace STACK */
typedef struct openssl_stack_st OPENSSL_STACK;

/* Define the actual stack functions */
extern OPENSSL_STACK* (*OPENSSL_sk_new_null)(void);
extern void (*OPENSSL_sk_free)(OPENSSL_STACK *sk);
extern int (*OPENSSL_sk_push)(OPENSSL_STACK *sk, const void *ptr);
extern int (*OPENSSL_sk_num)(const OPENSSL_STACK *sk);
extern void* (*OPENSSL_sk_value)(const OPENSSL_STACK *sk, int i);
extern void (*OPENSSL_sk_pop_free)(OPENSSL_STACK *sk, void (*func)(void *));

/* Define our own macros to map sk_X509_* to OPENSSL_sk_* */
#define sk_X509_new_null() (STACK_OF(X509) *)OPENSSL_sk_new_null()
#define sk_X509_free(st) OPENSSL_sk_free((OPENSSL_STACK *)(st))
#define sk_X509_push(st, val) OPENSSL_sk_push((OPENSSL_STACK *)(st), (const void *)(val))
#define sk_X509_num(st) OPENSSL_sk_num((const OPENSSL_STACK *)(st))
#define sk_X509_value(st, i) (X509 *)OPENSSL_sk_value((const OPENSSL_STACK *)(st), (i))
#define sk_X509_pop_free(st, free_func) OPENSSL_sk_pop_free((OPENSSL_STACK *)(st), (void (*)(void *))(free_func))

/* ASN1 Functions */
extern const unsigned char* (*ASN1_STRING_get0_data)(const ASN1_STRING *x);
extern int (*ASN1_STRING_length)(const ASN1_STRING *x);

/* Object Management */
extern int (*OBJ_create)(const char *oid, const char *sn, const char *ln);
extern int (*OBJ_obj2nid)(const ASN1_OBJECT *o);

/* Error Handling */
extern void (*ERR_print_errors_fp)(FILE *fp);
extern unsigned long (*ERR_peek_last_error)(void);
extern void (*ERR_clear_error)(void);
extern int (*ERR_GET_LIB)(unsigned long e);
extern int (*ERR_GET_REASON)(unsigned long e);

/* SHA Functions */
extern unsigned char* (*SHA256)(const unsigned char *d, size_t n, unsigned char *md);

/* Memory Management */
extern void (*CRYPTO_free)(void *ptr, const char *file, int line);
/* Define our own OPENSSL_free macro to redirect to CRYPTO_free with the proper file and line information */
#define OPENSSL_free(addr) CRYPTO_free(addr, __FILE__, __LINE__)

/* OpenSSL initialization and cleanup */
extern void (*OpenSSL_add_all_algorithms)(void);
extern void (*ERR_load_crypto_strings)(void);
extern void (*EVP_cleanup)(void);
extern void (*ERR_free_strings)(void);
extern void (*OPENSSL_cleanup)(void);  /* Modern equivalent of EVP_cleanup() + ERR_free_strings() */

/* Load OpenSSL dynamically at runtime */
int init_openssl_runtime(void);

#else /* !OPENSSL_RUNTIME_LINK */

/* When not using runtime linking, include the standard OpenSSL headers */
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/crypto.h>

/* In static linking mode, we just provide a stub function that always succeeds */
static inline int init_openssl_runtime(void) {
    return 1;
}

#endif /* OPENSSL_RUNTIME_LINK */

#endif /* ECHECK_OPENSSL_RUNTIME_H */