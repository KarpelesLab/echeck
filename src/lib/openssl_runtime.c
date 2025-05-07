#include <stdio.h>
#include <string.h>

#ifdef OPENSSL_RUNTIME_LINK
#include <dlfcn.h>
#include "echeck/openssl_runtime.h"

/* Define all OpenSSL function pointers */
BIO* (*BIO_new_file)(const char *filename, const char *mode) = NULL;
BIO* (*BIO_new_mem_buf)(const void *buf, int len) = NULL;
int (*BIO_free)(BIO *bio) = NULL;
X509* (*PEM_read_bio_X509)(BIO *bp, X509 **x, pem_password_cb *cb, void *u) = NULL;

void (*X509_free)(X509 *a) = NULL;
X509_NAME* (*X509_get_subject_name)(const X509 *x) = NULL;
char* (*X509_NAME_oneline)(const X509_NAME *a, char *buf, int size) = NULL;
EVP_PKEY* (*X509_get_pubkey)(X509 *x) = NULL;
int (*X509_get_ext_count)(const X509 *x) = NULL;
X509_EXTENSION* (*X509_get_ext)(const X509 *x, int loc) = NULL;
ASN1_OBJECT* (*X509_EXTENSION_get_object)(X509_EXTENSION *ex) = NULL;
ASN1_OCTET_STRING* (*X509_EXTENSION_get_data)(X509_EXTENSION *ex) = NULL;
int (*X509_verify_cert)(X509_STORE_CTX *ctx) = NULL;
const char* (*X509_verify_cert_error_string)(long n) = NULL;
X509_STORE* (*X509_STORE_new)(void) = NULL;
void (*X509_STORE_free)(X509_STORE *v) = NULL;
int (*X509_STORE_add_cert)(X509_STORE *ctx, X509 *x) = NULL;
X509_STORE_CTX* (*X509_STORE_CTX_new)(void) = NULL;
void (*X509_STORE_CTX_free)(X509_STORE_CTX *ctx) = NULL;
int (*X509_STORE_CTX_init)(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x, STACK_OF(X509) *chain) = NULL;
int (*X509_STORE_CTX_get_error)(X509_STORE_CTX *ctx) = NULL;
X509_VERIFY_PARAM *(*X509_STORE_get0_param)(X509_STORE *ctx) = NULL;
int (*X509_VERIFY_PARAM_set_flags)(X509_VERIFY_PARAM *param, unsigned long flags) = NULL;

void (*EVP_PKEY_free)(EVP_PKEY *pkey) = NULL;
int (*EVP_PKEY_get_base_id)(const EVP_PKEY *pkey) = NULL;
EVP_PKEY* (*EVP_PKEY_new)(void) = NULL;
int (*EVP_PKEY_set1_EC_KEY)(EVP_PKEY *pkey, EC_KEY *key) = NULL;
EVP_PKEY_CTX* (*EVP_PKEY_CTX_new_id)(int id, ENGINE *e) = NULL;
void (*EVP_PKEY_CTX_free)(EVP_PKEY_CTX *ctx) = NULL;
int (*EVP_PKEY_paramgen_init)(EVP_PKEY_CTX *ctx) = NULL;
int (*EVP_PKEY_CTX_set_ec_paramgen_curve_nid)(EVP_PKEY_CTX *ctx, int nid) = NULL;
int (*EVP_PKEY_paramgen)(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey) = NULL;
EVP_PKEY* (*EVP_PKEY_get1_EC_KEY)(EVP_PKEY *pkey) = NULL;
const EVP_MD* (*EVP_sha256)(void) = NULL;
EVP_MD_CTX* (*EVP_MD_CTX_new)(void) = NULL;
void (*EVP_MD_CTX_free)(EVP_MD_CTX *ctx) = NULL;
int (*EVP_DigestInit_ex)(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl) = NULL;
int (*EVP_DigestUpdate)(EVP_MD_CTX *ctx, const void *d, size_t cnt) = NULL;
int (*EVP_DigestFinal_ex)(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s) = NULL;
int (*EVP_DigestVerifyInit)(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey) = NULL;
int (*EVP_DigestVerifyUpdate)(EVP_MD_CTX *ctx, const void *d, size_t cnt) = NULL;
int (*EVP_DigestVerifyFinal)(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen) = NULL;

EC_KEY* (*EC_KEY_new_by_curve_name)(int nid) = NULL;
void (*EC_KEY_free)(EC_KEY* key) = NULL;
int (*EC_KEY_set_public_key_affine_coordinates)(EC_KEY *key, BIGNUM *x, BIGNUM *y) = NULL;
ECDSA_SIG* (*ECDSA_SIG_new)(void) = NULL;
void (*ECDSA_SIG_free)(ECDSA_SIG *sig) = NULL;
int (*ECDSA_SIG_set0)(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s) = NULL;
int (*ECDSA_do_verify)(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig, EC_KEY *eckey) = NULL;
int (*i2d_ECDSA_SIG)(const ECDSA_SIG *sig, unsigned char **pp) = NULL;
int (*i2d_PUBKEY)(EVP_PKEY *a, unsigned char **pp) = NULL;

BIGNUM* (*BN_bin2bn)(const unsigned char *s, int len, BIGNUM *ret) = NULL;
void (*BN_free)(BIGNUM *a) = NULL;

/* OPENSSL_sk_* functions (OpenSSL 3.0 replaces sk_ with OPENSSL_sk_) */
OPENSSL_STACK* (*OPENSSL_sk_new_null)(void) = NULL;
void (*OPENSSL_sk_free)(OPENSSL_STACK *sk) = NULL;
int (*OPENSSL_sk_push)(OPENSSL_STACK *sk, const void *ptr) = NULL;
int (*OPENSSL_sk_num)(const OPENSSL_STACK *sk) = NULL;
void* (*OPENSSL_sk_value)(const OPENSSL_STACK *sk, int i) = NULL;
void (*OPENSSL_sk_pop_free)(OPENSSL_STACK *sk, void (*func)(void *)) = NULL;

const unsigned char* (*ASN1_STRING_get0_data)(const ASN1_STRING *x) = NULL;
int (*ASN1_STRING_length)(const ASN1_STRING *x) = NULL;

int (*OBJ_create)(const char *oid, const char *sn, const char *ln) = NULL;
int (*OBJ_obj2nid)(const ASN1_OBJECT *o) = NULL;

void (*ERR_print_errors_fp)(FILE *fp) = NULL;
unsigned long (*ERR_peek_last_error)(void) = NULL;
void (*ERR_clear_error)(void) = NULL;

/* SHA Functions */
unsigned char* (*SHA256)(const unsigned char *d, size_t n, unsigned char *md) = NULL;

/* Memory management */
void (*CRYPTO_free)(void *ptr, const char *file, int line) = NULL;

/* OpenSSL initialization and cleanup */
/* Modern OpenSSL (3.0+) doesn't need these functions */
void (*OPENSSL_cleanup)(void) = NULL; /* Modern equivalent of the deprecated functions */

/* Library handles for libssl and libcrypto */
static void *libssl_handle = NULL;
static void *libcrypto_handle = NULL;

#define LOAD_SYMBOL(handle, symbol) \
    do { \
        *(void **)(&symbol) = dlsym(handle, #symbol); \
        if (!symbol) { \
            fprintf(stderr, "Error loading symbol %s: %s\n", #symbol, dlerror()); \
            return 0; \
        } \
    } while(0)

/* Version of LOAD_SYMBOL that does not fail if the symbol is not found */
#define LOAD_SYMBOL_OPTIONAL(handle, symbol) \
    do { \
        *(void **)(&symbol) = dlsym(handle, #symbol); \
        if (!symbol) { \
            fprintf(stderr, "Warning: Optional symbol %s not found, functionality may be limited\n", #symbol); \
        } \
    } while(0)

/* Library name configuration based on platform */
#if defined(__APPLE__)
    #define LIBSSL_NAME "libssl.dylib"
    #define LIBCRYPTO_NAME "libcrypto.dylib"
#elif defined(_WIN32) || defined(_WIN64)
    #define LIBSSL_NAME "libssl.dll"
    #define LIBCRYPTO_NAME "libcrypto.dll"
#else /* Linux, Unix, etc. */
    #define LIBSSL_NAME "libssl.so.3"
    #define LIBSSL_NAME_FALLBACK "libssl.so.1.1"
    #define LIBCRYPTO_NAME "libcrypto.so.3"
    #define LIBCRYPTO_NAME_FALLBACK "libcrypto.so.1.1"
#endif

int init_openssl_runtime(void) {
    /* Return immediately if libraries are already loaded */
    if (libssl_handle && libcrypto_handle) {
        return 1;
    }

    /* Clear any previous errors */
    dlerror();

    /* Try to load libcrypto */
    libcrypto_handle = dlopen(LIBCRYPTO_NAME, RTLD_LAZY);
    if (!libcrypto_handle) {
#if defined(LIBCRYPTO_NAME_FALLBACK)
        /* Try fallback name */
        libcrypto_handle = dlopen(LIBCRYPTO_NAME_FALLBACK, RTLD_LAZY);
        if (!libcrypto_handle) {
            fprintf(stderr, "Failed to load libcrypto: %s\n", dlerror());
            return 0;
        }
#else
        fprintf(stderr, "Failed to load libcrypto: %s\n", dlerror());
        return 0;
#endif
    }

    /* Try to load libssl */
    libssl_handle = dlopen(LIBSSL_NAME, RTLD_LAZY);
    if (!libssl_handle) {
#if defined(LIBSSL_NAME_FALLBACK)
        /* Try fallback name */
        libssl_handle = dlopen(LIBSSL_NAME_FALLBACK, RTLD_LAZY);
        if (!libssl_handle) {
            fprintf(stderr, "Failed to load libssl: %s\n", dlerror());
            dlclose(libcrypto_handle);
            libcrypto_handle = NULL;
            return 0;
        }
#else
        fprintf(stderr, "Failed to load libssl: %s\n", dlerror());
        dlclose(libcrypto_handle);
        libcrypto_handle = NULL;
        return 0;
#endif
    }

    /* Load all required symbols from libcrypto */
    LOAD_SYMBOL(libcrypto_handle, BIO_new_file);
    LOAD_SYMBOL(libcrypto_handle, BIO_new_mem_buf);
    LOAD_SYMBOL(libcrypto_handle, BIO_free);
    LOAD_SYMBOL(libcrypto_handle, PEM_read_bio_X509);
    
    LOAD_SYMBOL(libcrypto_handle, X509_free);
    LOAD_SYMBOL(libcrypto_handle, X509_get_subject_name);
    LOAD_SYMBOL(libcrypto_handle, X509_NAME_oneline);
    LOAD_SYMBOL(libcrypto_handle, X509_get_pubkey);
    LOAD_SYMBOL(libcrypto_handle, X509_get_ext_count);
    LOAD_SYMBOL(libcrypto_handle, X509_get_ext);
    LOAD_SYMBOL(libcrypto_handle, X509_EXTENSION_get_object);
    LOAD_SYMBOL(libcrypto_handle, X509_EXTENSION_get_data);
    LOAD_SYMBOL(libcrypto_handle, X509_verify_cert);
    LOAD_SYMBOL(libcrypto_handle, X509_verify_cert_error_string);
    LOAD_SYMBOL(libcrypto_handle, X509_STORE_new);
    LOAD_SYMBOL(libcrypto_handle, X509_STORE_free);
    LOAD_SYMBOL(libcrypto_handle, X509_STORE_add_cert);
    LOAD_SYMBOL(libcrypto_handle, X509_STORE_CTX_new);
    LOAD_SYMBOL(libcrypto_handle, X509_STORE_CTX_free);
    LOAD_SYMBOL(libcrypto_handle, X509_STORE_CTX_init);
    LOAD_SYMBOL(libcrypto_handle, X509_STORE_CTX_get_error);
    LOAD_SYMBOL(libcrypto_handle, X509_STORE_get0_param);
    LOAD_SYMBOL(libcrypto_handle, X509_VERIFY_PARAM_set_flags);
    
    LOAD_SYMBOL(libcrypto_handle, EVP_PKEY_free);
    LOAD_SYMBOL(libcrypto_handle, EVP_PKEY_get_base_id);
    LOAD_SYMBOL(libcrypto_handle, EVP_PKEY_new);
    LOAD_SYMBOL(libcrypto_handle, EVP_PKEY_set1_EC_KEY);
    LOAD_SYMBOL(libcrypto_handle, EVP_PKEY_CTX_new_id);
    LOAD_SYMBOL(libcrypto_handle, EVP_PKEY_CTX_free);
    LOAD_SYMBOL(libcrypto_handle, EVP_PKEY_paramgen_init);
    LOAD_SYMBOL(libcrypto_handle, EVP_PKEY_CTX_set_ec_paramgen_curve_nid);
    LOAD_SYMBOL(libcrypto_handle, EVP_PKEY_paramgen);
    LOAD_SYMBOL(libcrypto_handle, EVP_PKEY_get1_EC_KEY);
    LOAD_SYMBOL(libcrypto_handle, EVP_sha256);
    LOAD_SYMBOL(libcrypto_handle, EVP_MD_CTX_new);
    LOAD_SYMBOL(libcrypto_handle, EVP_MD_CTX_free);
    LOAD_SYMBOL(libcrypto_handle, EVP_DigestInit_ex);
    LOAD_SYMBOL(libcrypto_handle, EVP_DigestUpdate);
    LOAD_SYMBOL(libcrypto_handle, EVP_DigestFinal_ex);
    LOAD_SYMBOL(libcrypto_handle, EVP_DigestVerifyInit);
    LOAD_SYMBOL(libcrypto_handle, EVP_DigestVerifyUpdate);
    LOAD_SYMBOL(libcrypto_handle, EVP_DigestVerifyFinal);
    
    LOAD_SYMBOL(libcrypto_handle, EC_KEY_new_by_curve_name);
    LOAD_SYMBOL(libcrypto_handle, EC_KEY_free);
    LOAD_SYMBOL(libcrypto_handle, EC_KEY_set_public_key_affine_coordinates);
    LOAD_SYMBOL(libcrypto_handle, ECDSA_SIG_new);
    LOAD_SYMBOL(libcrypto_handle, ECDSA_SIG_free);
    LOAD_SYMBOL(libcrypto_handle, ECDSA_SIG_set0);
    LOAD_SYMBOL(libcrypto_handle, ECDSA_do_verify);
    LOAD_SYMBOL(libcrypto_handle, i2d_ECDSA_SIG);
    LOAD_SYMBOL(libcrypto_handle, i2d_PUBKEY);
    
    LOAD_SYMBOL(libcrypto_handle, BN_bin2bn);
    LOAD_SYMBOL(libcrypto_handle, BN_free);
    
    /* Load OPENSSL_sk_* functions (OpenSSL 3.0 compatible) */
    LOAD_SYMBOL(libcrypto_handle, OPENSSL_sk_new_null);
    LOAD_SYMBOL(libcrypto_handle, OPENSSL_sk_free);
    LOAD_SYMBOL(libcrypto_handle, OPENSSL_sk_push);
    LOAD_SYMBOL(libcrypto_handle, OPENSSL_sk_num);
    LOAD_SYMBOL(libcrypto_handle, OPENSSL_sk_value);
    LOAD_SYMBOL(libcrypto_handle, OPENSSL_sk_pop_free);
    
    /* Successfully loaded stack functions */
    
    LOAD_SYMBOL(libcrypto_handle, ASN1_STRING_get0_data);
    LOAD_SYMBOL(libcrypto_handle, ASN1_STRING_length);
    
    /* Make sure we load Object identifier functions */
    LOAD_SYMBOL(libcrypto_handle, OBJ_create);
    LOAD_SYMBOL(libcrypto_handle, OBJ_obj2nid);
    
    /* Successfully loaded object identifier functions */
    
    LOAD_SYMBOL(libcrypto_handle, ERR_print_errors_fp);
    LOAD_SYMBOL(libcrypto_handle, ERR_peek_last_error);
    LOAD_SYMBOL(libcrypto_handle, ERR_clear_error);
    
    /* Load SHA functions */
    LOAD_SYMBOL(libcrypto_handle, SHA256);
    
    /* Load memory management functions */
    LOAD_SYMBOL(libcrypto_handle, CRYPTO_free);
    
    /* ERR_GET_LIB and ERR_GET_REASON are macros, not functions to load 
     * We've defined our own macros above that operate directly on error codes */
    
    /* In OpenSSL 3.0+, the initialization/cleanup functions are deprecated 
     * Only OPENSSL_cleanup might exist, though it's typically not needed 
     * as cleanup happens automatically */
    LOAD_SYMBOL_OPTIONAL(libcrypto_handle, OPENSSL_cleanup);
    
    /* Successfully loaded all required symbols */
    fprintf(stderr, "Successfully loaded OpenSSL libraries at runtime\n");
    
    /* Successfully loaded all key OpenSSL functions */
    
    return 1;
}

#endif /* OPENSSL_RUNTIME_LINK */