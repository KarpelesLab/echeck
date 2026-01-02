#include <stdio.h>
#include <string.h>

#ifdef OPENSSL_RUNTIME_LINK
#include "echeck_internal.h" /* For is_verbose_mode() */

/* Include platform-specific headers for dynamic library loading */
#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include "openssl_runtime.h"

/* Define all OpenSSL function pointers */
BIO* (*BIO_new_file)(const char *filename, const char *mode) = NULL;
BIO* (*BIO_new_mem_buf)(const void *buf, int len) = NULL;
int (*BIO_free)(BIO *bio) = NULL;
X509* (*PEM_read_bio_X509)(BIO *bp, X509 **x, pem_password_cb *cb, void *u) = NULL;

void (*X509_free)(X509 *a) = NULL;
#if defined(_WIN32) || defined(_WIN64)
void* (*X509_get_subject_name)(const X509 *x) = NULL; /* Returns X509_NAME* */
char* (*X509_NAME_oneline)(void *a, char *buf, int size) = NULL; /* First arg is X509_NAME* */
#else
X509_NAME* (*X509_get_subject_name)(const X509 *x) = NULL;
char* (*X509_NAME_oneline)(const X509_NAME *a, char *buf, int size) = NULL;
#endif
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
int (*EC_KEY_check_key)(const EC_KEY *key) = NULL;
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

/* Constant-time comparison */
int (*CRYPTO_memcmp)(const void *a, const void *b, size_t len) = NULL;

/* Memory management */
void (*CRYPTO_free)(void *ptr, const char *file, int line) = NULL;

/* OpenSSL initialization and cleanup */
/* Modern OpenSSL (3.0+) doesn't need these functions */
void (*OPENSSL_cleanup)(void) = NULL; /* Modern equivalent of the deprecated functions */

/* Library handles for libssl and libcrypto */
#if defined(_WIN32) || defined(_WIN64)
static HMODULE libssl_handle = NULL;
static HMODULE libcrypto_handle = NULL;
#else
static void *libssl_handle = NULL;
static void *libcrypto_handle = NULL;
#endif

#if defined(_WIN32) || defined(_WIN64)
/* Windows implementation using GetProcAddress */
#define LOAD_SYMBOL(handle, symbol) \
    do { \
        *(void **)(&symbol) = (void *)GetProcAddress(handle, #symbol); \
        if (!symbol) { \
            fprintf(stderr, "Error loading symbol %s: error code %lu\n", #symbol, GetLastError()); \
            return 0; \
        } \
    } while(0)

/* All symbols are required */
#else
/* Unix implementation using dlsym */
#define LOAD_SYMBOL(handle, symbol) \
    do { \
        *(void **)(&symbol) = dlsym(handle, #symbol); \
        if (!symbol) { \
            fprintf(stderr, "Error loading symbol %s: %s\n", #symbol, dlerror()); \
            return 0; \
        } \
    } while(0)

/* All symbols are required */
#endif

/* Library name configuration based on platform */
#if defined(__APPLE__)
    /* macOS library names with version */
    #define LIBSSL_NAME "libssl.3.dylib"
    #define LIBCRYPTO_NAME "libcrypto.3.dylib"
#elif defined(_WIN32) || defined(_WIN64)
    /* On Windows, try both generic and architecture-specific libraries */
    #if defined(_WIN64)
        #if defined(_M_ARM64) || defined(__aarch64__)
            /* ARM64 architecture */
            #define LIBSSL_NAME "libssl-3.dll"
            #define LIBCRYPTO_NAME "libcrypto-3.dll"
        #else
            /* x64 architecture (default for 64-bit) */
            #define LIBSSL_NAME "libssl-3.dll"
            #define LIBCRYPTO_NAME "libcrypto-3.dll"
        #endif
    #else
        /* 32-bit x86 architecture */
        #define LIBSSL_NAME "libssl-3.dll"
        #define LIBCRYPTO_NAME "libcrypto-3.dll"
    #endif
#else /* Linux, Unix, etc. */
    #define LIBSSL_NAME "libssl.so.3"
    #define LIBCRYPTO_NAME "libcrypto.so.3"
#endif

/* Forward declaration for symbol loading */
static int load_openssl_symbols(const char *loaded_crypto_path, const char *loaded_ssl_path);

/* Load OpenSSL from specific library paths */
int init_openssl_runtime_with_paths(const char *libcrypto_path, const char *libssl_path) {
    /* Return immediately if libraries are already loaded */
    if (libssl_handle && libcrypto_handle) {
        return 1;
    }

    if (!libcrypto_path || !libssl_path) {
        fprintf(stderr, "Error: NULL library path provided\n");
        return 0;
    }

#if defined(_WIN32) || defined(_WIN64)
    libcrypto_handle = LoadLibraryA(libcrypto_path);
    if (!libcrypto_handle) {
        fprintf(stderr, "Failed to load libcrypto from %s: error code %lu\n",
                libcrypto_path, GetLastError());
        return 0;
    }

    libssl_handle = LoadLibraryA(libssl_path);
    if (!libssl_handle) {
        fprintf(stderr, "Failed to load libssl from %s: error code %lu\n",
                libssl_path, GetLastError());
        FreeLibrary(libcrypto_handle);
        libcrypto_handle = NULL;
        return 0;
    }
#else
    dlerror(); /* Clear any previous errors */

    libcrypto_handle = dlopen(libcrypto_path, RTLD_NOW | RTLD_GLOBAL);
    if (!libcrypto_handle) {
        fprintf(stderr, "Failed to load libcrypto from %s: %s\n",
                libcrypto_path, dlerror());
        return 0;
    }

    libssl_handle = dlopen(libssl_path, RTLD_NOW | RTLD_GLOBAL);
    if (!libssl_handle) {
        fprintf(stderr, "Failed to load libssl from %s: %s\n",
                libssl_path, dlerror());
        dlclose(libcrypto_handle);
        libcrypto_handle = NULL;
        return 0;
    }
#endif

    return load_openssl_symbols(libcrypto_path, libssl_path);
}

int init_openssl_runtime(void) {
    /* Return immediately if libraries are already loaded */
    if (libssl_handle && libcrypto_handle) {
        return 1;
    }

#if defined(_WIN32) || defined(_WIN64)
    /* Windows implementation using LoadLibrary
     *
     * SECURITY: Search absolute paths FIRST to prevent DLL hijacking.
     * On Windows, the default search order includes the current working
     * directory, which could be controlled by an attacker. By trying
     * absolute paths to known installation directories first, we reduce
     * the risk of loading a malicious DLL. */

    /* Define platform-specific search paths for Windows - absolute paths first */
    const char* crypto_paths[] = {
#if defined(_M_ARM64) || defined(__aarch64__)
        /* ARM64-specific absolute paths first */
        "C:\\Program Files\\OpenSSL-Win64\\bin\\libcrypto-3-arm64.dll",
        "C:\\Program Files\\OpenSSL\\bin\\libcrypto-3-arm64.dll",
        "C:\\Program Files\\OpenSSL-ARM64\\bin\\libcrypto-3-arm64.dll",
#else
        /* x64 absolute paths first */
        "C:\\Program Files\\OpenSSL-Win64\\bin\\libcrypto-3-x64.dll",
        "C:\\Program Files\\OpenSSL\\bin\\libcrypto-3-x64.dll",
#endif
        "C:\\OpenSSL-Win64\\bin\\libcrypto-3-x64.dll",
        "C:\\OpenSSL\\bin\\libcrypto-3-x64.dll",
        /* Default name as fallback (may search current directory - less secure) */
        LIBCRYPTO_NAME,
        "libcrypto-3.dll",
        NULL
    };

    const char* ssl_paths[] = {
#if defined(_M_ARM64) || defined(__aarch64__)
        /* ARM64-specific absolute paths first */
        "C:\\Program Files\\OpenSSL-Win64\\bin\\libssl-3-arm64.dll",
        "C:\\Program Files\\OpenSSL\\bin\\libssl-3-arm64.dll",
        "C:\\Program Files\\OpenSSL-ARM64\\bin\\libssl-3-arm64.dll",
#else
        /* x64 absolute paths first */
        "C:\\Program Files\\OpenSSL-Win64\\bin\\libssl-3-x64.dll",
        "C:\\Program Files\\OpenSSL\\bin\\libssl-3-x64.dll",
#endif
        "C:\\OpenSSL-Win64\\bin\\libssl-3-x64.dll",
        "C:\\OpenSSL\\bin\\libssl-3-x64.dll",
        /* Default name as fallback (may search current directory - less secure) */
        LIBSSL_NAME,
        "libssl-3.dll",
        NULL
    };

    /* Try to load libcrypto from various paths */
    const char *loaded_crypto_path = NULL;
    for (int i = 0; crypto_paths[i] != NULL; i++) {
        libcrypto_handle = LoadLibraryA(crypto_paths[i]);
        if (libcrypto_handle) {
            loaded_crypto_path = crypto_paths[i];
            break;
        }
    }

    if (!libcrypto_handle) {
        fprintf(stderr, "Failed to load libcrypto from any known path: error code %lu\n", GetLastError());
        return 0;
    }

    /* Try to load libssl from various paths */
    const char *loaded_ssl_path = NULL;
    for (int i = 0; ssl_paths[i] != NULL; i++) {
        libssl_handle = LoadLibraryA(ssl_paths[i]);
        if (libssl_handle) {
            loaded_ssl_path = ssl_paths[i];
            break;
        }
    }

    if (!libssl_handle) {
        fprintf(stderr, "Failed to load libssl from any known path: error code %lu\n", GetLastError());
        FreeLibrary(libcrypto_handle);
        libcrypto_handle = NULL;
        return 0;
    }
    
#else
    /* Unix implementation using dlopen */
    
    /* Clear any previous errors */
    dlerror();

    /* Define platform-specific search paths */
    const char* crypto_paths[] = {
        LIBCRYPTO_NAME,  /* Try the basic name first */
#if defined(__APPLE__)
        "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib",
        "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib",
        "/opt/homebrew/lib/libcrypto.3.dylib",
        "/usr/local/lib/libcrypto.3.dylib",
#elif defined(__linux__)
        "/usr/lib/libcrypto.so.3",
        "/usr/lib64/libcrypto.so.3",
        "/usr/local/lib/libcrypto.so.3",
        "/lib/libcrypto.so.3",
        "/lib64/libcrypto.so.3",
#endif
        NULL
    };

    const char* ssl_paths[] = {
        LIBSSL_NAME,  /* Try the basic name first */
#if defined(__APPLE__)
        "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib",
        "/usr/local/opt/openssl@3/lib/libssl.3.dylib",
        "/opt/homebrew/lib/libssl.3.dylib",
        "/usr/local/lib/libssl.3.dylib",
#elif defined(__linux__)
        "/usr/lib/libssl.so.3",
        "/usr/lib64/libssl.so.3",
        "/usr/local/lib/libssl.so.3",
        "/lib/libssl.so.3",
        "/lib64/libssl.so.3",
#endif
        NULL
    };

    /* Try to load libcrypto from various paths */
    const char *loaded_crypto_path = NULL;
    for (int i = 0; crypto_paths[i] != NULL; i++) {
        /* Clear any previous errors */
        dlerror();

        libcrypto_handle = dlopen(crypto_paths[i], RTLD_LAZY);
        if (libcrypto_handle) {
            loaded_crypto_path = crypto_paths[i];
            break;
        }
    }

    if (!libcrypto_handle) {
        fprintf(stderr, "Failed to load libcrypto from any known path\n");
        return 0;
    }

    /* Try to load libssl from various paths */
    const char *loaded_ssl_path = NULL;
    for (int i = 0; ssl_paths[i] != NULL; i++) {
        /* Clear any previous errors */
        dlerror();

        libssl_handle = dlopen(ssl_paths[i], RTLD_LAZY);
        if (libssl_handle) {
            loaded_ssl_path = ssl_paths[i];
            break;
        }
    }

    if (!libssl_handle) {
        fprintf(stderr, "Failed to load libssl from any known path\n");
        dlclose(libcrypto_handle);
        libcrypto_handle = NULL;
        return 0;
    }
#endif

    return load_openssl_symbols(loaded_crypto_path, loaded_ssl_path);
}

/* Helper function to load all OpenSSL symbols after libraries are loaded */
static int load_openssl_symbols(const char *loaded_crypto_path, const char *loaded_ssl_path) {
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
    LOAD_SYMBOL(libcrypto_handle, EC_KEY_check_key);
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

    LOAD_SYMBOL(libcrypto_handle, ASN1_STRING_get0_data);
    LOAD_SYMBOL(libcrypto_handle, ASN1_STRING_length);

    /* Make sure we load Object identifier functions */
    LOAD_SYMBOL(libcrypto_handle, OBJ_create);
    LOAD_SYMBOL(libcrypto_handle, OBJ_obj2nid);

    LOAD_SYMBOL(libcrypto_handle, ERR_print_errors_fp);
    LOAD_SYMBOL(libcrypto_handle, ERR_peek_last_error);
    LOAD_SYMBOL(libcrypto_handle, ERR_clear_error);

    /* Load SHA functions */
    LOAD_SYMBOL(libcrypto_handle, SHA256);

    /* Load constant-time comparison */
    LOAD_SYMBOL(libcrypto_handle, CRYPTO_memcmp);

    /* Load memory management functions */
    LOAD_SYMBOL(libcrypto_handle, CRYPTO_free);

    /* In OpenSSL 3.0+, the initialization/cleanup functions are deprecated
     * OPENSSL_cleanup is required for cleanup operations */
    LOAD_SYMBOL(libcrypto_handle, OPENSSL_cleanup);

    /* Successfully loaded all required symbols */
    if (is_verbose_mode()) {
        fprintf(stderr, "Successfully loaded OpenSSL libraries at runtime:\n");
        fprintf(stderr, "  - libcrypto: %s\n", loaded_crypto_path ? loaded_crypto_path : "(unknown)");
        fprintf(stderr, "  - libssl: %s\n", loaded_ssl_path ? loaded_ssl_path : "(unknown)");
    }

    return 1;
}

/* Function to unload OpenSSL libraries */
void cleanup_openssl_runtime(void) {
    if (libssl_handle || libcrypto_handle) {
        /* Call OPENSSL_cleanup if available */
        if (OPENSSL_cleanup) {
            OPENSSL_cleanup();
        }
        
        /* Close library handles */
#if defined(_WIN32) || defined(_WIN64)
        if (libssl_handle) {
            FreeLibrary(libssl_handle);
            libssl_handle = NULL;
        }
        if (libcrypto_handle) {
            FreeLibrary(libcrypto_handle);
            libcrypto_handle = NULL;
        }
#else
        if (libssl_handle) {
            dlclose(libssl_handle);
            libssl_handle = NULL;
        }
        if (libcrypto_handle) {
            dlclose(libcrypto_handle);
            libcrypto_handle = NULL;
        }
#endif
    }
}

#endif /* OPENSSL_RUNTIME_LINK */