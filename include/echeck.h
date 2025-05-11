/**
 * @file echeck.h
 * @brief Intel SGX Quote Verification Library - Public API
 *
 * This library provides functions for extracting and validating 
 * Intel SGX quotes embedded in X.509 certificates.
 */

#ifndef ECHECK_H
#define ECHECK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* Define visibility macros for shared library symbols */
#if defined(_WIN32) || defined(__CYGWIN__)
  #ifdef ECHECK_SHARED_LIBRARY
    #define ECHECK_API __declspec(dllexport)
  #else
    #define ECHECK_API __declspec(dllimport)
  #endif
  #define ECHECK_PRIVATE
#else
  #if defined(__GNUC__) && __GNUC__ >= 4
    #define ECHECK_API __attribute__ ((visibility ("default")))
    #define ECHECK_PRIVATE __attribute__ ((visibility ("hidden")))
  #else
    #define ECHECK_API
    #define ECHECK_PRIVATE
  #endif
#endif

/**
 * @brief Initialize the library and OpenSSL
 *
 * @return 1 on success, 0 on failure
 */
ECHECK_API int echeck_initialize(void);

/**
 * @brief Quote buffer structure (opaque handle)
 * 
 * This is an opaque structure used to store and pass SGX quotes between API functions.
 */
typedef struct echeck_quote_t echeck_quote_t;

/**
 * @brief Quote info structure to hold extracted measurements
 */
typedef struct {
    uint8_t mr_enclave[32];   /**< MRENCLAVE value (32 bytes) */
    uint8_t mr_signer[32];    /**< MRSIGNER value (32 bytes) */
    uint16_t isv_prod_id;     /**< ISV Product ID */
    uint16_t isv_svn;         /**< ISV SVN (Security Version Number) */
} echeck_quote_info_t;

/**
 * @brief Verification result structure
 */
typedef struct {
    /* Basic validation result */
    int valid;                     /**< 1 if valid, 0 if invalid */
    char *error_message;           /**< Error message (NULL if valid) */
    
    /* Detailed validation flags */
    int mr_enclave_valid;          /**< MRENCLAVE validation result */
    int mr_signer_valid;           /**< MRSIGNER validation result */
    int signature_valid;           /**< Quote signature validation result */
    int quote_valid;               /**< Overall quote format and data validation */
    int report_data_matches_cert;  /**< Report data matches certificate */
    int cert_chain_valid;          /**< Certificate chain validation result */
    
    /* Statistics */
    int checks_performed;          /**< Number of checks performed */
    int checks_passed;             /**< Number of checks that passed */
} echeck_verification_result_t;

/**
 * @brief Load a certificate from a PEM file
 *
 * @param file_path Path to the PEM file
 * @return Certificate pointer on success, NULL on failure
 */
ECHECK_API void* echeck_load_certificate(const char *file_path);

/**
 * @brief Free a certificate that was loaded with echeck_load_certificate
 *
 * @param cert Certificate pointer returned by echeck_load_certificate
 */
ECHECK_API void echeck_free_certificate(void *cert);

/**
 * @brief Extract SGX quote from a certificate
 *
 * @param cert Certificate pointer
 * @return Quote handle on success, NULL on failure
 */
ECHECK_API echeck_quote_t* echeck_extract_quote(void *cert);

/**
 * @brief Free a quote that was extracted with echeck_extract_quote
 *
 * @param quote Quote pointer returned by echeck_extract_quote
 */
ECHECK_API void echeck_free_quote(echeck_quote_t *quote);

/**
 * @brief Get information from a quote
 *
 * @param quote Quote handle
 * @param info Pointer to info structure to fill
 * @return 1 on success, 0 on failure
 */
ECHECK_API int echeck_get_quote_info(echeck_quote_t *quote, echeck_quote_info_t *info);

/**
 * @brief Verify an SGX quote against its certificate
 *
 * @param cert Certificate pointer
 * @param quote Quote handle
 * @param result Verification result structure
 * @return 1 on success, 0 on failure
 */
ECHECK_API int echeck_verify_quote(void *cert, echeck_quote_t *quote, echeck_verification_result_t *result);

/**
 * @brief Verify a quote against expected MRENCLAVE and MRSIGNER values
 *
 * @param quote Quote handle
 * @param expected_mrenclave Expected MRENCLAVE value (32 bytes), NULL to skip check
 * @param expected_mrsigner Expected MRSIGNER value (32 bytes), NULL to skip check
 * @return 1 if the values match (or were NULL), 0 otherwise
 */
ECHECK_API int echeck_verify_quote_measurements(echeck_quote_t *quote, const uint8_t *expected_mrenclave, const uint8_t *expected_mrsigner);

/**
 * @brief Set global verbose mode
 *
 * @param verbose 1 to enable verbose mode, 0 to disable
 */
ECHECK_API void echeck_set_verbose_mode(int verbose);

#ifdef __cplusplus
}
#endif

#endif /* ECHECK_H */