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

/**
 * @brief Initialize the library and OpenSSL
 * 
 * @return 1 on success, 0 on failure
 */
int initialize_openssl(void);

/**
 * @brief SGX Quote buffer structure
 */
typedef struct {
    unsigned char *data;  /**< Pointer to quote data */
    int length;           /**< Length of quote data */
} sgx_quote_buffer_t;

/* SGX certificate extension OID */
#define SGX_QUOTE_OID "1.3.6.1.4.1.311.105.1"

/**
 * @brief Custom header structure for SGX quotes
 */
#pragma pack(push, 1)
typedef struct {
    uint32_t version;              /**< Version of the header structure */
    uint32_t type;                 /**< Type of quote or data that follows */
    uint32_t size;                 /**< Size of the data after this header */
    uint32_t reserved;             /**< Reserved field */
} sgx_quote_header_t;
#pragma pack(pop)

/**
 * @brief SGX Quote structure
 */
#pragma pack(push, 1)
typedef struct {
    uint16_t version;              /**< Quote version */
    uint16_t sign_type;            /**< Signature type */
    uint8_t epid_group_id[4];      /**< EPID Group ID */
    uint16_t qe_svn;               /**< Quoting Enclave SVN */
    uint16_t pce_svn;              /**< Provisioning Certification Enclave SVN */
    uint32_t xeid;                 /**< Extended EPID Group ID */
    uint8_t basename[32];          /**< Basename */
    
    /**
     * @brief SGX Report Body
     */
    struct {
        uint8_t cpu_svn[16];       /**< CPU SVN */
        uint32_t misc_select;      /**< MISCSELECT */
        uint8_t reserved1[12];     /**< Reserved bytes */
        uint8_t isv_ext_prod_id[16]; /**< ISV Extended Product ID */
        uint8_t attributes[16];    /**< Attributes */
        uint8_t mr_enclave[32];    /**< Measurement of the enclave (code+data) */
        uint8_t reserved2[32];     /**< Reserved bytes */
        uint8_t mr_signer[32];     /**< Measurement of the signing key */
        uint8_t reserved3[32];     /**< Reserved bytes */
        uint8_t config_id[64];     /**< Configuration ID */
        uint16_t isv_prod_id;      /**< ISV Product ID */
        uint16_t isv_svn;          /**< ISV SVN */
        uint16_t config_svn;       /**< Configuration SVN */
        uint8_t reserved4[42];     /**< Reserved bytes */
        uint8_t isv_family_id[16]; /**< ISV Family ID */
        uint8_t report_data[64];   /**< Custom report data */
    } report_body;
    
    uint32_t signature_len;        /**< Length of the signature data */
    /* Followed by variable-length signature data */
} sgx_quote_t;
#pragma pack(pop)

/**
 * @brief Verification result structure
 */
typedef struct {
    int valid;                     /**< 1 if valid, 0 if invalid */
    char *error_message;           /**< Error message (NULL if valid) */
} sgx_verification_result_t;

/**
 * @brief Certificate verification result
 */
typedef struct {
    int valid;                     /**< 1 if valid, 0 if invalid */
    int error_code;                /**< Error code (0 if valid) */
    char *error_string;            /**< Error message (NULL if valid) */
} sgx_cert_verification_result_t;

/**
 * @brief Load a certificate from a PEM file
 * 
 * @param file_path Path to the PEM file
 * @return Certificate pointer on success, NULL on failure
 */
void* load_certificate(const char *file_path);

/**
 * @brief Extract SGX quote from a certificate
 * 
 * @param cert Certificate pointer
 * @param quote_buffer Buffer to store the quote
 * @return 1 on success, 0 on failure
 */
int extract_sgx_quote(void *cert, sgx_quote_buffer_t *quote_buffer);

/**
 * @brief Compute the hash of a certificate's public key
 * 
 * @param cert Certificate pointer
 * @param hash_buf Buffer to store the hash (should be at least 32 bytes)
 * @param hash_len Pointer to store the hash length
 * @return 1 on success, 0 on failure
 */
int compute_pubkey_hash(void *cert, unsigned char *hash_buf, unsigned int *hash_len);

/**
 * @brief Verify report data against certificate public key hash
 * 
 * @param quote SGX quote
 * @param pubkey_hash Certificate public key hash
 * @param pubkey_hash_len Hash length
 * @return 1 on success, 0 on failure
 */
int verify_report_data(const sgx_quote_t *quote, const unsigned char *pubkey_hash, unsigned int pubkey_hash_len);

/**
 * @brief Verify an SGX quote
 * 
 * @param quote_data Quote data buffer
 * @param quote_size Quote data size
 * @param result Verification result
 * @return 1 on success, 0 on failure
 */
int verify_sgx_quote(const unsigned char *quote_data, size_t quote_size, sgx_verification_result_t *result);

/**
 * @brief Set global verbose flag
 */
extern int global_verbose_flag;

#ifdef __cplusplus
}
#endif

#endif /* ECHECK_H */