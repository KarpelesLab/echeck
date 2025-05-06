#ifndef SGX_TYPES_H
#define SGX_TYPES_H

#include <stdint.h>

/* SGX certificate extension OID */
#define SGX_QUOTE_OID "1.3.6.1.4.1.311.105.1"

/* SGX types and constants */
#pragma pack(push, 1)
#define SGX_KEYID_SIZE    32
#define SGX_CPUSVN_SIZE   16
#define SGX_CONFIGID_SIZE 64

typedef uint8_t                  sgx_epid_group_id_t[4];
typedef uint16_t                 sgx_isv_svn_t;
typedef uint32_t                 sgx_misc_select_t;
typedef uint16_t                 sgx_prod_id_t;
typedef uint16_t                 sgx_config_svn_t;
typedef uint8_t                  sgx_measurement_t[32];
typedef uint8_t                  sgx_config_id_t[SGX_CONFIGID_SIZE];
typedef uint8_t                  sgx_isvext_prod_id_t[16];
typedef uint8_t                  sgx_isvfamily_id_t[16];
typedef uint8_t                  sgx_report_data_t[64];
typedef uint8_t                  sgx_attributes_t[16];

/* Structured types */
typedef struct _sgx_cpu_svn_t
{
    uint8_t                      svn[SGX_CPUSVN_SIZE];
} sgx_cpu_svn_t;

/* Constants for reserved fields */
#define SGX_REPORT_BODY_RESERVED1_BYTES 12
#define SGX_REPORT_BODY_RESERVED2_BYTES 32
#define SGX_REPORT_BODY_RESERVED3_BYTES 32
#define SGX_REPORT_BODY_RESERVED4_BYTES 42

/* SGX Report Body (384 bytes) */
typedef struct _sgx_report_body_t
{
    sgx_cpu_svn_t           cpu_svn;         /* (  0) Security Version of the CPU */
    sgx_misc_select_t       misc_select;     /* ( 16) Which fields defined in SSA.MISC */
    uint8_t                 reserved1[SGX_REPORT_BODY_RESERVED1_BYTES];  /* ( 20) */
    sgx_isvext_prod_id_t    isv_ext_prod_id; /* ( 32) ISV assigned Extended Product ID */
    sgx_attributes_t        attributes;      /* ( 48) Any special Capabilities the Enclave possess */
    sgx_measurement_t       mr_enclave;      /* ( 64) The value of the enclave's ENCLAVE measurement */
    uint8_t                 reserved2[SGX_REPORT_BODY_RESERVED2_BYTES];  /* ( 96) */
    sgx_measurement_t       mr_signer;       /* (128) The value of the enclave's SIGNER measurement */
    uint8_t                 reserved3[SGX_REPORT_BODY_RESERVED3_BYTES];  /* (160) */
    sgx_config_id_t         config_id;       /* (192) CONFIGID */
    sgx_prod_id_t           isv_prod_id;     /* (256) Product ID of the Enclave */
    sgx_isv_svn_t           isv_svn;         /* (258) Security Version of the Enclave */
    sgx_config_svn_t        config_svn;      /* (260) CONFIGSVN */
    uint8_t                 reserved4[SGX_REPORT_BODY_RESERVED4_BYTES];  /* (262) */
    sgx_isvfamily_id_t      isv_family_id;   /* (304) ISV assigned Family ID */
    sgx_report_data_t       report_data;     /* (320) Data provided by the user */
} sgx_report_body_t;

typedef struct _basename_t
{
    uint8_t                 name[32];
} sgx_basename_t;

/* Complete SGX Quote structure */
typedef struct _sgx_quote_t
{
    uint16_t            version;        /* 0   */
    uint16_t            sign_type;      /* 2   */
    sgx_epid_group_id_t epid_group_id;  /* 4   */
    sgx_isv_svn_t       qe_svn;         /* 8   */
    sgx_isv_svn_t       pce_svn;        /* 10  */
    uint32_t            xeid;           /* 12  */
    sgx_basename_t      basename;       /* 16  */
    sgx_report_body_t   report_body;    /* 48  */
    uint32_t            signature_len;  /* 432 */
    uint8_t             signature[];    /* 436 */
} sgx_quote_t;

/* Custom header structure that appears to be prepended to the SGX quote */
typedef struct _sgx_quote_header_t {
    uint32_t version;         /* Version of the header structure */
    uint32_t type;            /* Type of quote or data that follows */
    uint32_t size;            /* Size of the data after this header */
    uint32_t reserved;        /* Reserved field, possibly for alignment or future use */
} sgx_quote_header_t;

/* Additional SGX types needed for verification */
typedef uint8_t                  sgx_key_128bit_t[16];
typedef uint8_t                  sgx_target_info_t[512]; /* Simplified for our purposes */
typedef uint8_t                  sgx_report_t[432];     /* Simplified for our purposes */

typedef struct _sgx_key_id_t
{
    uint8_t                      id[SGX_KEYID_SIZE];
} sgx_key_id_t;

typedef struct _spid_t
{
    uint8_t             id[16];
} sgx_spid_t;

typedef struct _quote_nonce
{
    uint8_t             rand[16];
} sgx_quote_nonce_t;

typedef enum
{
    SGX_UNLINKABLE_SIGNATURE,
    SGX_LINKABLE_SIGNATURE
} sgx_quote_sign_type_t;

/* 
 * The signature section may contain:
 * 1. ECDSA signature
 * 2. Attestation Key certificate chain
 * 3. QE certification data
 * 4. QE report and ECDSA signature
 * 5. QE certification data signature
 */
/* SGX Quote v3 ECDSA signature data format */
typedef struct _sgx_ql_ecdsa_sig_data_t {
    uint8_t               sig[32*2];            /* Signature over the Quote using the ECDSA Att key. Big Endian. */
    uint8_t               attest_pub_key[32*2]; /* ECDSA Att Public Key. Hash in QE3Report.ReportData. Big Endian */
    sgx_report_body_t     qe_report;            /* QE3 Report of the QE when the Att key was generated. The ReportData will contain the ECDSA_ID */
    uint8_t               qe_report_sig[32*2];  /* Signature of QE Report using the Certification Key (PCK for root signing). Big Endian */
    uint8_t               auth_certification_data[];  /* Place holder for both the auth_data_t and certification_data_t. Concatenated in that order. */
} sgx_ql_ecdsa_sig_data_t;

typedef struct _sgx_quote_signature {
    uint32_t signature_size;     /* Size of the signature */
    uint8_t signature[64];       /* The actual ECDSA signature (r,s components) */
    /* Certificate chain follows, but varies in structure based on the quote version */
} sgx_quote_signature_t;

#define SGX_PLATFORM_INFO_SIZE 101
typedef struct _platform_info
{
    uint8_t platform_info[SGX_PLATFORM_INFO_SIZE];
} sgx_platform_info_t;

typedef struct _update_info_bit
{
    int ucodeUpdate;
    int csmeFwUpdate;
    int pswUpdate;
} sgx_update_info_bit_t;

typedef struct _att_key_id_t {
    uint8_t     att_key_id[256];
} sgx_att_key_id_t;

/** Describes a single attestation key. Contains both QE identity and the attestation algorithm ID. */
typedef struct _sgx_ql_att_key_id_t {
    uint16_t    id;                              ///< Structure ID
    uint16_t    version;                         ///< Structure version
    uint16_t    mrsigner_length;                 ///< Number of valid bytes in MRSIGNER.
    uint8_t     mrsigner[48];                    ///< SHA256 or SHA384 hash of the Public key that signed the QE.
                                                 ///< The lower bytes contain MRSIGNER. Bytes beyond mrsigner_length '0'
    uint32_t    prod_id;                         ///< Legacy Product ID of the QE
    uint8_t     extended_prod_id[16];            ///< Extended Product ID or the QE. All 0's for legacy format enclaves.
    uint8_t     config_id[64];                   ///< Config ID of the QE.
    uint8_t     family_id[16];                   ///< Family ID of the QE.
    uint32_t    algorithm_id;                    ///< Identity of the attestation key algorithm.
} sgx_ql_att_key_id_t;

/** Describes an extended attestation key. Contains sgx_ql_att_key_id_t, spid and quote_type */
typedef struct _sgx_att_key_id_ext_t {
    sgx_ql_att_key_id_t base;
    uint8_t             spid[16];                ///< Service Provider ID, should be 0s for ECDSA quote
    uint16_t            att_key_type;            ///< For non-EPID quote, it should be 0
                                                 ///< For EPID quote, it equals to sgx_quote_sign_type_t
    uint8_t             reserved[80];            ///< It should have the same size of sgx_att_key_id_t
} sgx_att_key_id_ext_t;

typedef struct _qe_report_info_t {
    sgx_quote_nonce_t nonce;
    sgx_target_info_t app_enclave_target_info;
    sgx_report_t qe_report;
} sgx_qe_report_info_t;

#pragma pack(pop)

#endif /* SGX_TYPES_H */