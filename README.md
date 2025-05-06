# SGX Certificate Checker (echeck)

A utility for extracting and validating Intel SGX quotes embedded in X.509 certificates.

## Overview

This tool is designed to:

1. Load X.509 certificates that contain SGX quotes
2. Extract the SGX quote extension (OID 1.3.6.1.4.1.311.105.1)
3. Parse and display key fields from the quote
4. Perform basic validation of the quote structure

## Usage

```
./echeck <certificate.pem> [ca.pem]
```

Where:
- `certificate.pem`: The X.509 certificate containing an SGX quote
- `ca.pem` (optional): CA certificate(s) for verification

## Example Output

```
SGX Quote extracted successfully, 4616 bytes
Quote data (first 16 bytes): 01 00 00 00 02 00 00 00 f8 11 00 00 00 00 00 00 

Loaded 1 CA certificates from sample.pem

SGX Quote Analysis:
Version: 1
Signature Type: 0
QE SVN: 4600
PCE SVN: 0
MR_ENCLAVE: 07000000000000004b7100c0b65a3310ad5eee113e29752eb35cd822b6a4a7df
MR_SIGNER: 0000000000000000976aa9f931b8a16e01e01895d627e3ee96dce5478ebbbc77
ISV Product ID: 0
ISV SVN: 0

Verification Steps:
✓ Quote version check passed
✓ MR_ENCLAVE is valid (not empty)
✓ MR_SIGNER is valid (not empty)

This tool provides basic SGX quote analysis but does not perform
complete cryptographic verification of the quote signatures.
SGX quote verification successful
```

## Building

To build the program, simply run:

```
make
```

The program requires OpenSSL development libraries to be installed.

## SGX Quote Fields

The tool extracts and displays the following fields from SGX quotes:

- **Version**: The SGX quote format version
- **Signature Type**: The type of signature used
- **QE SVN**: Quoting Enclave Security Version Number
- **PCE SVN**: Provisioning Certification Enclave Security Version Number
- **MR_ENCLAVE**: A hash of the enclave measurement (code + data)
- **MR_SIGNER**: A hash of the enclave signer's public key
- **ISV Product ID**: The Independent Software Vendor's product ID
- **ISV SVN**: The Independent Software Vendor's Security Version Number

### SGX Quote Structure

The implementation follows Intel's SGX quote structure format, which is a fixed specification:

```c
typedef struct _sgx_quote {
    sgx_quote_header_t header;   /* 0-47 */
    sgx_report_body_t report_body; /* 48-431 */
    uint32_t signature_len;      /* 432-435 */
    uint8_t signature[];         /* 436+ (variable length) */
} sgx_quote_t;
```

This allows the tool to correctly extract fields like MR_SIGNER with the value:
```
mrsigner=976aa9f931b8a16e01e01895d627e3ee96dce5478ebbbc77e120a25c79fe6016
```

## Limitations

1. The tool does not perform full cryptographic verification of the SGX quote signatures
2. It doesn't verify the quote against Intel Attestation Services
3. It provides basic structural validation only

## Future Enhancements

- Full verification against Intel Attestation Services
- Detailed parsing of SGX signature data
- Enhanced certificate chain validation
- Support for DCAP quotes