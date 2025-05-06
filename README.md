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
SGX Quote extracted successfully, 4600 bytes
Quote data (first 16 bytes): 03 00 02 00 00 00 00 00 0b 00 10 00 93 9a 72 33 
Quote dumped to quote.bin for analysis

[Certificate Public Key Hash Analysis]
Certificate Public Key Hash (SHA-256): 4f1ea6825b7a95d4dc0f9b6929a91b66c5fcaa9ef3078afe48f0c02cde48b13a
Report Data (first 32 bytes): 4f1ea6825b7a95d4dc0f9b6929a91b66c5fcaa9ef3078afe48f0c02cde48b13a
✅ VERIFIED: Report data correctly contains padded SHA-256 hash of certificate's public key
This confirms the enclave knew the public key of this certificate when generating the quote.
Loaded 1 built-in CA certificates for SGX validation

=====================================================
                  SGX Quote Analysis                 
=====================================================

[Quote Header]
Version:          3
Sign Type:        2
EPID Group ID:    0x00000000
QE SVN:           11
PCE SVN:          16
XEID:             0x33729a93
Basename:         f79c4ca9940a0db3957f0607ecbb6229...

[Report Body]
CPU SVN:          0c0d0218ffff04000000000000000000
Misc Select:      0x00000000
ISV Ext Prod ID:  00000000000000000000000000000000
Attributes:       05000000000000000700000000000000
MR_ENCLAVE: df2493c11fc01708af6913323b64e20ae84b12779dbe44ba428da66dfc4488f5
MR_SIGNER: 976aa9f931b8a16e01e01895d627e3ee96dce5478ebbbc77e120a25c79fe6016
CONFIG_ID:        00000000000000000000000000000000...
ISV Product ID:   1
ISV SVN:          1
CONFIG SVN:       0
ISV Family ID:    00000000000000000000000000000000
Report Data:      4f1ea6825b7a95d4dc0f9b6929a91b66c5fcaa9ef3078afe48f0c02cde48b13a...

[Signature Section] (4164 bytes)
Signature data dumped to signature.bin for analysis

=====================================================
                Verification Results                 
=====================================================
✅ Quote version is valid: 3
✅ MR_ENCLAVE is valid (not all zeros)
✅ MR_SIGNER is valid (not all zeros)
✅ MR_SIGNER validation check passed
✅ MR_ENCLAVE validation check passed
✅ Signature length is valid: 4164 bytes
✅ Quote version is supported: 3

[ECDSA Signature Verification]
Quote hash for verification: 849232956fbb9dd6d93ca4d54621978e0df19818a51d56e73f1ed91b6790b04f
ECDSA signature verification succeeded
✅ ECDSA signature verification succeeded

Verification Summary: 8 of 8 checks passed
✅ SGX Quote verification PASSED

[Certificate Chain Verification]
Found PCK certificate chain (3548 bytes)
Certificate 1: /CN=Intel SGX PCK Processor CA/O=Intel Corporation/L=Santa Clara/ST=CA/C=US
Certificate 2: /CN=Intel SGX Root CA/O=Intel Corporation/L=Santa Clara/ST=CA/C=US
Successfully extracted 2 certificates from the quote
✅ PCK certificate chain verified successfully

[Attestation Key Verification]
Successfully extracted attestation public key
✅ Attestation key verified against PCK certificate
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

## Features

1. Full ECDSA signature verification for SGX quotes
2. Certificate chain verification against the Intel SGX Root CA
3. Validation of the attestation key against the PCK certificate
4. Verification of certificate's public key hash against quote report data
5. Support for external CA certificates or built-in Intel SGX Root CA

## Testing

The tool includes a test framework to validate SGX quotes from certificates:

```
make test
```

This will run the verification on all certificate files in the `test/` directory.
If `ca.pem` is present in the root directory, it will be used for verification.
Otherwise, the built-in Intel SGX Root CA will be used.

## Limitations

1. The tool doesn't verify the quote against Intel Attestation Services
2. It doesn't perform revocation checking on certificates

## Future Enhancements

- Integration with Intel Attestation Services for online verification
- Certificate revocation checking via OCSP or CRLs
- Support for custom verification policies