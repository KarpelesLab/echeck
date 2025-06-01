# SGX Certificate Checker (echeck)

A utility and library for extracting and validating Intel SGX quotes embedded in X.509 certificates. Available as both a C library with command-line tool and a Go library.

## Overview

This tool and library are designed to:

1. Load X.509 certificates that contain SGX quotes
2. Extract the SGX quote extension (OID 1.3.6.1.4.1.311.105.1)
3. Parse and display key fields from the quote
4. **Perform complete chain of trust verification**, including:
   - TLS certificate → SGX enclave (via public key hash in report data)
   - SGX enclave → Intel attestation service (via quote signature)
   - Intel attestation service → trusted root CAs (via certificate chain)

### Complete Chain of Trust Verification

The primary feature of this library is its comprehensive verification of the entire trust chain:

```
TLS Certificate ⟶ SGX Enclave ⟶ Intel Attestation Service ⟶ Trusted CA Roots
        │                │                   │                      │
        │                │                   │                      │
 Public Key Hash  ┌─────────────┐     Quote Signature      Certificate Chain
 matches Report   │ Genuine SGX │      verification         verification
     Data         │   Enclave   │                                │
        │         └─────────────┘                                │
        └───────────────┬─────────────────────────────────────────
                        │
                    VALIDATED
                  SECURE CHANNEL
```

This **end-to-end verification** ensures:

1. **TLS Certificate Trust**: The public key of the TLS certificate matches the hash in the SGX quote's report data, proving the enclave signed the certificate

2. **Enclave Integrity**: The enclave's identity (MRENCLAVE/MRSIGNER) is verified and can be validated against expected values

3. **Intel Attestation**: The quote is properly signed by Intel's Quoting Enclave (QE) using a valid attestation key

4. **Root of Trust**: The complete certificate chain from the PCK certificates to Intel's trusted CA roots is verified

### SGX Attestation and TLS Connections

Intel SGX (Software Guard Extensions) provides a hardware-based trusted execution environment that enables secure code execution, even in untrusted environments. A key feature of SGX is **remote attestation**, which allows a remote party to verify the identity and integrity of an SGX enclave.

The remote attestation process involves:

1. An enclave generates a report that includes its identity (MRENCLAVE, MRSIGNER) and hash of the TLS certificate's public key
2. This report is signed by the Intel Quoting Enclave, creating a quote
3. The quote is embedded in an X.509 certificate extension
4. The certificate is used in a TLS connection

By integrating this verification into a TLS handshake, you can establish a secure, attested connection to an SGX enclave, ensuring that you're communicating with a genuine and unmodified enclave within an SGX-enabled CPU.

## C Library and Command-Line Tool

### Command-Line Usage

```
./echeck [OPTIONS] <certificate.pem>
```

Where:
- `certificate.pem`: The X.509 certificate containing an SGX quote to be verified

#### Options

- `-h, --help`: Display help message
- `-v, --verbose`: Enable verbose output (prints detailed verification info)
- `-q, --quiet`: Quiet mode (only errors will be printed, success is silent)
- `-r, --raw`: Output in machine-readable format (key=value)
- `--mrenclave=<hash>`: Verify the SGX quote has the specified MRENCLAVE value (64 hex characters)
- `--mrsigner=<hash>`: Verify the SGX quote has the specified MRSIGNER value (64 hex characters)

#### Example Output

**Standard mode:**
```
$ ./echeck test/sample.pem
SGX quote verification successful
```

**Verbose mode:**
```
$ ./echeck -v test/sample.pem
Certificate public key hash verified: 4f1ea6825b7a95d4dc0f9b6929a91b66c5fcaa9ef3078afe48f0c02cde48b13a
SGX Quote verification successful
MRENCLAVE: df2493c11fc01708af6913323b64e20ae84b12779dbe44ba428da66dfc4488f5
MRSIGNER: 976aa9f931b8a16e01e01895d627e3ee96dce5478ebbbc77e120a25c79fe6016
ISV Product ID: 1
ISV SVN: 1
```

**Raw mode (machine readable):**
```
$ ./echeck -r test/sample.pem
mrenclave=df2493c11fc01708af6913323b64e20ae84b12779dbe44ba428da66dfc4488f5
mrsigner=976aa9f931b8a16e01e01895d627e3ee96dce5478ebbbc77e120a25c79fe6016
version=3
signtype=2
isvprodid=1
isvsvn=1
```

For detailed C API examples including TLS integration, measurement verification, and error handling, see [API_EXAMPLES.md](API_EXAMPLES.md#c-library-examples).

## Go Library

### Installation

```bash
go get github.com/KarpelesLab/echeck
```

For detailed Go API examples including quote extraction, verification, measurement checking, certificate chain validation, and HTTP client integration, see [API_EXAMPLES.md](API_EXAMPLES.md#go-library-examples).

## API Reference

### C API

#### Core Functions

**`int echeck_initialize(void)`**
Initialize the OpenSSL library. Call this before using any other functions.

**`void* echeck_load_certificate(const char *file_path)`**
Load an X.509 certificate from a PEM file.

**`echeck_quote_t* echeck_extract_quote(void *cert)`**
Extract an SGX quote from a certificate.

**`int echeck_verify_quote(void *cert, echeck_quote_t *quote, echeck_verification_result_t *result)`**
Perform full end-to-end chain of trust verification of an SGX quote against its certificate.

**`int echeck_verify_quote_measurements(echeck_quote_t *quote, const uint8_t *expected_mrenclave, const uint8_t *expected_mrsigner)`**
Verify the MRENCLAVE and/or MRSIGNER values of a quote against expected values.

### Go API

#### Types

**`QuoteInfo`** - Contains essential measurements extracted from an SGX quote:
- `MREnclave [32]byte` - MRENCLAVE value
- `MRSigner [32]byte` - MRSIGNER value  
- `ISVProdID uint16` - ISV Product ID
- `ISVSVN uint16` - ISV SVN (Security Version Number)
- `ReportData [64]byte` - Report data from the quote

**Error Types:**
- `ErrReportDataMismatch` - Report data doesn't match certificate's public key hash
- `ErrInvalidQuoteFormat` - Quote format or version is invalid
- `ErrCertChainVerification` - Certificate chain verification failed

#### Functions

**`ExtractQuote(cert *x509.Certificate) (*Quote, error)`**
Extracts an SGX quote from an X.509 certificate.

**`VerifyQuote(cert *x509.Certificate, quote *Quote) error`**
Performs comprehensive verification of an SGX quote against its certificate.

**`GetIntelSGXCertPool() (*x509.CertPool, error)`**
Returns a certificate pool pre-initialized with Intel's SGX Root CA.

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

## Features

### Comprehensive Security Validations

1. **Complete End-to-End Chain of Trust Verification**:
   - TLS certificate to SGX enclave (via report data verification)
   - SGX enclave to Intel attestation service (via signature verification)
   - Intel attestation service to trusted CA roots (via certificate chain verification)

2. **Full ECDSA Signature Verification**:
   - Complete cryptographic verification of quote signatures
   - Attestation key extraction and validation
   - Quote hash computation and verification

3. **Certificate Chain Verification**:
   - Complete certificate chain verification against Intel SGX Root CA
   - PCK certificate extraction and validation
   - Built-in Intel SGX Root CA for certificate chain verification

4. **Report Data Validation**:
   - Cryptographic verification of certificate's public key hash against quote report data
   - Zero-padding validation for report data integrity

### Platform Support

- **C Library**: Cross-platform support (Linux, macOS, Windows) with both static and runtime OpenSSL linking
- **Go Library**: Pure Go implementation with standard library cryptography
- **GitHub Actions**: Automated builds for all supported platforms

### Command-Line Interface

- Verbose mode for detailed output
- Quiet mode for scripting
- Raw output mode for machine parsing
- Verification of specific MRENCLAVE/MRSIGNER values

## Documentation

- **[BUILD.md](BUILD.md)** - Detailed build instructions for both C and Go libraries
- **[API_EXAMPLES.md](API_EXAMPLES.md)** - Comprehensive API examples and usage patterns

## Verification Process Details

The library implements a rigorous multi-step verification process to ensure the complete chain of trust:

### 1. Report Data Verification
- Computes SHA-256 hash of the TLS certificate's public key
- Verifies this hash matches the first 32 bytes of the quote's report data
- Validates zero-padding in remaining report data bytes
- Establishes the link between TLS certificate and SGX enclave

### 2. Quote Format Validation
- Validates the quote's structure and format
- Checks MRENCLAVE and MRSIGNER values are properly formed
- Verifies all required fields in the quote structure

### 3. ECDSA Signature Verification
- Extracts the attestation public key from the quote
- Computes SHA-256 hash of quote data for signature verification
- Verifies the quote's ECDSA signature using P-256 curve
- Ensures the quote was genuinely signed by Intel's Quoting Enclave

### 4. PCK Certificate Chain Verification
- Extracts the PCK certificate chain from the quote signature data
- Validates the complete chain against Intel's trusted CA roots
- Verifies signatures, validity periods, and certificate purposes
- Establishes root of trust back to Intel CA

### 5. Attestation Key Validation
- Validates that the attestation key can be properly extracted
- Ensures the key is a valid ECDSA key on the P-256 curve
- Verifies key extractability and format compliance

A quote is only considered valid when **ALL** verification steps pass, providing cryptographic guarantees at every step of the chain.

## Exit Codes

The command-line tool follows standard Unix exit code conventions:
- `0`: Success (quote verification passed)
- `1`: Error (verification failed, invalid parameters, etc.)

This makes it suitable for use in scripts and automated workflows.

## Limitations

1. The tool doesn't verify the quote against Intel Attestation Services (IAS) for online verification
2. It doesn't perform revocation checking on certificates
3. Currently focuses on ECDSA Quote v3 format

## Future Enhancements

- Integration with Intel Attestation Services for online verification
- Certificate revocation checking via OCSP or CRLs
- Support for custom verification policies
- Expanded API for more fine-grained control over verification process
- Support for additional SGX quote formats and versions

## License

This project is licensed under the MIT License - see the LICENSE file for details.