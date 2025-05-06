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
./echeck [OPTIONS] <certificate.pem>
```

Where:
- `certificate.pem`: The X.509 certificate containing an SGX quote to be verified

### Options

- `-h, --help`: Display help message
- `-v, --verbose`: Enable verbose output (prints detailed verification info)
- `-q, --quiet`: Quiet mode (only errors will be printed, success is silent)
- `-r, --raw`: Output in machine-readable format (key=value)
- `--mrenclave=<hash>`: Verify the SGX quote has the specified MRENCLAVE value (64 hex characters)
- `--mrsigner=<hash>`: Verify the SGX quote has the specified MRSIGNER value (64 hex characters)

## Example Output

### Standard mode
```
$ ./echeck test/sample.pem
SGX quote verification successful
```

### Verbose mode
```
$ ./echeck -v test/sample.pem
Certificate public key hash verified: 4f1ea6825b7a95d4dc0f9b6929a91b66c5fcaa9ef3078afe48f0c02cde48b13a
SGX Quote verification successful
MRENCLAVE: df2493c11fc01708af6913323b64e20ae84b12779dbe44ba428da66dfc4488f5
MRSIGNER: 976aa9f931b8a16e01e01895d627e3ee96dce5478ebbbc77e120a25c79fe6016
ISV Product ID: 1
ISV SVN: 1
SGX Quote extracted: 4600 bytes
Quote saved to quote.bin
Loaded 1 built-in CA certificates for SGX validation
Successfully extracted attestation public key
[ECDSA Signature Components]
R: 053f4bc2270533c9db7f11391a40ed91b1765adf620e2180759e34497d3a41c2
S: def1bc706eaae07d2b4a7c8683fcca27dae9b1517f5c77c7a4cbf71bbd31daca
Found PCK certificate chain (3548 bytes)
Certificate 1: /CN=Intel SGX PCK Processor CA/O=Intel Corporation/L=Santa Clara/ST=CA/C=US
Certificate 2: /CN=Intel SGX Root CA/O=Intel Corporation/L=Santa Clara/ST=CA/C=US
Successfully extracted 2 certificates from the quote
Successfully extracted attestation public key
```

### Raw mode (machine readable)
```
$ ./echeck -r test/sample.pem
mrenclave=df2493c11fc01708af6913323b64e20ae84b12779dbe44ba428da66dfc4488f5
mrsigner=976aa9f931b8a16e01e01895d627e3ee96dce5478ebbbc77e120a25c79fe6016
version=3
signtype=2
isvprodid=1
isvsvn=1
```

### Quiet mode (only errors)
```
$ ./echeck -q test/sample.pem
$ echo $?
0
```

### Verification with specific MRENCLAVE
```
$ ./echeck --mrenclave=df2493c11fc01708af6913323b64e20ae84b12779dbe44ba428da66dfc4488f5 test/sample.pem
SGX quote verification successful

$ ./echeck --mrenclave=incorrect_value test/sample.pem
Error: Invalid MRENCLAVE format (expected 64 hex characters)
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

## Features

1. Full ECDSA signature verification for SGX quotes
2. Certificate chain verification against the Intel SGX Root CA
3. Validation of the attestation key against the PCK certificate
4. Verification of certificate's public key hash against quote report data
5. Built-in Intel SGX Root CA for certificate chain verification
6. Unix-like command-line interface with support for:
   - Verbose mode for detailed output
   - Quiet mode for scripting
   - Raw output mode for machine parsing
   - Verification of specific MRENCLAVE/MRSIGNER values

## Testing

The tool includes a test framework to validate SGX quotes from certificates:

```
make test
```

This will run the verification on all certificate files in the `test/` directory
using the built-in Intel SGX Root CA certificate.

## Limitations

1. The tool doesn't verify the quote against Intel Attestation Services
2. It doesn't perform revocation checking on certificates

## Exit Codes

The tool follows standard Unix exit code conventions:
- `0`: Success (quote verification passed)
- `1`: Error (verification failed, invalid parameters, etc.)

This makes it suitable for use in scripts and automated workflows.

## Future Enhancements

- Integration with Intel Attestation Services for online verification
- Certificate revocation checking via OCSP or CRLs
- Support for custom verification policies