# SGX Certificate Checker (echeck)

A utility for extracting and validating Intel SGX quotes embedded in X.509 certificates.

## Overview

This tool and library are designed to:

1. Load X.509 certificates that contain SGX quotes
2. Extract the SGX quote extension (OID 1.3.6.1.4.1.311.105.1)
3. Parse and display key fields from the quote
4. Perform full validation of the quote, including:
   - Signature verification
   - Certificate chain verification
   - Attestation key verification
   - MRENCLAVE/MRSIGNER validation

### SGX Attestation and TLS Connections

Intel SGX (Software Guard Extensions) provides a hardware-based trusted execution environment that enables secure code execution, even in untrusted environments. A key feature of SGX is **remote attestation**, which allows a remote party to verify the identity and integrity of an SGX enclave.

The remote attestation process involves:

1. An enclave generates a report that includes its identity (MRENCLAVE, MRSIGNER)
2. This report is signed by the Intel Quoting Enclave, creating a quote
3. The quote can be embedded in an X.509 certificate extension
4. The certificate can be used in a TLS connection

This library enables verification of such certificates by:
- Extracting the SGX quote from the certificate
- Verifying the quote's signature against Intel's Certificate Chain
- Confirming that the report data in the quote matches the certificate's public key
- Validating MRENCLAVE/MRSIGNER values against expected values

By integrating this verification into a TLS handshake (see API examples below), you can establish a secure, attested connection to an SGX enclave, ensuring that you're communicating with a genuine and unmodified enclave within an SGX-enabled CPU.

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

The project requires OpenSSL development libraries to be installed.

### Option 1: Using the build script

Run the build script to compile the project:

```
./build.sh                    # Standard build
./build.sh runtime-link       # Build with runtime OpenSSL linking
./build.sh test               # Build and run tests
./build.sh runtime-link test  # Build with runtime linking and run tests
```

This will create a `build` directory with the `echeck` executable and `libecheck.a` static library.

### Option 2: Using CMake directly

```
mkdir -p build
cd build
cmake ..
make
```

### Runtime linking of OpenSSL

The project supports an option to dynamically load OpenSSL libraries at runtime instead of linking them at build time:

```
mkdir -p build
cd build
cmake -DOPENSSL_RUNTIME_LINK=ON ..
make
```

With runtime linking, the project will load the following OpenSSL libraries depending on platform:

**On macOS:**
- `libssl.3.dylib`, `libcrypto.3.dylib`

**On Windows:**
- For 64-bit AMD64: `libssl-3-x64.dll`, `libcrypto-3-x64.dll`
- For 64-bit ARM64: `libssl-3-arm64.dll`, `libcrypto-3-arm64.dll`
- For 32-bit x86: `libssl-3.dll`, `libcrypto-3.dll`

**On Linux/Unix:**
- `libssl.so.3`, `libcrypto.so.3`

This option is useful in environments where:
- You want to deploy the binary without OpenSSL dependencies
- You need to use a specific OpenSSL version at runtime
- The system may have multiple OpenSSL versions installed
- You need to support multiple platforms with a single binary

The executable will be located at `build/echeck` and the static library at `build/libecheck.a`.

### Installing

To install the executable, library, and headers:

```
cd build
sudo make install
```

This will install:
- The `echeck` executable to `/usr/local/bin/`
- The `libecheck.a` static library to `/usr/local/lib/`
- The header files to `/usr/local/include/echeck/`
- The pkg-config file to `/usr/local/lib/pkgconfig/`

### Using the library in your projects

The library can be used in other projects through pkg-config:

```
gcc -o myapp myapp.c $(pkg-config --cflags --libs echeck)
```

Or by directly linking:

```
gcc -o myapp myapp.c -I/usr/local/include/echeck -L/usr/local/lib -lecheck -lssl -lcrypto
```

### API Examples

Here are some examples of how to use the echeck library API in your own code:

#### Basic Quote Extraction and Verification

```c
#include <echeck.h>
#include <stdio.h>

int main() {
    // Initialize OpenSSL
    if (!initialize_openssl()) {
        fprintf(stderr, "Failed to initialize OpenSSL\n");
        return 1;
    }

    // Load a certificate containing an SGX quote
    void *cert = load_certificate("/path/to/certificate.pem");
    if (!cert) {
        fprintf(stderr, "Failed to load certificate\n");
        return 1;
    }

    // Extract SGX quote from the certificate
    echeck_quote_t *quote = extract_quote(cert);
    if (!quote) {
        fprintf(stderr, "Failed to extract SGX quote\n");
        free_certificate(cert);
        return 1;
    }

    // Get the quote information
    echeck_quote_info_t info;
    if (!get_quote_info(quote, &info)) {
        fprintf(stderr, "Failed to get quote info\n");
        free_quote(quote);
        free_certificate(cert);
        return 1;
    }

    // Print the MRENCLAVE and MRSIGNER values
    printf("MRENCLAVE: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", info.mr_enclave[i]);
    }
    printf("\n");

    printf("MRSIGNER: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", info.mr_signer[i]);
    }
    printf("\n");

    // Verify the quote
    echeck_verification_result_t result;
    if (!verify_quote(cert, quote, &result)) {
        fprintf(stderr, "Quote verification failed: %s\n",
                result.error_message ? result.error_message : "Unknown error");
        free_quote(quote);
        free_certificate(cert);
        return 1;
    }

    printf("Quote verification successful!\n");

    // Cleanup
    free_quote(quote);
    free_certificate(cert);
    return 0;
}
```

#### Verifying Specific MRENCLAVE/MRSIGNER Values

```c
#include <echeck.h>
#include <stdio.h>
#include <string.h>

// Helper function to convert hex string to binary
int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_size) {
    if (strlen(hex) != bin_size * 2)
        return 0;

    for (size_t i = 0; i < bin_size; i++) {
        if (sscanf(&hex[i*2], "%02hhx", &bin[i]) != 1)
            return 0;
    }
    return 1;
}

int main() {
    // Initialize OpenSSL
    initialize_openssl();

    // Expected MRENCLAVE value (32 bytes)
    const char *expected_mrenclave_hex = "df2493c11fc01708af6913323b64e20ae84b12779dbe44ba428da66dfc4488f5";
    uint8_t expected_mrenclave[32];

    if (!hex_to_bin(expected_mrenclave_hex, expected_mrenclave, sizeof(expected_mrenclave))) {
        fprintf(stderr, "Invalid MRENCLAVE format\n");
        return 1;
    }

    // Load and extract quote
    void *cert = load_certificate("/path/to/certificate.pem");
    echeck_quote_t *quote = extract_quote(cert);

    // Verify with expected MRENCLAVE
    if (!verify_quote_measurements(quote, expected_mrenclave, NULL)) {
        fprintf(stderr, "MRENCLAVE value doesn't match expected value\n");
        free_quote(quote);
        free_certificate(cert);
        return 1;
    }

    printf("MRENCLAVE verified successfully\n");

    // Cleanup
    free_quote(quote);
    free_certificate(cert);
    return 0;
}
```

#### Integration with TLS Connections

Here's an example of how to verify an SGX quote during a TLS handshake, which is useful for attestation in TLS-based applications:

```c
#include <echeck.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

// Custom TLS certificate verification function
int verify_certificate_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    // First, let OpenSSL do standard verification
    if (!preverify_ok) {
        fprintf(stderr, "Standard certificate verification failed\n");
        return 0;
    }

    // Get the certificate being verified
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    if (!cert) {
        fprintf(stderr, "Failed to get current certificate\n");
        return 0;
    }

    // Extract SGX quote from the certificate
    echeck_quote_t *quote = extract_quote(cert);
    if (!quote) {
        fprintf(stderr, "No SGX quote found in certificate\n");
        return 0;
    }

    // Verify the quote
    echeck_verification_result_t result;
    int quote_verified = verify_quote(cert, quote, &result);

    // Optional: Check if MRENCLAVE/MRSIGNER matches expected values
    echeck_quote_info_t info;
    if (quote_verified && get_quote_info(quote, &info)) {
        // Example: Check if this is the enclave we're expecting
        // (In a real application, you would compare against your known good values)
        const uint8_t expected_mrenclave[32] = {
            /* Your expected MRENCLAVE value */
        };

        if (memcmp(info.mr_enclave, expected_mrenclave, 32) != 0) {
            fprintf(stderr, "MRENCLAVE doesn't match expected value\n");
            quote_verified = 0;
        }
    }

    // Cleanup
    free_quote(quote);

    return quote_verified;
}

// Create a TLS client with SGX quote verification
SSL_CTX* create_tls_client_context() {
    // Initialize OpenSSL libraries
    initialize_openssl();

    // Create a new TLS context
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        return NULL;
    }

    // Set the verification callback
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_certificate_callback);

    // Load trusted CA certificates
    if (SSL_CTX_load_verify_locations(ctx, "/path/to/ca/cert.pem", NULL) != 1) {
        fprintf(stderr, "Failed to load CA certificate\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

// Example usage in a TLS client application
int connect_to_tls_server(const char *hostname, int port) {
    // Create a TLS context with SGX quote verification
    SSL_CTX *ctx = create_tls_client_context();
    if (!ctx) return 1;

    // Create socket and SSL connection
    // ... (standard TLS connection code)

    // When performing the TLS handshake, our verify_certificate_callback
    // will be called to verify both the standard certificate
    // and the embedded SGX quote

    // SSL_connect(...);

    // ... (rest of your TLS client code)

    // Cleanup
    // SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
```

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

The tool includes a test framework to validate SGX quotes from certificates using CMake's testing functionality.

**Option 1**: Using the build script:
```
./build.sh test
```

**Option 2**: Using CMake's testing capabilities:
```
cd build
make run_tests     # Run all tests with nice output formatting
```

**Option 3**: Using CTest directly:
```
cd build
ctest              # Run all tests
ctest -V           # Run all tests with verbose output
ctest -R test_sample  # Run specific test
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

## Library API Reference

The echeck library provides a simple API for working with SGX quotes in X.509 certificates:

### Core Functions

#### `int initialize_openssl(void)`
Initialize the OpenSSL library. Call this before using any other functions.
- Returns: 1 on success, 0 on failure

#### `void* load_certificate(const char *file_path)`
Load an X.509 certificate from a PEM file.
- Parameters:
  - `file_path`: Path to the PEM certificate file
- Returns: Certificate handle on success, NULL on failure

#### `void free_certificate(void *cert)`
Free a certificate that was loaded with `load_certificate`.
- Parameters:
  - `cert`: Certificate handle returned by `load_certificate`

### Quote Handling Functions

#### `echeck_quote_t* extract_quote(void *cert)`
Extract an SGX quote from a certificate.
- Parameters:
  - `cert`: Certificate handle
- Returns: Quote handle on success, NULL if no quote was found or on error

#### `void free_quote(echeck_quote_t *quote)`
Free a quote that was extracted with `extract_quote`.
- Parameters:
  - `quote`: Quote handle returned by `extract_quote`

#### `int get_quote_info(echeck_quote_t *quote, echeck_quote_info_t *info)`
Extract information from an SGX quote into the provided structure.
- Parameters:
  - `quote`: Quote handle
  - `info`: Pointer to a structure that will be filled with quote information
- Returns: 1 on success, 0 on failure

### Verification Functions

#### `int verify_quote(void *cert, echeck_quote_t *quote, echeck_verification_result_t *result)`
Perform full verification of an SGX quote against its certificate, including signature verification, certificate chain verification, and attestation key verification.
- Parameters:
  - `cert`: Certificate handle
  - `quote`: Quote handle
  - `result`: Pointer to a structure that will be filled with verification results
- Returns: 1 if the verification succeeded, 0 if it failed

#### `int verify_quote_measurements(echeck_quote_t *quote, const uint8_t *expected_mrenclave, const uint8_t *expected_mrsigner)`
Verify the MRENCLAVE and/or MRSIGNER values of a quote against expected values.
- Parameters:
  - `quote`: Quote handle
  - `expected_mrenclave`: Expected MRENCLAVE value (32 bytes), or NULL to skip check
  - `expected_mrsigner`: Expected MRSIGNER value (32 bytes), or NULL to skip check
- Returns: 1 if all the provided values match, 0 otherwise

### Data Structures

#### `echeck_quote_info_t`
Structure containing information extracted from an SGX quote.
- Fields:
  - `uint8_t mr_enclave[32]`: MRENCLAVE value (32 bytes)
  - `uint8_t mr_signer[32]`: MRSIGNER value (32 bytes)
  - `uint16_t isv_prod_id`: ISV Product ID
  - `uint16_t isv_svn`: ISV Security Version Number

#### `echeck_verification_result_t`
Structure containing the results of quote verification.
- Fields:
  - `int valid`: 1 if the quote is valid, 0 if invalid
  - `char *error_message`: Error message if verification failed, NULL otherwise
  - `int mr_enclave_valid`: MRENCLAVE validation result
  - `int mr_signer_valid`: MRSIGNER validation result
  - `int signature_valid`: Quote signature validation result
  - `int quote_valid`: Overall quote format and data validation
  - `int report_data_matches_cert`: Report data matches certificate
  - `int cert_chain_valid`: Certificate chain validation result
  - `int checks_performed`: Number of checks performed
  - `int checks_passed`: Number of checks that passed

## Future Enhancements

- Integration with Intel Attestation Services for online verification
- Certificate revocation checking via OCSP or CRLs
- Support for custom verification policies
- Expanded API for more fine-grained control over verification process