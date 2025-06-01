# API Examples

This document provides comprehensive examples for using both the C library and Go library APIs.

## C Library Examples

### Basic Quote Extraction and Verification

```c
#include <echeck.h>
#include <stdio.h>

int main() {
    // Initialize OpenSSL
    if (!echeck_initialize()) {
        fprintf(stderr, "Failed to initialize OpenSSL\n");
        return 1;
    }

    // Load a certificate containing an SGX quote
    void *cert = echeck_load_certificate("/path/to/certificate.pem");
    if (!cert) {
        fprintf(stderr, "Failed to load certificate\n");
        return 1;
    }

    // Extract SGX quote from the certificate
    echeck_quote_t *quote = echeck_extract_quote(cert);
    if (!quote) {
        fprintf(stderr, "Failed to extract SGX quote\n");
        echeck_free_certificate(cert);
        return 1;
    }

    // Get the quote information
    echeck_quote_info_t info;
    if (!echeck_get_quote_info(quote, &info)) {
        fprintf(stderr, "Failed to get quote info\n");
        echeck_free_quote(quote);
        echeck_free_certificate(cert);
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
    if (!echeck_verify_quote(cert, quote, &result)) {
        fprintf(stderr, "Quote verification failed: %s\n",
                result.error_message ? result.error_message : "Unknown error");
        echeck_free_quote(quote);
        echeck_free_certificate(cert);
        return 1;
    }

    printf("Quote verification successful!\n");

    // Cleanup
    echeck_free_quote(quote);
    echeck_free_certificate(cert);
    return 0;
}
```

### Verifying Specific MRENCLAVE/MRSIGNER Values

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
    echeck_initialize();

    // Expected MRENCLAVE value (32 bytes)
    const char *expected_mrenclave_hex = "df2493c11fc01708af6913323b64e20ae84b12779dbe44ba428da66dfc4488f5";
    uint8_t expected_mrenclave[32];

    if (!hex_to_bin(expected_mrenclave_hex, expected_mrenclave, sizeof(expected_mrenclave))) {
        fprintf(stderr, "Invalid MRENCLAVE format\n");
        return 1;
    }

    // Load and extract quote
    void *cert = echeck_load_certificate("/path/to/certificate.pem");
    echeck_quote_t *quote = echeck_extract_quote(cert);

    // Verify with expected MRENCLAVE
    if (!echeck_verify_quote_measurements(quote, expected_mrenclave, NULL)) {
        fprintf(stderr, "MRENCLAVE value doesn't match expected value\n");
        echeck_free_quote(quote);
        echeck_free_certificate(cert);
        return 1;
    }

    printf("MRENCLAVE verified successfully\n");

    // Cleanup
    echeck_free_quote(quote);
    echeck_free_certificate(cert);
    return 0;
}
```

### Integration with TLS Connections

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
    echeck_quote_t *quote = echeck_extract_quote(cert);
    if (!quote) {
        fprintf(stderr, "No SGX quote found in certificate\n");
        return 0;
    }

    // Verify the quote
    echeck_verification_result_t result;
    int quote_verified = echeck_verify_quote(cert, quote, &result);

    // Optional: Check if MRENCLAVE/MRSIGNER matches expected values
    echeck_quote_info_t info;
    if (quote_verified && echeck_get_quote_info(quote, &info)) {
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
    echeck_free_quote(quote);

    return quote_verified;
}

// Create a TLS client with SGX quote verification
SSL_CTX* create_tls_client_context() {
    // Initialize OpenSSL libraries
    echeck_initialize();

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

## Go Library Examples

### Basic Quote Extraction

```go
package main

import (
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "log"
    "os"
    
    "github.com/KarpelesLab/echeck"
)

func main() {
    // Load certificate from file
    certPEM, err := os.ReadFile("certificate.pem")
    if err != nil {
        log.Fatal(err)
    }
    
    block, _ := pem.Decode(certPEM)
    if block == nil {
        log.Fatal("Failed to decode PEM certificate")
    }
    
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        log.Fatal(err)
    }
    
    // Extract SGX quote
    quote, err := echeck.ExtractQuote(cert)
    if err != nil {
        log.Fatal(err)
    }
    
    // Get quote information
    info := quote.GetQuoteInfo()
    fmt.Printf("MRENCLAVE: %x\n", info.MREnclave)
    fmt.Printf("MRSIGNER: %x\n", info.MRSigner)
    fmt.Printf("ISV Product ID: %d\n", info.ISVProdID)
    fmt.Printf("ISV SVN: %d\n", info.ISVSVN)
}
```

### Quote Verification with Error Handling

```go
package main

import (
    "crypto/x509"
    "encoding/pem"
    "errors"
    "fmt"
    "log"
    "os"
    
    "github.com/KarpelesLab/echeck"
)

func main() {
    // Load certificate
    certPEM, err := os.ReadFile("certificate.pem")
    if err != nil {
        log.Fatal(err)
    }
    
    block, _ := pem.Decode(certPEM)
    if block == nil {
        log.Fatal("Failed to decode PEM certificate")
    }
    
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        log.Fatal(err)
    }
    
    // Extract quote
    quote, err := echeck.ExtractQuote(cert)
    if err != nil {
        log.Fatal(err)
    }
    
    // Verify the quote against the certificate
    err = echeck.VerifyQuote(cert, quote)
    if err != nil {
        // Check for specific error types
        var reportErr echeck.ErrReportDataMismatch
        var formatErr echeck.ErrInvalidQuoteFormat
        var certErr echeck.ErrCertChainVerification
        
        if errors.As(err, &reportErr) {
            fmt.Printf("Report data mismatch: %v\n", reportErr)
            fmt.Printf("Expected: %x\n", reportErr.Expected[:32])
            fmt.Printf("Actual: %x\n", reportErr.Actual[:32])
        } else if errors.As(err, &formatErr) {
            fmt.Printf("Invalid quote format: version %d, size %d bytes\n", 
                formatErr.Version, formatErr.Size)
        } else if errors.As(err, &certErr) {
            fmt.Printf("Certificate chain verification failed: %s\n", certErr.Reason)
        } else {
            fmt.Printf("Verification failed: %v\n", err)
        }
        return
    }
    
    fmt.Println("Quote verification successful!")
}
```

### Measurement Verification

```go
package main

import (
    "encoding/hex"
    "fmt"
    "log"
    
    "github.com/KarpelesLab/echeck"
)

func main() {
    // Load certificate and extract quote (as shown above)
    cert, quote := loadCertificateAndQuote("certificate.pem")
    
    // Expected measurements from hex strings
    expectedMREnclaveHex := "df2493c11fc01708af6913323b64e20ae84b12779dbe44ba428da66dfc4488f5"
    expectedMRSignerHex := "976aa9f931b8a16e01e01895d627e3ee96dce5478ebbbc77e120a25c79fe6016"
    
    expectedMREnclave, err := hex.DecodeString(expectedMREnclaveHex)
    if err != nil {
        log.Fatal("Invalid MRENCLAVE hex:", err)
    }
    
    expectedMRSigner, err := hex.DecodeString(expectedMRSignerHex)
    if err != nil {
        log.Fatal("Invalid MRSIGNER hex:", err)
    }
    
    // Verify both measurements
    if quote.VerifyMeasurements(expectedMREnclave, expectedMRSigner) {
        fmt.Println("Both measurements match expected values")
    } else {
        fmt.Println("Measurements do not match")
        
        // Check individual measurements for more detail
        if quote.VerifyMeasurements(expectedMREnclave, nil) {
            fmt.Println("MRENCLAVE matches, but MRSIGNER does not")
        } else if quote.VerifyMeasurements(nil, expectedMRSigner) {
            fmt.Println("MRSIGNER matches, but MRENCLAVE does not")
        } else {
            fmt.Println("Neither measurement matches")
        }
    }
    
    // Display actual values for comparison
    info := quote.GetQuoteInfo()
    fmt.Printf("Actual MRENCLAVE: %x\n", info.MREnclave)
    fmt.Printf("Actual MRSIGNER: %x\n", info.MRSigner)
}
```

### Certificate Chain Verification

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/KarpelesLab/echeck"
)

func main() {
    // Load certificate and extract quote
    cert, quote := loadCertificateAndQuote("certificate.pem")
    
    // Extract PCK certificate chain from the quote
    pckChain, err := quote.ExtractPCKCertChain()
    if err != nil {
        log.Fatal("Failed to extract PCK certificate chain:", err)
    }
    
    fmt.Printf("Found %d certificates in the chain\n", len(pckChain.Certificates))
    
    // Display certificate subjects
    if pckChain.PCKCert != nil {
        fmt.Printf("PCK Certificate: %s\n", pckChain.PCKCert.Subject.String())
    }
    
    if pckChain.IntermediateCert != nil {
        fmt.Printf("Intermediate Certificate: %s\n", pckChain.IntermediateCert.Subject.String())
    }
    
    // Verify against Intel's trusted CAs (built-in)
    err = pckChain.VerifyWithIntelCAs()
    if err != nil {
        fmt.Printf("Certificate chain verification failed: %v\n", err)
    } else {
        fmt.Println("Certificate chain verification successful!")
    }
    
    // Alternative: Use a custom certificate pool
    pool, err := echeck.GetIntelSGXCertPool()
    if err != nil {
        log.Fatal("Failed to get Intel SGX certificate pool:", err)
    }
    
    // You can add additional trusted certificates if needed
    // pool.AddCert(additionalCert)
    
    err = pckChain.VerifyCertificateChain(pool)
    if err != nil {
        fmt.Printf("Custom certificate chain verification failed: %v\n", err)
    } else {
        fmt.Println("Custom certificate chain verification successful!")
    }
}
```

### Complete Verification Example

```go
package main

import (
    "crypto/x509"
    "encoding/hex"
    "encoding/pem"
    "fmt"
    "log"
    "os"
    
    "github.com/KarpelesLab/echeck"
)

func main() {
    // Load certificate
    cert := loadCertificate("certificate.pem")
    
    // Extract quote
    quote, err := echeck.ExtractQuote(cert)
    if err != nil {
        log.Fatal("Failed to extract quote:", err)
    }
    
    fmt.Printf("Quote version: %d\n", quote.Quote.Version)
    fmt.Printf("Quote signature length: %d bytes\n", quote.Quote.SignatureLen)
    
    // Get quote information
    info := quote.GetQuoteInfo()
    fmt.Printf("MRENCLAVE: %x\n", info.MREnclave)
    fmt.Printf("MRSIGNER: %x\n", info.MRSigner)
    fmt.Printf("ISV Product ID: %d\n", info.ISVProdID)
    fmt.Printf("ISV SVN: %d\n", info.ISVSVN)
    
    // Perform complete verification
    fmt.Println("\nPerforming complete verification...")
    
    err = echeck.VerifyQuote(cert, quote)
    if err != nil {
        log.Fatal("Quote verification failed:", err)
    }
    
    fmt.Println("✓ Complete quote verification successful!")
    
    // Optional: Verify against expected measurements
    expectedMREnclave, _ := hex.DecodeString("df2493c11fc01708af6913323b64e20ae84b12779dbe44ba428da66dfc4488f5")
    expectedMRSigner, _ := hex.DecodeString("976aa9f931b8a16e01e01895d627e3ee96dce5478ebbbc77e120a25c79fe6016")
    
    if quote.VerifyMeasurements(expectedMREnclave, expectedMRSigner) {
        fmt.Println("✓ Measurements match expected values")
    } else {
        fmt.Println("⚠ Measurements do not match expected values")
    }
}

// Helper function to load a certificate from a PEM file
func loadCertificate(filename string) *x509.Certificate {
    certPEM, err := os.ReadFile(filename)
    if err != nil {
        log.Fatal(err)
    }
    
    block, _ := pem.Decode(certPEM)
    if block == nil {
        log.Fatal("Failed to decode PEM certificate")
    }
    
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        log.Fatal(err)
    }
    
    return cert
}
```

### HTTP Client with SGX Verification

```go
package main

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "io"
    "net/http"
    
    "github.com/KarpelesLab/echeck"
)

// Custom certificate verification function for HTTP client
func verifySGXCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
    if len(rawCerts) == 0 {
        return fmt.Errorf("no certificates provided")
    }
    
    // Parse the leaf certificate
    cert, err := x509.ParseCertificate(rawCerts[0])
    if err != nil {
        return fmt.Errorf("failed to parse certificate: %v", err)
    }
    
    // Extract SGX quote
    quote, err := echeck.ExtractQuote(cert)
    if err != nil {
        return fmt.Errorf("failed to extract SGX quote: %v", err)
    }
    
    // Verify the quote
    err = echeck.VerifyQuote(cert, quote)
    if err != nil {
        return fmt.Errorf("SGX quote verification failed: %v", err)
    }
    
    fmt.Println("✓ SGX quote verification successful")
    return nil
}

func main() {
    // Create HTTP client with custom SGX verification
    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                VerifyPeerCertificate: verifySGXCertificate,
                ServerName:           "your-sgx-server.com",
            },
        },
    }
    
    // Make request to SGX-enabled server
    resp, err := client.Get("https://your-sgx-server.com/api/data")
    if err != nil {
        fmt.Printf("Request failed: %v\n", err)
        return
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        fmt.Printf("Failed to read response: %v\n", err)
        return
    }
    
    fmt.Printf("Response: %s\n", body)
}
```

## Error Handling Best Practices

### C Library Error Handling

```c
// Always check return values
echeck_verification_result_t result;
if (!echeck_verify_quote(cert, quote, &result)) {
    if (result.error_message) {
        fprintf(stderr, "Verification failed: %s\n", result.error_message);
    }
    
    // Check specific failure reasons
    if (!result.report_data_matches_cert) {
        fprintf(stderr, "Report data does not match certificate\n");
    }
    
    if (!result.signature_valid) {
        fprintf(stderr, "Quote signature is invalid\n");
    }
    
    if (!result.cert_chain_valid) {
        fprintf(stderr, "Certificate chain verification failed\n");
    }
    
    printf("Checks performed: %d, passed: %d\n", 
           result.checks_performed, result.checks_passed);
}
```

### Go Library Error Handling

```go
// Use typed errors for specific handling
err := echeck.VerifyQuote(cert, quote)
if err != nil {
    switch e := err.(type) {
    case echeck.ErrReportDataMismatch:
        fmt.Printf("Report data mismatch - expected %x, got %x\n", 
            e.Expected[:8], e.Actual[:8])
    case echeck.ErrInvalidQuoteFormat:
        fmt.Printf("Invalid quote format - version %d, size %d\n", 
            e.Version, e.Size)
    case echeck.ErrCertChainVerification:
        fmt.Printf("Certificate chain error: %s\n", e.Reason)
    default:
        fmt.Printf("Verification failed: %v\n", err)
    }
}
```

These examples demonstrate comprehensive usage of both the C and Go libraries for various SGX quote verification scenarios.