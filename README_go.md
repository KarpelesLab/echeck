# echeck Go Library

A Go library for Intel SGX quote verification. This library provides functionality to extract and validate SGX quotes embedded in X.509 certificates.

## Features

- Extract SGX quotes from X.509 certificate extensions
- Parse SGX quote structures and report bodies
- Verify quote measurements (MRENCLAVE, MRSIGNER)
- Basic quote format validation
- Report data verification against certificate public keys

## Installation

```bash
go get github.com/KarpelesLab/echeck
```

## Usage

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

### Quote Verification

```go
// Verify the quote against the certificate
result, err := echeck.VerifyQuote(cert, quote)
if err != nil {
    log.Fatal(err)
}

if result.Valid {
    fmt.Println("Quote verification successful!")
} else {
    fmt.Printf("Quote verification failed: %s\n", result.ErrorMessage)
}

// Print detailed results
fmt.Printf("Report data matches cert: %t\n", result.ReportDataMatchesCert)
fmt.Printf("Quote format valid: %t\n", result.QuoteValid)
fmt.Printf("Certificate chain valid: %t\n", result.CertChainValid)
fmt.Printf("Checks performed: %d\n", result.ChecksPerformed)
fmt.Printf("Checks passed: %d\n", result.ChecksPassed)
```

### Measurement Verification

```go
// Expected measurements (32 bytes each)
expectedMREnclave := []byte{0x01, 0x02, 0x03, /* ... */}
expectedMRSigner := []byte{0x04, 0x05, 0x06, /* ... */}

// Verify measurements
if quote.VerifyMeasurements(expectedMREnclave, expectedMRSigner) {
    fmt.Println("Measurements match expected values")
} else {
    fmt.Println("Measurements do not match")
}

// You can also verify only one measurement by passing nil for the other
if quote.VerifyMeasurements(expectedMREnclave, nil) {
    fmt.Println("MRENCLAVE matches")
}
```

### Certificate Chain Verification

```go
// Extract PCK certificate chain from the quote
pckChain, err := quote.ExtractPCKCertChain()
if err != nil {
    log.Fatal(err)
}

// Verify against Intel's trusted CAs (built-in)
err = pckChain.VerifyWithIntelCAs()
if err != nil {
    fmt.Printf("Certificate chain verification failed: %v\n", err)
} else {
    fmt.Println("Certificate chain verification successful!")
}

// Or use a custom certificate pool
pool, err := echeck.GetIntelSGXCertPool()
if err != nil {
    log.Fatal(err)
}

// Add additional trusted certificates if needed
// pool.AddCert(additionalCert)

err = pckChain.VerifyCertificateChain(pool)
if err != nil {
    fmt.Printf("Certificate chain verification failed: %v\n", err)
} else {
    fmt.Println("Certificate chain verification successful!")
}
```

## API Reference

### Types

#### `QuoteInfo`
Contains essential measurements extracted from an SGX quote:
- `MREnclave [32]byte` - MRENCLAVE value
- `MRSigner [32]byte` - MRSIGNER value  
- `ISVProdID uint16` - ISV Product ID
- `ISVSVN uint16` - ISV SVN (Security Version Number)
- `ReportData [64]byte` - Report data from the quote

#### `VerificationResult`
Contains detailed verification results:
- `Valid bool` - Overall validation result
- `ErrorMessage string` - Error message if validation failed
- `ReportDataMatchesCert bool` - Report data matches certificate public key hash
- `QuoteValid bool` - Quote format and data validation
- `CertChainValid bool` - Certificate chain validation result
- `ChecksPerformed int` - Number of checks performed
- `ChecksPassed int` - Number of checks that passed

#### `Quote`
Represents an extracted SGX quote:
- `RawData []byte` - Raw quote data
- `Quote SGXQuote` - Parsed quote structure

#### `PCKCertChain`
Represents the extracted PCK certificate chain from a quote:
- `PCKCert *x509.Certificate` - Leaf PCK certificate
- `IntermediateCert *x509.Certificate` - Intermediate certificate (optional)
- `Certificates []*x509.Certificate` - All certificates in the chain

### Functions

#### `ExtractQuote(cert *x509.Certificate) (*Quote, error)`
Extracts an SGX quote from an X.509 certificate.

#### `VerifyQuote(cert *x509.Certificate, quote *Quote) (*VerificationResult, error)`
Performs comprehensive verification of an SGX quote against its certificate.

#### `GetIntelSGXCertPool() (*x509.CertPool, error)`
Returns a certificate pool pre-initialized with Intel's SGX Root CA.

#### `(q *Quote) GetQuoteInfo() QuoteInfo`
Extracts essential information from a quote.

#### `(q *Quote) VerifyMeasurements(expectedMREnclave, expectedMRSigner []byte) bool`
Verifies a quote against expected MRENCLAVE and MRSIGNER values.

#### `(q *Quote) ExtractPCKCertChain() (*PCKCertChain, error)`
Extracts the PCK certificate chain from an SGX quote's signature data.

#### `(chain *PCKCertChain) VerifyCertificateChain(trustedCAs *x509.CertPool) error`
Verifies the PCK certificate chain against trusted Intel CAs.

#### `(chain *PCKCertChain) VerifyWithIntelCAs() error`
Verifies the PCK certificate chain against Intel's built-in trusted CAs.

## Testing

Run the test suite:

```bash
go test
```

Run benchmarks:

```bash
go test -bench=.
```

## Limitations

This is a basic implementation focused on quote extraction and basic validation. Advanced features like full ECDSA signature verification and complete certificate chain validation are planned for future releases.

Currently implemented:
- ✅ SGX quote extraction from certificates
- ✅ Quote structure parsing
- ✅ Basic format validation
- ✅ Report data verification against certificate public keys
- ✅ Measurement verification
- ✅ PCK certificate chain extraction from quotes
- ✅ Certificate chain validation against Intel's trusted CAs
- ✅ Built-in Intel SGX Root CA certificate pool

Planned for future releases:
- ⏳ Full ECDSA signature verification
- ⏳ Advanced SGX quote types support

## License

This project is licensed under the same terms as the parent echeck project.