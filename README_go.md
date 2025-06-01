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
err = echeck.VerifyQuote(cert, quote)
if err != nil {
    // Check for specific error types
    var reportErr echeck.ErrReportDataMismatch
    var formatErr echeck.ErrInvalidQuoteFormat
    var certErr echeck.ErrCertChainVerification
    
    if errors.As(err, &reportErr) {
        fmt.Printf("Report data mismatch: %v\n", reportErr)
    } else if errors.As(err, &formatErr) {
        fmt.Printf("Invalid quote format: %v\n", formatErr)
    } else if errors.As(err, &certErr) {
        fmt.Printf("Certificate chain error: %v\n", certErr)
    } else {
        fmt.Printf("Verification failed: %v\n", err)
    }
    return
}

fmt.Println("Quote verification successful!")
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

#### Error Types

The library uses specific error types for different verification failures:

**`ErrReportDataMismatch`**
Indicates the report data doesn't match the certificate's public key hash:
- `Expected []byte` - Expected hash value
- `Actual []byte` - Actual report data

**`ErrInvalidQuoteFormat`**
Indicates the quote format or version is invalid:
- `Version uint16` - Quote version found
- `Size int` - Quote data size

**`ErrCertChainVerification`**
Indicates certificate chain verification failed:
- `Reason string` - Detailed error reason

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

#### `VerifyQuote(cert *x509.Certificate, quote *Quote) error`
Performs comprehensive verification of an SGX quote against its certificate. Returns nil on success, or a specific error type on failure.

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