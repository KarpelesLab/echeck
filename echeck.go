// Package echeck provides Intel SGX quote verification for Go applications.
// It can extract and validate SGX quotes embedded in X.509 certificates.
package echeck

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

const (
	// SGXQuoteOID is the OID for Intel SGX quote extensions in X.509 certificates
	SGXQuoteOID = "1.3.6.1.4.1.311.105.1"
)

// QuoteInfo contains the essential measurements extracted from an SGX quote
type QuoteInfo struct {
	MREnclave  [32]byte // MRENCLAVE value (32 bytes)
	MRSigner   [32]byte // MRSIGNER value (32 bytes)
	ISVProdID  uint16   // ISV Product ID
	ISVSVN     uint16   // ISV SVN (Security Version Number)
	ReportData [64]byte // Report data from the quote
}

// Specific error types for different verification failures

// ErrReportDataMismatch indicates the report data doesn't match the certificate's public key hash
type ErrReportDataMismatch struct {
	Expected []byte
	Actual   []byte
}

func (e ErrReportDataMismatch) Error() string {
	return fmt.Sprintf("report data does not match certificate public key hash: expected %x, got %x", e.Expected[:32], e.Actual[:32])
}

// ErrInvalidQuoteFormat indicates the quote format or version is invalid
type ErrInvalidQuoteFormat struct {
	Version uint16
	Size    int
}

func (e ErrInvalidQuoteFormat) Error() string {
	return fmt.Sprintf("invalid quote format: version %d, size %d bytes", e.Version, e.Size)
}

// ErrCertChainVerification indicates certificate chain verification failed
type ErrCertChainVerification struct {
	Reason string
}

func (e ErrCertChainVerification) Error() string {
	return fmt.Sprintf("certificate chain verification failed: %s", e.Reason)
}

// SGXQuoteHeader represents the header structure that precedes SGX quote data
type SGXQuoteHeader struct {
	Version  uint32 // Version of the header structure
	Type     uint32 // Type of quote or data that follows
	Size     uint32 // Size of the data after this header
	Reserved uint32 // Reserved field, possibly for alignment or future use
}

// SGXReportBody represents the SGX report body structure (384 bytes)
type SGXReportBody struct {
	CPUSVN       [16]byte // Security Version of the CPU
	MiscSelect   uint32   // Which fields defined in SSA.MISC
	Reserved1    [12]byte // Reserved field 1
	ISVExtProdID [16]byte // ISV assigned Extended Product ID
	Attributes   [16]byte // Any special Capabilities the Enclave possess
	MREnclave    [32]byte // The value of the enclave's ENCLAVE measurement
	Reserved2    [32]byte // Reserved field 2
	MRSigner     [32]byte // The value of the enclave's SIGNER measurement
	Reserved3    [32]byte // Reserved field 3
	ConfigID     [64]byte // CONFIGID
	ISVProdID    uint16   // Product ID of the Enclave
	ISVSVN       uint16   // Security Version of the Enclave
	ConfigSVN    uint16   // CONFIGSVN
	Reserved4    [42]byte // Reserved field 4
	ISVFamilyID  [16]byte // ISV assigned Family ID
	ReportData   [64]byte // Data provided by the user
}

// SGXQuote represents the complete SGX quote structure
type SGXQuote struct {
	Version       uint16        // Quote version
	SignType      uint16        // Signature type
	EPIDGroupID   [4]byte       // EPID Group ID
	QESVN         uint16        // QE SVN
	PCESVN        uint16        // PCE SVN
	XEID          uint32        // Extended Enclave ID
	Basename      [32]byte      // Basename
	ReportBody    SGXReportBody // Report body (384 bytes)
	SignatureLen  uint32        // Length of signature data
	SignatureData []byte        // Variable-length signature data
}

// SGXECDSASignatureData represents the ECDSA signature data structure for SGX quotes
type SGXECDSASignatureData struct {
	Signature         [64]byte      // ECDSA signature (r=32 bytes, s=32 bytes)
	AttestationPubKey [64]byte      // Attestation public key (x=32 bytes, y=32 bytes)
	QEReport          SGXReportBody // QE report (384 bytes)
	QEReportSignature [64]byte      // QE report signature (64 bytes)
	// Additional authentication data follows...
}

// Quote represents an extracted SGX quote with its raw data
type Quote struct {
	RawData []byte   // Raw quote data
	Quote   SGXQuote // Parsed quote structure
}

// ExtractQuote extracts an SGX quote from an X.509 certificate
func ExtractQuote(cert *x509.Certificate) (*Quote, error) {
	if cert == nil {
		return nil, errors.New("certificate is nil")
	}

	// Look for the SGX quote extension
	var quoteData []byte
	for _, ext := range cert.Extensions {
		if ext.Id.String() == SGXQuoteOID {
			quoteData = ext.Value
			break
		}
	}

	if quoteData == nil {
		return nil, errors.New("SGX quote extension not found in certificate")
	}

	// The quote extension data may be directly the raw bytes or wrapped in ASN.1
	// Try direct parsing first, then ASN.1 if that fails
	var rawQuoteData []byte
	
	// First try to parse as ASN.1 OCTET STRING
	if _, err := asn1.Unmarshal(quoteData, &rawQuoteData); err != nil {
		// If ASN.1 parsing fails, use the raw extension data directly
		rawQuoteData = quoteData
	}

	// Check if we have at least enough data for the header
	if len(rawQuoteData) < 16 { // sizeof(SGXQuoteHeader)
		return nil, errors.New("SGX quote data too short for header")
	}

	// Parse the header
	header := SGXQuoteHeader{
		Version:  binary.LittleEndian.Uint32(rawQuoteData[0:4]),
		Type:     binary.LittleEndian.Uint32(rawQuoteData[4:8]),
		Size:     binary.LittleEndian.Uint32(rawQuoteData[8:12]),
		Reserved: binary.LittleEndian.Uint32(rawQuoteData[12:16]),
	}

	// Verify the size makes sense
	if header.Size > uint32(len(rawQuoteData)-16) {
		return nil, fmt.Errorf("SGX quote size in header (%d) exceeds available data (%d)", header.Size, len(rawQuoteData)-16)
	}

	// Extract the actual quote data (after the header)
	actualQuoteData := rawQuoteData[16 : 16+header.Size]

	// Parse the SGX quote structure
	quote, err := parseQuote(actualQuoteData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SGX quote: %v", err)
	}

	return &Quote{
		RawData: actualQuoteData,
		Quote:   *quote,
	}, nil
}

// parseQuote parses raw quote data into an SGXQuote structure
func parseQuote(data []byte) (*SGXQuote, error) {
	// Check minimum size for the fixed part of the quote
	minSize := 2 + 2 + 4 + 2 + 2 + 4 + 32 + 384 + 4 // up to signature_len field
	if len(data) < minSize {
		return nil, fmt.Errorf("quote data too short: %d bytes, need at least %d", len(data), minSize)
	}

	quote := &SGXQuote{}
	offset := 0

	// Parse fixed fields
	quote.Version = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	quote.SignType = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	copy(quote.EPIDGroupID[:], data[offset:offset+4])
	offset += 4

	quote.QESVN = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	quote.PCESVN = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	quote.XEID = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	copy(quote.Basename[:], data[offset:offset+32])
	offset += 32

	// Parse report body (384 bytes)
	if err := parseReportBody(data[offset:offset+384], &quote.ReportBody); err != nil {
		return nil, fmt.Errorf("failed to parse report body: %v", err)
	}
	offset += 384

	// Parse signature length
	quote.SignatureLen = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Parse signature data
	if offset+int(quote.SignatureLen) > len(data) {
		return nil, fmt.Errorf("signature length (%d) exceeds remaining data (%d)", quote.SignatureLen, len(data)-offset)
	}

	quote.SignatureData = make([]byte, quote.SignatureLen)
	copy(quote.SignatureData, data[offset:offset+int(quote.SignatureLen)])

	return quote, nil
}

// parseReportBody parses the SGX report body structure
func parseReportBody(data []byte, reportBody *SGXReportBody) error {
	if len(data) < 384 {
		return fmt.Errorf("report body data too short: %d bytes, need 384", len(data))
	}

	offset := 0

	copy(reportBody.CPUSVN[:], data[offset:offset+16])
	offset += 16

	reportBody.MiscSelect = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	copy(reportBody.Reserved1[:], data[offset:offset+12])
	offset += 12

	copy(reportBody.ISVExtProdID[:], data[offset:offset+16])
	offset += 16

	copy(reportBody.Attributes[:], data[offset:offset+16])
	offset += 16

	copy(reportBody.MREnclave[:], data[offset:offset+32])
	offset += 32

	copy(reportBody.Reserved2[:], data[offset:offset+32])
	offset += 32

	copy(reportBody.MRSigner[:], data[offset:offset+32])
	offset += 32

	copy(reportBody.Reserved3[:], data[offset:offset+32])
	offset += 32

	copy(reportBody.ConfigID[:], data[offset:offset+64])
	offset += 64

	reportBody.ISVProdID = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	reportBody.ISVSVN = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	reportBody.ConfigSVN = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2

	copy(reportBody.Reserved4[:], data[offset:offset+42])
	offset += 42

	copy(reportBody.ISVFamilyID[:], data[offset:offset+16])
	offset += 16

	copy(reportBody.ReportData[:], data[offset:offset+64])

	return nil
}

// GetQuoteInfo extracts the essential information from a quote
func (q *Quote) GetQuoteInfo() QuoteInfo {
	return QuoteInfo{
		MREnclave:  q.Quote.ReportBody.MREnclave,
		MRSigner:   q.Quote.ReportBody.MRSigner,
		ISVProdID:  q.Quote.ReportBody.ISVProdID,
		ISVSVN:     q.Quote.ReportBody.ISVSVN,
		ReportData: q.Quote.ReportBody.ReportData,
	}
}

// VerifyMeasurements verifies a quote against expected MRENCLAVE and MRSIGNER values
func (q *Quote) VerifyMeasurements(expectedMREnclave, expectedMRSigner []byte) bool {
	if expectedMREnclave != nil {
		if len(expectedMREnclave) != 32 {
			return false
		}
		for i := 0; i < 32; i++ {
			if q.Quote.ReportBody.MREnclave[i] != expectedMREnclave[i] {
				return false
			}
		}
	}

	if expectedMRSigner != nil {
		if len(expectedMRSigner) != 32 {
			return false
		}
		for i := 0; i < 32; i++ {
			if q.Quote.ReportBody.MRSigner[i] != expectedMRSigner[i] {
				return false
			}
		}
	}

	return true
}

// VerifyECDSASignature verifies the ECDSA signature of the quote
func (q *Quote) VerifyECDSASignature() error {
	if q.Quote.Version != 3 {
		return fmt.Errorf("ECDSA signature verification only supported for quote version 3, got %d", q.Quote.Version)
	}

	if len(q.Quote.SignatureData) < 64+64+384+64 {
		return fmt.Errorf("signature data too short for ECDSA format: %d bytes", len(q.Quote.SignatureData))
	}

	// Extract signature components from signature data
	sigData := q.Quote.SignatureData
	sigR := sigData[0:32]
	sigS := sigData[32:64]

	// Extract attestation public key
	pubKeyX := sigData[64:96]
	pubKeyY := sigData[96:128]

	// Create the attestation public key
	pubKey, err := q.createAttestationPublicKey(pubKeyX, pubKeyY)
	if err != nil {
		return fmt.Errorf("failed to create attestation public key: %v", err)
	}

	// Compute the quote hash for signature verification
	quoteHash, err := q.computeQuoteHash()
	if err != nil {
		return fmt.Errorf("failed to compute quote hash: %v", err)
	}

	// Verify the ECDSA signature
	if err := q.verifyECDSASignature(quoteHash, sigR, sigS, pubKey); err != nil {
		return fmt.Errorf("ECDSA signature verification failed: %v", err)
	}

	return nil
}

// createAttestationPublicKey creates an ECDSA public key from X,Y coordinates
func (q *Quote) createAttestationPublicKey(pubKeyX, pubKeyY []byte) (*ecdsa.PublicKey, error) {
	if len(pubKeyX) != 32 || len(pubKeyY) != 32 {
		return nil, fmt.Errorf("invalid public key coordinate length: x=%d, y=%d", len(pubKeyX), len(pubKeyY))
	}

	// Convert byte arrays to big integers
	x := new(big.Int).SetBytes(pubKeyX)
	y := new(big.Int).SetBytes(pubKeyY)

	// Create the public key using P-256 curve (secp256r1)
	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// Verify the public key is on the curve
	if !pubKey.Curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("public key coordinates are not on the P-256 curve")
	}

	return pubKey, nil
}

// computeQuoteHash computes SHA-256 hash of the quote data up to (but not including) signature_len field
func (q *Quote) computeQuoteHash() ([]byte, error) {
	// For ECDSA quotes, the hash is computed over everything up to but not including signature_len
	// Quote structure: version(2) + sign_type(2) + epid_group_id(4) + qe_svn(2) + pce_svn(2) + 
	//                  xeid(4) + basename(32) + report_body(384) = 432 bytes
	
	if len(q.RawData) < 432 {
		return nil, fmt.Errorf("quote data too short for hash computation: %d bytes", len(q.RawData))
	}

	// Hash the first 432 bytes (everything up to signature_len field)
	hashData := q.RawData[0:432]
	hash := sha256.Sum256(hashData)
	
	return hash[:], nil
}

// verifyECDSASignature verifies the ECDSA signature using the provided parameters
func (q *Quote) verifyECDSASignature(hash, sigR, sigS []byte, pubKey *ecdsa.PublicKey) error {
	if len(sigR) != 32 || len(sigS) != 32 {
		return fmt.Errorf("invalid signature component length: r=%d, s=%d", len(sigR), len(sigS))
	}

	// Convert signature components to big integers
	r := new(big.Int).SetBytes(sigR)
	s := new(big.Int).SetBytes(sigS)

	// Verify the signature
	valid := ecdsa.Verify(pubKey, hash, r, s)
	if !valid {
		return fmt.Errorf("ECDSA signature verification failed")
	}

	return nil
}

// VerifyAttestationKey verifies that the attestation key in the quote can be properly extracted
// and is a valid ECDSA key. The PCK certificate verification (Intel's authority) is handled separately.
func (q *Quote) VerifyAttestationKey() error {
	if q.Quote.Version != 3 {
		return fmt.Errorf("attestation key verification only supported for quote version 3, got %d", q.Quote.Version)
	}

	if len(q.Quote.SignatureData) < 64+64 {
		return fmt.Errorf("signature data too short for attestation key extraction: %d bytes", len(q.Quote.SignatureData))
	}

	// Extract attestation public key from quote signature data
	sigData := q.Quote.SignatureData
	pubKeyX := sigData[64:96]
	pubKeyY := sigData[96:128]

	// Create the attestation public key from the quote - this validates it's a proper ECDSA key
	_, err := q.createAttestationPublicKey(pubKeyX, pubKeyY)
	if err != nil {
		return fmt.Errorf("failed to create attestation public key from quote: %v", err)
	}

	// Attestation key is valid and extractable
	return nil
}

// ComputePublicKeyHash computes SHA-256 hash of a public key in DER format
func ComputePublicKeyHash(pubKeyDER []byte) []byte {
	hash := sha256.Sum256(pubKeyDER)
	return hash[:]
}

// VerifyQuote performs comprehensive verification of an SGX quote against its certificate.
// Returns nil if verification succeeds, or a specific error if any check fails.
func VerifyQuote(cert *x509.Certificate, quote *Quote) error {
	if cert == nil || quote == nil {
		return errors.New("certificate or quote is nil")
	}

	// Step 1: Verify that the report data matches the certificate's public key hash
	pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}

	pubKeyHash := sha256.Sum256(pubKeyDER)

	// Check if the first 32 bytes of report data match the public key hash
	for i := 0; i < 32; i++ {
		if quote.Quote.ReportBody.ReportData[i] != pubKeyHash[i] {
			return ErrReportDataMismatch{
				Expected: pubKeyHash[:],
				Actual:   quote.Quote.ReportBody.ReportData[:],
			}
		}
	}

	// Verify the remaining bytes (32-63) of report data are zero (padding)
	for i := 32; i < 64; i++ {
		if quote.Quote.ReportBody.ReportData[i] != 0 {
			return fmt.Errorf("non-zero padding found in report data at position %d: 0x%02x", i, quote.Quote.ReportBody.ReportData[i])
		}
	}

	// Step 2: Basic quote validation
	if quote.Quote.Version < 3 || len(quote.RawData) <= 432 {
		return ErrInvalidQuoteFormat{
			Version: quote.Quote.Version,
			Size:    len(quote.RawData),
		}
	}

	// Step 3: ECDSA signature verification - proves quote authenticity
	// This verifies the cryptographic signature that proves the SGX enclave generated this quote
	if quote.Quote.Version == 3 {
		if err := quote.VerifyECDSASignature(); err != nil {
			return fmt.Errorf("ECDSA signature verification failed: %v", err)
		}
	}

	// Step 4: PCK certificate chain validation - establishes Intel's authority
	// This proves the quote came from genuine Intel SGX hardware certified by Intel
	pckChain, err := quote.ExtractPCKCertChain()
	if err != nil {
		return ErrCertChainVerification{
			Reason: fmt.Sprintf("failed to extract PCK certificate chain: %v", err),
		}
	}

	// Verify the PCK certificate chain against Intel's trusted CAs
	if err := pckChain.VerifyWithIntelCAs(); err != nil {
		return ErrCertChainVerification{
			Reason: err.Error(),
		}
	}

	// Step 5: Verify attestation key is valid and extractable
	if quote.Quote.Version == 3 {
		if err := quote.VerifyAttestationKey(); err != nil {
			return fmt.Errorf("attestation key verification failed: %v", err)
		}
	}

	// All verification steps passed
	return nil
}