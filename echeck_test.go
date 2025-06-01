package echeck

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
)

// loadTestCertificate loads a test certificate from a PEM file
func loadTestCertificate(filename string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, err
	}

	return x509.ParseCertificate(block.Bytes)
}

func TestExtractQuoteWithSample(t *testing.T) {
	// Test with sample certificate
	cert, err := loadTestCertificate("test/sample.pem")
	if err != nil {
		t.Skipf("Skipping test - sample certificate not found: %v", err)
		return
	}

	quote, err := ExtractQuote(cert)
	if err != nil {
		t.Fatalf("Quote extraction failed: %v", err)
	}

	if quote == nil {
		t.Fatal("Expected non-nil quote")
	}

	// Validate quote structure
	if len(quote.RawData) < 432 {
		t.Errorf("Quote data too small: %d bytes", len(quote.RawData))
	}

	if quote.Quote.Version != 3 {
		t.Errorf("Expected quote version 3, got %d", quote.Quote.Version)
	}

	// Get quote information and verify it matches expected values from C version
	info := quote.GetQuoteInfo()
	expectedMREnclave := "df2493c11fc01708af6913323b64e20ae84b12779dbe44ba428da66dfc4488f5"
	expectedMRSigner := "976aa9f931b8a16e01e01895d627e3ee96dce5478ebbbc77e120a25c79fe6016"
	
	if fmt.Sprintf("%x", info.MREnclave) != expectedMREnclave {
		t.Errorf("Unexpected MRENCLAVE: got %x, expected %s", info.MREnclave, expectedMREnclave)
	}
	
	if fmt.Sprintf("%x", info.MRSigner) != expectedMRSigner {
		t.Errorf("Unexpected MRSIGNER: got %x, expected %s", info.MRSigner, expectedMRSigner)
	}

	if info.ISVProdID != 1 {
		t.Errorf("Expected ISV Product ID 1, got %d", info.ISVProdID)
	}

	if info.ISVSVN != 1 {
		t.Errorf("Expected ISV SVN 1, got %d", info.ISVSVN)
	}
}

func TestExtractQuoteNilCert(t *testing.T) {
	_, err := ExtractQuote(nil)
	if err == nil {
		t.Error("Expected error for nil certificate")
	}
}

func TestGetQuoteInfo(t *testing.T) {
	// Create a mock quote with known values
	quote := &Quote{
		Quote: SGXQuote{
			ReportBody: SGXReportBody{
				MREnclave: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
				MRSigner:  [32]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
				ISVProdID: 0x1234,
				ISVSVN:    0x5678,
			},
		},
	}

	info := quote.GetQuoteInfo()

	// Verify the extracted information
	if info.MREnclave != quote.Quote.ReportBody.MREnclave {
		t.Error("MREnclave mismatch")
	}

	if info.MRSigner != quote.Quote.ReportBody.MRSigner {
		t.Error("MRSigner mismatch")
	}

	if info.ISVProdID != 0x1234 {
		t.Errorf("Expected ISVProdID 0x1234, got 0x%x", info.ISVProdID)
	}

	if info.ISVSVN != 0x5678 {
		t.Errorf("Expected ISVSVN 0x5678, got 0x%x", info.ISVSVN)
	}
}

func TestVerifyMeasurements(t *testing.T) {
	expectedMREnclave := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	expectedMRSigner := []byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	quote := &Quote{
		Quote: SGXQuote{
			ReportBody: SGXReportBody{
				MREnclave: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
				MRSigner:  [32]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
			},
		},
	}

	// Test matching measurements
	if !quote.VerifyMeasurements(expectedMREnclave, expectedMRSigner) {
		t.Error("Expected measurements to match")
	}

	// Test with nil values (should pass)
	if !quote.VerifyMeasurements(nil, nil) {
		t.Error("Expected verification to pass with nil measurements")
	}

	// Test with only MRENCLAVE
	if !quote.VerifyMeasurements(expectedMREnclave, nil) {
		t.Error("Expected MRENCLAVE-only verification to pass")
	}

	// Test with only MRSIGNER
	if !quote.VerifyMeasurements(nil, expectedMRSigner) {
		t.Error("Expected MRSIGNER-only verification to pass")
	}

	// Test with wrong MRENCLAVE
	wrongMREnclave := make([]byte, 32)
	if quote.VerifyMeasurements(wrongMREnclave, expectedMRSigner) {
		t.Error("Expected verification to fail with wrong MRENCLAVE")
	}

	// Test with wrong MRSIGNER
	wrongMRSigner := make([]byte, 32)
	if quote.VerifyMeasurements(expectedMREnclave, wrongMRSigner) {
		t.Error("Expected verification to fail with wrong MRSIGNER")
	}

	// Test with invalid length
	if quote.VerifyMeasurements([]byte{1, 2, 3}, nil) {
		t.Error("Expected verification to fail with invalid MRENCLAVE length")
	}
}

func TestVerifyQuoteNilInputs(t *testing.T) {
	_, err := VerifyQuote(nil, nil)
	if err == nil {
		t.Error("Expected error for nil inputs")
	}
}

func TestParseQuoteInvalidData(t *testing.T) {
	// Test with empty data
	_, err := parseQuote([]byte{})
	if err == nil {
		t.Error("Expected error for empty data")
	}

	// Test with insufficient data
	_, err = parseQuote([]byte{1, 2, 3, 4})
	if err == nil {
		t.Error("Expected error for insufficient data")
	}
}

func TestParseReportBodyInvalidData(t *testing.T) {
	var reportBody SGXReportBody

	// Test with insufficient data
	err := parseReportBody([]byte{1, 2, 3, 4}, &reportBody)
	if err == nil {
		t.Error("Expected error for insufficient data")
	}

	// Test with exactly 384 bytes (should work)
	validData := make([]byte, 384)
	err = parseReportBody(validData, &reportBody)
	if err != nil {
		t.Errorf("Expected no error for valid data, got: %v", err)
	}
}

func TestCertificateChainVerificationWithSample(t *testing.T) {
	// Load sample certificate
	cert, err := loadTestCertificate("test/sample.pem")
	if err != nil {
		t.Skipf("Skipping test - sample certificate not found: %v", err)
		return
	}

	// Extract quote
	quote, err := ExtractQuote(cert)
	if err != nil {
		t.Fatalf("Quote extraction failed: %v", err)
	}

	// Extract PCK certificate chain
	pckChain, err := quote.ExtractPCKCertChain()
	if err != nil {
		t.Fatalf("PCK certificate chain extraction failed: %v", err)
	}

	// Verify we have the expected certificates
	if len(pckChain.Certificates) != 2 {
		t.Errorf("Expected 2 certificates, got %d", len(pckChain.Certificates))
	}

	if pckChain.PCKCert == nil {
		t.Fatal("Expected non-nil PCK certificate")
	}

	if pckChain.IntermediateCert == nil {
		t.Fatal("Expected non-nil intermediate certificate")
	}

	// Verify certificate subjects match expected values
	expectedPCKSubject := "CN=Intel SGX PCK Processor CA,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"
	expectedIntermediateSubject := "CN=Intel SGX Root CA,O=Intel Corporation,L=Santa Clara,ST=CA,C=US"

	if pckChain.PCKCert.Subject.String() != expectedPCKSubject {
		t.Errorf("Unexpected PCK cert subject: %s", pckChain.PCKCert.Subject.String())
	}

	if pckChain.IntermediateCert.Subject.String() != expectedIntermediateSubject {
		t.Errorf("Unexpected intermediate cert subject: %s", pckChain.IntermediateCert.Subject.String())
	}

	// Verify certificate chain against Intel CAs
	err = pckChain.VerifyWithIntelCAs()
	if err != nil {
		t.Errorf("Certificate chain verification failed: %v", err)
	}
}

func TestCompleteVerificationWithSample(t *testing.T) {
	// Load sample certificate
	cert, err := loadTestCertificate("test/sample.pem")
	if err != nil {
		t.Skipf("Skipping test - sample certificate not found: %v", err)
		return
	}

	// Extract quote
	quote, err := ExtractQuote(cert)
	if err != nil {
		t.Fatalf("Quote extraction failed: %v", err)
	}

	// Perform complete verification
	result, err := VerifyQuote(cert, quote)
	if err != nil {
		t.Fatalf("VerifyQuote failed: %v", err)
	}

	// Verify all checks pass
	if !result.Valid {
		t.Errorf("Expected verification to pass, but got: %s", result.ErrorMessage)
	}

	if !result.ReportDataMatchesCert {
		t.Error("Expected report data to match certificate")
	}

	if !result.QuoteValid {
		t.Error("Expected quote to be valid")
	}

	if !result.CertChainValid {
		t.Error("Expected certificate chain to be valid")
	}

	if result.ChecksPerformed != 4 {
		t.Errorf("Expected 4 checks performed, got %d", result.ChecksPerformed)
	}

	if result.ChecksPassed != 3 {
		t.Errorf("Expected 3 checks passed, got %d", result.ChecksPassed)
	}
}

// Benchmark tests
func BenchmarkExtractQuote(b *testing.B) {
	cert, err := loadTestCertificate("test/sample.pem")
	if err != nil {
		b.Skip("Sample certificate not found")
		return
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractQuote(cert)
	}
}

func BenchmarkVerifyQuote(b *testing.B) {
	cert, err := loadTestCertificate("test/sample.pem")
	if err != nil {
		b.Skip("Sample certificate not found")
		return
	}

	quote, err := ExtractQuote(cert)
	if err != nil {
		b.Skip("Quote extraction failed")
		return
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyQuote(cert, quote)
	}
}