package echeck

import (
	"crypto/x509"
	"testing"
)

func TestGetIntelSGXCertPool(t *testing.T) {
	pool, err := GetIntelSGXCertPool()
	if err != nil {
		t.Fatalf("Failed to get Intel SGX certificate pool: %v", err)
	}

	if pool == nil {
		t.Fatal("Expected non-nil certificate pool")
	}
}

func TestExtractPCKCertChainInvalidQuote(t *testing.T) {
	// Test with a quote that's not version 3
	quote := &Quote{
		Quote: SGXQuote{
			Version: 2, // Not version 3
		},
	}

	_, err := quote.ExtractPCKCertChain()
	if err == nil {
		t.Error("Expected error for non-v3 quote")
	}
}

func TestParseAuthDataInsufficientData(t *testing.T) {
	// Test with insufficient signature data
	quote := &Quote{
		Quote: SGXQuote{
			Version:       3,
			SignatureData: make([]byte, 10), // Too small
		},
	}

	_, err := quote.parseAuthData()
	if err == nil {
		t.Error("Expected error for insufficient signature data")
	}
}

func TestVerifyCertificateChainNilInputs(t *testing.T) {
	chain := &PCKCertChain{}

	// Test with nil PCK certificate
	err := chain.VerifyCertificateChain(nil)
	if err == nil {
		t.Error("Expected error for nil PCK certificate")
	}

	// Test with nil trusted CAs
	chain.PCKCert = &x509.Certificate{} // Empty certificate for testing
	err = chain.VerifyCertificateChain(nil)
	if err == nil {
		t.Error("Expected error for nil trusted CAs")
	}
}

// Benchmark tests for certificate verification
func BenchmarkGetIntelSGXCertPool(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GetIntelSGXCertPool()
	}
}