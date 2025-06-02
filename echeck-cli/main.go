package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/KarpelesLab/echeck"
)

// Version information
const Version = "1.0.0"

// JSONOutput represents the JSON output format
type JSONOutput struct {
	Success        bool                `json:"success"`
	Error          string              `json:"error,omitempty"`
	Quote          *JSONQuoteInfo      `json:"quote,omitempty"`
	Certificate    *JSONCertInfo       `json:"certificate,omitempty"`
	Measurements   *JSONMeasurements   `json:"measurements,omitempty"`
	PCKCertChain   *JSONPCKCertChain   `json:"pck_cert_chain,omitempty"`
}

type JSONQuoteInfo struct {
	Version     uint16 `json:"version"`
	SignType    uint16 `json:"sign_type"`
	QESVN       uint16 `json:"qe_svn,omitempty"`
	PCESVN      uint16 `json:"pce_svn,omitempty"`
	RawDataSize int    `json:"raw_data_size"`
}

type JSONMeasurements struct {
	MREnclave  string `json:"mr_enclave"`
	MRSigner   string `json:"mr_signer"`
	ISVProdID  uint16 `json:"isv_prod_id"`
	ISVSVN     uint16 `json:"isv_svn"`
}

type JSONCertInfo struct {
	Subject           string `json:"subject"`
	Issuer            string `json:"issuer"`
	PublicKeyHash     string `json:"public_key_hash,omitempty"`
}

type JSONPCKCertChain struct {
	CertificateCount int                    `json:"certificate_count"`
	Certificates     []JSONPCKCertificate   `json:"certificates"`
}

type JSONPCKCertificate struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
}

// CLI flags
var (
	verbose    = flag.Bool("v", false, "Enable verbose output")
	quiet      = flag.Bool("q", false, "Quiet mode (only errors)")
	raw        = flag.Bool("r", false, "Raw output mode (machine readable)")
	jsonOutput = flag.Bool("json", false, "Output in JSON format")
	help       = flag.Bool("h", false, "Display help message")
	version    = flag.Bool("version", false, "Display version information")
	mrenclave  = flag.String("mrenclave", "", "Expected MRENCLAVE value (64 hex characters)")
	mrsigner   = flag.String("mrsigner", "", "Expected MRSIGNER value (64 hex characters)")
)

func init() {
	flag.BoolVar(verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(quiet, "quiet", false, "Quiet mode (only errors)")
	flag.BoolVar(raw, "raw", false, "Raw output mode (machine readable)")
	flag.BoolVar(help, "help", false, "Display help message")
}

func main() {
	flag.Parse()

	if *help {
		printHelp()
		os.Exit(0)
	}

	if *version {
		fmt.Printf("echeck-cli version %s\n", Version)
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "Error: Please provide exactly one certificate file or '-' for stdin\n")
		printUsage()
		os.Exit(1)
	}

	certFile := args[0]

	// Validate MRENCLAVE and MRSIGNER if provided
	var expectedMREnclave, expectedMRSigner []byte
	var err error

	if *mrenclave != "" {
		expectedMREnclave, err = validateHexValue(*mrenclave, "MRENCLAVE")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	if *mrsigner != "" {
		expectedMRSigner, err = validateHexValue(*mrsigner, "MRSIGNER")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	// Load certificate
	cert, err := loadCertificate(certFile)
	if err != nil {
		if *jsonOutput {
			handleError(err.Error())
		} else {
			handleError(fmt.Sprintf("Error loading certificate: %v", err))
		}
		os.Exit(1)
	}

	// Extract SGX quote
	quote, err := echeck.ExtractQuote(cert)
	if err != nil {
		if *jsonOutput {
			handleError(err.Error())
		} else {
			handleError(fmt.Sprintf("Error extracting SGX quote: %v", err))
		}
		os.Exit(1)
	}

	// Verify the quote
	err = echeck.VerifyQuote(cert, quote)
	if err != nil {
		var errorMsg string
		var reportErr echeck.ErrReportDataMismatch
		var formatErr echeck.ErrInvalidQuoteFormat
		var certErr echeck.ErrCertChainVerification

		if errors.As(err, &reportErr) {
			errorMsg = "Report data does not match certificate public key hash"
			if *verbose && !*jsonOutput {
				fmt.Fprintf(os.Stderr, "Expected: %x\n", reportErr.Expected[:32])
				fmt.Fprintf(os.Stderr, "Actual: %x\n", reportErr.Actual[:32])
			}
		} else if errors.As(err, &formatErr) {
			errorMsg = fmt.Sprintf("Invalid quote format (version %d, size %d bytes)", 
				formatErr.Version, formatErr.Size)
		} else if errors.As(err, &certErr) {
			errorMsg = fmt.Sprintf("Certificate chain verification failed: %s", certErr.Reason)
		} else {
			errorMsg = fmt.Sprintf("Quote verification failed: %v", err)
		}
		
		handleError(errorMsg)
		os.Exit(1)
	}

	// Get quote information
	info := quote.GetQuoteInfo()

	// Verify measurements if provided
	if expectedMREnclave != nil || expectedMRSigner != nil {
		if !quote.VerifyMeasurements(expectedMREnclave, expectedMRSigner) {
			var errorMsg string
			if expectedMREnclave != nil {
				if !quote.VerifyMeasurements(expectedMREnclave, nil) {
					errorMsg = "MRENCLAVE value does not match expected value"
					if *verbose && !*jsonOutput {
						fmt.Fprintf(os.Stderr, "Expected: %x\n", expectedMREnclave)
						fmt.Fprintf(os.Stderr, "Actual: %x\n", info.MREnclave)
					}
				}
			}
			if expectedMRSigner != nil {
				if !quote.VerifyMeasurements(nil, expectedMRSigner) {
					if errorMsg != "" {
						errorMsg += " and MRSIGNER value does not match expected value"
					} else {
						errorMsg = "MRSIGNER value does not match expected value"
					}
					if *verbose && !*jsonOutput {
						fmt.Fprintf(os.Stderr, "Expected: %x\n", expectedMRSigner)
						fmt.Fprintf(os.Stderr, "Actual: %x\n", info.MRSigner)
					}
				}
			}
			handleError(errorMsg)
			os.Exit(1)
		}
	}

	// Output results based on mode
	if *jsonOutput {
		printJSONOutput(cert, quote, info)
	} else if *raw {
		printRawOutput(quote, info)
	} else if *verbose {
		printVerboseOutput(cert, quote, info)
	} else if !*quiet {
		printStandardOutput()
	}
}

func printHelp() {
	fmt.Printf("SGX Certificate Checker (echeck-cli) - Go version %s\n\n", Version)
	fmt.Printf("A utility for extracting and validating Intel SGX quotes embedded in X.509 certificates.\n\n")
	fmt.Printf("USAGE:\n")
	fmt.Printf("    echeck-cli [OPTIONS] <certificate.pem>\n")
	fmt.Printf("    echeck-cli [OPTIONS] -\n\n")
	fmt.Printf("ARGS:\n")
	fmt.Printf("    <certificate.pem>    The X.509 certificate containing an SGX quote to be verified\n")
	fmt.Printf("    -                    Read certificate from stdin\n\n")
	fmt.Printf("OPTIONS:\n")
	fmt.Printf("    -h, --help           Display this help message\n")
	fmt.Printf("    --version            Display version information\n")
	fmt.Printf("    -v, --verbose        Enable verbose output (prints detailed verification info)\n")
	fmt.Printf("    -q, --quiet          Quiet mode (only errors will be printed, success is silent)\n")
	fmt.Printf("    -r, --raw            Output in machine-readable format (key=value)\n")
	fmt.Printf("    --json               Output in JSON format\n")
	fmt.Printf("    --mrenclave=<hash>   Verify the SGX quote has the specified MRENCLAVE value (64 hex characters)\n")
	fmt.Printf("    --mrsigner=<hash>    Verify the SGX quote has the specified MRSIGNER value (64 hex characters)\n\n")
	fmt.Printf("EXAMPLES:\n")
	fmt.Printf("    echeck-cli test/sample.pem\n")
	fmt.Printf("    echeck-cli -v test/sample.pem\n")
	fmt.Printf("    echeck-cli --json test/sample.pem\n")
	fmt.Printf("    cat test/sample.pem | echeck-cli -\n")
	fmt.Printf("    echeck-cli --mrenclave=df2493c11fc01708af6913323b64e20ae84b12779dbe44ba428da66dfc4488f5 test/sample.pem\n")
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: echeck-cli [OPTIONS] <certificate.pem|->\n")
	fmt.Fprintf(os.Stderr, "Use --help for more information.\n")
}

func validateHexValue(value, name string) ([]byte, error) {
	if len(value) != 64 {
		return nil, fmt.Errorf("invalid %s format (expected 64 hex characters)", name)
	}

	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid %s format (not valid hex): %v", name, err)
	}

	return decoded, nil
}

func loadCertificate(filename string) (*x509.Certificate, error) {
	var certPEM []byte
	var err error

	if filename == "-" {
		// Read from stdin
		certPEM, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("failed to read from stdin: %v", err)
		}
	} else {
		// Read from file
		certPEM, err = os.ReadFile(filename)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate file: %v", err)
		}
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE block, got %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

func printStandardOutput() {
	fmt.Println("SGX quote verification successful")
}

func printVerboseOutput(cert *x509.Certificate, quote *echeck.Quote, info echeck.QuoteInfo) {
	// Compute and display certificate public key hash
	pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err == nil {
		pubKeyHash := echeck.ComputePublicKeyHash(pubKeyDER)
		fmt.Printf("Certificate public key hash verified: %x\n", pubKeyHash)
	}

	fmt.Println("SGX Quote verification successful")
	fmt.Printf("MRENCLAVE: %x\n", info.MREnclave)
	fmt.Printf("MRSIGNER: %x\n", info.MRSigner)
	fmt.Printf("ISV Product ID: %d\n", info.ISVProdID)
	fmt.Printf("ISV SVN: %d\n", info.ISVSVN)
	fmt.Printf("SGX Quote extracted: %d bytes\n", len(quote.RawData))

	// Display quote version and signature information
	fmt.Printf("Quote version: %d\n", quote.Quote.Version)
	fmt.Printf("Signature type: %d\n", quote.Quote.SignType)
	
	if quote.Quote.Version == 3 {
		fmt.Printf("QE SVN: %d\n", quote.Quote.QESVN)
		fmt.Printf("PCE SVN: %d\n", quote.Quote.PCESVN)
	}

	// Try to extract and display PCK certificate chain info
	pckChain, err := quote.ExtractPCKCertChain()
	if err == nil {
		fmt.Printf("Found PCK certificate chain (%d certificates)\n", len(pckChain.Certificates))
		for i, cert := range pckChain.Certificates {
			fmt.Printf("Certificate %d: %s\n", i+1, cert.Subject.String())
		}
	}
}

func printRawOutput(quote *echeck.Quote, info echeck.QuoteInfo) {
	fmt.Printf("mrenclave=%x\n", info.MREnclave)
	fmt.Printf("mrsigner=%x\n", info.MRSigner)
	fmt.Printf("version=%d\n", quote.Quote.Version)
	fmt.Printf("signtype=%d\n", quote.Quote.SignType)
	fmt.Printf("isvprodid=%d\n", info.ISVProdID)
	fmt.Printf("isvsvn=%d\n", info.ISVSVN)
	
	if quote.Quote.Version == 3 {
		fmt.Printf("qesvn=%d\n", quote.Quote.QESVN)
		fmt.Printf("pcesvn=%d\n", quote.Quote.PCESVN)
	}
}

func handleError(message string) {
	if *jsonOutput {
		output := JSONOutput{
			Success: false,
			Error:   message,
		}
		jsonData, _ := json.MarshalIndent(output, "", "  ")
		fmt.Println(string(jsonData))
	} else if !*quiet {
		fmt.Fprintf(os.Stderr, "Error: %s\n", message)
	}
}

func printJSONOutput(cert *x509.Certificate, quote *echeck.Quote, info echeck.QuoteInfo) {
	output := JSONOutput{
		Success: true,
		Quote: &JSONQuoteInfo{
			Version:     quote.Quote.Version,
			SignType:    quote.Quote.SignType,
			RawDataSize: len(quote.RawData),
		},
		Certificate: &JSONCertInfo{
			Subject: cert.Subject.String(),
			Issuer:  cert.Issuer.String(),
		},
		Measurements: &JSONMeasurements{
			MREnclave: fmt.Sprintf("%x", info.MREnclave),
			MRSigner:  fmt.Sprintf("%x", info.MRSigner),
			ISVProdID: info.ISVProdID,
			ISVSVN:    info.ISVSVN,
		},
	}

	// Add version-specific fields
	if quote.Quote.Version == 3 {
		output.Quote.QESVN = quote.Quote.QESVN
		output.Quote.PCESVN = quote.Quote.PCESVN
	}

	// Compute and add certificate public key hash
	pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err == nil {
		pubKeyHash := echeck.ComputePublicKeyHash(pubKeyDER)
		output.Certificate.PublicKeyHash = fmt.Sprintf("%x", pubKeyHash)
	}

	// Try to extract and add PCK certificate chain info
	pckChain, err := quote.ExtractPCKCertChain()
	if err == nil {
		pckCertChain := &JSONPCKCertChain{
			CertificateCount: len(pckChain.Certificates),
			Certificates:     make([]JSONPCKCertificate, len(pckChain.Certificates)),
		}
		for i, cert := range pckChain.Certificates {
			pckCertChain.Certificates[i] = JSONPCKCertificate{
				Subject: cert.Subject.String(),
				Issuer:  cert.Issuer.String(),
			}
		}
		output.PCKCertChain = pckCertChain
	}

	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		handleError(fmt.Sprintf("Failed to marshal JSON output: %v", err))
		os.Exit(1)
	}
	fmt.Println(string(jsonData))
}