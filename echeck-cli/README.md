# echeck-cli

A Go command-line tool for extracting and validating Intel SGX quotes embedded in X.509 certificates. This is the Go equivalent of the C echeck program, built using the echeck Go library.

## Installation

### Using go install

```bash
go install github.com/KarpelesLab/echeck/echeck-cli@latest
```

### Building from source

```bash
git clone https://github.com/KarpelesLab/echeck.git
cd echeck/echeck-cli
go build -o echeck-cli .
```

## Usage

```
echeck-cli [OPTIONS] <certificate.pem>
```

### Options

- `-h, --help`: Display help message
- `--version`: Display version information
- `-v, --verbose`: Enable verbose output (prints detailed verification info)
- `-q, --quiet`: Quiet mode (only errors will be printed, success is silent)
- `-r, --raw`: Output in machine-readable format (key=value)
- `--mrenclave=<hash>`: Verify the SGX quote has the specified MRENCLAVE value (64 hex characters)
- `--mrsigner=<hash>`: Verify the SGX quote has the specified MRSIGNER value (64 hex characters)

## Examples

### Basic verification
```bash
echeck-cli test/sample.pem
# Output: SGX quote verification successful
```

### Verbose mode
```bash
echeck-cli -v test/sample.pem
# Output:
# Certificate public key hash verified: 4f1ea6825b7a95d4dc0f9b6929a91b66c5fcaa9ef3078afe48f0c02cde48b13a
# SGX Quote verification successful
# MRENCLAVE: df2493c11fc01708af6913323b64e20ae84b12779dbe44ba428da66dfc4488f5
# MRSIGNER: 976aa9f931b8a16e01e01895d627e3ee96dce5478ebbbc77e120a25c79fe6016
# ISV Product ID: 1
# ISV SVN: 1
# SGX Quote extracted: 4600 bytes
# Quote version: 3
# Signature type: 2
# QE SVN: 11
# PCE SVN: 16
# Found PCK certificate chain (2 certificates)
# Certificate 1: CN=Intel SGX PCK Processor CA,O=Intel Corporation,L=Santa Clara,ST=CA,C=US
# Certificate 2: CN=Intel SGX Root CA,O=Intel Corporation,L=Santa Clara,ST=CA,C=US
```

### Raw output (machine readable)
```bash
echeck-cli -r test/sample.pem
# Output:
# mrenclave=df2493c11fc01708af6913323b64e20ae84b12779dbe44ba428da66dfc4488f5
# mrsigner=976aa9f931b8a16e01e01895d627e3ee96dce5478ebbbc77e120a25c79fe6016
# version=3
# signtype=2
# isvprodid=1
# isvsvn=1
# qesvn=11
# pcesvn=16
```

### Quiet mode (for scripting)
```bash
echeck-cli -q test/sample.pem
# No output on success, only errors are printed
echo $?  # Check exit code (0 = success, 1 = failure)
```

### Verify specific MRENCLAVE
```bash
echeck-cli --mrenclave=df2493c11fc01708af6913323b64e20ae84b12779dbe44ba428da66dfc4488f5 test/sample.pem
# Output: SGX quote verification successful
```

### Verify specific MRSIGNER
```bash
echeck-cli --mrsigner=976aa9f931b8a16e01e01895d627e3ee96dce5478ebbbc77e120a25c79fe6016 test/sample.pem
# Output: SGX quote verification successful
```

## Features

- **Complete SGX quote verification**: Full cryptographic validation including ECDSA signature verification
- **Certificate chain validation**: Validates PCK certificates against Intel's trusted CAs
- **Report data verification**: Ensures certificate public key hash matches quote report data
- **Measurement verification**: Optional validation against expected MRENCLAVE/MRSIGNER values
- **Multiple output formats**: Standard, verbose, raw, and quiet modes
- **Cross-platform**: Pure Go implementation that works on all platforms
- **Exit codes**: Standard Unix exit codes (0 = success, 1 = failure)

## Exit Codes

The tool follows standard Unix exit code conventions:
- `0`: Success (quote verification passed)
- `1`: Error (verification failed, invalid parameters, etc.)

This makes it suitable for use in scripts and automated workflows.

## Comparison with C echeck

The Go echeck-cli provides the same functionality as the C echeck program:

| Feature | C echeck | Go echeck-cli |
|---------|----------|---------------|
| Quote extraction | ✅ | ✅ |
| ECDSA signature verification | ✅ | ✅ |
| Certificate chain validation | ✅ | ✅ |
| Report data verification | ✅ | ✅ |
| MRENCLAVE/MRSIGNER validation | ✅ | ✅ |
| Verbose mode | ✅ | ✅ |
| Quiet mode | ✅ | ✅ |
| Raw output | ✅ | ✅ |
| Cross-platform | ✅ | ✅ |
| Dependencies | OpenSSL | None (pure Go) |

## Dependencies

The Go CLI tool has no external dependencies - it uses only the Go standard library and the echeck Go library.

## Error Handling

The tool provides detailed error messages for different failure scenarios:

- **Report data mismatch**: Certificate public key doesn't match quote report data
- **Invalid quote format**: Quote structure or version is invalid
- **Certificate chain verification failed**: PCK certificate chain validation failed
- **MRENCLAVE/MRSIGNER mismatch**: Measurements don't match expected values
- **File errors**: Certificate file not found or invalid format

## License

This project is licensed under the same terms as the parent echeck project.