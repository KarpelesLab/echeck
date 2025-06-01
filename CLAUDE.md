# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

### Building the Project

```bash
# Standard build (static OpenSSL linking)
mkdir -p build
cd build
cmake ..
make

# Build with runtime OpenSSL linking
mkdir -p build
cd build
cmake -DOPENSSL_RUNTIME_LINK=ON ..
make

# Or use the build script
./build.sh                    # Standard build
./build.sh runtime-link       # Build with runtime OpenSSL linking
```

### Running Tests

```bash
# Using CMake's run_tests target
cd build
make run_tests

# Using CTest directly
cd build
ctest              # Run all tests
ctest -V           # Run all tests with verbose output
ctest -R test_name # Run a specific test

# Or use the build script
./build.sh test               # Build and run tests
./build.sh runtime-link test  # Build with runtime linking and run tests
```

### Package Creation

```bash
# Install the library and headers
cd build
sudo make install

# Create a package (only needed for releases)
cd build
cpack
```

## Cross-Platform Builds

The project uses GitHub Actions to build for multiple platforms:
- Ubuntu (Static and Runtime OpenSSL)
- macOS (Static and Runtime OpenSSL)
- Windows x64 (Static and Runtime OpenSSL)
- Windows ARM64 (Static and Runtime OpenSSL)

## Code Architecture

### Core Components

1. **Public API (include/echeck.h)**
   - Main interface for applications
   - Certificate and quote handling
   - Verification functions

2. **Internal Headers (src/include)**
   - `echeck_internal.h` - Internal types and functions
   - `sgx_types.h` - SGX data structures
   - Various subsystem headers for quote parsing, verification, etc.

3. **Library Components**
   - `ca.c` - Certificate Authority management
   - `cert_utils.c` - Certificate handling utilities
   - `sgx_quote_parser.c` - SGX quote extraction and parsing
   - `sgx_quote_verify.c` - SGX quote verification
   - `sgx_cert_verify.c` - Certificate chain verification
   - `sgx_utils.c` - SGX utility functions
   - `common.c` - Common utilities
   - `echeck_quote.c` - Quote handling API implementation
   - `openssl_runtime.c` - Runtime OpenSSL loading (when OPENSSL_RUNTIME_LINK=ON)

4. **Main Application**
   - `main.c` - Command-line interface

### Data Flow

1. Certificate is loaded using `load_certificate()`
2. SGX quote is extracted with `extract_quote()`
3. Quote is verified through multiple steps:
   - Signature verification
   - Certificate chain verification
   - Attestation key verification
   - MRENCLAVE/MRSIGNER validation
   - Report data validation

### Cross-Platform Considerations

The codebase supports different platforms through:
1. CMake build system for cross-platform compatibility
2. Conditional compilation for platform-specific code
3. Runtime OpenSSL loading option to handle different OpenSSL installations
4. Platform-specific path handling for dynamically loaded libraries

## OpenSSL Integration

The project can use OpenSSL in two ways:
1. **Static linking** - OpenSSL libraries are linked at build time
2. **Runtime loading** - OpenSSL functions are loaded dynamically at runtime

Runtime loading uses:
- Windows: `LoadLibrary` and `GetProcAddress`
- UNIX/Linux: `dlopen` and `dlsym`
- macOS: `dlopen` and `dlsym` with platform-specific paths

## GitHub Actions Workflow

The GitHub workflow in `.github/workflows/build.yml` handles:
1. Building on multiple platforms (Ubuntu, macOS, Windows x64, Windows ARM64)
2. Testing on each platform
3. Creating artifacts for each build
4. Uploading artifacts to GitHub releases

### Checking Build Status with GitHub CLI

After pushing changes, use these commands to check build status across all platforms:

```bash
# List recent workflow runs
gh run list -L 5

# View details of the latest run
gh run view

# View details of a specific run
gh run view <run-id>

# View logs for failed jobs in a run
gh run view <run-id> --log-failed

# View logs for a specific job in a run
gh run view <run-id> --job=<job-id>

# Download artifacts from a successful run
gh run download <run-id>
```

Always verify that changes build successfully on all platforms before considering them complete. Pay particular attention to platform-specific issues on:
- macOS (OpenSSL paths)
- Windows x64 (MSVC compiler differences)
- Windows ARM64 (architecture-specific issues)

## Important Development Notes

1. When modifying OpenSSL function calls, ensure compatibility with both static and runtime linking modes
2. For cross-platform changes, test on all supported platforms
3. Use CMake's built-in FindOpenSSL module for OpenSSL detection
4. Use `OpenSSL::SSL` and `OpenSSL::Crypto` targets for proper linking