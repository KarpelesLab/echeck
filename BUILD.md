# Building echeck

This document contains instructions for building the echeck library and command-line tool.

## Requirements

The project requires OpenSSL development libraries to be installed.

## Build Options

### Option 1: Using the build script (Recommended)

Run the build script to compile the project:

```bash
./build.sh                    # Standard build
./build.sh runtime-link       # Build with runtime OpenSSL linking
./build.sh test               # Build and run tests
./build.sh runtime-link test  # Build with runtime linking and run tests
```

This will create a `build` directory with the `echeck` executable and `libecheck.a` static library.

### Option 2: Using CMake directly

```bash
mkdir -p build
cd build
cmake ..
make
```

## Runtime OpenSSL Linking

The project supports an option to dynamically load OpenSSL libraries at runtime instead of linking them at build time:

```bash
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

## Cross-Platform Builds

The project uses GitHub Actions to build for multiple platforms:
- Ubuntu (Static and Runtime OpenSSL)
- macOS (Static and Runtime OpenSSL)
- Windows x64 (Static and Runtime OpenSSL)
- Windows ARM64 (Static and Runtime OpenSSL)

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

## Installation

To install the executable, library, and headers:

```bash
cd build
sudo make install
```

This will install:
- The `echeck` executable to `/usr/local/bin/`
- The `libecheck.a` static library to `/usr/local/lib/`
- The header files to `/usr/local/include/echeck/`
- The pkg-config file to `/usr/local/lib/pkgconfig/`

## Using the Library in Your Projects

The library can be used in other projects through pkg-config:

```bash
gcc -o myapp myapp.c $(pkg-config --cflags --libs echeck)
```

Or by directly linking:

```bash
gcc -o myapp myapp.c -I/usr/local/include/echeck -L/usr/local/lib -lecheck -lssl -lcrypto
```

## Package Creation

To create a package (only needed for releases):

```bash
cd build
cpack
```

## Testing

The tool includes a test framework to validate SGX quotes from certificates using CMake's testing functionality.

**Option 1**: Using the build script:
```bash
./build.sh test
```

**Option 2**: Using CMake's testing capabilities:
```bash
cd build
make run_tests     # Run all tests with nice output formatting
```

**Option 3**: Using CTest directly:
```bash
cd build
ctest              # Run all tests
ctest -V           # Run all tests with verbose output
ctest -R test_sample  # Run specific test
```

This will run the verification on all certificate files in the `test/` directory using the built-in Intel SGX Root CA certificate.

## Go Library

To build and test the Go library:

```bash
# Install dependencies
go mod tidy

# Run tests
go test

# Run benchmarks
go test -bench=.

# Run tests with verbose output
go test -v
```

## Important Development Notes

1. When modifying OpenSSL function calls, ensure compatibility with both static and runtime linking modes
2. For cross-platform changes, test on all supported platforms
3. Use CMake's built-in FindOpenSSL module for OpenSSL detection
4. Use `OpenSSL::SSL` and `OpenSSL::Crypto` targets for proper linking