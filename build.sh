#!/bin/bash

# Script to build echeck using CMake

# Check for runtime-link option
CMAKE_OPTS=""
if [ "$1" == "runtime-link" ] || [ "$2" == "runtime-link" ]; then
    CMAKE_OPTS="-DOPENSSL_RUNTIME_LINK=ON"
    echo "Building with runtime OpenSSL linking enabled"
fi

# Create a build directory
mkdir -p build
cd build

# Generate build files
cmake $CMAKE_OPTS ..

# Build the project
make

# Optionally run tests
if [ "$1" == "test" ] || [ "$2" == "test" ]; then
    make run_tests
fi

echo "Build complete!"
echo "The echeck binary is in the build directory: ./build/echeck"
echo "The static library is in the build directory: ./build/libecheck.a"