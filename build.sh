#!/bin/bash

# Script to build echeck using CMake

# Create a build directory
mkdir -p build
cd build

# Generate build files
cmake ..

# Build the project
make

# Optionally run tests
if [ "$1" == "test" ]; then
    make run_tests
fi

echo "Build complete! The echeck binary is in the build directory."
echo "You can run it with: ./build/echeck"