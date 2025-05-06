#!/bin/bash

# Script to run tests for echeck
cd "$(dirname "$0")"

if [ -d "build" ]; then
    cd build
fi

echo "Running tests from $(pwd)"

# Run tests on all certificate files in the test directory
for file in ../test/*.pem; do
    echo -e "\n\n===== Testing $file with built-in CA ====="
    ./echeck "$file" || exit 1
done

echo -e "\nAll tests passed successfully!"
exit 0