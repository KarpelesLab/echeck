#!/bin/bash
# This script updates include paths in all source files

# Define replacement mapping
declare -A replacements=(
    ["#include \"sgx_types.h\""]="#include \"echeck/sgx_types.h\""
    ["#include \"common.h\""]="#include \"echeck/common.h\""
    ["#include \"cert_utils.h\""]="#include \"echeck/cert_utils.h\""
    ["#include \"sgx_quote_parser.h\""]="#include \"echeck/sgx_quote_parser.h\""
    ["#include \"sgx_quote_verify.h\""]="#include \"echeck/sgx_quote_verify.h\""
    ["#include \"sgx_utils.h\""]="#include \"echeck/sgx_utils.h\""
    ["#include \"sgx_cert_verify.h\""]="#include \"echeck/sgx_cert_verify.h\""
    ["#include \"ca.h\""]="#include \"echeck/ca.h\""
)

# Update files in src/lib directory
for file in src/lib/*.c; do
    echo "Updating includes in $file"
    for pattern in "${!replacements[@]}"; do
        replacement="${replacements[$pattern]}"
        sed -i "s|$pattern|$replacement|g" "$file"
    done
done

# Update main.c
echo "Updating includes in src/main/main.c"
for pattern in "${!replacements[@]}"; do
    replacement="${replacements[$pattern]}"
    sed -i "s|$pattern|$replacement|g" src/main/main.c
done

echo "Include paths updated successfully"