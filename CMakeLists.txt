cmake_minimum_required(VERSION 3.10)
project(echeck C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler options
add_compile_options(-Wall -pipe -O2 -g -ggdb)

# Find OpenSSL
find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSL REQUIRED libssl libcrypto)

# Source files
set(SOURCES
    main.c
    common.c
    cert_utils.c
    sgx_quote_parser.c
    sgx_quote_verify.c
    sgx_utils.c
    sgx_cert_verify.c
    ca.c
)

# Add executable target
add_executable(echeck ${SOURCES})

# Link libraries
target_include_directories(echeck PRIVATE ${OPENSSL_INCLUDE_DIRS})
target_link_libraries(echeck PRIVATE ${OPENSSL_LIBRARIES})

# Install target
install(TARGETS echeck DESTINATION bin)

# Test target
file(GLOB TEST_FILES "${CMAKE_SOURCE_DIR}/test/*.pem")

# Enable testing functionality
enable_testing()

# Add tests for each file
foreach(TEST_FILE ${TEST_FILES})
    get_filename_component(TEST_NAME ${TEST_FILE} NAME_WE)
    add_test(
        NAME test_${TEST_NAME}
        COMMAND echeck ${TEST_FILE}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endforeach()

# Custom target to run all tests
add_custom_target(run_tests
    COMMAND ${CMAKE_COMMAND} -E echo "Running tests on all certificate files in test directory..."
    COMMAND ${CMAKE_COMMAND} -E echo "Using built-in CA certificates"
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS echeck
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)