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

# Library source files (everything except main.c)
set(LIB_SOURCES
    src/lib/common.c
    src/lib/cert_utils.c
    src/lib/sgx_quote_parser.c
    src/lib/sgx_quote_verify.c
    src/lib/sgx_utils.c
    src/lib/sgx_cert_verify.c
    src/lib/ca.c
)

# Create static library
add_library(libecheck STATIC ${LIB_SOURCES})
# Set output name to "echeck" (without "lib" prefix that CMake would add)
set_target_properties(libecheck PROPERTIES OUTPUT_NAME echeck)
target_include_directories(libecheck PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(libecheck PRIVATE ${OPENSSL_INCLUDE_DIRS})
target_link_libraries(libecheck PRIVATE ${OPENSSL_LIBRARIES})

# Add executable target
add_executable(echeck src/main/main.c)

# Link against our static library
target_include_directories(echeck PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(echeck PRIVATE ${OPENSSL_INCLUDE_DIRS})
target_link_libraries(echeck PRIVATE libecheck ${OPENSSL_LIBRARIES})

# Set library version
set(ECHECK_VERSION_MAJOR 1)
set(ECHECK_VERSION_MINOR 0)
set(ECHECK_VERSION_PATCH 0)
set(ECHECK_VERSION "${ECHECK_VERSION_MAJOR}.${ECHECK_VERSION_MINOR}.${ECHECK_VERSION_PATCH}")

# Set library properties
set_target_properties(libecheck PROPERTIES
    VERSION ${ECHECK_VERSION}
    SOVERSION ${ECHECK_VERSION_MAJOR}
)

# Install targets
install(TARGETS echeck DESTINATION bin)
install(TARGETS libecheck
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib)

# Install headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/echeck
        DESTINATION include
        FILES_MATCHING PATTERN "*.h")

# Generate and install pkg-config file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/echeck.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/echeck.pc
    @ONLY
)
install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/echeck.pc
    DESTINATION lib/pkgconfig
)

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