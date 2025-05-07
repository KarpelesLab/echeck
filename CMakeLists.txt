cmake_minimum_required(VERSION 3.10)
project(echeck C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler options
add_compile_options(-Wall -pipe -O2 -g -ggdb)

# Option to use runtime loading of OpenSSL
option(OPENSSL_RUNTIME_LINK "Load OpenSSL functions at runtime using dlopen instead of linking at build time" OFF)

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
    src/lib/echeck_quote.c
)

# Add openssl_runtime.c if OPENSSL_RUNTIME_LINK is enabled
if(OPENSSL_RUNTIME_LINK)
    list(APPEND LIB_SOURCES src/lib/openssl_runtime.c)
    add_compile_definitions(OPENSSL_RUNTIME_LINK)
endif()

# Set library version
set(ECHECK_VERSION_MAJOR 1)
set(ECHECK_VERSION_MINOR 0)
set(ECHECK_VERSION_PATCH 0)
set(ECHECK_VERSION "${ECHECK_VERSION_MAJOR}.${ECHECK_VERSION_MINOR}.${ECHECK_VERSION_PATCH}")
set(ECHECK_SOVERSION ${ECHECK_VERSION_MAJOR})

# Add symbol visibility flags for shared library
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
endif()

# Create static library
add_library(libecheck_static STATIC ${LIB_SOURCES})
# Set output name to "echeck" (without "lib" prefix that CMake would add)
set_target_properties(libecheck_static PROPERTIES OUTPUT_NAME echeck)

# Create shared library
add_library(libecheck SHARED ${LIB_SOURCES})
# Set output name and version properties
set_target_properties(libecheck PROPERTIES 
    OUTPUT_NAME echeck
    VERSION ${ECHECK_VERSION}
    SOVERSION ${ECHECK_SOVERSION})

# Define ECHECK_SHARED_LIBRARY when building shared library
target_compile_definitions(libecheck PRIVATE ECHECK_SHARED_LIBRARY)

# Include directories for static library
target_include_directories(libecheck_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(libecheck_static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/include)
target_include_directories(libecheck_static PRIVATE ${OPENSSL_INCLUDE_DIRS})

# Include directories for shared library
target_include_directories(libecheck PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(libecheck PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/include)
target_include_directories(libecheck PRIVATE ${OPENSSL_INCLUDE_DIRS})

# Link with OpenSSL only if not using runtime linking
if(NOT OPENSSL_RUNTIME_LINK)
    target_link_libraries(libecheck_static PRIVATE ${OPENSSL_LIBRARIES})
    target_link_libraries(libecheck PRIVATE ${OPENSSL_LIBRARIES})
else()
    # For runtime linking, link with appropriate dynamic loading library
    if(WIN32)
        # Windows doesn't need explicit linking as LoadLibrary is part of kernel32.lib
        # which is linked by default on Windows
    else()
        # Unix systems need libdl for dlopen/dlsym
        target_link_libraries(libecheck_static PRIVATE dl)
        target_link_libraries(libecheck PRIVATE dl)
    endif()
endif()

# Add executable target
add_executable(echeck src/main/main.c)

# Link against our static library
target_include_directories(echeck PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(echeck PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/include)
target_include_directories(echeck PRIVATE ${OPENSSL_INCLUDE_DIRS})

# Link with OpenSSL only if not using runtime linking
if(NOT OPENSSL_RUNTIME_LINK)
    target_link_libraries(echeck PRIVATE libecheck_static ${OPENSSL_LIBRARIES})
else()
    target_link_libraries(echeck PRIVATE libecheck_static)
endif()

# Not needed as library version is already set above

# Install targets
install(TARGETS echeck DESTINATION bin)
install(TARGETS libecheck_static libecheck
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin)

# Install public header
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/echeck.h
        DESTINATION include)

# Generate and install pkg-config file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/echeck.pc.in
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