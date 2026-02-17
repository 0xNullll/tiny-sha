cmake_minimum_required(VERSION 3.15)
project(test_sha C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Source files
set(SOURCES
    src/tiny_sha.c
    test/test_sha.c
)

# Create executable
add_executable(test_sha ${SOURCES})

# Compiler macros (all Tiny-SHA flags + optional prefix)
target_compile_definitions(test_sha PRIVATE
    ENABLE_SHA1=1
    ENABLE_SHA224=1
    ENABLE_SHA256=1
    ENABLE_SHA384=1
    ENABLE_SHA512=1
    ENABLE_SHA512_224=1
    ENABLE_SHA512_256=1

    ENABLE_SHA3_224=1
    ENABLE_SHA3_256=1
    ENABLE_SHA3_384=1
    ENABLE_SHA3_512=1

    ENABLE_SHAKE128=1
    ENABLE_SHAKE256=1
    ENABLE_RAWSHAKE128=1
    ENABLE_RAWSHAKE256=1

    ENABLE_RAW_KECCAK=0         # off by default
    TSHASH_PREFIX=MyLib_        # optional function prefix
)

# Compiler flags
if(MSVC)
    target_compile_options(test_sha PRIVATE /W3)
    target_compile_options(test_sha PRIVATE
        $<$<CONFIG:Release>:/O2>
    )
else()
    target_compile_options(test_sha PRIVATE -Wall -Wextra -O2 -s)
endif()

# Output directories
set_target_properties(test_sha PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
)
