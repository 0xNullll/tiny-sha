cmake_minimum_required(VERSION 3.15)
project(sha_test C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Source files
set(SOURCES
    src/tiny_sha.c
    test/sha_test.c
)

# Create executable
add_executable(sha_test ${SOURCES})

# Compiler flags
if(MSVC)
    target_compile_options(sha_test PRIVATE /W3 /O2)
else()
    target_compile_options(sha_test PRIVATE -Wall -Wextra -O2)
endif()

# output directory for the binary
set_target_properties(sha_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)