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

# Compiler flags
if(MSVC)
    target_compile_options(test_sha PRIVATE /W3)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_compile_options(test_sha PRIVATE /O2)
    endif()
else()
    target_compile_options(test_sha PRIVATE -Wall -Wextra -O2)
endif()

# output directory for the binary
set_target_properties(test_sha PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)