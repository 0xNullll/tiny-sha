cmake_minimum_required(VERSION 3.15)
project(sha_test C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
if(MSVC)
    add_compile_options(/W3 /O2)
else()
    add_compile_options(-Wall -Wextra -O2)
endif()

# Source files
set(SOURCES
    src/tiny_sha.c
    test/sha_test.c
)

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES})

# Optional: output directory for the binary
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)