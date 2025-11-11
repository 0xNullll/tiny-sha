# Tiny SHA Library

A lightweight, header-only C library implementing **SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512**.  
All algorithms are **enabled by default**. It is portable, endian-aware, and optimized for both little-endian and big-endian systems.

## Features

- SHA-1, SHA-224, SHA-256, SHA-384, SHA-512  
- Single header file (`tiny_sha.h`)  
- Incremental (streaming) API: `Init`, `Update`, `Final` ,  
- Header-only and portable  
- Handles endianness automatically  

## Installation

Include the header in **one C file** with implementation:

```c
#define TINY_SHA_IMPLEMENTATION
#include "tiny_sha.h"
```

Then include the header normally in other files without defining the implementation macro.

Usage Example
```c
int main() {
    const char *msg = "Hello, Tiny SHA!";
    uint8_t hash[SHA256_HASH_SIZE];

    // Wrapper function returns bool indicating success
    if (SHA256((const uint8_t*)msg, strlen(msg), hash)) {
        printf("SHA-256: ");
        for (int i = 0; i < SHA256_HASH_SIZE; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
    } else {
        printf("SHA-256 computation failed!\n");
    }

    return 0;
}
```
