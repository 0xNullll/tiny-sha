# Tiny SHA Library

A lightweight, header-only C library implementing **SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512**.  
All algorithms are **enabled by default**. It is portable, endian-aware, and optimized for both little-endian and big-endian systems.

## Features

- SHA-1, SHA-224, SHA-256, SHA-384, SHA-512  
- Single header file (`tiny_sha.h`)  
- Incremental (streaming) API: `Init`, `Update`, `Final`  
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
#include <stdio.h>
#include "tiny_sha.h"

int main() {
    const char *msg = "Hello, Tiny SHA!";
    uint8_t hash[SHA256_HASH_SIZE];

    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t*)msg, strlen(msg));
    sha256_final(&ctx, hash);

    printf("SHA-256: ");
    for (int i = 0; i < SHA256_HASH_SIZE; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}
```
