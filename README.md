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

Notes

Output sizes:

SHA-1: 20 bytes

SHA-224: 28 bytes

SHA-256: 32 bytes

SHA-384: 48 bytes

SHA-512: 64 bytes

No external flags are required—all algorithms are enabled by default.
```
