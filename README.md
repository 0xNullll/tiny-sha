# Tiny SHA Library

A lightweight, portable C library implementing **SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256**.  
All algorithms are **enabled by default**. Portable, endian-aware, and optimized for both little-endian and big-endian systems.  
SHA-3 is planned for future versions.  

---

## Features

- SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256  
- Separate implementation file (`tiny_sha.c`) and header (`tiny_sha.h`)  
- Incremental (streaming) API: `Init`, `Update`, `Final` — all functions return `bool`  
- Wrapper functions for each algorithm for single-shot hashing — return `bool`  
- Handles endianness automatically  
- Lightweight — the entire library is under 50 KB

---

## Configurable Feature Flags

The library allows enabling or disabling specific hash algorithms. By default, all are enabled.  

- Flags are defined inside the header:

```c
#define ENABLE_SHA1   1  // 1 = enable, 0 = disable
#define ENABLE_SHA256 0
#include "tiny_sha.h"
```

> ⚠️ Note: Defining these macros before including the header may not always work. Recommended ways:

1. Update the flags directly inside the header.  
2. Use compiler `-D` flags, for example:

```bash
gcc -DENABLE_SHA1=1 -DENABLE_SHA256=0 tiny_sha.c test_sha.c -o test_sha
```

The header handles internal dependencies automatically:

- SHA-224 uses SHA-256 internally.
- SHA-384 uses SHA-512 internally.
- SHA-512/224 uses SHA-512 internally.
- SHA-512/256 uses SHA-512 internally.  

---

## Optional Function Name Prefix (`TSHASH_PREFIX`)

To avoid name collisions, you can add a prefix to all functions:

```c
#define TSHASH_PREFIX MyLib_      // prefix for all functions
#define TINY_SHA_IMPLEMENTATION
#include "tiny_sha.h"
```

Now all functions will have the prefix:

```c
MyLib_SHA256(...);         // wrapper function
MyLib_sha256_init(...);    // incremental API
```

You can also define it via compiler flags:

```bash
gcc -DTSHASH_PREFIX=MyLib_ -DTINY_SHA_IMPLEMENTATION tiny_sha.c test_sha.c -o test_sha
```

> ⚠️ Note: `TSHASH_PREFIX` must be defined **before including the header**. If not defined, functions will have no prefix (default behavior).

---

### Installation / Usage

Tiny SHA consists of:

- tiny_sha.c — contains all function implementations

- tiny_sha.h — contains declarations, macros, and configuration flags

Steps to use in your project

Include the header in any file where you want to use the functions:

```c
#include "tiny_sha.h"
```

Compile your program together with the implementation file:

```bash
gcc -DENABLE_SHA1=1 -DENABLE_SHA256=0 tiny_sha.c your_program.c -o your_program
```

The -D flags let you enable/disable specific algorithms.

> ⚠️ Note: Do not define TINY_SHA_IMPLEMENTATION — that macro is irrelevant for this library. All implementations are already in tiny_sha.c.

---

## Usage Examples

### Wrapper / Single-Shot API

```c
#include <stdio.h>
#include "tiny_sha.h"

int main() {
    const char *msg = "Hello, Tiny SHA!";
    uint8_t hash[SHA256_DIGEST_SIZE];

    // Wrapper returns bool
    if (SHA256((const uint8_t*)msg, strlen(msg), hash)) {
        printf("SHA-256: ");
        for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
    } else {
        printf("SHA-256 computation failed!\n");
    }

    return 0;
}
```

### Incremental / Streaming API

```c
#include <stdio.h>
#include "tiny_sha.h"

int main() {
    const char *msg = "Hello, Tiny SHA!";
    uint8_t hash[SHA256_DIGEST_SIZE];
    SHA256_CTX ctx;

    if (sha256_init(&ctx) &&
        sha256_update(&ctx, (const uint8_t*)msg, strlen(msg)) &&
        sha256_final(&ctx, hash)) {

        printf("SHA-256: ");
        for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
    } else {
        printf("SHA-256 computation failed!\n");
    }

    return 0;
}
```

---

## Output Sizes

| Algorithm   | Digest Size |
|-------------|-------------|
| SHA-1       |  20 bytes   |
| SHA-224     |  28 bytes   |
| SHA-256     |  32 bytes   |
| SHA-384     |  48 bytes   |
| SHA-512     |  64 bytes   |
| SHA-512/224 |	 28 bytes   |
| SHA-512/256 |	 32 bytes   |

---

## Notes

- No external dependencies — fully self-contained.  
- All functions return `bool` to indicate success/failure.  
- Designed for simplicity, speed, and ease of integration.  

---

## Why I made this

I wrote **Tiny SHA** because I wanted a small, self-contained hashing library I can easily include in my C projects (for example, my PE dumper) without pulling in large dependencies like OpenSSL. It's both a learning tool, helping me understand padding, endianness, and incremental hashing and a practical library: configurable (enable/disable algorithms), prefixable to avoid name collisions, and straightforward to compile and link. The code is minimal, auditable, and easy to extend. :)

---

## References

- RFC 6234 — *US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)*: [https://datatracker.ietf.org/doc/html/rfc6234](https://datatracker.ietf.org/doc/html/rfc6234)

---

## License

This project is released under the **MIT License**. See `LICENSE` for full text.
