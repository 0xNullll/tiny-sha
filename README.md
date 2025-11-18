# Tiny SHA Library

A lightweight, portable C library implementing a wide range of SHA algorithms, fully enabled by default and optimized for both little-endian and big-endian systems.

---

## Features

- **SHA-1/2 variants**: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256  
- **SHA-3 variants**: SHA3-224, SHA3-256, SHA3-384, SHA3-512  
- **SHAKE / XOF variants**: SHAKE128, SHAKE256  
- **Raw SHAKE / Raw Keccak**: RawSHAKE128, RawSHAKE256 (for bit-level manipulation, can be enabled via `ENABLE_RAW_KECCAK`)  
- Separate implementation file (`tiny_sha.c`) and header (`tiny_sha.h`)  
- Incremental (streaming) API: `Init`, `Absorb/Update`, `Final`, `Squeeze` (all return `bool`)  
- Wrapper functions for one-shot hashing  
- Safe hash comparison via `CompareOrder` inline functions  
- Handles endianness automatically  
- Lightweight — entire library under 50 KB

---

## Configurable Feature Flags

The library allows enabling or disabling specific hash algorithms. By default, all are enabled.

Flags are defined inside the header:

```c
#define ENABLE_SHA1      1    // enable SHA-1
#define ENABLE_SHA256    1    // enable SHA-256
#define ENABLE_SHA3_256  0    // disable SHA3-256
#include "tiny_sha.h"
```

> ⚠️ Note: Defining these macros before including the header may not always work. Recommended ways:

1. Update the flags directly inside the header.  
2. Use compiler `-D` flags, for example:
```bash
gcc -DENABLE_SHA1=1 -DENABLE_SHA256=0 tiny_sha.c test_sha.c -o test_sha
```

The header handles internal dependencies automatically:

- SHA-224 → uses SHA-256 internally.  
- SHA-384 → uses SHA-512 internally.  
- SHA-512/224 and SHA-512/256 → use SHA-512 internally.  
- SHA-3 (224, 256, 384, 512) and SHAKE (128, 256) → use internal Keccak permutation functions (`k_init_wrap`, `k_absorb_wrap`, `k_final_wrap`, `k_squeeze_wrap`) for processing.

---

## Optional Function Name Prefix (`TSHASH_PREFIX`)

To avoid name collisions, you can add a prefix to all functions:

```c
#define TSHASH_PREFIX MyLib_      // prefix for all functions
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

## Usage Examples

### Wrapper / Single-Shot API

```c
#include <stdio.h>
#include "tiny_sha.h"

int main() {
    const char *msg = "Hello, Tiny SHA!";
    uint8_t hash[SHA256_DIGEST_SIZE];

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

### Comparing Hash Digests

```c
uint8_t hash1[SHA256_DIGEST_SIZE];
uint8_t hash2[SHA256_DIGEST_SIZE];

// Compute hash1 and hash2...

int cmp = SHA256CompareOrder(hash1, hash2);
if (cmp == 0) {
    printf("Hashes are equal\n");
} else if (cmp < 0) {
    printf("hash1 < hash2\n");
} else {
    printf("hash1 > hash2\n");
}
```

---

## Output Sizes

| Algorithm      | Digest Size |
|----------------|-------------|
| SHA-1          | 20 bytes    |
| SHA-224        | 28 bytes    |
| SHA-256        | 32 bytes    |
| SHA-384        | 48 bytes    |
| SHA-512        | 64 bytes    |
| SHA-512/224    | 28 bytes    |
| SHA-512/256    | 32 bytes    |
| SHA3-224       | 28 bytes    |
| SHA3-256       | 32 bytes    |
| SHA3-384       | 48 bytes    |
| SHA3-512       | 64 bytes    |
| SHAKE128       | variable    |
| SHAKE256       | variable    |
| RawSHAKE128    | variable    |
| RawSHAKE256    | variable    |

---

## Notes

- Fully self-contained — no external dependencies.  
- All functions return `bool` to indicate success or failure.  
- Designed for simplicity, speed, and easy integration.  
- SHA-3 functions correspond to SHA-2 operations:  
  - `Init` (SHA-2) → `Init` (SHA-3)  
  - `Update` (SHA-2) → `Absorb` (SHA-3)  
  - `Final` (SHA-2) → `Final` / `Squeeze` (SHA-3)  
- One-shot wrapper functions follow the same style across all algorithms, ensuring a consistent API.  
- SHAKE and RawSHAKE functions support variable-length output for flexible bit-level operations.  
- Raw Keccak API can be enabled via `ENABLE_RAW_KECCAK`.

---

## Why I made this

Hi!

I wrote Tiny SHA because I wanted a small, self-contained hashing library I can easily include in my C projects (for example, my PE dumper) without pulling in large dependencies like OpenSSL or relying on copying/stealing other people’s code. It's both a learning tool, helping me understand padding, endianness, and incremental hashing, and a practical library: configurable (enable/disable algorithms), prefixable to avoid name collisions, and straightforward to compile and link. The code is minimal, auditable, and easy to extend. :)

---

## Sources

- [RFC 6234 – US Secure Hash Algorithms (SHA and SHA‑based HMAC and HKDF), May 2011](https://datatracker.ietf.org/doc/html/rfc6234)
- [FIPS PUB 202 – SHA‑3 Standard: Permutation-Based Hash and Extendable-Output Functions, August 2015](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)

---

## License

This project is released under the **MIT License**. See `LICENSE` for full text.
