/*
 * File: tiny_sha.h
 * Author: 0xNullll
 * Description: This header provides the public interface for the Tiny SHA library.
 *              It defines context structs, function prototypes, feature flags,
 *              and inline helpers for all supported SHA algorithms (SHA-1, SHA-224,
 *              SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256).
 *              Implementation is in tiny_sha.c.
 * License: MIT
 */

#ifndef TINY_SHA_H
#define TINY_SHA_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#define FORCE_INLINE __forceinline
#else
#define FORCE_INLINE inline __attribute__((always_inline))
#endif

/* ------------------------
   Feature flags
   Users can define these as 0 (disable) or 1 (enable) 
   before including the header, or via compiler -D flags.
   ------------------------ */

/* Main user-facing options */
#ifndef ENABLE_SHA1
#define ENABLE_SHA1 1
#endif

#ifndef ENABLE_SHA224
#define ENABLE_SHA224 1
#endif

#ifndef ENABLE_SHA256
#define ENABLE_SHA256 1
#endif

#ifndef ENABLE_SHA512_256
#define ENABLE_SHA512_256 1
#endif

#ifndef ENABLE_SHA512_224
#define ENABLE_SHA512_224 1
#endif

#ifndef ENABLE_SHA384
#define ENABLE_SHA384 1
#endif

#ifndef ENABLE_SHA512
#define ENABLE_SHA512 1
#endif

/* ------------------------
   Internal auto-enabling
   ------------------------ */

/* SHA-224 uses SHA-256 functions internally */
#if ENABLE_SHA224
  #undef ENABLE_SHA256
  #define ENABLE_SHA256 1
#endif

/* SHA-384 uses SHA-512 functions internally */
#if ENABLE_SHA384
  #undef ENABLE_SHA512
  #define ENABLE_SHA512 1
#endif

/* SHA-512_224 uses SHA-512 functions internally */
#if ENABLE_SHA512_224
  #undef ENABLE_SHA512
  #define ENABLE_SHA512 1
#endif

/* SHA-512_256 uses SHA-512 functions internally */
#if ENABLE_SHA512_256
  #undef ENABLE_SHA512
  #define ENABLE_SHA512 1
#endif

#ifndef TSHASH_PREFIX
#define TSHASH_PREFIX /* empty */
#endif

#define _TS_CAT(a,b) a##b
#define _TS_CAT2(a,b) _TS_CAT(a,b)
#define TSHASH_FN(name) _TS_CAT2(TSHASH_PREFIX, name)

/* ----------------------
   Bit rotation helpers
   ---------------------- */
static FORCE_INLINE uint32_t rotl32(uint32_t x, uint32_t n) {
    n &= 31;
    return (x << n) | (x >> (32 - n));
}

static FORCE_INLINE uint64_t rotl64(uint64_t x, uint64_t n) {
    n &= 63;
    return (x << n) | (x >> (64 - n));
}

static FORCE_INLINE uint32_t rotr32(uint32_t x, uint32_t n) {
    n &= 31;
    return (x >> n) | (x << (32 - n));
}

static FORCE_INLINE uint64_t rotr64(uint64_t x, uint64_t n) {
    n &= 63;
    return (x >> n) | (x << (64 - n));
}

#define ROTL32(x,n) rotl32(x,n)
#define ROTL64(x,n) rotl64(x,n)
#define ROTR32(x,n) rotr32(x,n)
#define ROTR64(x,n) rotr64(x,n)

/* ----------------------
   Big-endian conversions
   ---------------------- */

// 32-bit (SHA-1 / SHA-256 / SHA-224)
static FORCE_INLINE uint32_t BE32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           ((uint32_t)p[3]);
}

// 64-bit (SHA-512 / SHA-384)
static FORCE_INLINE uint64_t BE64(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) |
           ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) |
           ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  |
           ((uint64_t)p[7]);
}

// Write back to memory (big-endian)
static FORCE_INLINE void PUT_BE32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)(x >> 24) & 0xFF;
    p[1] = (uint8_t)(x >> 16) & 0xFF;
    p[2] = (uint8_t)(x >> 8)  & 0xFF;
    p[3] = (uint8_t)x & 0xFF;
}

static FORCE_INLINE void PUT_BE64(uint8_t *p, uint64_t x) {
    p[0] = (uint8_t)(x >> 56) & 0xFF;
    p[1] = (uint8_t)(x >> 48) & 0xFF;
    p[2] = (uint8_t)(x >> 40) & 0xFF;
    p[3] = (uint8_t)(x >> 32) & 0xFF;
    p[4] = (uint8_t)(x >> 24) & 0xFF;
    p[5] = (uint8_t)(x >> 16) & 0xFF;
    p[6] = (uint8_t)(x >> 8)  & 0xFF;
    p[7] = (uint8_t)x & 0xFF;
}

/* ----------------------
   CPU endianness optimized macros
   ---------------------- */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define CPU_BIG_ENDIAN 1
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define CPU_LITTLE_ENDIAN 1
#else
#error "Cannot determine CPU endianness"
#endif

/* ----------------------
   Load/Store macros
   ---------------------- */
#ifdef CPU_BIG_ENDIAN
  #define LOAD32(p)    (*(const uint32_t*)(p))
  #define STORE32(p,x) (*(uint32_t*)(p) = (x))
  #define LOAD64(p)    (*(const uint64_t*)(p))
  #define STORE64(p,x) (*(uint64_t*)(p) = (x))
#else
  #define LOAD32(p)    BE32(p)
  #define STORE32(p,x) PUT_BE32(p,x)
  #define LOAD64(p)    BE64(p)
  #define STORE64(p,x) PUT_BE64(p,x)
#endif

/* ======================================
   SHA-1
   ====================================== */
#if ENABLE_SHA1
#define SHA1Init         TSHASH_FN(SHA1Init)
#define SHA1Update       TSHASH_FN(SHA1Update)
#define SHA1Final        TSHASH_FN(SHA1Final)
#define SHA1             TSHASH_FN(SHA1)
#define SHA1CompareOrder TSHASH_FN(SHA1CompareOrder)

#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20

typedef struct {
   uint32_t h0,h1,h2,h3,h4;
   uint32_t Nl,Nh;
   uint8_t buf[SHA1_BLOCK_SIZE];
   uint32_t num;
} SHA1_CTX;

bool SHA1Init(SHA1_CTX *ctx);
bool SHA1Update(SHA1_CTX *ctx, const uint8_t *data, size_t len);
bool SHA1Final(SHA1_CTX *ctx, uint8_t digest[SHA1_DIGEST_SIZE]);
bool SHA1(const uint8_t *data, size_t len, uint8_t digest[SHA1_DIGEST_SIZE]);

static FORCE_INLINE int SHA1CompareOrder(const uint8_t *a, const uint8_t *b) {
    for (size_t i = 0; i < SHA1_DIGEST_SIZE; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

#endif

/* ======================================
   SHA-256
   ====================================== */
#if ENABLE_SHA256
#define SHA256Init         TSHASH_FN(SHA256Init)
#define SHA256Update       TSHASH_FN(SHA256Update)
#define SHA256Final        TSHASH_FN(SHA256Final)
#define SHA256             TSHASH_FN(SHA256)
#define SHA256CompareOrder TSHASH_FN(SHA256CompareOrder)

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
   uint32_t state[8];
   uint64_t len;
   uint8_t buf[SHA256_BLOCK_SIZE];
   size_t buf_len;
   size_t md_len;
} SHA256_CTX;

bool SHA256Init(SHA256_CTX *ctx);
bool SHA256Update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
bool SHA256Final(SHA256_CTX *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);
bool SHA256(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]);

static FORCE_INLINE int SHA256CompareOrder(const uint8_t *a, const uint8_t *b) {
    for (size_t i = 0; i < SHA256_DIGEST_SIZE; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

#endif

/* ======================================
   SHA-224 (truncated SHA-256)
   ====================================== */
#if ENABLE_SHA224
#define SHA224Init         TSHASH_FN(SHA224Init)
#define SHA224Update       TSHASH_FN(SHA224Update)
#define SHA224Final        TSHASH_FN(SHA224Final)
#define SHA224             TSHASH_FN(SHA224)
#define SHA224CompareOrder TSHASH_FN(SHA224CompareOrder)

#define SHA224_BLOCK_SIZE 64
#define SHA224_DIGEST_SIZE 28

typedef SHA256_CTX SHA224_CTX;

bool SHA224Init(SHA224_CTX *ctx);
bool SHA224Update(SHA224_CTX *ctx, const uint8_t *data, size_t len);
bool SHA224Final(SHA224_CTX *ctx, uint8_t digest[SHA224_DIGEST_SIZE]);
bool SHA224(const uint8_t *data, size_t len, uint8_t digest[SHA224_DIGEST_SIZE]);

static FORCE_INLINE int SHA224CompareOrder(const uint8_t *a, const uint8_t *b) {
    for (size_t i = 0; i < SHA224_DIGEST_SIZE; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

#endif

/* ======================================
   SHA-512
   ====================================== */
#if ENABLE_SHA512
#define SHA512Init         TSHASH_FN(SHA512Init)
#define SHA512Update       TSHASH_FN(SHA512Update)
#define SHA512Final        TSHASH_FN(SHA512Final)
#define SHA512             TSHASH_FN(SHA512)
#define SHA512CompareOrder TSHASH_FN(SHA512CompareOrder)

#define SHA512_BLOCK_SIZE 128
#define SHA512_DIGEST_SIZE 64

typedef struct {
   uint64_t state[8];
   uint64_t Nl, Nh;
   uint8_t buf[SHA512_BLOCK_SIZE];
   size_t buf_len;
   size_t md_len;
} SHA512_CTX;

bool SHA512Init(SHA512_CTX *ctx);
bool SHA512Update(SHA512_CTX *ctx, const uint8_t *data, size_t len);
bool SHA512Final(SHA512_CTX *ctx, uint8_t digest[SHA512_DIGEST_SIZE]);
bool SHA512(const uint8_t *data, size_t len, uint8_t digest[SHA512_DIGEST_SIZE]);

static FORCE_INLINE int SHA512CompareOrder(const uint8_t *a, const uint8_t *b) {
    for (size_t i = 0; i < SHA512_DIGEST_SIZE; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

#endif

/* ======================================
   SHA-384 (truncated SHA-512)
   ====================================== */
#if ENABLE_SHA384
#define SHA384Init         TSHASH_FN(SHA384Init)
#define SHA384Update       TSHASH_FN(SHA384Update)
#define SHA384Final        TSHASH_FN(SHA384Final)
#define SHA384             TSHASH_FN(SHA384)
#define SHA384CompareOrder TSHASH_FN(SHA384CompareOrder)

#define SHA384_BLOCK_SIZE 128
#define SHA384_DIGEST_SIZE 48

typedef SHA512_CTX SHA384_CTX;

bool SHA384Init(SHA384_CTX *ctx);
bool SHA384Update(SHA384_CTX *ctx, const uint8_t *data, size_t len);
bool SHA384Final(SHA384_CTX *ctx, uint8_t digest[SHA384_DIGEST_SIZE]);
bool SHA384(const uint8_t *data, size_t len, uint8_t digest[SHA384_DIGEST_SIZE]);

static FORCE_INLINE int SHA384CompareOrder(const uint8_t *a, const uint8_t *b) {
    for (size_t i = 0; i < SHA384_DIGEST_SIZE; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

#endif

/* ======================================
   SHA-512/224 (truncated SHA-512)
   ====================================== */
#if ENABLE_SHA512_224
#define SHA512_224Init         TSHASH_FN(SHA512_224Init)
#define SHA512_224Update       TSHASH_FN(SHA512_224Update)
#define SHA512_224Final        TSHASH_FN(SHA512_224Final)
#define SHA512_224             TSHASH_FN(SHA512_224)
#define SHA512_224CompareOrder TSHASH_FN(SHA512_224CompareOrder)

#define SHA512_224_BLOCK_SIZE 128
#define SHA512_224_DIGEST_SIZE 28

typedef SHA512_CTX SHA512_224_CTX;

bool SHA512_224Init(SHA512_224_CTX *ctx);
bool SHA512_224Update(SHA512_224_CTX *ctx, const uint8_t *data, size_t len);
bool SHA512_224Final(SHA512_224_CTX *ctx, uint8_t digest[SHA512_224_DIGEST_SIZE]);
bool SHA512_224(const uint8_t *data, size_t len, uint8_t digest[SHA512_224_DIGEST_SIZE]);

static FORCE_INLINE int SHA512_224CompareOrder(const uint8_t *a, const uint8_t *b) {
    for (size_t i = 0; i < SHA512_224_DIGEST_SIZE; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

#endif

/* ======================================
   SHA-512/256 (truncated SHA-512)
   ====================================== */
#if ENABLE_SHA512_256
#define SHA512_256Init         TSHASH_FN(SHA512_256Init)
#define SHA512_256Update       TSHASH_FN(SHA512_256Update)
#define SHA512_256Final        TSHASH_FN(SHA512_256Final)
#define SHA512_256             TSHASH_FN(SHA512_256)
#define SHA512_256CompareOrder TSHASH_FN(SHA512_256CompareOrder)

#define SHA512_256_BLOCK_SIZE 128
#define SHA512_256_DIGEST_SIZE 32

typedef SHA512_CTX SHA512_256_CTX;

bool SHA512_256Init(SHA512_256_CTX *ctx);
bool SHA512_256Update(SHA512_256_CTX *ctx, const uint8_t *data, size_t len);
bool SHA512_256Final(SHA512_256_CTX *ctx, uint8_t digest[SHA512_256_DIGEST_SIZE]);
bool SHA512_256(const uint8_t *data, size_t len, uint8_t digest[SHA512_256_DIGEST_SIZE]);

static FORCE_INLINE int SHA512_256CompareOrder(const uint8_t *a, const uint8_t *b) {
    for (size_t i = 0; i < SHA512_256_DIGEST_SIZE; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

#endif

#ifdef __cplusplus
}
#endif

#endif  /* TINY_SHA_H */
