/*
 * File: tiny_sha.h
 * Author: 0xNullll
 * Description: This header provides the public interface for the Tiny SHA library.
 *              It defines context structs, function prototypes, feature flags,
 *              and inline helpers for all supported SHA algorithms:
 *              SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256,
 *              as well as SHA-3 variants (SHA3-224, SHA3-256, SHA3-384, SHA3-512)
 *              and optional raw SHAKE support if enabled.
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

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
# define U64(C) C##UI64
#elif defined(__arch64__)
# define U64(C) C##UL
#else
# define U64(C) C##ULL
#endif

/* ------------------------
   Feature Flags
   Users can define these as 0 (disable) or 1 (enable)
   before including the header, or via compiler -D flags.
   ------------------------ */

/* ------------------------
   SHA-1 / SHA-2 variants
   ------------------------ */
#ifndef ENABLE_SHA1
#define ENABLE_SHA1 1          /* enable SHA-1 by default */
#endif

#ifndef ENABLE_SHA224
#define ENABLE_SHA224 1        /* enable SHA-224 by default */
#endif

#ifndef ENABLE_SHA256
#define ENABLE_SHA256 1        /* enable SHA-256 by default */
#endif

#ifndef ENABLE_SHA384
#define ENABLE_SHA384 1        /* enable SHA-384 by default */
#endif

#ifndef ENABLE_SHA512
#define ENABLE_SHA512 1        /* enable SHA-512 by default */
#endif

#ifndef ENABLE_SHA512_224
#define ENABLE_SHA512_224 1    /* enable SHA-512/224 by default */
#endif

#ifndef ENABLE_SHA512_256
#define ENABLE_SHA512_256 1    /* enable SHA-512/256 by default */
#endif

/* ------------------------
   SHA-3 variants
   ------------------------ */
#ifndef ENABLE_SHA3_224
#define ENABLE_SHA3_224 1      /* enable SHA3-224 by default */
#endif

#ifndef ENABLE_SHA3_256
#define ENABLE_SHA3_256 1      /* enable SHA3-256 by default */
#endif

#ifndef ENABLE_SHA3_384
#define ENABLE_SHA3_384 1      /* enable SHA3-384 by default */
#endif

#ifndef ENABLE_SHA3_512
#define ENABLE_SHA3_512 1      /* enable SHA3-512 by default */
#endif

/* ------------------------
   SHAKE / RawSHAKE
   ------------------------ */
#ifndef ENABLE_SHAKE128
#define ENABLE_SHAKE128 1      /* enable SHAKE128 by default */
#endif

#ifndef ENABLE_SHAKE256
#define ENABLE_SHAKE256 1      /* enable SHAKE256 by default */
#endif

#ifndef ENABLE_RAWSHAKE128
#define ENABLE_RAWSHAKE128 1   /* enable RawSHAKE128 by default */
#endif

#ifndef ENABLE_RAWSHAKE256
#define ENABLE_RAWSHAKE256 1   /* enable RawSHAKE256 by default */
#endif

/* ------------------------
   Raw Keccak
   ------------------------ */
#ifndef ENABLE_RAW_KECCAK
#define ENABLE_RAW_KECCAK 0    /* off by default */
#endif

/* ------------------------
   Internal auto-enabling
   ------------------------ */

/* SHA-224 uses SHA-256 internally */
#if ENABLE_SHA224
  #undef ENABLE_SHA256
  #define ENABLE_SHA256 1
#endif

/* SHA-384 uses SHA-512 internally */
#if ENABLE_SHA384
  #undef ENABLE_SHA512
  #define ENABLE_SHA512 1
#endif

/* SHA-512/224 and SHA-512/256 use SHA-512 internally */
#if ENABLE_SHA512_224 || ENABLE_SHA512_256
  #undef ENABLE_SHA512
  #define ENABLE_SHA512 1
#endif

/* Core Keccak engine (permutation + sponge)
   Automatically enabled if ANY Keccak-based algorithm is requested */
#if ENABLE_SHA3_224     || \
    ENABLE_SHA3_256     || \
    ENABLE_SHA3_384     || \
    ENABLE_SHA3_512     || \
    ENABLE_SHAKE128     || \
    ENABLE_SHAKE256     || \
    ENABLE_RAWSHAKE128  || \
    ENABLE_RAWSHAKE256  || \
    ENABLE_RAW_KECCAK
  #ifndef ENABLE_KECCAK_CORE
    #define ENABLE_KECCAK_CORE 1
  #endif
#endif

/* ------------------------
   Function name prefix support
   ------------------------ */
#ifndef TSHASH_PREFIX
#define TSHASH_PREFIX /* empty by default */
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
    return ((x) << (n)) | ((x) >> (64 - (n)));
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

/* ==============================================================
   SHA-1 / SHA-2 Big-endian helpers (32/64-bit)
   For use with SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
   ============================================================== */

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
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)x;
}

static FORCE_INLINE void PUT_BE64(uint8_t *p, uint64_t x) {
    p[0] = (uint8_t)(x >> 56);
    p[1] = (uint8_t)(x >> 48);
    p[2] = (uint8_t)(x >> 40);
    p[3] = (uint8_t)(x >> 32);
    p[4] = (uint8_t)(x >> 24);
    p[5] = (uint8_t)(x >> 16);
    p[6] = (uint8_t)(x >> 8);
    p[7] = (uint8_t)x;
}

/* ----------------------
   SHA-1 / SHA-2 load/store macros (big-endian)
   ---------------------- */
#define SHA_LOAD32(p)    BE32((const uint8_t*)(p))
#define SHA_STORE32(p,x) PUT_BE32((uint8_t*)(p), x)
#define SHA_LOAD64(p)    BE64((const uint8_t*)(p))
#define SHA_STORE64(p,x) PUT_BE64((uint8_t*)(p), x)


/* ==============================================================
   Keccak / SHA-3 Big-endian helpers (32/64-bit)
   For use with Keccak, SHA3-224, SHA3-256, SHA3-384, SHA3-512
   ============================================================== */
#ifdef CPU_BIG_ENDIAN
/* Big-endian CPU: swap bytes manually for Keccak */
static FORCE_INLINE uint32_t KECCAK_BE32(const uint8_t *p) {
    return  (uint32_t)p[0]       |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static FORCE_INLINE void KECCAK_PUT_BE32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)(x      );
    p[1] = (uint8_t)(x >>  8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

static FORCE_INLINE uint64_t KECCAK_BE64(const uint8_t *p) {
    return  (uint64_t)p[0]       |
           ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static FORCE_INLINE void KECCAK_PUT_BE64(uint8_t *p, uint64_t x) {
    p[0] = (uint8_t)(x      );
    p[1] = (uint8_t)(x >>  8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
    p[4] = (uint8_t)(x >> 32);
    p[5] = (uint8_t)(x >> 40);
    p[6] = (uint8_t)(x >> 48);
    p[7] = (uint8_t)(x >> 56);
}

#else
/* Little-endian CPU: memory matches Keccak → no operation needed */
static FORCE_INLINE uint32_t KECCAK_BE32(const uint8_t *p) {
    return *(const uint32_t*)p;
}

static FORCE_INLINE void KECCAK_PUT_BE32(uint8_t *p, uint32_t x) {
    *(uint32_t*)p = x;
}

static FORCE_INLINE uint64_t KECCAK_BE64(const uint8_t *p) {
    return *(const uint64_t*)p;
}

static FORCE_INLINE void KECCAK_PUT_BE64(uint8_t *p, uint64_t x) {
    *(uint64_t*)p = x;
}
#endif

/* Load/store macros for Keccak */
#define KECCAK_LOAD32(p)    KECCAK_BE32((const uint8_t*)(p))
#define KECCAK_STORE32(p,x) KECCAK_PUT_BE32((uint8_t*)(p), x)
#define KECCAK_LOAD64(p)    KECCAK_BE64((const uint8_t*)(p))
#define KECCAK_STORE64(p,x) KECCAK_PUT_BE64((uint8_t*)(p), x)

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
   uint64_t len;
   uint8_t buf[SHA1_BLOCK_SIZE];
   size_t num;
} SHA1_CTX;

bool SHA1Init(SHA1_CTX *ctx);
bool SHA1Update(SHA1_CTX *ctx, const uint8_t *data, size_t len);
bool SHA1Final(SHA1_CTX *ctx, uint8_t digest[SHA1_DIGEST_SIZE]);

static FORCE_INLINE bool SHA1(const uint8_t *data, size_t len, uint8_t digest[SHA1_DIGEST_SIZE]) {
    SHA1_CTX ctx;
    return SHA1Init(&ctx) && SHA1Update(&ctx, data, len) && SHA1Final(&ctx, digest);
}

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
} SHA256_CTX;


bool SHA256Init(SHA256_CTX *ctx);
bool SHA256Update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
bool SHA256Final(SHA256_CTX *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);

static FORCE_INLINE bool SHA256(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]){
    SHA256_CTX ctx;
    return SHA256Init(&ctx) && SHA256Update(&ctx, data, len) && SHA256Final(&ctx, digest);
}

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

static FORCE_INLINE bool SHA224(const uint8_t *data, size_t len, uint8_t digest[SHA224_DIGEST_SIZE]) {
    SHA224_CTX ctx;
    return SHA224Init(&ctx) && SHA224Update(&ctx, data, len) && SHA224Final(&ctx, digest);   
}

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
} SHA512_CTX;

bool SHA512Init(SHA512_CTX *ctx);
bool SHA512Update(SHA512_CTX *ctx, const uint8_t *data, size_t len);
bool SHA512Final(SHA512_CTX *ctx, uint8_t digest[SHA512_DIGEST_SIZE]);

static FORCE_INLINE bool SHA512(const uint8_t *data, size_t len, uint8_t digest[SHA512_DIGEST_SIZE]) {
    SHA512_CTX ctx;
    return SHA512Init(&ctx) && SHA512Update(&ctx, data, len) && SHA512Final(&ctx, digest);
}

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

static FORCE_INLINE bool SHA384(const uint8_t *data, size_t len, uint8_t digest[SHA384_DIGEST_SIZE]) {
    SHA384_CTX ctx;
    return SHA384Init(&ctx) && SHA384Update(&ctx, data, len) && SHA384Final(&ctx, digest);   
}

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

static FORCE_INLINE bool SHA512_224(const uint8_t *data, size_t len, uint8_t digest[SHA512_224_DIGEST_SIZE]) {
    SHA512_224_CTX ctx;
    return SHA512_224Init(&ctx) && SHA512_224Update(&ctx, data, len) && SHA512_224Final(&ctx, digest);
}

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

static FORCE_INLINE bool SHA512_256(const uint8_t *data, size_t len, uint8_t digest[SHA512_256_DIGEST_SIZE]) {
    SHA512_256_CTX ctx;
    return SHA512_256Init(&ctx) && SHA512_256Update(&ctx, data, len) && SHA512_256Final(&ctx, digest);
}

static FORCE_INLINE int SHA512_256CompareOrder(const uint8_t *a, const uint8_t *b) {
    for (size_t i = 0; i < SHA512_256_DIGEST_SIZE; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

#endif

/* ======================================
   KECCAK (SHA-3 / SHAKE)
   ====================================== */
#if ENABLE_KECCAK_CORE
#define KeccakCompareOrder TSHASH_FN(KeccakCompareOrder)

#define KECCAK_BLOCK_SIZE 200

typedef struct {
    uint64_t state[5][5];
    uint8_t buf[KECCAK_BLOCK_SIZE];
    size_t buf_len;
    size_t rate;
    uint8_t suffix;
    int finalized;
} KECCAK_CTX;

/* -----------------------------
   Optional public API
   ----------------------------- */
#if ENABLE_RAW_KECCAK

    #define KeccakInit                TSHASH_FN(KeccakInit)
    #define keccakP                   TSHASH_FN(keccakP)
    #define KeccakAbsorb              TSHASH_FN(KeccakAbsorb)
    #define KeccakFinal               TSHASH_FN(KeccakFinal)
    #define KeccakSqueeze             TSHASH_FN(KeccakSqueeze)
    #define Keccak                    TSHASH_FN(Keccak)
    #define KeccakCompareOrder        TSHASH_FN(KeccakCompareOrder)

    bool KeccakInit(KECCAK_CTX *ctx, size_t rate, uint8_t suffix);
    bool keccakP(uint64_t state[5][5], unsigned int w, unsigned int nr);
    bool KeccakAbsorb(KECCAK_CTX *ctx, const uint8_t *data, size_t len);
    bool KeccakFinal(KECCAK_CTX *ctx);
    bool KeccakSqueeze(KECCAK_CTX *ctx, uint8_t *output, size_t outlen);
    bool Keccak(const uint8_t *data, size_t len,
                uint8_t *digest, size_t outlen,
                size_t rate, uint8_t suffix);

    static FORCE_INLINE int KeccakCompareOrder(const uint8_t *a, const uint8_t *b, size_t len) {
        for (size_t i = 0; i < len; i++) {
            if (a[i] < b[i]) return -1;
            if (a[i] > b[i]) return 1;
        }
        return 0;
    }

#endif

#endif // ENABLE_KECCAK_CORE

/* ======================================
   SHA3-224
   ====================================== */
#if ENABLE_SHA3_224
#define SHA3_224Init         TSHASH_FN(SHA3_224Init)
#define SHA3_224Absorb       TSHASH_FN(SHA3_224Absorb)
#define SHA3_224Final        TSHASH_FN(SHA3_224Final)
#define SHA3_224Squeeze      TSHASH_FN(SHA3_224Squeeze)
#define SHA3_224             TSHASH_FN(SHA3_224)
#define SHA3_224CompareOrder TSHASH_FN(SHA3_224CompareOrder)

#define SHA3_224_BLOCK_SIZE 144
#define SHA3_224_DIGEST_SIZE 28
#define SHA3_224_DOMAIN 0x06

typedef KECCAK_CTX SHA3_224_CTX;

bool SHA3_224Init(SHA3_224_CTX *ctx);
bool SHA3_224Absorb(SHA3_224_CTX *ctx, const uint8_t *data, size_t len);
bool SHA3_224Final(SHA3_224_CTX *ctx);
bool SHA3_224Squeeze(SHA3_224_CTX *ctx, uint8_t *output, size_t outlen);
bool SHA3_224(const uint8_t *data, size_t len, uint8_t digest[SHA3_224_DIGEST_SIZE]);

static FORCE_INLINE int SHA3_224CompareOrder(const uint8_t *a, const uint8_t *b) {
    for (size_t i = 0; i < SHA3_224_DIGEST_SIZE; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}
#endif

/* ======================================
   SHA3-256
   ====================================== */
#if ENABLE_SHA3_256
#define SHA3_256Init         TSHASH_FN(SHA3_256Init)
#define SHA3_256Absorb       TSHASH_FN(SHA3_256Absorb)
#define SHA3_256Final        TSHASH_FN(SHA3_256Final)
#define SHA3_256Squeeze      TSHASH_FN(SHA3_256Squeeze)
#define SHA3_256             TSHASH_FN(SHA3_256)
#define SHA3_256CompareOrder TSHASH_FN(SHA3_256CompareOrder)

#define SHA3_256_BLOCK_SIZE 136
#define SHA3_256_DIGEST_SIZE 32
#define SHA3_256_DOMAIN 0x06

typedef KECCAK_CTX SHA3_256_CTX;

bool SHA3_256Init(SHA3_256_CTX *ctx);
bool SHA3_256Absorb(SHA3_256_CTX *ctx, const uint8_t *data, size_t len);
bool SHA3_256Final(SHA3_256_CTX *ctx);
bool SHA3_256Squeeze(SHA3_256_CTX *ctx, uint8_t *output, size_t outlen);
bool SHA3_256(const uint8_t *data, size_t len, uint8_t digest[SHA3_256_DIGEST_SIZE]);

static FORCE_INLINE int SHA3_256CompareOrder(const uint8_t *a, const uint8_t *b) {
    for (size_t i = 0; i < SHA3_256_DIGEST_SIZE; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}
#endif

/* ======================================
   SHA3-384
   ====================================== */
#if ENABLE_SHA3_384
#define SHA3_384Init         TSHASH_FN(SHA3_384Init)
#define SHA3_384Absorb       TSHASH_FN(SHA3_384Absorb)
#define SHA3_384Final        TSHASH_FN(SHA3_384Final)
#define SHA3_384Squeeze      TSHASH_FN(SHA3_384Squeeze)
#define SHA3_384             TSHASH_FN(SHA3_384)
#define SHA3_384CompareOrder TSHASH_FN(SHA3_384CompareOrder)

#define SHA3_384_BLOCK_SIZE 104
#define SHA3_384_DIGEST_SIZE 48
#define SHA3_384_DOMAIN 0x06

typedef KECCAK_CTX SHA3_384_CTX;

bool SHA3_384Init(SHA3_384_CTX *ctx);
bool SHA3_384Absorb(SHA3_384_CTX *ctx, const uint8_t *data, size_t len);
bool SHA3_384Final(SHA3_384_CTX *ctx);
bool SHA3_384Squeeze(SHA3_384_CTX *ctx, uint8_t *output, size_t outlen);
bool SHA3_384(const uint8_t *data, size_t len, uint8_t digest[SHA3_384_DIGEST_SIZE]);

static FORCE_INLINE int SHA3_384CompareOrder(const uint8_t *a, const uint8_t *b) {
    for (size_t i = 0; i < SHA3_384_DIGEST_SIZE; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}
#endif

/* ======================================
   SHA3-512
   ====================================== */
#if ENABLE_SHA3_512
#define SHA3_512Init         TSHASH_FN(SHA3_512Init)
#define SHA3_512Absorb       TSHASH_FN(SHA3_512Absorb)
#define SHA3_512Final        TSHASH_FN(SHA3_512Final)
#define SHA3_512Squeeze      TSHASH_FN(SHA3_512Squeeze)
#define SHA3_512             TSHASH_FN(SHA3_512)
#define SHA3_512CompareOrder TSHASH_FN(SHA3_512CompareOrder)

#define SHA3_512_BLOCK_SIZE 72
#define SHA3_512_DIGEST_SIZE 64
#define SHA3_512_DOMAIN 0x06

typedef KECCAK_CTX SHA3_512_CTX;

bool SHA3_512Init(SHA3_512_CTX *ctx);
bool SHA3_512Absorb(SHA3_512_CTX *ctx, const uint8_t *data, size_t len);
bool SHA3_512Final(SHA3_512_CTX *ctx);
bool SHA3_512Squeeze(SHA3_512_CTX *ctx, uint8_t *output, size_t outlen);
bool SHA3_512(const uint8_t *data, size_t len, uint8_t digest[SHA3_512_DIGEST_SIZE]);

static FORCE_INLINE int SHA3_512CompareOrder(const uint8_t *a, const uint8_t *b) {
    for (size_t i = 0; i < SHA3_512_DIGEST_SIZE; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}
#endif

/* ======================================
   SHAKE128
   ====================================== */
#if ENABLE_SHAKE128
#define SHAKE128Init         TSHASH_FN(SHAKE128Init)
#define SHAKE128Absorb       TSHASH_FN(SHAKE128Absorb)
#define SHAKE128Final        TSHASH_FN(SHAKE128Final)
#define SHAKE128Squeeze      TSHASH_FN(SHAKE128Squeeze)
#define SHAKE128             TSHASH_FN(SHAKE128)
#define SHAKE128CompareOrder TSHASH_FN(SHAKE128CompareOrder)

#define SHAKE128_BLOCK_SIZE 168
#define SHAKE128_DOMAIN 0x1F

typedef KECCAK_CTX SHAKE128_CTX;

bool SHAKE128Init(SHAKE128_CTX *ctx);
bool SHAKE128Absorb(SHAKE128_CTX *ctx, const uint8_t *data, size_t len);
bool SHAKE128Final(SHAKE128_CTX *ctx);
bool SHAKE128Squeeze(SHAKE128_CTX *ctx, uint8_t *output, size_t outlen);
bool SHAKE128(const uint8_t *data, size_t len, uint8_t *digest, size_t outlen);

static FORCE_INLINE int SHAKE128CompareOrder(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}
#endif

/* ======================================
   SHAKE256
   ====================================== */
#if ENABLE_SHAKE256
#define SHAKE256Init         TSHASH_FN(SHAKE256Init)
#define SHAKE256Absorb       TSHASH_FN(SHAKE256Absorb)
#define SHAKE256Final        TSHASH_FN(SHAKE256Final)
#define SHAKE256Squeeze      TSHASH_FN(SHAKE256Squeeze)
#define SHAKE256             TSHASH_FN(SHAKE256)
#define SHAKE256CompareOrder TSHASH_FN(SHAKE256CompareOrder)

#define SHAKE256_BLOCK_SIZE 136
#define SHAKE256_DOMAIN 0x1F

typedef KECCAK_CTX SHAKE256_CTX;

bool SHAKE256Init(SHAKE256_CTX *ctx);
bool SHAKE256Absorb(SHAKE256_CTX *ctx, const uint8_t *data, size_t len);
bool SHAKE256Final(SHAKE256_CTX *ctx);
bool SHAKE256Squeeze(SHAKE256_CTX *ctx, uint8_t *output, size_t outlen);
bool SHAKE256(const uint8_t *data, size_t len, uint8_t *digest, size_t outlen);

static FORCE_INLINE int SHAKE256CompareOrder(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}
#endif

#if ENABLE_SHAKE128 || ENABLE_SHAKE256

static void Trunc_s(const uint8_t *X, size_t Xlen, size_t s, uint8_t *out);

static void concat_bits(const uint8_t *X, size_t x_bits,
                        const uint8_t *Y, size_t y_bits,
                        uint8_t *out);

#endif // ENABLE_SHAKE128 || ENABLE_SHAKE256

/* ======================================
   RawSHAKE128
   ====================================== */
#if ENABLE_RAWSHAKE128
#define RawSHAKE128Init         TSHASH_FN(RawSHAKE128Init)
#define RawSHAKE128Absorb       TSHASH_FN(RawSHAKE128Absorb)
#define RawSHAKE128Final        TSHASH_FN(RawSHAKE128Final)
#define RawSHAKE128Squeeze      TSHASH_FN(RawSHAKE128Squeeze)
#define RawSHAKE128             TSHASH_FN(RawSHAKE128)
#define RawSHAKE128CompareOrder TSHASH_FN(RawSHAKE128CompareOrder)

#define RAWSHAKE128_BLOCK_SIZE 168
#define RAWSHAKE128_DOMAIN 0x00

typedef KECCAK_CTX RawSHAKE128_CTX;

bool RawSHAKE128Init(RawSHAKE128_CTX *ctx);
bool RawSHAKE128Absorb(RawSHAKE128_CTX *ctx, const uint8_t *data, size_t len);
bool RawSHAKE128Final(RawSHAKE128_CTX *ctx);
bool RawSHAKE128Squeeze(RawSHAKE128_CTX *ctx, uint8_t *output, size_t outlen);
bool RawSHAKE128(const uint8_t *data, size_t len, uint8_t *digest, size_t outlen);

static FORCE_INLINE int RawSHAKE128CompareOrder(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}
#endif

/* ======================================
   RawSHAKE256
   ====================================== */
#if ENABLE_RAWSHAKE256
#define RawSHAKE256Init         TSHASH_FN(RawSHAKE256Init)
#define RawSHAKE256Absorb       TSHASH_FN(RawSHAKE256Absorb)
#define RawSHAKE256Final        TSHASH_FN(RawSHAKE256Final)
#define RawSHAKE256Squeeze      TSHASH_FN(RawSHAKE256Squeeze)
#define RawSHAKE256             TSHASH_FN(RawSHAKE256)
#define RawSHAKE256CompareOrder TSHASH_FN(RawSHAKE256CompareOrder)

#define RAWSHAKE256_BLOCK_SIZE 136
#define RAWSHAKE256_DOMAIN 0x00

typedef KECCAK_CTX RawSHAKE256_CTX;

bool RawSHAKE256Init(RawSHAKE256_CTX *ctx);
bool RawSHAKE256Absorb(RawSHAKE256_CTX *ctx, const uint8_t *data, size_t len);
bool RawSHAKE256Final(RawSHAKE256_CTX *ctx);
bool RawSHAKE256Squeeze(RawSHAKE256_CTX *ctx, uint8_t *output, size_t outlen);
bool RawSHAKE256(const uint8_t *data, size_t len, uint8_t *digest, size_t outlen);

static FORCE_INLINE int RawSHAKE256CompareOrder(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
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
