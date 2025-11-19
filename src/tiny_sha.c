/*
 * File: tiny_sha.c
 * Author: 0xNullll
 * Description: Implementation of the Tiny SHA library.
 *              Provides full support for all enabled SHA algorithms:
 *              SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256,
 *              and SHA-3 variants (SHA3-224, SHA3-256, SHA3-384, SHA3-512, as well as raw SHAKE if enabled).
 *              Includes initialization, update, and finalization functions for each variant.
 *              Uses endian-aware macros, CPU-optimized block processing, and clean modular design.
 *              Designed to be lightweight, self-contained, and suitable for embedded or minimal environments.
 * License: MIT
 */

#define TINY_SHA_IMPLEMENTATION
#include "tiny_sha.h"

#ifdef TINY_SHA_IMPLEMENTATION

#if ENABLE_SHA1

// SHA-1 constants
#define K_00_19 0x5a827999UL
#define K_20_39 0x6ed9eba1UL
#define K_40_59 0x8f1bbcdcUL
#define K_60_79 0xca62c1d6UL

// SHA-1 round functions f(t; B, C, D)
#define F_00_19(B,C,D)  (((B) & (C)) | ((~(B)) & (D)))            // Ch,           rounds 0–19
#define F_20_39(B,C,D)  ((B) ^ (C) ^ (D))                         // Parity,       rounds 20–39
#define F_40_59(B,C,D)  (((B) & (C)) | ((B) & (D)) | ((C) & (D))) // Maj,          rounds 40–59
#define F_60_79(B,C,D)  F_20_39((B),(C),(D))                      // Parity again, rounds 60–79

bool SHA1Init(SHA1_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));

    ctx->h0 = 0x67452301UL;
    ctx->h1 = 0xefcdab89UL;
    ctx->h2 = 0x98badcfeUL;
    ctx->h3 = 0x10325476UL;
    ctx->h4 = 0xc3d2e1f0UL;
    return true;
}

static bool SHA1ProcessBlock(SHA1_CTX *ctx, const uint8_t *block) {
    uint32_t W[80];
    uint32_t A,B,C,D,E,TEMP;

    // Copy block to W[0..15] (big-endian)
    for(int i = 0; i < 16; i++)
        W[i] = SHA_LOAD32(block + i*4);

    // Expand W[16..79]
    for(int t=16;t<80;t++) {
        W[t] = ROTL32(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
    }

    // Initialize working variables
    A = ctx->h0; B = ctx->h1; C = ctx->h2; D = ctx->h3; E = ctx->h4;

    // Main loop
    for(int t=0;t<80;t++) {
        uint32_t f,k;
        if(t<=19) {
            f=F_00_19(B,C,D); k=K_00_19;
        }
        else if(t<=39) {
            f=F_20_39(B,C,D); k=K_20_39;
        }
        else if(t<=59) {
            f=F_40_59(B,C,D); k=K_40_59;
        }
        else {
            f=F_60_79(B,C,D); k=K_60_79;
        }

        TEMP = ROTL32(A,5) + f + E + W[t] + k;
        E = D;
        D = C;
        C = ROTL32(B,30);
        B = A;
        A = TEMP;
    }

    // Update hash state
    ctx->h0 += A; ctx->h1 += B; ctx->h2 += C; ctx->h3 += D; ctx->h4 += E;
    return true;
} 

bool SHA1Update(SHA1_CTX *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data) return false;

    ctx->len += (uint64_t)len * 8;  // total length in bits

    while (len > 0) {
        size_t to_copy = 64 - ctx->num;   // remaining space in buffer
        if (to_copy > len) to_copy = len;

        memcpy(ctx->buf + ctx->num, data, to_copy);
        ctx->num += (uint32_t)to_copy;    // ctx->num is 32-bit
        data += to_copy;
        len -= to_copy;

        if (ctx->num == 64) {
            if (!SHA1ProcessBlock(ctx, ctx->buf)) return false;
            ctx->num = 0;
        }
    }

    return true;
}

bool SHA1Final(SHA1_CTX *ctx, uint8_t digest[SHA1_DIGEST_SIZE]) {
    if (!ctx || !digest) return false;

    uint8_t block[SHA1_BLOCK_SIZE] = {0};

    // Copy leftover bytes and append 0x80
    memcpy(block, ctx->buf, ctx->num);
    block[ctx->num++] = 0x80;

    // Pad zeros
    if (ctx->num > 56) {
        memset(block + ctx->num, 0, SHA1_BLOCK_SIZE - ctx->num);
        if (!SHA1ProcessBlock(ctx, block)) return false;
        memset(block, 0, 56); // new zeroed block
    } else {
        memset(block + ctx->num, 0, 56 - ctx->num);
    }

    // Append length in bits using STORE64 (CPU-endian aware)
    SHA_STORE64(block + 56, ctx->len);

    // Process final block
    if (!SHA1ProcessBlock(ctx, block)) return false;

    // Output digest using STORE32
    SHA_STORE32(digest + 0,  ctx->h0);
    SHA_STORE32(digest + 4,  ctx->h1);
    SHA_STORE32(digest + 8,  ctx->h2);
    SHA_STORE32(digest + 12, ctx->h3);
    SHA_STORE32(digest + 16, ctx->h4);

    return true;
}

#endif

#if ENABLE_SHA256

// SHA-256 constants
static const uint32_t K256[64] = {
    0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,
    0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
    0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,
    0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
    0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,
    0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
    0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,
    0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
    0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,
    0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
    0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,
    0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
    0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,
    0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
    0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,
    0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
};

// Big sigma — used for working state
#define SHA256_BSIG0(x) (ROTR32((uint32_t)(x), 2)  ^ ROTR32((uint32_t)(x), 13) ^ ROTR32((uint32_t)(x), 22))
#define SHA256_BSIG1(x) (ROTR32((uint32_t)(x), 6)  ^ ROTR32((uint32_t)(x), 11) ^ ROTR32((uint32_t)(x), 25))

// Small sigma — used for message schedule expansion
#define SHA256_SSIG0(x) (ROTR32((uint32_t)(x),7) ^ ROTR32((uint32_t)(x),18) ^ ((uint32_t)(x) >> 3))
#define SHA256_SSIG1(x) (ROTR32((uint32_t)(x),17) ^ ROTR32((uint32_t)(x),19) ^ ((uint32_t)(x) >> 10))

// Logical functions
#define SHA256_CH(x,y,z)   ((x & y) ^ (~x & z))
#define SHA256_MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))

bool SHA256Init(SHA256_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));

    ctx->state[0] = 0x6a09e667UL;
    ctx->state[1] = 0xbb67ae85UL;
    ctx->state[2] = 0x3c6ef372UL;
    ctx->state[3] = 0xa54ff53aUL;
    ctx->state[4] = 0x510e527fUL;
    ctx->state[5] = 0x9b05688cUL;
    ctx->state[6] = 0x1f83d9abUL;
    ctx->state[7] = 0x5be0cd19UL;
    
    return true;
}

static bool SHA256ProcessBlock(SHA256_CTX *ctx, const uint8_t *block) {
    uint32_t W[64], A, B, C, D, E, F, G, H, T1, T2;

    // Prepare 16 words
    for(int t=0;t<16;t++)
        W[t] = BE32(block + t*4);

    // Extend to 64 words
    for(int t=16;t<64;t++)
        W[t] = SHA256_SSIG1(W[t-2]) + W[t-7] + SHA256_SSIG0(W[t-15]) + W[t-16];

    // Initialize
    A=ctx->state[0]; B=ctx->state[1]; C=ctx->state[2]; D=ctx->state[3];
    E=ctx->state[4]; F=ctx->state[5]; G=ctx->state[6]; H=ctx->state[7];

    for(int t=0;t<64;t++){
        T1 = H + SHA256_BSIG1(E) + SHA256_CH(E,F,G) + K256[t] + W[t];
        T2 = SHA256_BSIG0(A) + SHA256_MAJ(A,B,C);
        H=G; G=F; F=E; E=D+T1;
        D=C; C=B; B=A; A=T1+T2;
    }

    ctx->state[0]+=A; ctx->state[1]+=B; ctx->state[2]+=C; ctx->state[3]+=D;
    ctx->state[4]+=E; ctx->state[5]+=F; ctx->state[6]+=G; ctx->state[7]+=H;

    return true;
}

bool SHA256Update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    ctx->len += len;

    // Fill buffer if leftover
    if(ctx->buf_len){
        size_t fill = SHA256_BLOCK_SIZE - ctx->buf_len;
        if(fill>len) fill=len;
        memcpy(ctx->buf+ctx->buf_len, data, fill);
        ctx->buf_len+=fill; i+=fill;
        if(ctx->buf_len==SHA256_BLOCK_SIZE){
            if(!SHA256ProcessBlock(ctx, ctx->buf)) return false;
            ctx->buf_len=0;
        }
    }

    // Process full blocks directly
    for(; i+SHA256_BLOCK_SIZE <= len; i+=SHA256_BLOCK_SIZE)
        if(!SHA256ProcessBlock(ctx, data+i)) return false;

    // Copy remaining
    if(i<len){
        ctx->buf_len=len-i;
        memcpy(ctx->buf, data+i, ctx->buf_len);
    }

    return true;
}

bool SHA256Final(SHA256_CTX *ctx, uint8_t digest[SHA256_DIGEST_SIZE]) {
    if (!ctx || !digest) return false;

    uint8_t block[SHA256_BLOCK_SIZE] = {0};

    // Copy remaining bytes and append 0x80
    memcpy(block, ctx->buf, ctx->buf_len);
    block[ctx->buf_len++] = 0x80;

    // Compute padding length (56 bytes reserved for length)
    size_t pad_len = (ctx->buf_len <= 56) ? (56 - ctx->buf_len) : (64 + 56 - ctx->buf_len);
    memset(block + ctx->buf_len, 0, pad_len);

    // Append message length in bits using STORE64
    uint64_t bit_len = ctx->len * 8;
    SHA_STORE64(block + 56, bit_len);

    // Process final block
    if (!SHA256ProcessBlock(ctx, block)) return false;

    // If padding + length overflowed one block
    if (ctx->buf_len + pad_len + 8 > 64) {
        memset(block, 0, SHA256_BLOCK_SIZE);
        if (!SHA256ProcessBlock(ctx, block)) return false;
    }

    // Store digest using STORE32 (CPU-endian optimized)
    for (size_t i = 0; i < 8; i++)
        SHA_STORE32(digest + i*4, ctx->state[i]);

    return true;
}

#endif

#if ENABLE_SHA224

bool SHA224Init(SHA224_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));

    ctx->state[0] = 0xc1059ed8UL;
    ctx->state[1] = 0x367cd507UL;
    ctx->state[2] = 0x3070dd17UL;
    ctx->state[3] = 0xf70e5939UL;
    ctx->state[4] = 0xffc00b31UL;
    ctx->state[5] = 0x68581511UL;
    ctx->state[6] = 0x64f98fa7UL;
    ctx->state[7] = 0xbefa4fa4UL;

    return true;
}

bool SHA224Update(SHA224_CTX *ctx, const uint8_t *data, size_t len) {
    return SHA256Update((SHA256_CTX*)ctx, data, len);
}

bool SHA224Final(SHA224_CTX *ctx, uint8_t digest[SHA224_DIGEST_SIZE]) {
    uint8_t full_digest[SHA256_DIGEST_SIZE];
    if (!SHA256Final((SHA256_CTX*)ctx, full_digest)) return false;
    memcpy(digest, full_digest, SHA224_DIGEST_SIZE);
    return true;
}


#endif

#if ENABLE_SHA512

static const uint64_t K512[80] = {
    U64(0x428a2f98d728ae22), U64(0x7137449123ef65cd),
    U64(0xb5c0fbcfec4d3b2f), U64(0xe9b5dba58189dbbc),
    U64(0x3956c25bf348b538), U64(0x59f111f1b605d019),
    U64(0x923f82a4af194f9b), U64(0xab1c5ed5da6d8118),
    U64(0xd807aa98a3030242), U64(0x12835b0145706fbe),
    U64(0x243185be4ee4b28c), U64(0x550c7dc3d5ffb4e2),
    U64(0x72be5d74f27b896f), U64(0x80deb1fe3b1696b1),
    U64(0x9bdc06a725c71235), U64(0xc19bf174cf692694),
    U64(0xe49b69c19ef14ad2), U64(0xefbe4786384f25e3),
    U64(0x0fc19dc68b8cd5b5), U64(0x240ca1cc77ac9c65),
    U64(0x2de92c6f592b0275), U64(0x4a7484aa6ea6e483),
    U64(0x5cb0a9dcbd41fbd4), U64(0x76f988da831153b5),
    U64(0x983e5152ee66dfab), U64(0xa831c66d2db43210),
    U64(0xb00327c898fb213f), U64(0xbf597fc7beef0ee4),
    U64(0xc6e00bf33da88fc2), U64(0xd5a79147930aa725),
    U64(0x06ca6351e003826f), U64(0x142929670a0e6e70),
    U64(0x27b70a8546d22ffc), U64(0x2e1b21385c26c926),
    U64(0x4d2c6dfc5ac42aed), U64(0x53380d139d95b3df),
    U64(0x650a73548baf63de), U64(0x766a0abb3c77b2a8),
    U64(0x81c2c92e47edaee6), U64(0x92722c851482353b),
    U64(0xa2bfe8a14cf10364), U64(0xa81a664bbc423001),
    U64(0xc24b8b70d0f89791), U64(0xc76c51a30654be30),
    U64(0xd192e819d6ef5218), U64(0xd69906245565a910),
    U64(0xf40e35855771202a), U64(0x106aa07032bbd1b8),
    U64(0x19a4c116b8d2d0c8), U64(0x1e376c085141ab53),
    U64(0x2748774cdf8eeb99), U64(0x34b0bcb5e19b48a8),
    U64(0x391c0cb3c5c95a63), U64(0x4ed8aa4ae3418acb),
    U64(0x5b9cca4f7763e373), U64(0x682e6ff3d6b2b8a3),
    U64(0x748f82ee5defb2fc), U64(0x78a5636f43172f60),
    U64(0x84c87814a1f0ab72), U64(0x8cc702081a6439ec),
    U64(0x90befffa23631e28), U64(0xa4506cebde82bde9),
    U64(0xbef9a3f7b2c67915), U64(0xc67178f2e372532b),
    U64(0xca273eceea26619c), U64(0xd186b8c721c0c207),
    U64(0xeada7dd6cde0eb1e), U64(0xf57d4f7fee6ed178),
    U64(0x06f067aa72176fba), U64(0x0a637dc5a2c898a6),
    U64(0x113f9804bef90dae), U64(0x1b710b35131c471b),
    U64(0x28db77f523047d84), U64(0x32caab7b40c72493),
    U64(0x3c9ebe0a15c9bebc), U64(0x431d67c49c100d4c),
    U64(0x4cc5d4becb3e42b6), U64(0x597f299cfc657e2a),
    U64(0x5fcb6fab3ad6faec), U64(0x6c44198c4a475817)
};

#define SHA512_BSIG0(x) (ROTR64((uint64_t)(x), 28) ^ ROTR64((uint64_t)(x), 34) ^ ROTR64((uint64_t)(x), 39))
#define SHA512_BSIG1(x) (ROTR64((uint64_t)(x), 14) ^ ROTR64((uint64_t)(x), 18) ^ ROTR64((uint64_t)(x), 41))

#define SHA512_SSIG0(x) (ROTR64((uint64_t)(x), 1)  ^ ROTR64((uint64_t)(x), 8)  ^ ((uint64_t)(x) >> 7))
#define SHA512_SSIG1(x) (ROTR64((uint64_t)(x), 19) ^ ROTR64((uint64_t)(x), 61) ^ ((uint64_t)(x) >> 6))

#define SHA512_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA512_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

bool SHA512Init(SHA512_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));

    ctx->state[0] = U64(0x6a09e667f3bcc908);
    ctx->state[1] = U64(0xbb67ae8584caa73b);
    ctx->state[2] = U64(0x3c6ef372fe94f82b);
    ctx->state[3] = U64(0xa54ff53a5f1d36f1);
    ctx->state[4] = U64(0x510e527fade682d1);
    ctx->state[5] = U64(0x9b05688c2b3e6c1f);
    ctx->state[6] = U64(0x1f83d9abfb41bd6b);
    ctx->state[7] = U64(0x5be0cd19137e2179);

    return true;
}

static bool SHA512ProcessBlock(SHA512_CTX *ctx, const uint8_t *block) {
    uint64_t W[80], a,b,c,d,e,f,g,h,T1,T2;

    for (int t=0; t<16; t++) 
        W[t] = SHA_LOAD64(block + t*8);

    for (int t=16; t<80; t++) 
        W[t] = SHA512_SSIG1(W[t-2]) + W[t-7] + SHA512_SSIG0(W[t-15]) + W[t-16];

    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];

    for (int t=0; t<80; t++) {
        T1 = h + SHA512_BSIG1(e) + SHA512_CH(e,f,g) + K512[t] + W[t];
        T2 = SHA512_BSIG0(a) + SHA512_MAJ(a,b,c);
        h=g; g=f; f=e; e=d+T1;
        d=c; c=b; b=a; a=T1+T2;
    }

    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;

    return true;
}

bool SHA512Update(SHA512_CTX *ctx, const uint8_t *data, size_t len) {
    if (!data || !len) return false;
    size_t i = 0;

    // update bit length
    uint64_t nbits = (uint64_t)len << 3;
    ctx->Nl += nbits;
    if (ctx->Nl < nbits) ctx->Nh++;  // carry
    ctx->Nh += (uint64_t)len >> 61;

    if (ctx->buf_len && (ctx->buf_len + len >= 128)) {
        size_t fill = 128 - ctx->buf_len;
        memcpy(ctx->buf + ctx->buf_len, data, fill);
        if (!SHA512ProcessBlock(ctx, ctx->buf)) return false;
        ctx->buf_len = 0;
        i = fill;
    }

    for (; i + 127 < len; i += 128)
        if (!SHA512ProcessBlock(ctx, data + i)) return false;

    if (i < len) {
        memcpy(ctx->buf + ctx->buf_len, data + i, len - i);
        ctx->buf_len += (len - i);
    }
    return true;
}

bool SHA512Final(SHA512_CTX *ctx, uint8_t digest[SHA512_DIGEST_SIZE]) {
    if (!ctx || !digest) return false;

    uint8_t pad[128] = {0};
    pad[0] = 0x80;  // first byte is 0x80

    uint8_t len_bytes[16];
    uint64_t high = ctx->Nh, low = ctx->Nl;

    // encode length (big-endian aware)
    SHA_STORE64(len_bytes, high);
    SHA_STORE64(len_bytes + 8, low);

    // compute padding length to reach 112 bytes (128-16) before length
    size_t pad_len = (ctx->buf_len < 112) ? (112 - ctx->buf_len)
                                          : (128 + 112 - ctx->buf_len);

    // update with padding
    if (!SHA512Update(ctx, pad, pad_len)) return false;

    // update with length
    if (!SHA512Update(ctx, len_bytes, 16)) return false;

    // store final hash state into digest using STORE64 (CPU-endian aware)
    for (int i = 0; i < 8; i++)
        SHA_STORE64(digest + i*8, ctx->state[i]);

    return true;
}

#endif

#if ENABLE_SHA384

bool SHA384Init(SHA384_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));

    ctx->state[0] = U64(0xcbbb9d5dc1059ed8);
    ctx->state[1] = U64(0x629a292a367cd507);
    ctx->state[2] = U64(0x9159015a3070dd17);
    ctx->state[3] = U64(0x152fecd8f70e5939);
    ctx->state[4] = U64(0x67332667ffc00b31);
    ctx->state[5] = U64(0x8eb44a8768581511);
    ctx->state[6] = U64(0xdb0c2e0d64f98fa7);
    ctx->state[7] = U64(0x47b5481dbefa4fa4);

    return true;
}

bool SHA384Update(SHA384_CTX *ctx, const uint8_t *data, size_t len) {
    return SHA512Update((SHA512_CTX*)ctx, data, len);
}

bool SHA384Final(SHA384_CTX *ctx, uint8_t digest[SHA384_DIGEST_SIZE]) {
    uint8_t full_digest[SHA512_DIGEST_SIZE];
    if (!SHA512Final((SHA512_CTX*)ctx, full_digest)) return false;
    memcpy(digest, full_digest, SHA384_DIGEST_SIZE);
    return true;
}

#endif

#if ENABLE_SHA512_224

bool SHA512_224Init(SHA512_224_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));

    ctx->state[0] = U64(0x8c3d37c819544da2);
    ctx->state[1] = U64(0x73e1996689dcd4d6);
    ctx->state[2] = U64(0x1dfab7ae32ff9c82);
    ctx->state[3] = U64(0x679dd514582f9fcf);
    ctx->state[4] = U64(0x0f6d2b697bd44da8);
    ctx->state[5] = U64(0x77e36f7304c48942);
    ctx->state[6] = U64(0x3f9d85a86a1d36c8);
    ctx->state[7] = U64(0x1112e6ad91d692a1);

    return true;
}

bool SHA512_224Update(SHA512_224_CTX *ctx, const uint8_t *data, size_t len) {
    return SHA512Update((SHA512_CTX*)ctx, data, len);
}

bool SHA512_224Final(SHA512_224_CTX *ctx, uint8_t digest[SHA512_224_DIGEST_SIZE]) {
    uint8_t full_digest[SHA512_DIGEST_SIZE];
    if (!SHA512Final((SHA512_CTX*)ctx, full_digest)) return false;
    memcpy(digest, full_digest, SHA512_224_DIGEST_SIZE);
    return true;
}

#endif

#if ENABLE_SHA512_256

bool SHA512_256Init(SHA512_256_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));

    ctx->state[0] = U64(0x22312194fc2bf72c);
    ctx->state[1] = U64(0x9f555fa3c84c64c2);
    ctx->state[2] = U64(0x2393b86b6f53b151);
    ctx->state[3] = U64(0x963877195940eabd);
    ctx->state[4] = U64(0x96283ee2a88effe3);
    ctx->state[5] = U64(0xbe5e1e2553863992);
    ctx->state[6] = U64(0x2b0199fc2c85b8aa);
    ctx->state[7] = U64(0x0eb72ddc81c52ca2);

    return true;
}

bool SHA512_256Update(SHA512_256_CTX *ctx, const uint8_t *data, size_t len) {
    return SHA512Update((SHA512_CTX*)ctx, data, len);
}

bool SHA512_256Final(SHA512_256_CTX *ctx, uint8_t digest[SHA512_256_DIGEST_SIZE]) {
    uint8_t full_digest[SHA512_DIGEST_SIZE];
    if (!SHA512Final((SHA512_CTX*)ctx, full_digest)) return false;
    memcpy(digest, full_digest, SHA512_256_DIGEST_SIZE);
    return true;
}

#endif

#if ENABLE_KECCAK_CORE

// Precomputed rotation offsets for the ρ (rho) step of Keccak-f[1600].
// Each entry rhotates[x][y] specifies the number of bits to rotate the lane A[x][y] left.
// Derived from Section 3.2.2 of FIPS PUB 202, modulo lane size w=64.
static const uint8_t rhotates[5][5] = {
    {  0,  1, 62, 28, 27 },
    { 36, 44,  6, 55, 20 },
    {  3, 10, 43, 25, 39 },
    { 41, 45, 15, 21,  8 },
    { 18,  2, 61, 56, 14 }
};

// Precomputed round constants for the ι (iota) step of Keccak-f[1600].
// Each entry iotas[round] corresponds to the round constant RC for that round.
// Derived from Section 3.2.5 of FIPS PUB 202, expressed as 64-bit unsigned integers.
// Precomputing the values improves clarity and runtime efficiency.
static const uint64_t iotas[24] = {
    U64(0x0000000000000001), U64(0x0000000000008082),
    U64(0x800000000000808a), U64(0x8000000080008000),
    U64(0x000000000000808b), U64(0x0000000080000001),
    U64(0x8000000080008081), U64(0x8000000000008009),
    U64(0x000000000000008a), U64(0x0000000000000088),
    U64(0x0000000080008009), U64(0x000000008000000a),
    U64(0x000000008000808b), U64(0x800000000000008b),
    U64(0x8000000000008089), U64(0x8000000000008003),
    U64(0x8000000000008002), U64(0x8000000000000080),
    U64(0x000000000000800a), U64(0x800000008000000a),
    U64(0x8000000080008081), U64(0x8000000000008080),
    U64(0x0000000080000001), U64(0x8000000080008008)
};

#define KECCAK_ROUNDS 24

#define SHA3_KECCAK_F_WIDTH 1600

/*
 * Straightforward implementation of the θ (theta) step of Keccak-f[1600],
 * following Section 3.2.1 of FIPS PUB 202 "SHA-3 Standard: Permutation-Based
 * Hash and Extendible-Output Functions" as closely as possible. 
 */
static void Theta(uint64_t A[5][5]) {
    uint64_t C[5], D[5];

    C[0] = A[0][0];
    C[1] = A[0][1];
    C[2] = A[0][2];
    C[3] = A[0][3];
    C[4] = A[0][4];

    for (int y = 1; y < 5; y++) {
        C[0] ^= A[y][0];
        C[1] ^= A[y][1];
        C[2] ^= A[y][2];
        C[3] ^= A[y][3];
        C[4] ^= A[y][4];
    }

    D[0] = ROTL64(C[1], 1) ^ C[4];
    D[1] = ROTL64(C[2], 1) ^ C[0];
    D[2] = ROTL64(C[3], 1) ^ C[1];
    D[3] = ROTL64(C[4], 1) ^ C[2];
    D[4] = ROTL64(C[0], 1) ^ C[3];

    for (int y = 0; y < 5; y++) {
        A[y][0] ^= D[0];
        A[y][1] ^= D[1];
        A[y][2] ^= D[2];
        A[y][3] ^= D[3];
        A[y][4] ^= D[4];
    }
}

// /*
//  * Straightforward, table-driven implementation of the ρ (rho) step of Keccak-f[1600],
//  * following Section 3.2.2 of FIPS PUB 202 "SHA-3 Standard: Permutation-Based
//  * Hash and Extendible-Output Functions". 
//  * 
//  * Uses precomputed lane rotation offsets (rhotates) for maximum clarity and efficiency.
//  */

static void Rho(uint64_t A[5][5]) {
    for (int y = 0; y < 5; y++) {
        A[y][0] = ROTL64(A[y][0], rhotates[y][0]);
        A[y][1] = ROTL64(A[y][1], rhotates[y][1]);
        A[y][2] = ROTL64(A[y][2], rhotates[y][2]);
        A[y][3] = ROTL64(A[y][3], rhotates[y][3]);
        A[y][4] = ROTL64(A[y][4], rhotates[y][4]);
    }
}

/*
 * Straightforward, fully unrolled implementation of the π (pi) step of Keccak-f[1600],
 * following Section 3.2.3 of FIPS PUB 202 "SHA-3 Standard: Permutation-Based
 * Hash and Extendible-Output Functions".
 *
 * Maps each lane A[x][y] to its new position A[y][(2x + 3y) % 5] according to the spec.
 * Loop is unrolled manually to avoid modulo operations and improve performance.
 */
static void Pi(uint64_t A[5][5]) {
    uint64_t T[5][5];

    // T = A
    memcpy(T, A, sizeof(T));

    // A[y][x] = T[x][(3*y+x)%5]
    A[0][0] = T[0][0];
    A[0][1] = T[1][1];
    A[0][2] = T[2][2];
    A[0][3] = T[3][3];
    A[0][4] = T[4][4];

    A[1][0] = T[0][3];
    A[1][1] = T[1][4];
    A[1][2] = T[2][0];
    A[1][3] = T[3][1];
    A[1][4] = T[4][2];

    A[2][0] = T[0][1];
    A[2][1] = T[1][2];
    A[2][2] = T[2][3];
    A[2][3] = T[3][4];
    A[2][4] = T[4][0];

    A[3][0] = T[0][4];
    A[3][1] = T[1][0];
    A[3][2] = T[2][1];
    A[3][3] = T[3][2];
    A[3][4] = T[4][3];

    A[4][0] = T[0][2];
    A[4][1] = T[1][3];
    A[4][2] = T[2][4];
    A[4][3] = T[3][0];
    A[4][4] = T[4][1];
}

/*
 * Straightforward, row-wise implementation of the χ (chi) step of Keccak-f[1600],
 * following Section 3.2.4 of FIPS PUB 202 "SHA-3 Standard: Permutation-Based
 * Hash and Extendible-Output Functions".
 *
 * Applies a non-linear transformation on each row: 
 * each bit A[y][x] is XORed with the AND of the complement of the next bit and the bit after that.
 * Loop over rows; each row is processed with fully unrolled bitwise operations for clarity.
 */
static void Chi(uint64_t A[5][5]) {
    uint64_t C[5];

    for (int y = 0; y < 5; y++) {
        C[0] = A[y][0] ^ (~A[y][1] & A[y][2]);
        C[1] = A[y][1] ^ (~A[y][2] & A[y][3]);
        C[2] = A[y][2] ^ (~A[y][3] & A[y][4]);
        C[3] = A[y][3] ^ (~A[y][4] & A[y][0]);
        C[4] = A[y][4] ^ (~A[y][0] & A[y][1]);

        A[y][0] = C[0];
        A[y][1] = C[1];
        A[y][2] = C[2];
        A[y][3] = C[3];
        A[y][4] = C[4];
    }
}

/*
 * Straightforward implementation of the ι (iota) step of Keccak-f[1600],
 * following Section 3.2.5 of FIPS PUB 202 "SHA-3 Standard: Permutation-Based
 * Hash and Extendible-Output Functions".
 *
 * Injects the round constant for round 'i' into the first lane A[0][0] via XOR.
 * Precomputed 64-bit constants (iotas) are used for clarity and efficiency.
 */
static void Iota(uint64_t A[5][5], size_t i) {
    A[0][0] ^= iotas[i];
}

/*
 * Executes the Keccak-p[b, nr] permutation on state A,
 * performing 'nr' rounds as specified in FIPS PUB 202.
 *
 * Each round applies, in order, the five step mappings:
 * θ (Theta), ρ (Rho), π (Pi), χ (Chi), and ι (Iota).
 * The number of rounds is parameterized by 'nr', and precomputed
 * constants and rotation offsets are used for efficiency.
 */
static FORCE_INLINE void Round(uint64_t A[5][5], size_t i, uint64_t lane_mask) {
    Theta(A);
    Rho(A);
    Pi(A);
    Chi(A);

    // Apply lane mask after each step or at least here
    for (size_t y = 0; y < 5; y++) {
        for (size_t x = 0; x < 5; x++) {
            A[y][x] &= lane_mask;
        }
    }

    Iota(A, i);  // round constant step
}

/* ----------------------
   Keccak block functions
   ---------------------- */
static FORCE_INLINE void absorb_block(uint64_t A[5][5], const uint8_t *buf, size_t r) {
    size_t lanes = r / 8;
    for (size_t i = 0; i < lanes; i++) {
        size_t x = i % 5;
        size_t y = i / 5;
        uint64_t lane = KECCAK_LOAD64(buf + i * 8);

    A[y][x] ^= lane;
    }
}

static FORCE_INLINE void squeeze_block(uint64_t A[5][5], uint8_t *buf, size_t r) {
    size_t lanes = r / 8;
    for (size_t i = 0; i < lanes; i++) {
        size_t x = i % 5;
        size_t y = i / 5;
        
        uint64_t lane = A[y][x];
        
        KECCAK_STORE64(buf + i * 8, lane);
    }
}

bool keccakP(uint64_t state[5][5], unsigned int w, unsigned int nr) {
    if (!state || nr > KECCAK_ROUNDS || (w != 64 && w != 32)) return false;

    uint64_t mask = (w == 64) ? 0xFFFFFFFFFFFFFFFFULL : 0xFFFFFFFFULL;

    for (unsigned int i = 0; i < nr; i++) {
        Round(state, i, mask); // pass mask to Round so lane size is applied
    }

    return true;
}

/* -------------------------
   KECCAK_CTX wrappers
   ------------------------- */
static FORCE_INLINE bool k_init_wrap(KECCAK_CTX *ctx, size_t rate, uint8_t suffix) {
    memset(ctx->state, 0, sizeof(ctx->state));
    memset(ctx->buf, 0, sizeof(ctx->buf));
    ctx->buf_len = 0;
    ctx->rate = rate;
    ctx->suffix = suffix;
    ctx->finalized = 0;
    return true;
}

/* absorb into ctx (buffers partial blocks, processes full blocks) */
static bool k_absorb_wrap(KECCAK_CTX *ctx, const uint8_t *input, size_t inlen) {
    if (ctx->finalized) return false; // Cannot absorb after finalization

    size_t offset = 0;

    while (inlen > 0) {
        size_t space = ctx->rate - ctx->buf_len;
        size_t to_copy = (inlen < space) ? inlen : space;

        memcpy(ctx->buf + ctx->buf_len, input + offset, to_copy);
        ctx->buf_len += to_copy;
        offset += to_copy;
        inlen -= to_copy;

        if (ctx->buf_len == ctx->rate) {
            absorb_block(ctx->state, ctx->buf, ctx->rate);
            keccakP(ctx->state, 64, KECCAK_ROUNDS);
            ctx->buf_len = 0;
        }
    }

    return true;
}

/* finalization: multi-rate padding (domain suffix + 10*1), absorb last block */
static bool k_final_wrap(KECCAK_CTX *ctx) {
    if (ctx->finalized) return false;

    size_t r = ctx->rate;
    size_t num = ctx->buf_len;

    memset(ctx->buf + num, 0, r - num);

    if (num == r - 1)
        ctx->buf[num] ^= ctx->suffix ^ 0x80;  // combine suffix + final bit
    else {
        ctx->buf[num] ^= ctx->suffix;
        ctx->buf[r - 1] ^= 0x80;
    }

    absorb_block(ctx->state, ctx->buf, r);
    keccakP(ctx->state, 64, KECCAK_ROUNDS);

    ctx->buf_len = 0;
    ctx->finalized = 1;
    return true;
}

/* squeeze: produce outlen bytes. Uses permutation between full-rate blocks */
static bool k_squeeze_wrap(KECCAK_CTX *ctx, uint8_t *output, size_t outlen) {
    if (!ctx->finalized) {
        if (!k_final_wrap(ctx)) return false;
    }

    size_t offset = 0;
    uint8_t tmp[200];

    while (outlen > 0) {
        size_t block = (outlen < ctx->rate) ? outlen : ctx->rate;

        /* always squeeze into tmp, copy requested bytes */
        squeeze_block(ctx->state, tmp, ctx->rate);
        memcpy(output + offset, tmp, block);

        offset += block;
        outlen -= block;

        if (outlen > 0)
            keccakP(ctx->state, 64, KECCAK_ROUNDS);
    }

    return true;
}

static FORCE_INLINE bool k_hash_wrap(const uint8_t *data, size_t len,
                                     uint8_t *digest, size_t outlen,
                                     size_t rate, uint8_t suffix) {
    KECCAK_CTX ctx;
    return k_init_wrap(&ctx, rate, suffix)
        && k_absorb_wrap(&ctx, data, len)
        && k_final_wrap(&ctx)
        && k_squeeze_wrap(&ctx, digest, outlen);
}

#if ENABLE_RAW_KECCAK

    bool KeccakInit(KECCAK_CTX *ctx, size_t rate, uint8_t suffix) {
        return k_init_wrap(ctx, rate, suffix);
    }

    bool KeccakAbsorb(KECCAK_CTX *ctx, const uint8_t *data, size_t len) {
        return k_absorb_wrap(ctx, data, len);
    }

    bool KeccakFinal(KECCAK_CTX *ctx) {
        return k_final_wrap(ctx);
    }

    bool KeccakSqueeze(KECCAK_CTX *ctx, uint8_t *output, size_t outlen) {
        return k_squeeze_wrap(ctx, output, outlen);
    }

    /* One-shot Keccak (raw): absorb, finalize, squeeze */
    bool Keccak(const uint8_t *data, size_t len,
                uint8_t *digest, size_t outlen,
                size_t rate, uint8_t suffix) {
        return k_hash_wrap(data, len, digest, outlen, rate, suffix);
    }

#endif // ENABLE_RAW_KECCAK

#endif // ENABLE_KECCAK_CORE

/* =============================
   SHA-3 convenience wrappers
   ============================= */

#if ENABLE_SHA3_224

bool SHA3_224Init(SHA3_224_CTX *ctx) {
    return k_init_wrap(ctx, SHA3_224_BLOCK_SIZE, SHA3_224_DOMAIN);
}

bool SHA3_224Absorb(SHA3_224_CTX *ctx, const uint8_t *data, size_t len) {
    return k_absorb_wrap(ctx, data, len);
}

bool SHA3_224Final(SHA3_224_CTX *ctx) {
    return k_final_wrap(ctx);
}

bool SHA3_224Squeeze(SHA3_224_CTX *ctx, uint8_t *output, size_t outlen) {
    return k_squeeze_wrap(ctx, output, outlen);
}

bool SHA3_224(const uint8_t *data, size_t len, uint8_t digest[SHA3_224_DIGEST_SIZE]) {
    return k_hash_wrap(data, len, digest, SHA3_224_DIGEST_SIZE, SHA3_224_BLOCK_SIZE, SHA3_224_DOMAIN);
}

#endif // ENABLE_SHA3_224


#if ENABLE_SHA3_256

bool SHA3_256Init(SHA3_256_CTX *ctx) {
    return k_init_wrap(ctx, SHA3_256_BLOCK_SIZE, SHA3_256_DOMAIN);
}

bool SHA3_256Absorb(SHA3_256_CTX *ctx, const uint8_t *data, size_t len) {
    return k_absorb_wrap(ctx, data, len);
}

bool SHA3_256Final(SHA3_256_CTX *ctx) {
    return k_final_wrap(ctx);
}

bool SHA3_256Squeeze(SHA3_256_CTX *ctx, uint8_t *output, size_t outlen) {
    return k_squeeze_wrap(ctx, output, outlen);
}

bool SHA3_256(const uint8_t *data, size_t len, uint8_t digest[SHA3_256_DIGEST_SIZE]) {
    return k_hash_wrap(data, len, digest, SHA3_256_DIGEST_SIZE, SHA3_256_BLOCK_SIZE, SHA3_256_DOMAIN);
}

#endif // ENABLE_SHA3_256


#if ENABLE_SHA3_384

bool SHA3_384Init(SHA3_384_CTX *ctx) {
    return k_init_wrap(ctx, SHA3_384_BLOCK_SIZE, SHA3_384_DOMAIN);
}

bool SHA3_384Absorb(SHA3_384_CTX *ctx, const uint8_t *data, size_t len) {
    return k_absorb_wrap(ctx, data, len);
}

bool SHA3_384Final(SHA3_384_CTX *ctx) {
    return k_final_wrap(ctx);
}

bool SHA3_384Squeeze(SHA3_384_CTX *ctx, uint8_t *output, size_t outlen) {
    return k_squeeze_wrap(ctx, output, outlen);
}

bool SHA3_384(const uint8_t *data, size_t len, uint8_t digest[SHA3_384_DIGEST_SIZE]) {
    return k_hash_wrap(data, len, digest, SHA3_384_DIGEST_SIZE, SHA3_384_BLOCK_SIZE, SHA3_384_DOMAIN);
}

#endif // ENABLE_SHA3_384


#if ENABLE_SHA3_512

bool SHA3_512Init(SHA3_512_CTX *ctx) {
    return k_init_wrap(ctx, SHA3_512_BLOCK_SIZE, SHA3_512_DOMAIN);
}

bool SHA3_512Absorb(SHA3_512_CTX *ctx, const uint8_t *data, size_t len) {
    return k_absorb_wrap(ctx, data, len);
}

bool SHA3_512Final(SHA3_512_CTX *ctx) {
    return k_final_wrap(ctx);
}

bool SHA3_512Squeeze(SHA3_512_CTX *ctx, uint8_t *output, size_t outlen) {
    return k_squeeze_wrap(ctx, output, outlen);
}

bool SHA3_512(const uint8_t *data, size_t len, uint8_t digest[SHA3_512_DIGEST_SIZE]) {
    return k_hash_wrap(data, len, digest, SHA3_512_DIGEST_SIZE, SHA3_512_BLOCK_SIZE, SHA3_512_DOMAIN);
}

#endif // ENABLE_SHA3_512

/* ======================================
   SHAKE128
   ====================================== */
#if ENABLE_SHAKE128

bool SHAKE128Init(SHAKE128_CTX *ctx) {
    return k_init_wrap(ctx, SHAKE128_BLOCK_SIZE, SHAKE128_DOMAIN);
}

bool SHAKE128Absorb(SHAKE128_CTX *ctx, const uint8_t *data, size_t len) {
    return k_absorb_wrap(ctx, data, len);
}

bool SHAKE128Final(SHAKE128_CTX *ctx) {
    return k_final_wrap(ctx);
}

bool SHAKE128Squeeze(SHAKE128_CTX *ctx, uint8_t *output, size_t outlen) {
    return k_squeeze_wrap(ctx, output, outlen);
}

bool SHAKE128(const uint8_t *data, size_t len, uint8_t *digest, size_t outlen) {
    return k_hash_wrap(data, len, digest, outlen, SHAKE128_BLOCK_SIZE, SHAKE128_DOMAIN);
}

#endif // ENABLE_SHAKE128


/* ======================================
   SHAKE256
   ====================================== */
#if ENABLE_SHAKE256

bool SHAKE256Init(SHAKE256_CTX *ctx) {
    return k_init_wrap(ctx, SHAKE256_BLOCK_SIZE, SHAKE256_DOMAIN);
}

bool SHAKE256Absorb(SHAKE256_CTX *ctx, const uint8_t *data, size_t len) {
    return k_absorb_wrap(ctx, data, len);
}

bool SHAKE256Final(SHAKE256_CTX *ctx) {
    return k_final_wrap(ctx);
}

bool SHAKE256Squeeze(SHAKE256_CTX *ctx, uint8_t *output, size_t outlen) {
    return k_squeeze_wrap(ctx, output, outlen);
}

bool SHAKE256(const uint8_t *data, size_t len, uint8_t *digest, size_t outlen) {
    return k_hash_wrap(data, len, digest, outlen, SHAKE256_BLOCK_SIZE, SHAKE256_DOMAIN);
}

#endif // ENABLE_SHAKE256


/* ======================================
   Optional helpers for bit truncation/concat
   ====================================== */
#if ENABLE_SHAKE128 || ENABLE_SHAKE256

void Trunc_s(const uint8_t *X, size_t Xlen, size_t s, uint8_t *out) {
    size_t full_bytes = s / 8;
    size_t rem_bits  = s % 8;

    if (full_bytes > Xlen) full_bytes = Xlen;
    memcpy(out, X, full_bytes);

    if (rem_bits && full_bytes < Xlen) {
        uint8_t mask = 0xFF << (8 - rem_bits);
        out[full_bytes] = X[full_bytes] & mask;
    }
}

void concat_bits(const uint8_t *X, size_t x_bits,
                               const uint8_t *Y, size_t y_bits,
                               uint8_t *out) {

    size_t out_bits = x_bits + y_bits;
    size_t out_bytes = (out_bits + 7) / 8;
    memset(out, 0, out_bytes);

    size_t x_full_bytes = x_bits / 8;
    memcpy(out, X, x_full_bytes);

    size_t x_rem_bits = x_bits % 8;
    if (x_rem_bits && x_full_bytes < out_bytes) {
        out[x_full_bytes] = X[x_full_bytes] & (0xFF << (8 - x_rem_bits));
    }

    for (size_t i = 0; i < y_bits; i++) {
        size_t bit_index = x_bits + i;
        size_t out_byte = bit_index / 8;
        size_t out_bit  = 7 - (bit_index % 8);
        uint8_t y_bit = (Y[i / 8] >> (7 - (i % 8))) & 1;
        out[out_byte] |= y_bit << out_bit;
    }
}

#endif // ENABLE_SHAKE128 || ENABLE_SHAKE256


/* ======================================
   RawSHAKE128
   ====================================== */
#if ENABLE_RAWSHAKE128

bool RawSHAKE128Init(RawSHAKE128_CTX *ctx) {
    return k_init_wrap(ctx, RAWSHAKE128_BLOCK_SIZE, RAWSHAKE128_DOMAIN);
}

bool RawSHAKE128Absorb(RawSHAKE128_CTX *ctx, const uint8_t *data, size_t len) {
    return k_absorb_wrap(ctx, data, len);
}

bool RawSHAKE128Final(RawSHAKE128_CTX *ctx) {
    return k_final_wrap(ctx);
}

bool RawSHAKE128Squeeze(RawSHAKE128_CTX *ctx, uint8_t *output, size_t outlen) {
    return k_squeeze_wrap(ctx, output, outlen);
}

bool RawSHAKE128(const uint8_t *data, size_t len, uint8_t *digest, size_t outlen) {
    return k_hash_wrap(data, len, digest, outlen, RAWSHAKE128_BLOCK_SIZE, RAWSHAKE128_DOMAIN);
}

#endif // ENABLE_RAWSHAKE128


/* ======================================
   RawSHAKE256
   ====================================== */
#if ENABLE_RAWSHAKE256

bool RawSHAKE256Init(RawSHAKE256_CTX *ctx) {
    return k_init_wrap(ctx, RAWSHAKE256_BLOCK_SIZE, RAWSHAKE256_DOMAIN);
}

bool RawSHAKE256Absorb(RawSHAKE256_CTX *ctx, const uint8_t *data, size_t len) {
    return k_absorb_wrap(ctx, data, len);
}

bool RawSHAKE256Final(RawSHAKE256_CTX *ctx) {
    return k_final_wrap(ctx);
}

bool RawSHAKE256Squeeze(RawSHAKE256_CTX *ctx, uint8_t *output, size_t outlen) {
    return k_squeeze_wrap(ctx, output, outlen);
}

bool RawSHAKE256(const uint8_t *data, size_t len, uint8_t *digest, size_t outlen) {
    return k_hash_wrap(data, len, digest, outlen, RAWSHAKE256_BLOCK_SIZE, RAWSHAKE256_DOMAIN);

}

#endif // ENABLE_RAWSHAKE256

#endif
