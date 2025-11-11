/*
 * File: tiny_sha.c
 * Author: 0xNullll
 * Description: Implementation of the Tiny SHA library. 
 *              Provides the function definitions for all enabled SHA algorithms:
 *              SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256.
 *              Implements initialization, update, finalization, and single-shot hash functions.
 *              Uses endian-aware macros and CPU-optimized block processing.
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
#define F_00_19(B,C,D)  (((B) & (C)) | ((~(B)) & (D)))           // Ch, rounds 0–19
#define F_20_39(B,C,D)  ((B) ^ (C) ^ (D))                        // Parity, rounds 20–39
#define F_40_59(B,C,D)  (((B) & (C)) | ((B) & (D)) | ((C) & (D)))// Maj, rounds 40–59
#define F_60_79(B,C,D)  F_20_39((B),(C),(D))                     // Parity again, rounds 60–79

bool SHA1Init(SHA1_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));

    ctx->h0 = 0x67452301UL;
    ctx->h1 = 0xefcdab89UL;
    ctx->h2 = 0x98badcfeUL;
    ctx->h3 = 0x10325476UL;
    ctx->h4 = 0xc3d2e1f0UL;
    return true;
}

static inline bool SHA1ProcessBlock(SHA1_CTX *ctx, const uint8_t *block) {
    uint32_t W[80];
    uint32_t A,B,C,D,E,TEMP;

    // Copy block to W[0..15] (big-endian)
    for(int i = 0; i < 16; i++)
        W[i] = LOAD32(block + i*4);

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

bool SHA1Update(SHA1_CTX *ctx,const uint8_t *data,size_t len) {
    ctx->Nl += (uint32_t)(len*8);
    if(ctx->Nl < (len*8)) ctx->Nh++;

    while(len > 0) {
        uint32_t to_copy = 64 - ctx->num;
        if(to_copy > len) to_copy = (uint32_t)len;
        memcpy((uint8_t*)ctx->buf + ctx->num, data, to_copy);
        ctx->num += to_copy;
        data += to_copy;
        len -= to_copy;

        if(ctx->num == 64) {
            if (!SHA1ProcessBlock(ctx, (uint8_t*)ctx->buf)) return false;
            ctx->num = 0;
        }
    }
    return true;
}

bool SHA1Final(SHA1_CTX *ctx, uint8_t digest[SHA1_DIGEST_SIZE]) {
    if (!ctx || !digest) return false;

    uint64_t total_bits = ((uint64_t)ctx->Nh << 32) | ctx->Nl;
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
    STORE64(block + 56, total_bits);

    // Process final block
    if (!SHA1ProcessBlock(ctx, block)) return false;

    // Output digest using STORE32
    STORE32(digest + 0,  ctx->h0);
    STORE32(digest + 4,  ctx->h1);
    STORE32(digest + 8,  ctx->h2);
    STORE32(digest + 12, ctx->h3);
    STORE32(digest + 16, ctx->h4);

    return true;
}

bool SHA1(const uint8_t *data, size_t len, uint8_t digest[SHA1_DIGEST_SIZE]) {
    SHA1_CTX ctx;
    return SHA1Init(&ctx) && SHA1Update(&ctx, data, len) && SHA1Final(&ctx, digest);
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
    
    ctx->md_len = SHA256_DIGEST_SIZE;
    return true;
}

static inline bool SHA256ProcessBlock(SHA256_CTX *ctx, const uint8_t *block) {
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
    STORE64(block + 56, bit_len);

    // Process final block
    if (!SHA256ProcessBlock(ctx, block)) return false;

    // If padding + length overflowed one block
    if (ctx->buf_len + pad_len + 8 > 64) {
        memset(block, 0, SHA256_BLOCK_SIZE);
        if (!SHA256ProcessBlock(ctx, block)) return false;
    }

    // Store digest using STORE32 (CPU-endian optimized)
    for (size_t i = 0; i < 8; i++)
        STORE32(digest + i*4, ctx->state[i]);

    return true;
}

bool SHA256(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]){
    SHA256_CTX ctx;
    return SHA256Init(&ctx) && SHA256Update(&ctx, data, len) && SHA256Final(&ctx, digest);
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

    ctx->md_len = SHA224_DIGEST_SIZE;
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

bool SHA224(const uint8_t *data, size_t len, uint8_t digest[SHA224_DIGEST_SIZE]) {
    SHA224_CTX ctx;
    return SHA224Init(&ctx) && SHA224Update(&ctx, data, len) && SHA224Final(&ctx, digest);   
}

#endif

#if ENABLE_SHA512

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
# define U64(C) C##UI64
#elif defined(__arch64__)
# define U64(C) C##UL
#else
# define U64(C) C##ULL
#endif

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

    ctx->md_len = SHA512_DIGEST_SIZE;
    return true;
}

static inline bool SHA512ProcessBlock(SHA512_CTX *ctx, const uint8_t *block) {
    uint64_t W[80], a,b,c,d,e,f,g,h,T1,T2;

    for (int t=0; t<16; t++) 
        W[t] = LOAD64(block + t*8);

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
    STORE64(len_bytes, high);
    STORE64(len_bytes + 8, low);

    // compute padding length to reach 112 bytes (128-16) before length
    size_t pad_len = (ctx->buf_len < 112) ? (112 - ctx->buf_len)
                                          : (128 + 112 - ctx->buf_len);

    // update with padding
    if (!SHA512Update(ctx, pad, pad_len)) return false;

    // update with length
    if (!SHA512Update(ctx, len_bytes, 16)) return false;

    // store final hash state into digest using STORE64 (CPU-endian aware)
    for (int i = 0; i < 8; i++)
        STORE64(digest + i*8, ctx->state[i]);

    return true;
}

bool SHA512(const uint8_t *data, size_t len, uint8_t digest[SHA512_DIGEST_SIZE]) {
    SHA512_CTX ctx;
    return SHA512Init(&ctx) && SHA512Update(&ctx, data, len) && SHA512Final(&ctx, digest);
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

    ctx->md_len = SHA384_DIGEST_SIZE;
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

bool SHA384(const uint8_t *data, size_t len, uint8_t digest[SHA384_DIGEST_SIZE]) {
    SHA384_CTX ctx;
    return SHA384Init(&ctx) && SHA384Update(&ctx, data, len) && SHA384Final(&ctx, digest);   
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

    ctx->md_len = SHA512_224_DIGEST_SIZE;
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

bool SHA512_224(const uint8_t *data, size_t len, uint8_t digest[SHA512_224_DIGEST_SIZE]) {
    SHA512_224_CTX ctx;
    return SHA512_224Init(&ctx) && SHA512_224Update(&ctx, data, len) && SHA512_224Final(&ctx, digest);
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

    ctx->md_len = SHA512_256_DIGEST_SIZE;
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

bool SHA512_256(const uint8_t *data, size_t len, uint8_t digest[SHA512_256_DIGEST_SIZE]) {
    SHA512_256_CTX ctx;
    return SHA512_256Init(&ctx) && SHA512_256Update(&ctx, data, len) && SHA512_256Final(&ctx, digest);
}

#endif

#endif
