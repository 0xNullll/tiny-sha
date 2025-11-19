#include "tiny_sha.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

void print_hex(const uint8_t *digest, size_t size) {
    for (size_t i = 0; i < size; i++)
        printf("%02x", digest[i]);
    printf("\n");
}

void compute_and_print_hashes(const uint8_t *data, size_t len) {

#if ENABLE_SHA1
    uint8_t digest1[SHA1_DIGEST_SIZE];
    if (!SHA1((const uint8_t*)data, len, digest1)) {
        printf("SHA1 computation failed!\n");
    }
    printf("SHA1:    ");
    print_hex(digest1, SHA1_DIGEST_SIZE);
#endif

#if ENABLE_SHA224
    uint8_t digest224[SHA224_DIGEST_SIZE];
    if (!SHA224((const uint8_t*)data, len, digest224)) {
        printf("SHA224 computation failed!\n");
    }
    printf("SHA224:  ");
    print_hex(digest224, SHA224_DIGEST_SIZE);
#endif

#if ENABLE_SHA256
    uint8_t digest256[SHA256_DIGEST_SIZE];
    if (!SHA256((const uint8_t*)data, len, digest256)) {
        printf("SHA256 computation failed!\n");
    }
    printf("SHA256:  ");
    print_hex(digest256, SHA256_DIGEST_SIZE);
#endif

#if ENABLE_SHA384
    uint8_t digest384[SHA384_DIGEST_SIZE];
    if (!SHA384((const uint8_t*)data, len, digest384)) {
        printf("SHA384 computation failed!\n");
    }
    printf("SHA384:  ");
    print_hex(digest384, SHA384_DIGEST_SIZE);
#endif

#if ENABLE_SHA512
    uint8_t digest512[SHA512_DIGEST_SIZE];
    if (!SHA512((const uint8_t*)data, len, digest512)) {
        printf("SHA512 computation failed!\n");
    }
    printf("SHA512:  ");
    print_hex(digest512, SHA512_DIGEST_SIZE);
#endif

#if ENABLE_SHA512_224
    uint8_t digest512_224[SHA512_224_DIGEST_SIZE];
    if (!SHA512_224((const uint8_t*)data, len, digest512_224)) {
        printf("SHA512/224 computation failed!\n");
    }
    printf("SHA512/224: ");
    print_hex(digest512_224, SHA512_224_DIGEST_SIZE);
#endif

#if ENABLE_SHA512_256
    uint8_t digest512_256[SHA512_256_DIGEST_SIZE];
    if (!SHA512_256((const uint8_t*)data, len, digest512_256)) {
        printf("SHA512/256 computation failed!\n");
    }
    printf("SHA512/256: ");
    print_hex(digest512_256, SHA512_256_DIGEST_SIZE);
#endif

#if ENABLE_SHA3_224
    uint8_t digest3_224[SHA3_224_DIGEST_SIZE];
    if (!SHA3_224((const uint8_t*)data, len, digest3_224)) {
        printf("SHA3-224 computation failed!\n");
    }
    printf("SHA3-224: ");
    print_hex(digest3_224, SHA3_224_DIGEST_SIZE);
#endif

#if ENABLE_SHA3_256
    uint8_t digest3_256[SHA3_256_DIGEST_SIZE];
    if (!SHA3_256((const uint8_t*)data, len, digest3_256)) {
        printf("SHA3-256 computation failed!\n");
    }
    printf("SHA3-256: ");
    print_hex(digest3_256, SHA3_256_DIGEST_SIZE);
#endif

#if ENABLE_SHA3_384
    uint8_t digest3_384[SHA3_384_DIGEST_SIZE];
    if (!SHA3_384((const uint8_t*)data, len, digest3_384)) {
        printf("SHA3-384 computation failed!\n");
    }
    printf("SHA3-384: ");
    print_hex(digest3_384, SHA3_384_DIGEST_SIZE);
#endif

#if ENABLE_SHA3_512
    uint8_t digest3_512[SHA3_512_DIGEST_SIZE];
    if (!SHA3_512((const uint8_t*)data, len, digest3_512)) {
        printf("SHA3-512 computation failed!\n");
    }
    printf("SHA3-512: ");
    print_hex(digest3_512, SHA3_512_DIGEST_SIZE);
#endif

#if ENABLE_SHAKE128
    size_t shake128_len = 32; // example digest length
    uint8_t digest_shake128[shake128_len];
    if (!SHAKE128((const uint8_t*)data, len, digest_shake128, shake128_len)) {
        printf("SHAKE128 computation failed!\n");
    }
    printf("SHAKE128 (%zu bytes): ", shake128_len);
    print_hex(digest_shake128, shake128_len);
#endif

#if ENABLE_SHAKE256
    size_t shake256_len = 64; // example digest length
    uint8_t digest_shake256[shake256_len];
    if (!SHAKE256((const uint8_t*)data, len, digest_shake256, shake256_len)) {
        printf("SHAKE256 computation failed!\n");
    }
    printf("SHAKE256 (%zu bytes): ", shake256_len);
    print_hex(digest_shake256, shake256_len);
#endif

#if ENABLE_RAWSHAKE128
    size_t rawshake128_len = 32; // example digest length
    uint8_t digest_rawshake128[rawshake128_len];
    if (!RawSHAKE128((const uint8_t*)data, len, digest_rawshake128, rawshake128_len)) {
        printf("RawSHAKE128 computation failed!\n");
    }
    printf("RawSHAKE128 (%zu bytes): ", rawshake128_len);
    print_hex(digest_rawshake128, rawshake128_len);
#endif

#if ENABLE_RAWSHAKE256
    size_t rawshake256_len = 64; // example digest length
    uint8_t digest_rawshake256[rawshake256_len];
    if (!RawSHAKE256((const uint8_t*)data, len, digest_rawshake256, rawshake256_len)) {
        printf("RawSHAKE256 computation failed!\n");
    }
    printf("RawSHAKE256 (%zu bytes): ", rawshake256_len);
    print_hex(digest_rawshake256, rawshake256_len);
#endif
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <text-to-hash>\n", argv[0]);
        return 1;
    }
    const char *input = argv[1];
    compute_and_print_hashes((const uint8_t*)input, strlen(input));
    return 0;
}