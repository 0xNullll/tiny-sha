#include "tiny_sha.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

void print_hex(const uint8_t *digest, size_t size) {
    for (size_t i = 0; i < size; i++)
        printf("%02x", digest[i]);
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <text-to-hash>\n", argv[0]);
        return 1;
    }

    const char *input = argv[1];
    size_t len = strlen(input);

#if ENABLE_SHA1
    uint8_t digest1[SHA1_DIGEST_SIZE];
    if (!SHA1((const uint8_t*)input, len, digest1)) {
        printf("SHA1 computation failed!\n");
        return 1;
    }
    printf("SHA1:    ");
    print_hex(digest1, SHA1_DIGEST_SIZE);
#endif

#if ENABLE_SHA224
    uint8_t digest224[SHA224_DIGEST_SIZE];
    if (!SHA224((const uint8_t*)input, len, digest224)) {
        printf("SHA224 computation failed!\n");
        return 1;
    }
    printf("SHA224:  ");
    print_hex(digest224, SHA224_DIGEST_SIZE);
#endif

#if ENABLE_SHA256
    uint8_t digest256[SHA256_DIGEST_SIZE];
    if (!SHA256((const uint8_t*)input, len, digest256)) {
        printf("SHA256 computation failed!\n");
        return 1;
    }
    printf("SHA256:  ");
    print_hex(digest256, SHA256_DIGEST_SIZE);
#endif

#if ENABLE_SHA384
    uint8_t digest384[SHA384_DIGEST_SIZE];
    if (!SHA384((const uint8_t*)input, len, digest384)) {
        printf("SHA384 computation failed!\n");
        return 1;
    }
    printf("SHA384:  ");
    print_hex(digest384, SHA384_DIGEST_SIZE);
#endif

#if ENABLE_SHA512
    uint8_t digest512[SHA512_DIGEST_SIZE];
    if (!SHA512((const uint8_t*)input, len, digest512)) {
        printf("SHA512 computation failed!\n");
        return 1;
    }
    printf("SHA512:  ");
    print_hex(digest512, SHA512_DIGEST_SIZE);
#endif

#if ENABLE_SHA512_224
    uint8_t digest512_224[SHA512_224_DIGEST_SIZE];
    if (!SHA512_224((const uint8_t*)input, len, digest512_224)) {
        printf("SHA512/224 computation failed!\n");
        return 1;
    }
    printf("SHA512/224: ");
    print_hex(digest512_224, SHA512_224_DIGEST_SIZE);
#endif

#if ENABLE_SHA512_256
    uint8_t digest512_256[SHA512_256_DIGEST_SIZE];
    if (!SHA512_256((const uint8_t*)input, len, digest512_256)) {
        printf("SHA512/256 computation failed!\n");
        return 1;
    }
    printf("SHA512/256: ");
    print_hex(digest512_256, SHA512_256_DIGEST_SIZE);
#endif

    return 0;
}

