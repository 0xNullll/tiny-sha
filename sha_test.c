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
    if (!SHA1((uint8_t*)input, len, digest1)) {
        printf("SHA1 computation failed!\n");
        return 1;
    }
    printf("SHA1:   ");
    print_hex(digest1, SHA1_DIGEST_SIZE);
#endif

#if ENABLE_SHA224
    uint8_t digest3[SHA224_DIGEST_SIZE];
    if (!SHA224((uint8_t*)input, len, digest3)) {
        printf("SHA224 computation failed!\n");
        return 1;
    }
    printf("SHA224: ");
    print_hex(digest3, SHA224_DIGEST_SIZE);
#endif

#if ENABLE_SHA256
    uint8_t digest2[SHA256_DIGEST_SIZE];
    if (!SHA256((uint8_t*)input, len, digest2)) {
        printf("SHA256 computation failed!\n");
        return 1;
    }
    printf("SHA256: ");
    print_hex(digest2, SHA256_DIGEST_SIZE);
#endif

#if ENABLE_SHA384
    uint8_t digest5[SHA384_DIGEST_SIZE];
    if (!SHA384((uint8_t*)input, len, digest5)) {
        printf("SHA384 computation failed!\n");
        return 1;
    }
    printf("SHA384: ");
    print_hex(digest5, SHA384_DIGEST_SIZE);
#endif

#if ENABLE_SHA512
    uint8_t digest4[SHA512_DIGEST_SIZE];
    if (!SHA512((uint8_t*)input, len, digest4)) {
        printf("SHA512 computation failed!\n");
        return 1;
    }
    printf("SHA512: ");
    print_hex(digest4, SHA512_DIGEST_SIZE);
#endif

    return 0;
}
