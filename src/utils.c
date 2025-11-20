#include "crypto_api.h"
#include <stdio.h>

/* 헤더에 선언된 이름에 맞춘 구현 */
void CRYPTO_printHex(const byte* data, int len) {
    if (!data || len < 0) return;
    for (int i = 0; i < len; ++i) {
        printf("%02X", (unsigned)data[i]);
    }
    printf("\n");
}

int CRYPTO_isEqual(const byte* a, const byte* b, int len) {
    if (!a || !b || len < 0) return 0;
    unsigned char acc = 0;
    for (int i = 0; i < len; ++i) {
        acc |= (unsigned char)(a[i] ^ b[i]);
    }
    return acc == 0;
}
