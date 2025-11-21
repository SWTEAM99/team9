#include "hmac.h"
#include "error.h"
#include "sha512.h"
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
// Windows: BCryptGenRandom 사용
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
// macOS / Linux: /dev/urandom 사용
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#endif

// 랜덤 바이트 생성 헬퍼 함수 (플랫폼별 안전한 난수 생성)
static int generate_random_bytes(byte* buf, size_t len) {
    if (!buf || len == 0) {
        return CRYPTO_ERR_PARAM;
    }

#ifdef _WIN32
    /* ---- Windows: BCryptGenRandom ---- */
    NTSTATUS st = BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (st == 0) ? CRYPTO_OK : CRYPTO_ERR_RANDOM;
#else
    /* ---- macOS / Linux: /dev/urandom ---- */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return CRYPTO_ERR_RANDOM;
    }

    size_t remaining = len;
    while (remaining > 0) {
        ssize_t r = read(fd, buf + (len - remaining), remaining);
        if (r <= 0) {
            close(fd);
            return CRYPTO_ERR_RANDOM;
        }
        remaining -= (size_t)r;
    }

    close(fd);
    return CRYPTO_OK;
#endif
}

// GenKey: 해시 키 s와 키 k 생성
// s는 GenH(1^l)로 생성 (여기서는 l 비트 랜덤 바이트 생성)
// k는 {0,1}^l에서 랜덤 선택
int GenKey(int l, byte* s, byte* k) {
    if (l <= 0 || !s || !k) {
        return CRYPTO_ERR_PARAM;
    }

    size_t byte_len = (l + 7) / 8;  // 비트를 바이트로 변환

    // 해시 키 s 생성 (랜덤 바이트 생성)
    if (generate_random_bytes(s, byte_len) != CRYPTO_OK) {
        return CRYPTO_ERR_RANDOM;
    }

    // 키 k 생성 (랜덤 바이트 생성)
    if (generate_random_bytes(k, byte_len) != CRYPTO_OK) {
        return CRYPTO_ERR_RANDOM;
    }

    // 마지막 바이트의 불필요한 비트 제거
    int remainder = l % 8;
    if (remainder != 0) {
        byte mask = (1 << remainder) - 1;
        s[byte_len - 1] &= mask;
        k[byte_len - 1] &= mask;
    }

    return CRYPTO_OK;
}

// GenSubKeys: 서브키 k0, k1 생성
// s는 선택사항: NULL이거나 s_len이 0이면 s를 사용하지 않음
int GenSubKeys(const byte* s, size_t s_len, const byte* k, size_t k_len, byte* k0, byte* k1) {
    // 입력 검증 (s는 선택사항이므로 제외)
    if (!k || !k0 || !k1) {
        return CRYPTO_ERR_PARAM;  // NULL 포인터
    }
    // s는 선택사항: NULL이거나 s_len이 0이면 사용하지 않음
    if (s == NULL) {
        s_len = 0;  // s가 NULL이면 s_len을 0으로 설정
    }

    // SHA2-512 블록 크기: 128 바이트 (1024 bits)
    size_t b = SHA512_BLOCK_SIZE;
    // SHA2-512 해시 출력 크기: 64 바이트 (512 bits)
    size_t h = SHA512_DIGEST_SIZE;

    byte key_buf[SHA512_BLOCK_SIZE];
    byte hash_output[SHA512_DIGEST_SIZE];

    // 키 길이에 따른 처리
    if (k_len <= b) {
        // 키 길이가 블록 크기 이하인 경우: k || 0^(b-bitlen(k))
        memset(key_buf, 0, b);
        memcpy(key_buf, k, k_len);
    }
    else {
        // 키 길이가 블록 크기보다 큰 경우: H_s(k) || 0^(b-h) 또는 H(k) (s가 없을 때)
        // s가 있으면 H(s || k), 없으면 H(k)
        if (s_len > 0 && s != NULL) {
            // H_s(k): 해시 키 s를 사용하여 k를 해시
            // s와 k를 결합하여 해시 (H(s || k) 형태)
            size_t combined_len = s_len + k_len;
            byte* combined = (byte*)malloc(combined_len);
            if (!combined) {
                return CRYPTO_ERR_MEMORY;
            }
            memcpy(combined, s, s_len);
            memcpy(combined + s_len, k, k_len);
            SHA512_hash(combined, combined_len, hash_output);
            free(combined);
        }
        else {
            // s가 없으면 H(k)만 사용
            SHA512_hash(k, k_len, hash_output);
        }

        memset(key_buf, 0, b);
        memcpy(key_buf, hash_output, h);
    }

    // k0 생성: key XOR ipad (ipad = 0x36)
    for (size_t i = 0; i < b; i++) {
        k0[i] = key_buf[i] ^ 0x36;
    }

    // k1 생성: key XOR opad (opad = 0x5c)
    for (size_t i = 0; i < b; i++) {
        k1[i] = key_buf[i] ^ 0x5c;
    }

    return CRYPTO_OK;
}

