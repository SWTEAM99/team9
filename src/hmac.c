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

// GenKey: 해시 키 s와 키 key 생성
// s는 GenH(1^l)로 생성 (여기서는 l 비트 랜덤 바이트 생성)
// k는 {0,1}^l에서 랜덤 선택
int GenKey(int l, byte* s, byte* k) {
    if (l <= 0 || !s || !k) {
        return CRYPTO_ERR_PARAM;
    }

    size_t byte_len = (l + 7) / 8;  // 비트를 바이트로 변환

    // 해시 키 salt 생성 (랜덤 바이트 생성)
    if (generate_random_bytes(s, byte_len) != CRYPTO_OK) {
        return CRYPTO_ERR_RANDOM;
    }

    // 키 key 생성 (랜덤 바이트 생성)
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
int GenSubKeys(const byte* salt, size_t s_len, const byte* key, size_t k_len, byte* k0, byte* k1) {
    // 입력 검증 (s는 선택사항이므로 제외)
    if (!key || !k0 || !k1) {
        return CRYPTO_ERR_PARAM;  // NULL 포인터
    }
    // s는 선택사항: NULL이거나 s_len이 0이면 사용하지 않음
    if (salt == NULL) {
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
        // 키 길이가 블록 크기 이하인 경우: key || 0^(b-bitlen(key))
        memset(key_buf, 0, b);
        memcpy(key_buf, key, k_len);
    }
    else {
        // 키 길이가 블록 크기보다 큰 경우: H_s(key) || 0^(b-h) 또는 H(key) (s가 없을 때)
        // s가 있으면 H(salt || key), 없으면 H(key)
        if (s_len > 0 && salt != NULL) {
            // H_s(key): 해시 키 s를 사용하여 k를 해시
            // s와 k를 결합하여 해시 (H(salt || key) 형태)
            size_t combined_len = s_len + k_len;
            byte* combined = (byte*)malloc(combined_len);
            if (!combined) {
                return CRYPTO_ERR_MEMORY;
            }
            memcpy(combined, salt, s_len);
            memcpy(combined + s_len, key, k_len);
            SHA512_hash_impl(combined, combined_len, hash_output);
            free(combined);
        }
        else {
            // s가 없으면 H(key)만 사용
            SHA512_hash_impl(key, k_len, hash_output);
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

int HMAC_Mac(const byte* s, size_t s_len, const byte* k, size_t k_len,
    int tag_len, const byte* msg, size_t msg_len, byte* mac_tag) {
    // 파라미터 검증: 필수 포인터와 tag_len 범위 체크
    if (!k || !msg || !mac_tag || tag_len <= 0 || tag_len > SHA512_DIGEST_SIZE) {
        return CRYPTO_ERR_PARAM;
    }

    // s가 NULL이면 s_len을 0으로 설정 (일관성 유지)
    if (s == NULL) {
        s_len = 0;
    }

    byte k0[SHA512_BLOCK_SIZE];
    byte k1[SHA512_BLOCK_SIZE];
    byte hash_output[SHA512_DIGEST_SIZE];

    // 서브키 버퍼 초기화
    memset(k0, 0, SHA512_BLOCK_SIZE);
    memset(k1, 0, SHA512_BLOCK_SIZE);
    memset(hash_output, 0, SHA512_DIGEST_SIZE);

    // 서브키 k0, k1 생성
    if (GenSubKeys(s, s_len, k, k_len, k0, k1) != 0) {
        return CRYPTO_ERR_INTERNAL;
    }

    // 첫 번째 해시 입력: k0 || s(optional) || msg
    size_t first_input_len = SHA512_BLOCK_SIZE + s_len + msg_len;
    byte* first_input = (byte*)malloc(first_input_len);
    if (!first_input) {
        return CRYPTO_ERR_MEMORY;
    }

    size_t offset = 0;
    // 앞부분에 k0 복사
    memcpy(first_input, k0, SHA512_BLOCK_SIZE);
    offset += SHA512_BLOCK_SIZE;

    // s가 있으면 이어서 s 복사
    if (s_len > 0 && s != NULL) {
        memcpy(first_input + offset, s, s_len);
        offset += s_len;
    }

    // 마지막으로 msg 복사
    memcpy(first_input + offset, msg, msg_len);

    // 첫 번째 해시: H(k0 || s || msg)
    SHA512_hash_impl(first_input, first_input_len, hash_output);

    free(first_input);

    // 두 번째 해시 입력: k1 || 첫 번째 해시값
    size_t second_input_len = SHA512_BLOCK_SIZE + SHA512_DIGEST_SIZE;
    byte* second_input = (byte*)malloc(second_input_len);
    if (!second_input) {
        return CRYPTO_ERR_MEMORY;
    }

    offset = 0;
    // k1 복사
    memcpy(second_input, k1, SHA512_BLOCK_SIZE);
    offset += SHA512_BLOCK_SIZE;

    // 뒤에 첫 번째 해시값 붙이기
    memcpy(second_input + offset, hash_output, SHA512_DIGEST_SIZE);

    // 두 번째 해시: H(k1 || H1)
    SHA512_hash_impl(second_input, second_input_len, hash_output);

    free(second_input);

    // 최종 태그: 앞에서부터 tag_len 바이트만 사용
    memcpy(mac_tag, hash_output, tag_len);

    return CRYPTO_OK;
}

int HMAC_Vrfy(const byte* s, size_t s_len,
    const byte* k, size_t k_len,
    int tag_len,
    const byte* msg, size_t msg_len,
    const byte* mac_tag)
{
    // 입력 파라미터 검증
    if (!k || !msg || !mac_tag ||
        tag_len <= 0 || tag_len > SHA512_DIGEST_SIZE) {
        return CRYPTO_ERR_PARAM;
    }

    // s가 NULL이면 s_len을 0으로 설정 (일관성 유지)
    if (s == NULL) {
        s_len = 0;
    }

    byte computed_tag[SHA512_DIGEST_SIZE];

    // 동일한 방식으로 MAC 다시 계산
    int err = HMAC_Mac(s, s_len, k, k_len, tag_len, msg, msg_len, computed_tag);
    if (err != CRYPTO_OK) {
        return CRYPTO_ERR_INTERNAL;
    }

    // 상수 시간 비교: 한 바퀴 모두 도는 동안 diff에 XOR 누적
    int diff = 0;
    for (int i = 0; i < tag_len; i++) {
        diff |= (computed_tag[i] ^ mac_tag[i]);
    }

    // diff == 0 이면 모두 같음 → 유효한 MAC
    if (diff != 0) {
        return CRYPTO_ERR_INVALID;
    }

    return CRYPTO_OK;
}
