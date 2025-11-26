#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>
#include <stddef.h>

/* 공통 byte 타입 정의 (중복 방지) */
#ifndef BYTE_TYPE_DEFINED
#define BYTE_TYPE_DEFINED
typedef uint8_t byte;
#endif

// SHA2-512 상수
#define SHA512_BLOCK_SIZE 128  // 1024비트 = 128바이트

/**
 * @brief 해시 키(s)와 MAC 키(k) 생성
 * @param l 키 길이
 * @param s 출력: 해시 키
 * @param k 출력: MAC 키
 */
int GenKey(int l, byte* s, byte* k);

/**
 * @brief 서브키(k0, k1) 생성
 * @details HMAC 내부에서 사용됨
 */
int GenSubKeys(const byte* s, size_t s_len, const byte* k, size_t k_len, byte* k0, byte* k1);

/**
 * @brief MAC 생성 (실제 구현)
 * @details HMAC-SHA512 기반 MAC 계산
 */
int HMAC_Mac(const byte* s, size_t s_len,
    const byte* k, size_t k_len,
    int tag_len,
    const byte* msg, size_t msg_len,
    byte* mac_tag);

/**
 * @brief MAC 검증 (실제 구현)
 * @details 상수 시간 비교로 타이밍 공격 방지
 * @return CRYPTO_OK (유효) / CRYPTO_ERR_INVALID (무효) / 기타 에러 코드
 */
int HMAC_Vrfy(const byte* s, size_t s_len,
    const byte* k, size_t k_len,
    int tag_len,
    const byte* msg, size_t msg_len,
    const byte* mac_tag);

#endif // HMAC_H