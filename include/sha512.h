#ifndef SHA512_H
#define SHA512_H
#include <stdint.h>   // uint64_t 등
#include <stddef.h>   // size_t

#define SHA512_BLOCK_SIZE   128    // 블록 바이트
#define SHA512_DIGEST_SIZE   64    // 출력 바이트

typedef struct {
    uint64_t state[8];             // H0..H7
    uint64_t bitlen[2];            // 총 입력 비트를 상위/하위 64비트로 누적
    uint8_t  buffer[SHA512_BLOCK_SIZE];   // 스트리밍 수신 중인 바이트를 128바이트까지 임시 저장
    uint32_t datalen;              // 현재 버퍼에 쌓인 바이트 수(0~128)
} SHA512_CTX;

int SHA512_init(SHA512_CTX* ctx);
int SHA512_update(SHA512_CTX* ctx, const uint8_t* data, size_t len);
int SHA512_final(SHA512_CTX* ctx, uint8_t out[SHA512_DIGEST_SIZE]);

/**
 * @brief SHA-512 해시를 한 번에 계산하는 원샷 함수 (실제 구현)
 * @details SHA512_init(), SHA512_update(), SHA512_final()을 순차적으로 호출
 */
int SHA512_hash_impl(const uint8_t* data, size_t len, uint8_t out[SHA512_DIGEST_SIZE]);

#endif