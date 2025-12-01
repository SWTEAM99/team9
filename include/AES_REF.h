#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief AES 관련 상수 정의
 * @details
 *  - AES는 128비트(16바이트) 고정 블록 크기를 사용한다.
 *  - 키 길이는 표준에 따라 128 / 192 / 256비트(16 / 24 / 32바이트)를 사용.
 */
#define AES_128_KEY_SIZE 16   // AES-128 키 길이 (바이트)
#define AES_192_KEY_SIZE 24  // AES-192 키 길이
#define AES_256_KEY_SIZE 32   // AES-256 키 길이

 /* AES 블록 크기 (중복 정의 방지) */
#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16   // AES 블록 크기 (128비트)
#endif

#define AES_128_ROUNDS 10
#define AES_192_ROUNDS 12
#define AES_256_ROUNDS 14


/* 공통 byte 타입 정의 (여러 헤더에서 중복 정의 방지) */
#ifndef BYTE_TYPE_DEFINED
#define BYTE_TYPE_DEFINED
typedef uint8_t byte;
#endif

/* =========================================================
 * AES Reference 컨텍스트 정의
 * ========================================================= */

 /**
  * @brief AES Reference 구현용 컨텍스트
  */
typedef struct {
    byte round_keys[240];  // 라운드 키 (15 라운드 * 16 바이트 = 240 바이트)
    byte rounds;           // 라운드 수 (AES-128=10, AES-192=12, AES-256=14)
    byte key_len;          // 키 길이 (16/24/32)
} AES_REF_CTX;

/**
 * @brief AES Reference 컨텍스트 초기화 (키 확장 수행)
 * @param ctx AES_REF_CTX 포인터
 * @param key 16/24/32바이트 키
 * @param key_len 키 길이(16/24/32)
 * @return CRYPTO_OK 성공, CRYPTO_ERR_PARAM 파라미터 오류, CRYPTO_ERR_KEYLEN 키 길이 오류
 */
int AES_REF_init(AES_REF_CTX* ctx, const byte* key, int key_len);

/**
 * @brief AES 한 블록 암호화(Reference 기반, 컨텍스트 사용)
 * @param ctx AES_REF_CTX 포인터
 * @param in 입력 블록 (16바이트)
 * @param out 출력 블록 (16바이트)
 * @return CRYPTO_OK 성공, CRYPTO_ERR_PARAM 파라미터 오류
 */
int aes_ref_encrypt_core(const AES_REF_CTX* ctx, const byte in[16], byte out[16]);

/**
 * @brief AES 한 블록 복호화(Reference 기반, 컨텍스트 사용)
 * @param ctx AES_REF_CTX 포인터
 * @param in 입력 블록 (16바이트)
 * @param out 출력 블록 (16바이트)
 * @return CRYPTO_OK 성공, CRYPTO_ERR_PARAM 파라미터 오류
 */
int aes_ref_decrypt_core(const AES_REF_CTX* ctx, const byte in[16], byte out[16]);

// 내부 함수들
int aes_key_expansion(const byte* key, byte key_size, byte* round_keys);
void aes_add_round_key(byte* state, const byte* round_key);
void aes_sub_bytes(byte* state);
void aes_shift_rows(byte* state);
void aes_mix_columns(byte* state);
void aes_inv_sub_bytes(byte* state);
void aes_inv_shift_rows(byte* state);
void aes_inv_mix_columns(byte* state);

#endif // AES_H