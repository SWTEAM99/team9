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

// 함수 선언
int AES_REF_encrypt_block(const byte in[AES_BLOCK_SIZE], byte out[AES_BLOCK_SIZE],
    const byte* key, int key_len);
int AES_REF_decrypt_block(const byte in[AES_BLOCK_SIZE], byte out[AES_BLOCK_SIZE],
    const byte* key, int key_len);

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