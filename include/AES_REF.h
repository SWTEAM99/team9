#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>
#include "crypto_api.h"

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