#include "AES_REF.h"
#include "error.h"
#include <string.h>

// S-Box (Substitution Box)
static const byte sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// 역 S-Box
static const byte inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Rcon (Round Constants)
static const byte rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// xtimes 매크로 (x * 2 in GF(2^8))
#define xtimes(x) ((x & 0x80) ? ((x << 1) ^ 0x1b) : (x << 1))

// 키 크기로부터 라운드 수 계산
static byte get_rounds(byte key_size) {
    switch (key_size) {
    case AES_128_KEY_SIZE: return AES_128_ROUNDS;
    case AES_192_KEY_SIZE: return AES_192_ROUNDS;
    case AES_256_KEY_SIZE: return AES_256_ROUNDS;
    default: return 0;
    }
}

// 키 확장 (바이트 단위 연산)
int aes_key_expansion(const byte* key, byte key_size, byte* round_keys) {
    byte rounds = get_rounds(key_size);
    if (rounds == 0) return CRYPTO_ERR_KEYLEN;

    byte temp[4] = { 0 };
    int i;
    int max_round_keys = 4 * (rounds + 1);

    // 첫 번째 라운드 키는 원본 키 (바이트 단위로 복사)
    for (i = 0; i < key_size; i++) {
        round_keys[i] = key[i];
    }

    // 나머지 라운드 키 생성 (4바이트씩 처리)
    for (i = key_size / 4; i < max_round_keys; i++) {
        // 이전 라운드 키를 바이트 배열로 변환
        temp[0] = round_keys[(i - 1) * 4];
        temp[1] = round_keys[(i - 1) * 4 + 1];
        temp[2] = round_keys[(i - 1) * 4 + 2];
        temp[3] = round_keys[(i - 1) * 4 + 3];

        if (i % (key_size / 4) == 0) {
            // RotWord: 1바이트 왼쪽 회전
            byte rot_temp = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = rot_temp;

            // SubWord: S-box 적용
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];

            // Rcon 적용
            int rcon_index = i / (key_size / 4);
            if (rcon_index < 11) {
                temp[0] ^= rcon[rcon_index];
            }
        }
        else if (key_size == AES_256_KEY_SIZE && i % (key_size / 4) == 4) {
            // AES-256: 4번째마다 SubWord 적용
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
        }

        // 이전 라운드 키와 XOR
        round_keys[i * 4] = temp[0] ^ round_keys[(i - key_size / 4) * 4];
        round_keys[i * 4 + 1] = temp[1] ^ round_keys[(i - key_size / 4) * 4 + 1];
        round_keys[i * 4 + 2] = temp[2] ^ round_keys[(i - key_size / 4) * 4 + 2];
        round_keys[i * 4 + 3] = temp[3] ^ round_keys[(i - key_size / 4) * 4 + 3];
    }

    return 0;
}

// 라운드 키 추가
void aes_add_round_key(byte* state, const byte* round_key) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

// 바이트 치환
void aes_sub_bytes(byte* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

// 행 이동
void aes_shift_rows(byte* state) {
    byte temp;

    // 두 번째 행을 1바이트 왼쪽으로 이동
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // 세 번째 행을 2바이트 왼쪽으로 이동
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // 네 번째 행을 3바이트 왼쪽으로 이동
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

// 열 혼합
void aes_mix_columns(byte* state) {
    byte temp[4] = { 0 };

    for (int i = 0; i < 4; i++) {
        temp[0] = xtimes(state[i * 4]) ^ (xtimes(state[i * 4 + 1]) ^ state[i * 4 + 1]) ^ state[i * 4 + 2] ^ state[i * 4 + 3];
        temp[1] = state[i * 4] ^ xtimes(state[i * 4 + 1]) ^ (xtimes(state[i * 4 + 2]) ^ state[i * 4 + 2]) ^ state[i * 4 + 3];
        temp[2] = state[i * 4] ^ state[i * 4 + 1] ^ xtimes(state[i * 4 + 2]) ^ (xtimes(state[i * 4 + 3]) ^ state[i * 4 + 3]);
        temp[3] = (xtimes(state[i * 4]) ^ state[i * 4]) ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ xtimes(state[i * 4 + 3]);

        state[i * 4] = temp[0];
        state[i * 4 + 1] = temp[1];
        state[i * 4 + 2] = temp[2];
        state[i * 4 + 3] = temp[3];
    }
}

// 역 바이트 치환
void aes_inv_sub_bytes(byte* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = inv_sbox[state[i]];
    }
}

// 역 행 이동
void aes_inv_shift_rows(byte* state) {
    byte temp;

    // 두 번째 행을 1바이트 오른쪽으로 이동
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    // 세 번째 행을 2바이트 오른쪽으로 이동
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // 네 번째 행을 3바이트 오른쪽으로 이동
    temp = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = state[3];
    state[3] = temp;
}

// 역 열 혼합
void aes_inv_mix_columns(byte* state) {
    byte temp[16] = { 0 };
    byte array[4][4] = {
        {0x0e, 0x0b, 0x0d, 0x09},
        {0x09, 0x0e, 0x0b, 0x0d},
        {0x0d, 0x09, 0x0e, 0x0b},
        {0x0b, 0x0d, 0x09, 0x0e}
    };

    for (int p_idx = 0; p_idx < 16; p_idx++) {
        byte columns = p_idx % 4;
        byte result = 0;

        for (int row = 0; row < 4; row++) {
            byte mult = state[row + (p_idx / 4) * 4];
            byte calc = 0;
            byte mult_arr = array[columns][row];

            for (int bit = 0; bit < 4; bit++) {
                if (mult_arr & 1) {
                    calc ^= mult;
                }
                mult_arr >>= 1;
                mult = xtimes(mult);
            }
            result ^= calc;
        }
        temp[p_idx] = result;
    }

    for (int p_idx = 0; p_idx < 16; p_idx++) {
        state[p_idx] = temp[p_idx];
    }
}

// AES 암호화 블록
int AES_REF_encrypt_block(const byte in[AES_BLOCK_SIZE], byte out[AES_BLOCK_SIZE],
    const byte* key, int key_len) {
    if (!in || !out || !key) {
        return CRYPTO_ERR_PARAM;  // 잘못된 매개변수
    }

    // 키 크기 검증
    if (key_len != AES_128_KEY_SIZE && key_len != AES_192_KEY_SIZE && key_len != AES_256_KEY_SIZE) {
        return CRYPTO_ERR_KEYLEN;
    }

    byte rounds = get_rounds(key_len);
    if (rounds == 0) return CRYPTO_ERR_KEYLEN;

    // 라운드 키 배열 할당 (바이트 단위)
    byte round_keys[240];  // 15 * 16 = 240 바이트

    // 키 확장
    if (aes_key_expansion(key, key_len, round_keys) != 0) {
        return CRYPTO_ERR_INTERNAL;
    }

    byte state[16];

    // 입력을 state 배열로 복사
    for (int i = 0; i < 16; i++) {
        state[i] = in[i];
    }

    // 초기 라운드 키 추가
    aes_add_round_key(state, &round_keys[0]);

    // 라운드 수행
    for (int round = 1; round < rounds; round++) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, &round_keys[round * 16]);
    }

    // 마지막 라운드 (MixColumns 제외)
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, &round_keys[rounds * 16]);

    // 결과를 출력으로 복사
    for (int i = 0; i < 16; i++) {
        out[i] = state[i];
    }

    return CRYPTO_OK;  // 성공
}

// AES 복호화 블록
int AES_REF_decrypt_block(const byte in[AES_BLOCK_SIZE], byte out[AES_BLOCK_SIZE],
    const byte* key, int key_len) {
    if (!in || !out || !key) {
        return CRYPTO_ERR_PARAM;  // 잘못된 매개변수
    }

    // 키 크기 검증
    if (key_len != AES_128_KEY_SIZE && key_len != AES_192_KEY_SIZE && key_len != AES_256_KEY_SIZE) {
        return CRYPTO_ERR_KEYLEN;
    }

    byte rounds = get_rounds(key_len);
    if (rounds == 0) return CRYPTO_ERR_KEYLEN;

    // 라운드 키 배열 할당 (바이트 단위)
    byte round_keys[240];  // 60 * 4 = 240 바이트

    // 키 확장
    if (aes_key_expansion(key, key_len, round_keys) != 0) {
        return CRYPTO_ERR_INTERNAL;
    }

    byte state[16] = { 0 };

    // 입력을 state 배열로 복사
    for (int i = 0; i < 16; i++) {
        state[i] = in[i];
    }

    // 초기 라운드 키 추가
    aes_add_round_key(state, &round_keys[rounds * 16]);

    // 라운드 수행
    for (int round = rounds - 1; round > 0; round--) {
        aes_inv_shift_rows(state);
        aes_inv_sub_bytes(state);
        aes_add_round_key(state, &round_keys[round * 16]);
        aes_inv_mix_columns(state);
    }

    // 마지막 라운드 (InvMixColumns 제외)
    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state);
    aes_add_round_key(state, &round_keys[0]);

    // 결과를 출력으로 복사
    for (int i = 0; i < 16; i++) {
        out[i] = state[i];
    }

    return CRYPTO_OK;  // 성공
}

