#include "AES_TBL_CORE.h"
#include "error.h"
#include <string.h>
#include <stdlib.h>

/* =========================================================
 * 키 확장 함수
 * ========================================================= */

 /**
  * @brief RotWord (4바이트 회전)
  */
static uint32_t rot_word(uint32_t word) {
    // 상위 바이트를 맨 뒤로 보내는 8비트 좌측 회전
    return ((word << 8) | (word >> 24));
}

/**
 * @brief SubWord (각 바이트를 S-box로 치환)
 */
static uint32_t sub_word(uint32_t word) {
    // 32비트 word를 바이트 단위로 쪼개서 S-box 치환 후 다시 합침
    return ((uint32_t)g_sbox[(word >> 24) & 0xff] << 24) |
        ((uint32_t)g_sbox[(word >> 16) & 0xff] << 16) |
        ((uint32_t)g_sbox[(word >> 8) & 0xff] << 8) |
        (uint32_t)g_sbox[word & 0xff];
}

/**
 * @brief 키 확장 핵심 함수
 * @details
 *  AES-128/192/256 키 스케줄 생성
 */
static int key_expansion_core(const uint8_t* key, int key_len, uint32_t* round_keys, int num_rounds) {
    if (!key || !round_keys || key_len <= 0 || num_rounds <= 0) {
        return CRYPTO_ERR_PARAM;
    }

    int nk = key_len / 4;  // 32비트 word 개수 (AES-128: 4, 192: 6, 256: 8)

    /* 원본 키를 round_keys 첫 nk word에 채움 */
    for (int i = 0; i < nk; i++) {
        round_keys[i] =
            ((uint32_t)key[4 * i] << 24) |
            ((uint32_t)key[4 * i + 1] << 16) |
            ((uint32_t)key[4 * i + 2] << 8) |
            ((uint32_t)key[4 * i + 3]);
    }

    /* 나머지 라운드 키 생성 */
    for (int i = nk; i < 4 * (num_rounds + 1); i++) {
        uint32_t temp = round_keys[i - 1];

        // i가 nk의 배수일 때: RotWord → SubWord → Rcon XOR
        if (i % nk == 0) {
            temp = sub_word(rot_word(temp)) ^ ((uint32_t)g_rcon[i / nk] << 24);
        }
        // AES-256일 때 (nk > 6) 중간 word 추가 SubWord
        else if (nk > 6 && i % nk == 4) {
            temp = sub_word(temp);
        }

        // W[i] = W[i - nk] ^ temp
        round_keys[i] = round_keys[i - nk] ^ temp;
    }

    return CRYPTO_OK;
}
/**
 * @brief GF(2^8)에서 곱셈
 */
static uint8_t gmul_u8(uint8_t a, uint8_t b) {
    // 표준 GF(2^8) 곱셈 구현 (비트 곱셈 + x^8 모듈러 감소)
    uint8_t p = 0;
    while (b) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

/**
 * @brief 단일 word(열)에 InvMixColumns 적용
 */
static uint32_t inv_mcol_word(uint32_t w) {
    // 4바이트를 각각 컬럼 요소로 분리
    uint8_t a0 = (uint8_t)(w >> 24);
    uint8_t a1 = (uint8_t)(w >> 16);
    uint8_t a2 = (uint8_t)(w >> 8);
    uint8_t a3 = (uint8_t)(w);

    // AES 역 MixColumns 계수(0x0e, 0x0b, 0x0d, 0x09)를 사용한 선형변환
    uint8_t b0 = gmul_u8(a0, 0x0e) ^ gmul_u8(a1, 0x0b) ^ gmul_u8(a2, 0x0d) ^ gmul_u8(a3, 0x09);
    uint8_t b1 = gmul_u8(a0, 0x09) ^ gmul_u8(a1, 0x0e) ^ gmul_u8(a2, 0x0b) ^ gmul_u8(a3, 0x0d);
    uint8_t b2 = gmul_u8(a0, 0x0d) ^ gmul_u8(a1, 0x09) ^ gmul_u8(a2, 0x0e) ^ gmul_u8(a3, 0x0b);
    uint8_t b3 = gmul_u8(a0, 0x0b) ^ gmul_u8(a1, 0x0d) ^ gmul_u8(a2, 0x09) ^ gmul_u8(a3, 0x0e);

    // 다시 32비트 word로 합침
    return ((uint32_t)b0 << 24) | ((uint32_t)b1 << 16) |
        ((uint32_t)b2 << 8) | ((uint32_t)b3);
}


/* =========================================================
 * AES T-Table 기반 암호화/복호화
 * ========================================================= */

int AES_TBL_init(AES_TBL_CTX* ctx, const uint8_t* key, int key_len) {
    if (!ctx || !key) return CRYPTO_ERR_PARAM;
    if (key_len != 16 && key_len != 24 && key_len != 32) return CRYPTO_ERR_KEYLEN;

    int nr;
    switch (key_len) {
    case 16: nr = 10; break;  // AES-128
    case 24: nr = 12; break;  // AES-192
    case 32: nr = 14; break;  // AES-256
    default: return CRYPTO_ERR_KEYLEN;
    }

    ctx->num_rounds = nr;

    // 암호화용 라운드 키 생성
    if (key_expansion_core(key, key_len, ctx->round_keys_enc, nr) != CRYPTO_OK) {
        return CRYPTO_ERR_INTERNAL;
    }

    /* 복호화용 키 생성
       - 첫 라운드와 마지막 라운드 키는 그대로
       - 중간 라운드 키는 InvMixColumns 적용 */
    for (int j = 0; j < 4; j++) {
        // 마지막 라운드 키 -> dec 첫 라운드
        ctx->round_keys_dec[j] = ctx->round_keys_enc[nr * 4 + j];
        // 첫 라운드 키 -> dec 마지막 라운드
        ctx->round_keys_dec[nr * 4 + j] = ctx->round_keys_enc[j];
    }

    for (int i = 1; i < nr; i++) {
        uint32_t* dec_key = &ctx->round_keys_dec[(nr - i) * 4];
        uint32_t* enc_key = &ctx->round_keys_enc[i * 4];

        dec_key[0] = inv_mcol_word(enc_key[0]);
        dec_key[1] = inv_mcol_word(enc_key[1]);
        dec_key[2] = inv_mcol_word(enc_key[2]);
        dec_key[3] = inv_mcol_word(enc_key[3]);
    }

    return CRYPTO_OK;
}


/**
 * @brief AES encrypt (T-table)
 */
int aes_encrypt_core(const AES_TBL_CTX* ctx, const uint8_t in[16], uint8_t out[16]) {
    if (!ctx || !in || !out) {
        return CRYPTO_ERR_PARAM;
    }

    if (ctx->num_rounds <= 0 || ctx->num_rounds > 14) {
        return CRYPTO_ERR_INTERNAL;
    }

    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
    const uint32_t* rk = ctx->round_keys_enc;

    // 입력 16바이트를 4개의 32비트 state word로 조합
    s0 = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
    s1 = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 8) | (uint32_t)in[7];
    s2 = ((uint32_t)in[8] << 24) | ((uint32_t)in[9] << 16) | ((uint32_t)in[10] << 8) | (uint32_t)in[11];
    s3 = ((uint32_t)in[12] << 24) | ((uint32_t)in[13] << 16) | ((uint32_t)in[14] << 8) | (uint32_t)in[15];

    // 초기 AddRoundKey
    s0 ^= rk[0]; s1 ^= rk[1]; s2 ^= rk[2]; s3 ^= rk[3];
    rk += 4;

    // 중간 라운드: T-table을 이용한 SubBytes+ShiftRows+MixColumns+AddRoundKey
    for (int r = 1; r < ctx->num_rounds; r++) {
        t0 = g_Te0[(s0 >> 24) & 0xff] ^ g_Te1[(s1 >> 16) & 0xff] ^ g_Te2[(s2 >> 8) & 0xff] ^ g_Te3[s3 & 0xff] ^ rk[0];
        t1 = g_Te0[(s1 >> 24) & 0xff] ^ g_Te1[(s2 >> 16) & 0xff] ^ g_Te2[(s3 >> 8) & 0xff] ^ g_Te3[s0 & 0xff] ^ rk[1];
        t2 = g_Te0[(s2 >> 24) & 0xff] ^ g_Te1[(s3 >> 16) & 0xff] ^ g_Te2[(s0 >> 8) & 0xff] ^ g_Te3[s1 & 0xff] ^ rk[2];
        t3 = g_Te0[(s3 >> 24) & 0xff] ^ g_Te1[(s0 >> 16) & 0xff] ^ g_Te2[(s1 >> 8) & 0xff] ^ g_Te3[s2 & 0xff] ^ rk[3];

        // 다음 라운드를 위해 state 갱신
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        rk += 4;
    }

    // 마지막 라운드: MixColumns 없이 SubBytes+ShiftRows+AddRoundKey만 수행
    t0 = (((uint32_t)g_sbox[(s0 >> 24) & 0xff] << 24) |
        ((uint32_t)g_sbox[(s1 >> 16) & 0xff] << 16) |
        ((uint32_t)g_sbox[(s2 >> 8) & 0xff] << 8) |
        (uint32_t)g_sbox[s3 & 0xff]) ^ rk[0];

    t1 = (((uint32_t)g_sbox[(s1 >> 24) & 0xff] << 24) |
        ((uint32_t)g_sbox[(s2 >> 16) & 0xff] << 16) |
        ((uint32_t)g_sbox[(s3 >> 8) & 0xff] << 8) |
        (uint32_t)g_sbox[s0 & 0xff]) ^ rk[1];

    t2 = (((uint32_t)g_sbox[(s2 >> 24) & 0xff] << 24) |
        ((uint32_t)g_sbox[(s3 >> 16) & 0xff] << 16) |
        ((uint32_t)g_sbox[(s0 >> 8) & 0xff] << 8) |
        (uint32_t)g_sbox[s1 & 0xff]) ^ rk[2];

    t3 = (((uint32_t)g_sbox[(s3 >> 24) & 0xff] << 24) |
        ((uint32_t)g_sbox[(s0 >> 16) & 0xff] << 16) |
        ((uint32_t)g_sbox[(s1 >> 8) & 0xff] << 8) |
        (uint32_t)g_sbox[s2 & 0xff]) ^ rk[3];

    // 최종 state를 16바이트 배열로 분해하여 out에 저장
    out[0] = (t0 >> 24) & 0xff; out[1] = (t0 >> 16) & 0xff; out[2] = (t0 >> 8) & 0xff; out[3] = t0 & 0xff;
    out[4] = (t1 >> 24) & 0xff; out[5] = (t1 >> 16) & 0xff; out[6] = (t1 >> 8) & 0xff; out[7] = t1 & 0xff;
    out[8] = (t2 >> 24) & 0xff; out[9] = (t2 >> 16) & 0xff; out[10] = (t2 >> 8) & 0xff; out[11] = t2 & 0xff;
    out[12] = (t3 >> 24) & 0xff; out[13] = (t3 >> 16) & 0xff; out[14] = (t3 >> 8) & 0xff; out[15] = t3 & 0xff;

    return CRYPTO_OK;
}


/**
 * @brief AES decrypt (T-table)
 */
int aes_decrypt_core(const AES_TBL_CTX* ctx, const uint8_t in[16], uint8_t out[16]) {
    if (!ctx || !in || !out) {
        return CRYPTO_ERR_PARAM;
    }

    if (ctx->num_rounds <= 0 || ctx->num_rounds > 14) {
        return CRYPTO_ERR_INTERNAL;
    }

    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
    const uint32_t* rk = ctx->round_keys_dec;

    // 입력을 4개의 32비트 word로 변환
    s0 = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
    s1 = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 8) | (uint32_t)in[7];
    s2 = ((uint32_t)in[8] << 24) | ((uint32_t)in[9] << 16) | ((uint32_t)in[10] << 8) | (uint32_t)in[11];
    s3 = ((uint32_t)in[12] << 24) | ((uint32_t)in[13] << 16) | ((uint32_t)in[14] << 8) | (uint32_t)in[15];

    // 초기 AddRoundKey (복호화용 키)
    s0 ^= rk[0]; s1 ^= rk[1]; s2 ^= rk[2]; s3 ^= rk[3];
    rk += 4;

    // 중간 라운드: 역 T-table(Td0~Td3) 사용
    for (int r = 1; r < ctx->num_rounds; r++) {
        t0 = g_Td0[(s0 >> 24) & 0xff] ^ g_Td1[(s3 >> 16) & 0xff] ^ g_Td2[(s2 >> 8) & 0xff] ^ g_Td3[s1 & 0xff] ^ rk[0];
        t1 = g_Td0[(s1 >> 24) & 0xff] ^ g_Td1[(s0 >> 16) & 0xff] ^ g_Td2[(s3 >> 8) & 0xff] ^ g_Td3[s2 & 0xff] ^ rk[1];
        t2 = g_Td0[(s2 >> 24) & 0xff] ^ g_Td1[(s1 >> 16) & 0xff] ^ g_Td2[(s0 >> 8) & 0xff] ^ g_Td3[s3 & 0xff] ^ rk[2];
        t3 = g_Td0[(s3 >> 24) & 0xff] ^ g_Td1[(s2 >> 16) & 0xff] ^ g_Td2[(s1 >> 8) & 0xff] ^ g_Td3[s0 & 0xff] ^ rk[3];

        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        rk += 4;
    }

    // 마지막 라운드: InvSubBytes + InvShiftRows + AddRoundKey
    t0 = (((uint32_t)g_inv_sbox[(s0 >> 24) & 0xff] << 24) |
        ((uint32_t)g_inv_sbox[(s3 >> 16) & 0xff] << 16) |
        ((uint32_t)g_inv_sbox[(s2 >> 8) & 0xff] << 8) |
        (uint32_t)g_inv_sbox[s1 & 0xff]) ^ rk[0];

    t1 = (((uint32_t)g_inv_sbox[(s1 >> 24) & 0xff] << 24) |
        ((uint32_t)g_inv_sbox[(s0 >> 16) & 0xff] << 16) |
        ((uint32_t)g_inv_sbox[(s3 >> 8) & 0xff] << 8) |
        (uint32_t)g_inv_sbox[s2 & 0xff]) ^ rk[1];

    t2 = (((uint32_t)g_inv_sbox[(s2 >> 24) & 0xff] << 24) |
        ((uint32_t)g_inv_sbox[(s1 >> 16) & 0xff] << 16) |
        ((uint32_t)g_inv_sbox[(s0 >> 8) & 0xff] << 8) |
        (uint32_t)g_inv_sbox[s3 & 0xff]) ^ rk[2];

    t3 = (((uint32_t)g_inv_sbox[(s3 >> 24) & 0xff] << 24) |
        ((uint32_t)g_inv_sbox[(s2 >> 16) & 0xff] << 16) |
        ((uint32_t)g_inv_sbox[(s1 >> 8) & 0xff] << 8) |
        (uint32_t)g_inv_sbox[s0 & 0xff]) ^ rk[3];

    // 최종 state를 out[16]에 기록
    out[0] = (t0 >> 24) & 0xff; out[1] = (t0 >> 16) & 0xff; out[2] = (t0 >> 8) & 0xff; out[3] = t0 & 0xff;
    out[4] = (t1 >> 24) & 0xff; out[5] = (t1 >> 16) & 0xff; out[6] = (t1 >> 8) & 0xff; out[7] = t1 & 0xff;
    out[8] = (t2 >> 24) & 0xff; out[9] = (t2 >> 16) & 0xff; out[10] = (t2 >> 8) & 0xff; out[11] = t2 & 0xff;
    out[12] = (t3 >> 24) & 0xff; out[13] = (t3 >> 16) & 0xff; out[14] = (t3 >> 8) & 0xff; out[15] = t3 & 0xff;

    return CRYPTO_OK;
}
