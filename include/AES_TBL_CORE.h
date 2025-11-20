#ifndef AES_TBL_CORE_H
#define AES_TBL_CORE_H

#include <stdint.h>

/* =========================================================
 * T-Table 및 S-Box 선언 (실제 데이터는 .c 파일에 있음)
 * ========================================================= */

 /// 암호화 시 필요한 S-box
extern const uint8_t g_sbox[256];

/// 복호화 시 필요한 Inverse S-box
extern const uint8_t g_inv_sbox[256];

/// 키 확장 시 필요한 Rcon 상수
extern const uint8_t g_rcon[];

/// 암호화용 T-Tables (Te0~Te3)
extern const uint32_t g_Te0[256], g_Te1[256], g_Te2[256], g_Te3[256];

/// 복호화용 T-Tables (Td0~Td3)
extern const uint32_t g_Td0[256], g_Td1[256], g_Td2[256], g_Td3[256];


/* =========================================================
 * AES 컨텍스트 정의
 * ========================================================= */

 /// AES T-Table 기반 컨텍스트
typedef struct {
    uint32_t round_keys_enc[60];   // 암호화 라운드 키
    uint32_t round_keys_dec[60];   // 복호화 라운드 키
    int num_rounds;                // 라운드 수 (AES-128=10, AES-192=12, AES-256=14)
} AES_TBL_CTX;


/* =========================================================
 * AES T-Table 기반 함수 선언
 * ========================================================= */

 /**
  * @brief AES 키 스케줄을 초기화 (암/복호화 라운드 키 생성)
  * @param ctx       AES_TBL_CTX 포인터
  * @param key       16/24/32바이트 키
  * @param key_len   키 길이(16/24/32)
  * @return 성공=0 / 실패=-1
  */
int AES_TBL_init(AES_TBL_CTX* ctx, const uint8_t* key, int key_len);

/**
 * @brief AES 한 블록 암호화(T-Table 기반)
 * @return CRYPTO_OK 성공, CRYPTO_ERR_PARAM 파라미터 오류, CRYPTO_ERR_INTERNAL 내부 오류
 */
int aes_encrypt_core(const AES_TBL_CTX* ctx, const uint8_t in[16], uint8_t out[16]);

/**
 * @brief AES 한 블록 복호화(T-Table 기반)
 * @return CRYPTO_OK 성공, CRYPTO_ERR_PARAM 파라미터 오류, CRYPTO_ERR_INTERNAL 내부 오류
 */
int aes_decrypt_core(const AES_TBL_CTX* ctx, const uint8_t in[16], uint8_t out[16]);

#endif