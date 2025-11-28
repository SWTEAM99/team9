#ifndef MODES_H
#define MODES_H

#include <stdint.h>

/* 공통 byte 타입 정의 (중복 방지) */
#ifndef BYTE_TYPE_DEFINED
#define BYTE_TYPE_DEFINED
typedef uint8_t byte;
#endif

/* AES 블록 크기 (중복 정의 방지) */
#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16   // AES 블록 크기 (128비트)
#endif

/* =========================================================
 * 난수 / IV 생성
 * ========================================================= */

 /**
  * @brief 안전한 랜덤 바이트 생성
  * @param out 출력 버퍼
  * @param len 생성할 바이트 수
  * @return CRYPTO_OK 성공, 그 외 실패
  */
int CRYPTO_randomBytes(byte* out, int len);

/**
 * @brief AES 블록 크기만큼 IV 생성
 * @param iv 출력 버퍼 (AES_BLOCK_SIZE 바이트)
 * @return CRYPTO_OK 성공, 그 외 실패
 */
int IV_generate(byte iv[AES_BLOCK_SIZE]);


/* =========================================================
 * 범용 CBC 모드 (Generic CBC)
 * ========================================================= */

 /**
  * @brief 범용 CBC 암호화 (항상 PKCS7 패딩 사용)
  */
int MODES_CBC_encrypt(
    void (*encrypt_block)(const byte* in, byte* out, const void* user_ctx),
    int block_size,
    const byte iv[],
    const byte* plaintext, int pt_len,
    byte* ciphertext, int* ct_len,
    const void* user_ctx
);

/**
 * @brief 범용 CBC 복호화 (항상 PKCS7 패딩 제거)
 */
int MODES_CBC_decrypt(
    void (*decrypt_block)(const byte* in, byte* out, const void* user_ctx),
    int block_size,
    const byte iv[],
    const byte* ciphertext, int ct_len,
    byte* plaintext, int* pt_len,
    const void* user_ctx
);


/* =========================================================
 * CTR 모드
 * ========================================================= */

 /**
  * @brief 범용 CTR 암/복호화 (AES 또는 다른 블록 암호 모두 지원)
  */
int MODES_CTR_crypt(
    void (*encrypt_block)(const byte* in, byte* out, const void* user_ctx),
    int block_size,
    byte* nonce_ctr,
    const byte* in, int len,
    byte* out,
    const void* user_ctx
);

#endif // MODES_H

