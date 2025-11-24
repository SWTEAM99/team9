#ifndef CRYPTO_API_H
#define CRYPTO_API_H

#include <stdint.h>   // 고정폭 정수형 (uint32_t, uint64_t 등) 사용을 위해 포함
#include "error.h"    // API에서 사용하는 에러 코드 정의
#include "AES_REF.h"      // 레퍼런스 버전 AES 함수 선언
#include "AES_TBL_CORE.h"       // 테이블 룩업 버전 AES_TBL_CTX, 함수 선언
#include "sha512.h" // sha2-512 해시함수 
#include "hmac.h" // HMAC구현 

   /* =========================================================
    * 기본 타입 정의
    * ========================================================= */

    /**
     * @brief 바이트 단위 데이터 타입 별칭
     */
     /* 여러 헤더에서 중복 정의되지 않도록 가드 */
#ifndef BYTE_TYPE_DEFINED
#define BYTE_TYPE_DEFINED
typedef uint8_t byte;
#endif

 /* =========================================================
  * AES 구현 옵션
  * ========================================================= */

  /**
   * @brief AES 구현 방식 선택
   * @details
   *  - AES_IMPL_REF : 참조(reference) 구현
   *  - AES_IMPL_TBL : 32x8 T-Table 기반 고속 구현
   */
typedef enum {
    AES_IMPL_REF = 0,
    AES_IMPL_TBL = 1
} AES_Impl;

/**
 * @brief AES 키/구현 정보를 CBC/CTR 콜백에 전달하기 위한 컨텍스트
 * @details
 *  - CBC_encrypt, CBC_decrypt, CTR_crypt 함수의 user_ctx 파라미터로 사용
 *  - 콜백 함수에서 키와 구현 방식을 참조할 수 있도록 함
 */
typedef struct {
    const byte* key;      // 암호화 키
    int         key_len;  // 키 길이 (16, 24, 32 바이트)
    AES_Impl    impl;     // AES 구현 방식 (AES_IMPL_REF 또는 AES_IMPL_TBL)
} AES_CTX;

/* =========================================================
 * AES 블록 암/복호화 API
 * ========================================================= */

 /**
  * @brief AES 한 블록(128비트) 암호화
  */
int AES_encrypt_block(const byte in[AES_BLOCK_SIZE],
    byte out[AES_BLOCK_SIZE],
    const byte* key,
    int key_len,
    AES_Impl impl);

/**
 * @brief AES 한 블록(128비트) 복호화
 */
int AES_decrypt_block(const byte in[AES_BLOCK_SIZE],
    byte out[AES_BLOCK_SIZE],
    const byte* key,
    int key_len,
    AES_Impl impl);


/* =========================================================
 * 범용 CBC 모드 (Generic CBC)
 * ========================================================= */

 /**
  * @brief 범용 CBC 암호화
  */
int CBC_encrypt(
    void (*encrypt_block)(const byte* in, byte* out, const void* user_ctx),
    int block_size,
    const byte iv[],
    const byte* plaintext, int pt_len,
    byte* ciphertext, int* ct_len,
    const void* user_ctx
);

/**
 * @brief 범용 CBC 복호화
 */
int CBC_decrypt(
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
int CTR_crypt(
    void (*encrypt_block)(const byte* in, byte* out, const void* user_ctx),
    int block_size,
    byte* nonce_ctr,
    const byte* in, int len,
    byte* out,
    const void* user_ctx
);


/* =========================================================
 * SHA-512 (sha512.c 구현)
 * ========================================================= */

 /* 원샷 SHA-512 */
int SHA512_hash(const uint8_t* data, size_t len, uint8_t out[SHA512_DIGEST_SIZE]);


/* =========================================================
 * 유틸리티 함수
 * ========================================================= */

int CRYPTO_randomBytes(byte* out, int len);      // 안전한 랜덤 바이트 생성
int IV_generate(byte iv[AES_BLOCK_SIZE]);        // AES 블록 크기만큼 IV 생성
void CRYPTO_printHex(const byte* data, int len); // 바이트 배열을 16진수로 출력
int CRYPTO_isEqual(const byte* a, const byte* b, int len); // 상수 시간 비교


/* =========================================================
 * HMAC-SHA512
 * ========================================================= */

 /**
  * @brief MAC 생성
  * @details
  *  - 1. GenSubKeys()로 서브키 k0, k1 생성
  *  - 2. 첫 번째 해시 = H_s(k0 || msg)
  *  - 3. 두 번째 해시 = H_s(k1 || 첫 번째 해시)
  */
int Mac(const byte* s, size_t s_len,
    const byte* k, size_t k_len,
    int tag_len,
    const byte* msg, size_t msg_len,
    byte* mac_tag);

/**
 * @brief MAC 검증
 * @return 1 (VALID, 일치) / 0 (INVALID, 불일치)
 */
int Vrfy(const byte* s, size_t s_len,
    const byte* k, size_t k_len,
    int tag_len,
    const byte* msg, size_t msg_len,
    const byte* mac_tag);

#endif // CRYPTO_API_H
