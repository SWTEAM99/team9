#ifndef CRYPTO_API_H
#define CRYPTO_API_H

#include <stdint.h>   // 고정폭 정수형 (uint32_t, uint64_t 등) 사용을 위해 포함

/* =========================================================*/

/**
 * @brief AES 관련 상수 정의
 * @details
 *  - AES는 128비트(16바이트) 고정 블록 크기를 사용한다.
 *  - 키 길이는 표준에 따라 128 / 192 / 256비트(16 / 24 / 32바이트)를 사용.
 */
#define AES_BLOCK_SIZE     16   // AES 블록 크기 (128비트)
#define AES_KEY_SIZE_128   16   // AES-128 키 길이 (바이트)
#define AES_KEY_SIZE_192   24   // AES-192 키 길이
#define AES_KEY_SIZE_256   32   // AES-256 키 길이

 /**
  * @brief SHA-2 관련 상수
  * @details
  *  - SHA-512 출력: 64바이트 (512비트)
  */
#define SHA512_BLOCK_SIZE   128    // SHA-512 입력 블록 크기
#define SHA512_DIGEST_SIZE   64    // SHA-512 출력(해시) 크기

  /**
   * @brief 기타 상수
   */
#define CRYPTO_MAX_KEY_SIZE AES_KEY_SIZE_256   // AES에서 사용 가능한 최대 키 크기


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
 * 오류 반환 코드 (성공 / 실패)
 * ========================================================= */

#define CRYPTO_OK             0    // 정상 종료
#define CRYPTO_ERR_PARAM     -1    // 잘못된 파라미터(NULL, 길이 오류 등)
#define CRYPTO_ERR_KEYLEN    -2    // 지원하지 않는 키 길이
#define CRYPTO_ERR_MODE      -3    // 지원하지 않는 모드
#define CRYPTO_ERR_PADDING   -4    // CBC 패딩 오류
#define CRYPTO_ERR_MEMORY    -5    // 메모리 오류
#define CRYPTO_ERR_INTERNAL  -6    // 함수 내부 오류


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
 * @brief CBC 모드 패딩 방식
 * @details
 *  - NONE  : 입력 데이터가 블록 크기(16) 배수일 때만 처리 (패딩 없음)
 *  - PKCS7 : 일반 텍스트/파일 암호화에 적합한 표준 패딩
 */
typedef enum {
    CBC_PADDING_NONE = 0,
    CBC_PADDING_PKCS7 = 1
} CBC_Padding;


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
    CBC_Padding padding,
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
    CBC_Padding padding,
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
void SHA512_hash(const uint8_t* data, size_t len, uint8_t out[SHA512_DIGEST_SIZE]);


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