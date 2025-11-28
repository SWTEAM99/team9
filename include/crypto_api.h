/**
 * @file crypto_api.h
 * @brief 암호화 API 헤더 파일
 * @details 이 파일은 암호화 라이브러리의 공개 API를 정의합니다.
 *          AES 블록 암호, CBC/CTR 모드, SHA-512 해시, HMAC-SHA512 등의 기능을 제공합니다.
 * @author 보안SW구현 프로젝트
 * @date 2025
 */

#ifndef CRYPTO_API_H
#define CRYPTO_API_H

#include <stdint.h>   // 고정폭 정수형 (uint32_t, uint64_t 등) 사용을 위해 포함
#include <stddef.h>   // size_t 사용을 위해 포함
#include "error.h"    // API에서 사용하는 에러 코드 정의
#include "AES_REF.h"      // 레퍼런스 버전 AES 함수 선언
#include "AES_TBL_CORE.h"       // 테이블 룩업 버전 AES_TBL_CTX, 함수 선언
#include "sha512.h" // sha2-512 해시함수 
#include "hmac.h" // HMAC구현
#include "modes.h" // CBC, CTR 모드 함수 선언 
#include "utils.h" // 유틸리티 함수 구현은 utils.h와 utils.c에 있습니다 //
 /* =========================================================
  * 기본 타입 정의
  * ========================================================= */

  /**
   * @brief 바이트 단위 데이터 타입 별칭
   * @details uint8_t의 별칭으로, 암호화 데이터를 표현하는 데 사용됩니다.
   *          여러 헤더에서 중복 정의되지 않도록 가드 매크로로 보호됩니다.
   */
#ifndef BYTE_TYPE_DEFINED
#define BYTE_TYPE_DEFINED
typedef uint8_t byte;
#endif

/* =========================================================
 * AES 구현 옵션
 * ========================================================= */

 /**
  * @brief AES 구현 방식 선택 열거형
  * @details AES 암호화/복호화 시 사용할 구현 방식을 지정합니다.
  */
typedef enum {
    AES_IMPL_REF = 0,  /**< 참조(reference) 구현 - 교육용/디버깅용 */
    AES_IMPL_TBL = 1   /**< 32x8 T-Table 기반 고속 구현 - 프로덕션용 */
} AES_Impl;

/**
 * @brief AES 키 및 구현 정보를 담는 컨텍스트 구조체
 * @details CBC/CTR 모드의 콜백 함수에 전달하기 위한 컨텍스트입니다.
 *          콜백 함수에서 키와 구현 방식을 참조할 수 있도록 합니다.
 */
typedef struct {
    const byte* key;      /**< 암호화 키 포인터 (16, 24, 또는 32 바이트) */
    int         key_len;  /**< 키 길이 (바이트 단위): 16, 24, 또는 32 */
    AES_Impl    impl;     /**< AES 구현 방식 (AES_IMPL_REF 또는 AES_IMPL_TBL) */
} AES_CTX;


/* =========================================================
 * AES 블록 암/복호화 API
 * ========================================================= */

 /**
  * @brief AES 한 블록(128비트) 암호화
  * @param[in] in 입력 평문 블록 (16바이트)
  * @param[out] out 출력 암호문 블록 (16바이트)
  * @param[in] key 암호화 키 (16, 24, 또는 32바이트)
  * @param[in] key_len 키 길이 (바이트 단위): 16, 24, 또는 32
  * @param[in] impl AES 구현 방식 (AES_IMPL_REF 또는 AES_IMPL_TBL)
  * @return CRYPTO_OK 성공, CRYPTO_ERR_PARAM 파라미터 오류, CRYPTO_ERR_KEYLEN 키 길이 오류
  * @note 이 함수는 단일 블록(16바이트)만 암호화합니다. 여러 블록을 암호화하려면 CBC_encrypt나 CTR_crypt를 사용하세요.
  */
int AES_encrypt_block(const byte in[AES_BLOCK_SIZE],
    byte out[AES_BLOCK_SIZE],
    const byte* key,
    int key_len,
    AES_Impl impl);

/**
 * @brief AES 한 블록(128비트) 복호화
 * @param[in] in 입력 암호문 블록 (16바이트)
 * @param[out] out 출력 평문 블록 (16바이트)
 * @param[in] key 복호화 키 (16, 24, 또는 32바이트)
 * @param[in] key_len 키 길이 (바이트 단위): 16, 24, 또는 32
 * @param[in] impl AES 구현 방식 (AES_IMPL_REF 또는 AES_IMPL_TBL)
 * @return CRYPTO_OK 성공, CRYPTO_ERR_PARAM 파라미터 오류, CRYPTO_ERR_KEYLEN 키 길이 오류
 * @note 이 함수는 단일 블록(16바이트)만 복호화합니다. 여러 블록을 복호화하려면 CBC_decrypt나 CTR_crypt를 사용하세요.
 */
int AES_decrypt_block(const byte in[AES_BLOCK_SIZE],
    byte out[AES_BLOCK_SIZE],
    const byte* key,
    int key_len,
    AES_Impl impl);


/* =========================================================
* 범용 CBC 모드 및 CTR 모드
* ========================================================= */

/**
 * @brief 범용 CBC 암호화 (항상 PKCS7 패딩 사용)
 * @param[in] encrypt_block 블록 암호화 함수 포인터
 * @param[in] block_size 블록 크기
 * @param[in] iv 초기화 벡터
 * @param[in] plaintext 평문 데이터
 * @param[in] pt_len 평문 길이
 * @param[out] ciphertext 암호문 출력 버퍼
 * @param[out] ct_len 암호문 길이 (출력)
 * @param[in] user_ctx 사용자 컨텍스트
 * @return CRYPTO_OK 성공, 그 외 실패
 * @details 실제 구현은 modes.c의 MODES_CBC_encrypt() 함수에서 수행됩니다.
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
 * @brief 범용 CBC 복호화 (항상 PKCS7 패딩 제거)
 * @param[in] decrypt_block 블록 복호화 함수 포인터
 * @param[in] block_size 블록 크기
 * @param[in] iv 초기화 벡터
 * @param[in] ciphertext 암호문 데이터
 * @param[in] ct_len 암호문 길이
 * @param[out] plaintext 평문 출력 버퍼
 * @param[out] pt_len 평문 길이 (출력)
 * @param[in] user_ctx 사용자 컨텍스트
 * @return CRYPTO_OK 성공, 그 외 실패
 * @details 실제 구현은 modes.c의 MODES_CBC_decrypt() 함수에서 수행됩니다.
 */
int CBC_decrypt(
    void (*decrypt_block)(const byte* in, byte* out, const void* user_ctx),
    int block_size,
    const byte iv[],
    const byte* ciphertext, int ct_len,
    byte* plaintext, int* pt_len,
    const void* user_ctx
);

/**
 * @brief 범용 CTR 암/복호화 (AES 또는 다른 블록 암호 모두 지원)
 * @param[in] encrypt_block 블록 암호화 함수 포인터
 * @param[in] block_size 블록 크기
 * @param[in,out] nonce_ctr Nonce/Counter (수정됨)
 * @param[in] in 입력 데이터
 * @param[in] len 입력 데이터 길이
 * @param[out] out 출력 데이터
 * @param[in] user_ctx 사용자 컨텍스트
 * @return CRYPTO_OK 성공, 그 외 실패
 * @details 실제 구현은 modes.c의 MODES_CTR_crypt() 함수에서 수행됩니다.
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

 /**
  * @brief SHA-512 해시를 한 번에 계산하는 원샷 함수
  * @param[in] data 입력 데이터
  * @param[in] len 입력 데이터 길이 (바이트 단위)
  * @param[out] out 해시 결과 출력 버퍼 (64바이트, SHA512_DIGEST_SIZE)
  * @return CRYPTO_OK 성공, CRYPTO_ERR_PARAM 파라미터 오류
  * @details 이 함수는 SHA512_init(), SHA512_update(), SHA512_final()을 순차적으로 호출합니다.
  *          스트리밍이 필요 없는 경우 이 함수를 사용하는 것이 편리합니다.
  */
int SHA512_hash(const uint8_t* data, size_t len, uint8_t out[SHA512_DIGEST_SIZE]);


/* =========================================================
 * 유틸리티 함수
 * ========================================================= */

 /**
  * @brief 안전한 랜덤 바이트 생성
  * @param[out] out 출력 버퍼
  * @param[in] len 생성할 바이트 수
  * @return CRYPTO_OK 성공, CRYPTO_ERR_PARAM 파라미터 오류, CRYPTO_ERR_RANDOM 난수 생성 오류
  * @details 플랫폼별로 안전한 난수 생성기를 사용합니다.
  *          - Windows: CryptGenRandom
  *          - Linux/macOS: /dev/urandom
  */
int CRYPTO_randomBytes(byte* out, int len);

/**
 * @brief AES 블록 크기만큼 IV(Initialization Vector) 생성
 * @param[out] iv 출력 IV 버퍼 (16바이트, AES_BLOCK_SIZE)
 * @return CRYPTO_OK 성공, CRYPTO_ERR_PARAM 파라미터 오류, CRYPTO_ERR_RANDOM 난수 생성 오류
 * @details CRYPTO_randomBytes()를 사용하여 안전한 랜덤 IV를 생성합니다.
 *          CBC 모드나 CTR 모드에서 사용하기 적합합니다.
 */
int IV_generate(byte iv[AES_BLOCK_SIZE]);

/* =========================================================
 * 유틸리티 함수
 * ========================================================= */

 /**
  * @brief 데이터를 16진수로 출력
  * @param[in] data 출력할 데이터
  * @param[in] len 데이터 길이 (바이트)
  * @details 디버깅 및 테스트 목적으로 사용됩니다. stdout에 출력합니다.
  *          실제 구현은 utils.c의 UTIL_printHex() 함수에서 수행됩니다.
  */
void CRYPTO_printHex(const byte* data, int len);

/**
 * @brief 두 바이트 배열을 상수 시간으로 비교
 * @param[in] a 첫 번째 바이트 배열
 * @param[in] b 두 번째 바이트 배열
 * @param[in] len 비교할 길이 (바이트 단위)
 * @return 1 두 배열이 동일함, 0 다름
 * @details 타이밍 공격을 방지하기 위해 상수 시간 비교를 수행합니다.
 *          MAC 검증 등 보안이 중요한 비교에 사용하세요.
 *          실제 구현은 utils.c의 UTIL_isEqual() 함수에서 수행됩니다.
 */
int CRYPTO_isEqual(const byte* a, const byte* b, int len);

/**
 * @brief 파일 전체를 읽어서 메모리에 저장
 * @param[in] filename 파일 경로
 * @param[out] data 읽은 데이터를 저장할 버퍼 포인터 (호출자가 free해야 함)
 * @param[out] len 읽은 데이터 길이 (바이트)
 * @return CRYPTO_OK 성공, CRYPTO_ERR_PARAM/CRYPTO_ERR_MEMORY/CRYPTO_ERR_INTERNAL 실패
 * @details 파일을 바이너리 모드로 읽어서 동적으로 할당된 버퍼에 저장합니다.
 *          호출자는 반드시 반환된 버퍼를 free()로 해제해야 합니다.
 *          실제 구현은 utils.c의 UTIL_readFile() 함수에서 수행됩니다.
 */
int CRYPTO_readFile(const char* filename, byte** data, size_t* len);

/**
 * @brief 데이터를 파일에 저장
 * @param[in] filename 파일 경로
 * @param[in] data 저장할 데이터
 * @param[in] len 데이터 길이 (바이트)
 * @return CRYPTO_OK 성공, CRYPTO_ERR_PARAM/CRYPTO_ERR_INTERNAL 실패
 * @details 데이터를 바이너리 모드로 파일에 저장합니다.
 *          실제 구현은 utils.c의 UTIL_writeFile() 함수에서 수행됩니다.
 */
int CRYPTO_writeFile(const char* filename, const byte* data, size_t len);


/* =========================================================
 * HMAC-SHA512
 * ========================================================= */

 /**
  * @brief HMAC-SHA512 기반 MAC(Message Authentication Code) 생성
  * @param[in] s 비밀 파라미터 (salt, 선택사항)
  * @param[in] s_len s의 길이 (바이트 단위, 0이면 사용 안 함)
  * @param[in] k MAC 생성에 사용할 비밀 키
  * @param[in] k_len 비밀 키 길이 (바이트 단위)
  * @param[in] tag_len 생성할 MAC 태그의 길이 (바이트 단위, 최대 64)
  * @param[in] msg 인증할 메시지 데이터
  * @param[in] msg_len 메시지 길이 (바이트 단위)
  * @param[out] mac_tag 최종 생성된 MAC 값을 저장할 버퍼 (tag_len 크기)
  * @return CRYPTO_OK 성공, CRYPTO_ERR_PARAM 파라미터 오류, CRYPTO_ERR_MEMORY 메모리 오류
  * @details
  *   HMAC-SHA512 알고리즘을 사용하여 MAC을 생성합니다:
  *   1. GenSubKeys()로 서브키 k0, k1 생성
  *   2. 첫 번째 해시 = H_s(k0 || msg)
  *   3. 두 번째 해시 = H_s(k1 || 첫 번째 해시)
  *   4. 결과 태그 생성
  * @note MAC(tag) = SHA512( k1 || SHA512(k0 || msg) )
  */
int Mac(const byte* s, size_t s_len,
    const byte* k, size_t k_len,
    int tag_len,
    const byte* msg, size_t msg_len,
    byte* mac_tag);

/**
 * @brief HMAC-SHA512 기반 MAC 검증
 * @param[in] s 비밀 파라미터 (salt, 선택사항)
 * @param[in] s_len s의 길이 (바이트 단위, 0이면 사용 안 함)
 * @param[in] k MAC 생성에 사용된 비밀 키
 * @param[in] k_len 비밀 키 길이 (바이트 단위)
 * @param[in] tag_len MAC 태그 길이 (바이트 단위, 최대 64)
 * @param[in] msg 검증할 메시지 데이터
 * @param[in] msg_len 메시지 길이 (바이트 단위)
 * @param[in] mac_tag 검증 대상 MAC 태그 (tag_len 크기)
 * @return CRYPTO_OK 유효한 MAC (메시지가 변조되지 않음), CRYPTO_ERR_INVALID 무효한 MAC, 기타 에러 코드
 * @details
 *   Mac() 함수를 호출하여 새 MAC을 계산하고, 상수 시간 비교로 타이밍 공격을 방지합니다.
 *   모든 바이트를 비교하여 조기 종료를 하지 않습니다.
 */
int Vrfy(const byte* s, size_t s_len,
    const byte* k, size_t k_len,
    int tag_len,
    const byte* msg, size_t msg_len,
    const byte* mac_tag);

#endif // CRYPTO_API_H