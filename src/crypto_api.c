/*
 * crypto_api.c
 * --------------------------------------------------------------------
 * 이 파일은 AES 블록 암호화를 위한 상위 래퍼(wrapper) 코드입니다.
 *  - AES_IMPL_REF : 레퍼런스 버전(AES_REF.c / AES_REF.h)
 *  - AES_IMPL_TBL : 테이블 룩업 버전(aes_implnn.c / 헤더파일.h)
 *
 * 즉, 사용자는 crypto_api.h만 포함하고 AES_encrypt_block()을 호출하면
 * 내부적으로 선택된 구현에 따라 자동으로 적절한 AES 함수를 실행합니다.
 * --------------------------------------------------------------------
 */

#include "crypto_api.h"   // AES_Impl enum, 상수, 오류 코드 정의
#include "error.h"        // 에러 처리 함수
#include "AES_REF.h"      // 레퍼런스 버전 AES 함수 선언
#include "AES_TBL_CORE.h"       // 테이블 룩업 버전 AES_TBL_CTX, 함수 선언
#include "sha512.h" // sha2-512 해시함수 
#include "hmac.h" // HMAC구현 

#include <string.h>       // memcpy 등 기본 유틸 사용
#include <stdlib.h>

 /* ================================================================
  * 함수 포인터 타입 정의
  * ================================================================ */
typedef int (*aes_encrypt_func_t)(const byte in[AES_BLOCK_SIZE],
    byte out[AES_BLOCK_SIZE],
    const byte* key, int key_len);

typedef int (*aes_decrypt_func_t)(const byte in[AES_BLOCK_SIZE],
    byte out[AES_BLOCK_SIZE],
    const byte* key, int key_len);

/* ================================================================
 * T-table 버전 래퍼 함수들
 * ================================================================ */
static int aes_tbl_encrypt_wrapper(const byte in[AES_BLOCK_SIZE],
    byte out[AES_BLOCK_SIZE],
    const byte* key, int key_len) {
    AES_TBL_CTX ctx;
    if (AES_TBL_init(&ctx, key, key_len) != CRYPTO_OK) {
        return CRYPTO_ERR_INTERNAL;
    }
    if (aes_encrypt_core(&ctx, in, out) != CRYPTO_OK) {
        return CRYPTO_ERR_INTERNAL;
    }
    return CRYPTO_OK;
}

static int aes_tbl_decrypt_wrapper(const byte in[AES_BLOCK_SIZE],
    byte out[AES_BLOCK_SIZE],
    const byte* key, int key_len) {
    AES_TBL_CTX ctx;
    if (AES_TBL_init(&ctx, key, key_len) != CRYPTO_OK) {
        return CRYPTO_ERR_INTERNAL;
    }
    if (aes_decrypt_core(&ctx, in, out) != CRYPTO_OK) {
        return CRYPTO_ERR_INTERNAL;
    }
    return CRYPTO_OK;
}

/* ================================================================
 * 함수 포인터 테이블
 * ================================================================ */
static const aes_encrypt_func_t encrypt_funcs[] = {
    [AES_IMPL_REF] = AES_REF_encrypt_block,
    [AES_IMPL_TBL] = aes_tbl_encrypt_wrapper
};

static const aes_decrypt_func_t decrypt_funcs[] = {
    [AES_IMPL_REF] = AES_REF_decrypt_block,
    [AES_IMPL_TBL] = aes_tbl_decrypt_wrapper
};

/* ================================================================
 * AES_encrypt_block()
 * ---------------------------------------------------------------
 * AES 한 블록(128비트 = 16바이트)을 암호화하는 함수입니다.
 *
 * 매개변수:
 *   - in: 입력 평문 (16바이트)
 *   - out: 출력 암호문 (16바이트)
 *   - key: 암호화 키 (16, 24, 32바이트 중 하나)
 *   - key_len: 키 길이 (바이트 단위)
 *   - impl: 구현 방식 (AES_IMPL_REF 또는 AES_IMPL_TBL)
 *
 * 반환값:
 *   - CRYPTO_OK (정상 동작)
 *   - CRYPTO_ERR_PARAM (입력 인자 NULL 등)
 *   - CRYPTO_ERR_KEYLEN (잘못된 키 길이)
 *   - CRYPTO_ERR_INTERNAL (내부 오류)
 * ================================================================ */
int AES_encrypt_block(const byte in[AES_BLOCK_SIZE], byte out[AES_BLOCK_SIZE],
    const byte* key, int key_len, AES_Impl impl)
{
    // --- 기본 입력 유효성 검사 ---
    if (!in || !out || !key)
        return CRYPTO_ERR_PARAM;

    // --- 지원되지 않는 키 길이 검사 ---
    if (key_len != AES_KEY_SIZE_128 &&
        key_len != AES_KEY_SIZE_192 &&
        key_len != AES_KEY_SIZE_256)
        return CRYPTO_ERR_KEYLEN;

    // --- 구현 방식에 따라 함수 포인터로 호출 ---
    if (impl < 0 || impl >= (int)(sizeof(encrypt_funcs) / sizeof(encrypt_funcs[0]))) {
        return CRYPTO_ERR_MODE;
    }

    aes_encrypt_func_t encrypt_func = encrypt_funcs[impl];
    if (!encrypt_func) {
        return CRYPTO_ERR_MODE;
    }

    if (encrypt_func(in, out, key, key_len) != 0) {
        return CRYPTO_ERR_INTERNAL;
    }

    return CRYPTO_OK;  // 정상 종료
}

/* ================================================================
 * AES_decrypt_block()
 * ---------------------------------------------------------------
 * AES 한 블록(16바이트)을 복호화하는 함수입니다.
 *
 * 매개변수:
 *   - in: 입력 암호문 (16바이트)
 *   - out: 출력 평문 (16바이트)
 *   - key: AES 키
 *   - key_len: 키 길이 (16/24/32바이트)
 *   - impl: 구현 방식 선택 (REF / TBL)
 *
 * 반환값:
 *   - CRYPTO_OK / CRYPTO_ERR_PARAM / CRYPTO_ERR_KEYLEN / CRYPTO_ERR_INTERNAL
 * ================================================================ */
int AES_decrypt_block(const byte in[AES_BLOCK_SIZE], byte out[AES_BLOCK_SIZE],
    const byte* key, int key_len, AES_Impl impl)
{
    // --- 기본 입력 검사 ---
    if (!in || !out || !key)
        return CRYPTO_ERR_PARAM;

    // --- 키 길이 검사 ---
    if (key_len != AES_KEY_SIZE_128 &&
        key_len != AES_KEY_SIZE_192 &&
        key_len != AES_KEY_SIZE_256)
        return CRYPTO_ERR_KEYLEN;

    // --- 구현 방식에 따라 함수 포인터로 호출 ---
    if (impl < 0 || impl >= (int)(sizeof(decrypt_funcs) / sizeof(decrypt_funcs[0]))) {
        return CRYPTO_ERR_MODE;
    }

    aes_decrypt_func_t decrypt_func = decrypt_funcs[impl];
    if (!decrypt_func) {
        return CRYPTO_ERR_MODE;
    }

    if (decrypt_func(in, out, key, key_len) != 0) {
        return CRYPTO_ERR_INTERNAL;
    }

    return CRYPTO_OK;
}

/* ================================================================
 * SHA512_hash()
 * ---------------------------------------------------------------
 * SHA-512 해시를 한 번에 계산하는 **원샷(One-shot)** 함수입니다.
 *
 * 매개변수:
 *   - data : 입력 데이터 (바이트 배열)
 *   - len  : 입력 데이터 길이 (바이트 단위)
 *   - out  : 해시 결과 출력 버퍼 (64바이트, SHA512_DIGEST_SIZE)
 *
 * 설명:
 *   이 함수는 다음 세 단계를 내부적으로 순차 실행합니다.
 *     1. SHA512_init()   : 내부 상태 초기화
 *     2. SHA512_update() : 입력 데이터 처리
 *     3. SHA512_final()  : 최종 패딩 및 결과 출력
 * ================================================================ */
void SHA512_hash(const uint8_t* data, size_t len, uint8_t out[SHA512_DIGEST_SIZE]) {
    SHA512_CTX ctx;
    SHA512_init(&ctx);
    SHA512_update(&ctx, data, len);
    SHA512_final(&ctx, out);
}

/* ================================================================
 * Mac()
 * ---------------------------------------------------------------
 * SHA-512 기반 MAC(Message Authentication Code)을 계산하는 함수입니다.
 *
 * 매개변수:
 *   - s        : 비밀 파라미터(또는 고정된 salt 등, 현재 구현에서는 사용되지 않음)
 *   - s_len    : s의 길이 (바이트 단위)
 *   - k        : MAC 생성에 사용할 비밀 키
 *   - k_len    : 비밀 키 길이 (바이트 단위)
 *   - tag_len  : 생성할 MAC 태그의 길이 (바이트 단위, 최대 64)
 *   - msg      : 인증할 메시지 데이터
 *   - msg_len  : 메시지 길이 (바이트 단위)
 *   - mac_tag  : 최종 생성된 MAC 값을 저장할 버퍼 (tag_len 크기)
 *
 * 반환값:
 *   -  0 : 성공적으로 MAC 계산 완료
 *   - -1 : 입력 검증 실패 또는 메모리 할당 오류
 *
 * 동작 과정:
 *   이 함수는 SHA-512를 기반으로 다음 단계를 수행합니다.
 *
 *   1. **GenSubKeys()**
 *      - 입력 키(k)로부터 두 개의 서브키(k0, k1)를 생성합니다.
 *        (HMAC의 inner pad, outer pad 역할과 유사)
 *
 *   2. **첫 번째 해시 (H_s(k0 || msg))**
 *      - 서브키 k0와 메시지(msg)를 연결(concatenate)하여 SHA512 해시를 계산합니다.
 *      - 결과값은 `hash_output`에 저장됩니다.
 *
 *   3. **두 번째 해시 (H_s(k1 || hash_output))**
 *      - 서브키 k1과 첫 번째 해시 결과(hash_output)를 연결하여 다시 해시를 수행합니다.
 *      - 이중 해싱 구조로, HMAC의 "outer hash" 단계에 해당합니다.
 *
 *   4. **결과 태그 생성**
 *      - 최종 해시 결과의 앞부분에서 `tag_len` 바이트를 MAC 태그로 복사합니다.
 *
 * 메모리 관리:
 *   - k0, k1은 스택에 고정 배열로 선언되어 있고,
 *   - (k0||msg) 및 (k1||hash_output) 연결 시에만 동적 메모리(`malloc`)를 사용합니다.
 *   - 계산 후, 동적으로 할당된 버퍼는 즉시 `free()`로 해제합니다.
 *
 * 요약:
 *   MAC(tag) = SHA512( k1 || SHA512(k0 || msg) )
 * ================================================================ */
int Mac(const byte* s, size_t s_len, const byte* k, size_t k_len,
    int tag_len, const byte* msg, size_t msg_len, byte* mac_tag) {
    if (!k || !msg || !mac_tag || tag_len <= 0 || tag_len > SHA512_DIGEST_SIZE) {
        return CRYPTO_ERR_PARAM;
    }

    byte k0[SHA512_BLOCK_SIZE];
    byte k1[SHA512_BLOCK_SIZE];
    byte hash_output[SHA512_DIGEST_SIZE];

    memset(k0, 0, SHA512_BLOCK_SIZE);
    memset(k1, 0, SHA512_BLOCK_SIZE);
    memset(hash_output, 0, SHA512_DIGEST_SIZE);

    if (GenSubKeys(s, s_len, k, k_len, k0, k1) != 0) {
        return CRYPTO_ERR_INTERNAL;
    }

    size_t first_input_len = SHA512_BLOCK_SIZE + s_len + msg_len;
    byte* first_input = (byte*)malloc(first_input_len);
    if (!first_input) {
        return CRYPTO_ERR_MEMORY;
    }

    size_t offset = 0;
    memcpy(first_input, k0, SHA512_BLOCK_SIZE);
    offset += SHA512_BLOCK_SIZE;

    if (s_len > 0 && s != NULL) {
        memcpy(first_input + offset, s, s_len);
        offset += s_len;
    }

    memcpy(first_input + offset, msg, msg_len);

    SHA512_hash(first_input, first_input_len, hash_output);

    free(first_input);

    size_t second_input_len = SHA512_BLOCK_SIZE + s_len + SHA512_DIGEST_SIZE;
    byte* second_input = (byte*)malloc(second_input_len);
    if (!second_input) {
        return CRYPTO_ERR_MEMORY;
    }

    offset = 0;
    memcpy(second_input, k1, SHA512_BLOCK_SIZE);
    offset += SHA512_BLOCK_SIZE;

    if (s_len > 0 && s != NULL) {
        memcpy(second_input + offset, s, s_len);
        offset += s_len;
    }

    memcpy(second_input + offset, hash_output, SHA512_DIGEST_SIZE);

    SHA512_hash(second_input, second_input_len, hash_output);

    free(second_input);

    memcpy(mac_tag, hash_output, tag_len);

    return CRYPTO_OK;
}

/* ================================================================
 * Vrfy()
 * ---------------------------------------------------------------
 * 메시지와 주어진 MAC 태그를 검증(Verification)하는 함수입니다.
 *
 * 매개변수:
 *   - s        : 비밀 파라미터(또는 salt, 현재 구현에서는 사용되지 않음)
 *   - s_len    : s의 길이 (바이트 단위)
 *   - k        : MAC 생성에 사용된 비밀 키
 *   - k_len    : 비밀 키 길이 (바이트 단위)
 *   - tag_len  : MAC 태그 길이 (바이트 단위, 최대 64)
 *   - msg      : 검증할 메시지 데이터
 *   - msg_len  : 메시지 길이 (바이트 단위)
 *   - mac_tag  : 검증 대상 MAC 태그 (tag_len 크기)
 *
 * 반환값:
 *   - 1 : 유효한 MAC (메시지가 변조되지 않음)
 *   - 0 : 무효한 MAC (검증 실패 또는 입력 오류)
 *
 * 동작 과정:
 *   1. 입력 유효성 검사를 수행합니다.
 *      (널 포인터, tag_len 범위 등을 확인)
 *
 *   2. **Mac()** 함수를 호출하여 동일한 입력 데이터(msg, k 등)로
 *      새 MAC을 계산하고 `computed_tag`에 저장합니다.
 *
 *   3. **상수 시간 비교(Constant-time comparison)**
 *      - `computed_tag`와 입력으로 받은 `mac_tag`를 바이트 단위로 비교합니다.
 *      - 중간에 차이가 나도 루프를 끝내지 않고 끝까지 비교하여,
 *        타이밍 공격(timing attack)을 방지합니다.
 *
 *   4. 모든 바이트가 동일하면 1을 반환하고,
 *      하나라도 다르면 0을 반환합니다.
 *
 * 보안 고려:
 *   - 타이밍 공격 방지를 위해 비교 시 조기 종료를 하지 않습니다.
 *   - `memcmp()` 대신 직접 루프를 사용하는 이유가 바로 이 때문입니다.
 *
 * 요약:
 *   return (Mac(s, k, msg) == mac_tag) ? VALID(1) : INVALID(0);
 * ================================================================ */
int Vrfy(const byte* s, size_t s_len, const byte* k, size_t k_len,
    int tag_len, const byte* msg, size_t msg_len, const byte* mac_tag) {
    if (!k || !msg || !mac_tag || tag_len <= 0 || tag_len > SHA512_DIGEST_SIZE) {
        return 0;
    }

    byte computed_tag[SHA512_DIGEST_SIZE];

    if (Mac(s, s_len, k, k_len, tag_len, msg, msg_len, computed_tag) != 0) {
        return 0;
    }

    int result = 1;
    for (int i = 0; i < tag_len; i++) {
        if (computed_tag[i] != mac_tag[i]) {
            result = 0;
        }
    }

    return result;
}