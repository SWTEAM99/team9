#include "crypto_api.h"   // AES_Impl enum, 상수, 오류 코드 정의
#include "utils.h"        // UTIL_* 함수들
#include <string.h>       // memcpy 등 기본 유틸 사용
#include <stdlib.h>

/* ================================================================
 * 함수 포인터 타입 정의
 * ================================================================ */

 /* AES 암호화 함수 포인터 타입 */
typedef int (*aes_encrypt_func_t)(const byte in[AES_BLOCK_SIZE],
    byte out[AES_BLOCK_SIZE],
    const byte* key, int key_len);

/* AES 복호화 함수 포인터 타입 */
typedef int (*aes_decrypt_func_t)(const byte in[AES_BLOCK_SIZE],
    byte out[AES_BLOCK_SIZE],
    const byte* key, int key_len);

/* ================================================================
 * T-table 버전 래퍼 함수들
 * ================================================================ */

 /* T-table 기반 AES 암호화 래퍼: AES_TBL_CTX 초기화 후 암호화 수행 */
static int aes_tbl_encrypt_wrapper(const byte in[AES_BLOCK_SIZE],
    byte out[AES_BLOCK_SIZE],
    const byte* key, int key_len) {
    AES_TBL_CTX ctx;
    if (AES_TBL_init(&ctx, key, key_len) != 0) {
        return CRYPTO_ERR_INTERNAL;
    }
    aes_encrypt_core(&ctx, in, out);
    return CRYPTO_OK;
}

/* T-table 기반 AES 복호화 래퍼: AES_TBL_CTX 초기화 후 복호화 수행 */
static int aes_tbl_decrypt_wrapper(const byte in[AES_BLOCK_SIZE],
    byte out[AES_BLOCK_SIZE],
    const byte* key, int key_len) {
    AES_TBL_CTX ctx;
    if (AES_TBL_init(&ctx, key, key_len) != 0) {
        return CRYPTO_ERR_INTERNAL;
    }
    aes_decrypt_core(&ctx, in, out);
    return CRYPTO_OK;
}

/* ================================================================
 * 함수 포인터 테이블: 구현 방식에 따라 적절한 함수를 선택
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
    if (key_len != AES_128_KEY_SIZE &&
        key_len != AES_192_KEY_SIZE &&
        key_len != AES_256_KEY_SIZE)
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
    if (key_len != AES_128_KEY_SIZE &&
        key_len != AES_192_KEY_SIZE &&
        key_len != AES_256_KEY_SIZE)
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
 * SHA-512 해시를 한 번에 계산하는 **원샷(One-shot)** 래퍼 함수입니다.
 *
 * 매개변수:
 *   - data : 입력 데이터 (바이트 배열)
 *   - len  : 입력 데이터 길이 (바이트 단위)
 *   - out  : 해시 결과 출력 버퍼 (64바이트, SHA512_DIGEST_SIZE)
 *
 * 반환값:
 *   - CRYPTO_OK : 성공
 *   - CRYPTO_ERR_PARAM : 입력 검증 실패
 *
 * 설명:
 *   이 함수는 SHA-512 해시를 계산하는 래퍼 함수입니다.
 *   실제 구현은 sha512.c의 SHA512_hash_impl() 함수에서 수행됩니다.
 *   내부적으로 다음 세 단계를 순차 실행합니다.
 *     1. SHA512_init()   : 내부 상태 초기화
 *     2. SHA512_update() : 입력 데이터 처리
 *     3. SHA512_final()  : 최종 패딩 및 결과 출력
 * ================================================================ */
int SHA512_hash(const uint8_t* data, size_t len, uint8_t out[SHA512_DIGEST_SIZE]) {
    return SHA512_hash_impl(data, len, out);
}

/* ================================================================
 * Mac()
 * ---------------------------------------------------------------
 * SHA-512 기반 MAC(Message Authentication Code)을 계산하는 래퍼 함수입니다.
 *
 * 매개변수:
 *   - s        : 비밀 파라미터(또는 고정된 salt 등)
 *   - s_len    : s의 길이 (바이트 단위)
 *   - k        : MAC 생성에 사용할 비밀 키
 *   - k_len    : 비밀 키 길이 (바이트 단위)
 *   - tag_len  : 생성할 MAC 태그의 길이 (바이트 단위, 최대 64)
 *   - msg      : 인증할 메시지 데이터
 *   - msg_len  : 메시지 길이 (바이트 단위)
 *   - mac_tag  : 최종 생성된 MAC 값을 저장할 버퍼 (tag_len 크기)
 *
 * 반환값:
 *   - CRYPTO_OK : 성공적으로 MAC 계산 완료
 *   - CRYPTO_ERR_PARAM : 입력 검증 실패
 *   - CRYPTO_ERR_MEMORY : 메모리 할당 오류
 *   - CRYPTO_ERR_INTERNAL : 내부 오류
 *
 * 설명:
 *   이 함수는 HMAC-SHA512 기반 MAC을 계산하는 래퍼 함수입니다.
 *   실제 구현은 hmac.c의 HMAC_Mac() 함수에서 수행됩니다.
 * ================================================================ */
int Mac(const byte* s, size_t s_len, const byte* k, size_t k_len,
    int tag_len, const byte* msg, size_t msg_len, byte* mac_tag) {
    return HMAC_Mac(s, s_len, k, k_len, tag_len, msg, msg_len, mac_tag);
}

/* ================================================================
 * Vrfy()
 * ---------------------------------------------------------------
 * 메시지와 주어진 MAC 태그를 검증(Verification)하는 래퍼 함수입니다.
 *
 * 매개변수:
 *   - s        : 비밀 파라미터(또는 salt)
 *   - s_len    : s의 길이 (바이트 단위)
 *   - k        : MAC 생성에 사용된 비밀 키
 *   - k_len    : 비밀 키 길이 (바이트 단위)
 *   - tag_len  : MAC 태그 길이 (바이트 단위, 최대 64)
 *   - msg      : 검증할 메시지 데이터
 *   - msg_len  : 메시지 길이 (바이트 단위)
 *   - mac_tag  : 검증 대상 MAC 태그 (tag_len 크기)
 *
 * 반환값:
 *   - CRYPTO_OK : 유효한 MAC (메시지가 변조되지 않음)
 *   - CRYPTO_ERR_INVALID : 무효한 MAC (검증 실패)
 *   - CRYPTO_ERR_PARAM : 입력 오류
 *   - CRYPTO_ERR_INTERNAL : 내부 오류
 *
 * 설명:
 *   이 함수는 MAC 검증을 수행하는 래퍼 함수입니다.
 *   실제 구현은 hmac.c의 HMAC_Vrfy() 함수에서 수행되며,
 *   상수 시간 비교를 통해 타이밍 공격을 방지합니다.
 * ================================================================ */
int Vrfy(const byte* s, size_t s_len,
    const byte* k, size_t k_len,
    int tag_len,
    const byte* msg, size_t msg_len,
    const byte* mac_tag)
{
    return HMAC_Vrfy(s, s_len, k, k_len, tag_len, msg, msg_len, mac_tag);
}

/* ================================================================
 * CBC_encrypt()
 * ---------------------------------------------------------------
 * 범용 CBC 암호화를 수행하는 래퍼 함수입니다.
 *
 * 매개변수:
 *   - encrypt_block : 블록 암호화 함수 포인터
 *   - block_size     : 블록 크기
 *   - iv             : 초기화 벡터
 *   - plaintext      : 평문 데이터
 *   - pt_len         : 평문 길이
 *   - ciphertext     : 암호문 출력 버퍼
 *   - ct_len         : 암호문 길이 (출력)
 *   - user_ctx       : 사용자 컨텍스트
 *
 * 반환값:
 *   - CRYPTO_OK : 성공
 *   - 기타 에러 코드
 *
 * 설명:
 *   이 함수는 범용 CBC 암호화를 수행하는 래퍼 함수입니다.
 *   실제 구현은 modes.c의 MODES_CBC_encrypt() 함수에서 수행됩니다.
 *   항상 PKCS7 패딩을 사용합니다.
 * ================================================================ */
int CBC_encrypt(
    void (*encrypt_block)(const byte* in, byte* out, const void* user_ctx),
    int block_size,
    const byte iv[],
    const byte* plaintext, int pt_len,
    byte* ciphertext, int* ct_len,
    const void* user_ctx
) {
    return MODES_CBC_encrypt(encrypt_block, block_size, iv, plaintext, pt_len, ciphertext, ct_len, user_ctx);
}

/* ================================================================
 * CBC_decrypt()
 * ---------------------------------------------------------------
 * 범용 CBC 복호화를 수행하는 래퍼 함수입니다.
 *
 * 매개변수:
 *   - decrypt_block : 블록 복호화 함수 포인터
 *   - block_size     : 블록 크기
 *   - iv             : 초기화 벡터
 *   - ciphertext     : 암호문 데이터
 *   - ct_len         : 암호문 길이
 *   - plaintext      : 평문 출력 버퍼
 *   - pt_len         : 평문 길이 (출력)
 *   - user_ctx       : 사용자 컨텍스트
 *
 * 반환값:
 *   - CRYPTO_OK : 성공
 *   - 기타 에러 코드
 *
 * 설명:
 *   이 함수는 범용 CBC 복호화를 수행하는 래퍼 함수입니다.
 *   실제 구현은 modes.c의 MODES_CBC_decrypt() 함수에서 수행됩니다.
 *   항상 PKCS7 패딩을 제거합니다.
 * ================================================================ */
int CBC_decrypt(
    void (*decrypt_block)(const byte* in, byte* out, const void* user_ctx),
    int block_size,
    const byte iv[],
    const byte* ciphertext, int ct_len,
    byte* plaintext, int* pt_len,
    const void* user_ctx
) {
    return MODES_CBC_decrypt(decrypt_block, block_size, iv, ciphertext, ct_len, plaintext, pt_len, user_ctx);
}

/* ================================================================
 * CTR_crypt()
 * ---------------------------------------------------------------
 * 범용 CTR 암/복호화를 수행하는 래퍼 함수입니다.
 *
 * 매개변수:
 *   - encrypt_block : 블록 암호화 함수 포인터
 *   - block_size     : 블록 크기
 *   - nonce_ctr      : nonce/counter (수정됨)
 *   - in             : 입력 데이터
 *   - len            : 입력 데이터 길이
 *   - out            : 출력 버퍼
 *   - user_ctx       : 사용자 컨텍스트
 *
 * 반환값:
 *   - CRYPTO_OK : 성공
 *   - 기타 에러 코드
 *
 * 설명:
 *   이 함수는 범용 CTR 암/복호화를 수행하는 래퍼 함수입니다.
 *   실제 구현은 modes.c의 MODES_CTR_crypt() 함수에서 수행됩니다.
 * ================================================================ */
int CTR_crypt(
    void (*encrypt_block)(const byte* in, byte* out, const void* user_ctx),
    int block_size,
    byte* nonce_ctr,
    const byte* in, int len,
    byte* out,
    const void* user_ctx
) {
    return MODES_CTR_crypt(encrypt_block, block_size, nonce_ctr, in, len, out, user_ctx);
}

/* ================================================================
 * 유틸리티 함수 별칭 (CRYPTO_* 이름으로 utils.c의 UTIL_* 함수 호출)
 * ================================================================ */

void CRYPTO_printHex(const byte* data, int len) {
    UTIL_printHex(data, len);
}

int CRYPTO_isEqual(const byte* a, const byte* b, int len) {
    return UTIL_isEqual(a, b, len);
}

int CRYPTO_readFile(const char* filename, byte** data, size_t* len) {
    return UTIL_readFile(filename, data, len);
}

int CRYPTO_writeFile(const char* filename, const byte* data, size_t len) {
    return UTIL_writeFile(filename, data, len);
}
