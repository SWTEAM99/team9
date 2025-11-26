#include "modes.h"
#include "error.h"
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#else
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#endif

/* ---------- 공통 유틸 ---------- */

/* 두 블록을 XOR 연산하여 결과를 d에 저장 */
static inline void xor_block(byte* d, const byte* a, const byte* b, int bs) {
    for (int i = 0; i < bs; ++i) d[i] = (byte)(a[i] ^ b[i]);
}

/* PKCS7 패딩 길이 계산 (n 바이트를 block_size에 맞추기 위해 필요한 패딩 바이트 수) */
static int pkcs7_padlen(int n, int bs) {
    int r = n % bs;
    return bs - r;
}

/* 마지막 블록에 PKCS7 패딩 적용 (used 바이트 사용됨, 나머지를 패딩 값으로 채움) */
static int pkcs7_apply_last(byte* blk, int used, int bs) {
    if (used < 0 || used > bs - 1) return CRYPTO_ERR_INTERNAL;
    int pad = bs - used;
    for (int i = used; i < bs; ++i) blk[i] = (byte)pad;
    return CRYPTO_OK;
}

/* PKCS7 패딩 제거 (in-place) — 마지막 바이트 값 = 패딩 길이 p */
static int pkcs7_unpad_inplace(byte* buf, int* len_io, int bs) {
    int L = *len_io;
    if (L <= 0 || (L % bs) != 0) return CRYPTO_ERR_PADDING;

    byte p = buf[L - 1];
    if (p == 0 || p > bs) return CRYPTO_ERR_INVALID;

    // 패딩 값 p가 연속으로 p번 반복되는지 상수 시간으로 검사
    unsigned char bad = 0;
    for (int i = 0; i < p; ++i)
        bad |= (unsigned char)(buf[L - 1 - i] ^ p);

    if (bad) return CRYPTO_ERR_INVALID;

    *len_io = L - p;
    return CRYPTO_OK;
}

/* ---------- 난수 / IV ---------- */

/* 플랫폼별 안전한 랜덤 바이트 생성 */
int CRYPTO_randomBytes(byte* out, int len) {
    if (!out || len <= 0) return CRYPTO_ERR_PARAM;

#ifdef _WIN32
    // Windows: CryptGenRandom 사용
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return CRYPTO_ERR_RANDOM;
    }

    if (!CryptGenRandom(hProv, (DWORD)len, out)) {
        CryptReleaseContext(hProv, 0);
        return CRYPTO_ERR_RANDOM;
    }

    CryptReleaseContext(hProv, 0);
    return CRYPTO_OK;

#else
    // Linux/macOS: /dev/urandom 사용
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return CRYPTO_ERR_RANDOM;

    int remaining = len;
    while (remaining > 0) {
        ssize_t r = read(fd, out + (len - remaining), remaining);
        if (r <= 0) {
            close(fd);
            return CRYPTO_ERR_RANDOM;
        }
        remaining -= (int)r;
    }

    close(fd);
    return CRYPTO_OK;
#endif
}

/* AES 블록 크기만큼 IV 생성 */
int IV_generate(byte iv[AES_BLOCK_SIZE]) {
    return CRYPTO_randomBytes(iv, AES_BLOCK_SIZE);
}

/* =========================================================
 * CBC 모드 (Generic) — 실제 구현
 * ========================================================= */

 /* CBC 암호화 — 항상 PKCS7 패딩 사용 */
int MODES_CBC_encrypt(
    void (*encrypt_block)(const byte* in, byte* out, const void* user_ctx),
    int block_size,
    const byte iv[],
    const byte* plaintext, int pt_len,
    byte* ciphertext, int* ct_len,
    const void* user_ctx
) {
    // 기본 검증
    if (!encrypt_block || !iv || !plaintext || !ciphertext || !ct_len)
        return CRYPTO_ERR_PARAM;
    if (block_size <= 0 || pt_len < 0)
        return CRYPTO_ERR_PARAM;

    // 전체 블록 수, 마지막 부분 길이
    int full = pt_len / block_size;
    int rem = pt_len % block_size;

    // 총 암호문 길이: 항상 PKCS7 패딩
    int total = pt_len + pkcs7_padlen(pt_len, block_size);
    *ct_len = total;

    // prev = IV (첫 라운드에는 IV와 XOR)
    byte prev[32];
    if (block_size > (int)sizeof(prev)) return CRYPTO_ERR_BUFFER;
    memcpy(prev, iv, block_size);

    // 완전한 블록들 처리
    for (int b = 0; b < full; ++b) {
        byte x[32], y[32];
        // 평문 블록 XOR 이전 암호블록(prev)
        xor_block(x, plaintext + block_size * b, prev, block_size);

        // 블록 암호화
        encrypt_block(x, y, user_ctx);

        // 암호문 저장 및 prev 업데이트
        memcpy(ciphertext + block_size * b, y, block_size);
        memcpy(prev, y, block_size);
    }

    // 마지막 블록(패딩 포함)
    byte last[32] = { 0 };
    if (rem) memcpy(last, plaintext + block_size * full, rem);

    // PKCS7 패딩 적용
    int rc = pkcs7_apply_last(last, rem, block_size);
    if (rc != CRYPTO_OK) return rc;

    byte x[32], y[32];
    xor_block(x, last, prev, block_size);
    encrypt_block(x, y, user_ctx);

    memcpy(ciphertext + block_size * full, y, block_size);

    return CRYPTO_OK;
}

/* CBC 복호화 — 항상 PKCS7 패딩 제거 */
int MODES_CBC_decrypt(
    void (*decrypt_block)(const byte* in, byte* out, const void* user_ctx),
    int block_size,
    const byte iv[],
    const byte* ciphertext, int ct_len,
    byte* plaintext, int* pt_len,
    const void* user_ctx
) {
    // 기본 파라미터 검사
    if (!decrypt_block || !iv || !ciphertext || !plaintext || !pt_len)
        return CRYPTO_ERR_PARAM;
    if (block_size <= 0 || ct_len <= 0 || (ct_len % block_size) != 0)
        return CRYPTO_ERR_PARAM;

    // prev = IV
    byte prev[32];
    if (block_size > (int)sizeof(prev)) return CRYPTO_ERR_BUFFER;
    memcpy(prev, iv, block_size);

    // 모든 블록 복호화 (PKCS7 제거는 마지막에)
    for (int off = 0; off < ct_len; off += block_size) {
        byte tmp[32], pt[32];

        // 블록 복호화
        decrypt_block(ciphertext + off, tmp, user_ctx);

        // XOR(prev) → 평문블록 생성
        xor_block(pt, tmp, prev, block_size);

        memcpy(plaintext + off, pt, block_size);

        // prev = 현재 암호블록
        memcpy(prev, ciphertext + off, block_size);
    }

    // PKCS7 패딩 제거
    int out_len = ct_len;
    int rc = pkcs7_unpad_inplace(plaintext, &out_len, block_size);
    if (rc != CRYPTO_OK) return rc;

    *pt_len = out_len;
    return CRYPTO_OK;
}

/* =========================================================
 * CTR 모드 (Generic) — 실제 구현
 * ========================================================= */

 /* CTR 암/복호화 — encrypt_block만 호출하면 암/복호화 동일 */
int MODES_CTR_crypt(
    void (*encrypt_block)(const byte* in, byte* out, const void* user_ctx),
    int block_size,
    byte* nonce_ctr,
    const byte* in, int len,
    byte* out,
    const void* user_ctx
) {
    // 기본 검증
    if (!encrypt_block || !nonce_ctr || !in || !out)
        return CRYPTO_ERR_PARAM;
    if (block_size <= 0 || len < 0)
        return CRYPTO_ERR_PARAM;

    // ctr = 초기 nonce/counter 값 복사
    byte ctr[32];
    if (block_size > (int)sizeof(ctr)) return CRYPTO_ERR_BUFFER;
    memcpy(ctr, nonce_ctr, block_size);

    int off = 0;

    // 전체 데이터 처리
    while (off < len) {
        byte ks[32];

        // keystream block = Encrypt(counter)
        encrypt_block(ctr, ks, user_ctx);

        // plaintext ^ keystream → ciphertext (또는 그 반대)
        int chunk = (len - off >= block_size) ? block_size : (len - off);
        for (int i = 0; i < chunk; ++i)
            out[off + i] = (byte)(in[off + i] ^ ks[i]);

        // counter 증가 (Big-endian increment)
        for (int i = block_size - 1; i >= 0; --i)
            if (++ctr[i] != 0) break;

        off += chunk;
    }

    return CRYPTO_OK;
}
