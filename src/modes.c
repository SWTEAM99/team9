#include "crypto_api.h"
#include "error.h"
#include <string.h>

#ifdef _WIN32
// ===== Windows: BCryptGenRandom 사용 =====
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
// ===== macOS / Linux: /dev/urandom 사용 =====
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#endif

/* AES 이상 가정: 블록 크기 최대 32바이트까지만 지원 (AES는 16바이트라 충분함) */
#define MAX_BLOCK_SIZE 32

/* =========================================================
 * 내부 유틸 함수들
 * ========================================================= */

 /* 두 블록 XOR */
static inline void xor_block(byte* d, const byte* a, const byte* b, int bs) {
    for (int i = 0; i < bs; ++i) d[i] = (byte)(a[i] ^ b[i]);
}

/* PKCS#7 패딩 길이 계산 */
static int pkcs7_padlen(int n, int bs) {
    int r = n % bs;
    return bs - r;
}

/* 마지막 블록에 PKCS#7 패딩 적용 (used = 실제 데이터 길이) */
static int pkcs7_apply_last(byte* blk, int used, int bs) {
    if (used < 0 || used > bs) return CRYPTO_ERR_INTERNAL;
    int pad = bs - used;
    for (int i = used; i < bs; ++i) blk[i] = (byte)pad;
    return CRYPTO_OK;
}

/* PKCS#7 패딩 제거 (in-place) */
static int pkcs7_unpad_inplace(byte* buf, int* len_io, int bs) {
    int L = *len_io;
    if (L <= 0 || (L % bs) != 0) return CRYPTO_ERR_PADDING;

    byte p = buf[L - 1];
    if (p == 0 || p > bs) return CRYPTO_ERR_PADDING;

    unsigned char bad = 0;
    for (int i = 0; i < p; ++i) {
        bad |= (unsigned char)(buf[L - 1 - i] ^ p);
    }
    if (bad) return CRYPTO_ERR_PADDING;

    *len_io = L - p;
    return CRYPTO_OK;
}

/* =========================================================
 * 난수 / IV 생성 (플랫폼 별 분기)
 * ========================================================= */

int CRYPTO_randomBytes(byte* out, int len) {
    if (!out || len < 0) return CRYPTO_ERR_PARAM;
    if (len == 0) return CRYPTO_OK;

#ifdef _WIN32
    /* ---- Windows: BCryptGenRandom ---- */
    NTSTATUS st = BCryptGenRandom(NULL, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (st == 0) ? CRYPTO_OK : CRYPTO_ERR_RANDOM;
#else
    /* ---- macOS / Linux: /dev/urandom ---- */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return CRYPTO_ERR_RANDOM;
    }

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

/* AES용 IV 생성 (블록 크기 = AES_BLOCK_SIZE) */
int IV_generate(byte iv[AES_BLOCK_SIZE]) {
    return CRYPTO_randomBytes(iv, AES_BLOCK_SIZE);
}

/* =========================================================
 * Generic CBC 모드
 *   - 모든 블록 암호에 사용 가능
 *   - encrypt_block / decrypt_block 콜백에 AES_encrypt_block 등 래퍼를 넘겨서 사용
 * ========================================================= */

int CBC_encrypt(
    void (*encrypt_block)(const byte* in, byte* out, const void* user_ctx),
    int block_size,
    const byte iv[],                 /* block_size bytes */
    CBC_Padding padding,
    const byte* plaintext, int pt_len,
    byte* ciphertext, int* ct_len,
    const void* user_ctx
) {
    if (!encrypt_block || !iv || !plaintext || !ciphertext || !ct_len)
        return CRYPTO_ERR_PARAM;
    if (block_size <= 0 || pt_len < 0)
        return CRYPTO_ERR_PARAM;
    if (block_size > MAX_BLOCK_SIZE)
        return CRYPTO_ERR_PARAM;     // 이 구현은 최대 32바이트 블록만 지원

    int full = pt_len / block_size;
    int rem = pt_len % block_size;
    int total;

    if (padding == CBC_PADDING_NONE) {
        if (rem) return CRYPTO_ERR_PADDING;
        total = pt_len;
    }
    else if (padding == CBC_PADDING_PKCS7) {
        total = pt_len + pkcs7_padlen(pt_len, block_size);
    }
    else {
        return CRYPTO_ERR_MODE;
    }
    *ct_len = total;

    byte prev[MAX_BLOCK_SIZE];
    memcpy(prev, iv, block_size);

    /* 완전한 블록들 처리 */
    for (int b = 0; b < full; ++b) {
        byte x[MAX_BLOCK_SIZE], y[MAX_BLOCK_SIZE];
        xor_block(x, plaintext + block_size * b, prev, block_size);
        encrypt_block(x, y, user_ctx);
        memcpy(ciphertext + block_size * b, y, block_size);
        memcpy(prev, y, block_size);
    }

    /* 마지막 패딩 블록 */
    if (padding == CBC_PADDING_PKCS7) {
        byte last[MAX_BLOCK_SIZE] = { 0 };
        if (rem) memcpy(last, plaintext + block_size * full, rem);
        int rc = pkcs7_apply_last(last, rem, block_size);
        if (rc != CRYPTO_OK) return rc;

        byte x[MAX_BLOCK_SIZE], y[MAX_BLOCK_SIZE];
        xor_block(x, last, prev, block_size);
        encrypt_block(x, y, user_ctx);
        memcpy(ciphertext + block_size * full, y, block_size);
    }

    return CRYPTO_OK;
}

int CBC_decrypt(
    void (*decrypt_block)(const byte* in, byte* out, const void* user_ctx),
    int block_size,
    const byte iv[],                 /* block_size bytes */
    CBC_Padding padding,
    const byte* ciphertext, int ct_len,
    byte* plaintext, int* pt_len,
    const void* user_ctx
) {
    if (!decrypt_block || !iv || !ciphertext || !plaintext || !pt_len)
        return CRYPTO_ERR_PARAM;
    if (block_size <= 0 || ct_len <= 0 || (ct_len % block_size) != 0)
        return CRYPTO_ERR_PARAM;
    if (block_size > MAX_BLOCK_SIZE)
        return CRYPTO_ERR_PARAM;

    byte prev[MAX_BLOCK_SIZE];
    memcpy(prev, iv, block_size);

    /* CBC 역연산: C_i -> P_i */
    for (int off = 0; off < ct_len; off += block_size) {
        byte tmp[MAX_BLOCK_SIZE], pt[MAX_BLOCK_SIZE];
        decrypt_block(ciphertext + off, tmp, user_ctx);
        xor_block(pt, tmp, prev, block_size);
        memcpy(plaintext + off, pt, block_size);
        memcpy(prev, ciphertext + off, block_size);
    }

    int out_len = ct_len;

    if (padding == CBC_PADDING_PKCS7) {
        int rc = pkcs7_unpad_inplace(plaintext, &out_len, block_size);
        if (rc != CRYPTO_OK) return rc;
    }
    else if (padding != CBC_PADDING_NONE) {
        return CRYPTO_ERR_MODE;
    }

    *pt_len = out_len;
    return CRYPTO_OK;
}

/* =========================================================
 * Generic CTR 모드
 *   - encrypt_block 콜백만 필요 (CTR은 암/복호 동일)
 * ========================================================= */

int CTR_crypt(
    void (*encrypt_block)(const byte* in, byte* out, const void* user_ctx),
    int block_size,
    byte* nonce_ctr,      /* 초기 nonce || counter 값 (block_size 바이트) */
    const byte* in, int len,
    byte* out,
    const void* user_ctx
) {
    if (!encrypt_block || !nonce_ctr || !in || !out)
        return CRYPTO_ERR_PARAM;
    if (block_size <= 0 || len < 0)
        return CRYPTO_ERR_PARAM;
    if (block_size > MAX_BLOCK_SIZE)
        return CRYPTO_ERR_PARAM;

    byte ctr[MAX_BLOCK_SIZE];
    memcpy(ctr, nonce_ctr, block_size);

    int off = 0;
    while (off < len) {
        byte keystream[MAX_BLOCK_SIZE];
        encrypt_block(ctr, keystream, user_ctx);

        int chunk = (len - off >= block_size) ? block_size : (len - off);
        for (int i = 0; i < chunk; ++i)
            out[off + i] = (byte)(in[off + i] ^ keystream[i]);

        /* big-endian counter 증가 */
        for (int i = block_size - 1; i >= 0; --i) {
            if (++ctr[i] != 0) break;
        }

        off += chunk;
    }

    /* 원하면 nonce_ctr에 마지막 ctr 값 다시 저장할 수도 있음 (지금은 그대로 두는 버전) */
    return CRYPTO_OK;
}

