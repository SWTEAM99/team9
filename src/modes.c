#include "crypto_api.h"
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
static inline void xor_block(byte* d, const byte* a, const byte* b, int bs) {
    for (int i = 0; i < bs; ++i) d[i] = (byte)(a[i] ^ b[i]);
}

static int pkcs7_padlen(int n, int bs) {
    int r = n % bs;
    return bs - r;
}

static int pkcs7_apply_last(byte* blk, int used, int bs) {
    if (used < 0 || used > bs - 1) return CRYPTO_ERR_INTERNAL;
    int pad = bs - used;
    for (int i = used; i < bs; ++i) blk[i] = (byte)pad;
    return CRYPTO_OK;
}

static int pkcs7_unpad_inplace(byte* buf, int* len_io, int bs) {
    int L = *len_io;
    if (L <= 0 || (L % bs) != 0) return CRYPTO_ERR_PADDING;
    byte p = buf[L - 1];
    if (p == 0 || p > bs) return CRYPTO_ERR_INVALID;

    unsigned char bad = 0;
    for (int i = 0; i < p; ++i) bad |= (unsigned char)(buf[L - 1 - i] ^ p);
    if (bad) return CRYPTO_ERR_INVALID;

    *len_io = L - p;
    return CRYPTO_OK;
}

/* ---------- 난수 / IV ---------- */
int CRYPTO_randomBytes(byte* out, int len) {
    if (!out || len <= 0) return CRYPTO_ERR_PARAM;

#ifdef _WIN32
    /* Windows: CryptGenRandom 사용 */
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
    /* Linux/macOS: /dev/urandom 사용 */
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


int IV_generate(byte iv[AES_BLOCK_SIZE]) {
    return CRYPTO_randomBytes(iv, AES_BLOCK_SIZE);
}

/* =========================================================
 * Generic CBC (콜백/블록사이즈 기반) — 이름 요구: CBC_*
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
    if (!encrypt_block || !iv || !plaintext || !ciphertext || !ct_len) return CRYPTO_ERR_PARAM;
    if (block_size <= 0 || pt_len < 0) return CRYPTO_ERR_PARAM;

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

    byte prev[32];
    if (block_size > (int)sizeof(prev)) return CRYPTO_ERR_BUFFER;
    memcpy(prev, iv, block_size);

    for (int b = 0; b < full; ++b) {
        byte x[32], y[32];
        xor_block(x, plaintext + block_size * b, prev, block_size);
        encrypt_block(x, y, user_ctx);
        memcpy(ciphertext + block_size * b, y, block_size);
        memcpy(prev, y, block_size);
    }

    if (padding == CBC_PADDING_PKCS7) {
        byte last[32] = { 0 };
        if (rem) memcpy(last, plaintext + block_size * full, rem);
        int rc = pkcs7_apply_last(last, rem, block_size);
        if (rc != CRYPTO_OK) return rc;
        byte x[32], y[32];
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
    if (!decrypt_block || !iv || !ciphertext || !plaintext || !pt_len) return CRYPTO_ERR_PARAM;
    if (block_size <= 0 || ct_len <= 0 || (ct_len % block_size) != 0) return CRYPTO_ERR_PARAM;

    byte prev[32];
    if (block_size > (int)sizeof(prev)) return CRYPTO_ERR_BUFFER;
    memcpy(prev, iv, block_size);

    for (int off = 0; off < ct_len; off += block_size) {
        byte tmp[32], pt[32];
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
 * CTR (제너릭)
 * ========================================================= */
int CTR_crypt(
    void (*encrypt_block)(const byte* in, byte* out, const void* user_ctx),
    int block_size,
    byte* nonce_ctr,
    const byte* in, int len,
    byte* out,
    const void* user_ctx
) {
    if (!encrypt_block || !nonce_ctr || !in || !out) return CRYPTO_ERR_PARAM;
    if (block_size <= 0 || len < 0) return CRYPTO_ERR_PARAM;

    byte ctr[32];
    if (block_size > (int)sizeof(ctr)) return CRYPTO_ERR_BUFFER;
    memcpy(ctr, nonce_ctr, block_size);

    int off = 0;
    while (off < len) {
        byte ks[32];
        encrypt_block(ctr, ks, user_ctx);
        int chunk = (len - off >= block_size) ? block_size : (len - off);
        for (int i = 0; i < chunk; ++i) out[off + i] = (byte)(in[off + i] ^ ks[i]);

        for (int i = block_size - 1; i >= 0; --i) { if (++ctr[i] != 0) break; }
        off += chunk;
    }
    return CRYPTO_OK;
}