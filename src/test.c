#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "crypto_api.h"   // byte, AES_BLOCK_SIZE, SHA512_DIGEST_SIZE,
// AES_encrypt_block, AES_decrypt_block,
// CBC_encrypt, CBC_decrypt, CTR_crypt,
// SHA512_hash, Mac, AES_Impl, AES_IMPL_REF, AES_IMPL_TBL
// CRYPTO_OK 등

#define TEST_RESULT_FILE "test_results.txt"

/* ============================================================
 * 공통 상태/유틸
 * ============================================================ */

static FILE* result_file = NULL;
static int total_tests = 0;
static int passed_tests = 0;
static int failed_tests = 0;

/* hex 문자열을 바이트 배열로 */
static void hex_to_bytes(const char* hex, byte* out, size_t len_bytes)
{
    for (size_t i = 0; i < len_bytes; i++) {
        unsigned int v = 0;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) {
            out[i] = 0;
        }
        else {
            out[i] = (byte)v;
        }
    }
}

/* 바이트 배열을 hex 문자열로 (로그용) */
static void bytes_to_hex(const byte* data, size_t len, char* hex_buf, size_t hex_buf_size)
{
    size_t need = len * 2 + 1;
    if (hex_buf_size < need) {
        /* 그냥 잘리는대로 찍는다 */
        need = hex_buf_size;
    }
    for (size_t i = 0; i < len && (i * 2 + 2) <= hex_buf_size; i++) {
        snprintf(hex_buf + i * 2, hex_buf_size - i * 2, "%02x", data[i]);
    }
    if (hex_buf_size > 0)
        hex_buf[need - 1] = '\0';
}

/* 바이트 비교 */
static int compare_bytes(const byte* a, const byte* b, size_t len)
{
    return memcmp(a, b, len) == 0;
}

/* 결과 파일 열기/닫기/삭제 */
static int init_result_file(void)
{
    result_file = fopen(TEST_RESULT_FILE, "w");
    if (!result_file) {
        fprintf(stderr, "결과 파일을 열 수 없습니다: %s\n", TEST_RESULT_FILE);
        return -1;
    }
    fprintf(result_file, "=== 암호화 알고리즘 테스트 결과 ===\n\n");
    return 0;
}

static void close_result_file(void)
{
    if (result_file) {
        fclose(result_file);
        result_file = NULL;
    }
}

static void delete_result_file(void)
{
    if (result_file) {
        fclose(result_file);
        result_file = NULL;
    }
    remove(TEST_RESULT_FILE);
}

/* 공통 테스트 로그 */
static void log_test_result(
    const char* test_name,
    int         test_num,
    const byte* key, size_t key_len,
    const byte* input, size_t input_len,
    const byte* output, size_t output_len,
    const byte* expected, size_t expected_len,
    int         passed)
{
    total_tests++;
    if (passed) passed_tests++;
    else        failed_tests++;

    if (!result_file) return;

    /* 여유있게 고정 버퍼 (필요시 늘려도 됨) */
    char key_hex[512] = { 0 };
    char input_hex[2048] = { 0 };
    char output_hex[2048] = { 0 };
    char expected_hex[2048] = { 0 };

    if (key && key_len)
        bytes_to_hex(key, key_len, key_hex, sizeof(key_hex));
    if (input && input_len)
        bytes_to_hex(input, input_len, input_hex, sizeof(input_hex));
    if (output && output_len)
        bytes_to_hex(output, output_len, output_hex, sizeof(output_hex));
    if (expected && expected_len)
        bytes_to_hex(expected, expected_len, expected_hex, sizeof(expected_hex));

    fprintf(result_file, "--- 테스트 #%d: %s ---\n", test_num, test_name);
    fprintf(result_file, "키: 0x%s\n", (key && key_len) ? key_hex : "");
    fprintf(result_file, "입력: 0x%s\n", (input && input_len) ? input_hex : "");
    fprintf(result_file, "출력: 0x%s\n", (output && output_len) ? output_hex : "");
    fprintf(result_file, "기대값: 0x%s\n", (expected && expected_len) ? expected_hex : "");
    fprintf(result_file, "결과: %s\n\n", passed ? "PASS" : "FAIL");
    fflush(result_file);
}

/* ============================================================
 * AES 래퍼 (CBC/CTR용)
 * ============================================================ */

typedef struct {
    const byte* key;
    int         key_len;
    AES_Impl    impl;
} aes_context_t;

static void aes_encrypt_wrapper(const byte* in, byte* out, const void* user_ctx)
{
    const aes_context_t* ctx = (const aes_context_t*)user_ctx;
    AES_encrypt_block(in, out, ctx->key, ctx->key_len, ctx->impl);
}

static void aes_decrypt_wrapper(const byte* in, byte* out, const void* user_ctx)
{
    const aes_context_t* ctx = (const aes_context_t*)user_ctx;
    AES_decrypt_block(in, out, ctx->key, ctx->key_len, ctx->impl);
}

/* ============================================================
 * 1. AES 블록 테스트 (ECB 스타일, NIST 벡터)
 * ============================================================ */

typedef struct {
    const char* name;
    const char* key_hex;
    const char* pt_hex;
    const char* ct_hex;
    int         key_len;   /* 바이트 */
} aes_block_vec_t;

/* FIPS 197 / SP 800-38A AES-128 예제 일부 */
static const aes_block_vec_t g_aes_block_vecs[] = {
    {
        "AES-128 Block #1",
        "2b7e151628aed2a6abf7158809cf4f3c",
        "6bc1bee22e409f96e93d7e117393172a",
        "3ad77bb40d7a3660a89ecaf32466ef97",
        16
    },
    {
        "AES-128 Block #2",
        "2b7e151628aed2a6abf7158809cf4f3c",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "f5d3d58503b9699de785895a96fdbaaf",
        16
    }
};

static int test_aes_block_one(
    const aes_block_vec_t* v,
    int                    test_idx,
    AES_Impl               impl)
{
    byte key[32];
    byte pt[AES_BLOCK_SIZE];
    byte ct_exp[AES_BLOCK_SIZE];
    byte ct[AES_BLOCK_SIZE];
    byte dec[AES_BLOCK_SIZE];

    hex_to_bytes(v->key_hex, key, v->key_len);
    hex_to_bytes(v->pt_hex, pt, AES_BLOCK_SIZE);
    hex_to_bytes(v->ct_hex, ct_exp, AES_BLOCK_SIZE);

    if (AES_encrypt_block(pt, ct, key, v->key_len, impl) != CRYPTO_OK) {
        fprintf(stderr, "AES_encrypt_block 실패 (%s)\n", v->name);
        return 0;
    }
    if (AES_decrypt_block(ct, dec, key, v->key_len, impl) != CRYPTO_OK) {
        fprintf(stderr, "AES_decrypt_block 실패 (%s)\n", v->name);
        return 0;
    }

    int ok = compare_bytes(ct, ct_exp, AES_BLOCK_SIZE) &&
        compare_bytes(dec, pt, AES_BLOCK_SIZE);

    char full_name[128];
    snprintf(full_name, sizeof(full_name), "%s (%s)",
        v->name,
        (impl == AES_IMPL_REF) ? "REF" : "TBL");

    log_test_result(full_name, test_idx,
        key, v->key_len,
        pt, AES_BLOCK_SIZE,
        ct, AES_BLOCK_SIZE,
        ct_exp, AES_BLOCK_SIZE,
        ok);
    return ok;
}

static int run_aes_block_tests(AES_Impl impl)
{
    int count = (int)(sizeof(g_aes_block_vecs) / sizeof(g_aes_block_vecs[0]));
    int all_ok = 1;

    printf("\n[AES Block / %s]\n",
        (impl == AES_IMPL_REF) ? "REF" : "TBL");

    for (int i = 0; i < count; i++) {
        if (!test_aes_block_one(&g_aes_block_vecs[i], i + 1, impl)) {
            all_ok = 0;
            printf("  ❌ %s 실패\n", g_aes_block_vecs[i].name);
        }
        else {
            printf("  ✅ %s 통과\n", g_aes_block_vecs[i].name);
        }
    }
    return all_ok;
}

/* ============================================================
 * 2. AES-CBC 테스트 (SP 800-38A F.2 128-bit 일부)
 * ============================================================ */

typedef struct {
    const char* name;
    const char* key_hex;
    const char* iv_hex;
    const char* pt_hex;
    const char* ct_hex;
    int         key_len;
    size_t      pt_len;
    size_t      ct_len;
} aes_cbc_vec_t;

/* 여기선 2블록짜리 예제 하나만 사용 */
static const aes_cbc_vec_t g_aes_cbc_vecs[] = {
    {
        "AES-128-CBC NIST F.2.1 (2 blocks)",
        "2b7e151628aed2a6abf7158809cf4f3c",
        "000102030405060708090a0b0c0d0e0f",
        /* PT: 2 blocks */
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51",
    /* CT: 2 blocks */
    "7649abac8119b246cee98e9b12e9197d"
    "5086cb9b507219ee95db113a917678b2",
    16, 32, 32
}
};

static int test_aes_cbc_one(
    const aes_cbc_vec_t* v,
    int                  test_idx,
    AES_Impl             impl)
{
    byte key[32];
    byte iv[AES_BLOCK_SIZE];
    byte pt[256];
    byte ct_exp[256];
    byte ct[256];
    byte dec[256];

    if (v->pt_len > sizeof(pt) || v->ct_len > sizeof(ct)) {
        fprintf(stderr, "버퍼 부족 (CBC)\n");
        return 0;
    }

    hex_to_bytes(v->key_hex, key, v->key_len);
    hex_to_bytes(v->iv_hex, iv, AES_BLOCK_SIZE);
    hex_to_bytes(v->pt_hex, pt, v->pt_len);
    hex_to_bytes(v->ct_hex, ct_exp, v->ct_len);

    aes_context_t ctx = { key, v->key_len, impl };
    int out_len = (int)v->ct_len;

    if (CBC_encrypt(aes_encrypt_wrapper, AES_BLOCK_SIZE, iv,
        CBC_PADDING_PKCS7,
        pt, (int)v->pt_len,
        ct, &out_len,
        &ctx) != CRYPTO_OK) {
        fprintf(stderr, "CBC_encrypt 실패 (%s)\n", v->name);
        return 0;
    }

    if ((size_t)out_len != v->ct_len) {
        fprintf(stderr, "CBC 암호문 길이 불일치 (%s)\n", v->name);
        return 0;
    }

    /* 복호화할 때는 IV 다시 사용해야 하므로 재로딩 */
    hex_to_bytes(v->iv_hex, iv, AES_BLOCK_SIZE);
    int dec_len = (int)v->pt_len;

    if (CBC_decrypt(aes_decrypt_wrapper, AES_BLOCK_SIZE, iv,
        CBC_PADDING_PKCS7,
        ct, out_len,
        dec, &dec_len,
        &ctx) != CRYPTO_OK) {
        fprintf(stderr, "CBC_decrypt 실패 (%s)\n", v->name);
        return 0;
    }

    int ok = (dec_len == (int)v->pt_len) &&
        compare_bytes(ct, ct_exp, v->ct_len) &&
        compare_bytes(dec, pt, v->pt_len);

    char full_name[128];
    snprintf(full_name, sizeof(full_name), "%s (%s)",
        v->name,
        (impl == AES_IMPL_REF) ? "REF" : "TBL");

    log_test_result(full_name, test_idx,
        key, v->key_len,
        pt, v->pt_len,
        ct, v->ct_len,
        ct_exp, v->ct_len,
        ok);
    return ok;
}

static int run_aes_cbc_tests(AES_Impl impl)
{
    int count = (int)(sizeof(g_aes_cbc_vecs) / sizeof(g_aes_cbc_vecs[0]));
    int all_ok = 1;

    printf("\n[AES-CBC / %s]\n",
        (impl == AES_IMPL_REF) ? "REF" : "TBL");

    for (int i = 0; i < count; i++) {
        if (!test_aes_cbc_one(&g_aes_cbc_vecs[i], i + 1, impl)) {
            all_ok = 0;
            printf("  ❌ %s 실패\n", g_aes_cbc_vecs[i].name);
        }
        else {
            printf("  ✅ %s 통과\n", g_aes_cbc_vecs[i].name);
        }
    }
    return all_ok;
}

/* ============================================================
 * 3. AES-CTR 테스트 (SP 800-38A F.5 128-bit 일부)
 * ============================================================ */

typedef struct {
    const char* name;
    const char* key_hex;
    const char* nonce_hex;    /* 초기 counter 블록 */
    const char* pt_hex;
    const char* ct_hex;
    int         key_len;
    size_t      pt_len;
} aes_ctr_vec_t;

/* 1블록짜리 예제 */
static const aes_ctr_vec_t g_aes_ctr_vecs[] = {
    {
        "AES-128-CTR NIST F.5.1 (1 block)",
        "2b7e151628aed2a6abf7158809cf4f3c",
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "6bc1bee22e409f96e93d7e117393172a",
        "874d6191b620e3261bef6864990db6ce",
        16, 16
    }
};

static int test_aes_ctr_one(
    const aes_ctr_vec_t* v,
    int                  test_idx,
    AES_Impl             impl)
{
    byte key[32];
    byte nonce[AES_BLOCK_SIZE];
    byte pt[256];
    byte ct_exp[256];
    byte ct[256];
    byte dec[256];

    if (v->pt_len > sizeof(pt)) {
        fprintf(stderr, "버퍼 부족 (CTR)\n");
        return 0;
    }

    hex_to_bytes(v->key_hex, key, v->key_len);
    hex_to_bytes(v->nonce_hex, nonce, AES_BLOCK_SIZE);
    hex_to_bytes(v->pt_hex, pt, v->pt_len);
    hex_to_bytes(v->ct_hex, ct_exp, v->pt_len);

    aes_context_t ctx = { key, v->key_len, impl };

    /* 암호화 */
    byte nonce_enc[AES_BLOCK_SIZE];
    memcpy(nonce_enc, nonce, AES_BLOCK_SIZE);

    if (CTR_crypt(aes_encrypt_wrapper, AES_BLOCK_SIZE,
        nonce_enc,
        pt, (int)v->pt_len,
        ct, &ctx) != CRYPTO_OK) {
        fprintf(stderr, "CTR_crypt(암호화) 실패 (%s)\n", v->name);
        return 0;
    }

    /* 복호화 (CTR은 같은 함수 재사용) */
    byte nonce_dec[AES_BLOCK_SIZE];
    memcpy(nonce_dec, nonce, AES_BLOCK_SIZE);

    if (CTR_crypt(aes_encrypt_wrapper, AES_BLOCK_SIZE,
        nonce_dec,
        ct, (int)v->pt_len,
        dec, &ctx) != CRYPTO_OK) {
        fprintf(stderr, "CTR_crypt(복호화) 실패 (%s)\n", v->name);
        return 0;
    }

    int ok = compare_bytes(ct, ct_exp, v->pt_len) &&
        compare_bytes(dec, pt, v->pt_len);

    char full_name[128];
    snprintf(full_name, sizeof(full_name), "%s (%s)",
        v->name,
        (impl == AES_IMPL_REF) ? "REF" : "TBL");

    log_test_result(full_name, test_idx,
        key, v->key_len,
        pt, v->pt_len,
        ct, v->pt_len,
        ct_exp, v->pt_len,
        ok);
    return ok;
}

static int run_aes_ctr_tests(AES_Impl impl)
{
    int count = (int)(sizeof(g_aes_ctr_vecs) / sizeof(g_aes_ctr_vecs[0]));
    int all_ok = 1;

    printf("\n[AES-CTR / %s]\n",
        (impl == AES_IMPL_REF) ? "REF" : "TBL");

    for (int i = 0; i < count; i++) {
        if (!test_aes_ctr_one(&g_aes_ctr_vecs[i], i + 1, impl)) {
            all_ok = 0;
            printf("  ❌ %s 실패\n", g_aes_ctr_vecs[i].name);
        }
        else {
            printf("  ✅ %s 통과\n", g_aes_ctr_vecs[i].name);
        }
    }
    return all_ok;
}

/* ============================================================
 * 4. SHA-512 테스트 (FIPS 180-4 표준 벡터)
 *   - input: "" (빈 문자열)
 *   - input: "abc"
 * ============================================================ */

typedef struct {
    const char* name;
    const char* msg_hex;   /* 메시지 바이트를 hex로 표현 */
    size_t      msg_len;   /* 바이트 단위 길이 */
    const char* digest_hex;
} sha512_vec_t;

static const sha512_vec_t g_sha512_vecs[] = {
    {
        "SHA-512(\"\")",
        "", 0,
        /* empty string */
        "cf83e1357eefb8bdf1542850d66d8007"
        "d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f"
        "63b931bd47417a81a538327af927da3e"
    },
    {
        "SHA-512(\"abc\")",
        "616263", 3,
        "ddaf35a193617abacc417349ae204131"
        "12e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd"
        "454d4423643ce80e2a9ac94fa54ca49f"
    }
};

static int test_sha512_one(const sha512_vec_t* v, int test_idx)
{
    byte msg[1024];
    byte digest[SHA512_DIGEST_SIZE];
    byte digest_exp[SHA512_DIGEST_SIZE];

    if (v->msg_len > 0)
        hex_to_bytes(v->msg_hex, msg, v->msg_len);

    hex_to_bytes(v->digest_hex, digest_exp, SHA512_DIGEST_SIZE);

    SHA512_hash((v->msg_len ? msg : (const byte*)""), v->msg_len, digest);

    int ok = compare_bytes(digest, digest_exp, SHA512_DIGEST_SIZE);

    /* SHA는 키 없음 -> 빈 키 */
    byte empty_key[1] = { 0 };

    log_test_result(v->name, test_idx,
        empty_key, 0,
        v->msg_len ? msg : (const byte*)"", v->msg_len,
        digest, SHA512_DIGEST_SIZE,
        digest_exp, SHA512_DIGEST_SIZE,
        ok);
    if (!ok) {
        printf("  ❌ %s 실패\n", v->name);
    }
    else {
        printf("  ✅ %s 통과\n", v->name);
    }
    return ok;
}

static int run_sha512_tests(void)
{
    printf("\n[SHA-512 테스트]\n");
    int count = (int)(sizeof(g_sha512_vecs) / sizeof(g_sha512_vecs[0]));
    int all_ok = 1;

    for (int i = 0; i < count; i++) {
        if (!test_sha512_one(&g_sha512_vecs[i], i + 1))
            all_ok = 0;
    }
    return all_ok;
}

/* ============================================================
 * 5. HMAC-SHA-512 테스트 (RFC 4231 Test Case 1,2)
 * ============================================================ */

typedef struct {
    const char* name;
    const char* key_hex;
    size_t      key_len;
    const char* data_hex;
    size_t      data_len;
    const char* mac_hex;
} hmac_vec_t;

/* RFC 4231 공식 벡터 (Test Case 1,2) */
static const hmac_vec_t g_hmac_vecs[] = {
    {
        "HMAC-SHA-512 TC1 (Hi There)",
        /* Key = 0x0b * 20 */
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        "0b0b0b0b",
        20,
    /* "Hi There" */
    "4869205468657265",
    8,
    /* 87aa7cde...6854 */
    "87aa7cdea5ef619d4ff0b4241a1d6cb0"
    "2379f4e2ce4ec2787ad0b30545e17cde"
    "daa833b7d6b8a702038b274eaea3f4e4"
    "be9d914eeb61f1702e696c203a126854"
},
{
    "HMAC-SHA-512 TC2 (Jefe, \"what do ya want...\")",
    /* "Jefe" */
    "4a656665",
    4,
    /* "what do ya want for nothing?" */
    "7768617420646f2079612077616e7420"
    "666f72206e6f7468696e673f",
    28,
    /* 164b7a7b...e737 */
    "164b7a7bfcf819e2e395fbe73b56e0a3"
    "87bd64222e831fd610270cd7ea250554"
    "9758bf75c05a994a6d034f65f8f0e6fd"
    "caeab1a34d4a6b4b636e070a38bce737"
}
};

static int test_hmac_sha512_one(const hmac_vec_t* v, int test_idx)
{
    byte key[256];
    byte data[512];
    byte mac[SHA512_DIGEST_SIZE];
    byte mac_exp[SHA512_DIGEST_SIZE];

    if (v->key_len > sizeof(key) || v->data_len > sizeof(data)) {
        fprintf(stderr, "버퍼 부족 (HMAC)\n");
        return 0;
    }

    hex_to_bytes(v->key_hex, key, v->key_len);
    hex_to_bytes(v->data_hex, data, v->data_len);
    hex_to_bytes(v->mac_hex, mac_exp, SHA512_DIGEST_SIZE);

    if (Mac(NULL, 0, key, v->key_len,
        SHA512_DIGEST_SIZE,
        data, v->data_len,
        mac) != 0) {
        fprintf(stderr, "Mac() 실패 (%s)\n", v->name);
        return 0;
    }

    int ok = compare_bytes(mac, mac_exp, SHA512_DIGEST_SIZE);
    if (!ok) {
        printf("  ❌ %s 실패\n", v->name);
        printf("     계산값: ");
        for (int i = 0; i < SHA512_DIGEST_SIZE; i++) {
            printf("%02x", mac[i]);
        }
        printf("\n     기대값: ");
        for (int i = 0; i < SHA512_DIGEST_SIZE; i++) {
            printf("%02x", mac_exp[i]);
        }
        printf("\n");
    }
    else {
        printf("  ✅ %s 통과\n", v->name);
    }

    log_test_result(v->name, test_idx,
        key, v->key_len,
        data, v->data_len,
        mac, SHA512_DIGEST_SIZE,
        mac_exp, SHA512_DIGEST_SIZE,
        ok);
    return ok;
}

static int run_hmac_sha512_tests(void)
{
    printf("\n[HMAC-SHA-512 테스트]\n");
    int count = (int)(sizeof(g_hmac_vecs) / sizeof(g_hmac_vecs[0]));
    int all_ok = 1;
    for (int i = 0; i < count; i++) {
        if (!test_hmac_sha512_one(&g_hmac_vecs[i], i + 1))
            all_ok = 0;
    }
    return all_ok;
}

/* ============================================================
 * 메뉴 & main
 * ============================================================ */

static void print_menu(void)
{
    printf("\n=== 암호화 알고리즘 테스트 스위트 ===\n");
    printf("1. AES 단일 블록 테스트 (Reference)\n");
    printf("2. AES 단일 블록 테스트 (T-table)\n");
    printf("3. AES-CBC 테스트 (Reference)\n");
    printf("4. AES-CBC 테스트 (T-table)\n");
    printf("5. AES-CTR 테스트 (Reference)\n");
    printf("6. AES-CTR 테스트 (T-table)\n");
    printf("7. SHA2-512 테스트\n");
    printf("8. HMAC-SHA2-512 테스트\n");
    printf("0. 종료\n");
    printf("선택: ");
}

int main(void)
{
    if (init_result_file() != 0) {
        return 1;
    }

    int all_passed = 1;

    while (1) {
        int choice;
        print_menu();

        if (scanf("%d", &choice) != 1) {
            printf("잘못된 입력입니다.\n");
            while (getchar() != '\n') { /* flush */ }
            continue;
        }

        if (choice == 0)
            break;

        int ok = 1;
        switch (choice) {
        case 1: ok = run_aes_block_tests(AES_IMPL_REF);  break;
        case 2: ok = run_aes_block_tests(AES_IMPL_TBL);  break;
        case 3: ok = run_aes_cbc_tests(AES_IMPL_REF);    break;
        case 4: ok = run_aes_cbc_tests(AES_IMPL_TBL);    break;
        case 5: ok = run_aes_ctr_tests(AES_IMPL_REF);    break;
        case 6: ok = run_aes_ctr_tests(AES_IMPL_TBL);    break;
        case 7: ok = run_sha512_tests();                 break;
        case 8: ok = run_hmac_sha512_tests();            break;
        default:
            printf("잘못된 선택입니다.\n");
            continue;
        }

        if (!ok) all_passed = 0;
    }

    close_result_file();

    if (all_passed && failed_tests == 0) {
        printf("\n=== 전체 테스트 통과 ===\n");
        printf("총 테스트: %d, 통과: %d, 실패: %d\n",
            total_tests, passed_tests, failed_tests);
        printf("결과 파일: %s\n", TEST_RESULT_FILE);
    }
    else {
        printf("\n=== 테스트 실패 발생 ===\n");
        printf("총 테스트: %d, 통과: %d, 실패: %d\n",
            total_tests, passed_tests, failed_tests);
        /* 실패하면 결과 파일 삭제할지 말지는 네 취향 */
        // delete_result_file();
    }

    return (all_passed && failed_tests == 0) ? 0 : 1;
}
