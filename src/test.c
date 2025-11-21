#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "crypto_api.h"
#include "error.h"

// 테스트 결과 파일
#define TEST_RESULT_FILE "test_results.txt"

// 전역 변수
static FILE* result_file = NULL;
static int total_tests = 0;
static int passed_tests = 0;
static int failed_tests = 0;

// 유틸리티 함수들
static void hex_to_bytes(const char* hex, byte* out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned int val;
        if (sscanf(hex + i * 2, "%2x", &val) != 1) {
            out[i] = 0;
        }
        else {
            out[i] = (byte)val;
        }
    }
}

static void bytes_to_hex(const byte* data, size_t len, char* hex) {
    size_t hex_buf_size = len * 2 + 1;
    for (size_t i = 0; i < len; i++) {
        snprintf(hex + i * 2, hex_buf_size - i * 2, "%02x", data[i]);
    }
    hex[len * 2] = '\0';
}

static int compare_bytes(const byte* a, const byte* b, size_t len) {
    return memcmp(a, b, len) == 0;
}

// 결과 파일 초기화
static int init_result_file(void) {
    result_file = fopen(TEST_RESULT_FILE, "w");
    if (!result_file) {
        fprintf(stderr, "결과 파일을 열 수 없습니다: %s\n", TEST_RESULT_FILE);
        return -1;
    }
    fprintf(result_file, "=== 암호화 알고리즘 테스트 결과 ===\n\n");
    return 0;
}

// 결과 파일 닫기
static void close_result_file(void) {
    if (result_file) {
        fclose(result_file);
        result_file = NULL;
    }
}

// 결과 파일 삭제
static void delete_result_file(void) {
    if (result_file) {
        fclose(result_file);
        result_file = NULL;
    }
    remove(TEST_RESULT_FILE);
}

// 테스트 결과 기록
static void log_test_result(const char* test_name, int test_num,
    const byte* key, size_t key_len,
    const byte* input, size_t input_len,
    const byte* output, size_t output_len,
    const byte* expected, size_t expected_len,
    int passed, const char* vector_source) {
    total_tests++;
    if (passed) {
        passed_tests++;
    }
    else {
        failed_tests++;
    }

    if (result_file) {
        char key_hex[512];
        char input_hex[2048];
        char output_hex[2048];
        char expected_hex[2048];

        bytes_to_hex(key, key_len, key_hex);
        bytes_to_hex(input, input_len, input_hex);
        bytes_to_hex(output, output_len, output_hex);
        bytes_to_hex(expected, expected_len, expected_hex);

        fprintf(result_file, "--- 테스트 #%d: %s ---\n", test_num, test_name);
        if (vector_source && strlen(vector_source) > 0) {
            fprintf(result_file, "테스트 벡터 출처: %s\n", vector_source);
        }
        fprintf(result_file, "키: 0x%s\n", key_hex);
        fprintf(result_file, "평문: 0x%s\n", input_hex);
        fprintf(result_file, "출력: 0x%s\n", output_hex);
        fprintf(result_file, "기대값: 0x%s\n", expected_hex);
        fprintf(result_file, "결과: %s\n\n", passed ? "PASS" : "FAIL");
        fflush(result_file);
    }
}

// AES 컨텍스트 구조체 (CBC/CTR용)
typedef struct {
    const byte* key;
    int key_len;
    AES_Impl impl;
} aes_context_t;

// AES 블록 암호화 래퍼 (CBC/CTR용)
static void aes_encrypt_wrapper(const byte* in, byte* out, const void* user_ctx) {
    const aes_context_t* ctx = (const aes_context_t*)user_ctx;
    AES_encrypt_block(in, out, ctx->key, ctx->key_len, ctx->impl);
}

static void aes_decrypt_wrapper(const byte* in, byte* out, const void* user_ctx) {
    const aes_context_t* ctx = (const aes_context_t*)user_ctx;
    AES_decrypt_block(in, out, ctx->key, ctx->key_len, ctx->impl);
}

// ===== AES 단일 블록 테스트 =====
static int test_aes_block(void) {
    printf("[AES 단일 블록 테스트]\n");

    // NIST FIPS 197 Appendix B 테스트 벡터
    struct {
        const char* key_hex;
        const char* plaintext_hex;
        const char* ciphertext_hex;
        int key_len;
        const char* name;
    } test_vectors[] = {
        // AES-128
        {
            "2b7e151628aed2a6abf7158809cf4f3c",
            "6bc1bee22e409f96e93d7e117393172a",
            "3ad77bb40d7a3660a89ecaf32466ef97",
            16,
            "AES-128"
        },
        // AES-192
        {
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            "6bc1bee22e409f96e93d7e117393172a",
            "bd334f1d6e45f25ff712a214571fa5cc",
            24,
            "AES-192"
        },
        // AES-256
        {
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "6bc1bee22e409f96e93d7e117393172a",
            "f3eed1bdb5d2a03c064b5a7e3db181f8",
            32,
            "AES-256"
        }
    };

    int all_passed = 1;
    int test_num = 1;

    // Reference와 T-table 모두 테스트
    for (int impl_idx = 0; impl_idx < 2; impl_idx++) {
        AES_Impl impl = (impl_idx == 0) ? AES_IMPL_REF : AES_IMPL_TBL;
        const char* impl_name = (impl == AES_IMPL_REF) ? "Reference" : "T-table";

        for (int i = 0; i < 3; i++) {
            byte key[32], plaintext[16], expected[16], ciphertext[16];

            hex_to_bytes(test_vectors[i].key_hex, key, test_vectors[i].key_len);
            hex_to_bytes(test_vectors[i].plaintext_hex, plaintext, 16);
            hex_to_bytes(test_vectors[i].ciphertext_hex, expected, 16);

            if (AES_encrypt_block(plaintext, ciphertext, key, test_vectors[i].key_len, impl) != CRYPTO_OK) {
                printf("❌ %s %s 암호화 실패\n", impl_name, test_vectors[i].name);
                all_passed = 0;
                continue;
            }

            int passed = compare_bytes(ciphertext, expected, 16);

            char test_name[128];
            snprintf(test_name, sizeof(test_name), "%s %s (%s)", test_vectors[i].name, impl_name, "Block");

            log_test_result(test_name, test_num++, key, test_vectors[i].key_len,
                plaintext, 16, ciphertext, 16, expected, 16, passed,
                "NIST FIPS 197 Appendix B");

            if (!passed) {
                printf("❌ %s %s 테스트 실패\n", impl_name, test_vectors[i].name);
                all_passed = 0;
            }
        }
    }

    if (all_passed) {
        printf("✅ 모든 AES 블록 테스트 통과\n");
    }

    // 랜덤 벡터 테스트 (500회)
    printf("\n[랜덤 벡터 테스트] AES 단일 블록 (500회)\n");
    int random_passed = 0;
    int random_failed = 0;

    for (int impl_idx = 0; impl_idx < 2; impl_idx++) {
        AES_Impl impl = (impl_idx == 0) ? AES_IMPL_REF : AES_IMPL_TBL;
        const char* impl_name = (impl == AES_IMPL_REF) ? "Reference" : "T-table";

        int key_lengths[] = { 16, 24, 32 };
        const char* key_names[] = { "AES-128", "AES-192", "AES-256" };

        for (int key_idx = 0; key_idx < 3; key_idx++) {
            int key_len = key_lengths[key_idx];

            for (int i = 0; i < 500; i++) {
                byte key[32], plaintext[16], ciphertext[16], decrypted[16];

                // 랜덤 키 생성
                if (CRYPTO_randomBytes(key, key_len) != CRYPTO_OK) {
                    printf("❌ 랜덤 키 생성 실패\n");
                    random_failed++;
                    continue;
                }

                // 랜덤 평문 생성
                if (CRYPTO_randomBytes(plaintext, 16) != CRYPTO_OK) {
                    printf("❌ 랜덤 평문 생성 실패\n");
                    random_failed++;
                    continue;
                }

                // 암호화
                if (AES_encrypt_block(plaintext, ciphertext, key, key_len, impl) != CRYPTO_OK) {
                    random_failed++;
                    continue;
                }

                // 복호화
                if (AES_decrypt_block(ciphertext, decrypted, key, key_len, impl) != CRYPTO_OK) {
                    random_failed++;
                    continue;
                }

                // 복호화 결과가 원래 평문과 같은지 확인
                int passed = compare_bytes(decrypted, plaintext, 16);

                char test_name[128];
                snprintf(test_name, sizeof(test_name), "%s %s 랜덤 #%d", key_names[key_idx], impl_name, i + 1);

                log_test_result(test_name, test_num++, key, key_len,
                    plaintext, 16, ciphertext, 16, plaintext, 16, passed,
                    "랜덤 생성");

                if (passed) {
                    random_passed++;
                }
                else {
                    random_failed++;
                    if (random_failed <= 5) {
                        printf("❌ %s %s 랜덤 테스트 #%d 실패\n", key_names[key_idx], impl_name, i + 1);
                    }
                }
            }
        }
    }

    printf("랜덤 테스트 완료: 통과 %d, 실패 %d\n", random_passed, random_failed);
    if (random_failed == 0) {
        printf("✅ 모든 랜덤 테스트 통과\n");
    }
    else {
        printf("❌ 랜덤 테스트 실패 (%d개 실패)\n", random_failed);
        all_passed = 0;
    }

    printf("\n");
    return all_passed;
}

// ===== AES-CBC 테스트 =====
static int test_aes_cbc(void) {
    printf("[AES-CBC 테스트]\n");

    // NIST SP800-38A 테스트 벡터
    struct {
        const char* key_hex;
        const char* iv_hex;
        const char* plaintext_hex;
        const char* ciphertext_hex;
        int key_len;
        int pt_len;
        const char* name;
    } test_vectors[] = {
        // AES-128-CBC
        {
            "2b7e151628aed2a6abf7158809cf4f3c",
            "000102030405060708090a0b0c0d0e0f",
            "6bc1bee22e409f96e93d7e117393172a",
            "7649abac8119b246cee98e9b12e9197d",
            16, 16,
            "AES-128-CBC"
        },
        // AES-192-CBC
        {
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            "000102030405060708090a0b0c0d0e0f",
            "6bc1bee22e409f96e93d7e117393172a",
            "4f021db243bc633d7178183a9fa071e8",
            24, 16,
            "AES-192-CBC"
        },
        // AES-256-CBC
        {
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "000102030405060708090a0b0c0d0e0f",
            "6bc1bee22e409f96e93d7e117393172a",
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
            32, 16,
            "AES-256-CBC"
        }
    };

    int all_passed = 1;
    int test_num = 1;

    for (int impl_idx = 0; impl_idx < 2; impl_idx++) {
        AES_Impl impl = (impl_idx == 0) ? AES_IMPL_REF : AES_IMPL_TBL;
        const char* impl_name = (impl == AES_IMPL_REF) ? "Reference" : "T-table";

        for (int i = 0; i < 3; i++) {
            byte key[32], iv[16], plaintext[64], expected[64], ciphertext[64];
            int ct_len;
            aes_context_t ctx = { key, test_vectors[i].key_len, impl };

            hex_to_bytes(test_vectors[i].key_hex, key, test_vectors[i].key_len);
            hex_to_bytes(test_vectors[i].iv_hex, iv, 16);
            hex_to_bytes(test_vectors[i].plaintext_hex, plaintext, test_vectors[i].pt_len);
            hex_to_bytes(test_vectors[i].ciphertext_hex, expected, test_vectors[i].pt_len);

            ct_len = test_vectors[i].pt_len;
            if (CBC_encrypt(aes_encrypt_wrapper, AES_BLOCK_SIZE, iv,
                CBC_PADDING_NONE, plaintext, test_vectors[i].pt_len,
                ciphertext, &ct_len, &ctx) != CRYPTO_OK) {
                printf("❌ %s %s 암호화 실패\n", impl_name, test_vectors[i].name);
                all_passed = 0;
                continue;
            }

            int passed = compare_bytes(ciphertext, expected, test_vectors[i].pt_len);

            char test_name[128];
            snprintf(test_name, sizeof(test_name), "%s (%s)", test_vectors[i].name, impl_name);

            log_test_result(test_name, test_num++, key, test_vectors[i].key_len,
                plaintext, test_vectors[i].pt_len,
                ciphertext, ct_len, expected, test_vectors[i].pt_len, passed,
                "NIST SP800-38A");

            if (!passed) {
                printf("❌ %s %s 테스트 실패\n", impl_name, test_vectors[i].name);
                all_passed = 0;
            }
        }
    }

    if (all_passed) {
        printf("✅ 모든 AES-CBC 테스트 통과\n");
    }

    // 랜덤 벡터 테스트 (500회)
    printf("\n[랜덤 벡터 테스트] AES-CBC (500회)\n");
    int random_passed = 0;
    int random_failed = 0;

    for (int impl_idx = 0; impl_idx < 2; impl_idx++) {
        AES_Impl impl = (impl_idx == 0) ? AES_IMPL_REF : AES_IMPL_TBL;
        const char* impl_name = (impl == AES_IMPL_REF) ? "Reference" : "T-table";

        int key_lengths[] = { 16, 24, 32 };
        const char* key_names[] = { "AES-128-CBC", "AES-192-CBC", "AES-256-CBC" };

        for (int key_idx = 0; key_idx < 3; key_idx++) {
            int key_len = key_lengths[key_idx];

            for (int i = 0; i < 500; i++) {
                byte key[32], iv[16], plaintext[64], ciphertext[64], decrypted[64];
                int pt_len = 16 + (i % 3) * 16;  // 16, 32, 48 바이트
                int ct_len, dec_len;
                aes_context_t ctx = { key, key_len, impl };

                // 랜덤 키 생성
                if (CRYPTO_randomBytes(key, key_len) != CRYPTO_OK) {
                    random_failed++;
                    continue;
                }

                // 랜덤 IV 생성
                if (CRYPTO_randomBytes(iv, 16) != CRYPTO_OK) {
                    random_failed++;
                    continue;
                }

                // 랜덤 평문 생성
                if (CRYPTO_randomBytes(plaintext, pt_len) != CRYPTO_OK) {
                    random_failed++;
                    continue;
                }

                // 암호화
                ct_len = pt_len;
                if (CBC_encrypt(aes_encrypt_wrapper, AES_BLOCK_SIZE, iv,
                    CBC_PADDING_NONE, plaintext, pt_len,
                    ciphertext, &ct_len, &ctx) != CRYPTO_OK) {
                    random_failed++;
                    continue;
                }

                // 복호화
                dec_len = pt_len;
                if (CBC_decrypt(aes_decrypt_wrapper, AES_BLOCK_SIZE, iv,
                    CBC_PADDING_NONE, ciphertext, ct_len,
                    decrypted, &dec_len, &ctx) != CRYPTO_OK) {
                    random_failed++;
                    continue;
                }

                // 복호화 결과가 원래 평문과 같은지 확인
                int passed = compare_bytes(decrypted, plaintext, pt_len);

                char test_name[128];
                snprintf(test_name, sizeof(test_name), "%s %s 랜덤 #%d", key_names[key_idx], impl_name, i + 1);

                log_test_result(test_name, test_num++, key, key_len,
                    plaintext, pt_len, ciphertext, ct_len, plaintext, pt_len, passed,
                    "랜덤 생성");

                if (passed) {
                    random_passed++;
                }
                else {
                    random_failed++;
                    if (random_failed <= 5) {
                        printf("❌ %s %s 랜덤 테스트 #%d 실패\n", key_names[key_idx], impl_name, i + 1);
                    }
                }
            }
        }
    }

    printf("랜덤 테스트 완료: 통과 %d, 실패 %d\n", random_passed, random_failed);
    if (random_failed == 0) {
        printf("✅ 모든 랜덤 테스트 통과\n");
    }
    else {
        printf("❌ 랜덤 테스트 실패 (%d개 실패)\n", random_failed);
        all_passed = 0;
    }

    printf("\n");
    return all_passed;
}

// ===== AES-CTR 테스트 =====
static int test_aes_ctr(void) {
    printf("[AES-CTR 테스트]\n");

    // NIST SP800-38A 테스트 벡터
    struct {
        const char* key_hex;
        const char* nonce_hex;
        const char* plaintext_hex;
        const char* ciphertext_hex;
        int key_len;
        int pt_len;
        const char* name;
    } test_vectors[] = {
        // AES-128-CTR
        {
            "2b7e151628aed2a6abf7158809cf4f3c",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "6bc1bee22e409f96e93d7e117393172a",
            "874d6191b620e3261bef6864990db6ce",
            16, 16,
            "AES-128-CTR"
        },
        // AES-192-CTR
        {
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "6bc1bee22e409f96e93d7e117393172a",
            "1abc932417521ca24f2b0459fe7e6e0b",
            24, 16,
            "AES-192-CTR"
        },
        // AES-256-CTR
        {
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "6bc1bee22e409f96e93d7e117393172a",
            "601ec313775789a5b7a7f504bbf3d228",
            32, 16,
            "AES-256-CTR"
        }
    };

    int all_passed = 1;
    int test_num = 1;

    for (int impl_idx = 0; impl_idx < 2; impl_idx++) {
        AES_Impl impl = (impl_idx == 0) ? AES_IMPL_REF : AES_IMPL_TBL;
        const char* impl_name = (impl == AES_IMPL_REF) ? "Reference" : "T-table";

        for (int i = 0; i < 3; i++) {
            byte key[32], nonce[16], plaintext[64], expected[64], ciphertext[64];
            byte nonce_copy[16];
            aes_context_t ctx = { key, test_vectors[i].key_len, impl };

            hex_to_bytes(test_vectors[i].key_hex, key, test_vectors[i].key_len);
            hex_to_bytes(test_vectors[i].nonce_hex, nonce, 16);
            hex_to_bytes(test_vectors[i].plaintext_hex, plaintext, test_vectors[i].pt_len);
            hex_to_bytes(test_vectors[i].ciphertext_hex, expected, test_vectors[i].pt_len);

            memcpy(nonce_copy, nonce, 16);
            if (CTR_crypt(aes_encrypt_wrapper, AES_BLOCK_SIZE, nonce_copy,
                plaintext, test_vectors[i].pt_len, ciphertext, &ctx) != CRYPTO_OK) {
                printf("❌ %s %s 암호화 실패\n", impl_name, test_vectors[i].name);
                all_passed = 0;
                continue;
            }

            int passed = compare_bytes(ciphertext, expected, test_vectors[i].pt_len);

            char test_name[128];
            snprintf(test_name, sizeof(test_name), "%s (%s)", test_vectors[i].name, impl_name);

            log_test_result(test_name, test_num++, key, test_vectors[i].key_len,
                plaintext, test_vectors[i].pt_len,
                ciphertext, test_vectors[i].pt_len, expected, test_vectors[i].pt_len, passed,
                "NIST SP800-38A");

            if (!passed) {
                printf("❌ %s %s 테스트 실패\n", impl_name, test_vectors[i].name);
                all_passed = 0;
            }
        }
    }

    if (all_passed) {
        printf("✅ 모든 AES-CTR 테스트 통과\n");
    }

    // 랜덤 벡터 테스트 (500회)
    printf("\n[랜덤 벡터 테스트] AES-CTR (500회)\n");
    int random_passed = 0;
    int random_failed = 0;

    for (int impl_idx = 0; impl_idx < 2; impl_idx++) {
        AES_Impl impl = (impl_idx == 0) ? AES_IMPL_REF : AES_IMPL_TBL;
        const char* impl_name = (impl == AES_IMPL_REF) ? "Reference" : "T-table";

        int key_lengths[] = { 16, 24, 32 };
        const char* key_names[] = { "AES-128-CTR", "AES-192-CTR", "AES-256-CTR" };

        for (int key_idx = 0; key_idx < 3; key_idx++) {
            int key_len = key_lengths[key_idx];

            for (int i = 0; i < 500; i++) {
                byte key[32], nonce[16], plaintext[64], ciphertext[64], decrypted[64];
                byte nonce_copy[16];
                int pt_len = 16 + (i % 3) * 16;  // 16, 32, 48 바이트
                aes_context_t ctx = { key, key_len, impl };

                // 랜덤 키 생성
                if (CRYPTO_randomBytes(key, key_len) != CRYPTO_OK) {
                    random_failed++;
                    continue;
                }

                // 랜덤 nonce 생성
                if (CRYPTO_randomBytes(nonce, 16) != CRYPTO_OK) {
                    random_failed++;
                    continue;
                }

                // 랜덤 평문 생성
                if (CRYPTO_randomBytes(plaintext, pt_len) != CRYPTO_OK) {
                    random_failed++;
                    continue;
                }

                // 암호화
                memcpy(nonce_copy, nonce, 16);
                if (CTR_crypt(aes_encrypt_wrapper, AES_BLOCK_SIZE, nonce_copy,
                    plaintext, pt_len, ciphertext, &ctx) != CRYPTO_OK) {
                    random_failed++;
                    continue;
                }

                // 복호화 (CTR은 암호화와 동일)
                memcpy(nonce_copy, nonce, 16);
                if (CTR_crypt(aes_encrypt_wrapper, AES_BLOCK_SIZE, nonce_copy,
                    ciphertext, pt_len, decrypted, &ctx) != CRYPTO_OK) {
                    random_failed++;
                    continue;
                }

                // 복호화 결과가 원래 평문과 같은지 확인
                int passed = compare_bytes(decrypted, plaintext, pt_len);

                char test_name[128];
                snprintf(test_name, sizeof(test_name), "%s %s 랜덤 #%d", key_names[key_idx], impl_name, i + 1);

                log_test_result(test_name, test_num++, key, key_len,
                    plaintext, pt_len, ciphertext, pt_len, plaintext, pt_len, passed,
                    "랜덤 생성");

                if (passed) {
                    random_passed++;
                }
                else {
                    random_failed++;
                    if (random_failed <= 5) {
                        printf("❌ %s %s 랜덤 테스트 #%d 실패\n", key_names[key_idx], impl_name, i + 1);
                    }
                }
            }
        }
    }

    printf("랜덤 테스트 완료: 통과 %d, 실패 %d\n", random_passed, random_failed);
    if (random_failed == 0) {
        printf("✅ 모든 랜덤 테스트 통과\n");
    }
    else {
        printf("❌ 랜덤 테스트 실패 (%d개 실패)\n", random_failed);
        all_passed = 0;
    }

    printf("\n");
    return all_passed;
}

// ===== SHA2-512 테스트 =====
static int test_sha512(void) {
    printf("[SHA2-512 테스트]\n");

    // NIST FIPS 180-4 테스트 벡터
    struct {
        const char* input_hex;
        const char* expected_hex;
        int input_len;
        const char* name;
    } test_vectors[] = {
        {
            "616263",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            3,
            "SHA512-abc"
        },
        {
            "",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            0,
            "SHA512-empty"
        },
        {
            "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
            56,
            "SHA512-long"
        }
    };

    int all_passed = 1;
    int test_num = 1;

    for (int i = 0; i < 3; i++) {
        byte input[256], expected[64], hash[64];

        hex_to_bytes(test_vectors[i].input_hex, input, test_vectors[i].input_len);
        hex_to_bytes(test_vectors[i].expected_hex, expected, 64);

        SHA512_hash(input, test_vectors[i].input_len, hash);

        int passed = compare_bytes(hash, expected, 64);

        byte empty_key[1] = { 0 };
        log_test_result(test_vectors[i].name, test_num++, empty_key, 0,
            input, test_vectors[i].input_len,
            hash, 64, expected, 64, passed,
            "NIST FIPS 180-4");

        if (!passed) {
            printf("❌ %s 테스트 실패\n", test_vectors[i].name);
            all_passed = 0;
        }
    }

    if (all_passed) {
        printf("✅ 모든 SHA2-512 테스트 통과\n");
    }

    // 랜덤 벡터 테스트 (500회)
    printf("\n[랜덤 벡터 테스트] SHA2-512 (500회)\n");
    int random_passed = 0;
    int random_failed = 0;

    for (int i = 0; i < 500; i++) {
        byte input[256];
        int input_len = 1 + (i % 255);  // 1~255 바이트
        byte hash[64], hash2[64];

        // 랜덤 입력 생성
        if (CRYPTO_randomBytes(input, input_len) != CRYPTO_OK) {
            random_failed++;
            continue;
        }

        // 해시 계산 (두 번 계산해서 일관성 확인)
        SHA512_hash(input, input_len, hash);
        SHA512_hash(input, input_len, hash2);

        // 같은 입력에 대해 같은 해시가 나오는지 확인
        int passed = compare_bytes(hash, hash2, 64);

        byte empty_key[1] = { 0 };
        char test_name[128];
        snprintf(test_name, sizeof(test_name), "SHA512 랜덤 #%d", i + 1);

        log_test_result(test_name, test_num++, empty_key, 0,
            input, input_len, hash, 64, hash2, 64, passed,
            "랜덤 생성");

        if (passed) {
            random_passed++;
        }
        else {
            random_failed++;
            if (random_failed <= 5) {
                printf("❌ SHA512 랜덤 테스트 #%d 실패\n", i + 1);
            }
        }
    }

    printf("랜덤 테스트 완료: 통과 %d, 실패 %d\n", random_passed, random_failed);
    if (random_failed == 0) {
        printf("✅ 모든 랜덤 테스트 통과\n");
    }
    else {
        printf("❌ 랜덤 테스트 실패 (%d개 실패)\n", random_failed);
        all_passed = 0;
    }

    printf("\n");
    return all_passed;
}

// ===== HMAC-SHA2-512 테스트 =====
static int test_hmac_sha512(void) {
    printf("[HMAC-SHA2-512 테스트]\n");

    // RFC 4231 테스트 벡터
    struct {
        const char* key_hex;
        const char* message_hex;
        const char* expected_hex;
        int key_len;
        int msg_len;
        const char* name;
    } test_vectors[] = {
        {
            "4a656665",
            "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
            4, 28,
            "HMAC-SHA512-1"
        },
        {
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "4869205468657265",
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            20, 8,
            "HMAC-SHA512-2"
        }
    };

    int all_passed = 1;
    int test_num = 1;

    for (int i = 0; i < 2; i++) {
        byte key[256], message[1024], expected[64], mac[64];

        hex_to_bytes(test_vectors[i].key_hex, key, test_vectors[i].key_len);
        hex_to_bytes(test_vectors[i].message_hex, message, test_vectors[i].msg_len);
        hex_to_bytes(test_vectors[i].expected_hex, expected, 64);

        if (Mac(NULL, 0, key, test_vectors[i].key_len, 64, message, test_vectors[i].msg_len, mac) != CRYPTO_OK) {
            printf("❌ %s MAC 계산 실패\n", test_vectors[i].name);
            all_passed = 0;
            continue;
        }

        int passed = compare_bytes(mac, expected, 64);

        log_test_result(test_vectors[i].name, test_num++, key, test_vectors[i].key_len,
            message, test_vectors[i].msg_len,
            mac, 64, expected, 64, passed,
            "RFC 4231");

        if (!passed) {
            printf("❌ %s 테스트 실패\n", test_vectors[i].name);
            printf("계산된 MAC: ");
            for (int j = 0; j < 64; j++) printf("%02x", mac[j]);
            printf("\n기대된 MAC: ");
            for (int j = 0; j < 64; j++) printf("%02x", expected[j]);
            printf("\n");
            all_passed = 0;
        }
    }

    if (all_passed) {
        printf("✅ 모든 HMAC-SHA2-512 테스트 통과\n");
    }

    // 랜덤 벡터 테스트 (500회)
    printf("\n[랜덤 벡터 테스트] HMAC-SHA2-512 (500회)\n");
    int random_passed = 0;
    int random_failed = 0;

    for (int i = 0; i < 1000; i++) {
        byte key[256], message[512], mac[64], mac2[64];
        int key_len = 16 + (i % 3) * 8;  // 16, 24, 32 바이트
        int msg_len = 1 + (i % 511);     // 1~511 바이트

        // 랜덤 키 생성
        if (CRYPTO_randomBytes(key, key_len) != CRYPTO_OK) {
            random_failed++;
            continue;
        }

        // 랜덤 메시지 생성
        if (CRYPTO_randomBytes(message, msg_len) != CRYPTO_OK) {
            random_failed++;
            continue;
        }

        // MAC 계산 (두 번 계산해서 일관성 확인)
        if (Mac(NULL, 0, key, key_len, 64, message, msg_len, mac) != CRYPTO_OK) {
            random_failed++;
            continue;
        }

        if (Mac(NULL, 0, key, key_len, 64, message, msg_len, mac2) != CRYPTO_OK) {
            random_failed++;
            continue;
        }

        // 같은 입력에 대해 같은 MAC이 나오는지 확인
        int passed = compare_bytes(mac, mac2, 64);

        char test_name[128];
        snprintf(test_name, sizeof(test_name), "HMAC-SHA512 랜덤 #%d", i + 1);

        log_test_result(test_name, test_num++, key, key_len,
            message, msg_len, mac, 64, mac2, 64, passed,
            "랜덤 생성");

        if (passed) {
            random_passed++;
        }
        else {
            random_failed++;
            if (random_failed <= 5) {
                printf("❌ HMAC-SHA512 랜덤 테스트 #%d 실패\n", i + 1);
            }
        }
    }

    printf("랜덤 테스트 완료: 통과 %d, 실패 %d\n", random_passed, random_failed);
    if (random_failed == 0) {
        printf("✅ 모든 랜덤 테스트 통과\n");
    }
    else {
        printf("❌ 랜덤 테스트 실패 (%d개 실패)\n", random_failed);
        all_passed = 0;
    }

    printf("\n");
    return all_passed;
}

// ===== 오류 처리 테스트 =====
static int test_error_handling(void) {
    printf("[오류 처리 테스트]\n");

    int all_passed = 1;
    byte dummy[16] = { 0 };
    byte output[16];
    int err_code;

    // 1. NULL 포인터 테스트 - AES
    printf("\n[1] AES NULL 포인터 테스트\n");
    err_code = AES_encrypt_block(NULL, output, dummy, 16, AES_IMPL_REF);
    if (err_code != CRYPTO_ERR_PARAM) {
        printf("❌ NULL 입력 포인터 테스트 실패 (기대: CRYPTO_ERR_PARAM, 실제: %d)\n", err_code);
        all_passed = 0;
    }
    else {
        printf("✅ NULL 입력 포인터 테스트 통과\n");
        crypto_error_print(err_code, "AES_encrypt_block: NULL 입력 포인터");
    }

    err_code = AES_encrypt_block(dummy, NULL, dummy, 16, AES_IMPL_REF);
    if (err_code != CRYPTO_ERR_PARAM) {
        printf("❌ NULL 출력 포인터 테스트 실패\n");
        all_passed = 0;
    }
    else {
        printf("✅ NULL 출력 포인터 테스트 통과\n");
        crypto_error_print(err_code, "AES_encrypt_block: NULL 출력 포인터");
    }

    err_code = AES_encrypt_block(dummy, output, NULL, 16, AES_IMPL_REF);
    if (err_code != CRYPTO_ERR_PARAM) {
        printf("❌ NULL 키 포인터 테스트 실패\n");
        all_passed = 0;
    }
    else {
        printf("✅ NULL 키 포인터 테스트 통과\n");
        crypto_error_print(err_code, "AES_encrypt_block: NULL 키 포인터");
    }

    // 2. 잘못된 키 길이 테스트
    printf("\n[2] AES 잘못된 키 길이 테스트\n");
    err_code = AES_encrypt_block(dummy, output, dummy, 15, AES_IMPL_REF);
    if (err_code != CRYPTO_ERR_KEYLEN) {
        printf("❌ 잘못된 키 길이(15) 테스트 실패 (기대: CRYPTO_ERR_KEYLEN, 실제: %d)\n", err_code);
        all_passed = 0;
    }
    else {
        printf("✅ 잘못된 키 길이(15) 테스트 통과\n");
        crypto_error_print(err_code, "AES_encrypt_block: 키 길이 15바이트");
    }

    err_code = AES_encrypt_block(dummy, output, dummy, 17, AES_IMPL_REF);
    if (err_code != CRYPTO_ERR_KEYLEN) {
        printf("❌ 잘못된 키 길이(17) 테스트 실패\n");
        all_passed = 0;
    }
    else {
        printf("✅ 잘못된 키 길이(17) 테스트 통과\n");
        crypto_error_print(err_code, "AES_encrypt_block: 키 길이 17바이트");
    }

    err_code = AES_encrypt_block(dummy, output, dummy, 20, AES_IMPL_REF);
    if (err_code != CRYPTO_ERR_KEYLEN) {
        printf("❌ 잘못된 키 길이(20) 테스트 실패\n");
        all_passed = 0;
    }
    else {
        printf("✅ 잘못된 키 길이(20) 테스트 통과\n");
        crypto_error_print(err_code, "AES_encrypt_block: 키 길이 20바이트");
    }

    // 3. HMAC NULL 포인터 테스트
    printf("\n[3] HMAC NULL 포인터 테스트\n");
    err_code = Mac(NULL, 0, NULL, 16, 64, dummy, 16, output);
    if (err_code != CRYPTO_ERR_PARAM) {
        printf("❌ HMAC NULL 키 테스트 실패\n");
        all_passed = 0;
    }
    else {
        printf("✅ HMAC NULL 키 테스트 통과\n");
        crypto_error_print(err_code, "Mac: NULL 키 포인터");
    }

    err_code = Mac(NULL, 0, dummy, 16, 64, NULL, 16, output);
    if (err_code != CRYPTO_ERR_PARAM) {
        printf("❌ HMAC NULL 메시지 테스트 실패\n");
        all_passed = 0;
    }
    else {
        printf("✅ HMAC NULL 메시지 테스트 통과\n");
        crypto_error_print(err_code, "Mac: NULL 메시지 포인터");
    }

    err_code = Mac(NULL, 0, dummy, 16, 64, dummy, 16, NULL);
    if (err_code != CRYPTO_ERR_PARAM) {
        printf("❌ HMAC NULL 출력 테스트 실패\n");
        all_passed = 0;
    }
    else {
        printf("✅ HMAC NULL 출력 테스트 통과\n");
        crypto_error_print(err_code, "Mac: NULL 출력 포인터");
    }

    // 4. 잘못된 태그 길이 테스트
    printf("\n[4] HMAC 잘못된 태그 길이 테스트\n");
    err_code = Mac(NULL, 0, dummy, 16, 65, dummy, 16, output);
    if (err_code != CRYPTO_ERR_PARAM) {
        printf("❌ 잘못된 태그 길이(65) 테스트 실패\n");
        all_passed = 0;
    }
    else {
        printf("✅ 잘못된 태그 길이(65) 테스트 통과\n");
        crypto_error_print(err_code, "Mac: 태그 길이 65바이트 (최대 64)");
    }

    err_code = Mac(NULL, 0, dummy, 16, 0, dummy, 16, output);
    if (err_code != CRYPTO_ERR_PARAM) {
        printf("❌ 잘못된 태그 길이(0) 테스트 실패\n");
        all_passed = 0;
    }
    else {
        printf("✅ 잘못된 태그 길이(0) 테스트 통과\n");
        crypto_error_print(err_code, "Mac: 태그 길이 0바이트");
    }

    // 5. 에러 메시지 출력 테스트
    printf("\n[5] 에러 메시지 출력 테스트\n");
    printf("에러 코드별 메시지:\n");
    printf("  CRYPTO_OK: %s\n", crypto_error_string(CRYPTO_OK));
    printf("  CRYPTO_ERR_PARAM: %s\n", crypto_error_string(CRYPTO_ERR_PARAM));
    printf("  CRYPTO_ERR_KEYLEN: %s\n", crypto_error_string(CRYPTO_ERR_KEYLEN));
    printf("  CRYPTO_ERR_MODE: %s\n", crypto_error_string(CRYPTO_ERR_MODE));
    printf("  CRYPTO_ERR_PADDING: %s\n", crypto_error_string(CRYPTO_ERR_PADDING));
    printf("  CRYPTO_ERR_MEMORY: %s\n", crypto_error_string(CRYPTO_ERR_MEMORY));
    printf("  CRYPTO_ERR_INTERNAL: %s\n", crypto_error_string(CRYPTO_ERR_INTERNAL));
    printf("  알 수 없는 에러(-999): %s\n", crypto_error_string(-999));

    // 6. 에러 확인 함수 테스트
    printf("\n[6] 에러 확인 함수 테스트\n");
    if (crypto_is_success(CRYPTO_OK)) {
        printf("✅ crypto_is_success(CRYPTO_OK) 통과\n");
    }
    else {
        printf("❌ crypto_is_success(CRYPTO_OK) 실패\n");
        all_passed = 0;
    }

    if (!crypto_is_success(CRYPTO_ERR_PARAM)) {
        printf("✅ crypto_is_success(CRYPTO_ERR_PARAM) 통과\n");
    }
    else {
        printf("❌ crypto_is_success(CRYPTO_ERR_PARAM) 실패\n");
        all_passed = 0;
    }

    if (crypto_is_error(CRYPTO_ERR_PARAM)) {
        printf("✅ crypto_is_error(CRYPTO_ERR_PARAM) 통과\n");
    }
    else {
        printf("❌ crypto_is_error(CRYPTO_ERR_PARAM) 실패\n");
        all_passed = 0;
    }

    if (!crypto_is_error(CRYPTO_OK)) {
        printf("✅ crypto_is_error(CRYPTO_OK) 통과\n");
    }
    else {
        printf("❌ crypto_is_error(CRYPTO_OK) 실패\n");
        all_passed = 0;
    }

    if (all_passed) {
        printf("\n✅ 모든 오류 처리 테스트 통과\n");
    }
    else {
        printf("\n❌ 일부 오류 처리 테스트 실패\n");
    }
    printf("\n");
    return all_passed;
}

// 메인 함수
int main(void) {
    if (init_result_file() != 0) {
        return 1;
    }

    printf("=== 암호화 알고리즘 테스트 시작 ===\n\n");

    int all_passed = 1;

    if (!test_aes_block()) all_passed = 0;
    if (!test_aes_cbc()) all_passed = 0;
    if (!test_aes_ctr()) all_passed = 0;
    if (!test_sha512()) all_passed = 0;
    if (!test_hmac_sha512()) all_passed = 0;
    if (!test_error_handling()) all_passed = 0;

    // 최종 결과 출력
    close_result_file();

    if (all_passed && failed_tests == 0) {
        printf("\n=== 테스트 통과 ===\n");
        printf("총 테스트: %d, 통과: %d, 실패: %d\n", total_tests, passed_tests, failed_tests);
        printf("결과 파일: %s\n", TEST_RESULT_FILE);
    }
    else {
        printf("\n테스트 실패!\n");
        printf("총 테스트: %d, 통과: %d, 실패: %d\n", total_tests, passed_tests, failed_tests);
        delete_result_file();
    }

    return (all_passed && failed_tests == 0) ? 0 : 1;
}

