/*
 * Crypto Library Project
 * Developed by: SWTeam9
 * GitHub: https://github.com/SWTEAM99/team9
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include "crypto_api.h"

/* 진행률 표시를 위한 구조체 */
typedef struct {
    size_t total_bytes;      // 전체 바이트 수
    size_t processed_bytes;  // 처리된 바이트 수
    int last_percent;        // 마지막에 출력한 퍼센트
    const char* operation;   // 작업 이름 ("암호화" 또는 "복호화")
    int block_counter;       // 블록 카운터 (일정 간격마다 업데이트하기 위함)
} progress_info_t;

/* AES 컨텍스트와 진행률 정보를 함께 담는 구조체 */
typedef struct {
    AES_CTX aes_ctx;         // AES 컨텍스트
    progress_info_t* prog;   // 진행률 정보 (NULL 가능)
    int block_size;          // 블록 크기 (진행률 계산용)
} aes_ctx_with_progress_t;

/* 진행률 표시 함수 */
/*
 * \r (캐리지 리턴) 설명:
 * - \r은 커서를 현재 줄의 맨 앞으로 이동시킵니다
 * - printf로 같은 줄에 다시 출력하면 이전 내용이 덮어써집니다
 * - 예: "50%" 출력 후 \r로 돌아가서 "51%" 출력하면 "50%"가 "51%"로 바뀝니다
 * - \n (줄바꿈)과 달리 줄을 바꾸지 않고 같은 줄에 덮어쓰는 효과입니다
 */
static void update_progress(progress_info_t* prog, size_t additional_bytes) {
    if (!prog) return;

    prog->processed_bytes += additional_bytes;

    if (prog->total_bytes == 0) return;

    int current_percent = (int)((prog->processed_bytes * 100) / prog->total_bytes);
    if (current_percent > 100) current_percent = 100;

    // 5% 단위로만 업데이트하여 성능 저하 방지 (너무 자주 출력하지 않음)
    // 또는 마지막에 100% 표시
    // 예: 0%, 5%, 10%, 15%, ..., 95%, 100%만 출력
    if (current_percent == 100 ||
        (current_percent >= prog->last_percent + 5 && current_percent % 5 == 0)) {
        printf("\r[진행 중] %s: %d%% (%zu / %zu 바이트)",
            prog->operation, current_percent, prog->processed_bytes, prog->total_bytes);
        fflush(stdout);
        prog->last_percent = current_percent;

        if (current_percent == 100) {
            printf("\n");
        }
    }
}

static void stop_progress(void) {
    // 아무것도 하지 않음 (메시지는 각 함수에서 직접 출력)
}

/* CBC용 AES 블록 암호화 콜백 (진행률 표시 포함) */
static void aes_encrypt_block_cb_with_progress(const byte* in, byte* out, const void* user_ctx) {
    const aes_ctx_with_progress_t* ctx_prog = (const aes_ctx_with_progress_t*)user_ctx;
    const AES_CTX* ctx = &ctx_prog->aes_ctx;

    // 초기화된 컨텍스트를 사용하여 암호화 (키 확장은 이미 완료됨)
    if (ctx->impl == AES_IMPL_REF && ctx->ref_ctx_initialized) {
        aes_ref_encrypt_core(&ctx->ref_ctx, in, out);
    }
    else if (ctx->impl == AES_IMPL_TBL && ctx->tbl_ctx_initialized) {
        aes_encrypt_core(&ctx->tbl_ctx, in, out);
    }
    else {
        // 초기화되지 않은 경우 기존 방식 (직접 호출)
        AES_encrypt_block(in, out, ctx->key, ctx->key_len, ctx->impl);
    }

    // 진행률 업데이트 (일정 블록 수마다만 업데이트하여 성능 개선)
    if (ctx_prog->prog) {
        progress_info_t* prog = ctx_prog->prog;
        prog->block_counter++;
        prog->processed_bytes += ctx_prog->block_size;

        // 100블록마다 또는 마지막에만 업데이트
        int update_interval = (prog->total_bytes > 100 * ctx_prog->block_size) ? 100 : 1;
        if (prog->block_counter % update_interval == 0 || prog->processed_bytes >= prog->total_bytes) {
            update_progress(prog, 0);  // processed_bytes는 이미 업데이트됨
        }
    }
}

/* CBC용 AES 블록 복호화 콜백 (진행률 표시 포함) */
static void aes_decrypt_block_cb_with_progress(const byte* in, byte* out, const void* user_ctx) {
    const aes_ctx_with_progress_t* ctx_prog = (const aes_ctx_with_progress_t*)user_ctx;
    const AES_CTX* ctx = &ctx_prog->aes_ctx;

    // 초기화된 컨텍스트를 사용하여 복호화 (키 확장은 이미 완료됨)
    if (ctx->impl == AES_IMPL_REF && ctx->ref_ctx_initialized) {
        aes_ref_decrypt_core(&ctx->ref_ctx, in, out);
    }
    else if (ctx->impl == AES_IMPL_TBL && ctx->tbl_ctx_initialized) {
        aes_decrypt_core(&ctx->tbl_ctx, in, out);
    }
    else {
        // 초기화되지 않은 경우 기존 방식 (직접 호출)
        AES_decrypt_block(in, out, ctx->key, ctx->key_len, ctx->impl);
    }

    // 진행률 업데이트 (일정 블록 수마다만 업데이트하여 성능 개선)
    if (ctx_prog->prog) {
        progress_info_t* prog = ctx_prog->prog;
        prog->block_counter++;
        prog->processed_bytes += ctx_prog->block_size;

        // 100블록마다 또는 5% 단위로 업데이트
        int update_interval = (prog->total_bytes > 100 * ctx_prog->block_size) ? 100 : 1;
        if (prog->block_counter % update_interval == 0 || prog->processed_bytes >= prog->total_bytes) {
            update_progress(prog, 0);  // processed_bytes는 이미 업데이트됨
        }
    }
}

/**
 * @brief 키를 파일에서 읽거나 사용자 입력으로 받기
 * @param key_file 키 파일 경로 (NULL이면 사용자 입력)
 * @param key 출력 키 버퍼
 * @param key_len 키 길이 (16, 24, 32 중 하나)
 * @return CRYPTO_OK 성공, 그 외 실패
 */
static int load_key(const char* key_file, byte* key, int key_len) {
    if (key_file) {
        // 파일에서 키 읽기
        byte* key_data = NULL;
        size_t key_data_len = 0;
        int ret = CRYPTO_readFile(key_file, &key_data, &key_data_len);
        if (ret != CRYPTO_OK) {
            printf("[오류] 키 파일 읽기 실패: %s\n", key_file);
            return ret;
        }

        if (key_data_len < (size_t)key_len) {
            printf("[오류] 키 파일이 너무 짧습니다. 최소 %d 바이트 필요합니다.\n", key_len);
            free(key_data);
            return CRYPTO_ERR_KEYLEN;
        }

        memcpy(key, key_data, key_len);
        free(key_data);
        printf("[정보] 키 파일에서 키를 읽었습니다: %s\n", key_file);
    }
    else {
        // 사용자 입력으로 키 받기
        printf("암호화 키를 입력하세요 (%d 바이트, 16진수 또는 텍스트): ", key_len);
        char input[256];
        if (fgets(input, sizeof(input), stdin) == NULL) {
            return CRYPTO_ERR_PARAM;
        }

        // 개행 문자 제거
        size_t input_len = strlen(input);
        if (input_len > 0 && input[input_len - 1] == '\n') {
            input[input_len - 1] = '\0';
            input_len--;
        }

        // 16진수 형식인지 확인 (0x로 시작하거나 짝수 길이의 16진수 문자열)
        if (input_len >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
            // 16진수 파싱
            const char* hex_str = input + 2;
            size_t hex_len = strlen(hex_str);
            if (hex_len != (size_t)(key_len * 2)) {
                printf("[오류] 16진수 키 길이가 올바르지 않습니다. %d 바이트 = %d 자 필요\n",
                    key_len, key_len * 2);
                return CRYPTO_ERR_KEYLEN;
            }

            for (int i = 0; i < key_len; i++) {
                char hex_byte[3] = { hex_str[i * 2], hex_str[i * 2 + 1], '\0' };
                key[i] = (byte)strtol(hex_byte, NULL, 16);
            }
        }
        else {
            // 텍스트로 처리 (입력 길이가 key_len보다 작으면 0으로 패딩)
            memset(key, 0, key_len);
            size_t copy_len = (input_len < (size_t)key_len) ? input_len : (size_t)key_len;
            memcpy(key, input, copy_len);

            // 부족한 부분은 SHA-512 해시로 채우기
            if (input_len < (size_t)key_len) {
                byte hash[SHA512_DIGEST_SIZE];
                SHA512_hash((const uint8_t*)input, input_len, hash);
                memcpy(key + input_len, hash, key_len - input_len);
            }
        }
    }
    return CRYPTO_OK;
}


/**
 * @brief 파일 암호화 (CBC 모드)
 * @param input_file 입력 파일 경로
 * @param output_file 출력 파일 경로
 * @param key 암호화 키
 * @param key_len 키 길이
 * @param aes_impl AES 구현 방식
 * @param with_hmac HMAC 생성 여부 (1이면 Encrypt-then-MAC)
 * @param hmac_key HMAC 키 (with_hmac이 1일 때 사용)
 * @param hmac_key_len HMAC 키 길이
 * @param hmac_tag_len HMAC 태그 길이
 * @return CRYPTO_OK 성공, 그 외 실패
 */
static int encrypt_file_cbc(const char* input_file, const char* output_file,
    const byte* key, int key_len, AES_Impl aes_impl,
    int with_hmac, const byte* hmac_key, int hmac_key_len, int hmac_tag_len,
    const byte* hmac_salt, size_t hmac_salt_len) {
    clock_t start_time = clock();

    // 파일 읽기
    printf("파일 읽는 중...\n");
    byte* plaintext = NULL;
    size_t plaintext_len = 0;
    int ret = CRYPTO_readFile(input_file, &plaintext, &plaintext_len);
    if (ret != CRYPTO_OK) {
        crypto_error_print(ret, input_file);
        return ret;
    }

    printf("[정보] 파일 크기: %zu 바이트 (%.2f KB)\n", plaintext_len, plaintext_len / 1024.0);

    // IV 생성
    byte iv[AES_BLOCK_SIZE];
    if (IV_generate(iv) != CRYPTO_OK) {
        stop_progress();
        crypto_error_print(CRYPTO_ERR_RANDOM, "IV 생성 실패");
        free(plaintext);
        return CRYPTO_ERR_INTERNAL;
    }

    // 암호화 버퍼 준비 (IV + 암호문)
    size_t max_cipher_len = plaintext_len + AES_BLOCK_SIZE;
    byte* ciphertext = (byte*)malloc(AES_BLOCK_SIZE + max_cipher_len);
    if (!ciphertext) {
        stop_progress();
        crypto_error_print(CRYPTO_ERR_MEMORY, "메모리 할당 실패");
        free(plaintext);
        return CRYPTO_ERR_MEMORY;
    }

    // IV를 파일 앞에 저장
    memcpy(ciphertext, iv, AES_BLOCK_SIZE);

    // CBC 암호화 (진행률 표시 포함)
    // 진행률 표시 초기화
    progress_info_t prog = { 0 };
    prog.total_bytes = plaintext_len;
    prog.processed_bytes = 0;
    prog.last_percent = -1;
    prog.operation = "암호화";
    prog.block_counter = 0;

    // AES 컨텍스트와 진행률 정보를 함께 묶기
    aes_ctx_with_progress_t ctx_prog = { 0 };
    ctx_prog.aes_ctx.key = key;
    ctx_prog.aes_ctx.key_len = key_len;
    ctx_prog.aes_ctx.impl = aes_impl;
    ctx_prog.prog = &prog;
    ctx_prog.block_size = AES_BLOCK_SIZE;

    // 키 확장 수행 (한 번만)
    if (aes_impl == AES_IMPL_REF) {
        if (AES_REF_init(&ctx_prog.aes_ctx.ref_ctx, key, key_len) != CRYPTO_OK) {
            stop_progress();
            crypto_error_print(CRYPTO_ERR_INTERNAL, "AES Reference 컨텍스트 초기화 실패");
            free(plaintext);
            free(ciphertext);
            return CRYPTO_ERR_INTERNAL;
        }
        ctx_prog.aes_ctx.ref_ctx_initialized = 1;
    }
    else if (aes_impl == AES_IMPL_TBL) {
        if (AES_TBL_init(&ctx_prog.aes_ctx.tbl_ctx, key, key_len) != CRYPTO_OK) {
            stop_progress();
            crypto_error_print(CRYPTO_ERR_INTERNAL, "AES T-table 컨텍스트 초기화 실패");
            free(plaintext);
            free(ciphertext);
            return CRYPTO_ERR_INTERNAL;
        }
        ctx_prog.aes_ctx.tbl_ctx_initialized = 1;
    }

    printf("암호화 처리 중...\n");

    int cipher_len = 0;
    ret = MODES_CBC_encrypt(
        aes_encrypt_block_cb_with_progress,
        AES_BLOCK_SIZE,
        iv,
        plaintext, (int)plaintext_len,
        ciphertext + AES_BLOCK_SIZE, &cipher_len,
        &ctx_prog
    );

    free(plaintext);

    if (ret != CRYPTO_OK) {
        stop_progress();
        crypto_error_print(ret, "CBC 암호화 실패");
        free(ciphertext);
        return ret;
    }

    // Encrypt-then-MAC: 암호문에 대한 HMAC 생성
    size_t total_len = AES_BLOCK_SIZE + (size_t)cipher_len;
    byte* final_output = ciphertext;

    if (with_hmac) {
        printf("HMAC 생성 중...\n");
        byte mac_tag[64];
        ret = Mac(hmac_salt, hmac_salt_len, hmac_key, hmac_key_len, hmac_tag_len,
            ciphertext, total_len, mac_tag);
        if (ret != CRYPTO_OK) {
            crypto_error_print(ret, "HMAC 생성 실패");
            free(ciphertext);
            return ret;
        }

        // 출력 버퍼: 암호문 + HMAC
        final_output = (byte*)malloc(total_len + hmac_tag_len);
        if (!final_output) {
            crypto_error_print(CRYPTO_ERR_MEMORY, "메모리 할당 실패");
            free(ciphertext);
            return CRYPTO_ERR_MEMORY;
        }
        memcpy(final_output, ciphertext, total_len);
        memcpy(final_output + total_len, mac_tag, hmac_tag_len);
        total_len += hmac_tag_len;
        free(ciphertext);
    }

    // 파일 쓰기 (IV + 암호문 [+ HMAC])
    printf("파일 저장 중...\n");
    ret = CRYPTO_writeFile(output_file, final_output, total_len);
    free(final_output);

    if (ret != CRYPTO_OK) {
        crypto_error_print(CRYPTO_ERR_IO, output_file);
        return ret;
    }

    clock_t end_time = clock();
    double elapsed = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    printf("\n[성공] 암호화 완료!\n");
    printf("  입력 파일: %s\n", input_file);
    printf("  출력 파일: %s\n", output_file);
    printf("  원본 크기: %zu 바이트 (%.2f KB)\n", plaintext_len, plaintext_len / 1024.0);
    if (with_hmac) {
        printf("  암호화 크기: %zu 바이트 (%.2f KB, IV: %d + 암호문: %d + HMAC: %d)\n",
            total_len, total_len / 1024.0, AES_BLOCK_SIZE, cipher_len, hmac_tag_len);
    }
    else {
        printf("  암호화 크기: %zu 바이트 (%.2f KB, IV: %d + 암호문: %d)\n",
            total_len, total_len / 1024.0, AES_BLOCK_SIZE, cipher_len);
    }
    printf("  처리 시간: %.2f 초\n", elapsed);
    return CRYPTO_OK;
}

/**
 * @brief 파일 복호화 (CBC 모드)
 * @param input_file 입력 파일 경로 (암호화된 파일)
 * @param output_file 출력 파일 경로
 * @param key 복호화 키
 * @param key_len 키 길이
 * @param aes_impl AES 구현 방식
 * @param verify_hmac HMAC 검증 여부 (1이면 검증 후 복호화)
 * @param hmac_key HMAC 키 (verify_hmac이 1일 때 사용)
 * @param hmac_key_len HMAC 키 길이
 * @param hmac_tag_len HMAC 태그 길이
 * @return CRYPTO_OK 성공, CRYPTO_ERR_INVALID HMAC 검증 실패, 그 외 실패
 */
static int decrypt_file_cbc(const char* input_file, const char* output_file,
    const byte* key, int key_len, AES_Impl aes_impl,
    int verify_hmac, const byte* hmac_key, int hmac_key_len, int hmac_tag_len,
    const byte* hmac_salt, size_t hmac_salt_len) {
    clock_t start_time = clock();

    // 암호화된 파일 읽기
    printf("파일 읽는 중...\n");
    byte* encrypted_data = NULL;
    size_t encrypted_len = 0;
    int ret = CRYPTO_readFile(input_file, &encrypted_data, &encrypted_len);
    if (ret != CRYPTO_OK) {
        crypto_error_print(ret, input_file);
        return ret;
    }

    printf("[정보] 파일 크기: %zu 바이트 (%.2f KB)\n", encrypted_len, encrypted_len / 1024.0);

    // HMAC 검증 (Encrypt-then-MAC)
    size_t cipher_len = encrypted_len;

    if (verify_hmac) {
        printf("HMAC 검증 중...\n");
        if (encrypted_len < (size_t)(AES_BLOCK_SIZE + hmac_tag_len)) {
            printf("[오류] 암호화된 파일이 너무 짧습니다 (HMAC 포함).\n");
            free(encrypted_data);
            return CRYPTO_ERR_PARAM;
        }

        // 검증 데이터 길이 계산: IV + 암호문 (HMAC 제외)
        size_t verify_data_len = encrypted_len - hmac_tag_len;

        // 암호문과 HMAC 분리
        cipher_len = verify_data_len;
        byte* stored_mac = encrypted_data + cipher_len;

        // 암호문에 대한 HMAC 검증 (Vrfy가 내부적으로 MAC 계산 및 비교)
        // encrypted_data의 처음 verify_data_len 바이트 = IV + 암호문 (HMAC 제외)
        ret = Vrfy(hmac_salt, hmac_salt_len, hmac_key, hmac_key_len, hmac_tag_len,
            encrypted_data, verify_data_len, stored_mac);

        if (ret != CRYPTO_OK) {
            printf("[오류] HMAC 검증 실패! (오류 코드: %d)\n", ret);
            printf("  - 파일이 변조되었거나 키가 잘못되었습니다.\n");
            printf("  - 암호화 시 사용한 HMAC 키와 동일한 키를 사용했는지 확인하세요.\n");
            free(encrypted_data);
            return ret;
        }
        printf("[성공] HMAC 검증 성공!\n");
    }
    else {
        // 최소 크기 확인 (IV + 최소 1블록)
        if (encrypted_len < AES_BLOCK_SIZE * 2) {
            printf("[오류] 암호화된 파일이 너무 짧습니다.\n");
            free(encrypted_data);
            return CRYPTO_ERR_PARAM;
        }
    }

    // IV 추출
    byte iv[AES_BLOCK_SIZE];
    memcpy(iv, encrypted_data, AES_BLOCK_SIZE);

    // 암호문 추출 (IV 제외)
    cipher_len -= AES_BLOCK_SIZE;
    byte* ciphertext = encrypted_data + AES_BLOCK_SIZE;

    // 복호화 버퍼 준비
    byte* plaintext = (byte*)malloc(cipher_len);
    if (!plaintext) {
        stop_progress();
        crypto_error_print(CRYPTO_ERR_MEMORY, "메모리 할당 실패");
        free(encrypted_data);
        return CRYPTO_ERR_MEMORY;
    }

    // CBC 복호화 (진행률 표시 포함)
    // 진행률 표시 초기화
    progress_info_t prog = { 0 };
    prog.total_bytes = cipher_len;
    prog.processed_bytes = 0;
    prog.last_percent = -1;
    prog.operation = "복호화";
    prog.block_counter = 0;

    // AES 컨텍스트와 진행률 정보를 함께 묶기
    aes_ctx_with_progress_t ctx_prog;
    ctx_prog.aes_ctx.key = key;
    ctx_prog.aes_ctx.key_len = key_len;
    ctx_prog.aes_ctx.impl = aes_impl;
    ctx_prog.prog = &prog;
    ctx_prog.block_size = AES_BLOCK_SIZE;

    // 키 확장 수행 (한 번만)
    if (aes_impl == AES_IMPL_REF) {
        if (AES_REF_init(&ctx_prog.aes_ctx.ref_ctx, key, key_len) != CRYPTO_OK) {
            stop_progress();
            crypto_error_print(CRYPTO_ERR_INTERNAL, "AES 컨텍스트 초기화 실패");
            free(encrypted_data);
            free(plaintext);
            return CRYPTO_ERR_INTERNAL;
        }
        ctx_prog.aes_ctx.ref_ctx_initialized = 1;
    }
    else if (aes_impl == AES_IMPL_TBL) {
        if (AES_TBL_init(&ctx_prog.aes_ctx.tbl_ctx, key, key_len) != CRYPTO_OK) {
            stop_progress();
            crypto_error_print(CRYPTO_ERR_INTERNAL, "AES 컨텍스트 초기화 실패");
            free(encrypted_data);
            free(plaintext);
            return CRYPTO_ERR_INTERNAL;
        }
        ctx_prog.aes_ctx.tbl_ctx_initialized = 1;
    }

    printf("복호화 처리 중...\n");

    int plaintext_len = 0;
    ret = MODES_CBC_decrypt(
        aes_decrypt_block_cb_with_progress,
        AES_BLOCK_SIZE,
        iv,
        ciphertext, (int)cipher_len,
        plaintext, &plaintext_len,
        &ctx_prog
    );

    if (ret != CRYPTO_OK) {
        stop_progress();
        crypto_error_print(ret, "CBC 복호화 실패");
        free(encrypted_data);
        free(plaintext);
        return ret;
    }

    // 파일 쓰기
    printf("파일 저장 중...\n");
    ret = CRYPTO_writeFile(output_file, plaintext, (size_t)plaintext_len);
    free(encrypted_data);
    free(plaintext);

    if (ret != CRYPTO_OK) {
        crypto_error_print(CRYPTO_ERR_IO, output_file);
        return ret;
    }

    clock_t end_time = clock();
    double elapsed = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    printf("\n[성공] 복호화 완료!\n");
    printf("  입력 파일: %s\n", input_file);
    printf("  출력 파일: %s\n", output_file);
    printf("  복호화 크기: %d 바이트 (%.2f KB)\n", plaintext_len, plaintext_len / 1024.0);
    printf("  처리 시간: %.2f 초\n", elapsed);
    return CRYPTO_OK;
}

/**
 * @brief 파일 암호화/복호화 (CTR 모드)
 * @param input_file 입력 파일 경로
 * @param output_file 출력 파일 경로
 * @param key 암호화/복호화 키
 * @param key_len 키 길이
 * @param aes_impl AES 구현 방식
 * @param is_encrypt 1이면 암호화, 0이면 복호화
 * @param with_hmac HMAC 생성/검증 여부 (1이면 Encrypt-then-MAC)
 * @param hmac_key HMAC 키
 * @param hmac_key_len HMAC 키 길이
 * @param hmac_tag_len HMAC 태그 길이
 * @param hmac_salt HMAC salt (비밀 파라미터)
 * @param hmac_salt_len HMAC salt 길이
 * @return CRYPTO_OK 성공, CRYPTO_ERR_INVALID HMAC 검증 실패, 그 외 실패
 */
static int crypt_file_ctr(const char* input_file, const char* output_file,
    const byte* key, int key_len, AES_Impl aes_impl, int is_encrypt,
    int with_hmac, const byte* hmac_key, int hmac_key_len, int hmac_tag_len,
    const byte* hmac_salt, size_t hmac_salt_len) {
    clock_t start_time = clock();

    // 파일 읽기
    printf("파일 읽는 중...\n");
    byte* input_data = NULL;
    size_t input_len = 0;
    int ret = CRYPTO_readFile(input_file, &input_data, &input_len);
    if (ret != CRYPTO_OK) {
        crypto_error_print(ret, input_file);
        return ret;
    }

    printf("[정보] 파일 크기: %zu 바이트 (%.2f KB)\n", input_len, input_len / 1024.0);

    byte* output_data = NULL;

    if (is_encrypt) {
        // 암호화: Nonce 생성
        byte nonce_ctr[AES_BLOCK_SIZE];
        if (IV_generate(nonce_ctr) != CRYPTO_OK) {
            crypto_error_print(CRYPTO_ERR_RANDOM, "Nonce 생성 실패");
            free(input_data);
            return CRYPTO_ERR_INTERNAL;
        }

        // 출력 버퍼 준비 (Nonce + 암호문)
        output_data = (byte*)malloc(AES_BLOCK_SIZE + input_len);
        if (!output_data) {
            crypto_error_print(CRYPTO_ERR_MEMORY, "메모리 할당 실패");
            free(input_data);
            return CRYPTO_ERR_MEMORY;
        }

        // Nonce를 파일 앞에 저장
        memcpy(output_data, nonce_ctr, AES_BLOCK_SIZE);

        // CTR 암호화 (Nonce를 복사해서 사용, 원본은 보존)
        byte nonce_working[AES_BLOCK_SIZE];
        memcpy(nonce_working, nonce_ctr, AES_BLOCK_SIZE);

        // 진행률 표시 초기화
        progress_info_t prog_enc = { 0 };
        prog_enc.total_bytes = input_len;
        prog_enc.processed_bytes = 0;
        prog_enc.last_percent = -1;
        prog_enc.operation = "CTR 암호화";

        // AES 컨텍스트와 진행률 정보를 함께 묶기
        aes_ctx_with_progress_t ctx_prog_enc;
        ctx_prog_enc.aes_ctx.key = key;
        ctx_prog_enc.aes_ctx.key_len = key_len;
        ctx_prog_enc.aes_ctx.impl = aes_impl;
        ctx_prog_enc.prog = &prog_enc;
        ctx_prog_enc.block_size = AES_BLOCK_SIZE;

        // 키 확장 수행 (한 번만)
        if (aes_impl == AES_IMPL_REF) {
            if (AES_REF_init(&ctx_prog_enc.aes_ctx.ref_ctx, key, key_len) != CRYPTO_OK) {
                crypto_error_print(CRYPTO_ERR_INTERNAL, "AES 컨텍스트 초기화 실패");
                free(input_data);
                free(output_data);
                return CRYPTO_ERR_INTERNAL;
            }
            ctx_prog_enc.aes_ctx.ref_ctx_initialized = 1;
        }
        else if (aes_impl == AES_IMPL_TBL) {
            if (AES_TBL_init(&ctx_prog_enc.aes_ctx.tbl_ctx, key, key_len) != CRYPTO_OK) {
                crypto_error_print(CRYPTO_ERR_INTERNAL, "AES 컨텍스트 초기화 실패");
                free(input_data);
                free(output_data);
                return CRYPTO_ERR_INTERNAL;
            }
            ctx_prog_enc.aes_ctx.tbl_ctx_initialized = 1;
        }

        printf("CTR 암호화 처리 중...\n");

        ret = MODES_CTR_crypt(
            aes_encrypt_block_cb_with_progress,
            AES_BLOCK_SIZE,
            nonce_working,
            input_data, (int)input_len,
            output_data + AES_BLOCK_SIZE,
            &ctx_prog_enc
        );

        if (ret != CRYPTO_OK) {
            crypto_error_print(ret, "CTR 암호화 실패");
            free(input_data);
            free(output_data);
            return ret;
        }

        // 마지막 100% 확실히 표시
        if (prog_enc.processed_bytes < prog_enc.total_bytes) {
            prog_enc.processed_bytes = prog_enc.total_bytes;
            update_progress(&prog_enc, 0);
        }

        // Encrypt-then-MAC: 암호문에 대한 HMAC 생성
        size_t total_len = AES_BLOCK_SIZE + input_len;
        byte* final_output = output_data;

        if (with_hmac) {
            printf("HMAC 생성 중...\n");
            byte mac_tag[64];
            ret = Mac(hmac_salt, hmac_salt_len, hmac_key, hmac_key_len, hmac_tag_len,
                output_data, total_len, mac_tag);
            if (ret != CRYPTO_OK) {
                crypto_error_print(ret, "HMAC 생성 실패");
                free(output_data);
                free(input_data);
                return ret;
            }

            // 출력 버퍼: 암호문 + HMAC
            final_output = (byte*)malloc(total_len + hmac_tag_len);
            if (!final_output) {
                crypto_error_print(CRYPTO_ERR_MEMORY, "메모리 할당 실패");
                free(output_data);
                free(input_data);
                return CRYPTO_ERR_MEMORY;
            }
            memcpy(final_output, output_data, total_len);
            memcpy(final_output + total_len, mac_tag, hmac_tag_len);
            total_len += hmac_tag_len;
            free(output_data);
        }

        // 파일 쓰기
        printf("파일 저장 중...\n");
        ret = CRYPTO_writeFile(output_file, final_output, total_len);
        free(final_output);

        if (ret != CRYPTO_OK) {
            crypto_error_print(CRYPTO_ERR_IO, output_file);
            free(input_data);
            return ret;
        }

        clock_t end_time = clock();
        double elapsed = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

        printf("\n[성공] CTR 암호화 완료!\n");
        printf("  입력 파일: %s\n", input_file);
        printf("  출력 파일: %s\n", output_file);
        printf("  원본 크기: %zu 바이트 (%.2f KB)\n", input_len, input_len / 1024.0);
        if (with_hmac) {
            printf("  암호화 크기: %zu 바이트 (%.2f KB, Nonce: %d + 암호문: %zu + HMAC: %d)\n",
                total_len, total_len / 1024.0, AES_BLOCK_SIZE, input_len, hmac_tag_len);
        }
        else {
            printf("  암호화 크기: %zu 바이트 (%.2f KB, Nonce: %d + 암호문: %zu)\n",
                total_len, total_len / 1024.0, AES_BLOCK_SIZE, input_len);
        }
        printf("  처리 시간: %.2f 초\n", elapsed);
    }
    else {
        // 복호화: HMAC 검증 (Encrypt-then-MAC)
        size_t cipher_len = input_len;

        if (with_hmac) {
            printf("HMAC 검증 중...\n");
            if (input_len < (size_t)(AES_BLOCK_SIZE + hmac_tag_len)) {
                printf("[오류] 암호화된 파일이 너무 짧습니다 (HMAC 포함).\n");
                free(input_data);
                return CRYPTO_ERR_PARAM;
            }

            // 검증 데이터 길이 계산: Nonce + 암호문 (HMAC 제외)
            size_t verify_data_len = input_len - hmac_tag_len;

            // cipher_len = Nonce + 암호문 길이 (HMAC 제외)
            cipher_len = verify_data_len;
            byte* stored_mac = input_data + cipher_len;

            // HMAC 검증: input_data의 처음 verify_data_len 바이트 = Nonce + 암호문 (HMAC 제외)
            ret = Vrfy(hmac_salt, hmac_salt_len, hmac_key, hmac_key_len, hmac_tag_len,
                input_data, verify_data_len, stored_mac);
            if (ret != CRYPTO_OK) {
                crypto_error_print(ret, "HMAC 검증 실패");
                printf("  - 파일이 변조되었거나 키가 잘못되었습니다.\n");
                printf("  - 암호화 시 사용한 HMAC 키와 동일한 키를 사용했는지 확인하세요.\n");
                free(input_data);
                return ret;
            }
            printf("[성공] HMAC 검증 성공!\n");
        }
        else {
            if (input_len < AES_BLOCK_SIZE) {
                printf("[오류] 암호화된 파일이 너무 짧습니다.\n");
                free(input_data);
                return CRYPTO_ERR_PARAM;
            }
        }

        // Nonce 추출
        byte nonce_ctr[AES_BLOCK_SIZE];
        memcpy(nonce_ctr, input_data, AES_BLOCK_SIZE);

        // 암호문 추출 (Nonce 제외)
        size_t actual_cipher_len = cipher_len - AES_BLOCK_SIZE;
        byte* ciphertext = input_data + AES_BLOCK_SIZE;

        // 복호화 버퍼 준비
        output_data = (byte*)malloc(actual_cipher_len);
        if (!output_data) {
            crypto_error_print(CRYPTO_ERR_MEMORY, "메모리 할당 실패");
            free(input_data);
            return CRYPTO_ERR_MEMORY;
        }

        // CTR 복호화 (암호화와 동일)
        byte nonce_working[AES_BLOCK_SIZE];
        memcpy(nonce_working, nonce_ctr, AES_BLOCK_SIZE);

        // 진행률 표시 초기화
        progress_info_t prog_dec = { 0 };
        prog_dec.total_bytes = actual_cipher_len;
        prog_dec.processed_bytes = 0;
        prog_dec.last_percent = -1;
        prog_dec.operation = "CTR 복호화";

        // AES 컨텍스트와 진행률 정보를 함께 묶기
        aes_ctx_with_progress_t ctx_prog_dec = { 0 };
        ctx_prog_dec.aes_ctx.key = key;
        ctx_prog_dec.aes_ctx.key_len = key_len;
        ctx_prog_dec.aes_ctx.impl = aes_impl;
        ctx_prog_dec.prog = &prog_dec;
        ctx_prog_dec.block_size = AES_BLOCK_SIZE;

        // 키 확장 수행 (한 번만)
        if (aes_impl == AES_IMPL_REF) {
            if (AES_REF_init(&ctx_prog_dec.aes_ctx.ref_ctx, key, key_len) != CRYPTO_OK) {
                crypto_error_print(CRYPTO_ERR_INTERNAL, "AES 컨텍스트 초기화 실패");
                free(input_data);
                free(output_data);
                return CRYPTO_ERR_INTERNAL;
            }
            ctx_prog_dec.aes_ctx.ref_ctx_initialized = 1;
        }
        else if (aes_impl == AES_IMPL_TBL) {
            if (AES_TBL_init(&ctx_prog_dec.aes_ctx.tbl_ctx, key, key_len) != CRYPTO_OK) {
                crypto_error_print(CRYPTO_ERR_INTERNAL, "AES 컨텍스트 초기화 실패");
                free(input_data);
                free(output_data);
                return CRYPTO_ERR_INTERNAL;
            }
            ctx_prog_dec.aes_ctx.tbl_ctx_initialized = 1;
        }

        printf("CTR 복호화 처리 중...\n");

        ret = MODES_CTR_crypt(
            aes_encrypt_block_cb_with_progress,
            AES_BLOCK_SIZE,
            nonce_working,
            ciphertext, (int)actual_cipher_len,
            output_data,
            &ctx_prog_dec
        );

        if (ret != CRYPTO_OK) {
            crypto_error_print(ret, "CTR 복호화 실패");
            free(input_data);
            free(output_data);
            return ret;
        }

        // 마지막 100% 확실히 표시
        if (prog_dec.processed_bytes < prog_dec.total_bytes) {
            prog_dec.processed_bytes = prog_dec.total_bytes;
            update_progress(&prog_dec, 0);
        }

        // 파일 쓰기 (CTR은 입력 길이와 출력 길이가 동일)
        printf("파일 저장 중...\n");
        ret = CRYPTO_writeFile(output_file, output_data, actual_cipher_len);
        free(input_data);
        free(output_data);

        if (ret != CRYPTO_OK) {
            crypto_error_print(CRYPTO_ERR_IO, output_file);
            return ret;
        }

        clock_t end_time = clock();
        double elapsed = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

        printf("\n[성공] CTR 복호화 완료!\n");
        printf("  입력 파일: %s\n", input_file);
        printf("  출력 파일: %s\n", output_file);
        printf("  복호화 크기: %zu 바이트 (%.2f KB)\n", cipher_len, cipher_len / 1024.0);
        printf("  처리 시간: %.2f 초\n", elapsed);
    }

    return CRYPTO_OK;
}

/**
 * @brief 사용자 입력 받기 (줄바꿈 제거)
 */
static void get_user_input(char* buffer, size_t size, const char* prompt) {
    printf("%s", prompt);
    if (fgets(buffer, (int)size, stdin) == NULL) {
        buffer[0] = '\0';
        return;
    }
    // 개행 문자 제거
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }
}

/**
 * @brief 파일의 SHA-512 해시 계산
 * @param input_file 입력 파일 경로
 * @param output_file 출력 파일 경로 (해시 값 저장)
 * @return CRYPTO_OK 성공, 그 외 실패
 */
static int hash_file_sha512(const char* input_file, const char* output_file) {
    clock_t start_time = clock();

    // 파일 읽기
    printf("파일 읽는 중...\n");
    byte* file_data = NULL;
    size_t file_len = 0;
    int ret = CRYPTO_readFile(input_file, &file_data, &file_len);
    if (ret != CRYPTO_OK) {
        crypto_error_print(ret, input_file);
        return ret;
    }

    printf("[정보] 파일 크기: %zu 바이트 (%.2f KB)\n", file_len, file_len / 1024.0);

    // SHA-512 해시 계산
    printf("SHA-512 해시 계산 중...\n");
    byte hash[SHA512_DIGEST_SIZE];
    ret = SHA512_hash(file_data, file_len, hash);
    free(file_data);

    if (ret != CRYPTO_OK) {
        printf("[오류] 해시 계산 실패\n");
        return ret;
    }

    // 해시 값 저장
    ret = CRYPTO_writeFile(output_file, hash, SHA512_DIGEST_SIZE);
    if (ret != CRYPTO_OK) {
        crypto_error_print(CRYPTO_ERR_IO, output_file);
        return ret;
    }

    clock_t end_time = clock();
    double elapsed = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    printf("\n[성공] SHA-512 해시 계산 완료!\n");
    printf("  입력 파일: %s\n", input_file);
    printf("  출력 파일: %s\n", output_file);
    printf("  해시 크기: %d 바이트\n", SHA512_DIGEST_SIZE);
    printf("  처리 시간: %.2f 초\n", elapsed);
    printf("  해시 값: ");
    CRYPTO_printHex(hash, SHA512_DIGEST_SIZE);

    return CRYPTO_OK;
}

/**
 * @brief 파일의 SHA-512 해시 검증
 * @param input_file 입력 파일 경로
 * @param hash_file 해시 파일 경로
 * @return CRYPTO_OK 일치, CRYPTO_ERR_INVALID 불일치, 그 외 실패
 */
static int verify_hash_sha512(const char* input_file, const char* hash_file) {
    clock_t start_time = clock();

    // 파일 읽기
    printf("파일 읽는 중...\n");
    byte* file_data = NULL;
    size_t file_len = 0;
    int ret = CRYPTO_readFile(input_file, &file_data, &file_len);
    if (ret != CRYPTO_OK) {
        crypto_error_print(ret, input_file);
        return ret;
    }

    printf("[정보] 파일 크기: %zu 바이트 (%.2f KB)\n", file_len, file_len / 1024.0);

    // 해시 파일 읽기
    printf("해시 파일 읽는 중...\n");
    byte* stored_hash = NULL;
    size_t hash_len = 0;
    ret = CRYPTO_readFile(hash_file, &stored_hash, &hash_len);
    if (ret != CRYPTO_OK) {
        printf("[오류] 해시 파일 읽기 실패: %s\n", hash_file);
        free(file_data);
        return ret;
    }

    if (hash_len < SHA512_DIGEST_SIZE) {
        printf("[오류] 해시 파일이 너무 짧습니다.\n");
        free(file_data);
        free(stored_hash);
        return CRYPTO_ERR_PARAM;
    }

    // SHA-512 해시 계산
    printf("해시 계산 및 비교 중...\n");
    byte computed_hash[SHA512_DIGEST_SIZE];
    ret = SHA512_hash(file_data, file_len, computed_hash);
    free(file_data);

    if (ret != CRYPTO_OK) {
        printf("[오류] 해시 계산 실패\n");
        free(stored_hash);
        return ret;
    }

    // 해시 비교
    int match = CRYPTO_isEqual(computed_hash, stored_hash, SHA512_DIGEST_SIZE);

    clock_t end_time = clock();
    double elapsed = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    printf("\n");
    if (match) {
        printf("[성공] SHA-512 해시 검증 성공! 파일이 변조되지 않았습니다.\n");
    }
    else {
        printf("[실패] SHA-512 해시 검증 실패! 파일이 변조되었습니다.\n");
    }
    printf("  입력 파일: %s\n", input_file);
    printf("  해시 파일: %s\n", hash_file);
    printf("  계산된 해시: ");
    CRYPTO_printHex(computed_hash, SHA512_DIGEST_SIZE);
    printf("  저장된 해시: ");
    CRYPTO_printHex(stored_hash, SHA512_DIGEST_SIZE);
    printf("  처리 시간: %.2f 초\n", elapsed);

    free(stored_hash);
    return match ? CRYPTO_OK : CRYPTO_ERR_INVALID;
}

/**
 * @brief 파일에 대한 HMAC 생성
 * @param input_file 입력 파일 경로
 * @param output_file 출력 파일 경로 (MAC 태그 저장)
 * @param key_file 키 파일 경로 (NULL이면 직접 입력)
 * @param tag_len MAC 태그 길이 (바이트, 최대 64)
 * @return CRYPTO_OK 성공, 그 외 실패
 */
static int generate_hmac(const char* input_file, const char* output_file,
    const char* key_file, int tag_len) {
    clock_t start_time = clock();

    // 키 로드
    byte key[64];  // HMAC 키는 최대 64바이트
    printf("HMAC 키를 입력하세요 (최대 64바이트, 16진수 또는 텍스트): ");
    char key_input[256];
    if (fgets(key_input, sizeof(key_input), stdin) == NULL) {
        return CRYPTO_ERR_PARAM;
    }

    size_t key_input_len = strlen(key_input);
    if (key_input_len > 0 && key_input[key_input_len - 1] == '\n') {
        key_input[key_input_len - 1] = '\0';
        key_input_len--;
    }

    int key_len = 0;
    if (key_input_len >= 2 && key_input[0] == '0' && (key_input[1] == 'x' || key_input[1] == 'X')) {
        // 16진수 파싱
        const char* hex_str = key_input + 2;
        size_t hex_len = strlen(hex_str);
        key_len = (int)(hex_len / 2);
        if (key_len > 64) key_len = 64;

        for (int i = 0; i < key_len; i++) {
            char hex_byte[3] = { hex_str[i * 2], hex_str[i * 2 + 1], '\0' };
            key[i] = (byte)strtol(hex_byte, NULL, 16);
        }
    }
    else {
        // 텍스트로 처리
        key_len = (int)(key_input_len < 64 ? key_input_len : 64);
        memcpy(key, key_input, key_len);
    }

    // 파일 읽기
    printf("파일 읽는 중...\n");
    byte* file_data = NULL;
    size_t file_len = 0;
    int ret = CRYPTO_readFile(input_file, &file_data, &file_len);
    if (ret != CRYPTO_OK) {
        crypto_error_print(ret, input_file);
        return ret;
    }

    printf("[정보] 파일 크기: %zu 바이트 (%.2f KB)\n", file_len, file_len / 1024.0);

    // HMAC salt 입력 (선택사항, 엔터 시 NULL)
    byte salt[64] = { 0 };
    size_t salt_len = 0;
    printf("HMAC salt 입력 (엔터: 사용 안 함, 16진수 또는 텍스트): ");
    char salt_input[256];
    if (fgets(salt_input, sizeof(salt_input), stdin) != NULL) {
        size_t salt_input_len = strlen(salt_input);
        if (salt_input_len > 0 && salt_input[salt_input_len - 1] == '\n') {
            salt_input[salt_input_len - 1] = '\0';
            salt_input_len--;
        }

        if (salt_input_len > 0) {
            if (salt_input_len >= 2 && salt_input[0] == '0' && (salt_input[1] == 'x' || salt_input[1] == 'X')) {
                // 16진수 파싱
                const char* hex_str = salt_input + 2;
                size_t hex_len = strlen(hex_str);
                salt_len = hex_len / 2;
                if (salt_len > 64) salt_len = 64;

                for (size_t i = 0; i < salt_len; i++) {
                    char hex_byte[3] = { hex_str[i * 2], hex_str[i * 2 + 1], '\0' };
                    salt[i] = (byte)strtol(hex_byte, NULL, 16);
                }
            }
            else {
                // 텍스트로 처리
                salt_len = (salt_input_len < 64) ? salt_input_len : 64;
                memcpy(salt, salt_input, salt_len);
            }
            printf("[정보] Salt가 입력되었습니다 (%zu 바이트)\n", salt_len);
        }
    }

    // HMAC 생성
    printf("HMAC 생성 중...\n");
    byte mac_tag[64];
    ret = Mac(salt_len > 0 ? salt : NULL, salt_len, key, key_len, tag_len, file_data, file_len, mac_tag);
    free(file_data);

    if (ret != CRYPTO_OK) {
        printf("[오류] HMAC 생성 실패\n");
        return ret;
    }

    // MAC 태그 저장
    printf("MAC 태그 저장 중...\n");
    ret = CRYPTO_writeFile(output_file, mac_tag, tag_len);
    if (ret != CRYPTO_OK) {
        crypto_error_print(CRYPTO_ERR_IO, output_file);
        return ret;
    }

    clock_t end_time = clock();
    double elapsed = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    printf("\n[성공] HMAC 생성 완료!\n");
    printf("  입력 파일: %s\n", input_file);
    printf("  출력 파일: %s\n", output_file);
    printf("  MAC 태그 길이: %d 바이트\n", tag_len);
    printf("  처리 시간: %.2f 초\n", elapsed);
    printf("  MAC 태그: ");
    CRYPTO_printHex(mac_tag, tag_len);

    return CRYPTO_OK;
}

/**
 * @brief 파일에 대한 HMAC 검증
 * @param input_file 입력 파일 경로
 * @param mac_file MAC 태그 파일 경로
 * @param key_file 키 파일 경로 (NULL이면 직접 입력)
 * @param tag_len MAC 태그 길이 (바이트, 최대 64)
 * @return CRYPTO_OK 검증 성공, CRYPTO_ERR_INVALID 검증 실패, 그 외 실패
 */
static int verify_hmac(const char* input_file, const char* mac_file,
    const char* key_file, int tag_len) {
    clock_t start_time = clock();

    // 키 로드
    byte key[64];
    printf("HMAC 키를 입력하세요 (최대 64바이트, 16진수 또는 텍스트): ");
    char key_input[256];
    if (fgets(key_input, sizeof(key_input), stdin) == NULL) {
        return CRYPTO_ERR_PARAM;
    }

    size_t key_input_len = strlen(key_input);
    if (key_input_len > 0 && key_input[key_input_len - 1] == '\n') {
        key_input[key_input_len - 1] = '\0';
        key_input_len--;
    }

    int key_len = 0;
    if (key_input_len >= 2 && key_input[0] == '0' && (key_input[1] == 'x' || key_input[1] == 'X')) {
        const char* hex_str = key_input + 2;
        size_t hex_len = strlen(hex_str);
        key_len = (int)(hex_len / 2);
        if (key_len > 64) key_len = 64;

        for (int i = 0; i < key_len; i++) {
            char hex_byte[3] = { hex_str[i * 2], hex_str[i * 2 + 1], '\0' };
            key[i] = (byte)strtol(hex_byte, NULL, 16);
        }
    }
    else {
        key_len = (int)(key_input_len < 64 ? key_input_len : 64);
        memcpy(key, key_input, key_len);
    }

    // 파일 읽기
    printf("파일 읽는 중...\n");
    byte* file_data = NULL;
    size_t file_len = 0;
    int ret = CRYPTO_readFile(input_file, &file_data, &file_len);
    if (ret != CRYPTO_OK) {
        crypto_error_print(ret, input_file);
        return ret;
    }

    // MAC 태그 읽기
    printf("MAC 태그 읽는 중...\n");
    byte* mac_tag = NULL;
    size_t mac_len = 0;
    ret = CRYPTO_readFile(mac_file, &mac_tag, &mac_len);
    if (ret != CRYPTO_OK) {
        printf("[오류] MAC 태그 파일 읽기 실패: %s\n", mac_file);
        free(file_data);
        return ret;
    }

    if (mac_len < (size_t)tag_len) {
        printf("[오류] MAC 태그 파일이 너무 짧습니다.\n");
        free(file_data);
        free(mac_tag);
        return CRYPTO_ERR_PARAM;
    }

    // HMAC salt 입력 (선택사항, 엔터 시 NULL)
    byte salt[64] = { 0 };
    size_t salt_len = 0;
    printf("HMAC salt 입력 (HMAC 생성 시 사용한 salt, 엔터: 사용 안 함, 16진수 또는 텍스트): ");
    char salt_input[256];
    if (fgets(salt_input, sizeof(salt_input), stdin) != NULL) {
        size_t salt_input_len = strlen(salt_input);
        if (salt_input_len > 0 && salt_input[salt_input_len - 1] == '\n') {
            salt_input[salt_input_len - 1] = '\0';
            salt_input_len--;
        }

        if (salt_input_len > 0) {
            if (salt_input_len >= 2 && salt_input[0] == '0' && (salt_input[1] == 'x' || salt_input[1] == 'X')) {
                // 16진수 파싱
                const char* hex_str = salt_input + 2;
                size_t hex_len = strlen(hex_str);
                salt_len = hex_len / 2;
                if (salt_len > 64) salt_len = 64;

                for (size_t i = 0; i < salt_len; i++) {
                    char hex_byte[3] = { hex_str[i * 2], hex_str[i * 2 + 1], '\0' };
                    salt[i] = (byte)strtol(hex_byte, NULL, 16);
                }
            }
            else {
                // 텍스트로 처리
                salt_len = (salt_input_len < 64) ? salt_input_len : 64;
                memcpy(salt, salt_input, salt_len);
            }
            printf("[정보] Salt가 입력되었습니다 (%zu 바이트)\n", salt_len);
        }
    }

    // HMAC 검증
    printf("HMAC 검증 중...\n");
    ret = Vrfy(salt_len > 0 ? salt : NULL, salt_len, key, key_len, tag_len, file_data, file_len, mac_tag);
    free(file_data);
    free(mac_tag);

    clock_t end_time = clock();
    double elapsed = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    if (ret == CRYPTO_OK) {
        printf("\n[성공] HMAC 검증 성공! 파일이 변조되지 않았습니다.\n");
        printf("  입력 파일: %s\n", input_file);
        printf("  MAC 태그 파일: %s\n", mac_file);
        printf("  처리 시간: %.2f 초\n", elapsed);
    }
    else if (ret == CRYPTO_ERR_INVALID) {
        printf("\n[실패] HMAC 검증 실패! 파일이 변조되었거나 키가 잘못되었습니다.\n");
        printf("  입력 파일: %s\n", input_file);
        printf("  MAC 태그 파일: %s\n", mac_file);
        printf("  처리 시간: %.2f 초\n", elapsed);
    }
    else {
        printf("\n[오류] HMAC 검증 중 오류 발생: %d\n", ret);
    }

    return ret;
}

int main(int argc, char* argv[]) {
    printf("+===========================================================+\n");
    printf("|   암호화/해시/HMAC 프로그램 (AES, SHA-512, HMAC)          |\n");
    printf("+===========================================================+\n\n");

    // 메인 루프: 사용자가 종료할 때까지 계속 실행
    while (1) {
        char input[256];
        char input_file[256];
        char output_file[256];
        char key_file[256];
        int key_len = 32;
        int use_ctr = 1;  // 기본값: CTR
        AES_Impl aes_impl = AES_IMPL_TBL;  // 기본값: T-Table

        // 1. 작업 선택
        int operation = 0;
        while (1) {
            get_user_input(input, sizeof(input), "작업 선택 (1: 암호화, 2: 복호화, 3: HMAC 생성, 4: HMAC 검증, 5: 키 생성, 0: 종료): ");
            if (strcmp(input, "1") == 0) {
                operation = 1;
                break;
            }
            else if (strcmp(input, "2") == 0) {
                operation = 2;
                break;
            }
            else if (strcmp(input, "3") == 0) {
                operation = 3;
                break;
            }
            else if (strcmp(input, "4") == 0) {
                operation = 4;
                break;
            }
            else if (strcmp(input, "5") == 0) {
                operation = 5;
                break;
            }
            else if (strcmp(input, "0") == 0) {
                printf("\n프로그램을 종료합니다.\n");
                return 0;
            }
            else {
                printf("[오류] 0, 1, 2, 3, 4, 또는 5를 입력하세요.\n");
            }
        }

        // HMAC 생성인 경우
        if (operation == 3) {
            get_user_input(input_file, sizeof(input_file), "입력 파일 경로: ");
            if (strlen(input_file) == 0) {
                printf("[오류] 입력 파일 경로를 입력해야 합니다.\n");
                printf("\n");
                continue;
            }
            get_user_input(output_file, sizeof(output_file), "출력 파일 경로 (MAC 태그 저장): ");
            if (strlen(output_file) == 0) {
                printf("[오류] 출력 파일 경로를 입력해야 합니다.\n");
                printf("\n");
                continue;
            }
            int tag_len = 64;
            get_user_input(input, sizeof(input), "MAC 태그 길이 (바이트, 최대 64) [기본: 64]: ");
            if (strlen(input) > 0) {
                tag_len = atoi(input);
                if (tag_len <= 0 || tag_len > 64) {
                    printf("[오류] MAC 태그 길이는 1부터 64 사이의 값이어야 합니다.\n");
                    printf("\n");
                    continue;
                }
            }
            int ret = generate_hmac(input_file, output_file, NULL, tag_len);
            if (ret != CRYPTO_OK) {
                printf("\n[오류] HMAC 생성 실패\n");
            }
            printf("\n");
            continue;  // 다음 작업으로
        }

        // HMAC 검증인 경우
        if (operation == 4) {
            get_user_input(input_file, sizeof(input_file), "입력 파일 경로: ");
            if (strlen(input_file) == 0) {
                printf("[오류] 입력 파일 경로를 입력해야 합니다.\n");
                printf("\n");
                continue;
            }
            get_user_input(output_file, sizeof(output_file), "MAC 태그 파일 경로: ");
            if (strlen(output_file) == 0) {
                printf("[오류] MAC 태그 파일 경로를 입력해야 합니다.\n");
                printf("\n");
                continue;
            }
            int tag_len = 64;
            get_user_input(input, sizeof(input), "MAC 태그 길이 (바이트, 최대 64) [기본: 64]: ");
            if (strlen(input) > 0) {
                tag_len = atoi(input);
                if (tag_len <= 0 || tag_len > 64) {
                    printf("[오류] MAC 태그 길이는 1부터 64 사이의 값이어야 합니다.\n");
                    printf("\n");
                    continue;
                }
            }
            int ret = verify_hmac(input_file, output_file, NULL, tag_len);
            if (ret != CRYPTO_OK) {
                printf("\n[오류] HMAC 검증 실패\n");
            }
            printf("\n");
            continue;  // 다음 작업으로
        }

        // 키 생성인 경우
        if (operation == 5) {
            // 키 타입 선택
            int key_type = 0;
            while (1) {
                get_user_input(input, sizeof(input), "키 타입 선택 (1: AES 키, 2: HMAC 키) [기본: 1]: ");
                if (strlen(input) == 0 || strcmp(input, "1") == 0) {
                    key_type = 1;
                    break;
                }
                else if (strcmp(input, "2") == 0) {
                    key_type = 2;
                    break;
                }
                else {
                    printf("[오류] 1 또는 2를 입력하세요.\n");
                }
            }

            if (key_type == 1) {
                // AES 키 생성
                int aes_key_len = 32;  // 기본 256비트
                while (1) {
                    get_user_input(input, sizeof(input), "AES 키 길이 선택 (1: 128비트/16바이트, 2: 192비트/24바이트, 3: 256비트/32바이트) [기본: 3]: ");
                    if (strlen(input) == 0 || strcmp(input, "3") == 0) {
                        aes_key_len = 32;
                        break;
                    }
                    else if (strcmp(input, "1") == 0) {
                        aes_key_len = 16;
                        break;
                    }
                    else if (strcmp(input, "2") == 0) {
                        aes_key_len = 24;
                        break;
                    }
                    else {
                        printf("[오류] 1, 2, 또는 3을 입력하세요.\n");
                    }
                }

                get_user_input(output_file, sizeof(output_file), "키 저장 파일 경로: ");
                if (strlen(output_file) == 0) {
                    printf("[오류] 파일 경로를 입력해야 합니다.\n");
                    printf("\n");
                    continue;
                }

                // 랜덤 키 생성
                byte* key = (byte*)malloc(aes_key_len);
                if (!key) {
                    crypto_error_print(CRYPTO_ERR_MEMORY, "메모리 할당 실패");
                    printf("\n");
                    continue;
                }

                printf("랜덤 키 생성 중...\n");
                int ret = CRYPTO_randomBytes(key, aes_key_len);
                if (ret != CRYPTO_OK) {
                    printf("[오류] 키 생성 실패\n");
                    free(key);
                    printf("\n");
                    continue;
                }

                // 파일에 저장
                ret = CRYPTO_writeFile(output_file, key, aes_key_len);
                free(key);

                if (ret != CRYPTO_OK) {
                    printf("[오류] 키 파일 저장 실패: %s\n", output_file);
                    printf("\n");
                    continue;
                }

                printf("\n[성공] AES 키 생성 완료!\n");
                printf("  키 길이: %d 바이트 (AES-%d)\n", aes_key_len, aes_key_len * 8);
                printf("  저장 위치: %s\n", output_file);
                printf("  [주의] 생성된 키를 안전하게 보관하세요!\n");
                printf("\n");
                continue;  // 다음 작업으로
            }
            else {
                // HMAC 키 생성 (GenKey 사용)
                int hmac_key_bits = 256;  // 기본 256비트
                while (1) {
                    get_user_input(input, sizeof(input), "HMAC 키 길이 (비트) [기본: 256]: ");
                    if (strlen(input) == 0) {
                        hmac_key_bits = 256;
                        break;
                    }
                    else {
                        hmac_key_bits = atoi(input);
                        if (hmac_key_bits > 0 && hmac_key_bits <= 512) {
                            break;
                        }
                        else {
                            printf("[오류] 1부터 512 사이의 값을 입력하세요.\n");
                        }
                    }
                }

                get_user_input(output_file, sizeof(output_file), "HMAC 키 저장 파일 경로: ");
                if (strlen(output_file) == 0) {
                    printf("[오류] 파일 경로를 입력해야 합니다.\n");
                    printf("\n");
                    continue;
                }

                size_t key_byte_len = (hmac_key_bits + 7) / 8;
                byte* salt = (byte*)malloc(key_byte_len);
                byte* key = (byte*)malloc(key_byte_len);
                if (!salt || !key) {
                    crypto_error_print(CRYPTO_ERR_MEMORY, "메모리 할당 실패");
                    if (salt) free(salt);
                    if (key) free(key);
                    printf("\n");
                    continue;
                }

                printf("HMAC 키 생성 중 (GenKey 사용)...\n");
                int ret = GenKey(hmac_key_bits, salt, key);
                if (ret != CRYPTO_OK) {
                    printf("[오류] HMAC 키 생성 실패\n");
                    free(salt);
                    free(key);
                    printf("\n");
                    continue;
                }

                // 키만 저장 (salt는 필요시 별도 저장 가능)
                ret = CRYPTO_writeFile(output_file, key, key_byte_len);
                free(salt);
                free(key);

                if (ret != CRYPTO_OK) {
                    printf("[오류] HMAC 키 파일 저장 실패: %s\n", output_file);
                    printf("\n");
                    continue;
                }

                printf("\n[성공] HMAC 키 생성 완료!\n");
                printf("  키 길이: %d 비트 (%zu 바이트)\n", hmac_key_bits, key_byte_len);
                printf("  저장 위치: %s\n", output_file);
                printf("  [주의] 생성된 키를 안전하게 보관하세요!\n");
                printf("\n");
                continue;  // 다음 작업으로
            }
        }

        // 암호화/복호화인 경우 (기존 로직)
        if (operation == 1 || operation == 2) {
            int is_encrypt = (operation == 1);

            // 2. 입력 파일 경로
            get_user_input(input_file, sizeof(input_file), "입력 파일 경로: ");
            if (strlen(input_file) == 0) {
                printf("[오류] 입력 파일 경로를 입력해야 합니다.\n");
                printf("\n");
                continue;
            }

            // 3. 출력 파일 경로
            get_user_input(output_file, sizeof(output_file), "출력 파일 경로: ");
            if (strlen(output_file) == 0) {
                printf("[오류] 출력 파일 경로를 입력해야 합니다.\n");
                printf("\n");
                continue;
            }

            // 4. 키 파일 경로 (빈 값이면 직접 입력)
            get_user_input(key_file, sizeof(key_file), "키 파일 경로 (엔터: 직접 입력): ");
            const char* key_file_ptr = (strlen(key_file) > 0) ? key_file : NULL;

            // 5. 키 길이 선택
            while (1) {
                get_user_input(input, sizeof(input), "키 길이 선택 (1: AES-128, 2: AES-192, 3: AES-256) [기본: 3]: ");
                if (strlen(input) == 0 || strcmp(input, "3") == 0) {
                    key_len = 32;
                    break;
                }
                else if (strcmp(input, "1") == 0) {
                    key_len = 16;
                    break;
                }
                else if (strcmp(input, "2") == 0) {
                    key_len = 24;
                    break;
                }
                else {
                    printf("[오류] 1, 2, 또는 3을 입력하세요.\n");
                }
            }

            // 6. 암호화 모드 선택
            while (1) {
                get_user_input(input, sizeof(input), "암호화 모드 선택 (1: CBC, 2: CTR) [기본: 2]: ");
                if (strlen(input) == 0 || strcmp(input, "2") == 0) {
                    use_ctr = 1;
                    break;
                }
                else if (strcmp(input, "1") == 0) {
                    use_ctr = 0;
                    break;
                }
                else {
                    printf("[오류] 1 또는 2를 입력하세요.\n");
                }
            }

            // 7. AES 구현 방식 선택
            while (1) {
                get_user_input(input, sizeof(input), "AES 구현 선택 (1: Reference, 2: T-Table) [기본: 2]: ");
                if (strlen(input) == 0 || strcmp(input, "2") == 0) {
                    aes_impl = AES_IMPL_TBL;
                    break;
                }
                else if (strcmp(input, "1") == 0) {
                    aes_impl = AES_IMPL_REF;
                    break;
                }
                else {
                    printf("[오류] 1 또는 2를 입력하세요.\n");
                }
            }

            // 8. HMAC 사용 여부 (Encrypt-then-MAC)
            int use_hmac = 1;  // 기본값: 사용
            byte hmac_key[64] = { 0 };
            int hmac_key_len = 0;
            int hmac_tag_len = 64;
            byte hmac_salt[64] = { 0 };
            size_t hmac_salt_len = 0;

            while (1) {
                get_user_input(input, sizeof(input), "HMAC 사용 (Encrypt-then-MAC) (1: 사용, 2: 사용 안 함) [기본: 1]: ");
                if (strlen(input) == 0 || strcmp(input, "1") == 0) {
                    use_hmac = 1;
                    break;
                }
                else if (strcmp(input, "2") == 0) {
                    use_hmac = 0;
                    break;
                }
                else {
                    printf("[오류] 1 또는 2를 입력하세요.\n");
                }
            }

            if (use_hmac) {
                // HMAC salt 입력 (선택사항)
                get_user_input(input, sizeof(input), "HMAC salt 입력 (엔터: salt 사용 안 함, 16진수 또는 텍스트): ");
                if (strlen(input) == 0) {
                    // salt 사용 안 함
                    hmac_salt_len = 0;
                    printf("[정보] Salt를 사용하지 않습니다.\n");
                }
                else {
                    // 사용자 입력
                    size_t salt_input_len = strlen(input);
                    if (salt_input_len >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
                        // 16진수 파싱
                        const char* hex_str = input + 2;
                        size_t hex_len = strlen(hex_str);
                        hmac_salt_len = hex_len / 2;
                        if (hmac_salt_len > 64) hmac_salt_len = 64;

                        for (size_t i = 0; i < hmac_salt_len; i++) {
                            char hex_byte[3] = { hex_str[i * 2], hex_str[i * 2 + 1], '\0' };
                            hmac_salt[i] = (byte)strtol(hex_byte, NULL, 16);
                        }
                    }
                    else {
                        // 텍스트로 처리
                        hmac_salt_len = (salt_input_len < 64) ? salt_input_len : 64;
                        memcpy(hmac_salt, input, hmac_salt_len);
                    }
                    printf("[정보] Salt가 입력되었습니다 (%zu 바이트)\n", hmac_salt_len);
                }
                // HMAC 키 파일 경로 (빈 값이면 직접 입력)
                char hmac_key_file[256];
                get_user_input(hmac_key_file, sizeof(hmac_key_file), "HMAC 키 파일 경로 (엔터: 직접 입력): ");
                const char* hmac_key_file_ptr = (strlen(hmac_key_file) > 0) ? hmac_key_file : NULL;

                // HMAC 키 로드
                if (hmac_key_file_ptr) {
                    byte* hmac_key_data = NULL;
                    size_t hmac_key_data_len = 0;
                    int ret = CRYPTO_readFile(hmac_key_file_ptr, &hmac_key_data, &hmac_key_data_len);
                    if (ret != CRYPTO_OK) {
                        printf("[오류] HMAC 키 파일 읽기 실패: %s\n", hmac_key_file_ptr);
                        printf("\n");
                        continue;
                    }
                    hmac_key_len = (int)(hmac_key_data_len < 64 ? hmac_key_data_len : 64);
                    memcpy(hmac_key, hmac_key_data, hmac_key_len);
                    free(hmac_key_data);
                    printf("[정보] HMAC 키 파일에서 키를 읽었습니다: %s\n", hmac_key_file_ptr);
                }
                else {
                    // 직접 입력
                    printf("HMAC 키를 입력하세요 (최대 64바이트, 16진수 또는 텍스트): ");
                    char hmac_key_input[256];
                    if (fgets(hmac_key_input, sizeof(hmac_key_input), stdin) == NULL) {
                        printf("\n");
                        continue;
                    }

                    size_t hmac_key_input_len = strlen(hmac_key_input);
                    if (hmac_key_input_len > 0 && hmac_key_input[hmac_key_input_len - 1] == '\n') {
                        hmac_key_input[hmac_key_input_len - 1] = '\0';
                        hmac_key_input_len--;
                    }

                    if (hmac_key_input_len >= 2 && hmac_key_input[0] == '0' && (hmac_key_input[1] == 'x' || hmac_key_input[1] == 'X')) {
                        const char* hex_str = hmac_key_input + 2;
                        size_t hex_len = strlen(hex_str);
                        hmac_key_len = (int)(hex_len / 2);
                        if (hmac_key_len > 64) hmac_key_len = 64;

                        for (int i = 0; i < hmac_key_len; i++) {
                            char hex_byte[3] = { hex_str[i * 2], hex_str[i * 2 + 1], '\0' };
                            hmac_key[i] = (byte)strtol(hex_byte, NULL, 16);
                        }
                    }
                    else {
                        hmac_key_len = (int)(hmac_key_input_len < 64 ? hmac_key_input_len : 64);
                        memcpy(hmac_key, hmac_key_input, hmac_key_len);
                    }
                }

                // HMAC 태그 길이 입력
                get_user_input(input, sizeof(input), "HMAC 태그 길이 (바이트, 최대 64) [기본: 64]: ");
                if (strlen(input) > 0) {
                    hmac_tag_len = atoi(input);
                    if (hmac_tag_len <= 0 || hmac_tag_len > 64) {
                        printf("[오류] HMAC 태그 길이는 1부터 64 사이의 값이어야 합니다.\n");
                        printf("\n");
                        continue;
                    }
                }
            }

            printf("\n");
            printf("=== 설정 확인 ===\n");
            printf("작업: %s\n", is_encrypt ? "암호화" : "복호화");
            printf("입력 파일: %s\n", input_file);
            printf("출력 파일: %s\n", output_file);
            printf("키 파일: %s\n", key_file_ptr ? key_file_ptr : "(직접 입력)");
            printf("키 길이: %d 바이트 (AES-%d)\n", key_len, key_len * 8);
            printf("암호화 모드: %s\n", use_ctr ? "CTR" : "CBC");
            printf("AES 구현: %s\n", aes_impl == AES_IMPL_TBL ? "T-Table" : "Reference");
            if (use_hmac) {
                if (hmac_salt_len > 0) {
                    printf("HMAC: 사용 (Encrypt-then-MAC, 태그 길이: %d 바이트, salt 길이: %zu 바이트)\n",
                        hmac_tag_len, hmac_salt_len);
                    printf("  Salt 값: 0x");
                    CRYPTO_printHex(hmac_salt, (int)hmac_salt_len);
                    printf("\n");
                }
                else {
                    printf("HMAC: 사용 (Encrypt-then-MAC, 태그 길이: %d 바이트, salt: 사용 안 함)\n",
                        hmac_tag_len);
                }
            }
            else {
                printf("HMAC: 사용 안 함\n");
            }
            printf("\n");

            // 키 로드
            byte key[32];
            int ret = load_key(key_file_ptr, key, key_len);
            if (ret != CRYPTO_OK) {
                printf("\n");
                continue;
            }

            printf("\n");

            // 암호화 또는 복호화 수행
            if (is_encrypt) {
                if (use_ctr) {
                    ret = crypt_file_ctr(input_file, output_file, key, key_len, aes_impl, 1,
                        use_hmac, hmac_key, hmac_key_len, hmac_tag_len,
                        hmac_salt, hmac_salt_len);
                }
                else {
                    ret = encrypt_file_cbc(input_file, output_file, key, key_len, aes_impl,
                        use_hmac, hmac_key, hmac_key_len, hmac_tag_len,
                        hmac_salt, hmac_salt_len);
                }
            }
            else {
                if (use_ctr) {
                    ret = crypt_file_ctr(input_file, output_file, key, key_len, aes_impl, 0,
                        use_hmac, hmac_key, hmac_key_len, hmac_tag_len,
                        hmac_salt, hmac_salt_len);
                }
                else {
                    ret = decrypt_file_cbc(input_file, output_file, key, key_len, aes_impl,
                        use_hmac, hmac_key, hmac_key_len, hmac_tag_len,
                        hmac_salt, hmac_salt_len);
                }
            }

            if (ret != CRYPTO_OK) {
                printf("\n[오류] 작업 실패\n");
            }
            printf("\n");
            continue;  // 다음 작업으로
        }  // if (operation == 1 || operation == 2) 끝
    }  // while 루프 끝

    return 0;  // 이 코드는 실행되지 않음 (루프에서 return으로 종료)
}