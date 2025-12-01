#include "utils.h"
#include "error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 헤더에 선언된 이름에 맞춘 구현 */
void UTIL_printHex(const byte* data, int len) {
    if (!data || len < 0) return;
    for (int i = 0; i < len; ++i) {
        printf("%02X", (unsigned)data[i]);
    }
    printf("\n");
}

int UTIL_isEqual(const byte* a, const byte* b, int len) {
    if (!a || !b || len < 0) return 0;
    unsigned char acc = 0;
    for (int i = 0; i < len; ++i) {
        acc |= (unsigned char)(a[i] ^ b[i]);
    }
    return acc == 0;
}

/* ================================================================
 * 파일 읽기/쓰기 유틸리티 함수
 * ================================================================ */

 /**
  * @brief 파일 전체를 읽어서 메모리에 저장
  * @param filename 파일 경로
  * @param data 읽은 데이터를 저장할 버퍼 포인터 (호출자가 free해야 함)
  * @param len 읽은 데이터 길이 (바이트)
  * @return CRYPTO_OK 성공, CRYPTO_ERR_PARAM/CRYPTO_ERR_INTERNAL 실패
  */
int UTIL_readFile(const char* filename, byte** data, size_t* len) {
    if (!filename || !data || !len) return CRYPTO_ERR_PARAM;

    FILE* f = fopen(filename, "rb");
    if (!f) return CRYPTO_ERR_INTERNAL;

    // 파일 크기 확인
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    if (file_size < 0) {
        fclose(f);
        return CRYPTO_ERR_INTERNAL;
    }
    fseek(f, 0, SEEK_SET);

    // 메모리 할당
    byte* buf = (byte*)malloc((size_t)file_size);
    if (!buf) {
        fclose(f);
        return CRYPTO_ERR_MEMORY;
    }

    // 파일 읽기
    size_t read_bytes = fread(buf, 1, (size_t)file_size, f);
    fclose(f);

    if (read_bytes != (size_t)file_size) {
        free(buf);
        return CRYPTO_ERR_INTERNAL;
    }

    *data = buf;
    *len = read_bytes;
    return CRYPTO_OK;
}

/**
 * @brief 데이터를 파일에 저장
 * @param filename 파일 경로
 * @param data 저장할 데이터
 * @param len 데이터 길이 (바이트)
 * @return CRYPTO_OK 성공, CRYPTO_ERR_PARAM/CRYPTO_ERR_INTERNAL 실패
 */
int UTIL_writeFile(const char* filename, const byte* data, size_t len) {
    if (!filename || !data) return CRYPTO_ERR_PARAM;

    FILE* f = fopen(filename, "wb");
    if (!f) return CRYPTO_ERR_INTERNAL;

    size_t written = fwrite(data, 1, len, f);
    fclose(f);

    if (written != len) return CRYPTO_ERR_INTERNAL;
    return CRYPTO_OK;
}
