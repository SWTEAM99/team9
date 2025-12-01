/**
 * @file utils.h
 * @brief 유틸리티 함수 헤더 파일
 * @details 파일 읽기/쓰기, 16진수 출력, 데이터 비교 등의 유틸리티 함수를 제공합니다.
 */

#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>  // size_t

 /* 바이트 타입 정의 (crypto_api.h와 중복 방지) */
#ifndef BYTE_TYPE_DEFINED
#define BYTE_TYPE_DEFINED
typedef unsigned char byte;
#endif

/**
 * @brief 데이터를 16진수로 출력
 * @param data 출력할 데이터
 * @param len 데이터 길이 (바이트)
 */
void UTIL_printHex(const byte* data, int len);

/**
 * @brief 두 데이터가 같은지 비교 (타이밍 공격 방지)
 * @param a 첫 번째 데이터
 * @param b 두 번째 데이터
 * @param len 비교할 길이 (바이트)
 * @return 1 같음, 0 다름
 */
int UTIL_isEqual(const byte* a, const byte* b, int len);

/**
 * @brief 파일 전체를 읽어서 메모리에 저장
 * @param filename 파일 경로
 * @param data 읽은 데이터를 저장할 버퍼 포인터 (호출자가 free해야 함)
 * @param len 읽은 데이터 길이 (바이트)
 * @return CRYPTO_OK 성공, CRYPTO_ERR_PARAM/CRYPTO_ERR_MEMORY/CRYPTO_ERR_INTERNAL 실패
 */
int UTIL_readFile(const char* filename, byte** data, size_t* len);

/**
 * @brief 데이터를 파일에 저장
 * @param filename 파일 경로
 * @param data 저장할 데이터
 * @param len 데이터 길이 (바이트)
 * @return CRYPTO_OK 성공, CRYPTO_ERR_PARAM/CRYPTO_ERR_INTERNAL 실패
 */
int UTIL_writeFile(const char* filename, const byte* data, size_t len);

#endif /* UTILS_H */