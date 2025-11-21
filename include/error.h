#ifndef ERROR_H
#define ERROR_H

#include <stdio.h>

/* =========================================================
 * 에러 코드 정의
 * ========================================================= */

 // 성공
#define CRYPTO_OK             0

// 일반 오류
#define CRYPTO_ERR_PARAM      -1    // 잘못된 파라미터 (NULL 포인터, 잘못된 길이 등)
#define CRYPTO_ERR_KEYLEN     -2    // 지원하지 않는 키 길이
#define CRYPTO_ERR_MODE       -3    // 지원하지 않는 모드
#define CRYPTO_ERR_PADDING    -4    // 패딩 오류 (CBC 패딩 검증 실패 등)
#define CRYPTO_ERR_MEMORY     -5    // 메모리 오류 (할당 실패 등)
#define CRYPTO_ERR_INTERNAL   -6    // 내부 오류 (예상치 못한 오류)
#define CRYPTO_ERR_BUFFER     -7    // 버퍼 크기 부족
#define CRYPTO_ERR_INVALID    -8    // 잘못된 입력 데이터
#define CRYPTO_ERR_IO         -9   // 입출력 오류
#define CRYPTO_ERR_RANDOM     -10   // 난수 생성 오류

/* =========================================================
 * 에러 처리 함수
 * ========================================================= */

 /**
  * @brief 에러 코드에 해당하는 에러 메시지를 반환
  * @param err_code 에러 코드
  * @return 에러 메시지 문자열 (NULL이면 알 수 없는 오류)
  */
const char* crypto_error_string(int err_code);

/**
 * @brief 에러 코드를 stderr에 출력
 * @param err_code 에러 코드
 * @param context 추가 컨텍스트 정보 (NULL 가능)
 */
void crypto_error_print(int err_code, const char* context);

/**
 * @brief 에러 코드가 성공인지 확인
 * @param err_code 에러 코드
 * @return 1이면 성공, 0이면 실패
 */
int crypto_is_success(int err_code);

/**
 * @brief 에러 코드가 실패인지 확인
 * @param err_code 에러 코드
 * @return 1이면 실패, 0이면 성공
 */
int crypto_is_error(int err_code);

#endif // ERROR_H

