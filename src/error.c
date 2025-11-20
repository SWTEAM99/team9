#include "error.h"
#include <string.h>

/* =========================================================
 * 에러 메시지 문자열 반환
 * ========================================================= */
const char* crypto_error_string(int err_code) {
    switch (err_code) {
    case CRYPTO_OK:
        return "Success";
    case CRYPTO_ERR_PARAM:
        return "Invalid parameter";
    case CRYPTO_ERR_KEYLEN:
        return "Unsupported key length";
    case CRYPTO_ERR_MODE:
        return "Unsupported mode";
    case CRYPTO_ERR_PADDING:
        return "Padding error";
    case CRYPTO_ERR_MEMORY:
        return "Memory allocation error";
    case CRYPTO_ERR_INTERNAL:
        return "Internal error";
    case CRYPTO_ERR_BUFFER:
        return "Buffer too small";
    case CRYPTO_ERR_INVALID:
        return "Invalid input data";
    case CRYPTO_ERR_NOT_IMPL:
        return "Not implemented";
    case CRYPTO_ERR_IO:
        return "I/O error";
    case CRYPTO_ERR_RANDOM:
        return "Random number generation error";
    default:
        return "Unknown error";
    }
}

/* =========================================================
 * 에러 출력 함수
 * ========================================================= */
void crypto_error_print(int err_code, const char* context) {
    if (err_code == CRYPTO_OK) {
        return;  // 성공이면 출력하지 않음
    }

    const char* err_msg = crypto_error_string(err_code);

    if (context && strlen(context) > 0) {
        fprintf(stderr, "[ERROR] %s (code: %d) - %s\n", err_msg, err_code, context);
    }
    else {
        fprintf(stderr, "[ERROR] %s (code: %d)\n", err_msg, err_code);
    }
}

/* =========================================================
 * 에러 코드 확인 함수
 * ========================================================= */
int crypto_is_success(int err_code) {
    return (err_code == CRYPTO_OK);
}

int crypto_is_error(int err_code) {
    return (err_code != CRYPTO_OK);
}

