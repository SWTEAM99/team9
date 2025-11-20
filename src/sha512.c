#include "sha512.h"
#include <string.h>  // memcpy, memset 사용


// 매크로 & 상수
#define ROTR(x,n)   (((x) >> (n)) | ((x) << (64 - (n))))
#define SHR(x,n)    ((x) >> (n))

// Case w=64 
#define SIGMA0(x)   (ROTR((x),28) ^ ROTR((x),34) ^ ROTR((x),39))   // Σ0
#define SIGMA1(x)   (ROTR((x),14) ^ ROTR((x),18) ^ ROTR((x),41))   // Σ1
#define sigma0(x)   (ROTR((x), 1) ^ ROTR((x), 8) ^ SHR((x), 7))    // σ0
#define sigma1(x)   (ROTR((x),19) ^ ROTR((x),61) ^ SHR((x), 6))    // σ1
#define Ch(x,y,z)   (((x)&(y)) ^ (~(x)&(z)))
#define Maj(x,y,z)  (((x)&(y)) ^ ((x)&(z)) ^ ((y)&(z)))

// 초기 IV (필기 1.1.3 “SHA2-512 IV”)
static const uint64_t H0[8] = {
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

// K[0..79] (80-step 상수)
static const uint64_t K[80] = {
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
  0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

// big-endian 로드/스토어 (SHA-512 규격)
// 바이트 배열 p[0..7]을 big-endian으로 읽어 64비트 정수로 조립
static inline uint64_t load_be64(const uint8_t* p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
        ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
        ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
        ((uint64_t)p[6] << 8) | ((uint64_t)p[7]);
}

// 64비트 정수 x를 big-endian 바이트 배열로 분해해 저장
static inline void store_be64(uint8_t* dst, uint64_t val)
{
    dst[0] = (uint8_t)(val >> 56);
    dst[1] = (uint8_t)(val >> 48);
    dst[2] = (uint8_t)(val >> 40);
    dst[3] = (uint8_t)(val >> 32);
    dst[4] = (uint8_t)(val >> 24);
    dst[5] = (uint8_t)(val >> 16);
    dst[6] = (uint8_t)(val >> 8);
    dst[7] = (uint8_t)(val >> 0);
}

// 메시지 확장 + 80-step 압축
static void sha512_transform(SHA512_CTX* ctx, const uint8_t block[SHA512_BLOCK_SIZE]) {
    uint64_t W[80];
    for (int t = 0; t < 16; ++t) W[t] = load_be64(block + 8 * t);              // 입력 블록(128바이트)을 64비트 단위 W[0...15]에 로드
    for (int t = 16; t < 80; ++t)
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];    // 메시지 확장

    // 현재 체이닝 값(H0..H7)을 워킹 변수 a..h로 복사(라운드 수행용)
    uint64_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint64_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];


    // 80라운드 step 수행
    for (int t = 0; t < 80; ++t) {
        uint64_t T1 = h + SIGMA1(e) + Ch(e, f, g) + K[t] + W[t];  // T1 계산
        uint64_t T2 = SIGMA0(a) + Maj(a, b, c);                   // T2 계산
        h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;   // 레지스터(a...h) 시프트/갱신
    }

    // 라운드가 끝난 a...h를 원래 state에 더해 누적 (Merkle Damgard + Davies Meyer)
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

// 초기 상태를 IV로 세팅, 총 길이/버퍼 길이 초기화
void SHA512_init(SHA512_CTX* ctx) {
    memcpy(ctx->state, H0, sizeof(H0));
    ctx->bitlen[0] = ctx->bitlen[1] = 0;
    ctx->datalen = 0;
}

// 총 비트 길이 누적 보조
static inline void add_bits(SHA512_CTX* ctx, uint64_t bits) {
    // 128비트 누적 (하위 64비트에 더하다 overflow면 상위 64비트 + 1)
    uint64_t lo = ctx->bitlen[1] + bits;
    if (lo < ctx->bitlen[1]) ctx->bitlen[0]++; // carry 발생 시 상위 64비트 증가
    ctx->bitlen[1] = lo;
}
// 들어온 바이트 수를 비트 수(x8)로 변환해 총 길이에 누적
void SHA512_update(SHA512_CTX* ctx, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->buffer[ctx->datalen++] = data[i];
        if (ctx->datalen == SHA512_BLOCK_SIZE) {
            sha512_transform(ctx, ctx->buffer);

            // ---- 길이 누적 수정 ----
            // 하위(low) 비트부터 더하고, 오버플로우 시 상위(high)를 1 증가
            ctx->bitlen[1] += 1024; // 한 블록 = 128바이트 = 1024비트
            if (ctx->bitlen[1] < 1024)
                ctx->bitlen[0]++;

            ctx->datalen = 0;
        }
    }
}

// 패딩 + 마지막 변환 + 출력
void SHA512_final(SHA512_CTX* ctx, uint8_t out[SHA512_DIGEST_SIZE]) {

    // 0) 남아 있는 데이터 길이를 길이 누적에 먼저 반영 (비트 단위)
    //    반드시 0x80를 붙이기 전에!
    uint32_t rem = ctx->datalen;

    // add_bits: (하위 64비트 += bits; 오버플로 시 상위 64비트 carry)
    add_bits(ctx, (uint64_t)rem * 8);

    // One-zeros-bitlen(2w) padding 
    // 1) 0x80 추가
    ctx->buffer[ctx->datalen++] = 0x80;

    // 2) 마지막 16바이트(128bit) 직전까지 0 채우기
    if (ctx->datalen > SHA512_BLOCK_SIZE - 16) {
        // 남은 공간이 부족하면 현재 블록 0 채움 후 transform -> 새 블록에서 길이 기록
        while (ctx->datalen < SHA512_BLOCK_SIZE) ctx->buffer[ctx->datalen++] = 0x00;
        sha512_transform(ctx, ctx->buffer);
        ctx->datalen = 0;
    }
    while (ctx->datalen < SHA512_BLOCK_SIZE - 16) ctx->buffer[ctx->datalen++] = 0x00;

    // 3) 총 비트 길이(128비트) big-endian 저장 (수정 완료)
    uint8_t len_be[16];
    store_be64(len_be + 0, ctx->bitlen[0]);  // 상위 64비트
    store_be64(len_be + 8, ctx->bitlen[1]);  // 하위 64비트
    memcpy(ctx->buffer + SHA512_BLOCK_SIZE - 16, len_be, 16);





    sha512_transform(ctx, ctx->buffer);   // 패딩된 마지막 블록 압축

    // 4) digest 출력(big-endian)
    // 최종 state[0...7]를 big-endian 64바이트로 직렬화 -> 최종 해시
    for (int i = 0; i < 8; ++i) store_be64(out + 8 * i, ctx->state[i]);

    // 민감 상태 지우기
    memset(ctx, 0, sizeof(*ctx));
}

