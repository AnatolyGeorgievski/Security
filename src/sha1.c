/* SHA-1, FIPS 180-4. PKCS#1 and OpenPGP hash alg 2. */
#include "hmac.h"
#include <stdint.h>
#include <stddef.h>

typedef struct _HashCtx HashCtx;
struct _HashCtx {
    uint32_t H[5];
    uint32_t buffer[16];
    uint32_t length;
};

static void ntohl_vec(uint32_t *v, int len)
{
#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    do { *v = __builtin_bswap32(*v), v++; } while (--len);
#endif
}
#undef htole32
static uint32_t htole32(uint32_t v)
{
#if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    return __builtin_bswap32(v);
#else
    return v;
#endif
}
static inline uint32_t ROTR(uint32_t v, int i)
{
    return (v << (32 - i)) | (v >> i);
}
static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline uint32_t Parity(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }

#define R1(a,b,c,d,e,t) ({ e += ROTR(a, 27) + Ch(b,c,d) + 0x5a827999 + W[t]; b = ROTR(b,2); })
#define R2(a,b,c,d,e,t) ({ e += ROTR(a, 27) + Parity(b,c,d) + 0x6ed9eba1 + W[t]; b = ROTR(b,2); })
#define R3(a,b,c,d,e,t) ({ e += ROTR(a, 27) + Maj(b,c,d) + 0x8f1bbcdc + W[t]; b = ROTR(b,2); })
#define R4(a,b,c,d,e,t) ({ e += ROTR(a, 27) + Parity(b,c,d) + 0xca62c1d6 + W[t]; b = ROTR(b,2); })

static void SHA1(uint32_t *H, uint32_t *M)
{
    uint32_t W[80];
    int t;
    for (t = 0; t < 16; t++) W[t] = M[t];
    for (; t < 80; t++) W[t] = ROTR(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 31);
    uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4];
    for (t = 0; t < 20; t += 5) {
        R1(a,b,c,d,e,t+0); R1(e,a,b,c,d,t+1); R1(d,e,a,b,c,t+2); R1(c,d,e,a,b,t+3); R1(b,c,d,e,a,t+4);
    }
    for (; t < 40; t += 5) {
        R2(a,b,c,d,e,t+0); R2(e,a,b,c,d,t+1); R2(d,e,a,b,c,t+2); R2(c,d,e,a,b,t+3); R2(b,c,d,e,a,t+4);
    }
    for (; t < 60; t += 5) {
        R3(a,b,c,d,e,t+0); R3(e,a,b,c,d,t+1); R3(d,e,a,b,c,t+2); R3(c,d,e,a,b,t+3); R3(b,c,d,e,a,t+4);
    }
    for (; t < 80; t += 5) {
        R4(a,b,c,d,e,t+0); R4(e,a,b,c,d,t+1); R4(d,e,a,b,c,t+2); R4(c,d,e,a,b,t+3); R4(b,c,d,e,a,t+4);
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e;
}

static void sha1_init(HashCtx *ctx)
{
    static const uint32_t H0[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
    __builtin_memcpy(ctx->H, H0, 20);
    ctx->length = 0;
}
#define BLK_SIZE 64
static void sha1_update(HashCtx *ctx, const uint8_t *msg, unsigned int mlen)
{
    unsigned int offset = ctx->length & (BLK_SIZE - 1);
    ctx->length += mlen;
    while (mlen > 0) {
        unsigned int len = (mlen > BLK_SIZE - offset) ? BLK_SIZE - offset : mlen;
        __builtin_memcpy((uint8_t *)ctx->buffer + offset, msg, len);
        msg += len; mlen -= len; offset += len;
        if (offset == BLK_SIZE) {
            ntohl_vec(ctx->buffer, BLK_SIZE / 4);
            SHA1(ctx->H, ctx->buffer);
            offset = 0;
        }
    }
}
static void sha1_final(HashCtx *ctx, void *tag, unsigned int tlen)
{
    uint8_t *buffer = (uint8_t *)ctx->buffer;
    int offset = ctx->length & 63;
    buffer[offset] = 0x80;
    if (offset >= 56) {
        __builtin_memset(&buffer[offset + 1], 0, 63 - offset);
        ntohl_vec(ctx->buffer, 64 / 4);
        SHA1(ctx->H, ctx->buffer);
        __builtin_memset(&buffer[0], 0, 64);
    } else {
        __builtin_memset(&buffer[offset + 1], 0, 55 - offset);
        ntohl_vec(ctx->buffer, ((offset + 4) >> 2));
    }
    ctx->buffer[15] = htole32(ctx->length << 3);
    ctx->buffer[14] = htole32(ctx->length >> 29);
    SHA1(ctx->H, ctx->buffer);
    ntohl_vec(ctx->H, 5);
    __builtin_memcpy(tag, ctx->H, tlen ? tlen : 20);
}
static void sha1(const uint8_t *data, size_t len, uint8_t *hash)
{
    HashCtx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, (unsigned)len);
    sha1_final(&ctx, hash, 20);
}
MESSAGE_DIGEST(MD_SHA1) {
    .id = MD_SHA1,
    .name = "SHA-1",
    .block_len = 64,
    .hash_len = 20,
    .ctx_size = sizeof(HashCtx),
    .init = (void *)sha1_init,
    .update = (void *)sha1_update,
    .final = (void *)sha1_final,
    .digest = sha1
};
