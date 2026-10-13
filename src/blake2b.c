/*! \file blake2b.c
    \see [RFC 7693] BLAKE2 Crypto Hash and MAC, November 2015
    (https://datatracker.ietf.org/doc/html/rfc7693.html)
    A simple BLAKE2b Reference Implementation.
*/
//   #include "blake2b.h"
#include "hmac.h"
#include <stdint.h>
#include <stddef.h>

// state context
typedef struct
{
    uint8_t b[128];                     // input buffer
    uint64_t h[8];                      // chained state
    uint64_t t[2];                      // total number of bytes
    size_t c;                           // pointer for b[]
    size_t outlen;                      // digest size
} blake2b_ctx;


// Initialize the hashing context "ctx" with optional key "key".
//      1 <= outlen <= 64 gives the digest size in bytes.
//      Secret key (also <= 64 bytes) is optional (keylen = 0).
static int blake2b_init(blake2b_ctx *ctx, size_t outlen,
                 const void *key, size_t keylen);    // secret key

// Add "inlen" bytes from "in" into the hash.
static void blake2b_update(blake2b_ctx *ctx,   // context
                    const void *in, size_t inlen);      // data to be hashed

// Generate the message digest (size given in init).
//      Result placed in "out".
static void blake2b_final(blake2b_ctx *ctx, void *out);

// All-in-one convenience function.
int blake2b(void *out, size_t outlen,   // return buffer for digest
            const void *key, size_t keylen,     // optional secret key
            const void *in, size_t inlen);      // data to be hashed

// Cyclic right rotation.

#ifndef ROTR64
#define ROTR64(x, y)  (((x) >> (y)) ^ ((x) << (64 - (y))))
#endif

// Little-endian byte access.
#if 1//__has_builtin(__builtin_memcpy)
#define B2B_GET64(p) (*(uint64_t*)(p))
#else
#define B2B_GET64(p)                            \
       (((uint64_t) ((uint8_t *) (p))[0]) ^        \
       (((uint64_t) ((uint8_t *) (p))[1]) << 8) ^  \
       (((uint64_t) ((uint8_t *) (p))[2]) << 16) ^ \
       (((uint64_t) ((uint8_t *) (p))[3]) << 24) ^ \
       (((uint64_t) ((uint8_t *) (p))[4]) << 32) ^ \
       (((uint64_t) ((uint8_t *) (p))[5]) << 40) ^ \
       (((uint64_t) ((uint8_t *) (p))[6]) << 48) ^ \
       (((uint64_t) ((uint8_t *) (p))[7]) << 56))
#endif // 0
// G Mixing function.

#define B2B_G(a, b, c, d, x, y) {   \
       v[a] = v[a] + v[b] + x;         \
       v[d] = ROTR64(v[d] ^ v[a], 32); \
       v[c] = v[c] + v[d];             \
       v[b] = ROTR64(v[b] ^ v[c], 24); \
       v[a] = v[a] + v[b] + y;         \
       v[d] = ROTR64(v[d] ^ v[a], 16); \
       v[c] = v[c] + v[d];             \
       v[b] = ROTR64(v[b] ^ v[c], 63); }

// Initialization Vector.

static const uint64_t blake2b_iv[8] =
{
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

// Compression function. "last" flag indicates last block.

static void blake2b_compress(blake2b_ctx *ctx, int last)
{
    const uint8_t sigma[12][16] =
    {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
        { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
        { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
        { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
        { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
    };
    int i;
    uint64_t v[16], m[16];

    for (i = 0; i < 8; i++)             // init work variables
    {
        v[i] = ctx->h[i];
        v[i + 8] = blake2b_iv[i];
    }
    v[12] ^= ctx->t[0];                 // low 64 bits of offset
    v[13] ^= ctx->t[1];                 // high 64 bits
    if (last)                           // last block flag set ?
        v[14] = ~v[14];

    for (i = 0; i < 16; i++)            // get little-endian words
        m[i] = B2B_GET64(&ctx->b[8 * i]);

    for (i = 0; i < 12; i++)            // twelve rounds
    {
        B2B_G( 0, 4,  8, 12, m[sigma[i][ 0]], m[sigma[i][ 1]]);
        B2B_G( 1, 5,  9, 13, m[sigma[i][ 2]], m[sigma[i][ 3]]);
        B2B_G( 2, 6, 10, 14, m[sigma[i][ 4]], m[sigma[i][ 5]]);
        B2B_G( 3, 7, 11, 15, m[sigma[i][ 6]], m[sigma[i][ 7]]);
        B2B_G( 0, 5, 10, 15, m[sigma[i][ 8]], m[sigma[i][ 9]]);
        B2B_G( 1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]]);
        B2B_G( 2, 7,  8, 13, m[sigma[i][12]], m[sigma[i][13]]);
        B2B_G( 3, 4,  9, 14, m[sigma[i][14]], m[sigma[i][15]]);
    }

    for( i = 0; i < 8; ++i )
        ctx->h[i] ^= v[i] ^ v[i + 8];
}

// Initialize the hashing context "ctx" with optional key "key".
//      1 <= outlen <= 64 gives the digest size in bytes.
//      Secret key (also <= 64 bytes) is optional (keylen = 0).
static
int blake2b_init(blake2b_ctx *ctx, size_t outlen,
                 const void *key, size_t keylen)        // (keylen=0: no key)
{
    size_t i;

    if (outlen == 0 || outlen > 64 || keylen > 64)
        return -1;                      // illegal parameters

    for (i = 0; i < 8; i++)             // state, "param block"
        ctx->h[i] = blake2b_iv[i];
    ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

    ctx->t[0] = 0;                      // input count low word
    ctx->t[1] = 0;                      // input count high word
    ctx->c = 0;                         // pointer within buffer
    ctx->outlen = outlen;
    for (i = keylen; i < 128; i++)      // zero input block
        ctx->b[i] = 0;
    if (keylen > 0)
    {
        blake2b_update(ctx, key, keylen);
        ctx->c = 128;                   // at the end
    }

    return 0;
}

// Add "inlen" bytes from "in" into the hash.
static
void blake2b_update(blake2b_ctx *ctx,
                    const void *in, size_t inlen)       // data bytes
{
    size_t i;

    for (i = 0; i < inlen; i++)
    {
        if (ctx->c == 128)              // buffer full ?
        {
            ctx->t[0] += ctx->c;        // add counters
            if (ctx->t[0] < ctx->c)     // carry overflow ?
                ctx->t[1]++;            // high word
            blake2b_compress(ctx, 0);   // compress (not last)
            ctx->c = 0;                 // counter to zero
        }
        ctx->b[ctx->c++] = ((const uint8_t *) in)[i];
    }
}

// Generate the message digest (size given in init).
//      Result placed in "out".
static
void blake2b_final(blake2b_ctx *ctx, void *out)
{
    size_t i;

    ctx->t[0] += ctx->c;                // mark last block offset
    if (ctx->t[0] < ctx->c)             // carry overflow
        ctx->t[1]++;                    // high word

    while (ctx->c < 128)                // fill up with zeros
        ctx->b[ctx->c++] = 0;
    blake2b_compress(ctx, 1);           // final block flag = 1




// little endian convert and store
    for (i = 0; i < ctx->outlen; i++)
    {
        ((uint8_t *) out)[i] =
            (ctx->h[i >> 3] >> (8 * (i & 7))) & 0xFF;
    }
}
#if 1
MESSAGE_DIGEST(MD_BLAKE2B){
    .id=MD_BLAKE2B,
    .name = "Blake2b",
    .block_len = 128,
    .hash_len = 64/*28*/,
    .ctx_size = sizeof(blake2b_ctx),
    .init   = (void*)blake2b_init,
    .update = (void*)blake2b_update,
    .final  = (void*)blake2b_final,
};
#endif
// Convenience function for all-in-one computation.

int blake2b(void *out, size_t outlen,
            const void *key, size_t keylen,
            const void *in, size_t inlen)
{
    blake2b_ctx ctx;

    if (blake2b_init(&ctx, outlen, key, keylen))
        return -1;
    blake2b_update(&ctx, in, inlen);
    blake2b_final(&ctx, out);

    return 0;
}
#ifdef DEBUG_BLAKE2B

   // Deterministic sequences (Fibonacci generator).

static void selftest_seq(uint8_t *out, size_t len, uint32_t seed)
{
    size_t i;
    uint32_t t, a , b;

    a = 0xDEAD4BAD * seed;              // prime
    b = 1;

    for (i = 0; i < len; i++) {         // fill the buf
        t = a + b;
        a = b;
        b = t;
        out[i] = (t >> 24) & 0xFF;
    }
}
/*! \brief BLAKE2b self-test validation [RFC7693]. 
    \return Return 0 when OK.
 */
int blake2b_selftest()
{
    // grand hash of hash results
    const uint8_t blake2b_res[32] = {
        0xC2, 0x3A, 0x78, 0x00, 0xD9, 0x81, 0x23, 0xBD,
        0x10, 0xF5, 0x06, 0xC6, 0x1E, 0x29, 0xDA, 0x56,
        0x03, 0xD7, 0x63, 0xB8, 0xBB, 0xAD, 0x2E, 0x73,
        0x7F, 0x5E, 0x76, 0x5A, 0x7B, 0xCC, 0xD4, 0x75
    };
    // parameter sets
    const size_t b2b_md_len[4] = { 20, 32, 48, 64 };
    const size_t b2b_in_len[6] = { 0, 3, 128, 129, 255, 1024 };

    size_t i, j, outlen, inlen;
    uint8_t in[1024], md[64], key[64];
    blake2b_ctx ctx;

    // 256-bit hash for testing
    if (blake2b_init(&ctx, 32, NULL, 0))
        return -1;

    for (i = 0; i < 4; i++) {
        outlen = b2b_md_len[i];
        for (j = 0; j < 6; j++) {
            inlen = b2b_in_len[j];

            selftest_seq(in, inlen, inlen);     // unkeyed hash
            blake2b(md, outlen, NULL, 0, in, inlen);
            blake2b_update(&ctx, md, outlen);   // hash the hash

            selftest_seq(key, outlen, outlen);  // keyed hash
            blake2b(md, outlen, key, outlen, in, inlen);
            blake2b_update(&ctx, md, outlen);   // hash the hash
        }
    }

    // compute and compare the hash of hashes
    blake2b_final(&ctx, md);
    for (i = 0; i < 32; i++) {
        if (md[i] != blake2b_res[i])
            return -1;
    }

    return 0;
}

#include <stdio.h>
void digest_register(const MDigest* ){} // заглушка
int main ()
{
// (https://datatracker.ietf.org/doc/html/rfc7693.html#appendix-A):
/*	BLAKE2b-512("abc") = BA 80 A5 3F 98 1C 4D 0D 6A 27 97 B6 9F 12 F6 E9
                        4C 21 2F 14 68 5A C4 B7 4B 12 BB 6F DB FF A2 D1
                        7D 87 C5 39 2A AB 79 2D C2 52 D5 DE 45 33 CC 95
                        18 D3 8A A8 DB F1 92 5A B9 23 86 ED D4 00 99 23
						*/
	char m[]="abc";
	uint8_t out[512/8];
	blake2b(out, 512/8, NULL, 0, m, 3);
	int i;
	for(i=0;i<512/8;i++) printf(" %02X", out[i]);
    printf("\n");

    int res = blake2b_selftest();
    if (res == 0) printf("selftest OK\n"); 

	return 0;
}
#endif
#if defined(BLAKE2B_SELFTEST)
enum blake2b_constant {
    BLAKE2B_OUTBYTES   = 64,
    BLAKE2B_KEYBYTES   = 64,
};
enum blake2s_constant {
    BLAKE2S_OUTBYTES   = 32,
    BLAKE2S_KEYBYTES   = 32,
};
#define BLAKE2S_256_SIZE 32
#define BLAKE2B_512_SIZE 64
#define KAT_LENGTH 256
#include <stdio.h>
#include <string.h>
#include "blake2-kat.h"
void digest_register(const MDigest* ){} // заглушка
int main( int argc, char **argv )
{
  uint8_t key[BLAKE2B_KEYBYTES];
  uint8_t buf[KAT_LENGTH];

  for( size_t i = 0; i < BLAKE2B_KEYBYTES; ++i )
    key[i] = ( uint8_t )i;

  for( size_t i = 0; i < KAT_LENGTH; ++i )
    buf[i] = ( uint8_t )i;

  uint8_t hash[BLAKE2B_OUTBYTES];
  for( size_t i = 0; i < KAT_LENGTH; ++i )
  {
    blake2b( hash, BLAKE2B_OUTBYTES, key, 0, buf, i);

    if( 0 != memcmp( hash, blake2b_kat[i], BLAKE2B_OUTBYTES ) )
    {
        for (int j=0; j<BLAKE2B_OUTBYTES; j++) {
            printf(" %02X", hash[j]);
        }
        printf("\n");
        for (int j=0; j<BLAKE2B_OUTBYTES; j++) {
            printf(" %02X", blake2b_kat[i][j]);
        }
        printf("\n");

      printf( "error %d\n", i);
      return -1;
    }
  }
  for( size_t i = 0; i < KAT_LENGTH; ++i )
  {
    blake2b( hash, BLAKE2B_OUTBYTES, key, BLAKE2B_KEYBYTES,  buf, i );

    if( 0 != memcmp( hash, blake2b_keyed_kat[i], BLAKE2B_OUTBYTES ) )
    {
        for (int j=0; j<BLAKE2B_OUTBYTES; j++) {
            printf(" %02X", hash[j]);
        }
        printf("\n");
        for (int j=0; j<BLAKE2B_OUTBYTES; j++) {
            printf(" %02X", blake2b_keyed_kat[i][j]);
        }
        printf("\n");

      printf( "error %d\n", i);
      return -1;
    }
  }

  puts( "ok" );
  return 0;
}
#endif