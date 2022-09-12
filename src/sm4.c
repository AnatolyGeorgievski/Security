/*! 
// Transpose four 32-bit words between 128-bit vector lanes. 
#define transpose_4x4(x0, x1, x2, x3, t1, t2) \
	vpunpckhdq x1, x0, t2; \
	vpunpckldq x1, x0, x0; \
	\
	vpunpckldq x3, x2, t1; \
	vpunpckhdq x3, x2, x2; \
	\
	vpunpckhqdq t1, x0, x1; \
	vpunpcklqdq t1, x0, x0; \
	\
	vpunpckhqdq x2, t2, x3; \
	vpunpcklqdq x2, t2, x2;
	
https://github.com/mjosaarinen/sm4ni
S(x) = A2*(A1*x+C1)^-1 + C2, Poly 0x1F5 -- можно представить как аффинные преобразования в таблицу AES-Sbox и обратно. 

[RFC 8998] ShangMi (SM) Cipher Suites for TLS 1.3
SM4 Block Cipher Algorithm
http://www.gmbz.org.cn/upload/2018-04-04/1522788048733065051.pdf

http://gmssl.org/english.html
https://tinycrypt.wordpress.com/2017/02/15/asmcodes-sm4/
https://github.com/mjosaarinen/sm4ni/blob/master/sm4ni.c

Утверждается что можно отобразить любое поле с использованием матрицы 8x8 бит.
https://github.com/aws-samples/rainbow-with-gfni

$ gcc -DTEST_SM4 -O3 -march=icelake-server -o sm4 sm4.c
$ /sde/sde.exe -icl -- ./sm4
 68 1E DF 34 D2 06 96 5E 86 B3 E9 4F 53 6E 42 46


*/


#include <stdint.h>
#include <stdio.h>
#include <string.h>


static const uint32_t ck[] =
{
  0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
  0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
  0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
  0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
  0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
  0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
  0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
  0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};
static const uint32_t fk[4] =
{
  0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

static uint8_t sbox[] = {
  0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
  0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
  0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
  0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
  0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
  0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
  0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
  0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
  0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
  0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
  0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
  0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
  0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
  0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
  0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
  0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
  0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
  0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
  0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
  0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
  0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
  0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
  0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
  0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
  0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
  0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
  0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
  0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
  0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
  0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
  0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
  0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
}; 
static inline uint32_t buf_get_be32(const uint8_t* addr)
{
	return __builtin_bswap32(*(uint32_t*)addr);
}
static inline uint32_t buf_put_be32(uint8_t* addr, uint32_t value)
{
	return *(uint32_t*)addr = __builtin_bswap32(value);
}
static inline uint32_t rol(uint32_t x, int n)
{
	return x<<n ^ x>>(32-n);
}
static inline uint32_t sm4_tau(uint32_t x)
{
	union{
		uint8_t  b[4];
		uint32_t u32;
	} v;
	v.u32 =x;
	v.b[0] = sbox[v.b[0]];
	v.b[1] = sbox[v.b[1]];
	v.b[2] = sbox[v.b[2]];
	v.b[3] = sbox[v.b[3]];
	return v.u32;
}
#include <intrin.h>
static inline __m512i sm4_tau_16(__m512i state) __attribute__((target("gfni","avx512f")));
/*! \brief выполняет преобразования APA Affine-Power-Affine над вектором 64 байт/16 блоков */
static inline __m512i sm4_tau_16(__m512i state) {
    const __m512i A2= _mm512_set1_epi64 (0xD72D8E511E6C8B19);
    const __m512i A3= _mm512_set1_epi64 (0x34AC259E022DBC52);
    state = _mm512_gf2p8affine_epi64_epi8(state, A3, 0x65);
	return  _mm512_gf2p8affineinv_epi64_epi8(state, A2, 0xD3);
}
static inline __m512i sm4_lin_16(__m512i x) __attribute__((target("avx512f")));
static inline __m512i sm4_lin_16(__m512i x) {
//	return x ^ _mm_rol_epi32(x, 24) ^ _mm_rol_epi32(x, 2) ^ _mm_rol_epi32(x, 10) ^ _mm_rol_epi32(x, 18);
	__m512i y = _mm512_ternarylogic_epi32 (_mm512_rol_epi32(x, 2), _mm512_rol_epi32(x, 10), _mm512_rol_epi32(x, 18), 0x96);
	return _mm512_ternarylogic_epi32(y, x, _mm512_rol_epi32(x, 24), 0x96);// a^b^c
}
static  
__m512i sm4_round_16(__m512i x0, __m512i x1, __m512i x2, __m512i x3, uint32_t rk)  __attribute__((target("avx512f")));
static  
__m512i sm4_round_16(__m512i x0, __m512i x1, __m512i x2, __m512i x3, uint32_t rk){
  return x0 ^ sm4_lin_16(sm4_tau_16(_mm512_ternarylogic_epi32(x1, x2, x3,0x96) ^ _mm512_set1_epi32(rk)));
}
/*! \brief 

 Аффинные преобразования можно выполнить с инструкцией 
 pshufb xmm, xmm по 4 бита.
*/
static inline __m128i sm4_tau_4(__m128i state) __attribute__((target("gfni","avx512vl")));
static inline __m128i sm4_tau_4(__m128i state) {
    const __m128i A2= _mm_set1_epi64x (0xD72D8E511E6C8B19);
    const __m128i A3= _mm_set1_epi64x (0x34AC259E022DBC52);
    state = _mm_gf2p8affine_epi64_epi8(state, A3, 0x65);
	return  _mm_gf2p8affineinv_epi64_epi8(state, A2, 0xD3);
}
static inline __m128i sm4_lin_4(__m128i x) __attribute__((target("avx512vl","avx512f")));
static inline __m128i sm4_lin_4(__m128i x) {
//	return x ^ _mm_rol_epi32(x, 24) ^ _mm_rol_epi32(x, 2) ^ _mm_rol_epi32(x, 10) ^ _mm_rol_epi32(x, 18);
	__m128i y = _mm_ternarylogic_epi32 (_mm_rol_epi32(x, 2), _mm_rol_epi32(x, 10), _mm_rol_epi32(x, 18), 0x96);
	return _mm_ternarylogic_epi32(y, x, _mm_rol_epi32(x, 24), 0x96);// a^b^c
}
static  __m128i sm4_round_4(const __m128i x0, const __m128i x1, const __m128i x2, const __m128i x3, const uint32_t rk){
  return x0 ^ sm4_lin_4(sm4_tau_4(_mm_ternarylogic_epi32(x1, x2, x3,0x96) ^ _mm_set1_epi32(rk)));
}
//s = A2*Inv(A3(x)+c)+d3
//s = P(s)



static inline uint32_t sm4_lin(uint32_t x)
{// эта операция равносильна CLMUL умножению на константу 0x1040405
	return x ^ rol(x, 2) ^ rol(x, 10) ^ rol(x, 18) ^ rol(x, 24);
}
static inline uint32_t sm4_enc_sub(uint32_t x)
{
  return sm4_lin(sm4_tau(x));
}
static
void sm4_encrypt_ (const uint32_t *rk, uint8_t *out, const uint8_t *in)
{
	uint32_t x[4];

	x[0] = buf_get_be32(in + 0 * 4);
	x[1] = buf_get_be32(in + 1 * 4);
	x[2] = buf_get_be32(in + 2 * 4);
	x[3] = buf_get_be32(in + 3 * 4);

	int i;
	for (i = 0; i < 32; i += 4) {
		x[0] ^= sm4_enc_sub(x[1] ^ x[2] ^ x[3] ^ rk[i + 0]);
		x[1] ^= sm4_enc_sub(x[2] ^ x[3] ^ x[0] ^ rk[i + 1]);
		x[2] ^= sm4_enc_sub(x[3] ^ x[0] ^ x[1] ^ rk[i + 2]);
		x[3] ^= sm4_enc_sub(x[0] ^ x[1] ^ x[2] ^ rk[i + 3]);
	}

	buf_put_be32(out + 0 * 4, x[3]);
	buf_put_be32(out + 1 * 4, x[2]);
	buf_put_be32(out + 2 * 4, x[1]);
	buf_put_be32(out + 3 * 4, x[0]);
}
//static
void sm4_encrypt (const uint32_t *rk, uint8_t *out, const uint8_t *in)
{
	const __m128i BSWAP32 = _mm_setr_epi32(0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F);
	__m128i x[4];
//Загрузить 4 вектора и выполнить транспонирование.
	__m128i t =_mm_shuffle_epi8(_mm_loadu_si128((void*)(in + 0 * 16)), BSWAP32);
/*
tmp0 := _mm_unpacklo_ps(row0, row1); // 00 10 01 11
tmp2 := _mm_unpacklo_ps(row2, row3); // 20 30 21 31
tmp1 := _mm_unpackhi_ps(row0, row1); // 02 12 03 13 
tmp3 := _mm_unpackhi_ps(row2, row3); // 22 32 23 33
row0 := _mm_movelh_ps(tmp0, tmp2);
row1 := _mm_movehl_ps(tmp2, tmp0);
row2 := _mm_movelh_ps(tmp1, tmp3);
row3 := _mm_movehl_ps(tmp3, tmp1);
*/
	x[0] = _mm_set1_epi32(_mm_extract_epi32(t,0));
	x[1] = _mm_set1_epi32(_mm_extract_epi32(t,1));
	x[2] = _mm_set1_epi32(_mm_extract_epi32(t,2));
	x[3] = _mm_set1_epi32(_mm_extract_epi32(t,3));
__asm volatile("# LLVM-MCA-BEGIN SM4");
	int i;
	for (i = 0; i < 32; i += 4) {
		x[0] = sm4_round_4(x[0], x[1], x[2], x[3], rk[i + 0]);
		x[1] = sm4_round_4(x[1], x[2], x[3], x[0], rk[i + 1]);
		x[2] = sm4_round_4(x[2], x[3], x[0], x[1], rk[i + 2]);
		x[3] = sm4_round_4(x[3], x[0], x[1], x[2], rk[i + 3]);
	}
__asm volatile("# LLVM-MCA-END SM4");

	buf_put_be32(out + 0 * 4, _mm_extract_epi32(x[3],0));
	buf_put_be32(out + 1 * 4, _mm_extract_epi32(x[2],0));
	buf_put_be32(out + 2 * 4, _mm_extract_epi32(x[1],0));
	buf_put_be32(out + 3 * 4, _mm_extract_epi32(x[0],0));
}
static
void sm4_decrypt (const uint32_t *rk, uint8_t *out, const uint8_t *in)
{
	uint32_t x[4];

	x[0] = buf_get_be32(in + 0 * 4);
	x[1] = buf_get_be32(in + 1 * 4);
	x[2] = buf_get_be32(in + 2 * 4);
	x[3] = buf_get_be32(in + 3 * 4);

	int i;
	for (i = 0; i < 32; i += 4) {
		x[0] ^= sm4_enc_sub(x[1] ^ x[2] ^ x[3] ^ rk[31 - i - 0]);
		x[1] ^= sm4_enc_sub(x[2] ^ x[3] ^ x[0] ^ rk[31 - i - 1]);
		x[2] ^= sm4_enc_sub(x[3] ^ x[0] ^ x[1] ^ rk[31 - i - 2]);
		x[3] ^= sm4_enc_sub(x[0] ^ x[1] ^ x[2] ^ rk[31 - i - 3]);
	}
	buf_put_be32(out + 0 * 4, x[3 - 0]);
	buf_put_be32(out + 1 * 4, x[3 - 1]);
	buf_put_be32(out + 2 * 4, x[3 - 2]);
	buf_put_be32(out + 3 * 4, x[3 - 3]);
}
static inline uint32_t sm4_key_lin(uint32_t x) {
  return x ^ rol(x, 13) ^ rol(x, 23);
}
static inline uint32_t sm4_key_sub(uint32_t x) {
  return sm4_key_lin(sm4_tau(x));
}
static 
void sm4_key_expand (uint32_t *rkey, const uint8_t *key)
{
  uint32_t rk[4];

  rk[0] = buf_get_be32(key + 4 * 0) ^ fk[0];
  rk[1] = buf_get_be32(key + 4 * 1) ^ fk[1];
  rk[2] = buf_get_be32(key + 4 * 2) ^ fk[2];
  rk[3] = buf_get_be32(key + 4 * 3) ^ fk[3];

	int i;
	for (i = 0; i < 32; i += 4)
    {
      rk[0] = rk[0] ^ sm4_key_sub(rk[1] ^ rk[2] ^ rk[3] ^ ck[i + 0]);
      rk[1] = rk[1] ^ sm4_key_sub(rk[2] ^ rk[3] ^ rk[0] ^ ck[i + 1]);
      rk[2] = rk[2] ^ sm4_key_sub(rk[3] ^ rk[0] ^ rk[1] ^ ck[i + 2]);
      rk[3] = rk[3] ^ sm4_key_sub(rk[0] ^ rk[1] ^ rk[2] ^ ck[i + 3]);
      rkey[i + 0] = rk[0];
      rkey[i + 1] = rk[1];
      rkey[i + 2] = rk[2];
      rkey[i + 3] = rk[3];
/*
		ctx->rkey_dec[31 - i - 0] = rk[0];
      ctx->rkey_dec[31 - i - 1] = rk[1];
      ctx->rkey_dec[31 - i - 2] = rk[2];
      ctx->rkey_dec[31 - i - 3] = rk[3];
	  */
    }
}
#ifdef TEST_SM4
int main()
{
    // test vectors from the standard

    const uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    const uint8_t ref[16] = {
        0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E,
        0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46
    };

    uint8_t buf1[64], buf2[64];
    uint32_t rk[32];

    memset(buf1, 0x55, sizeof(buf1));
    memset(buf2, 0xAA, sizeof(buf2));

    // Test reference implementation with a test vector.

    sm4_key_expand(rk, key);
    sm4_encrypt(rk, buf1, key);
	int i;
	for (i=0; i< 16; i++) printf (" %02X", buf1[i]);
	printf("\n");
    if (memcmp(buf1, ref, 16) != 0) {
        fprintf(stderr, "sm4_encrypt() test failed.\n");
        return -1;
    }
    sm4_decrypt(rk, buf1, ref);
    if (memcmp(buf1, key, 16) != 0) {
        fprintf(stderr, "sm4_decrypt() test failed.\n");
        return -1;
    }
	printf("S-Box SM4:\n");
	for (i=0; i<256; i+=16) {
		__m128i s = _mm_setr_epi8(i,i+1,i+2,i+3,i+4,i+5,i+6,i+7,i+8,i+9,i+10,i+11,i+12,i+13,i+14,i+15);
		s = sm4_tau_4(s);
		int j;
		#pragma GCC unroll 16
		for (j=0; j<16; j++) printf("0x%02X,", _mm_extract_epi8(s, j));
		printf("\n");
	}

	return 0;
	

}
#endif // TEST_SM4
