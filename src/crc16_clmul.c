/*! обновление контрольной суммы CRC с использованием умножения без переноса.
	Copyright (C) 2019-2021 , Anatoly Georgievskii <anatoly.georgievski@gmail.com>

Изначально идея основана на работе
Intel/ Fast CRC Computation Using PCLMULQDQ Instruction

Оптимизация CRC16:
    В операцию CRC можно разложить на CL_MUL - умножение без переноса и редуцирование.
    В тех случаях, когда операция проивзодится с 4 биными числами и растояния между битами в
    полиноме превышают 4 бита, можно заменить операцию умоножения без переноса на обычное
    целочисленное умножение.

CRC (M (x)) = x^deg(P(x)) • M(x) mod P (x)
A = B mod C => A•K = B•K mod C•K

Редукция Barrett's высчитывается, как остаток от деления в поле Галуа по данному полиному.
В моем варианте алгоритма редукция от 64 битного числа производится в одно действие 
за счет увеличения разрядности константы до 64 бит.

Битовое отражение и сдвиговые константы
reflected (A)•reflected (B) = reflected (A•B) >> 1
Возможно уменьшить число сдвигов и умножений без переноса. 
Сдвиг и умножение без переноса могут быть объединены в одну операцию.


тестирование
# gcc crc16_clmul.c -O3 -march=native -o crc16.exe
 gcc -O3 -march=native -o crc16.exe crc16_clmul.c
#

#define REFLECT(X)\
hlp1 = _mm_srli_epi16(X,4);\
X = _mm_and_si128(AMASK,X);\ {0xF}
hlp1 = _mm_and_si128(AMASK,hlp1);\
X = _mm_shuffle_epi8(MASKH,X);\
hlp1 = _mm_shuffle_epi8(MASKL,hlp1);\
X = _mm_xor_si128(X,hlp1)

ARMv8-A с расширением Crypto
Here are results from the sample program below. The conversions are:

    _mm_clmulepi64_si128(a, b, 0x00) → vmull_p64(vgetq_lane_u64(a, 0), vgetq_lane_u64(b, 0))

    _mm_clmulepi64_si128(a, b, 0x01) → vmull_p64(vgetq_lane_u64(a, 1), vgetq_lane_u64(b, 0))

    _mm_clmulepi64_si128(a, b, 0x10) → vmull_p64(vgetq_lane_u64(a, 0), vgetq_lane_u64(b, 1))

    _mm_clmulepi64_si128(a, b, 0x11) → vmull_p64(vgetq_lane_u64(a, 1), vgetq_lane_u64(b, 1))

For case (4), _mm_clmulepi64_si128(a, b, 0x11), the following also holds:

    _mm_clmulepi64_si128(a, b, 0x11) → vmull_high_p64((poly64x2_t)a, (poly64x2_t)b)

I'm guessing the cases (1) through (4) can spill out into memory if not careful 
because vgetq_lane_u64 returns a scalar or non-vector type. I'm also guessing case (5) 
has a propensity to stay in the Q registers because its a vector type.
-gcc -march=armv8-a+crc+crypto


Для NEON существует три операции умножения без переноса,
Cortex-A5|A7|A9 поддерживает.
         | результат  | тип | аргументы 
vmul_p8    poly8x8_t    p8    poly8x8_t  poly8x8_t
vmulq_p8   poly8x16_t   p8    poly8x16_t poly8x16_t
vmull_p8   poly16x8_t   p8    poly8x8_t  poly8x8_t
ARMv8.1-M+MVE Helium поддерживает:
vmull_p8
vmull_p16

$ arm-eabi-gcc -march=armv8-a+crc+crypto -mtune=cortex-a53 -mfloat-abi=hard -O3 -S -o - crc16_clmul.c
$ arm-eabi-gcc -march=armv8.1-a+crypto -mthumb -mtune=cortex-a53 -mfpu=crypto-neon-fp-armv8 -mfloat-abi=hard 


unsigned __int64 uiClockCycles = __rdtsc();
 */
#include <stdint.h>
#include <stdio.h>
#include "crc.h"
/*! Значение с =0x00 (a0*b0) 0x11 (a1*b1) */
typedef  int64_t v2di __attribute__((__vector_size__(16)));
typedef uint64_t v2du __attribute__((__vector_size__(16)));
typedef uint32_t v4su __attribute__((__vector_size__(16)));
typedef uint8_t  v16qu __attribute__((__vector_size__(16)));
typedef char     v16qi __attribute__((__vector_size__(16)));


#ifdef __ARM_NEON
#include <arm_neon.h>
static inline
poly64x2_t CL_MUL128(poly64x2_t a, poly64x2_t b, const int c)
{
/* if (c==0x11) {

	return (poly64x2_t) vmull_hight_p64 ( __t1, __t2);
} else */
{
	poly64_t __t1 = (poly64_t)vgetq_lane_p64(a, c & 1);
	poly64_t __t2 = (poly64_t)vgetq_lane_p64(b,(c>>4) & 1);

	return (poly64x2_t) __builtin_arm_crypto_vmullp64 ( __t1,  __t2);
}
//    return (v2du)__builtin_arm_crypto_vmullp64(vgetq_lane_u64(a, c & 0x1),vgetq_lane_u64(b, (c & 0x10)?1:0));
}
static inline uint8x16_t LOAD128U(uint8_t* p) {
	return vld1q_u8(p);
}
static inline poly64x2_t SLL128U(poly64x2_t a, const int bits) {
	return (poly64x2_t) vextq_u8((uint8x16_t)a,(uint8x16_t){0}, bits>>3);
	//return (v2du){(uint64_t)a[0]<<bits, (uint64_t)a[0]>>(64-bits) | (uint64_t)a[1]<<(bits)};
}
static inline poly64x2_t SRL128U(poly64x2_t a, const int bits) {
	return (poly64x2_t) vextq_u8((uint8x16_t){0},(uint8x16_t)a, (128-bits)>>3);
//	return (v2du){(uint64_t)a[0]>>bits  | (uint64_t)a[1]<<(64-bits), (uint64_t)a[1]>>(bits)};
}
static inline uint8x16_t REVERSE(uint8x16_t v) {
	v = vrev64q_u8(v);
	return vextq_u8(v,v,8);
//	uint64x2_t t = (uint64x2_t)vrev64q_u8((uint8x16_t)x);
//	return (v16qi) vcombine_u64(vgetq_lane_u64(t,1), vgetq_lane_u64(t,0));
//	return (v16qi)(v2du){(uint64_t)vrev64_u8((uint8x8_t) vgetq_lane_u64(t,1)), (uint64_t) vrev64_u8((uint8x8_t)vgetq_lane_u64(t,0))};
}
#else
	#include <intrin.h>
typedef uint64_t uint64x2_t __attribute__((__vector_size__(16)));
typedef uint64_t poly64x4_t __attribute__((__vector_size__(32)));
typedef uint64_t poly64x2_t __attribute__((__vector_size__(16)));
typedef uint32_t uint32x4_t __attribute__((__vector_size__(16)));
typedef uint16_t uint16x8_t __attribute__((__vector_size__(16)));
typedef uint8_t  uint8x16_t __attribute__((__vector_size__(16)));

typedef uint64_t poly64_t __attribute__((__vector_size__(8)));
typedef uint32_t uint32x2_t __attribute__((__vector_size__(8)));
static inline
v2du CL_MUL128(v2du a, v2du b, const int c) __attribute__ ((__target__("pclmul")));
static inline v2du CL_MUL128(v2du a, v2du b, const int c) {
    return (v2du)__builtin_ia32_pclmulqdq128 ((v2di)a,(v2di)b,c);
}
static inline uint64_t CL_MUL8(uint8_t a, uint8_t b) {
    v2du v = (v2du)__builtin_ia32_pclmulqdq128 ((v2di){a},(v2di){b},0);
	return v[0];
}
static inline uint64_t CL_MUL16(uint16_t a, uint16_t b) {
    v2du v = (v2du)__builtin_ia32_pclmulqdq128 ((v2di){a},(v2di){b},0);
	return v[0];
}
static inline uint64_t CL_MUL24(uint32_t a, uint32_t b) {
    v2du v = (v2du)__builtin_ia32_pclmulqdq128 ((v2di){a & 0xFFFFFF} ,(v2di){b},0);
	return v[0];
}
static inline uint64_t CL_MUL32(uint32_t a, uint32_t b) {
    v2du v = (v2du)__builtin_ia32_pclmulqdq128 ((v2di){a} ,(v2di){b},0);
	return v[0];
}
static inline poly64x2_t XOR128(poly64x2_t a, poly64x2_t b) {
	return (poly64x2_t)_mm_xor_si128((__m128i)a,(__m128i)b);
}
static inline v16qi LOAD128U(uint8_t* p) {
    return (v16qi)_mm_loadu_si128((void*)p);
}
static inline poly64x2_t SLL128U(poly64x2_t a, const int bits) {
    return (poly64x2_t)__builtin_ia32_pslldqi128((v2di)a, bits);
}
static inline v2du SRL128U(v2du a, const int bits) {
    return (v2du)__builtin_ia32_psrldqi128((v2di)a, bits);
}
static const uint8x16_t BSWAP_MASK = {15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0};
static inline uint8x16_t REVERSE(uint8x16_t x) {
    return __builtin_shuffle (x,BSWAP_MASK);
}

#endif
#ifdef __AVX__
poly64x4_t CL_MUL256(poly64x2_t p, poly64x2_t v) __attribute__((__target__("avx")));
poly64x4_t CL_MUL256(poly64x2_t p, poly64x2_t v) {
	poly64x2_t q  = (poly64x2_t)CL_MUL128(p, v, 0x10) 
	              ^ (poly64x2_t)CL_MUL128(p, v, 0x01);
	poly64x2_t r0 = (poly64x2_t)CL_MUL128(p, v, 0x00) ^ SLL128U(q, 64);
	poly64x2_t r1 = (poly64x2_t)CL_MUL128(p, v, 0x11) ^ SRL128U(q, 64);
	return (poly64x4_t){r0[0], r0[1], r1[0], r1[1]};
}
poly64x4_t CL_MUL128x64(poly64x2_t p, poly64x2_t v) {
	poly64x2_t q  = (poly64x2_t)CL_MUL128(p, v, 0x01);
	poly64x2_t r0 = (poly64x2_t)CL_MUL128(p, v, 0x00) ^ SLL128U(q, 64);
	poly64x2_t r1 = (poly64x2_t)SRL128U(q, 64);
	return (poly64x4_t){r0[0], r0[1], r1[0], r1[1]};
}
#endif
/*! \brief 
Мы думали над аффинными преобразованиями. Получилось что алгоритм REFLECT можно использовать и для этого
Синтез таблиц происходит как циклические сдвиги от аргумента x<<<1 
*/
static inline
poly64x2_t REFLECT(poly64x2_t x)
{
	const uint8x16_t HI_MASK = {0x00,0x80,0x40,0xC0, 0x20,0xA0,0x60,0xE0, 0x10,0x90,0x50,0xD0, 0x30,0xB0,0x70,0xF0};
	const uint8x16_t LO_MASK = {0x00,0x08,0x04,0x0C, 0x02,0x0A,0x06,0x0E, 0x01,0x09,0x05,0x0D, 0x03,0x0B,0x07,0x0F};
	uint8x16_t hi = (uint8x16_t)(((v4su)x>>4));
	uint8x16_t lo = (uint8x16_t)(((v4su)x));
    hi = __builtin_shuffle (LO_MASK, hi & 0xF);
    lo = __builtin_shuffle (HI_MASK, lo & 0xF);
	return (poly64x2_t)REVERSE(hi ^ lo);// TODO отразить байты можно в маске
}
static inline
uint64_t REFLECT64(uint64_t x)
{

const uint64_t m4 = 0x0F0F0F0F0F0F0F0FULL;
const uint64_t m2 = 0x3333333333333333ULL;
const uint64_t m1 = 0x5555555555555555ULL;
	x = (x&m4)<<4 ^ (x&~m4)>>4;
	x = (x&m2)<<2 ^ (x&~m2)>>2;
	x = (x&m1)<<1 ^ (x&~m1)>>1;
	return __builtin_bswap64(x);
}

static inline
uint32_t CL_MUL32H(uint32_t a, const uint64_t b)
{
	uint32x4_t r = (uint32x4_t)CL_MUL128((poly64x2_t){a}, (poly64x2_t){ b}, 0x00);
	return r[1];
}
static inline
uint32_t CL_MUL16H(uint32_t a, const uint32_t b)
{
	uint16x8_t r = (uint16x8_t)CL_MUL128((poly64x2_t){a}, (poly64x2_t){ b}, 0x00);
	return r[1];
}
static inline
uint32_t CL_MUL16L(uint32_t a, const uint32_t b)
{
	uint16x8_t r = (uint16x8_t)CL_MUL128((poly64x2_t){a}, (poly64x2_t){ b}, 0x00);
	return r[0];
}
static inline
uint32_t CL_MUL32L(uint32_t a, const uint64_t b)
{
	uint32x4_t r = (uint32x4_t)CL_MUL128((poly64x2_t){a}, (poly64x2_t){ b}, 0x00);
	return r[0];
}
// 11011
poly64x2_t gf64_reduction(poly64x2_t x)
{
#if 1
	poly64x2_t t = CL_MUL128(x, (poly64x2_t){0x145ULL,0x1BULL}, 0x11) ^ x;
	return x ^ CL_MUL128(t, (poly64x2_t){0x145ULL,0x1BULL}, 0x11);// todo уточнить коэффициенты
#else	
	uint64_t x1 = x[1];
	uint64_t x0 = x[0];
	x1 = x1 ^ x1>>63 ^ x1>>61 ^ x1>>60;
	return x0 ^ x1 ^ x1<<1 ^ x1<<3 ^ x1<<4;
#endif
}
poly64x2_t gf128_reduction(poly64x2_t r0, poly64x2_t r1)
{
#if 0
	const poly64x2_t Px = {0x87ULL};
	poly64x2_t b = CL_MUL128(r1, Px, 0x01);
	poly64x2_t a = CL_MUL128(r1, Px, 0x00);
	poly64x2_t c = CL_MUL128( b, Px, 0x01);
	return r0 ^ a ^ c ^ SLL128U(b,64);
#elif 1
	const poly64x2_t Px ={0x86ULL};// (1 || 0^120 || x87)
	poly64x2_t b  = CL_MUL128(r1,Px, 0x01) ^ (poly64x2_t){r1[1],r1[0]};
	poly64x2_t d  = CL_MUL128( b,Px, 0x01) ^ (poly64x2_t){ b[1], b[0]};
	return r0 ^ d;
#else
	const poly64x2_t Px ={0x87ULL};// (1 || 0^120 || x87)
	poly64x2_t b  = CL_MUL128(r1,Px, 0x01) ^ SLL128U(r1, 64);
	poly64x2_t d  = CL_MUL128( b,Px, 0x01) ^ SLL128U( b, 64);
	return r0 ^ d;
#endif
}
poly64x2_t gfmul128(poly64x2_t a, poly64x2_t b)
{
    poly64x2_t M,L,H;
    H = CL_MUL128(a, b, 0x11);
    M = CL_MUL128(a, b, 0x01);
    M^= CL_MUL128(a, b, 0x10);
    L = CL_MUL128(a, b, 0x00);
// редуцирование по модулю, работает!
	M^= (poly64x2_t){H[1],H[0]};//SHUFFLE(H);
    M^= CL_MUL128(H, (poly64x2_t){0x86ULL}, 0x01);
// редуцирование по модулю, работает!
	L^= (poly64x2_t){M[1],M[0]};//SHUFFLE(M);
    L^= CL_MUL128(M, (poly64x2_t){0x86ULL}, 0x01);
    return L;
}
poly64x2_t gfmul128_3(poly64x2_t p, poly64x2_t v)
{
	poly64x2_t q  = CL_MUL128(p, v, 0x10) 
				  ^ CL_MUL128(p, v, 0x01);
	poly64x2_t r0 = CL_MUL128(p, v, 0x00) ^ SLL128U(q, 64);// этот сдвиг можно вынести из цикла
	poly64x2_t r1 = CL_MUL128(p, v, 0x11) ^ SRL128U(q, 64);// этот сдвиг можно вынести из цикла
#if 1
// редуцирование
	const poly64x2_t Px ={0x86ULL};// (1 || 0^120 || x87)
	poly64x2_t b  = CL_MUL128(r1,Px, 0x01) ^ (poly64x2_t){r1[1],r1[0]};
	poly64x2_t d  = CL_MUL128( b,Px, 0x01) ^ (poly64x2_t){ b[1], b[0]};
	return r0 ^ d;
#else
	const poly64x2_t Px ={0x87ULL};// (1 || 0^120 || x87)
	poly64x2_t b  = CL_MUL128(r1,Px, 0x01);
	uint64x2_t h  = SRL128U(b,64) ^ r1;
	poly64x2_t d  = CL_MUL128( h,Px, 0x00);// (1 || 0^120 || x87) 
	return r0 ^ d  ^ SLL128U(b,64);
#endif
}
static uint64x2_t SLL64x2 (uint64x2_t x, uint64x2_t x0,  const int n){
	return (x<<n) ^ x0>>(64-n);
}
poly64x2_t gfmul128_(poly64x2_t p, poly64x2_t v) {
	poly64x2_t q  = CL_MUL128(p, v, 0x10) 
	              ^ CL_MUL128(p, v, 0x01);
	poly64x2_t r0 = CL_MUL128(p, v, 0x00) ^ SLL128U(q, 64);// этот сдвиг можно вынести из цикла
	poly64x2_t r1 = CL_MUL128(p, v, 0x11) ^ SRL128U(q, 64);// этот сдвиг можно вынести из цикла
// редуцирование
	uint64x2_t d = SRL128U(r1,64);
	uint64x2_t h = r1 ^ (d>>63) ^ (d>>62) ^ (d>>57);// CL_MUL(r1, {C2||0^120}, 0x01) ^ r1
	//printf("h: 0x%016"PRIX64"%016"PRIX64" \n", h[1], h[0]);
// 
	d = SLL128U(h,64);
	d = d>>63 ^ d>>62 ^ d>>57;
	h = h ^ h<<1 ^ h<<2 ^ h<<7;//SLL64x2(h, d, 1) ^ SLL64x2(h, d, 2)^ SLL64x2(h, d, 7);
	return (r0 ^ h ^ d);
}
static poly64x2_t GF128_shift(poly64x2_t v)
{
	// ....
    return v;
}
static poly64x2_t SLM128(poly64x2_t d)
{
    poly64x2_t r = {d[1],d[0]};
    r >>=63;
    if (r[0]!=0) r[1] ^= 0xc2ULL<<56;
//	r ^= (r[0]!=0) & (poly64x2_t){1,0xc2ULL<<56};
    return  (d<<1) ^ r;
}
poly64x2_t gfmul128r(poly64x2_t p, poly64x2_t v)
{
	const poly64x2_t Px = {0xc2ULL<<56};
	v = SLM128(v);// сдвиг на один разряд
    poly64x2_t q  = CL_MUL128(p, v, 0x01)
				  ^ CL_MUL128(p, v, 0x10);
    poly64x2_t r0 = CL_MUL128(p, v, 0x00);
    poly64x2_t r1 = CL_MUL128(p, v, 0x11);
// редуцирование по модулю, работает!
	q^= (poly64x2_t){r0[1],r0[0]};//SHUFFLE(L);
    q^= CL_MUL128(r0, Px, 0x00);
// редуцирование по модулю, работает! это можно использовать как отдельную функцию
	r1^= (poly64x2_t){q[1],q[0]};//SHUFFLE(M);
    r1^= CL_MUL128(q, Px, 0x00);
    return r1;
}
// Умножение с отражением бит, умножаем на 0xE1 || 0^120 || 1
poly64x2_t gfmul128r_2(poly64x2_t p, poly64x2_t v)
{
	poly64x2_t q  = CL_MUL128(p, v, 0x10) 
	              ^ CL_MUL128(p, v, 0x01);
	poly64x2_t r0 = CL_MUL128(p, v, 0x00) ^ SLL128U(q, 64);// этот сдвиг можно вынести из цикла
	poly64x2_t r1 = CL_MUL128(p, v, 0x11) ^ SRL128U(q, 64);// этот сдвиг можно вынести из цикла
// результат нужно сдвинуть влево на один бит.
	r1 = (r1<<1) ^ ((uint64x2_t){r0[1],r1[0]}>>63);
	r0 = (r0<<1) ^ ((uint64x2_t){    0,r0[0]}>>63);
// редуцирование
	const poly64x2_t Px ={0xC200000000000000ULL};// (xE1 || 0^120 || 1)<<1
#if 1
	poly64x2_t b  = CL_MUL128(r0,Px, 0x00);
	poly64x2_t h  = SLL128U(b,64) ^ r0;
	poly64x2_t d  = CL_MUL128( h,Px, 0x01) ^ SRL128U(b,64);
	return r1 ^ h ^ d;
#else
	poly64x2_t b  = (poly64x2_t){r0[1],r0[0]} ^ CL_MUL128(r0,Px, 0x00);
	poly64x2_t d  = (poly64x2_t){ b[1], b[1]} ^ CL_MUL128( b,Px, 0x01);
	return r1 ^ d;
#endif
}
static uint64x2_t SRL64x2 (uint64x2_t x, uint64x2_t x0,  const int n){
	return (x>>n) ^ x0<<(64-n);
}
poly64x2_t gfmul128r_(poly64x2_t p, poly64x2_t v)
{
	poly64x2_t q  = CL_MUL128(p, v, 0x10) 
	              ^ CL_MUL128(p, v, 0x01);
	poly64x2_t r0 = CL_MUL128(p, v, 0x00) ^ SLL128U(q, 64);// этот сдвиг можно вынести из цикла
	poly64x2_t r1 = CL_MUL128(p, v, 0x11) ^ SRL128U(q, 64);// этот сдвиг можно вынести из цикла
// результат нужно сдвинуть влево на один бит.
	r1 = (r1<<1) ^ ((uint64x2_t){r0[1],r1[0]}>>63);
	r0 = (r0<<1) ^ ((uint64x2_t){    0,r0[0]}>>63);
// редуцирование
	uint64x2_t d = SLL128U(r0,64);
	uint64x2_t h = r0 ^ (d<<63) ^ (d<<62) ^ (d<<57);
//	printf("h: 0x%016"PRIX64"%016"PRIX64" \n", h[1], h[0]);
	// [b1:b0] = CL_MUL(x0, {C2||0^120}, 0x00)
	// h1:h0 = [b0+x1:x0]= [D+x1:x0]
	d = SRL128U(h,64);
	d = (d<<63) ^ (d<<62) ^ (d<<57);
//	printf("d: 0x%016"PRIX64"%016"PRIX64" \n", d[1], d[0]);
	h = h ^ h>>1 ^ h>>2 ^ h>>7;//SRL64x2(h, d, 1) ^ SRL64x2(h, d, 2)^ SRL64x2(h, d, 7);
// b1 = x1 ^ x0<<63 ^ x0<<62 ^ x0<<57 
// h0 = x0 ^ x0>>1  ^ x0>>2  ^ x0>>7
// d0 = x0<<63 ^ x0<<62 ^ x0<<57
// h1 = b1 ^ b1>>1 ^ b1>>2 ^ b1>>7
	
	
	return (h^r1^d);
}

uint64_t gfmul64(uint64_t a, uint64_t b)
{
	poly64x2_t r = CL_MUL128((poly64x2_t){a}, (poly64x2_t){b}, 0x00);
	poly64x2_t t = CL_MUL128(r, (poly64x2_t){0x1BULL}, 0x01)^r;
	r ^= CL_MUL128(t, (poly64x2_t){0x1BULL}, 0x01);// todo уточнить коэффициенты
	return r[0];
}
uint64_t gfmul64_(uint64_t a, uint64_t b)
{
	poly64x2_t r = CL_MUL128((poly64x2_t){a}, (poly64x2_t){b}, 0x00);
	uint64_t x1 = r[1];
	uint64_t x0 = r[0];
	x1 = x1 ^ x1>>63 ^ x1>>61 ^ x1>>60;
	return x0 ^ x1 ^ x1<<1 ^ x1<<3 ^ x1<<4;
//	return r[0];
}
uint64_t gfmul64_2(uint64_t a, uint64_t b)
{
	uint64_t r = 0;
	int i;
	for (i=0; i< 64; i++){
		if (b & (1ULL<<i)){
			r ^= a;
		}
		a = (a<<1) ^ (((int64_t)a>>63) & 0x1BULL);
	}
	return r;
}
// тбалица может использоваться для редуцирования по 4 бита
const uint8_t gf64_lookup4[] = {
//GF2m-64
//POLY=0x1B
0x00, 0x1B, 0x36, 0x2D,
0x6C, 0x77, 0x5A, 0x41,
0xD8, 0xC3, 0xEE, 0xF5,
0xB4, 0xAF, 0x82, 0x99,
};

uint64_t gfmul64r(uint64_t a, uint64_t b)
{
	poly64x2_t r = CL_MUL128((poly64x2_t){a}, (poly64x2_t){b}, 0x00);
	r = r<<1 ^ SLL128U(r>>63, 64);// сдвиг на 1 бит
	// сдвиг на один бит
//	x1 = x1<<1 ^ x0>>63;
//	x0 = x0<<1;

#if 0
	uint64_t x1 = r[1];
	uint64_t x0 = r[0];
	x0 = x0 ^  x0<<63 ^  x0<<62 ^ x0<<61;// 1b 1011  0xB000000000000001ULL
	return x1 ^ x0 ^ x0>>1 ^ x0>>3 ^ x0>>4;// 
#else
	poly64x2_t A,B;
	A = CL_MUL128(r, (poly64x2_t){0xB000000000000001ULL}, 0x00);
	B = CL_MUL128(A, (poly64x2_t){0xB000000000000001ULL}, 0x00);
	return r[1] ^ A[0] ^ B[1];
#endif
}
uint64_t gfmul64r_(uint64_t a, uint64_t b)
{
	poly64x2_t r = CL_MUL128((poly64x2_t){a}, (poly64x2_t){b}, 0x00);
	uint64_t x1 = r[1];
	uint64_t x0 = r[0];
	// сдвиг на один бит
	x1 = x1<<1 ^ x0>>63;
	x0 = x0<<1;
// редуцирование
	x0 = x0 ^  x0<<63 ^  x0<<62 ^ x0<<61;// 1b 1011  0xB000000000000001ULL
	return x1 ^ x0 ^ x0>>1 ^ x0>>3 ^ x0>>4;// 
}

static const uint8_t CRC8B_Lookup4[] = {
	0x00, 0xF1, 0xE1, 0x10,
	0xC1, 0x30, 0x20, 0xD1,
	0x81, 0x70, 0x60, 0x91,
	0x40, 0xB1, 0xA1, 0x50
};
static uint32_t	CRC8B_update(uint32_t crc, unsigned char val)
{
	crc^= val;
	crc = (crc>>4) ^ CRC8B_Lookup4[(crc) & 0xF];
	crc = (crc>>4) ^ CRC8B_Lookup4[(crc) & 0xF];
	return crc;
}
uint32_t CRC8B_update_32(uint32_t crc, uint8_t *data){
	uint32_t val=0;
	__builtin_memcpy(&val, data, 4);
	val ^= crc;
	poly64x2_t c = {(uint64_t)val<<32};

	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x8899AAFFULL, 0x103}, 0x00);//0x18899AAFFULL
	c = CL_MUL128(t, (poly64x2_t){0xFF, 0x103}, 0x10);// E83719AF 1D663B05D
	return c[1] /* & 0xFF */;
}

uint32_t CRC8B_update_40(uint32_t crc, uint8_t *data){
	uint64_t val=0;
	__builtin_memcpy(&val, data, 8);
	val ^= crc;
	poly64x2_t c = {(uint64_t)val<<24};
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x808182878899AAFF, 0x103}, 0x00);//0x18899AAFFULL
	c = CL_MUL128(t, (poly64x2_t){0x808182878899AAFF, 0x103}, 0x10);// E83719AF 1D663B05D
	return c[1] /* & 0xFF */;
}
uint32_t CRC8B_update_64(uint32_t crc, uint64_t val){
	poly64x2_t c = {val ^ crc};
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x808182878899AAFF, 0x103}, 0x00);
	c = CL_MUL128(t, (poly64x2_t){0x808182878899AAFF, 0x103}, 0x10);
	return c[1];
}
uint32_t CRC8B_update_128(uint32_t crc, uint8_t *data){
	poly64x2_t c = {crc};
	c ^= (poly64x2_t) LOAD128U(data);

	c = CL_MUL128(c, (poly64x2_t){0x81}, 0x00) //  7+64
	  ^ CL_MUL128(c, (poly64x2_t){0x01}, 0x01);//  7

	poly64x2_t t;
	t = CL_MUL128(c, (poly64x2_t){0x808182878899AAFF, 0x103}, 0x00);
	c^= CL_MUL128(t, (poly64x2_t){0x808182878899AAFF, 0x103}, 0x10);// E83719AF 1D663B05D
	return c[1] /*& 0xFF*/;
}
uint32_t CRC8B_update_N(uint32_t crc, uint8_t *data, int len){
	poly64x2_t c = {crc};
	int blocks = (len+15)>>4;
	while (--blocks>0) {
		c^= (poly64x2_t) LOAD128U(data);
		c = CL_MUL128(c, (poly64x2_t){0xC1}, 0x00) //  7+128
		  ^ CL_MUL128(c, (poly64x2_t){0x81}, 0x01);//  7+64
	}
	c^= (poly64x2_t) LOAD128U(data);

	c = CL_MUL128(c, (poly64x2_t){0x81}, 0x00) //  7+64
	  ^ CL_MUL128(c, (poly64x2_t){0x01}, 0x01);//  7

	poly64x2_t t;
	t = CL_MUL128(c, (poly64x2_t){0x808182878899AAFF, 0x103}, 0x00);
	c^= CL_MUL128(t, (poly64x2_t){0x808182878899AAFF, 0x103}, 0x10);// E83719AF 1D663B05D
	return c[1] /*& 0xFF*/;
}
uint32_t    CRC8B_update_8(uint32_t c, uint8_t val) {
	c ^= val;
	c ^= c<<4;
	c ^= c<<2;
	c ^= c<<1;
	c &= 0xFF;
	return (c ^ c>>7);
}
static const uint8_t CRC8I_Lookup4[] = {// POLY=0x1D
0x00, 0x1D, 0x3A, 0x27,
0x74, 0x69, 0x4E, 0x53,
0xE8, 0xF5, 0xD2, 0xCF,
0x9C, 0x81, 0xA6, 0xBB,
};
uint32_t    CRC8I_update(uint32_t crc, uint8_t val) {
	crc^= val;
	crc = (crc << 4) ^ CRC8I_Lookup4[(crc&0xFF) >> 4];
	crc = (crc << 4) ^ CRC8I_Lookup4[(crc&0xFF) >> 4];
	return crc & 0xFF;
}
uint32_t    CRC8I_update_8(uint32_t crc, uint8_t val) {
	uint64_t c = crc^val;
	//c<<=8;// это равносильно умножению на 0x100 mod Px = 0x07
	c = CL_MUL8(c, 0x1D);
	uint64_t t = CL_MUL8(c>>8, 0x1C)^c;
	c^= CL_MUL8(t>>8, 0x1D);
	return c & 0xFF;
}
uint32_t    CRC8I_update_16(uint32_t crc, uint8_t *data) {
	uint16_t val = 0;
	val = *(uint16_t*) data;
	val = __builtin_bswap16(val);
	uint64_t c = (crc<<8) ^ val;
	c= CL_MUL8(c>>8, 0x4C)
	 ^ CL_MUL8(c>>0, 0x1D);
	uint64_t t = CL_MUL8(c>>8, 0x1C)^c;
	c^= CL_MUL8(t>>8,0x1D);
	return c & 0xFF;
}
uint32_t    CRC8I_update_32(uint32_t crc, uint8_t *data) {
	uint32_t val = 0;
	val = *(uint32_t*) data;
	val = __builtin_bswap32(val);
	uint64_t c = (crc<<24)^val;
	c= CL_MUL8(c>>24, 0x9D) 
	 ^ CL_MUL8(c>>16, 0x8F) 
	 ^ CL_MUL8(c>> 8, 0x4C)
	 ^ CL_MUL8(c>> 0, 0x1D);
// Редуцирование 16 бит в 8 бит
	uint64_t t = CL_MUL8(c>>8, 0x1C)^c;// Ur
	c^= CL_MUL8(t>>8, 0x1D);// Pr
	return c & 0xFF;
}
/*
k3 = x^(192) mod P(x) = 0x82
k3 = x^(184) mod P(x) = 0x95
k3 = x^(176) mod P(x) = 0xE3
k3 = x^(168) mod P(x) = 0xFC
k3 = x^(160) mod P(x) = 0xE6
k3 = x^(152) mod P(x) = 0x49
k3 = x^(144) mod P(x) = 0xA8
k3 = x^(136) mod P(x) = 0x4F
k3 = x^(128) mod P(x) = 0x85
k3 = x^(120) mod P(x) = 0x3B
k3 = x^(112) mod P(x) = 0x81
k3 = x^(104) mod P(x) = 0x0D
k3 = x^(96) mod P(x) = 0xD9
k3 = x^(88) mod P(x) = 0xFE
k3 = x^(80) mod P(x) = 0xFD
k3 = x^(72) mod P(x) = 0x65
k3 = x^(64) mod P(x) = 0x5F
k3 = x^(56) mod P(x) = 0x5D
k3 = x^(48) mod P(x) = 0x46
k3 = x^(40) mod P(x) = 0x6A
k3 = x^(32) mod P(x) = 0x9D
k3 = x^(24) mod P(x) = 0x8F
k3 = x^(16) mod P(x) = 0x4C
k3 = x^(8) mod P(x) = 0x1D
*/
uint32_t    CRC8I_update_64(uint32_t crc, uint8_t *data) {
	uint64_t val = 0;
	val = *(uint64_t*) data;
	val = __builtin_bswap64(val);
	uint64_t c = ((uint64_t)crc<<56)^val;
	c= CL_MUL8(c>>56, 0x5F) 
	 ^ CL_MUL8(c>>48, 0x5D) 
	 ^ CL_MUL8(c>>40, 0x46) 
	 ^ CL_MUL8(c>>32, 0x6A) 
	 ^ CL_MUL8(c>>24, 0x9D) 
	 ^ CL_MUL8(c>>16, 0x8F) 
	 ^ CL_MUL8(c>> 8, 0x4C)
	 ^ CL_MUL8(c>> 0, 0x1D);
// Редуцирование 16 бит в 8 бит
	uint64_t t = CL_MUL8(c>>8, 0x1C)^c;// Ur
	c^= CL_MUL8(t>>8, 0x1D);// Pr
	return c & 0xFF;
}
uint32_t    CRC8I_update_128(uint32_t crc, uint8_t *data, int len) {
	uint64_t val = 0;
	val = *(uint64_t*) data;
	val = __builtin_bswap64(val);
	uint64_t c = ((uint64_t)crc<<56) ^ val;
	if (len & 7){
		data+=(len & 7);
		c>>= 64 - ((len&7)<<3);
	} else 
		data+=8;
	int blocks = (len+7 >> 3);
	while (--blocks>0) {// это одна операция на NEON
	
		c= CL_MUL8(c>>56, 0x3B) // <<120
		 ^ CL_MUL8(c>>48, 0x81) 
		 ^ CL_MUL8(c>>40, 0x0D) 
		 ^ CL_MUL8(c>>32, 0xD9) 
		 ^ CL_MUL8(c>>24, 0xFE) 
		 ^ CL_MUL8(c>>16, 0xFD) 
		 ^ CL_MUL8(c>> 8, 0x65) 
		 ^ CL_MUL8(c>> 0, 0x5F);// << 64
		val = *(uint64_t*) data; data+=8;
		val = __builtin_bswap64(val);
		c^= val;
	}
	// это одна операция на NEON
	c= CL_MUL8(c>>56, 0x5F) // << 64
	 ^ CL_MUL8(c>>48, 0x5D) 
	 ^ CL_MUL8(c>>40, 0x46) 
	 ^ CL_MUL8(c>>32, 0x6A) 
	 ^ CL_MUL8(c>>24, 0x9D) 
	 ^ CL_MUL8(c>>16, 0x8F) 
	 ^ CL_MUL8(c>> 8, 0x4C)
	 ^ CL_MUL8(c>> 0, 0x1D);
// Редуцирование 16 бит в 8 бит
	uint64_t t = CL_MUL8(c>>8, 0x1C) ^ c;// (c>>8)<<8; младшая часть все равно игнорируется
	c^= CL_MUL8(t>>8, 0x1D);
	return c & 0xFF;
}

#include <string.h>
unsigned char CRC5_BITMAIN(unsigned char *ptr, unsigned char bit_len)
{
	unsigned char crcout[5]={1, 1, 1, 1, 1};
    unsigned char crcin[5]={1, 1, 1, 1, 1};
	unsigned char i, j, k, din, crc=0x1f;
	for(i=0, j=0x80, k=0; i<bit_len; i++)
    {
        if(*ptr & j)
        {
            din=1;
        }
        else
        {
            din=0;
        }
        crcout[0]=crcin[4] ^ din;
        crcout[1]=crcin[0];
        crcout[2]=crcin[1] ^ crcin[4] ^ din;
        crcout[3]=crcin[2];
        crcout[4]=crcin[3];
        j=j >> 1;
        k++;
        if(k == 8)
        {
            j=0x80;
            k=0;
            ptr++;
        }
        memcpy(crcin, crcout, 5);
    }
    crc=0;
    if(crcin[4])
    {
        crc |= 0x10;
    }
    if(crcin[3])
    {
        crc |= 0x08;
    }
    if(crcin[2])
    {
        crc |= 0x04;
    }
    if(crcin[1])
    {
        crc |= 0x02;
    }
    if(crcin[0])
    {
        crc |= 0x01;
    }
    return crc;
}

static const uint8_t CRC5B_Lookup4[] = {
0x0, 0x16, 0x5, 0x13,
0xA, 0x1C, 0xF, 0x19,
0x14, 0x2, 0x11, 0x7,
0x1E, 0x8, 0x1B, 0xD,
};
uint32_t    CRC5B_update(uint32_t crc, uint8_t val) 
{
	crc^= val;
	crc = (crc>>4) ^ CRC5B_Lookup4[(crc) & 0xF];
	crc = (crc>>4) ^ CRC5B_Lookup4[(crc) & 0xF];
	return crc & 0x1F;
}
static const uint8_t CRC8SN_Lookup[256] = {
0x00, 0x31, 0x62, 0x53, 0xC4, 0xF5, 0xA6, 0x97,
0xB9, 0x88, 0xDB, 0xEA, 0x7D, 0x4C, 0x1F, 0x2E,
0x43, 0x72, 0x21, 0x10, 0x87, 0xB6, 0xE5, 0xD4,
0xFA, 0xCB, 0x98, 0xA9, 0x3E, 0x0F, 0x5C, 0x6D,
0x86, 0xB7, 0xE4, 0xD5, 0x42, 0x73, 0x20, 0x11,
0x3F, 0x0E, 0x5D, 0x6C, 0xFB, 0xCA, 0x99, 0xA8,
0xC5, 0xF4, 0xA7, 0x96, 0x01, 0x30, 0x63, 0x52,
0x7C, 0x4D, 0x1E, 0x2F, 0xB8, 0x89, 0xDA, 0xEB,
0x3D, 0x0C, 0x5F, 0x6E, 0xF9, 0xC8, 0x9B, 0xAA,
0x84, 0xB5, 0xE6, 0xD7, 0x40, 0x71, 0x22, 0x13,
0x7E, 0x4F, 0x1C, 0x2D, 0xBA, 0x8B, 0xD8, 0xE9,
0xC7, 0xF6, 0xA5, 0x94, 0x03, 0x32, 0x61, 0x50,
0xBB, 0x8A, 0xD9, 0xE8, 0x7F, 0x4E, 0x1D, 0x2C,
0x02, 0x33, 0x60, 0x51, 0xC6, 0xF7, 0xA4, 0x95,
0xF8, 0xC9, 0x9A, 0xAB, 0x3C, 0x0D, 0x5E, 0x6F,
0x41, 0x70, 0x23, 0x12, 0x85, 0xB4, 0xE7, 0xD6,
0x7A, 0x4B, 0x18, 0x29, 0xBE, 0x8F, 0xDC, 0xED,
0xC3, 0xF2, 0xA1, 0x90, 0x07, 0x36, 0x65, 0x54,
0x39, 0x08, 0x5B, 0x6A, 0xFD, 0xCC, 0x9F, 0xAE,
0x80, 0xB1, 0xE2, 0xD3, 0x44, 0x75, 0x26, 0x17,
0xFC, 0xCD, 0x9E, 0xAF, 0x38, 0x09, 0x5A, 0x6B,
0x45, 0x74, 0x27, 0x16, 0x81, 0xB0, 0xE3, 0xD2,
0xBF, 0x8E, 0xDD, 0xEC, 0x7B, 0x4A, 0x19, 0x28,
0x06, 0x37, 0x64, 0x55, 0xC2, 0xF3, 0xA0, 0x91,
0x47, 0x76, 0x25, 0x14, 0x83, 0xB2, 0xE1, 0xD0,
0xFE, 0xCF, 0x9C, 0xAD, 0x3A, 0x0B, 0x58, 0x69,
0x04, 0x35, 0x66, 0x57, 0xC0, 0xF1, 0xA2, 0x93,
0xBD, 0x8C, 0xDF, 0xEE, 0x79, 0x48, 0x1B, 0x2A,
0xC1, 0xF0, 0xA3, 0x92, 0x05, 0x34, 0x67, 0x56,
0x78, 0x49, 0x1A, 0x2B, 0xBC, 0x8D, 0xDE, 0xEF,
0x82, 0xB3, 0xE0, 0xD1, 0x46, 0x77, 0x24, 0x15,
0x3B, 0x0A, 0x59, 0x68, 0xFF, 0xCE, 0x9D, 0xAC,
};
uint8_t    CRC8SN_update8(uint8_t crc, uint8_t val) 
{
	crc^= val;
	crc = CRC8SN_Lookup[crc];
	return crc & 0xFF;
}
uint8_t    CRC8SN_update(uint8_t crc, uint8_t val) 
{
	crc^= val;
	crc = (crc<<4)^CRC8SN_Lookup[crc>>4];
	crc = (crc<<4)^CRC8SN_Lookup[crc>>4];
	return crc & 0xFF;
}
/*
CRC-5/BITMAIN
    width=5 poly=0x05 init=0x1f refin=false refout=false xorout=0x0 check=0x0F name="CRC-5/BITMAIN"
*/
static const uint8_t CRC5_Lookup[256] = {
0x00, 0x28, 0x50, 0x78,
0xA0, 0x88, 0xF0, 0xD8,
0x68, 0x40, 0x38, 0x10,
0xC8, 0xE0, 0x98, 0xB0,
0xD0, 0xF8, 0x80, 0xA8,
0x70, 0x58, 0x20, 0x08,
0xB8, 0x90, 0xE8, 0xC0,
0x18, 0x30, 0x48, 0x60,
0x88, 0xA0, 0xD8, 0xF0,
0x28, 0x00, 0x78, 0x50,
0xE0, 0xC8, 0xB0, 0x98,
0x40, 0x68, 0x10, 0x38,
0x58, 0x70, 0x08, 0x20,
0xF8, 0xD0, 0xA8, 0x80,
0x30, 0x18, 0x60, 0x48,
0x90, 0xB8, 0xC0, 0xE8,
0x38, 0x10, 0x68, 0x40,
0x98, 0xB0, 0xC8, 0xE0,
0x50, 0x78, 0x00, 0x28,
0xF0, 0xD8, 0xA0, 0x88,
0xE8, 0xC0, 0xB8, 0x90,
0x48, 0x60, 0x18, 0x30,
0x80, 0xA8, 0xD0, 0xF8,
0x20, 0x08, 0x70, 0x58,
0xB0, 0x98, 0xE0, 0xC8,
0x10, 0x38, 0x40, 0x68,
0xD8, 0xF0, 0x88, 0xA0,
0x78, 0x50, 0x28, 0x00,
0x60, 0x48, 0x30, 0x18,
0xC0, 0xE8, 0x90, 0xB8,
0x08, 0x20, 0x58, 0x70,
0xA8, 0x80, 0xF8, 0xD0,
0x70, 0x58, 0x20, 0x08,
0xD0, 0xF8, 0x80, 0xA8,
0x18, 0x30, 0x48, 0x60,
0xB8, 0x90, 0xE8, 0xC0,
0xA0, 0x88, 0xF0, 0xD8,
0x00, 0x28, 0x50, 0x78,
0xC8, 0xE0, 0x98, 0xB0,
0x68, 0x40, 0x38, 0x10,
0xF8, 0xD0, 0xA8, 0x80,
0x58, 0x70, 0x08, 0x20,
0x90, 0xB8, 0xC0, 0xE8,
0x30, 0x18, 0x60, 0x48,
0x28, 0x00, 0x78, 0x50,
0x88, 0xA0, 0xD8, 0xF0,
0x40, 0x68, 0x10, 0x38,
0xE0, 0xC8, 0xB0, 0x98,
0x48, 0x60, 0x18, 0x30,
0xE8, 0xC0, 0xB8, 0x90,
0x20, 0x08, 0x70, 0x58,
0x80, 0xA8, 0xD0, 0xF8,
0x98, 0xB0, 0xC8, 0xE0,
0x38, 0x10, 0x68, 0x40,
0xF0, 0xD8, 0xA0, 0x88,
0x50, 0x78, 0x00, 0x28,
0xC0, 0xE8, 0x90, 0xB8,
0x60, 0x48, 0x30, 0x18,
0xA8, 0x80, 0xF8, 0xD0,
0x08, 0x20, 0x58, 0x70,
0x10, 0x38, 0x40, 0x68,
0xB0, 0x98, 0xE0, 0xC8,
0x78, 0x50, 0x28, 0x00,
0xD8, 0xF0, 0x88, 0xA0,
};
uint32_t    CRC5_update(uint32_t crc, uint8_t val) 
{
	crc = (crc<<3) ^ val;
	crc = (crc << 4) ^ CRC5_Lookup[(crc & 0xFF)>>4];
	crc = (crc << 4) ^ CRC5_Lookup[(crc & 0xFF)>>4];
	return (crc>>3) & 0x1F;
}
uint32_t    CRC5_update8(uint32_t crc, uint8_t val) 
{
	crc = (crc<<3) ^ val;
	crc = CRC5_Lookup[crc & 0xFF];
	return (crc>>3) & 0x1F;
}
static unsigned char    CRC5_update_len(unsigned char *ptr, int bits) 
{
	uint8_t crc = 0xF8;//(crc<<3);
	int i;
	for (i=0; i< (bits>>3); i++)
		crc = CRC5_Lookup[crc ^ (*ptr++)];
	bits &= 7;
	if (bits) {
		crc = (crc << bits) ^ CRC5_Lookup[(crc ^ (*ptr++))>>(8-bits)];
	}
	return (crc>>3);
}
static const uint8_t CRC8S_Lookup4[] = {
	0x00, 0x07, 0x0E, 0x09,
	0x1C, 0x1B, 0x12, 0x15,
	0x38, 0x3F, 0x36, 0x31,
	0x24, 0x23, 0x2A, 0x2D,
};
uint8_t    CRC8S_update(uint8_t crc, uint8_t val) {
	crc^= val;
	crc = (crc << 4) ^ CRC8S_Lookup4[(crc&0xFF) >> 4];
	crc = (crc << 4) ^ CRC8S_Lookup4[(crc&0xFF) >> 4];
	return crc & 0xFF;
}
static const uint8_t CRC8_Lookup4[] = {
	0x00, 0x07, 0x0E, 0x09,
	0x1C, 0x1B, 0x12, 0x15,
	0x38, 0x3F, 0x36, 0x31,
	0x24, 0x23, 0x2A, 0x2D,
};
uint32_t    CRC8_update(uint32_t crc, uint8_t val) {
	crc^= val;
	crc = (crc << 4) ^ CRC8_Lookup4[(crc&0xFF) >> 4];
	crc = (crc << 4) ^ CRC8_Lookup4[(crc&0xFF) >> 4];
	return crc & 0xFF;
}
uint32_t    CRC8_update_8(uint32_t crc, uint8_t val) {
	uint64_t c = crc^val;
	//c<<=8;// это равносильно умножению на 0x100 mod Px = 0x07
	c = CL_MUL8(c, 0x07);
	uint64_t t = CL_MUL8(c>>8, 0x07)^c;
	c^= CL_MUL8(t>>8, 0x07);
	return c & 0xFF;
}
uint32_t    CRC8_update_16(uint32_t crc, uint8_t *data) {
	uint16_t val = 0;
	val = *(uint16_t*) data;
	val = __builtin_bswap16(val);
	uint64_t c = (crc<<8) ^ val;
	c= CL_MUL8(c>>8, 0x15)
	 ^ CL_MUL8(c>>0, 0x07);
	uint64_t t = CL_MUL8(c>>8, 0x07)^c;
	c^= CL_MUL8(t>>8,0x07);
	return c & 0xFF;
}
uint32_t    CRC8_update_24(uint32_t crc, uint8_t *data) {
	uint32_t val = 0;
	val = *(uint32_t*) data;
	val = __builtin_bswap32(val);
	uint64_t c = (crc<<16) ^ (val>>8);
	c= (c<<8)
	 ^ CL_MUL8(c>>16, 0x6B) 
	 ^ CL_MUL8(c>> 8, 0x15);
// Редуцирование 16 бит в 8 бит
	uint64_t t = CL_MUL8(c>>8, 0x07)^c;
	c^= CL_MUL8(t>>8, 0x07);
	return c & 0xFF;
}
uint32_t    CRC8_update_32(uint32_t crc, uint8_t *data) {
	uint32_t val = 0;
	val = *(uint32_t*) data;
	val = __builtin_bswap32(val);
	uint64_t c = (crc<<24)^val;
	c= CL_MUL8(c>>24, 0x16) 
	 ^ CL_MUL8(c>>16, 0x6B) 
	 ^ CL_MUL8(c>> 8, 0x15)
	 ^ CL_MUL8(c>> 0, 0x07);
// Редуцирование 16 бит в 8 бит
	uint64_t t = CL_MUL8(c>>8, 0x07)^c;
	c^= CL_MUL8(t>>8, 0x07);
	return c & 0xFF;
}
uint32_t    CRC8_update_64(uint32_t crc, uint8_t *data) {
	uint64_t val = 0;
	val = *(uint64_t*) data;
	val = __builtin_bswap64(val);
	uint64_t c = ((uint64_t)crc<<56)^val;
	c= CL_MUL8(c>>56, 0x13) 
	 ^ CL_MUL8(c>>48, 0xDF) 
	 ^ CL_MUL8(c>>40, 0x29) 
	 ^ CL_MUL8(c>>32, 0x62) 
	 ^ CL_MUL8(c>>24, 0x16) 
	 ^ CL_MUL8(c>>16, 0x6B) 
	 ^ CL_MUL8(c>> 8, 0x15)
	 ^ CL_MUL8(c>> 0, 0x07);
// Редуцирование 16 бит в 8 бит
	uint64_t t = CL_MUL8(c>>8, 0x07)^c;
	c^= CL_MUL8(t>>8, 0x07);
	return c & 0xFF;
}
uint32_t    CRC8_update_128(uint32_t crc, uint8_t *data, int len) {
	uint64_t val = 0;
	val = *(uint64_t*) data;
	val = __builtin_bswap64(val);
	uint64_t c = ((uint64_t)crc<<56) ^ val;
	if (len & 7){
		data+=(len & 7);
		c>>= 64 - ((len&7)<<3);
	} else 
		data+=8;
	int blocks = (len+7 >> 3);
	while (--blocks>0) {// это одна операция на NEON
	
		c= CL_MUL8(c>>56, 0xB5) 
		 ^ CL_MUL8(c>>48, 0xE5) 
		 ^ CL_MUL8(c>>40, 0x94) 
		 ^ CL_MUL8(c>>32, 0x5D) 
		 ^ CL_MUL8(c>>24, 0x1F) 
		 ^ CL_MUL8(c>>16, 0x68) 
		 ^ CL_MUL8(c>> 8, 0x79) 
		 ^ CL_MUL8(c>> 0, 0x13);
		val = *(uint64_t*) data; data+=8;
		val = __builtin_bswap64(val);
		c^= val;
	}
	// это одна операция на NEON
	c= CL_MUL8(c>>56, 0x13)//  <<64
	 ^ CL_MUL8(c>>48, 0xDF)//  <<56
	 ^ CL_MUL8(c>>40, 0x29)//  <<48
	 ^ CL_MUL8(c>>32, 0x62)//  <<40
	 ^ CL_MUL8(c>>24, 0x16)//  <<32
	 ^ CL_MUL8(c>>16, 0x6B)//  <<24
	 ^ CL_MUL8(c>> 8, 0x15)//  <<16
	 ^ CL_MUL8(c>> 0, 0x07);// << 8
// Редуцирование 16 бит в 8 бит
	uint64_t t = CL_MUL8(c>>8, 0x07) ^ c;// (c>>8)<<8; младшая часть все равно игнорируется
	c^= CL_MUL8(t>>8, 0x07);
	return c & 0xFF;
}
uint32_t    CRC16_update_64(uint32_t crc, uint8_t *data, int len) {
	uint64_t val = 0;
	val = *(uint64_t*) data; data+= (len & 7)?(len & 7):8;
	val = __builtin_bswap64(val);
	uint64_t c = (((uint64_t)crc<<48)^val)>>((len & 7)<<3);
	int blocks = (len+7 >> 3);
	while (--blocks>0) {
		// эту операцию можно заменить на CL_MUL128(c,0xB861);
		c= CL_MUL16(c>>48, 0x4563) 
		 ^ CL_MUL16(c>>32, 0xD849) 
		 ^ CL_MUL16(c>>16, 0xEB23) 
		 ^ CL_MUL16(c>> 0, 0xB861);
		val = *(uint64_t*) data; data+=8;
		val = __builtin_bswap64(val);
		c^= val;
	}
	// эту вывернуть, чтобы расчет был на границе
	c= CL_MUL16(c>>48, 0xB861) 
	 ^ CL_MUL16(c>>32, 0xAA51) 
	 ^ CL_MUL16(c>>16, 0x3730) 
	 ^ CL_MUL16(c>> 0, 0x1021);
// Редуцирование 16 бит в 8 бит
	uint64_t t = CL_MUL16(c>>16, 0x1130) ^ c;//c>>16<<16;
	c^= CL_MUL16(t>>16, 0x1021);
	return c & 0xFFFF;
}
static const uint16_t CRC15_Lookup[256] = {
0x0000, 0x8B32, 0x9D56, 0x1664, 0xB19E, 0x3AAC, 0x2CC8, 0xA7FA,
0xE80E, 0x633C, 0x7558, 0xFE6A, 0x5990, 0xD2A2, 0xC4C6, 0x4FF4,
0x5B2E, 0xD01C, 0xC678, 0x4D4A, 0xEAB0, 0x6182, 0x77E6, 0xFCD4,
0xB320, 0x3812, 0x2E76, 0xA544, 0x02BE, 0x898C, 0x9FE8, 0x14DA,
0xB65C, 0x3D6E, 0x2B0A, 0xA038, 0x07C2, 0x8CF0, 0x9A94, 0x11A6,
0x5E52, 0xD560, 0xC304, 0x4836, 0xEFCC, 0x64FE, 0x729A, 0xF9A8,
0xED72, 0x6640, 0x7024, 0xFB16, 0x5CEC, 0xD7DE, 0xC1BA, 0x4A88,
0x057C, 0x8E4E, 0x982A, 0x1318, 0xB4E2, 0x3FD0, 0x29B4, 0xA286,
0xE78A, 0x6CB8, 0x7ADC, 0xF1EE, 0x5614, 0xDD26, 0xCB42, 0x4070,
0x0F84, 0x84B6, 0x92D2, 0x19E0, 0xBE1A, 0x3528, 0x234C, 0xA87E,
0xBCA4, 0x3796, 0x21F2, 0xAAC0, 0x0D3A, 0x8608, 0x906C, 0x1B5E,
0x54AA, 0xDF98, 0xC9FC, 0x42CE, 0xE534, 0x6E06, 0x7862, 0xF350,
0x51D6, 0xDAE4, 0xCC80, 0x47B2, 0xE048, 0x6B7A, 0x7D1E, 0xF62C,
0xB9D8, 0x32EA, 0x248E, 0xAFBC, 0x0846, 0x8374, 0x9510, 0x1E22,
0x0AF8, 0x81CA, 0x97AE, 0x1C9C, 0xBB66, 0x3054, 0x2630, 0xAD02,
0xE2F6, 0x69C4, 0x7FA0, 0xF492, 0x5368, 0xD85A, 0xCE3E, 0x450C,
0x4426, 0xCF14, 0xD970, 0x5242, 0xF5B8, 0x7E8A, 0x68EE, 0xE3DC,
0xAC28, 0x271A, 0x317E, 0xBA4C, 0x1DB6, 0x9684, 0x80E0, 0x0BD2,
0x1F08, 0x943A, 0x825E, 0x096C, 0xAE96, 0x25A4, 0x33C0, 0xB8F2,
0xF706, 0x7C34, 0x6A50, 0xE162, 0x4698, 0xCDAA, 0xDBCE, 0x50FC,
0xF27A, 0x7948, 0x6F2C, 0xE41E, 0x43E4, 0xC8D6, 0xDEB2, 0x5580,
0x1A74, 0x9146, 0x8722, 0x0C10, 0xABEA, 0x20D8, 0x36BC, 0xBD8E,
0xA954, 0x2266, 0x3402, 0xBF30, 0x18CA, 0x93F8, 0x859C, 0x0EAE,
0x415A, 0xCA68, 0xDC0C, 0x573E, 0xF0C4, 0x7BF6, 0x6D92, 0xE6A0,
0xA3AC, 0x289E, 0x3EFA, 0xB5C8, 0x1232, 0x9900, 0x8F64, 0x0456,
0x4BA2, 0xC090, 0xD6F4, 0x5DC6, 0xFA3C, 0x710E, 0x676A, 0xEC58,
0xF882, 0x73B0, 0x65D4, 0xEEE6, 0x491C, 0xC22E, 0xD44A, 0x5F78,
0x108C, 0x9BBE, 0x8DDA, 0x06E8, 0xA112, 0x2A20, 0x3C44, 0xB776,
0x15F0, 0x9EC2, 0x88A6, 0x0394, 0xA46E, 0x2F5C, 0x3938, 0xB20A,
0xFDFE, 0x76CC, 0x60A8, 0xEB9A, 0x4C60, 0xC752, 0xD136, 0x5A04,
0x4EDE, 0xC5EC, 0xD388, 0x58BA, 0xFF40, 0x7472, 0x6216, 0xE924,
0xA6D0, 0x2DE2, 0x3B86, 0xB0B4, 0x174E, 0x9C7C, 0x8A18, 0x012A,
};
CRC16	CRC15_update(CRC16 crc, uint8_t val){
	crc<<=1;
	crc^= (val<<8);
	crc = (crc << 4) ^ CRC15_Lookup[(crc>>12) & 0xF];
	crc = (crc << 4) ^ CRC15_Lookup[(crc>>12) & 0xF];
	return (crc>>1);
}
CRC16	CRC15_update8(CRC16 crc, uint8_t val){
	crc<<=1;
	crc^= (val<<8);
	crc = (crc << 8) ^ CRC15_Lookup[crc>>8];
	return (crc>>1);
}


static const uint16_t CRC16B_Lookup4[16] = {
0x0000, 0xCC01, 0xD801, 0x1400,
0xF001, 0x3C00, 0x2800, 0xE401,
0xA001, 0x6C00, 0x7800, 0xB401,
0x5000, 0x9C01, 0x8801, 0x4400,
};
#define POLY16B	0x1081
CRC16	CRC16B_update(CRC16 crc, uint8_t val){
	crc^= val;
	crc = (crc >> 4) ^ (POLY16B* (crc & 0xF));
	crc = (crc >> 4) ^ (POLY16B* (crc & 0xF));
	return crc;
}
// Структура коэффициентов
struct _CRC_ctx {
	poly64x2_t K34[16];
	poly64x2_t K12;//!< fold by 1 (128 bits)
	poly64x2_t KBP;//!< final reduction: Barrett's constant and Polynom
	poly64x2_t KF2;//!< fold by 2
	poly64x2_t KF3;//!< fold by 3
	poly64x2_t KF4;//!< fold by 4
	poly64x2_t KF5;//!< fold by 4
};

static const struct _CRC_ctx CRC64XZ_ctx = {
.KBP = {0x9C3E466C172963D5ULL, 0x92D8AF2BAF0E1E85ULL},
.K12 = {0xE05DD497CA393AE4ULL, 0xDABE95AFC7875F40ULL},// x^{191}, x^{127}
.K34 = {
[ 1] = {0x0100000000000000ULL, 0x78E4CCEE804FE350ULL},// x^{7} , x^{-57}
[ 2] = {0x0001000000000000ULL, 0x19556E3E5470AE0BULL},// x^{15}, x^{-49}
[ 3] = {0x0000010000000000ULL, 0xB012A88E6AAD33FCULL},// x^{23}, x^{-41}
[ 4] = {0x0000000100000000ULL, 0xA7B7C93241EA6D5EULL},// x^{31}, x^{-33}
[ 5] = {0x0000000001000000ULL, 0x617F4FE12060498BULL},// x^{39}, x^{-25}
[ 6] = {0x0000000000010000ULL, 0x7906D53A625E2C59ULL},// x^{47}, x^{-17}
[ 7] = {0x0000000000000100ULL, 0x5DDB47907C2B5CCDULL},// x^{55}, x^{-9}
[ 8] = {0x0000000000000001ULL, 0x92D8AF2BAF0E1E85ULL},// x^{63}, x^{-1}
[ 9] = {0xB32E4CBE03A75F6FULL, 0x0100000000000000ULL},// x^{71}, x^{7}
[10] = {0x54E979925CD0F10DULL, 0x0001000000000000ULL},// x^{79}, x^{15}
[11] = {0x3F0BE14A916A6DCBULL, 0x0000010000000000ULL},// x^{87}, x^{23}
[12] = {0x1DEE8A5E222CA1DCULL, 0x0000000100000000ULL},// x^{95}, x^{31}
[13] = {0x5C2D776033C4205EULL, 0x0000000001000000ULL},// x^{103}, x^{39}
[14] = {0x6184D55F721267C6ULL, 0x0000000000010000ULL},// x^{111}, x^{47}
[15] = {0x22EF0D5934F964ECULL, 0x0000000000000100ULL},// x^{119}, x^{55}
[ 0] = {0xDABE95AFC7875F40ULL, 0x0000000000000001ULL},// x^{127}, x^{63}
}};
static const struct _CRC_ctx CRC32B_ctx= {
.KBP = {0xB4E5B025F7011641, 0x1DB710641},
.KF5 = {0x1C279815, 0xAE0B5394},
.KF4 = {0x8F352D95, 0x1D9513D7},
.KF3 = {0x3DB1ECDC, 0xAF449247},
.KF2 = {0xF1DA05AA, 0x81256527},
.K12 = {0xAE689191, 0xCCAA009E},
.K34 = {
[ 1] = {0x3F036DC2, 0x40B3A940},// x^{-25}, x^{-89}
[ 2] = {0x7555A0F1, 0x769CF239},// x^{-17}, x^{-81}
[ 3] = {0xCACF972A, 0x5F7314FA},// x^{-9}, x^{-73}
[ 4] = {0xDB710641, 0x5D376816},// x^{-1}, x^{-65}
[ 5] = {0x01000000, 0xF4898239},// x^{7}, x^{-57}
[ 6] = {0x00010000, 0x5FF1018A},// x^{15}, x^{-49}
[ 7] = {0x00000100, 0x0D329B3F},// x^{23}, x^{-41}
[ 8] = {0x00000001, 0xB66B1FA6},// x^{31}, x^{-33}
[ 9] = {0x77073096, 0x3F036DC2},// x^{39}, x^{-25}
[10] = {0x191B3141, 0x7555A0F1},// x^{47}, x^{-17}
[11] = {0x01C26A37, 0xCACF972A},// x^{55}, x^{-9}
[12] = {0xB8BC6765, 0xDB710641},// x^{63}, x^{-1}
[13] = {0x3D6029B0, 0x01000000},// x^{71}, x^{7}
[14] = {0xCB5CD3A5, 0x00010000},// x^{79}, x^{15}
[15] = {0xA6770BB4, 0x00000100},// x^{87}, x^{23}
[ 0] = {0xCCAA009E, 0x00000001},// x^{95}, x^{31}
}};

// CRC-32C (Castagnoli)
static const struct _CRC_ctx CRC32C_ctx= {
.KBP = {0x4869EC38DEA713F1, 0x105EC76F1},
.KF5 = {0x083A6EEC, 0x39D3B296},
.KF4 = {0x740EEF02, 0x9E4ADDF8},
.KF3 = {0x1C291D04, 0xDDC0152B},
.KF2 = {0x3DA6D0CB, 0xBA4FC28E},
.K12 = {0xF20C0DFE, 0x493C7D27},
.K34 = {
[ 1] = {0xBF818109, 0xF838CD50},// x^{-25}, x^{-89}
[ 2] = {0x780D5A4D, 0x51DDE21E},// x^{-17}, x^{-81}
[ 3] = {0xFE2B5C35, 0xBC77A5AA},// x^{-9}, x^{-73}
[ 4] = {0x05EC76F1, 0xC915EA3B},// x^{-1}, x^{-65}
[ 5] = {0x01000000, 0xA9A3F760},// x^{7}, x^{-57}
[ 6] = {0x00010000, 0x616F3095},// x^{15}, x^{-49}
[ 7] = {0x00000100, 0xA738873B},// x^{23}, x^{-41}
[ 8] = {0x00000001, 0xA9CDDA0D},// x^{31}, x^{-33}
[ 9] = {0xF26B8303, 0xBF818109},// x^{39}, x^{-25}
[10] = {0x13A29877, 0x780D5A4D},// x^{47}, x^{-17}
[11] = {0xA541927E, 0xFE2B5C35},// x^{55}, x^{-9}
[12] = {0xDD45AAB8, 0x05EC76F1},// x^{63}, x^{-1}
[13] = {0x38116FAC, 0x01000000},// x^{71}, x^{7}
[14] = {0xEF306B19, 0x00010000},// x^{79}, x^{15}
[15] = {0x68032CC8, 0x00000100},// x^{87}, x^{23}
[ 0] = {0x493C7D27, 0x00000001},// x^{95}, x^{31}
}};
// CRC-32K/BACnet (Koopman)
static const struct _CRC_ctx CRC32K_ctx= {
.KBP = {0xC25DD01C17D232CD, 0x1D663B05D},
.KF5 = {0x46CC6B97, 0x7FD4456B},
.KF4 = {0x1609284B, 0xBE6D8F38},
.KF3 = {0x97259F1A, 0x63C7D97F},
.KF2 = {0x9C899030, 0xADFA5198},
.K12 = {0x7B4BC878, 0x9D65B2A5},// x^{159}, x^{95}
.K34 = {
[ 1] = {0x91F9A353, 0x13F534A1},// x^{-25}, x^{-89}
[ 2] = {0x9B1BE78B, 0xAC4A47F5},// x^{-17}, x^{-81}
[ 3] = {0xC790B954, 0x7A51D862},// x^{-9}, x^{-73}
[ 4] = {0xD663B05D, 0x5F572A23},// x^{-1}, x^{-65}
[ 5] = {0x01000000, 0xBC7F040C},// x^{7}, x^{-57}
[ 6] = {0x00010000, 0x61A83B55},// x^{15}, x^{-49}
[ 7] = {0x00000100, 0x40504C15},// x^{23}, x^{-41}
[ 8] = {0x00000001, 0x35E95875},// x^{31}, x^{-33}
[ 9] = {0x9695C4CA, 0x91F9A353},// x^{39}, x^{-25}
[10] = {0x24901FAA, 0x9B1BE78B},// x^{47}, x^{-17}
[11] = {0x80475843, 0xC790B954},// x^{55}, x^{-9}
[12] = {0x18C5564C, 0xD663B05D},// x^{63}, x^{-1}
[13] = {0x14946D10, 0x01000000},// x^{71}, x^{7}
[14] = {0x83DB9B51, 0x00010000},// x^{79}, x^{15}
[15] = {0x6041FC7A, 0x00000100},// x^{87}, x^{23}
[ 0] = {0x9D65B2A5, 0x00000001},// x^{95}, x^{31}
}};

static const struct _CRC_ctx CRC16M_ctx= {
.KBP = {0xF0FFEBFFCFFFBFFF, 0x14003},
.K12 = {0x90C1, 0xCCC1},// x^{143}, x^{79}
.K34 = {
[ 1] = {0x2666, 0x9BDB},// x^{-41}, x^{-105}
[ 2] = {0x2AA6, 0x5BDB},// x^{-33}, x^{-97}
[ 3] = {0x7AAA, 0x5B1B},// x^{-25}, x^{-89}
[ 4] = {0x7FFA, 0x0B1B},// x^{-17}, x^{-81}
[ 5] = {0x43FF, 0x0B4B},// x^{-9}, x^{-73}
[ 6] = {0x4003, 0x374B},// x^{-1}, x^{-65}
[ 7] = {0x0100, 0x3777},// x^{7}, x^{-57}
[ 8] = {0x0001, 0x2677},// x^{15}, x^{-49}
[ 9] = {0xC0C1, 0x2666},// x^{23}, x^{-41}
[10] = {0x9001, 0x2AA6},// x^{31}, x^{-33}
[11] = {0xC051, 0x7AAA},// x^{39}, x^{-25}
[12] = {0xFC01, 0x7FFA},// x^{47}, x^{-17}
[13] = {0xC03D, 0x43FF},// x^{55}, x^{-9}
[14] = {0xD101, 0x4003},// x^{63}, x^{-1}
[15] = {0xC010, 0x0100},// x^{71}, x^{7}
[ 0] = {0xCCC1, 0x0001},// x^{79}, x^{15}
}};
static const struct _CRC_ctx CRC16B_ctx= {
.KBP = {0x859B040B1C581911ULL, 0x10811ULL},
.K12 = {0x8E10, 0x81BF},// x^{143}, x^{79} 128+16-1  64+(16-1)
.K34 = {
[ 1] = {0x4EA8, 0x97B7},// x^{-41}, x^{-105} i*8+64+(-128+16-1), -120+16-1
[ 2] = {0x290C, 0xC1A3},// x^{-33}, x^{-97}
[ 3] = {0xCA45, 0x9750},// x^{-25}, x^{-89}
[ 4] = {0x1563, 0x5212},// x^{-17}, x^{-81}
[ 5] = {0x5188, 0x33C1},// x^{-9}, x^{-73}
[ 6] = {0x0811, 0xD7B6},// x^{-1}, x^{-65}
[ 7] = {0x0100, 0xD06A},// x^{ 7}, x^{-57}
[ 8] = {0x0001, 0xCC8C},// x^{15}, x^{-49}
[ 9] = {0x1189, 0x4EA8},// x^{23}, x^{-41}
[10] = {0x19D8, 0x290C},// x^{31}, x^{-33}
[11] = {0x5ADC, 0xCA45},// x^{39}, x^{-25}
[12] = {0x1CBB, 0x1563},// x^{47}, x^{-17}
[13] = {0x0B44, 0x5188},// x^{55}, x^{-9}
[14] = {0x042B, 0x0811},// x^{63}, x^{-1}
[15] = {0x9FD5, 0x0100},// x^{71}, x^{ 7}
[ 0] = {0x81BF, 0x0001},// x^{79}, x^{15} 64+16-1  16-1
}};
static const struct _CRC_ctx CRC8B_ctx= {
.KBP = 	   {0x808182878899AAFFULL, 0x103ULL},
.K12 =     {0xC1, 0x81},// x^{135}, x^{71}
.K34 = {
[ 1] = {0xFF, 0xFD},// x^{-49}, x^{-113}
[ 2] = {0x55, 0xAA},// x^{-41}, x^{-105}
[ 3] = {0x33, 0x66},// x^{-33}, x^{-97}
[ 4] = {0x11, 0x22},// x^{-25}, x^{-89}
[ 5] = {0x0F, 0x1E},// x^{-17}, x^{-81}
[ 6] = {0x05, 0x0A},// x^{-9}, x^{-73}
[ 7] = {0x03, 0x06},// x^{-1}, x^{-65}
[ 8] = {0x01, 0x02},// x^{7}, x^{-57}
[ 9] = {0xFE, 0xFF},// x^{15}, x^{-49}
[10] = {0xAB, 0x55},// x^{23}, x^{-41}
[11] = {0x98, 0x33},// x^{31}, x^{-33}
[12] = {0x89, 0x11},// x^{39}, x^{-25}
[13] = {0x86, 0x0F},// x^{47}, x^{-17}
[14] = {0x83, 0x05},// x^{55}, x^{-9}
[15] = {0x80, 0x03},// x^{63}, x^{-1}
[ 0] = {0x81, 0x01},// x^{71}, x^{7}
}};
const struct _CRC_ctx CRC32_ctx= {
.KBP = {0x04D101DF481B4E5A, 0x04C11DB700000000},
.KF4 = {0xE6228B11, 0x8833794C},
.KF3 = {0x8C3828A8, 0x64BF7A9B},
.KF2 = {0x75BE46B7, 0x569700E5},
.K12 = {0xE8A45605, 0xC5B9CD4C},// x^{128}, x^{192}
.K34 = {
[ 1] = {0x052B9A0400000000, 0x876D81F800000000},// x^{-88}, x^{-24}
[ 2] = {0x3C5F6F6B00000000, 0x1ACA48EB00000000},// x^{-80}, x^{-16}
[ 3] = {0xBE519DF400000000, 0xA9D3E6A600000000},// x^{-72}, x^{-8}
[ 4] = {0xD02DD97400000000, 0x0000000100000000},// x^{-64}, x^{ 0}
[ 5] = {0x3C423FE900000000, 0x0000010000000000},// x^{-56}, x^{ 8}
[ 6] = {0xA3011FF400000000, 0x0001000000000000},// x^{-48}, x^{16}
[ 7] = {0xFD7384D700000000, 0x0100000000000000},// x^{-40}, x^{24}
[ 8] = {0xCBF1ACDA00000000, 0x04C11DB700000000},// x^{-32}, x^{32}
[ 9] = {0x876D81F800000000, 0xD219C1DC00000000},// x^{-24}, x^{40}
[10] = {0x1ACA48EB00000000, 0x01D8AC8700000000},// x^{-16}, x^{48}
[11] = {0xA9D3E6A600000000, 0xDC6D9AB700000000},// x^{-8}, x^{56}
[12] = {0x0000000100000000, 0x490D678D00000000},// x^{ 0}, x^{64}
[13] = {0x0000010000000000, 0x1B280D7800000000},// x^{ 8}, x^{72}
[14] = {0x0001000000000000, 0x4F57681100000000},// x^{16}, x^{80}
[15] = {0x0100000000000000, 0x5BA1DCCA00000000},// x^{24}, x^{88}
[ 0] = {0x04C11DB700000000, 0xF200AA6600000000},// x^{32}, x^{96}
}};
static const struct _CRC_ctx CRC24_ctx= {
.KBP = {0xF845FE2493242DA4, 0x864CFB0000000000},
.KF4 = {0x7DB43E, 0xB937A7},
.KF3 = {0x01CD94, 0x3B20E3},
.KF2 = {0xCB800E, 0xD15ED7},
.K12 = {0x6243DA, 0xB22B31},// x^{128}, x^{192}
.K34 = {
[ 1] = {0x2471670000000000, 0x7190920000000000},// x^{-96}, x^{-32}
[ 2] = {0xEE50080000000000, 0xC6E2490000000000},// x^{-88}, x^{-24}
[ 3] = {0xCE8F4A0000000000, 0xD19E9A0000000000},// x^{-80}, x^{-16}
[ 4] = {0x1D1CA30000000000, 0xF77C040000000000},// x^{-72}, x^{-8}
[ 5] = {0x6DC6AA0000000000, 0x0000010000000000},// x^{-64}, x^{ 0}
[ 6] = {0x67F3180000000000, 0x0001000000000000},// x^{-56}, x^{ 8}
[ 7] = {0x79152C0000000000, 0x0100000000000000},// x^{-48}, x^{16}
[ 8] = {0xE2DD700000000000, 0x864CFB0000000000},// x^{-40}, x^{24}
[ 9] = {0x7190920000000000, 0x668F480000000000},// x^{-32}, x^{32}
[10] = {0xC6E2490000000000, 0x8309D70000000000},// x^{-24}, x^{40}
[11] = {0xD19E9A0000000000, 0x3609520000000000},// x^{-16}, x^{48}
[12] = {0xF77C040000000000, 0xD9FE8C0000000000},// x^{-8}, x^{56}
[13] = {0x0000010000000000, 0x36EB3D0000000000},// x^{ 0}, x^{64}
[14] = {0x0001000000000000, 0x3B918C0000000000},// x^{ 8}, x^{72}
[15] = {0x0100000000000000, 0xF50BAF0000000000},// x^{16}, x^{80}
[ 0] = {0x864CFB0000000000, 0xFD7E0C0000000000},// x^{24}, x^{88}
}};
static const struct _CRC_ctx CRC16_ctx= {
.KBP = {0x11303471A041B343, 0x1021000000000000},
.K12 = {0xAEFC, 0x650B},// x^{128}, x^{192}
.K34 = {
[ 1] = {0xCBF3000000000000, 0x2AE4000000000000},// x^{-104}, x^{-40}
[ 2] = {0x9B27000000000000, 0x6128000000000000},// x^{-96}, x^{-32}
[ 3] = {0x15D2000000000000, 0x5487000000000000},// x^{-88}, x^{-24}
[ 4] = {0x9094000000000000, 0x9D71000000000000},// x^{-80}, x^{-16}
[ 5] = {0x17B9000000000000, 0x2314000000000000},// x^{-72}, x^{-8}
[ 6] = {0xDBD6000000000000, 0x0001000000000000},// x^{-64}, x^{ 0}
[ 7] = {0xAC16000000000000, 0x0100000000000000},// x^{-56}, x^{ 8}
[ 8] = {0x6266000000000000, 0x1021000000000000},// x^{-48}, x^{16}
[ 9] = {0x2AE4000000000000, 0x3331000000000000},// x^{-40}, x^{24}
[10] = {0x6128000000000000, 0x3730000000000000},// x^{-32}, x^{32}
[11] = {0x5487000000000000, 0x76B4000000000000},// x^{-24}, x^{40}
[12] = {0x9D71000000000000, 0xAA51000000000000},// x^{-16}, x^{48}
[13] = {0x2314000000000000, 0x45A0000000000000},// x^{-8}, x^{56}
[14] = {0x0001000000000000, 0xB861000000000000},// x^{ 0}, x^{64}
[15] = {0x0100000000000000, 0x47D3000000000000},// x^{ 8}, x^{72}
[ 0] = {0x1021000000000000, 0xEB23000000000000},// x^{16}, x^{80}
}};
/* CRC-8
    width=8 poly=0x07 init=0x00 refin=false refout=false xorout=0x00 check=0xf4 name="CRC-8" 
    The System Management Interface Forum, Inc. (3 August 2000), System Management Bus (SMBus) Specification, version 2.0
 */

static const struct _CRC_ctx CRC8_ctx= {
.KBP = {0x07156A166329DD13, 0x0700000000000000},
.K12 = {0x02, 0x26},// x^{128}, x^{192}
.K34 = {
[ 1] = {0x8900000000000000, 0x3400000000000000},// x^{-112}, x^{-48}
[ 2] = {0xB600000000000000, 0x8C00000000000000},// x^{-104}, x^{-40}
[ 3] = {0x0B00000000000000, 0xAD00000000000000},// x^{-96}, x^{-32}
[ 4] = {0x3100000000000000, 0x4A00000000000000},// x^{-88}, x^{-24}
[ 5] = {0x9700000000000000, 0xF100000000000000},// x^{-80}, x^{-16}
[ 6] = {0xEC00000000000000, 0xD900000000000000},// x^{-72}, x^{-8}
[ 7] = {0x8A00000000000000, 0x0100000000000000},// x^{-64}, x^{ 0}
[ 8] = {0xBF00000000000000, 0x0700000000000000},// x^{-56}, x^{ 8}
[ 9] = {0x3400000000000000, 0x1500000000000000},// x^{-48}, x^{16}
[10] = {0x8C00000000000000, 0x6B00000000000000},// x^{-40}, x^{24}
[11] = {0xAD00000000000000, 0x1600000000000000},// x^{-32}, x^{32}
[12] = {0x4A00000000000000, 0x6200000000000000},// x^{-24}, x^{40}
[13] = {0xF100000000000000, 0x2900000000000000},// x^{-16}, x^{48}
[14] = {0xD900000000000000, 0xDF00000000000000},// x^{-8}, x^{56}
[15] = {0x0100000000000000, 0x1300000000000000},// x^{ 0}, x^{64}
[ 0] = {0x0700000000000000, 0x7900000000000000},// x^{ 8}, x^{72}
}};
uint64_t 	CRC64B_update_N(const struct _CRC_ctx * ctx,  uint64_t crc, uint8_t *data, int len){
	poly64x2_t c = {crc};
	int blocks = (len+15) >> 4;
    if (0 && blocks>9) {// fold by 5x128 bits
        poly64x2_t c1 = {0}, c2 = {0}, c3 = {0}, c4 = {0};
__asm volatile("# LLVM-MCA-BEGIN CRC64B_update_N_fold4");
        do {
			c ^= (poly64x2_t)_mm_lddqu_si128((void*)(data   ));
			c1^= (poly64x2_t)_mm_lddqu_si128((void*)(data+16));
			c2^= (poly64x2_t)_mm_lddqu_si128((void*)(data+32));
			c3^= (poly64x2_t)_mm_lddqu_si128((void*)(data+48));
			c4^= (poly64x2_t)_mm_lddqu_si128((void*)(data+64));
            c  = CL_MUL128(c , ctx->KF5, 0x00) ^ CL_MUL128(c , ctx->KF5, 0x11);
            c1 = CL_MUL128(c1, ctx->KF5, 0x00) ^ CL_MUL128(c1, ctx->KF5, 0x11);
            c2 = CL_MUL128(c2, ctx->KF5, 0x00) ^ CL_MUL128(c2, ctx->KF5, 0x11);
            c3 = CL_MUL128(c3, ctx->KF5, 0x00) ^ CL_MUL128(c3, ctx->KF5, 0x11);
            c4 = CL_MUL128(c4, ctx->KF5, 0x00) ^ CL_MUL128(c4, ctx->KF5, 0x11);
            blocks-=5, data+=80;
        } while(blocks>9);
__asm volatile("# LLVM-MCA-END CRC64B_update_N_fold4");
        c ^= (poly64x2_t)_mm_lddqu_si128((void*)(data   ));
        c1^= (poly64x2_t)_mm_lddqu_si128((void*)(data+16));
        c2^= (poly64x2_t)_mm_lddqu_si128((void*)(data+32));
        c3^= (poly64x2_t)_mm_lddqu_si128((void*)(data+48));
        c  = c4
		   ^ CL_MUL128(c , ctx->KF4, 0x00) ^ CL_MUL128(c , ctx->KF4, 0x11)
		   ^ CL_MUL128(c1, ctx->KF3, 0x00) ^ CL_MUL128(c1, ctx->KF3, 0x11)
           ^ CL_MUL128(c2, ctx->KF2, 0x00) ^ CL_MUL128(c2, ctx->KF2, 0x11)
           ^ CL_MUL128(c3, ctx->K12, 0x00) ^ CL_MUL128(c3, ctx->K12, 0x11);
        blocks-=4, data+=64;
    }
    if (0 && blocks>7) {// fold by 4x128 bits
        poly64x2_t c1 = {0}, c2 = {0}, c3 = {0};
__asm volatile("# LLVM-MCA-BEGIN CRC64B_update_N_fold4");
        do {
			c ^= (poly64x2_t)_mm_lddqu_si128((void*)(data   ));
			c1^= (poly64x2_t)_mm_lddqu_si128((void*)(data+16));
			c2^= (poly64x2_t)_mm_lddqu_si128((void*)(data+32));
			c3^= (poly64x2_t)_mm_lddqu_si128((void*)(data+48));
            c  = CL_MUL128(c , ctx->KF4, 0x00) ^ CL_MUL128(c , ctx->KF4, 0x11);
            c1 = CL_MUL128(c1, ctx->KF4, 0x00) ^ CL_MUL128(c1, ctx->KF4, 0x11);
            c2 = CL_MUL128(c2, ctx->KF4, 0x00) ^ CL_MUL128(c2, ctx->KF4, 0x11);
            c3 = CL_MUL128(c3, ctx->KF4, 0x00) ^ CL_MUL128(c3, ctx->KF4, 0x11);
            blocks-=4, data+=64;
        } while(blocks>7);
__asm volatile("# LLVM-MCA-END CRC64B_update_N_fold4");
        c ^= (poly64x2_t)_mm_lddqu_si128((void*)(data   ));
        c1^= (poly64x2_t)_mm_lddqu_si128((void*)(data+16));
        c2^= (poly64x2_t)_mm_lddqu_si128((void*)(data+32));
        c  = c3
		   ^ CL_MUL128(c , ctx->KF3, 0x00) ^ CL_MUL128(c , ctx->KF3, 0x11)
		   ^ CL_MUL128(c1, ctx->KF2, 0x00) ^ CL_MUL128(c1, ctx->KF2, 0x11)
           ^ CL_MUL128(c2, ctx->K12, 0x00) ^ CL_MUL128(c2, ctx->K12, 0x11);
        blocks-=3, data+=48;
    }
    if (0 && blocks>3) {// fold by 2x128 bits
        poly64x2_t c1 = {0};
__asm volatile("# LLVM-MCA-BEGIN CRC64B_update_N_fold2");
        do {
			c ^= (poly64x2_t)_mm_lddqu_si128((void*)(data   ));
			c1^= (poly64x2_t)_mm_lddqu_si128((void*)(data+16));
            //c  = CL_MUL128(c, ctx->K12, 0x00) ^ CL_MUL128(c, ctx->K12, 0x11);
            c  = CL_MUL128(c, ctx->KF2, 0x00) ^ CL_MUL128(c, ctx->KF2, 0x11);
            c1 = CL_MUL128(c1, ctx->KF2, 0x00) ^ CL_MUL128(c1, ctx->KF2, 0x11);
            blocks-=2, data+=32;
        } while(blocks>3);
__asm volatile("# LLVM-MCA-END CRC64B_update_N_fold2");
        c ^= (poly64x2_t)LOAD128U(data);
        c  = c1 ^ CL_MUL128(c, ctx->K12, 0x00) ^ CL_MUL128(c, ctx->K12, 0x11);
        blocks-=1,  data+=16;;
    }
__asm volatile("# LLVM-MCA-BEGIN CRC64B_update_N");
    if (blocks>1) {// fold by 128 bits
        do {
			poly64x2_t v = (poly64x2_t)_mm_lddqu_si128((void*)data); data+=16;
			c^= v; 
            c = CL_MUL128(c, ctx->K12, 0x00) ^ CL_MUL128(c, ctx->K12, 0x11);
            blocks-=1;
        } while(blocks>1);
    }
__asm volatile("# LLVM-MCA-END CRC64B_update_N");
	len &= 15;
	if (len){
		poly64x2_t v={0};
		__builtin_memcpy(&v, data, len);
		c^= v;
	} else
		c^= (poly64x2_t)LOAD128U(data);
	c = CL_MUL128(c, ctx->K34[len], 0x00) // 15+64
	  ^ CL_MUL128(c, ctx->K34[len], 0x11);// 15
	poly64x2_t t;
	t  = CL_MUL128(c, ctx->KBP, 0x00);
	c ^= CL_MUL128(t, ctx->KBP, 0x10);
	return c[1];
}
/*! \brief Вычисление CRC8-CRC64
	\param crc Начальное значние суммы. При загрузке должно выполняться выравнивание по старшему биту (MSB).

*/
uint64_t 	CRC64_update_N(const struct _CRC_ctx * ctx,  uint64_t crc, uint8_t *data, int len){
	poly64x2_t c = {0, crc};
	/*
	if (len>=(16*4+16)){
		c ^= (poly64x2_t)REVERSE((uint8x16_t)LOAD128U(data));data+=16;
		c1^= (poly64x2_t)REVERSE((uint8x16_t)LOAD128U(data));data+=16;
		c2^= (poly64x2_t)REVERSE((uint8x16_t)LOAD128U(data));data+=16;
		c3^= (poly64x2_t)REVERSE((uint8x16_t)LOAD128U(data));data+=16;
		c  = CL_MUL128(c, ctx->KF4, 0x11) ^ CL_MUL128(c, ctx->KF4, 0x00);// 128
		
	}*/
	int blocks = (len+15) >> 4;
    if (0 && blocks>7) {// fold by 4x128 bits
        poly64x2_t c1 = {0}, c2 = {0}, c3 = {0};
__asm volatile("# LLVM-MCA-BEGIN CRC64_update_N_fold4");
        do {
			c ^= (poly64x2_t)REVERSE((uint8x16_t)_mm_lddqu_si128((void*)(data   )));
			c1^= (poly64x2_t)REVERSE((uint8x16_t)_mm_lddqu_si128((void*)(data+16)));
			c2^= (poly64x2_t)REVERSE((uint8x16_t)_mm_lddqu_si128((void*)(data+32)));
			c3^= (poly64x2_t)REVERSE((uint8x16_t)_mm_lddqu_si128((void*)(data+48)));
            c  = CL_MUL128(c , ctx->KF4, 0x00) ^ CL_MUL128(c , ctx->KF4, 0x11);
            c1 = CL_MUL128(c1, ctx->KF4, 0x00) ^ CL_MUL128(c1, ctx->KF4, 0x11);
            c2 = CL_MUL128(c2, ctx->KF4, 0x00) ^ CL_MUL128(c2, ctx->KF4, 0x11);
            c3 = CL_MUL128(c3, ctx->KF4, 0x00) ^ CL_MUL128(c3, ctx->KF4, 0x11);
            blocks-=4, data+=64;
        } while(blocks>7);
__asm volatile("# LLVM-MCA-END CRC64_update_N_fold4");
		c ^= (poly64x2_t)REVERSE((uint8x16_t)_mm_lddqu_si128((void*)(data   )));
		c1^= (poly64x2_t)REVERSE((uint8x16_t)_mm_lddqu_si128((void*)(data+16)));
		c2^= (poly64x2_t)REVERSE((uint8x16_t)_mm_lddqu_si128((void*)(data+32)));
        c  = c3
		   ^ CL_MUL128(c , ctx->KF3, 0x00) ^ CL_MUL128(c , ctx->KF3, 0x11)
           ^ CL_MUL128(c1, ctx->KF2, 0x00) ^ CL_MUL128(c1, ctx->KF2, 0x11)
           ^ CL_MUL128(c2, ctx->K12, 0x00) ^ CL_MUL128(c2, ctx->K12, 0x11);
        blocks-=3, data+=48;
    }
__asm volatile("# LLVM-MCA-BEGIN CRC64_update_N");
    if (blocks>1) {// fold by 128 bits
        do {
			c^= (poly64x2_t)REVERSE((uint8x16_t)_mm_lddqu_si128((void*)(data)));
            c = CL_MUL128(c, ctx->K12, 0x00) ^ CL_MUL128(c, ctx->K12, 0x11);
            blocks-=1, data+=16;
        } while(blocks>1);
    }
__asm volatile("# LLVM-MCA-END");
	poly64x2_t v;
	len &= 15;
	if (len){
		v = (poly64x2_t){0};
		__builtin_memcpy(&v, data, len);
	} else
		v = (poly64x2_t)LOAD128U(data);
	c^= (poly64x2_t)REVERSE((uint8x16_t)v);
	// final reduction 128 bit
	c = CL_MUL128(c, ctx->K34[len], 0x11) // 128-32
	  ^ CL_MUL128(c, ctx->K34[len], 0x00);// 64-32
	// Barrett's reduction
	poly64x2_t t;
	t  = CL_MUL128(c, ctx->KBP, 0x01)^c;//(uint64x2_t){0,c[1]};
	c ^= CL_MUL128(t, ctx->KBP, 0x11);//^(uint64x2_t){0,t[1]}; -- единица в старшем разряде Prime
//	printf("%016llx %016llx\n", c[0],c[1]);
	return c[0];
}


static const uint16_t CRC16_Lookup4[16] = {
	0x0000, 0x1021, 0x2042, 0x3063, 
	0x4084, 0x50A5, 0x60C6, 0x70E7,
	0x8108, 0x9129, 0xA14A, 0xB16B, 
	0xC18C, 0xD1AD, 0xE1CE, 0xF1EF
};
CRC16	CRC16_update(CRC16 crc, unsigned char val){
	crc^= (val << 8);
	crc = (crc << 4) ^ CRC16_Lookup4[(crc >> 12)];
	crc = (crc << 4) ^ CRC16_Lookup4[(crc >> 12)];
	return crc;
}
CRC16	CRC16_update1(CRC16 crc, unsigned char val){
	crc^= (val << 8);
	crc = (crc << 4) ^ (POLY16 * (crc >> 12)) ;
	crc = (crc << 4) ^ (POLY16 * (crc >> 12)) ;
	return crc;
}
CRC16	CRC16B_update_(CRC16 crc, uint8_t val)
{
	poly64x2_t c = {crc}, v;
	const poly64x2_t poly = {0x1081};
	v = (poly64x2_t){val};

	c = (c>>4) ^ CL_MUL128((c ^ (v   )) & 0xF, poly, 0x00);
	c = (c>>4) ^ CL_MUL128((c ^ (v>>4)) & 0xF, poly, 0x00);

	return c[0] & CRC16_MASK;
}
static const uint16_t CRC16M_Lookup4[16] = {
0x0000, 0xCC01, 0xD801, 0x1400,
0xF001, 0x3C00, 0x2800, 0xE401,
0xA001, 0x6C00, 0x7800, 0xB401,
0x5000, 0x9C01, 0x8801, 0x4400,
};
CRC16	CRC16M_update(CRC16 c, uint8_t v)
{
	c^= v;
	c = (c>>4) ^ CRC16M_Lookup4[c & 0xF];
	c = (c>>4) ^ CRC16M_Lookup4[c & 0xF];
	return c & CRC16_MASK;
}
CRC16 CRC16M_update_8(CRC16 crc, uint8_t *data){
	uint16_t val=0;
	__builtin_memcpy(&val, data, 1);
	crc = crc ^ val;
// Barrett's reduction для отраженного порядка бит
	uint32_t t = CL_MUL16L(crc<<8, 0x1BFFF);
	uint32_t v = CL_MUL16H(t, 0x14003)^(crc>>8);
	return v & CRC16_MASK;
}
CRC16 CRC16M_update_16(CRC16 crc, uint8_t *data){
	uint16_t val=0;
	__builtin_memcpy(&val, data, 2);
	crc ^= val;
#if 0
	c<<=16;
// Barrett's reduction для отраженного порядка бит

	uint32_t t = CL_MUL16L(c, 0x1BFFF);
	uint32_t v = CL_MUL16H(t, 0x14003)^c;
	return v & CRC16_MASK;
#else
	poly64x2_t c = {0,(uint64_t)crc<<48};
	//c = SLL128U(c,32+64);
	//c = CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0x82F63B78ULL<<1}, 0x01);//сдвиг влево на 32 6EA2D55C - 64
	c = CL_MUL128(c& 0xFFFF000000000000ULL, (poly64x2_t){0x1ULL}, 0x01);
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x1BFFFULL, 0x14003ULL}, 0x00);
	c ^= CL_MUL128(t, (poly64x2_t){0x1BFFFULL, 0x14003ULL}, 0x10);// E83719AF 1D663B05D
	return c[1];
#endif
}
CRC16 CRC16M_update_32(CRC16 crc, uint8_t *data){
	uint32_t val=0;
	__builtin_memcpy(&val, data, 4);
	val ^= crc;
	poly64x2_t c = {0,(uint64_t)val<<32};
	//c = SLL128U(c,32+64);
	//c = CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0x82F63B78ULL<<1}, 0x01);//сдвиг влево на 32 6EA2D55C - 64
	c = CL_MUL128(c<<16& 0xFFFF000000000000ULL, (poly64x2_t){0x9001}, 0x01)
	  ^ CL_MUL128(c    & 0xFFFF000000000000ULL, (poly64x2_t){0x0001}, 0x01);
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x1BFFFULL, 0x14003ULL}, 0x00);
	c ^= CL_MUL128(t, (poly64x2_t){0x1BFFFULL, 0x14003ULL}, 0x10);// E83719AF 1D663B05D
	return c[1];
}
CRC16 CRC16M_update_64(CRC16 crc, uint8_t *data){
	uint64_t val=0;
	__builtin_memcpy(&val, data, 8);
	val ^= crc;
	poly64x2_t c = {0,(uint64_t)val};
	
	
	
	c = CL_MUL128(c<< 0& 0xFFFF000000000000ULL, (poly64x2_t){0xCCC1}, 0x00)
	  ^ CL_MUL128(c<<48& 0xFFFF000000000000ULL, (poly64x2_t){0xD101}, 0x01)
	  ^ CL_MUL128(c<<32& 0xFFFF000000000000ULL, (poly64x2_t){0xFC01}, 0x01)
	  ^ CL_MUL128(c<<16& 0xFFFF000000000000ULL, (poly64x2_t){0x9001}, 0x01)
	  ^ CL_MUL128(c    & 0xFFFF000000000000ULL, (poly64x2_t){0x0001}, 0x01);
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x1BFFFULL, 0x14003ULL}, 0x00);
	c ^= CL_MUL128(t, (poly64x2_t){0x1BFFFULL, 0x14003ULL}, 0x10);
	return c[1];
}
CRC16 CRC16M_update_N(CRC16 crc, uint8_t *data, int len){
	poly64x2_t c = {crc};
	int blocks = (len+15 >> 4);
	while (--blocks>0){
		c^= (poly64x2_t)LOAD128U(data); data+=16;
		c = CL_MUL128(c, (poly64x2_t){0x90C1}, 0x00) // 191-48=143 0xCCD0<<48
		  ^ CL_MUL128(c, (poly64x2_t){0xCCC1}, 0x01);// 127-48=79  0xC100<<48
	}
	if (len & 15) {
		poly64x2_t v={0};
		__builtin_memcpy(&v, data, len & 15);
		c^= v;
	} else
		c^= (poly64x2_t)LOAD128U(data); //data+=16;
#if 0
	c = CL_MUL128(c<<48& 0xFFFF000000000000ULL, (poly64x2_t){0xC100}, 0x00)//127
	  ^ CL_MUL128(c<<32& 0xFFFF000000000000ULL, (poly64x2_t){0xC3FD}, 0x00)
	  ^ CL_MUL128(c<<16& 0xFFFF000000000000ULL, (poly64x2_t){0xC551}, 0x00)
	  ^ CL_MUL128(c<< 0& 0xFFFF000000000000ULL, (poly64x2_t){0xCCC1}, 0x00)
	  ^ CL_MUL128(c<<48& 0xFFFF000000000000ULL, (poly64x2_t){0xD101}, 0x01)
	  ^ CL_MUL128(c<<32& 0xFFFF000000000000ULL, (poly64x2_t){0xFC01}, 0x01)
	  ^ CL_MUL128(c<<16& 0xFFFF000000000000ULL, (poly64x2_t){0x9001}, 0x01)
	  ^ CL_MUL128(c<< 0& 0xFFFF000000000000ULL, (poly64x2_t){0x0001}, 0x01);
#else
	c = CL_MUL128(c, (poly64x2_t){0xCCC1}, 0x00) // 15+64
	  ^ CL_MUL128(c, (poly64x2_t){0x0001}, 0x01);// 15
#endif
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0xF0FFEBFFCFFFBFFF, 0x14003ULL}, 0x00);
	c ^= CL_MUL128(t, (poly64x2_t){0xF0FFEBFFCFFFBFFF, 0x14003ULL}, 0x10);
	return c[1];
}


#define BARRETT_U 0x11131
#define POLY16_ 0x11021
uint32_t	CRC16_update_(uint32_t crc, uint8_t val)
{
	poly64x2_t c = {crc}, v;
	v = (poly64x2_t){val};
	c = (c<<8) ^ (v<<16);//CL_MUL128(v, (v2du){POLY16}, 0x00);
// Barrett's reduction 32->16
	poly64x2_t t = CL_MUL128(c>>16 , (poly64x2_t){BARRETT_U}, 0x00);
	c^= CL_MUL128(t>>16 , (poly64x2_t){POLY16_}, 0x00);
	return c[0];// & CRC16_MASK;
}
uint32_t	CRC16_update_8(uint32_t crc, uint8_t *data)
{
	uint32_t val = data[0];
// редуцирование 24 бит в 16
#if 0
	crc = crc ^ (val<<8);// один сдвиг в уме
	uint32_t x = (crc>>8); // при 8 битах, часть действтй не нужны
	x = x ^ x>>4;// ^ x>>8 ^ x>>11 ^ x>>12 ^ x>>16;
	x = x<<16 ^ x <<12 ^ x <<5 ^ x;
	return x ^ (crc<<8);// & CRC16_MASK;
#elif 1
	uint64_t c = crc ^ (val<<8);// один сдвиг в уме
//	c <<= 8;//c = CL_MUL16(c, 0x100); Хотим сделать сдвиг вправо
//	c = CL_MUL16(c, 0x1021);
	c = CL_MUL16(c, 0x1021);
	uint64_t t =  CL_MUL16(c>>16, 0x1130) ^ c;//(c>>16)<<16;
	c^= CL_MUL16(t>>16, 0x1021);
// тестируем сдвиг вправо
//	c = CL_MUL16(c, 0x9D71);// сдвиг вправо на 16
	c = CL_MUL16(c, 0x2314);// сдвиг вправо на 8
// еще хотим обратить операцию.
// редуцирование
	t = CL_MUL16(c>>16, 0x1130) ^ c;//(c>>16)<<16;
	c^= CL_MUL16(t>>16, 0x1021);
	return c & CRC16_MASK;
#elif 1
	crc = crc ^ (val<<8);// один сдвиг в уме
	uint32_t t =  CL_MUL32L(crc>>8, BARRETT_U );
	uint32_t v =  CL_MUL32L(t>>16, POLY16_) ^ (crc<<8);
	return v;// & CRC16_MASK;
#else
	crc = crc ^ (val<<8);// один сдвиг в уме
	uint32_t x = crc>>8; // при 8 битах, часть действтй не нужны
	x = x ^ x>>4;// ^ x>>8 ^ x>>11 ^ x>>12 ^ x>>16;
	x = x<<16 ^ x <<12 ^ x <<5 ^ x;
	uint32_t v = x ^ (crc<<8);
	return v;// & CRC16_MASK;
#endif
}

uint32_t	CRC16_update_16(uint32_t crc, uint8_t *data)
{
	uint16_t val;
	val = __builtin_bswap16(*(uint16_t*)data);
#if 0
	crc = crc ^ val;
	uint32_t x = crc;
	x = x ^ x>>4 ^ x>>8 ^ x>>11 ^ x>>12;// ^ x>>16;// 11131
	x = x<<16 ^ x <<12 ^ x <<5 ^ x; // 11021
	uint32_t v = x ^ (crc<<16);
	return v;// & CRC16_MASK;
#elif 1
	uint64_t c = crc ^ val;// один сдвиг в уме
	//c <<= 16;
	c = CL_MUL16(c>> 0, 0x1021);
	uint64_t t =  CL_MUL16(c>>16, 0x1130) ^ c;//(c>>16)<<16;
	c ^= CL_MUL16(t>>16, 0x1021);
	return c & CRC16_MASK;
#else
	crc = crc ^ val;
	uint32_t t =  CL_MUL16H(crc, BARRETT_U&0xFFFF) ^ crc;
	uint32_t v =  CL_MUL16L(t, POLY16);
//	uint32_t v =  CL_MUL32L(t, POLY16_) ^ (crc<<16);
	return v;// & CRC16_MASK;
#endif
}

uint32_t	CRC16_update_N(uint32_t crc, uint8_t *data, int n)
{
	if (n==0) return crc;
	if ((uintptr_t)data & 1) {
		uint32_t val = *data++; n-=1;
		crc = crc ^ (val<<8);// один сдвиг в уме
		uint32_t x = (crc>>8); // при 8 битах, часть действтй не нужны
		x = x ^ x>>4;// ^ x>>8 ^ x>>11 ^ x>>12 ^ x>>16;
		x = x<<16 ^ x <<12 ^ x <<5 ^ x;
		crc = x ^ (crc<<8);
	}
	int i;
	for (i=0; i<(n>>1);i++) {
		uint32_t val = __builtin_bswap16(*(uint16_t*)data); data+=2;
		crc = crc ^ val;
		uint32_t x = crc;
		x = x ^ x>>4 ^ x>>8 ^ x>>11 ^ x>>12;// ^ x>>16;// 11131
		x = x<<16 ^ x <<12 ^ x <<5 ^ x; // 11021
		crc = x ^ (crc<<16);
	}
	if (n & 1) {
		uint32_t val = *data++;
		crc = crc ^ (val<<8);// один сдвиг в уме
		uint32_t x = (crc>>8); // при 8 битах, часть действтй не нужны
		x = x ^ x>>4;// ^ x>>8 ^ x>>11 ^ x>>12 ^ x>>16;
		x = x<<16 ^ x <<12 ^ x <<5 ^ x;
		crc = x ^ (crc<<8);
	}
	return crc;
}

uint32_t	CRC16_update_24(uint32_t crc, uint8_t *data)
{
	uint32_t val;
	val = __builtin_bswap32(*(uint32_t*)data);
	uint64_t c = (crc<<8) ^ val>>8;// один сдвиг в уме

	c = CL_MUL16(c>>16, 0x3730)
	  ^ CL_MUL16(c>> 0, 0x1021);
	uint64_t t =  CL_MUL16(c>>16, 0x1130) ^ c;//(c>>16)<<16;
	c ^= CL_MUL16(t>>16, 0x1021);
	return c & CRC16_MASK;
}

uint32_t CRC16_update_32(uint32_t crc, uint8_t *data){
	uint32_t val;
	val = __builtin_bswap32(*(uint32_t*)data);
	uint64_t c = (crc<<16) ^ val;// один сдвиг в уме

	c = CL_MUL16(c>>16, 0x3730)
	  ^ CL_MUL16(c>> 0, 0x1021);
	uint64_t t =  CL_MUL16(c>>16, 0x1130) ^ c;//(c>>16)<<16;
	c ^= CL_MUL16(t>>16, 0x1021);
	return c & CRC16_MASK;
}


#define POLY32   0x04C11DB7
#define CRC32_CHECK 0xFC891918
#define POLY32_ 0x104C11DB7
#define BARRETT_U32 0x104D101DF

static const CRC32 CRC32_Lookup4[16] = {
0x00000000, 0x04C11DB7, 0x09823B6E, 0x0D4326D9,
0x130476DC, 0x17C56B6B, 0x1A864DB2, 0x1E475005,
0x2608EDB8, 0x22C9F00F, 0x2F8AD6D6, 0x2B4BCB61,
0x350C9B64, 0x31CD86D3, 0x3C8EA00A, 0x384FBDBD
};
/* Один байт за два шага по таблице 4 бит */
CRC32 CRC32_update   (CRC32 crc, uint8_t val){
	crc^= (val <<24);
	crc = (crc << 4) ^ CRC32_Lookup4[crc >> 28];
	crc = (crc << 4) ^ CRC32_Lookup4[crc >> 28];
	return crc;
}

#define CRC24_CHECK 0x21cf02
#define CRC24_INIT  0xB704CE
#define CRC24_POLY  0x864CFB
static const CRC32 CRC24_Lookup4[16] = {
0x000000, 0x864CFB, 0x8AD50D, 0x0C99F6,
0x93E6E1, 0x15AA1A, 0x1933EC, 0x9F7F17,
0xA18139, 0x27CDC2, 0x2B5434, 0xAD18CF,
0x3267D8, 0xB42B23, 0xB8B2D5, 0x3EFE2E,
};

/* Один байт за два шага по таблице 4 бит */
CRC32 CRC24_update   (CRC32 crc, uint8_t val){
	crc^= (val <<16);
	crc = (crc << 4) ^ CRC24_Lookup4[(crc >> 20)&0xF];
	crc = (crc << 4) ^ CRC24_Lookup4[(crc >> 20)&0xF];
	return crc & 0xFFFFFF;
}

#define CRC32B_CHECK 0xcbf43926
static const CRC32 CRC32B_Lookup4[16]={
0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC,
0x76DC4190, 0x6B6B51F4, 0x4DB26158, 0x5005713C,
0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C,
0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C
};
CRC32 CRC32B_update(CRC32 crc, unsigned char val){
	crc^= val;
	crc = (crc>>4) ^ CRC32B_Lookup4[crc & 0xF];
	crc = (crc>>4) ^ CRC32B_Lookup4[crc & 0xF];
	return crc;
}
#define POLY32K 0x741B8CD7
static const CRC32 CRC32K_Lookup4[16] = {
0x00000000, 0x83CF0F3C, 0xD1FDAE25, 0x5232A119,
0x7598EC17, 0xF657E32B, 0xA4654232, 0x27AA4D0E,
0xEB31D82E, 0x68FED712, 0x3ACC760B, 0xB9037937,
0x9EA93439, 0x1D663B05, 0x4F549A1C, 0xCC9B9520,
};
CRC32 CRC32K_update   (CRC32 crc, uint8_t val){
	crc^= val;
	crc = (crc >> 4) ^ CRC32K_Lookup4[crc & 0xF ];
	crc = (crc >> 4) ^ CRC32K_Lookup4[crc & 0xF ];
	return crc;
}
#define POLY32C 0x1EDC6F41
#define CRC32C_CHECK 0xE3069283
static const CRC32 CRC32C_Lookup4[16] = {
0x00000000L, 0x105EC76FL, 0x20BD8EDEL, 0x30E349B1L,
0x417B1DBCL, 0x5125DAD3L, 0x61C69362L, 0x7198540DL,
0x82F63B78L, 0x92A8FC17L, 0xA24BB5A6L, 0xB21572C9L,
0xC38D26C4L, 0xD3D3E1ABL, 0xE330A81AL, 0xF36E6F75L,
};

/*!
    CRC-32C (Castagnoli) 	iSCSI, SCTP, G.hn payload, SSE4.2, Btrfs, ext4 	0x1EDC6F41 	инверсный полином 0x82F63B78
    \see [RFC 4960] Appendix B. CRC32c Checksum Calculation <http://tools.ietf.org/html/rfc4960#appendix-B>
*/
CRC32 CRC32C_update(CRC32 crc, uint8_t val){
	crc^= val;
	crc = (crc>>4) ^ CRC32C_Lookup4[crc & 0xF];
	crc = (crc>>4) ^ CRC32C_Lookup4[crc & 0xF];
	return crc;
}
// CRC-64/XZ POLY=0xC96C5795D7870F42
#define CRC64XZ_CHECK 0x995dc9bbdf1939faULL
static const CRC64 CRC64XZ_Lookup4[16] = {
0x0000000000000000, 0x7D9BA13851336649, 0xFB374270A266CC92, 0x86ACE348F355AADB,
0x64B62BCAEBC387A1, 0x192D8AF2BAF0E1E8, 0x9F8169BA49A54B33, 0xE21AC88218962D7A,
0xC96C5795D7870F42, 0xB4F7F6AD86B4690B, 0x325B15E575E1C3D0, 0x4FC0B4DD24D2A599,
0xADDA7C5F3C4488E3, 0xD041DD676D77EEAA, 0x56ED3E2F9E224471, 0x2B769F17CF112238,
};
CRC64 CRC64XZ_update   (CRC64 crc, uint8_t val){
	crc^= val;
	crc = (crc >> 4) ^ CRC64XZ_Lookup4[crc & 0xF ];
	crc = (crc >> 4) ^ CRC64XZ_Lookup4[crc & 0xF ];
	return crc;
}
CRC64 CRC64XZ_update_64(CRC64 crc, uint8_t* data){
	uint64_t val=0;
	__builtin_memcpy(&val, data, 8);
	crc = crc ^ val;
// Barrett's reduction
	poly64x2_t c = {crc};
	//c = SLL128U(c,64);
	//c = CL_MUL128(c, (poly64x2_t){0x9C3E466C172963D5ULL, 0x92D8AF2BAF0E1E85ULL}, 0x10);// сдвиг x^{64} mod P
	
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x9C3E466C172963D5ULL, 0x92D8AF2BAF0E1E85ULL}, 0x00);
	c ^= SLL128U(t,64) ^ CL_MUL128(t, (poly64x2_t){0x9C3E466C172963D5ULL, 0x92D8AF2BAF0E1E85ULL}, 0x10);// E83719AF 1D663B05D
	return c[1];
}
CRC64 CRC64XZ_update_128(CRC64 crc, uint8_t* data){
	poly64x2_t c = {crc,0};
	c ^= (uint64x2_t)LOAD128U(data);
	//c = SLL128U(c,64);
	c = CL_MUL128(c, (poly64x2_t){0xDABE95AFC7875F40ULL, 0x0000000000000001ULL}, 0x00) // сдвиг x^{128} mod P
	  ^ CL_MUL128(c, (poly64x2_t){0xDABE95AFC7875F40ULL, 0x0000000000000001ULL}, 0x11);// сдвиг x^{64} mod P

// Barrett's reduction
	
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x9C3E466C172963D5ULL, 0x92D8AF2BAF0E1E85ULL}, 0x00);
	c ^= SLL128U(t,64) ^ CL_MUL128(t, (poly64x2_t){0x9C3E466C172963D5ULL, 0x92D8AF2BAF0E1E85ULL}, 0x10);// E83719AF 1D663B05D
	return c[1];
}
/* 
static const struct _CRC_ctx CRC64XZ_ctx ={
.KBP = {0x9C3E466C172963D5ULL, 0x92D8AF2BAF0E1E85ULL},
.K12 = {0xE05DD497CA393AE4ULL, 0xDABE95AFC7875F40ULL} // 128 192
.K34 = {
[ 1] = {0x0100000000000000ULL, 0x78E4CCEE804FE350ULL},// x^{7} , x^{-57}
[ 2] = {0x0001000000000000ULL, 0x19556E3E5470AE0BULL},// x^{15}, x^{-49}
[ 3] = {0x0000010000000000ULL, 0xB012A88E6AAD33FCULL},// x^{23}, x^{-41}
[ 4] = {0x0000000100000000ULL, 0xA7B7C93241EA6D5EULL},// x^{31}, x^{-33}
[ 5] = {0x0000000001000000ULL, 0x617F4FE12060498BULL},// x^{39}, x^{-25}
[ 6] = {0x0000000000010000ULL, 0x7906D53A625E2C59ULL},// x^{47}, x^{-17}
[ 7] = {0x0000000000000100ULL, 0x5DDB47907C2B5CCDULL},// x^{55}, x^{-9}
[ 8] = {0x0000000000000001ULL, 0x92D8AF2BAF0E1E85ULL},// x^{63}, x^{-1}
[ 9] = {0xB32E4CBE03A75F6FULL, 0x0100000000000000ULL},// x^{71}, x^{7}
[10] = {0x54E979925CD0F10DULL, 0x0001000000000000ULL},// x^{79}, x^{15}
[11] = {0x3F0BE14A916A6DCBULL, 0x0000010000000000ULL},// x^{87}, x^{23}
[12] = {0x1DEE8A5E222CA1DCULL, 0x0000000100000000ULL},// x^{95}, x^{31}
[13] = {0x5C2D776033C4205EULL, 0x0000000001000000ULL},// x^{103}, x^{39}
[14] = {0x6184D55F721267C6ULL, 0x0000000000010000ULL},// x^{111}, x^{47}
[15] = {0x22EF0D5934F964ECULL, 0x0000000000000100ULL},// x^{119}, x^{55}
[ 0] = {0xDABE95AFC7875F40ULL, 0x0000000000000001ULL},// x^{127}, x^{63}
},
};*/
/*! 
Это такой же алгоритм как и CRC64B_update_N, но не помещается в 64 бита. Последняя константа 65 бит.
 */

CRC64 CRC64XZ_update_N(CRC64 crc, uint8_t* data, int len){
	poly64x2_t c = {crc,0};
	
	int blocks = (len+15 >> 4);
	while (--blocks){
		c ^= (poly64x2_t)LOAD128U(data); data+=16;
		c = CL_MUL128(c, CRC64XZ_ctx.K12, 0x11) // 192
		  ^ CL_MUL128(c, CRC64XZ_ctx.K12, 0x00);// 128
	}
	len &= 15;
	if (len){
		poly64x2_t v = {0};
		__builtin_memcpy(&v, data, len);
		c^= v;
	} else 
		c^= (poly64x2_t)LOAD128U(data); 
	c = CL_MUL128(c, CRC64XZ_ctx.K34[len], 0x00) // сдвиг x^{127} mod P
	  ^ CL_MUL128(c, CRC64XZ_ctx.K34[len], 0x11);// сдвиг x^{63} mod P

// Barrett's reduction
	poly64x2_t t = CL_MUL128(c, CRC64XZ_ctx.KBP, 0x00);
	c ^= SLL128U(t,64) ^ CL_MUL128(t, CRC64XZ_ctx.KBP, 0x10);// коэффициент содержит единицу в старшем разряде
	return c[1];
}

// CRC-64/WE 	POLY=0x42F0E1EBA9EA3693 0xFFFFFFFFFFFFFFFF false false 0xFFFFFFFFFFFFFFFF 0x62EC59E3F1A4F00A
// CRC-64/ECMA-182
//              poly=0x42f0e1eba9ea3693 0x0000000000000000 false false 0x0000000000000000 0x6c40df5f0b497347 residue=0x0000000000000000 name="CRC-64/ECMA-182"
// CRC-64/GO-ISO
//              poly=0x000000000000001b 0xFFFFFFFFFFFFFFFF true  true  0xffffffffffffffff 0xb90956c775a41001 residue=0x5300000000000000 name="CRC-64/GO-ISO"
#define GF64_POLY  0x1BULL
#define CRC64GO_CHECK 0xB90956C775A41001ULL
static const CRC64 CRC64GO_Lookup4[16] = {
0x0000000000000000, 0x1B00000000000000, 0x3600000000000000, 0x2D00000000000000,
0x6C00000000000000, 0x7700000000000000, 0x5A00000000000000, 0x4100000000000000,
0xD800000000000000, 0xC300000000000000, 0xEE00000000000000, 0xF500000000000000,
0xB400000000000000, 0xAF00000000000000, 0x8200000000000000, 0x9900000000000000,
};
CRC64 CRC64GO_update   (CRC64 crc, uint8_t val){
	crc^= val;
	crc = (crc >> 4) ^ CRC64GO_Lookup4[crc & 0xF];
	crc = (crc >> 4) ^ CRC64GO_Lookup4[crc & 0xF];
	return crc;
}
//#include "gf2m_64.h"
/*! таблица для редуцирования после умножения старшую часть по таблице добавить к остатку */
const uint8_t gf2m_64[] = {
0x00, 0x1B, 0x36, 0x2D,
0x6C, 0x77, 0x5A, 0x41,
0xD8, 0xC3, 0xEE, 0xF5,
0xB4, 0xAF, 0x82, 0x99,
};
/*! Операция сдвига в конечном поле с редуцированием */
uint64_t GF64_shlm   (uint64_t crc){
	uint8_t cy = crc>>60;
	crc = (crc<<4) ^ gf2m_64[cy];
	return crc;
}
/*! Умножение 64х8 по одному биту */
uint64_t GF64_mul_ui (uint64_t a, uint8_t b) {
	int i;
	uint64_t r=0;
	for(i=0; i<8; i++){
		if (r&(1ULL<<63)) {
			r = (r<<1) ^ 0x1BULL;
		} else
			r = (r<<1);
		if (b&0x80){
			r ^=a;
		}
		b<<=1;
	}
	return r;
}
/*! \brief Умножение 64х8 по четыре бита без редуцирования 
	\param[IN] a - таблица умножения, 16 элементов
 */
static inline uint64_t GF64_mul2_ui (const uint64_t* a, uint8_t b, uint8_t *cy) {
	uint64_t r = a[b>>4];
	*cy ^= r>>60;
	r = (r<<4)^a[b&0xF];
	return r;
}
/*! \brief Умножение 64х64 в поле GF(2^64) с полиномом по четыре бита без редуцирования */
uint64_t GF64_mulm   (uint64_t a, uint64_t b)
{
	const uint64_t P = 0x1BULL;
	int i,n;
	uint64_t aa[16];// 128 байт
	// расчитать таблицу умножения для 16 значений
	for (n=0; n<16;n++) aa[n] = 0;
	for (i=0; i<4; i++){
		for (n=0; n<16; n++)
			if (n & (1<<i)) aa[n] ^= a;
		if (a&(1ULL<<63))
			a = (a<<1) ^ P;
		else
			a = (a<<1);
	}
	uint64_t r = 0;
	for (i=15; i>=0; i--){
		uint8_t cy = r>>60;
		r = (r<<4);
		r^= aa[(b>>(4*i))&0xF];
		r^= gf2m_64[cy];// редуцирование
	}
	return r;
}

#define CRC64WE_POLY  0x42F0E1EBA9EA3693ULL
#define CRC64WE_CHECK 0x62EC59E3F1A4F00AULL
static const CRC64 CRC64WE_Lookup4[16] = {
0x0000000000000000, 0x42F0E1EBA9EA3693, 0x85E1C3D753D46D26, 0xC711223CFA3E5BB5,
0x493366450E42ECDF, 0x0BC387AEA7A8DA4C, 0xCCD2A5925D9681F9, 0x8E224479F47CB76A,
0x9266CC8A1C85D9BE, 0xD0962D61B56FEF2D, 0x17870F5D4F51B498, 0x5577EEB6E6BB820B,
0xDB55AACF12C73561, 0x99A54B24BB2D03F2, 0x5EB4691841135847, 0x1C4488F3E8F96ED4,
};
CRC64 CRC64WE_update   (CRC64 crc, uint8_t val){
	crc^= ((uint64_t)val <<56);
	crc = (crc << 4) ^ CRC64WE_Lookup4[crc>>60];
	crc = (crc << 4) ^ CRC64WE_Lookup4[crc>>60];
	return crc;
}
CRC64 CRC64WE_update_8 (CRC64 crc, uint8_t* data){
	uint64_t val=0;
	__builtin_memcpy(&val, data, 1);
	val = __builtin_bswap64(val);
	crc = crc ^ val;
// Barrett's reduction
	poly64x2_t c = {crc};
	c = SLL128U(c,8);
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x578D29D06CC4F872ULL, 0x42F0E1EBA9EA3693ULL}, 0x01) ^c;//(uint64x2_t){0,c[0]};
	c ^= CL_MUL128(t, (poly64x2_t){0x578D29D06CC4F872ULL, 0x42F0E1EBA9EA3693ULL}, 0x11);
	return c[0];
}
CRC64 CRC64WE_update_16(CRC64 crc, uint8_t* data){
	uint64_t val=0;
	__builtin_memcpy(&val, data, 2);
	val = __builtin_bswap64(val);
	crc = crc ^ val;
// Barrett's reduction
	poly64x2_t c = {crc};
	c = SLL128U(c,16);
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x578D29D06CC4F872ULL, 0x42F0E1EBA9EA3693ULL}, 0x01) ^c;//(uint64x2_t){0,c[0]};
	c ^= CL_MUL128(t, (poly64x2_t){0x578D29D06CC4F872ULL, 0x42F0E1EBA9EA3693ULL}, 0x11);
	return c[0];
}
CRC64 CRC64WE_update_48(CRC64 crc, uint8_t* data){
	uint64_t val=0;
	__builtin_memcpy(&val, data, 6);
	val = __builtin_bswap64(val);
	crc = crc ^ val;
// Barrett's reduction
	poly64x2_t c = {crc};
	//c = SLL128U(c,48);
	c = CL_MUL128(c, (poly64x2_t){1ULL<<48}, 0x00);
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x578D29D06CC4F872ULL, 0x42F0E1EBA9EA3693ULL}, 0x01) ^c;//(uint64x2_t){0,c[0]};
	c ^= CL_MUL128(t, (poly64x2_t){0x578D29D06CC4F872ULL, 0x42F0E1EBA9EA3693ULL}, 0x11);
	return c[0];
}
CRC64 CRC64WE_update_64(CRC64 crc, uint8_t* data){
	uint64_t val=0;
	__builtin_memcpy(&val, data, 8);
	val = __builtin_bswap64(val);
	crc = crc ^ val;
// Barrett's reduction
	poly64x2_t c = {crc};
	//c = SLL128U(c,64);
	c = CL_MUL128(c, (poly64x2_t){0x578D29D06CC4F872ULL, 0x42F0E1EBA9EA3693ULL}, 0x10);// сдвиг x^{64} mod P
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x578D29D06CC4F872ULL, 0x42F0E1EBA9EA3693ULL}, 0x01) ^c;//(uint64x2_t){0,c[0]};
	c ^= CL_MUL128(t, (poly64x2_t){0x578D29D06CC4F872ULL, 0x42F0E1EBA9EA3693ULL}, 0x11);
	return c[0];
}
CRC64 CRC64WE_update_128(CRC64 crc, uint8_t* data){
	poly64x2_t c = (poly64x2_t) REVERSE((uint8x16_t)LOAD128U(data));
	c[1]^=crc;
// Barrett's reduction
	
	//c = SLL128U(c,64);
	c = CL_MUL128(c, (poly64x2_t){0x05F5C3C7EB52FAB6ULL}, 0x01) // 128
	  ^ CL_MUL128(c, (poly64x2_t){0x578D29D06CC4F872ULL, 0x42F0E1EBA9EA3693ULL}, 0x10);// 64
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x578D29D06CC4F872ULL, 0x42F0E1EBA9EA3693ULL}, 0x01) ^c;//(uint64x2_t){0,c[0]};
	c ^= CL_MUL128(t, (poly64x2_t){0x578D29D06CC4F872ULL, 0x42F0E1EBA9EA3693ULL}, 0x11);
	return c[0];
}

static const struct _CRC_ctx CRC64WE_ctx ={
.KBP = {0x578D29D06CC4F872ULL, 0x42F0E1EBA9EA3693ULL},
.K12 = {0x05F5C3C7EB52FAB6ULL, 0x4EB938A7D257740EULL}, // 128 192
.K34 = {
[ 1] = {0x158FE402EE664E3CULL, 0x0000000000000100ULL},// x^{-56}, x^{8}
[ 2] = {0xE21AFDBF510763A3ULL, 0x0000000000010000ULL},// x^{-48}, x^{16}
[ 3] = {0x7F996AACE22A901AULL, 0x0000000001000000ULL},// x^{-40}, x^{24}
[ 4] = {0xF56CAF049927DBCAULL, 0x0000000100000000ULL},// x^{-32}, x^{32}
[ 5] = {0xE1D4EDE2A60FCB9FULL, 0x0000010000000000ULL},// x^{-24}, x^{40}
[ 6] = {0x7698156710BCF7AFULL, 0x0001000000000000ULL},// x^{-16}, x^{48}
[ 7] = {0x24854997BA2F81E7ULL, 0x0100000000000000ULL},// x^{-8}, x^{56}
[ 8] = {0x0000000000000001ULL, 0x42F0E1EBA9EA3693ULL},// x^{0},  x^{64}
[ 9] = {0x0000000000000100ULL, 0xAF052A6B538EDF09ULL},// x^{8},  x^{72}
[10] = {0x0000000000010000ULL, 0x23EEF79F3AD718C7ULL},// x^{16}, x^{80}
[11] = {0x0000000001000000ULL, 0xE59C4CF90CE5976BULL},// x^{24}, x^{88}
[12] = {0x0000000100000000ULL, 0x770A6888F4A2EF70ULL},// x^{32}, x^{96}
[13] = {0x0000010000000000ULL, 0xF40847980DDD6874ULL},// x^{40}, x^{104}
[14] = {0x0001000000000000ULL, 0xC7CC909DF556430CULL},// x^{48}, x^{112}
[15] = {0x0100000000000000ULL, 0x6E4D3E593561EE88ULL},// x^{56}, x^{120}
[ 0] = {0x42F0E1EBA9EA3693ULL, 0x05F5C3C7EB52FAB6ULL},// x^{64}, x^{128}
},
};
CRC64 CRC64WE_update_N(CRC64 crc, uint8_t* data, int len){
	poly64x2_t c = {0, crc};
	int blocks = (len+15 >> 4);
	while (--blocks>0){
		c^= (poly64x2_t) REVERSE((uint8x16_t)LOAD128U(data)); data+=16;
		c = CL_MUL128(c, CRC64WE_ctx.K12, 0x11) // 192
		  ^ CL_MUL128(c, CRC64WE_ctx.K12, 0x00);// 128
	}
	poly64x2_t v;
	len &= 15;
	if (len) {
		v = (poly64x2_t){0};
		__builtin_memcpy(&v, data, len);
	} else
		v = (poly64x2_t)LOAD128U(data);
	c^= (poly64x2_t) REVERSE((uint8x16_t)v);
	//c = SLL128U(c,64);
	c = CL_MUL128(c, CRC64WE_ctx.K34[len], 0x11) // 128
	  ^ CL_MUL128(c, CRC64WE_ctx.K34[len], 0x00);// 64
// Barrett's reduction
	poly64x2_t 
	t = CL_MUL128(c, CRC64WE_ctx.KBP, 0x01) ^c;// (uint64x2_t){0,c[1]};
	c^= CL_MUL128(t, CRC64WE_ctx.KBP, 0x11) ;// ^ (uint64x2_t){0,t[1]};// обнуляет старшую часть
	return c[0];
}


CRC32 CRC32C_update_8 (CRC32 crc, uint8_t *data){
	uint32_t val;
	val = *(uint8_t*)data;
	crc = crc ^ val;
// Barrett's reduction
#if 0
	uint32_t t = CL_MUL32L(crc<<24, 0xDEA713F1);// DEA713F0 0xBF22537F
	uint32_t v = CL_MUL32H(t   , 0x05EC76F1)^t^(crc>>8);// 0x1edc6f41 0xE83719AE 0x3DB8DE82 105EC76F0
	return v;// & CRC32_MASK;
#else
	poly64x2_t c = {crc};
	c = SLL128U(c,32+24);
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x1DEA713F1ULL, 0x105EC76F1ULL}, 0x00);
	c ^= CL_MUL128(t, (poly64x2_t){0x1DEA713F1ULL, 0x105EC76F1ULL}, 0x10);// E83719AF 1D663B05D
	return c[1];
#endif
}
CRC32 CRC32C_update_16(CRC32 crc, uint8_t *data){
	uint32_t val;
	val = *(uint16_t*)data;
	crc = crc ^ val;
// Barrett's reduction
#if 0
	uint32_t t = CL_MUL32L(crc<<16, 0xDEA713F1);// DEA713F0 0xBF22537F
	uint32_t v = CL_MUL32H(t   , 0x05EC76F1)^t^(crc>>16);// 0x1edc6f41 0xE83719AE 0x3DB8DE82 105EC76F0
	return v;// & CRC32_MASK;
#else
	poly64x2_t c = {crc};
	c = SLL128U(c,32+16);
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x1DEA713F1ULL, 0x105EC76F1ULL}, 0x00);
	c ^= CL_MUL128(t, (poly64x2_t){0x1DEA713F1ULL, 0x105EC76F1ULL}, 0x10);// E83719AF 1D663B05D
	return c[1];
#endif
}
CRC32 CRC32C_update_24(CRC32 crc, uint8_t *data){
	uint32_t val=0;
	__builtin_memcpy(&val, data,3);
	crc = crc ^ val;
// Barrett's reduction
#if 0
	uint32_t t = CL_MUL32L(crc<<8, 0xDEA713F1);
	uint32_t v = CL_MUL32H(t   , 0x05EC76F1)^t^(crc>>24);
	return v;// & CRC32_MASK;
#else
	poly64x2_t c = {crc};
	c = SLL128U(c,32+8);
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x1DEA713F1ULL, 0x105EC76F1ULL}, 0x00);
	c ^= CL_MUL128(t, (poly64x2_t){0x1DEA713F1ULL, 0x105EC76F1ULL}, 0x10);// E83719AF 1D663B05D
	return c[1];
#endif
}
CRC32 CRC32C_update_32(CRC32 crc, uint8_t *data){
	uint32_t val;
	val = *(uint32_t*)data;
	crc = crc ^ val;
// Barrett's reduction
#if 0
	uint32_t t = CL_MUL32L(crc, 0x1DEA713F1);
	uint32_t v = CL_MUL32H(t  , 0x105EC76F1);
	return v;// & CRC32_MASK;
#else
	poly64x2_t c = {0,(uint64_t)crc<<32};
	//c = SLL128U(c,32+64);
	//c = CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0x82F63B78ULL<<1}, 0x01);//сдвиг влево на 32 6EA2D55C - 64
	c = CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0x1ULL}, 0x01);
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x1DEA713F1ULL, 0x105EC76F0ULL}, 0x00);
	c ^= CL_MUL128(t, (poly64x2_t){0x1DEA713F1ULL, 0x105EC76F0ULL}, 0x10);// E83719AF 1D663B05D
	return c[1];
#endif
}
CRC32 CRC32C_update_64(CRC32 crc, uint8_t *data){
	uint32_t v0,v1;
	v0 = *(uint32_t*)&data[0] ^ crc;
	v1 = *(uint32_t*)&data[4];

	poly64x2_t c;// = {0,crc}, v;
	c = (poly64x2_t)(v4su){0,0,v0,v1};

//	c = SLL128U(c,32+64);
	c = CL_MUL128(c<<32, (poly64x2_t){0x6EA2D55CULL<<1}, 0x01)
	  ^ CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0x82F63B78ULL<<1}, 0x01);//сдвиг влево на 32 6EA2D55C - 64
	poly64x2_t 
	t  = CL_MUL128(c, (poly64x2_t){0x1DEA713F1ULL, 0x105EC76F0ULL}, 0x00);
	c ^= CL_MUL128(t, (poly64x2_t){0x1DEA713F1ULL, 0x105EC76F0ULL}, 0x10);// E83719AF 1D663B05D
	return c[1];
}
CRC32 CRC32C_update_128(CRC32 crc, uint8_t *data){
	poly64x2_t c = (poly64x2_t)LOAD128U(data);
	c[0]^=crc;

	c = CL_MUL128(c<<32, (poly64x2_t){0x18B8EA18ULL<<1}, 0x00)
	  ^ CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0xA66805EBULL<<1}, 0x00)
	  ^ CL_MUL128(c<<32, (poly64x2_t){0x6EA2D55CULL<<1}, 0x01)
	  ^ CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0x82F63B78ULL<<1}, 0x01);//сдвиг влево на 32 6EA2D55C - 64
	poly64x2_t 
	t  = CL_MUL128(c, (poly64x2_t){0x1DEA713F1ULL, 0x105EC76F0ULL}, 0x00);
	c ^= CL_MUL128(t, (poly64x2_t){0x1DEA713F1ULL, 0x105EC76F0ULL}, 0x10);// E83719AF 1D663B05D
	return c[1];
}
CRC32 CRC32C_update_N(CRC32 crc, uint8_t *data, int len){
	poly64x2_t c = {crc};// (poly64x2_t)LOAD128U(data);data+=16;
	int blocks = (len+15 >> 4);
	while (--blocks>0){
		c^= (poly64x2_t)LOAD128U(data);data+=16;
		c = CL_MUL128(c, (poly64x2_t){0xF20C0DFE,0x493C7D27}, 0x00) // 0x3743F7BD 191-32 = 159
		  ^ CL_MUL128(c, (poly64x2_t){0xF20C0DFE,0x493C7D27}, 0x11);// 0x3171D430 127-32 = 95
//		c = SLL128U(c, 32);
	}
	c^= (poly64x2_t)LOAD128U(data);
#if 0
	c = CL_MUL128(c<<32, (poly64x2_t){0x3171D430}, 0x00)
	  ^ CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0x493C7D27}, 0x00)
	  ^ CL_MUL128(c<<32, (poly64x2_t){0xDD45AAB8}, 0x01)
	  ^ CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0x00000001}, 0x01);//сдвиг влево на 32 6EA2D55C - 64
#else
	c = CL_MUL128(c, (poly64x2_t){0x493C7D27,0x00000001}, 0x00)
	  ^ CL_MUL128(c, (poly64x2_t){0x493C7D27,0x00000001}, 0x11);
#endif
	poly64x2_t 
	t  = CL_MUL128(c, (poly64x2_t){0x4869EC38DEA713F1ULL, 0x105EC76F0ULL}, 0x00);
	c ^= CL_MUL128(t, (poly64x2_t){0x4869EC38DEA713F1ULL, 0x105EC76F0ULL}, 0x10);// E83719AF 1D663B05D
	return c[1];
}


CRC32 CRC32K_update_8 (CRC32 crc, uint8_t *data){
	uint32_t val;
	val = *(uint8_t*)data;
	crc = crc ^ val;
// Barrett's reduction
#if 0
	uint32_t t = CL_MUL32L(crc<<24, 0x117D232CD);// 117D232CC+1
	uint32_t v = CL_MUL32H(t   , 0x1D663B05D)^(crc>>8);// (EB31D82E<<1)=1D663B05C
	return v;// & CRC32_MASK;
#else
	poly64x2_t c = {crc};
	c = SLL128U(c,32+24);
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x117D232CD, 0x1D663B05D}, 0x00);
	c ^= CL_MUL128(t, (poly64x2_t){0x117D232CD, 0x1D663B05D}, 0x10);// E83719AF 1D663B05D
	return c[1];
#endif
}
CRC32 CRC32K_update_16(CRC32 crc, uint8_t *data){
	uint32_t val;
	val = *(uint16_t*)data;
	crc = crc ^ val;
// Barrett's reduction
#if 0
	uint32_t t = CL_MUL32L(crc<<16, 0x117D232CD);
	uint32_t v = CL_MUL32H(t   , 0x1D663B05D)^(crc>>16);
	return v;// & CRC32_MASK;
#else
	poly64x2_t c = {crc};
	c = SLL128U(c,32+16);
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x117D232CD, 0x1D663B05D}, 0x00);
	c ^= CL_MUL128(t, (poly64x2_t){0x117D232CD, 0x1D663B05D}, 0x10);// E83719AF 1D663B05D
	return c[1];
#endif
}
CRC32 CRC32K_update_24(CRC32 crc, uint8_t *data){
	uint32_t val=0;
	__builtin_memcpy(&val, data,3);
	crc = crc ^ val;
// Barrett's reduction
#if 0
	uint32_t t = CL_MUL32L(crc<<8, 0x117D232CD);
	uint32_t v = CL_MUL32H(t   , 0x1D663B05D)^(crc>>24);
	return v;// & CRC32_MASK;
#else
	poly64x2_t c = {crc};
	c = SLL128U(c,32+8);
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x117D232CD, 0x1D663B05D}, 0x00);
	c ^= CL_MUL128(t, (poly64x2_t){0x117D232CD, 0x1D663B05D}, 0x10);// E83719AF 1D663B05D
	return c[1];
#endif
}
CRC32 CRC32K_update_32(CRC32 crc, uint8_t *data){
	uint32_t val;
	val = *(uint32_t*)data;
	crc = crc ^ val;
// Barrett's reduction
#if 0
	uint32_t t = CL_MUL32L(crc , 0x117D232CD);
	uint32_t v = CL_MUL32H(t   , 0x1D663B05D);// 741B8CD7 0xEB31D82E
	return v;// & CRC32_MASK;
#else
	poly64x2_t c = {0,(uint64_t)crc<<32};
//	c = SLL128U(c,32+0);
	c = CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0xEB31D82EULL<<1}, 0x01);
	poly64x2_t t;
	t  = CL_MUL128(c, (poly64x2_t){0x117D232CDULL, 0x1D663B05CULL}, 0x00);// {Ux, Px}
	c ^= CL_MUL128(t, (poly64x2_t){0x117D232CDULL, 0x1D663B05CULL}, 0x10);// E83719AF 1D663B05D
	return c[1];
#endif
}
CRC32 CRC32K_update_64(CRC32 crc, uint8_t *data){
	uint32_t v0,v1;
	v0 = *(uint32_t*)&data[0] ^ crc;
	v1 = *(uint32_t*)&data[4];

	poly64x2_t c;// = {0,crc}, v;
	c = (poly64x2_t)(v4su){v0,v1};
/*
	c = CL_MUL128(c<<32, (poly64x2_t){0x0C62AB26ULL<<1}, 0x01)
	  ^ CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0xEB31D82EULL<<1}, 0x01);
	  */
// Barrett's reduction
	poly64x2_t t;
	t  = CL_MUL128(c, (poly64x2_t){0xC25DD01C17D232CDULL, 0x1D663B05CULL}, 0x00);// {Ux, Px}
	c  = CL_MUL128(t, (poly64x2_t){0xC25DD01C17D232CDULL, 0x1D663B05CULL}, 0x10);// E83719AF 1D663B05D
	return c[1];
}
CRC32 CRC32K_update_128(CRC32 crc, uint8_t *data){
	poly64x2_t c = (poly64x2_t)LOAD128U(data);
	c[0]^=crc;
// Barrett's reduction
	c = CL_MUL128(c<<32, (poly64x2_t){0x69F48E4D}, 0x00)// 31+96
	  ^ CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0x9D65B2A5}, 0x00)// 31+64
	  ^ CL_MUL128(c<<32, (poly64x2_t){0x18C5564C}, 0x01)// 31+32
	  ^ CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){1}, 0x01);// 31
	poly64x2_t t;
	t  = CL_MUL128(c, (poly64x2_t){0x117D232CDULL, 0x1D663B05CULL}, 0x00);// {Ux, Px}
	c ^= CL_MUL128(t, (poly64x2_t){0x117D232CDULL, 0x1D663B05CULL}, 0x10);// E83719AF 1D663B05D
	return c[1];
}
uint64x2_t CRC32K_shift[]={
	// 31-64
	{0x00000001},//31
	// 31+8
	// 31+16
	// 31+24
	{0x18C5564C},//31+32
	{0x9D65B2A5},//31+64
	{0x69F48E4D},//31+96
};

CRC32 CRC32K_update_N(CRC32 crc, uint8_t *data, int len){
	poly64x2_t c = {crc};
	int blocks = (len+15 >> 4);
	while (--blocks>0){
		c^= (poly64x2_t)LOAD128U(data); data+=16;
		c = CL_MUL128(c, (poly64x2_t){0x7B4BC878, 0x9D65B2A5}, 0x00) // 159=191-32
		  ^ CL_MUL128(c, (poly64x2_t){0x7B4BC878, 0x9D65B2A5}, 0x11);// 95=127-32 
	}
	if (len & 15) {
		uint64x2_t v={0};
		__builtin_memcpy(&v, data, len&15);
		c^=v;
	} else
		c^= (poly64x2_t)LOAD128U(data);
/*
	c^= CL_MUL128(c<<32, (poly64x2_t){0x69F48E4D}, 0x00)// -33
	  ^ CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0x00000001}, 0x01);//31 маску убрать*/
// сдвиги
/*
	c = CL_MUL128(c, (poly64x2_t){0x9D65B2A5}, 0x00)// 31+64
	  ^ CL_MUL128(c, (poly64x2_t){0x00000001}, 0x01);// 31
*/
// сдвиги
#if 0
	c = CL_MUL128(c<<32, (poly64x2_t){0x69F48E4D}, 0x00)// 31+96
	  ^ CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0x9D65B2A5}, 0x00)// 31+64
	  ^ CL_MUL128(c<<32, (poly64x2_t){0x18C5564C}, 0x01)// 31+32
	  ^ CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0x00000001}, 0x01);// 31
#else
	c = CL_MUL128(c, (poly64x2_t){0x9D65B2A5}, 0x00) // 31+64
	  ^ CL_MUL128(c, (poly64x2_t){0x00000001}, 0x01);// 31
#endif
/*	c = CL_MUL128(c<<32, (poly64x2_t){0x18C5564C}, 0x01)//31+32
	  ^ CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0x9D65B2A5}, 0x00); //31+64*/
// Barrett's reduction
	poly64x2_t t;
	t  = CL_MUL128(c, (poly64x2_t){0xC25DD01C17D232CDULL, 0x1D663B05CULL}, 0x00);// {Ux, Px}
	c ^= CL_MUL128(t, (poly64x2_t){0xC25DD01C17D232CDULL, 0x1D663B05CULL}, 0x10);// E83719AF 1D663B05D
	return c[1];
}
CRC32 CRC32B_update_32(CRC32 crc, uint8_t *data){
	uint32_t val;
	//__builtin_memcpy(&val, data, 4);
	val = *(uint32_t*)data;
	crc = crc ^ val;
// Barrett's reduction для отраженного порядка бит
#if 0
	uint32_t t = CL_MUL32L(crc, 0xF7011641);
	uint32_t v = CL_MUL32H(t, 0x1DB710641);// 33 бита, представлено умножением CLMUL и операцией XOR
	return v;// & CRC32_MASK;
#elif 1
	poly64x2_t c = {0,(uint64_t)crc<<32};
	//c = SLL128U(c,32);
	c  = CL_MUL128(c, (poly64x2_t){0x1F7011641ULL, 0x1DB710640ULL}, 0x11);
	poly64x2_t t;
	t  = CL_MUL128(c, (poly64x2_t){0x1F7011641ULL, 0x1DB710640ULL}, 0x00);
	c ^= CL_MUL128(t, (poly64x2_t){0x1F7011641ULL, 0x1DB710640ULL}, 0x10);
	return c[1];
#else
	poly64x2_t c = {crc};
	c = SLL128U(c,32);
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x1F7011641ULL, 0x1DB710641ULL}, 0x00);
	c ^= CL_MUL128(t, (poly64x2_t){0x1F7011641ULL, 0x1DB710641ULL}, 0x10);
	return c[1];
#endif
}
CRC32 CRC32B_update_64(CRC32 crc, uint8_t *data){// не работает
	uint32_t v0,v1;
	v0 = *(uint32_t*)&data[0] ^ crc;
	v1 = *(uint32_t*)&data[4];

	poly64x2_t c;// = {0,crc}, v;
	c = (poly64x2_t)(v4su){0,0,v0,v1};
// редуцируем 128 бит в 96 бита c3:c2:c1:c0
//	c ^= CL_MUL128(c>>32, K56, 0x11);
// редуцируем 96 бит в 64 бита
	//poly64x2_t t = CL_MUL128(c, (poly64x2_t){0xB1E6B092ULL}, 0x00);
	c = CL_MUL128(c<<32, (poly64x2_t){0xB1E6B092ULL<<1}, 0x01)
	  ^ CL_MUL128(c&0xFFFFFFFF00000000ULL, (poly64x2_t){0xEDB88320ULL<<1}, 0x01);
// Barrett's reduction
	poly64x2_t t;
	t  = CL_MUL128(c, (poly64x2_t){0x1F7011641ULL, 0x1DB710640ULL}, 0x00);
	c ^= CL_MUL128(t, (poly64x2_t){0x1F7011641ULL, 0x1DB710640ULL}, 0x10);
	return c[1];
}
CRC32 CRC32B_update_128(CRC32 crc, uint8_t *data){
	poly64x2_t c = (poly64x2_t)LOAD128U(data);
	c[0]^=crc;
// Barrett's reduction
	c = CL_MUL128(c<<32, (poly64x2_t){0xA06A2517ULL<<1}, 0x00)
	  ^ CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0x6655004FULL<<1}, 0x00)
	  ^ CL_MUL128(c<<32, (poly64x2_t){0xB1E6B092ULL<<1}, 0x01)
	  ^ CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0xEDB88320ULL<<1}, 0x01);
	poly64x2_t t;
	t  = CL_MUL128(c, (poly64x2_t){0x1F7011641ULL, 0x1DB710640ULL}, 0x00);// {Ux, Px}
	c ^= CL_MUL128(t, (poly64x2_t){0x1F7011641ULL, 0x1DB710640ULL}, 0x10);// E83719AF 1D663B05D
	return c[1];
}
CRC32 CRC32B_update_N(CRC32 crc, uint8_t *data, int len){
	poly64x2_t c = {crc};
	int blocks = (len+15 >> 4);
	while (--blocks>0){
		c^= (poly64x2_t)LOAD128U(data); data+=16;
		c = CL_MUL128(c, (poly64x2_t){0xAE689191}, 0x00) // 191-32
		  ^ CL_MUL128(c, (poly64x2_t){0xCCAA009E}, 0x01);// 127-32
	}
	if (len & 15) {
		poly64x2_t v={0};
		__builtin_memcpy(&v, data, len & 15);
		c^= v;
	} else
		c^= (poly64x2_t)LOAD128U(data);
// Barrett's reduction
#if 0
	c = CL_MUL128(c<<32, (poly64x2_t){0x9BA54C6F}, 0x00)					// c1 x^127 0x9BA54C6F
	  ^ CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0xCCAA009E}, 0x00)	// c2 x^95
	  ^ CL_MUL128(c<<32, (poly64x2_t){0xB8BC6765}, 0x01)					// c3 x^63
	  ^ CL_MUL128(c& 0xFFFFFFFF00000000ULL, (poly64x2_t){0x00000001}, 0x01);// c4 x^31
#else
	c = CL_MUL128(c, (poly64x2_t){0xCCAA009E, 0x00000001}, 0x00) // x^95
	  ^ CL_MUL128(c, (poly64x2_t){0xCCAA009E, 0x00000001}, 0x11);// x^31
#endif
	poly64x2_t t;
	t  = CL_MUL128(c, (poly64x2_t){0xB4E5B025F7011641ULL, 0x1DB710640ULL}, 0x00);// {Ux, Px}
	c ^= CL_MUL128(t, (poly64x2_t){0xB4E5B025F7011641ULL, 0x1DB710640ULL}, 0x10);// E83719AF 1D663B05D
	return c[1];
}
CRC32 CRC32B_update_bits(CRC32 crc, uint8_t *data, int nbits){
	uint32_t val;
	__builtin_memcpy(&val, data, 4);
	uint32_t mask = ~0UL >> (32-nbits);
	crc = crc ^ (val & mask);
// Barrett's reduction для отраженного порядка бит
#if 0
	uint32_t t = CL_MUL32L(crc<<(32-nbits), 0x1F7011641);
	uint32_t v = CL_MUL32H(t, 0x1DB710641)^(crc>>nbits);// 33 бита, представлено умножением CLMUL и операцией XOR
	return v;// & CRC32_MASK;
#else
	poly64x2_t c = {(uint64_t)crc<<(32-nbits)};
	c = SLL128U(c,32);
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x1F7011641ULL, 0x1DB710641ULL}, 0x00);
	c ^= CL_MUL128(t, (poly64x2_t){0x1F7011641ULL, 0x1DB710641ULL}, 0x10);
	return c[1];
#endif
}
CRC32 CRC32B_update_24(CRC32 crc, uint8_t *data){
	uint32_t val=0;
	__builtin_memcpy(&val, data, 3);
	crc = crc ^ val;
// Barrett's reduction для отраженного порядка бит
	uint32_t t = CL_MUL32L(crc<<8, 0x1F7011641);
	uint32_t v = CL_MUL32H(t, 0x1DB710641)^(crc>>24);// 33 бита, представлено умножением CLMUL и операцией XOR
	return v;// & CRC32_MASK;
}
CRC32 CRC32B_update_16(CRC32 crc, uint8_t *data){
	uint32_t val=0;
	__builtin_memcpy(&val, data, 2);
	crc = crc ^ val;
// Barrett's reduction для отраженного порядка бит
	uint32_t t = CL_MUL32L(crc<<16, 0x1F7011641);
	uint32_t v = CL_MUL32H(t, 0x1DB710641)^(crc>>16);// 33 бита, представлено умножением CLMUL и операцией XOR
	return v;// & CRC32_MASK;
}
CRC32 CRC32B_update_8 (CRC32 crc, uint8_t *data){
	uint32_t val=0;
	__builtin_memcpy(&val, data, 1);
	crc = crc ^ val;
// Barrett's reduction для отраженного порядка бит
	uint32_t t = CL_MUL32L(crc<<24, 0x1F7011641);
	uint32_t v = CL_MUL32H(t, 0x1DB710641)^(crc>>8);// 33 бита, представлено умножением CLMUL и операцией XOR
	return v;// & CRC32_MASK;
}

static inline
uint32_t barrett24_requction(poly64x2_t c, const poly64x2_t KBP)
{
	poly64x2_t t = CL_MUL128(c, KBP, 0x00);
	c = CL_MUL128(t, KBP, 0x11) ^ (c>>16);//vshrq_n_u64((uint64x2_t)c, 16);
	return ((uint32x4_t)c)[0];//vgetq_lane_u32((uint32x4_t)c, 0);
}

CRC32 CRC24_update_8 (CRC32 crc, uint8_t *data){
	uint32_t val=0;
//	__builtin_memcpy(&val, data, 1);
//	val = __builtin_bswap32(val);
	crc = crc ^ (data[0]<<16);
// Barrett's reduction
#if 0
	uint32_t t = CL_MUL32H(crc>>16, 0x1F845FF00);
	uint32_t v = CL_MUL32L(t      , 0x1864CFB)^(crc<< 8);
	return v & 0xFFFFFF;//CRC32_MASK;
#elif 1
	poly64x2_t c = {crc};
	c = SLL128U(c, 40-16);
	return barrett24_requction(c, (poly64x2_t){0x1F845FF,0x1864CFB});
#else
	v2du c = {crc};
	c = SLL128U(c, 40-16);
	v2du t = CL_MUL128(c , (v2du){0x1F845FF,0x1864CFB}, 0x00);
	c = CL_MUL128(t, (v2du){0x1F845FF,0x1864CFB}, 0x11)^ (c>>16);
	return c[0];// & 0xFFFFFF;
#endif
}
CRC32 CRC24_update_16(CRC32 crc, uint8_t *data){
	uint32_t val=0;
//	__builtin_memcpy(&val, data, 1);
//	val = __builtin_bswap32(val);
	crc = crc ^ data[0]<<16 ^ data[1]<<8;
// Barrett's reduction
#if 0
	uint32_t t = CL_MUL32H(crc>>8, 0x1F845FF00);
	uint32_t v = CL_MUL32L(t      , 0x1864CFB)^(crc<<16);
	return v & 0xFFFFFF;//CRC32_MASK;
#elif 1
	poly64x2_t c = {crc};
	c = SLL128U(c, 40-8);
	return barrett24_requction(c, (poly64x2_t){0x1F845FF,0x1864CFB});
#else
	v2du c = {crc};
	c = SLL128U(c, 40-8);
	v2du t = CL_MUL128(c , (v2du){0x1F845FF,0x1864CFB}, 0x00);
	c = CL_MUL128(t, (v2du){0x1F845FF,0x1864CFB}, 0x11)^ (c>>16);
	return c[0];// & 0xFFFFFF;
#endif
}
CRC32 CRC24_update_24(CRC32 crc, uint8_t *data){
	uint32_t val=0;
//	__builtin_memcpy(&val, data, 1);
//	val = __builtin_bswap32(val);
	crc = crc ^ (data[0]<<16 | data[1]<<8 | data[2]<<0);
// Barrett's reduction
#if 0
	uint32_t t = CL_MUL32H(crc>>8, 0x1F845FF00);
	uint32_t v = CL_MUL32L(t      , 0x1864CFB)^(crc<<16);
	return v & 0xFFFFFF;//CRC32_MASK;
#elif 1
	poly64x2_t c = {crc};
	c = SLL128U(c, 40-0);
	return barrett24_requction(c, (poly64x2_t){0x1F845FF,0x1864CFB});
#else
	v2du c = {crc};
	c = SLL128U(c, 40);
	v2du t = CL_MUL128(c , (v2du){0x1F845FF,0x1864CFB}, 0x00);
	c = CL_MUL128(t, (v2du){0x1F845FF,0x1864CFB}, 0x11) ^ (c>>16);
	return c[0];// & 0xFFFFFF;
#endif
}
CRC32 CRC24_update_32(CRC32 crc, uint8_t *data){
	uint32_t val=0;
	__builtin_memcpy(&val, data, 4);
	val = __builtin_bswap32(val);
	poly64x2_t c = (poly64x2_t){val ^ (crc<<8)};
// редуцируем 128 бит в 96 бита c3:c2:c1:c0
	//c = CL_MUL128(c, K56, 0x11) ^ SLL128U((v2du){c[0],0}, 32);
   c = SLL128U(c, 40);// тоже самое что в предыдущей строке
// редуцируем 96 бит в 64 бита
   c ^= CL_MUL128(c, (poly64x2_t){0x360952ULL<<16}, 0x01);// 0x360952 0x1B045A9
// Barrett's reduction
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x1F845FF,0x1864CFB}, 0x00);
	c = CL_MUL128(t, (poly64x2_t){0x1F845FF,0x1864CFB}, 0x11) ^ (c>>16);
	return c[0];// & 0xFFFFFF;
}
CRC32 CRC24_update_48(CRC32 crc, uint8_t *data){
	uint64_t val=0;
//	__builtin_memcpy(&val, data, 6);
//	val = __builtin_bswap32(val);
	val = (uint64_t)data[0]<<40 | (uint64_t)data[1]<<32 | (uint64_t)data[2]<<24 
	| (uint64_t)data[3]<<16 | (uint64_t)data[4]<<8 | data[5];
	val ^= (uint64_t)crc << 24;
	poly64x2_t c = (poly64x2_t){val};
// редуцируем 128 бит в 96 бита c3:c2:c1:c0
	//c = CL_MUL128(c, K56, 0x11) ^ SLL128U((v2du){c[0],0}, 32);
   c = SLL128U(c, 40);// тоже самое что в предыдущей строке
// редуцируем 48 бит в 24 бита
   c ^= CL_MUL128(c, (poly64x2_t){0x360952ULL<<16}, 0x01);// 0x360952 0x1B045A9
// Barrett's reduction
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x1F845FF,0x1864CFB}, 0x00);
	c = CL_MUL128(t, (poly64x2_t){0x1F845FF,0x1864CFB}, 0x11) ^ (c>>16);
	return c[0];// & 0xFFFFFF;
}
CRC32 CRC24_update_128(CRC32 crc, uint8_t *data){
	poly64x2_t c,v={0};
	c = (poly64x2_t){crc};
	c = SLL128U(c, 128-24);
	v = (poly64x2_t)LOAD128U(data);
	c^= (poly64x2_t)REVERSE((uint8x16_t)v);
	c = SRL128U(c, 128-96-16);
// редуцируем 96 бит в 48 бита c3:c2:c1:c0
// c = SLL128U(c, 16); -- ушло выше
	c = CL_MUL128(c, (poly64x2_t){0x360952ULL<<16, 0x3B918CULL<<16}, 0x11) ^ SLL128U((poly64x2_t){c[0],0}, 24);
// редуцируем 48 бит в 24 бита
	c^= CL_MUL128(c, (poly64x2_t){0x360952ULL<<16, 0x3B918CULL<<16}, 0x01);// 0x360952 0x1B045A9
// Barrett's reduction
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x1F845FF,0x1864CFB}, 0x00);
	c = CL_MUL128(t, (poly64x2_t){0x1F845FF,0x1864CFB}, 0x11) ^ (c>>16);
	return c[0];// & 0xFFFFFF;
}
CRC32 CRC24_update_96(CRC32 crc, uint8_t *data){
	poly64x2_t c,t,v={0};
	c = (poly64x2_t){crc};
	c = SLL128U(c, 128-24);
	__builtin_memcpy(&v, data, 12);
	//v = (v2du)LOAD128U(data);
	c^= (poly64x2_t)REVERSE((uint8x16_t)v);
	c = SRL128U(c, 128-96-16);
// редуцируем 96 бит в 48 бита c3:c2:c1:c0
// c = SLL128U(c, 16); -- ушло выше
	c = CL_MUL128(c, (poly64x2_t){0x360952ULL<<16, 0x3B918CULL<<16}, 0x11) ^ SLL128U((poly64x2_t){c[0],0}, 24);
// редуцируем 48 бит в 24 бита
	c^= CL_MUL128(c, (poly64x2_t){0x360952ULL<<16, 0x3B918CULL<<16}, 0x01);// 0x360952 0x1B045A9
// Barrett's reduction
	t = CL_MUL128(c, (poly64x2_t){0x1F845FF,0x1864CFB}, 0x00);
	c = CL_MUL128(t, (poly64x2_t){0x1F845FF,0x1864CFB}, 0x11) ^ (c>>16);
	return c[0];// & 0xFFFFFF;
}
CRC32 CRC24_update_64(CRC32 crc, uint8_t *data){
	uint64_t val=0;
	__builtin_memcpy(&val, data, 8);
	val = __builtin_bswap64(val);
	val ^= (uint64_t)crc << (64-24);
	poly64x2_t c = (poly64x2_t){val};
// редуцируем 72 бит в 48 бита c3:c2:c1:c0
	c = SLL128U((poly64x2_t)c, 16);
	c = CL_MUL128(c, (poly64x2_t){0x360952ULL<<16, 0x3B918CULL<<16}, 0x11) ^ SLL128U((poly64x2_t){c[0],0}, 24);
//  c = SLL128U(c, 40);// тоже самое что в предыдущей строке
// редуцируем 48 бит в 24 бита
	c^= CL_MUL128(c, (poly64x2_t){0x360952ULL<<16, 0x3B918CULL<<16}, 0x01);// 0x360952 0x1B045A9
// Barrett's reduction
	poly64x2_t t = CL_MUL128(c, (poly64x2_t){0x1F845FF,0x1864CFB}, 0x00);
	c = CL_MUL128(t, (poly64x2_t){0x1F845FF,0x1864CFB}, 0x11) ^ (c>>16);
	return c[0];// & 0xFFFFFF;
}

uint32_t    CRC24_update_N(uint32_t crc, uint8_t *data, int len) {
	uint64_t val = 0;
	val = *(uint64_t*) data; data+= (len & 7)?(len & 7):8;
	val = __builtin_bswap64(val);
	uint64_t c = (((uint64_t)crc<<(64-24))^val)>>((len & 7)? 64-((len & 7)<<3):0);
	int blocks = (len+7 >> 3);
	while (--blocks>0) {
		c= CL_MUL24(c>>48, 0x6668A5) 
		 ^ CL_MUL24(c>>24, 0xFD7E0C) 
		 ^ CL_MUL24(c>> 0, 0x36EB3D);
		 
		val = *(uint64_t*) data; data+=8;
		val = __builtin_bswap64(val);
		c^= val;
	}
	c= CL_MUL24(c>>48, 0x3B918C) 
	 ^ CL_MUL24(c>>24, 0x360952) 
	 ^ CL_MUL24(c>> 0, 0x864CFB);
// Редуцирование 16 бит в 8 бит
	uint64_t t = CL_MUL24(c>>24, 0xF845FF) ^ c>>24<<24;
	c^= CL_MUL24(t>>24, 0x864CFB);
	return c & 0xFFFFFF;
}


static inline uint32_t 
barrett32_requction(poly64x2_t c, const poly64x2_t KBP, const int n)
{
	if (n!=32) {
		poly64x2_t t = CL_MUL128(c>>(32-n), KBP, 0x00);
		c = CL_MUL128(t>>32, KBP, 0x10) ^ (c<<n);//vshlq_n_u64((v2du)c, n);
	} else {
		poly64x2_t t = CL_MUL128(c, KBP, 0x00);
		c = CL_MUL128(t>>32, KBP, 0x10);
	}
	return ((uint32x4_t)c)[0];//vgetq_lane_u32((uint32x4_t)c, 0);
}
CRC32 CRC32_update_8 (CRC32 crc, uint8_t *data){
	uint32_t val=0;
	__builtin_memcpy(&val, data, 1);
	val = __builtin_bswap32(val);
	crc = crc ^ val;
// Barrett's reduction
#if 0
	uint32_t t = CL_MUL32H(crc>>24, 0x104D101DF);
	uint32_t v = CL_MUL32L(t      , 0x104C11DB7)^(crc<< 8);
	return v;// & CRC32_MASK;
#else
	return barrett32_requction((poly64x2_t)(uint32x4_t){crc}, (poly64x2_t){0x104D101DF,0x104C11DB7}, 8);
#endif
}
CRC32 CRC32_update_16(CRC32 crc, uint8_t *data){
	uint32_t val=0;
	__builtin_memcpy(&val, data, 2);
	val = __builtin_bswap32(val);
	crc = crc ^ val;
// Barrett's reduction
#if 0
	uint32_t t = CL_MUL32H(crc>>16, 0x104D101DF);
	uint32_t v = CL_MUL32L(t   , 0x104C11DB7)^ (crc<<16);
	return v;// & CRC32_MASK;
#else
	return barrett32_requction((poly64x2_t)(uint32x4_t){crc}, (poly64x2_t){0x104D101DF,0x104C11DB7}, 16);
#endif
}
CRC32 CRC32_update_24(CRC32 crc, uint8_t *data){/* шаг -- три байта */
	uint32_t val=0;
	__builtin_memcpy(&val, data, 3);
	val = __builtin_bswap32(val);
	crc = crc ^ val;
// Barrett's reduction
#if 0
	uint32_t t = CL_MUL32H(crc>>8, 0x104D101DF);
	uint32_t v = CL_MUL32L(t   , 0x104C11DB7)^ (crc<<24);
	return v;// & CRC32_MASK;
#else
	return barrett32_requction((poly64x2_t)(uint32x4_t){crc}, (poly64x2_t){0x104D101DF,0x104C11DB7}, 24);
#endif

}
CRC32 CRC32_update_32(CRC32 crc, uint8_t *data){/* шаг -- четыре байта */
	uint32_t val;
	val = __builtin_bswap32(*(uint32_t*)data);
	crc = crc ^ val;
// Barrett's reduction
#if 0
	uint32_t t = CL_MUL32H(crc , 0x104D101DF);// 33 бита умножение представлено как CLMUL XOR
	uint32_t v = CL_MUL32L(t   , 0x104C11DB7);
	return v;// & CRC32_MASK;
#elif 1
//	poly64x2_t c = {crc};
	return barrett32_requction((poly64x2_t)(uint32x4_t){crc}, (poly64x2_t){0x104D101DF,0x104C11DB7}, 32);
#else
	poly64x2_t c = {0,crc};
	c = CL_MUL128(c, (v2du){0x104D101DF,0x104C11DB7}, 0x01);
	c = CL_MUL128(c>>32, (v2du){0x104D101DF,0x104C11DB7}, 0x10);
	return c[0];
#endif
}
CRC32 CRC32_update_bits(CRC32 crc, uint8_t *data, int bits){/* шаг -- N бит от 1 до 31 бит */
	uint32_t val=0, mask = ~0UL>>(32-bits);
	//__builtin_memcpy(&val, data, 1);

	val = *(uint32_t*)data & mask;
	val = __builtin_bswap32(val);
	crc = crc ^ val;
// Barrett's reduction
	uint32_t t = CL_MUL32H(crc>>(32-bits), 0x104D101DF);
	uint32_t v = CL_MUL32L(t   , 0x104C11DB7)^ (crc<<(bits));
	return v;// & CRC32_MASK;
}

// Коэффициенты для редуцирования на 128 и 128+64 бита
static const poly64x2_t K34 = {/* K4 */0xE8A45605, /* K3 */0xC5B9CD4C};
// Коэффициенты для редуцирования на 96 и 64 бита
static const poly64x2_t K56 = {/* K6 */0x490D678D, /* K5 */0xF200AA66};
/* 
static inline
v16qi MASK0120(v16qi a){
	return __builtin_ia32_pshufb128(a, (v16qi){-1,-1,-1,-1,0,1,2,3,4,5,6,7,-1,-1,-1,-1});
} */
static const v16qi Shitfs[16] = {
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},// эта часть таблицы не используется
//    {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1},// эта
	{15,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1},
	{14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1},
	{13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1},

	{12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1},// для меньших сдвигов не работает
	{11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1},
	{10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1},
	{ 9,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1},
	{ 8, 9,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1},
	{ 7, 8, 9,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1},
	{ 6, 7, 8, 9,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1},
	{ 5, 6, 7, 8, 9,10,11,12,13,14,15,-1,-1,-1,-1,-1},
	{ 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,-1,-1,-1,-1},
	{ 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,-1,-1,-1},
	{ 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,-1,-1},
	{ 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,-1},

};
static v16qi MASKSHIFT(v16qi a, int i)
{
//	return (v16qi){0};
	uint64x2_t t = (uint64x2_t)a;
	if (i &~7) {
		t = (uint64x2_t){t[1], 0};
		i &=7;
	}
	if (i) {
		i<<=3;// в битах
		t = t>>i | (uint64x2_t){t[1], 0} << (64-i);
	}
	return (v16qi) t;
	//return __builtin_ia32_pshufb128(a, Shitfs[i]);
};
static inline 
poly64x2_t CRC64_single_folding(poly64x2_t c, const poly64x2_t K34)
{
//	v2du v = (v2du)LOAD128U(data);
//	v = (v2du)REVERSE((v16qi)v);
	return CL_MUL128(c, K34, 0x00) ^ CL_MUL128(c, K34, 0x11);
}
static const poly64x2_t KBP = { BARRETT_U32, POLY32_};// обе константы 33 бита
CRC32 CRC32_update_N_(CRC32 crc, uint8_t *data, int n){
 	int i = n&0xF;
	poly64x2_t c,v;
	if (i<4 && i>0) {
		crc = CRC32_update_bits(crc, data, i<<3);
		if (n<4) return crc;
		data+=i;
	}
	// начальное преобразование, загрузка вектора
	c = (poly64x2_t){crc};
	c = SLL128U(c, 96);
	v = (poly64x2_t)LOAD128U(data);
	c^= (poly64x2_t)REVERSE((uint8x16_t)v);
	if (i>=4){
		c = (poly64x2_t)MASKSHIFT((v16qi)c,i);
		data+=i;
	} else {
		data+=16;
		i+=16;
	}
	// сюда можно вставить folding х4 или x2
	// ...
	// single folding по вектору 256 в 128
	for(; i<n;i+=16)
	{
		c = CRC64_single_folding(c, K34);
		v = (poly64x2_t)LOAD128U(data); data+=16;
		v = (poly64x2_t)REVERSE((uint8x16_t)v);
		c ^= v;// ^ CRC64_single_folding(c, K34);
	}
// финальное редуцирование преобразует 128 бит в 32
// операцию финального редуцирования можно упростить, если использовать
// CRC64 с выравниванием по старшему биту,

// редуцируем 128 бит в 96 бита c3:c2:c1:c0
	c  = CL_MUL128(c, K56, 0x11) ^ SLL128U((poly64x2_t){c[0],0}, 32);// (v2du)MASK0120((v16qi)c);// {c[0]<<32, c[0]>>32};
// редуцируем 96 бит в 64 бита
	//printf("c96: %08llX:%08llX => ", c[0], c[1]);
c ^= CL_MUL128(c, (poly64x2_t){0x490D678DULL}, 0x01) ^ (poly64x2_t){0, c[1]};// в этом нет смысла, но это обнуляет.
	//printf("c: %08llX:%08llX => \n", c[0], c[1]);
// Barrett's reduction 64 в 32
	poly64x2_t t = CL_MUL128(c , KBP, 0x00);
	c ^= CL_MUL128(t , KBP, 0x11);
	//printf("c: %08llX:%08llX => \n", c[0], c[1]);
	return c[0];// & CRC32_MASK;
}
uint32_t CRC32_sh_high[] = {
	0x490D678D,// 64
	1<<8, //  8
	1<<16,// 16
	1<<24,// 24
	0x04C11DB7,// 32
	0xD219C1DC,// 40
	0x01D8AC87,// 48
	0xDC6D9AB7,// 56
};
uint32_t CRC32_sh_low[] = {
	0x04C11DB7, // 32
	0x876D81F8,// -24
	0x1ACA48EB,// -16
	0xA9D3E6A6,// -8
	1,
	1<<8,
	1<<16,// 16
	1<<24,// 24
};
uint32_t    CRC32_update_N(uint32_t crc, uint8_t *data, int len) {
	uint64_t val;
	uint64_t c = (uint64_t)crc<<32;
	int blocks = (len+7 >> 3);
	while (--blocks>0) {
		c^= __builtin_bswap64(*(uint64_t*) data);data+=8;
		c = CL_MUL32(c>>32, 0xF200AA66) // 96
		  ^ CL_MUL32(c>> 0, 0x490D678D);// 64
	}
	if (len&7) {
		val = 0;// *(uint64_t*) data; 
		__builtin_memcpy(&val, data, len&7);
		//val &= (~0ULL)>>(64- (len&7)*8);
	} else 
		val = *(uint64_t*) data;
	c^= __builtin_bswap64(val);
	c= CL_MUL32(c>>32, CRC32_sh_high[len&7]) // 64,  8, 16,24,32,40,48,56
	 ^ CL_MUL32(c>> 0, CRC32_sh_low [len&7]);// 32,-24,-16,-8, 0, 8,16,24
// Редуцирование 64 бит в 32 бит
	uint64_t t = CL_MUL32(c>>32, 0x04D101DF) ^ c;// x 0x104D101DFULL -- единица в старшем разряде, 33 бита
	c^= CL_MUL32(t>>32, 0x04C11DB7);
	return c;
}
// коэффициенты для CRC64
poly64x2_t CRC64_final_reduction(poly64x2_t c, const poly64x2_t KPB, const poly64x2_t K56)
{
// multiply with k5 [x^128 mod P(x)] (c3:c2)*K56[1] ^(с1:c0:0:0) -- выравнивание по левому краю 128бит
	c  = CL_MUL128(c, K56, 0x11) ^ (poly64x2_t){0,c[0]};
// Barrett's reduction 128 в 64
	poly64x2_t t = CL_MUL128(c, KBP, 0x01) ^ (poly64x2_t){0,c[0]};
	c^= CL_MUL128(t , KBP, 0x11) ^ (poly64x2_t){0,t[0]};
	return c;
}
static const poly64x2_t K56_ = {/* K6 */0x1490D678D, /* K5 */0xF200AA66};
v2du CRC32_update_128(v2du crc, uint8_t *data){
// начальное преобразование, загрузка вектора
	poly64x2_t c = SLL128U((poly64x2_t)crc, 96);// {0,crc[0]<<32};
	poly64x2_t v;
	//__builtin_ia32_loaddqu() -- загрузить без выравнивания
	v = (poly64x2_t)LOAD128U(data);
	v = (poly64x2_t)REVERSE((uint8x16_t)v);
	c^=v;
// сюда втыкается folding по вектору 256*n в 128
// ...
// финальное редуцирование преобразует 128 бит в 32 K56[1] = (c3:c2)*XT_modP(64+32) ^ (c1:c0)*XT_modP(32)
// 32 это финальный сдвиг
// редуцируем 128 бит в 96 бита c3:c2:c1:c0 => (c3:c2)*K56[1] ^ (c1:c0:0)
	//c  = CL_MUL128(c, K56, 0x11) ^ SLL128U((poly64x2_t){c[0],0}, 32);
	c  = CL_MUL128(c, K56, 0x11) ^ CL_MUL128(c, (poly64x2_t){1ULL<<32}, 0x00);
	
// редуцируем 96 бит в 64 бита с2:c1:c0 => (c1:c0) ^ (c2 *XT_modP(P,32)) -- в старшей части будет отстаток
	c ^= CL_MUL128(c, K56, 0x01);// ^ (poly64x2_t){0,c[1]}; // -- обнуляет старшую часть
// Barrett's reduction 64 -> 32
	poly64x2_t t = CL_MUL128(c , KBP, 0x00);
	c^= CL_MUL128(t , KBP, 0x11);
	return (v2du)c;
}
CRC32 CRC32_update_96(CRC32 crc, uint8_t *data){
	uint32_t v0,v1,v2;
	v0 = *(uint32_t*)&data[0];
	v1 = *(uint32_t*)&data[4];
	v2 = *(uint32_t*)&data[8];
	v0 = __builtin_bswap32(v0)^crc;
	v1 = __builtin_bswap32(v1);
	v2 = __builtin_bswap32(v2);

	poly64x2_t c;
	c = (poly64x2_t)(v4su){v2,v1,v0,0};
// редуцируем 128 бит в 96 бита c3:c2:c1:c0
	c = CL_MUL128(c, K56, 0x11) ^ SLL128U((poly64x2_t){c[0],0}, 32);// (v2du)MASK0120((v16qi)c);// {c[0]<<32, c[0]>>32};;
// редуцируем 96 бит в 64 бита
	c ^= CL_MUL128(c, K56, 0x01);
// Barrett's reduction
	poly64x2_t t = CL_MUL128(c , KBP, 0x00);
	c^= CL_MUL128(t , KBP, 0x11);
	return c[0];// & CRC32_MASK;
}
CRC32 CRC32_update_64(CRC32 crc, uint8_t *data){
	uint32_t v0,v1;
	v0 = *(uint32_t*)&data[0];
	v1 = *(uint32_t*)&data[4];
	v0 = __builtin_bswap32(v0)^crc;
	v1 = __builtin_bswap32(v1);

	poly64x2_t c;// = {0,crc}, v;
	c = (poly64x2_t)(v4su){v1,v0,0,0};
// редуцируем 128 бит в 96 бита c3:c2:c1:c0
	//c = CL_MUL128(c, K56, 0x11) ^ SLL128U((v2du){c[0],0}, 32);
	c = SLL128U(c, 32);// тоже самое что в предыдущей строке
// редуцируем 96 бит в 64 бита
	c ^= CL_MUL128(c, K56, 0x01);
	// 	c = CL_MUL128(c>>32, K56, 0x01) ^ (c<<32); -- две строки можно заменить
// Barrett's reduction
	poly64x2_t t = CL_MUL128((poly64x2_t)c , KBP, 0x00);
	c^= CL_MUL128(t , KBP, 0x11);
	return c[0];// & CRC32_MASK;
}

/*! расчитывает баррета */
uint64_t barret_calc(uint64_t poly, int bits)
{
//	poly <<=8;
	uint64_t r = (uint64_t)poly;
	uint64_t n = bits;
	uint64_t v = 0;
	while (--n){
		if (r & (1ULL<<n)) {
			if (bits>n)
				r ^= poly>>(bits-n) | (1ULL<<n);
			else
				r ^= poly<<(n-bits);
			v |= 1ULL<<n;
		}
	}
	if (r) v|=1;
	return v;
}
static
uint64_t xt_mod_P_neg(uint64_t poly, int t, int bits){
	uint64_t v=0;
	if (t>0) {
		v=1;
		do {
			if (v&1){
				v = (v>>1) ^ (1ULL<<(bits-1)|poly>>1);
			} else {
				v = (v>>1);
			}
		} while (--t);
	}
	return v;
}
/*!  x^(T) mod P(x) */
static
uint64_t xt_mod_P(uint64_t poly, int t, int bits)
{
	uint64_t v = 1;
	if (bits<64) {
		poly |= 1ULL<<bits;
	}
	if (t==0){}
	else if (t<0) {
		t = -t;
		do {
			if (v&1){
				v = (v>>1) ^ (1ULL<<(bits-1)|poly>>1);
			} else {
				v = (v>>1);
			}
		} while (--t);
		
	} else {
		do {
			if (v&(1ULL<<(bits-1))){
				v = (v<<1) ^ poly;
			} else {
				v = (v<<1);
			}
	//		printf(">> %0llX\n", v);
		} while (--t);
	}
	return v;
}
/*!  x^(T) mod P(x)  обратный порядок бит */
static
uint64_t xt_mod_P_ref(uint64_t poly, int t, int bits)
{
	uint64_t v = (1ULL<<(bits-1));
	if (t==0){
	} else if (t<0) {
		t = -t;
		do {
			if (v&(1ULL<<(bits-1))){
				v = (v<<1) ^ (poly<<1|1);
			} else {
				v = (v<<1);
			}
		} while (--t);
	} else
		do {
			if (v&1){
				v = (v>>1) ^ (poly);
			} else {
				v = (v>>1);
			}
		} while (--t);
	return v;
}
static
uint64_t bit_reflect(uint64_t v)
{
	v = __builtin_bswap64(v);
	const uint64_t m[]={0xF0F0F0F0F0F0F0F0ULL, 0xCCCCCCCCCCCCCCCCULL, 0xAAAAAAAAAAAAAAAAULL};
	v = (v&m[0])>>4 | (v&~m[0])<<4;
	v = (v&m[1])>>2 | (v&~m[1])<<2;
	v = (v&m[2])>>1 | (v&~m[2])<<1;
	return v;
}

void barrett_k64(uint64_t poly, int bits)
{
	int dig = bits/4;
	uint64_t u;
	printf("P'(x) = 0x1%0*"PRIX64"\n", dig, poly);
//	u = xt_mod_P(bit_reflect(poly), 127, bits);
//	printf("k5' = x^(128) mod P'(x) = 0x%0*llX\n", dig, bit_reflect(u));
//	u = xt_mod_P_ref(poly, 128, bits);
//	printf("k5' = x^(128) mod P'(x) = 0x%0*llX\n", dig, u);
	u = barret_calc(poly,bits);
	printf("Barrett u = x^%d/P(x) = 0x%0*"PRIX64"\n", bits*2, dig, (u));
	poly64x2_t v = CL_MUL128((poly64x2_t){u}, (poly64x2_t){poly}, 0x00);
	printf("[1/p]*p(x) = 0x1%016llX%016llX\n", v[1] ^ u ^ poly, v[0]);

}
void barrett_k(uint64_t poly, int bits)
{
	int dig = bits/4;
	uint64_t u;
	printf("P(x) = 0x1%0*llX\n", dig, poly);
	int i;
	for (i=128+64; i>0; i-=bits) {
		u = xt_mod_P(poly,i, bits);
		printf("k3 = x^(%d) mod P(x) = 0x%0*llX\n", i, dig, u);
	}

	u = barret_calc(poly,bits);
	printf("Barrett u = x^%d/P(x) U =0x1%0*llX (0x%0*llX)\n", bits*2, dig, u, dig, bit_reflect(u)<<1);
	poly64x2_t v = CL_MUL128((poly64x2_t){u|1ULL<<bits}, (poly64x2_t){poly|1ULL<<bits}, 0x00);//CL_MUL32L(ur, pr);
	printf("[1/p]*p(x) = %llX%016llX\n", v[1], v[0]);
}
void barrett_k_ref(uint64_t poly, int bits)
{
	int dig = bits/4;
	uint64_t u;
	printf("P(x) = 0x%0*llX\n", dig, poly);
	int i;
	for (i=128+64; i>0; i-=bits) {
		u = xt_mod_P_ref(poly,i, bits);
		printf("k3 = x^(%d) mod P(x) = 0x%0*llX\n", i, dig, u<<1);
	}
	u = barret_calc(bit_reflect(poly<<(64-bits)),bits);
	printf("Barrett u = x^%d/P(x)    =0x%0*llX\n", bits*2, dig, bit_reflect(u<<(63-bits)));
}
void barret_calc_ref(uint64_t poly, int bits)
{
	uint64_t u = barret_calc(bit_reflect(poly<<(64-bits)),bits);
	uint64_t ur= bits==64?bit_reflect(u):bit_reflect(u<<(63-bits))|1;
	uint64_t pr= poly<<1 | 1;
	printf("BarrettR u = x^%d/P(x) Ur=0x%0*llX Pr=0x%0*llX\n", bits*2, bits/4, ur, bits/4, pr);
	//v2du v = CL_MUL128((v2du){0x104D101DF}, (v2du){0x104C11DB7}, 0x00);//CL_MUL32L(ur, pr);
	poly64x2_t v = CL_MUL128((poly64x2_t){ur}, (poly64x2_t){pr}, 0x00);//CL_MUL32L(ur, pr);
	printf("[1/p]*p(x) = %llX%016llX\n", v[1], v[0]);
}
void barret_calc64(uint64_t poly, int bits)
{
	uint64_t p = poly<<(64-bits);
	uint64_t u = barret_calc(p,bits);
	printf("Barrett u = x^%d/P(x) Ux=0x%0*llX Px=0x1%0*llX\n", bits*2, bits/4, u, bits/4, poly);
	//v2du v = CL_MUL128((v2du){0x104D101DF}, (v2du){0x104C11DB7}, 0x00);//CL_MUL32L(ur, pr);
	poly64x2_t v = CL_MUL128((poly64x2_t){u}, (poly64x2_t){p}, 0x00) ^ (uint64x2_t){0, u ^ p};//CL_MUL32L(ur, pr);
	printf("[1/p]*p(x) = %llX%016llX\n", v[1], v[0]);
}
void barret_calc64_ref(uint64_t poly, int bits)
{
	uint64_t u = barret_calc(bit_reflect(poly<<(64-bits)),bits);
	uint64_t ur= bit_reflect(u)<<1|1;
	uint64_t pr= poly<<1 | 1;
	printf("BarrettR u = x^%d/P(x) Ur=0x%0*llX Pr=0x%0*llX\n", bits*2, bits/4, ur, bits/4, pr);
	//v2du v = CL_MUL128((v2du){0x104D101DF}, (v2du){0x104C11DB7}, 0x00);//CL_MUL32L(ur, pr);
	poly64x2_t v = CL_MUL128((poly64x2_t){ur}, (poly64x2_t){pr}, 0x00) ^ (uint64x2_t){0, ur ^ pr};//CL_MUL32L(ur, pr);
	printf("[1/p]*p(x) = %llX%016llX\n", v[1], v[0]);
}

/*! \brief генерация таблицы подстановки CRC
	\param poly полином
	\param bits число бит в полиноме
	\param size число элементов в таблице 16 или 256
 */
void crc_gen_table(uint64_t poly, int bits, int size)
{
	uint64_t table[size];// = {0};
	uint64_t p =poly;
	int i,j;
	table[0] = 0;
	table[1] = p;
	for (i=1;(1<<i)<size;i++)
	{
		if (p&(1ULL<<(bits-1))) {
			p &= ~((~0ULL)<<(bits-1));
			p = (p<<1) ^ poly;
		} else
			p = (p<<1);
		table[(1<<i)] = p;
		for(j=1; j<(1<<i); j++) {
			table[(1<<i)+j] = p ^ table[j];
		}
	}
	printf("POLY=0x%0*"PRIX64"\n", bits/4, poly);
	int align = 1<<(-bits&0x3);
	int mask = bits<=16?0x7: 0x3;
	for(i=0;i<size;i++){
		printf("0x%0*"PRIX64", ", (bits+3)/4, table[i]*align);
		if ((i&mask)==mask) printf("\n");
	}
	//printf("\n");
}
void crc_gen_inv_table(uint64_t poly, int bits)
{
	uint64_t table[16] = {0};
	uint64_t p =poly;
	int i,j;
	table[0] = 0;
	table[1] = p;
	for (i=1;(1<<i)<16;i++)
	{
		if (p&1)
			p = (p>>1) ^ poly;
		else
			p = (p>>1);

		table[(1<<i)] = p;
		for(j=1; j<(1<<i); j++) {
			table[(1<<i)+j] = p ^ table[j];
		}
	}
	printf("POLY=0x%0*"PRIX64"\n", bits/4, poly);
	for(i=0;i<16;i++){
		int ri;// reverse index 0..F
		ri = ( i&0x3)<<2 | ( i&0xC)>>2;
		ri = (ri&0x5)<<1 | (ri&0xA)>>1;
		printf("0x%0*"PRIX64", ", bits/4, table[ri]);
		if ((i&0x3)==0x3) printf("\n");
	}
	//printf("\n");
}
/* Генерирует сдвиговые константы */
void crc64b_gen(uint64_t poly, uint32_t bits)
{
	uint64_t u = barret_calc(bit_reflect(poly),64);
	uint64_t ur= bit_reflect(u)<<1|1;
	uint64_t pr= poly<<1 | 1;
//	printf("BarrettR u = x^%d/P(x) Ur=0x%0*llX Pr=0x%0*llX\n", bits*2, bits/4, ur, bits/4, pr);
	printf(".KBP = {0x%016llX, 0x%0*llX},\n", ur, bits/4+1, pr);
	uint64_t k, k1, k2;
	k1 = xt_mod_P_ref(poly, 640   -1+bits, bits);
	k2 = xt_mod_P_ref(poly, 640-64-1+bits, bits);
	printf(".KF5 = {0x%0*llX, 0x%0*llX},\n", bits/4, k1, bits/4, k2);
	k1 = xt_mod_P_ref(poly, 512   -1+bits, bits);
	k2 = xt_mod_P_ref(poly, 512-64-1+bits, bits);
	printf(".KF4 = {0x%0*llX, 0x%0*llX},\n", bits/4, k1, bits/4, k2);
	k1 = xt_mod_P_ref(poly, 384   -1+bits, bits);
	k2 = xt_mod_P_ref(poly, 384-64-1+bits, bits);
	printf(".KF3 = {0x%0*llX, 0x%0*llX},\n", bits/4, k1, bits/4, k2);
	k1 = xt_mod_P_ref(poly, 256   -1+bits, bits);
	k2 = xt_mod_P_ref(poly, 256-64-1+bits, bits);
	printf(".KF2 = {0x%0*llX, 0x%0*llX},\n", bits/4, k1, bits/4, k2);
	k1 = xt_mod_P_ref(poly, 128   -1+bits, bits);
	k2 = xt_mod_P_ref(poly, 128-64-1+bits, bits);
	printf(".K12 = {0x%0*llX, 0x%0*llX},\n", bits/4, k1, bits/4, k2);
	printf(".K34 = {\n");
	int i;
	for(i=0; i<16;i++){
		int sh1 = 8*i+bits-57;
		k = xt_mod_P_ref(poly, sh1, bits);
		printf("[%2d] = {0x%0*llX, ",(i+1) & 15, bits/4, k);
		int sh2 = 8*i+bits-64-57;
		k = xt_mod_P_ref(poly, sh2, bits);
		printf("0x%0*llX},// x^{%d}, x^{%d}\n", bits/4, k, sh1, sh2);
	}
	printf("}};\n");
}	
/* Генерирует сдвиговые константы */
void crc64_gen(uint64_t poly, uint32_t bits)
{
	uint64_t ur = barret_calc(poly<<(64-bits),64);
//	uint64_t ur= bit_reflect(u)<<1|1;
	uint64_t pr= poly;//<<1 | 1;
//	printf("BarrettR u = x^%d/P(x) Ur=0x%0*llX Pr=0x%0*llX\n", bits*2, bits/4, ur, bits/4, pr);
	printf(".KBP = {0x%016llX, 0x%016llX},\n", ur, pr<<(64-bits));
	uint64_t k, k1, k2;
		int sh1 = 128+64;
		int sh2 = 64+64;
	k1 = xt_mod_P(poly, 512   , bits);
	k2 = xt_mod_P(poly, 512+64, bits);
	printf(".KF4 = {0x%0*llX, 0x%0*llX},\n", bits/4, k1, bits/4, k2);
	k1 = xt_mod_P(poly, 384   , bits);
	k2 = xt_mod_P(poly, 384+64, bits);
	printf(".KF3 = {0x%0*llX, 0x%0*llX},\n", bits/4, k1, bits/4, k2);
	k1 = xt_mod_P(poly, 256   , bits);
	k2 = xt_mod_P(poly, 256+64, bits);
	printf(".KF2 = {0x%0*llX, 0x%0*llX},\n", bits/4, k1, bits/4, k2);
	k1 = xt_mod_P(poly, 128   , bits);
	k2 = xt_mod_P(poly, 128+64, bits);
	printf(".K12 = {0x%0*llX, 0x%0*llX},\n", bits/4, k1, bits/4, k2);
	printf(".K34 = {\n");
	int i;
	for(i=0; i<16;i++){
		int sh1 = 8*i+bits-56;
		int sh2 = 8*i+bits-64-56;
		k = xt_mod_P(poly, sh2, bits);
		printf("[%2d] = {0x%0*llX, ",(i+1) & 15, 16/* bits/4 */, k<<(64-bits));
		k = xt_mod_P(poly, sh1, bits);
		printf("0x%0*llX},// x^{%2d}, x^{%2d}\n", 16/* bits/4 */, k<<(64-bits), sh2, sh1);
	}
	printf("}};\n");
}	

#if defined(DEBUG_CRC)
int main()
{
	uint8_t data[] = 
		"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
		"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
	int i, len =96*2;
if (0) {
	uint8x16_t v16 = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
	v16 = (uint8x16_t)REFLECT((poly64x2_t)v16);
	printf("Reflect:\n");
	for (i=0; i< 16; i++){
		printf("%02X,", (uint8_t)v16[i]);
	}
	printf("\n");
}
char test[] = "123456789";
if (1) {// CRC-32
#define CRC32_POLY 0x04C11DB7
#define CRC32_INIT 0xFFFFFFFF
#define CRC32_XOUT 0xFFFFFFFF

	uint32_t crc;
	printf("CRC-32\n"); 
	crc_gen_table(CRC32_POLY, 32,16);//CRC32
	crc = CRC32_INIT;
	for(i=0; i<9; i++){
		crc = CRC32_update(crc, test[i]);
	}
	printf("Test =%0X ..%s\n", crc^CRC32_XOUT, (crc^CRC32_XOUT)==CRC32_CHECK?"ok":"fail");
	barrett_k(CRC32_POLY, 32);
	uint64_t u = barret_calc(0x04C11DB7ULL<<32, 64);
	printf("Barrett u = Ux= 0x1%016"PRIX64"\n", u);
	
	uint64_t k;
	for(i=0; i<8;i++){
		k = xt_mod_P(CRC32_POLY, 8+8*i, 32);
		printf("K7(%3d) = %08llX (N)\n",32+8+8*i, k);
	}
	for(i=0; i<8;i++){
		k = xt_mod_P(CRC32_POLY, -8*i, 32);
		printf("K8(%3d) = %08llX (N)\n",-8*i, k);
	}
crc64_gen(CRC32_POLY, 32);

	crc	= CRC32_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC32_update(crc, data[i]);
	}
	printf("CRC32 = %08X (x4)\n", crc ^ CRC32_XOUT);

	crc	= CRC32_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC32_update_8(crc, &data[i]);
	}
	printf("CRC32 = %08X (x8) \n", crc ^ CRC32_XOUT);

	crc	= CRC32_INIT;
	for (i=0; i< len; i+=2){
		crc = CRC32_update_16(crc, &data[i]);
	}
	printf("CRC32 = %08X (x16) \n", crc ^ CRC32_XOUT);

	crc	= CRC32_INIT;
	for (i=0; i< len; i+=3){
		crc = CRC32_update_24(crc, &data[i]);
	}
	printf("CRC32 = %08X (x24) \n", crc ^ CRC32_XOUT);

	crc	= CRC32_INIT;
	for (i=0; i< len; i+=4){
		crc = CRC32_update_32(crc, &data[i]);
	}
	printf("CRC32 = %08X (x32) \n", crc ^ CRC32_XOUT);

	crc	= CRC32_INIT;
	for (i=0; i< len; i+=8){
		crc = CRC32_update_64(crc, &data[i]);
	}
	printf("CRC32 = %08X (x64) \n", crc ^ CRC32_XOUT);

	crc	= CRC32_INIT;
	for (i=0; i< len; i+=12){
		crc = CRC32_update_96(crc, &data[i]);
	}
	printf("CRC32 = %08X (x96) \n", crc ^ CRC32_XOUT);

	v2du vcrc	= {0xFFFFFFFF};
	for (i=0; i< len; i+=16){
		vcrc = CRC32_update_128(vcrc, &data[i]);
	}
	printf("CRC32 = %08X (x128) \n", vcrc[0] ^ CRC32_XOUT);

	CRC64 crc64	= 0xFFFFFFFFULL<<32;
	for (i=0; i< len; i+=3){
		crc64 = CRC64_update_N(&CRC32_ctx, crc64, &data[i],3);
	}
	printf("CRC32 = %08X (xN=3) \n", (crc64>>32) ^ CRC32_XOUT);

	crc64	= 0xFFFFFFFFULL<<32;
	for (i=0; i< len; i+=8){
		crc64 = CRC64_update_N(&CRC32_ctx, crc64, &data[i],8);
	}
	printf("CRC32 = %08X (xN=8) \n", (crc64>>32) ^ CRC32_XOUT);

	crc64	= 0xFFFFFFFFULL<<32;
	for (i=0; i< len; i+=16){
		crc64 = CRC64_update_N(&CRC32_ctx, crc64, &data[i],16);
	}
	printf("CRC32 = %08X (xN=16) \n", (crc64>>32) ^ CRC32_XOUT);

	crc	= CRC32_INIT;
	for (i=0; i< len; i+=6){
		crc = CRC32_update_N(crc, &data[i],6);
	}
	printf("CRC32 = %08X (xN=6) \n", crc ^ CRC32_XOUT);

	crc	= CRC32_INIT;
	for (i=0; i< len; i+=8){
		crc = CRC32_update_N(crc, &data[i],8);
	}
	printf("CRC32 = %08X (xN=8) \n", crc ^ CRC32_XOUT);

	crc	= CRC32_INIT;
	for (i=0; i< len; i+=12){
		crc = CRC32_update_N(crc, &data[i],12);
	}
	printf("CRC32 = %08X (xN=12) \n", crc ^ CRC32_XOUT);

	crc	= CRC32_INIT;
	for (i=0; i< len; i+=16){
		crc = CRC32_update_N(crc, &data[i],16);
	}
	printf("CRC32 = %08X (xN=16) \n", crc ^ CRC32_XOUT);
	uint64_t ts;
	ts = __builtin_ia32_rdtsc();
	crc	= CRC32_INIT;
	crc = CRC32_update_N(crc, data, len);
	ts-= __builtin_ia32_rdtsc();
	printf("CRC32 = %08X (xN) %"PRId64" clk\n", crc ^ CRC32_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc64	= 0xFFFFFFFFULL<<32;
	crc64 = CRC64_update_N(&CRC32_ctx, crc64, data,len);
	ts-= __builtin_ia32_rdtsc();
	printf("CRC32 = %08X (xN) %"PRId64" clk\n", (crc64>>32) ^ CRC32_XOUT, -ts);




	int n;
	for (n=1; n<len; n++) {
		crc = 0xFFFFFFFF;
		for(i=0; i<n; i+=1){
			crc = CRC32_update(crc, data[i]);
		}
		uint32_t crc32;
		crc32 = 0xFFFFFFFF;
		crc32 = CRC32_update_N(crc32, &data[0], n);

		if (crc32!=crc) printf("CRC32 = fail %08"PRIX32" (%d)\n", crc ^ 0xFFFFFFFF, n);
	}
	printf("CRC32 done\n\n");
	for (n=1; n<len; n++) {
		crc = 0xFFFFFFFF;
		for(i=0; i<n; i+=1){
			crc = CRC32_update(crc, data[i]);
		}
		crc64	= 0xFFFFFFFFULL<<32;
		crc64 = CRC64_update_N(&CRC32_ctx, crc64, data,n);

		if ((crc64>>32)!=crc) printf("CRC32 = fail %08"PRIX32" (%d)\n", crc ^ 0xFFFFFFFF, n);
	}
	printf("CRC32 done\n\n");
/*
	for (n=1; n<len; n++) {
		crc = 0xFFFFFFFF;
		for(i=0; i<n; i+=1){
			crc = CRC32_update(crc, data[i]);
		}
		uint32_t crc32;
		crc32 = 0xFFFFFFFF;
		crc32 = CRC32_update_N_(crc32, &data[0], n);

		if (crc32!=crc) printf("CRC32 = fail %08"PRIX32" (%d)\n", crc ^ 0xFFFFFFFF, n);
	}
	printf("CRC32 done\n\n");
*/
	
}
if (1) {// CRC-32B
	uint32_t crc;
	#define CRC32B_INIT 0xFFFFFFFF
	#define CRC32B_XOUT 0xFFFFFFFF
	printf("CRC-32B %08llX\n", bit_reflect(0x04C11DB7ULL<<32));
	crc_gen_inv_table(bit_reflect(0x04C11DB7ULL<<32), 32);//CRC32/ZIP
	barret_calc_ref(bit_reflect(0x04C11DB7ULL<<32), 32);
	barret_calc64_ref(bit_reflect(0x04C11DB7ULL<<32), 64);
	uint64_t k;
	k = xt_mod_P_ref(0x1DB710641>>1, 32-1, 32);//bit_reflect(0x04C11DB7ULL<<32), 32, 32);
	printf("K7( 31) = %08llX (%08llX)\n", k, bit_reflect(k<<32));
	k = xt_mod_P_ref(0x1DB710641>>1, 64-1, 32);
	printf("K6( 63) = %08llX (%08llX)\n", k, bit_reflect(k<<32));
	k = xt_mod_P_ref(0x1DB710641>>1, 96-1, 32);
	printf("K5( 95) = %08llX (%08llX)\n", k, bit_reflect(k<<32));
	k = xt_mod_P_ref(0x1DB710641>>1,128-1, 32);
	printf("K4(127) = %08llX (%08llX)\n", k, bit_reflect(k<<32));
	k = xt_mod_P_ref(0x1DB710641>>1,160-1, 32);
	printf("K4(159) = %08llX (%08llX)\n", k, bit_reflect(k<<32));
	k = xt_mod_P_ref(0x1DB710641>>1,192-1, 32);
	printf("K3(191) = %08llX (%08llX)\n", k, bit_reflect(k<<32));
	k = xt_mod_P_ref(0x1DB710641>>1,256-32-1, 32);
	printf("K3(223) = %08llX (%08llX)\n", k, bit_reflect(k<<32));
	k = xt_mod_P_ref(0x1DB710641>>1,256+32-1, 32);
	printf("K3(287) = %08llX (%08llX)\n", k, bit_reflect(k<<32));
	k = xt_mod_P_ref(0x1DB710641>>1,384-32-1, 32);
	printf("K3(351) = %08llX (%08llX)\n", k, bit_reflect(k<<32));
	k = xt_mod_P_ref(0x1DB710641>>1,384+32-1, 32);
	printf("K3(415) = %08llX (%08llX)\n", k, bit_reflect(k<<32));
	k = xt_mod_P_ref(0x1DB710641>>1,512-32-1, 32);
	printf("K3(479) = %08llX (%08llX)\n", k, bit_reflect(k<<32));
	k = xt_mod_P_ref(0x1DB710641>>1,512+32-1, 32);
	printf("K3(543) = %08llX (%08llX)\n", k, bit_reflect(k<<32));


	crc64b_gen(0x1DB710641>>1, 32);

	//barrett_k_ref(bit_reflect(0x04C11DB7ULL<<32), 32);
	crc = ~0UL;
	for(i=0; i<9; i++){
		crc = CRC32B_update(crc, test[i]);
	}
	printf("Test =%0X ..%s\n", crc^~0UL, (crc^~0UL)==CRC32B_CHECK?"ok":"fail");

	crc	= 0xFFFFFFFF;
	for (i=0; i< len; i+=1){
		crc = CRC32B_update(crc, data[i]);
	}
	printf("CRC32B = %08X (x4)\n", crc ^ 0xFFFFFFFF);

	crc	= 0xFFFFFFFF;
	for (i=0; i< len; i+=1){
		crc = CRC32B_update_8(crc, &data[i]);
	}
	printf("CRC32B = %08X (x8) \n", crc ^ 0xFFFFFFFF);

	crc	= 0xFFFFFFFF;
	for (i=0; i< len; i+=2){
		crc = CRC32B_update_16(crc, &data[i]);
	}
	printf("CRC32B = %08X (x16) \n", crc ^ 0xFFFFFFFF);

	crc	= 0xFFFFFFFF;
	for (i=0; i< len; i+=3){
		crc = CRC32B_update_24(crc, &data[i]);
	}
	printf("CRC32B = %08X (x24) \n", crc ^ 0xFFFFFFFF);
/*
	crc	= 0xFFFFFFFF;
	for (i=0; i< len; i+=3){
		crc = CRC32B_update_bits(crc, &data[i], 24);
	}
	printf("CRC32B = %08X (x24 bits) \n", crc ^ 0xFFFFFFFF);
*/
	crc	= 0xFFFFFFFF;
	for (i=0; i< len; i+=4){
		crc = CRC32B_update_32(crc, &data[i]);
	}
	printf("CRC32B = %08X (x32) \n", crc ^ 0xFFFFFFFF);
/*
	crc	= 0xFFFFFFFF;
	for (i=0; i< len; i+=4){
		crc = CRC32B_update_bits(crc, &data[i], 32);
	}
	printf("CRC32B = %08X (x32 bits) \n", crc ^ 0xFFFFFFFF);
*/
	crc	= 0xFFFFFFFF;
	for (i=0; i< len; i+=8)
		crc = CRC32B_update_64(crc, &data[i]);
	printf("CRC32B = %08X (x64) \n", crc ^ 0xFFFFFFFF);
	crc	= 0xFFFFFFFF;
	for (i=0; i< len; i+=16)
		crc = CRC32B_update_128(crc, &data[i]);
	printf("CRC32B = %08X (x128) \n", crc ^ 0xFFFFFFFF);
	crc	= 0xFFFFFFFF;
	crc = CRC32B_update_N(crc, &data[0], len);
	printf("CRC32B = %08X (xN=len) \n", crc ^ 0xFFFFFFFF);

	uint64_t ts;
	ts = __builtin_ia32_rdtsc();
	crc	= CRC32B_INIT;
	crc = CRC64B_update_N(&CRC32B_ctx, crc, &data[0], len);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32B = %08X (xN) %"PRId64" clk\n", crc ^ CRC32B_XOUT, -ts);
	ts = __builtin_ia32_rdtsc();
	crc	= CRC32B_INIT;
	crc = CRC64B_update_N(&CRC32B_ctx, crc, &data[0], len);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32B = %08X (xN) %"PRId64" clk\n", crc ^ CRC32B_XOUT, -ts);

}
if (1) {// CRC-32C
	#define CRC32C_INIT 0xFFFFFFFF
	#define CRC32C_XOUT 0xFFFFFFFF
//	barrett_k_ref(bit_reflect(0x04C11DB7ULL<<32), 32);
	printf("CRC-32C (Castagnoli)\n");
	crc_gen_inv_table(bit_reflect(0x1EDC6F41ULL<<32), 32);//CRC32C
	barret_calc_ref(bit_reflect(0x1EDC6F41ULL<<32), 32);
	barret_calc64_ref(bit_reflect(0x1EDC6F41ULL<<32), 64);
	uint32_t crc;
	crc = ~0UL;
	for(i=0; i<9; i++){
		crc = CRC32C_update(crc, test[i]);
	}
	printf("Test =%0X ..%s\n", crc^~0UL, (crc^~0UL)==CRC32C_CHECK?"ok":"fail");
	uint64_t k;
	//k = xt_mod_P_ref(bit_reflect(0x1EDC6F41ULL<<32), 32, 32);
	k = xt_mod_P_ref(0x105EC76F1>>1, 32-1, 32);
	printf("K7( 31) = %08llX (N)\n", k);
	k = xt_mod_P_ref(0x105EC76F1>>1, 64-1, 32);
	printf("K6( 63) = %08llX (N)\n", k);
	k = xt_mod_P_ref(0x105EC76F1>>1, 96-1, 32);
	printf("K5( 95) = %08llX (N)\n", k);
	k = xt_mod_P_ref(0x105EC76F1>>1,128-1, 32);
	printf("K4(127) = %08llX (N)\n", k);
	k = xt_mod_P_ref(0x105EC76F1>>1,160-1, 32);
	printf("K4(159) = %08llX (N)\n", k);
	k = xt_mod_P_ref(0x105EC76F1>>1,192-1, 32);
	printf("K3(191) = %08llX (N)\n", k);
	k = xt_mod_P_ref(0x105EC76F1>>1,224-1, 32);
	printf("K3(223) = %08llX (N)\n", k);
	
	crc64b_gen(0x105EC76F1>>1, 32);
	uint64_t ts;

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32C_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC32C_update(crc, data[i]);
	}
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32C = %08X (x4) %"PRId64" clk\n", crc ^ CRC32C_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32C_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC32C_update_8(crc, &data[i]);
	}
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32C = %08X (x8) %"PRId64" clk\n", crc ^ CRC32C_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32C_INIT;
	for (i=0; i< len; i+=2){
		crc = CRC32C_update_16(crc, &data[i]);
	}
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32C = %08X (x16) %"PRId64" clk\n", crc ^ CRC32C_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32C_INIT;
	for (i=0; i< len; i+=3){
		crc = CRC32C_update_24(crc, &data[i]);
	}
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32C = %08X (x24) %"PRId64" clk\n", crc ^ CRC32C_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32C_INIT;
	for (i=0; i< len; i+=4){
		crc = CRC32C_update_32(crc, &data[i]);
	}
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32C = %08X (x32) %"PRId64" clk\n", crc ^ CRC32C_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32C_INIT;
	for (i=0; i< len; i+=8){
		crc = CRC32C_update_64(crc, &data[i]);
	}
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32C = %08X (x64) %"PRId64" clk\n", crc ^ CRC32C_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32C_INIT;
	for (i=0; i< len; i+=16)
		crc = CRC32C_update_128(crc, &data[i]);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32C = %08X (x128) %"PRId64" clk\n", crc ^ CRC32C_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32C_INIT;
	crc = CRC32C_update_N(crc, &data[0], len);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32C = %08X (xN) %"PRId64" clk\n", crc ^ CRC32C_XOUT, -ts);
	
	ts = __builtin_ia32_rdtsc();
	crc	= CRC32C_INIT;
	crc = CRC64B_update_N(&CRC32C_ctx, crc, &data[0], len);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32C = %08X (xN) %"PRId64" clk\n", crc ^ CRC32C_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32C_INIT;
	crc = CRC64B_update_N(&CRC32C_ctx, crc, &data[0], len);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32C = %08X (xN) %"PRId64" clk\n", crc ^ CRC32C_XOUT, -ts);
	
	int n;
	for (n=1; n<len; n++) {
		crc = CRC32C_INIT;
		for(i=0; i<n; i+=1){
			crc = CRC32C_update(crc, data[i]);
		}
		uint32_t crc1;
		crc1 = CRC32C_INIT;
		crc1 = CRC64B_update_N(&CRC32C_ctx, crc1, &data[0], n);

		if (crc1!=crc) printf("CRC32C = fail %04"PRIX32" (%d)\n", crc ^ CRC32C_XOUT, n);
	}
	printf("CRC-32C = ok\n\n");

}
if (1) {// CRC-32K/Koopman

	printf("CRC-32K/BACnet (Koopman)\n"); 
	crc_gen_inv_table(bit_reflect(0x741B8CD7ULL<<32),32);
	barret_calc_ref(bit_reflect(0x741B8CD7ULL<<32), 32);
	barret_calc64_ref(bit_reflect(0x741B8CD7ULL<<32), 64);
	#define CRC32K_CHECK 0x2D3DD0AE
	#define CRC32K_INIT 0xFFFFFFFF
	#define CRC32K_XOUT 0xFFFFFFFF
	uint32_t crc;
	crc = ~0UL;
	for(i=0; i<9; i++){
		crc = CRC32K_update(crc, test[i]);
	}
	printf("Test =%0X ..%s\n", crc^~0UL, (crc^~0UL)==CRC32K_CHECK?"ok":"fail");
	uint64_t k;
	k = xt_mod_P_ref(0x1D663B05D>>1, 32-1, 32);
	printf("K7( 32) = %08llX (N)\n", k);
	k = xt_mod_P_ref(0x1D663B05D>>1, 64-1, 32);
	printf("K6( 64) = %08llX (N)\n", k);
	k = xt_mod_P_ref(0x1D663B05D>>1, 96-1, 32);
	printf("K5( 96) = %08llX (N)\n", k);
	k = xt_mod_P_ref(0x1D663B05D>>1,128-1, 32);
	printf("K4(128) = %08llX (N)\n", k);
	k = xt_mod_P_ref(0x1D663B05D>>1,160-1, 32);
	printf("K3(160-1) = %08llX (N)\n", k);
	k = xt_mod_P_ref(0x1D663B05D>>1,192-1, 32);
	printf("K3(192) = %08llX (N)\n", k);
	k = xt_mod_P_ref(0x1D663B05D>>1,224-1, 32);
	printf("K3(224-1) = %08llX (N)\n", k);
	k = xt_mod_P_ref(0x1D663B05D>>1,256-1, 32);
	printf("K3(256-1) = %08llX (N)\n", k);

	crc64b_gen(0x1D663B05D>>1, 32);
	uint64_t ts;

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32K_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC32K_update(crc, data[i]);
	}
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32K = %08X (x4) %"PRId64" clk\n", crc ^ CRC32K_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32K_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC32K_update_8(crc, &data[i]);
	}
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32К = %08X (x8) %"PRId64" clk\n", crc ^ CRC32K_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32K_INIT;
	for (i=0; i< len; i+=2){
		crc = CRC32K_update_16(crc, &data[i]);
	}
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32К = %08X (x16) %"PRId64" clk\n", crc ^ CRC32K_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32K_INIT;
	for (i=0; i< len; i+=3){
		crc = CRC32K_update_24(crc, &data[i]);
	}
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32К = %08X (x24) %"PRId64" clk\n", crc ^ CRC32K_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32K_INIT;
	for (i=0; i< len; i+=4){
		crc = CRC32K_update_32(crc, &data[i]);
	}
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32К = %08X (x32) %"PRId64" clk\n", crc ^ CRC32K_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32K_INIT;
	for (i=0; i< len; i+=8)
		crc = CRC32K_update_64(crc, &data[i]);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32К = %08X (x64) %"PRId64" clk\n", crc ^ CRC32K_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32K_INIT;
	for (i=0; i< len; i+=16)
		crc = CRC32K_update_128(crc, &data[i]);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32К = %08X (x128) %"PRId64" clk\n", crc ^ CRC32K_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32K_INIT;
	for (i=0; i< len; i+=4)
		crc = CRC32K_update_N(crc, &data[i], 4);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32К = %08X (xN=32) %"PRId64" clk\n", crc ^ CRC32K_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32K_INIT;
	for (i=0; i< len; i+=6)
		crc = CRC32K_update_N(crc, &data[i], 6);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32К = %08X (xN=48) %"PRId64" clk\n", crc ^ CRC32K_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32K_INIT;
	for (i=0; i< len; i+=8)
		crc = CRC32K_update_N(crc, &data[i], 8);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32К = %08X (xN=64) %"PRId64" clk\n", crc ^ CRC32K_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32K_INIT;
	for (i=0; i< len; i+=12)
		crc = CRC32K_update_N(crc, &data[i], 12);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32К = %08X (xN=96) %"PRId64" clk\n", crc ^ CRC32K_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32K_INIT;
	for (i=0; i< len; i+=16)
		crc = CRC32K_update_N(crc, &data[i], 16);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32К = %08X (xN=128) %"PRId64" clk\n", crc ^ CRC32K_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32K_INIT;
	crc = CRC32K_update_N(crc, &data[0], len);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32К = %08X (xN) %"PRId64" clk\n", crc ^ CRC32K_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC32K_INIT;
	crc = CRC64B_update_N(&CRC32K_ctx, crc, &data[0], len);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32K = %08X (xN) %"PRId64" clk\n", crc ^ CRC32K_XOUT, -ts);
	ts = __builtin_ia32_rdtsc();
	crc	= CRC32K_INIT;
	crc = CRC64B_update_N(&CRC32K_ctx, crc, &data[0], len);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC32K = %08X (xN) %"PRId64" clk\n", crc ^ CRC32K_XOUT, -ts);
	
	int n;
	for (n=1; n<len; n++) {
		crc = CRC32K_INIT;
		for(i=0; i<n; i+=1){
			crc = CRC32K_update(crc, data[i]);
		}
		uint32_t crc1;
		crc1 = CRC32K_INIT;
		crc1 = CRC64B_update_N(&CRC32K_ctx, crc1, &data[0], n);

		if (crc1!=crc) printf("CRC32K = fail %04"PRIX32" (%d)\n", crc ^ CRC32K_XOUT, n);
	}
	printf("CRC-32K = ok\n\n");

}
if (1) {// CRC-24/OpenPGP
	printf("CRC-24/OpenPGP\n"); 
	crc_gen_table(CRC24_POLY, 24,16);//CRC32
	CRC32 crc24 = CRC24_INIT;
	for(i=0; i<9; i++){
		crc24 = CRC24_update(crc24, test[i]);
	}
	printf("Test =%0X ..%s\n", crc24, (crc24)==CRC24_CHECK?"ok":"fail");
	barrett_k(CRC24_POLY, 24);


crc64_gen(CRC24_POLY, 24);
	uint32_t crc;
	crc	= CRC24_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC24_update(crc, data[i]);
	}
	printf("CRC-24 = %08X (x4)\n", crc);

	crc	= CRC24_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC24_update_8(crc, &data[i]);
	}
	printf("CRC-24 = %08X (x8) \n", crc);

	crc	= CRC24_INIT;
	for (i=0; i< len; i+=2){
		crc = CRC24_update_16(crc, &data[i]);
	}
	printf("CRC-24 = %08X (x16) \n", crc);

	crc	= CRC24_INIT;
	for (i=0; i< len; i+=3){
		crc = CRC24_update_24(crc, &data[i]);
	}
	printf("CRC-24 = %08X (x24) \n", crc);

	crc	= CRC24_INIT;
	for (i=0; i< len; i+=4){
		crc = CRC24_update_32(crc, &data[i]);
	}
	printf("CRC-24 = %08X (x32) \n", crc);

	crc	= CRC24_INIT;
	for (i=0; i< len; i+=6){
		crc = CRC24_update_48(crc, &data[i]);
	}
	printf("CRC-24 = %08X (x48) \n", crc);

	crc	= CRC24_INIT;
	for (i=0; i< len; i+=8){
		crc = CRC24_update_64(crc, &data[i]);
	}
	printf("CRC-24 = %08X (x64) \n", crc);

	crc	= CRC24_INIT;
	for (i=0; i< len; i+=12){
		crc = CRC24_update_96(crc, &data[i]);
	}
	printf("CRC-24 = %08X (x96) \n", crc);

	crc	= CRC24_INIT;
	for (i=0; i< len; i+=16){
		crc = CRC24_update_128(crc, &data[i]);
	}
	printf("CRC-24 = %08X (x128) \n", crc);

	crc	= CRC24_INIT;
	for (i=0; i< len; i+=6){
		crc = CRC24_update_N(crc, &data[i], 6);
	}
	printf("CRC-24 = %08X (xN=6) \n", crc);

	crc	= CRC24_INIT;
	for (i=0; i< len; i+=8){
		crc = CRC24_update_N(crc, &data[i], 8);
	}
	printf("CRC-24 = %08X (xN=8) \n", crc);

	crc	= CRC24_INIT;
	for (i=0; i< len; i+=12){
		crc = CRC24_update_N(crc, &data[i], 12);
	}
	printf("CRC-24 = %08X (xN=12) \n", crc);

	crc	= CRC24_INIT;
	for (i=0; i< len; i+=16){
		crc = CRC24_update_N(crc, &data[i], 16);
	}
	printf("CRC-24 = %08X (xN=16) \n", crc);

	crc	= CRC24_INIT;
	crc = CRC24_update_N(crc, data, len);
	printf("CRC-24 = %08X (xN=len) \n", crc);

uint64_t ts;
CRC64 crc64;
//	crc64	= (uint64_t)CRC24_INIT<<(40);
//	crc64 = CRC64_update_N(&CRC24_ctx, crc64, data,len);

	ts = __builtin_ia32_rdtsc();
	crc64	= (uint64_t)CRC24_INIT<<(40);
	crc64 = CRC64_update_N(&CRC24_ctx, crc64, data,len);
	ts-= __builtin_ia32_rdtsc();
	printf("CRC-24 = %08X (xN) %"PRId64" clk\n", (crc64>>40), -ts);
	
	int n;
	for (n=1; n<len; n++) {
		crc = CRC24_INIT;
		for(i=0; i<n; i+=1){
			crc = CRC24_update(crc, data[i]);
		}
		crc64	= (uint64_t)CRC24_INIT<<40;
		crc64 = CRC64_update_N(&CRC24_ctx, crc64, data,n);

		if ((crc64>>40)!=crc) printf("CRC-24 = fail %04"PRIX32" (%d)\n", crc, n);
	}
	printf("CRC-24 done\n\n");

}
if (0) {// CRC-16/MODBUS poly=0x8005 init=0xffff refin=true refout=true xorout=0x0000 check=0x4b37
#define CRC16M_INIT 0xFFFF
#define CRC16M_POLY 0x8005
#define CRC16M_XOUT 0x0000
#define CRC16M_CHECK 0x4b37
	printf("CRC-16/MODBUS\n");
	crc_gen_inv_table(bit_reflect(0x8005ULL<<48),16);

	uint32_t crc;
	crc = CRC16M_INIT;
	for(i=0; i<9; i++){
		crc = CRC16M_update(crc, test[i]);
	}	
	printf("Check =%04X ..%s\n", crc^CRC16M_XOUT, (crc^CRC16M_XOUT)==CRC16M_CHECK?"ok":"fail");
	barret_calc_ref(0xA001ULL, 16);
	barret_calc64_ref(0xA001ULL, 64);

	uint64_t k;
	k = xt_mod_P_ref(0xA001ULL, 16-1, 16);
	printf("K7( 15) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0xA001ULL, 32-1, 16);
	printf("K6( 31) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0xA001ULL, 48-1, 16);
	printf("K5( 47) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0xA001ULL, 64-1, 16);
	printf("K4( 63) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0xA001ULL, 80-1, 16);
	printf("K3( 79) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0xA001ULL, 96-1, 16);
	printf("K3( 95) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0xA001ULL,112-1, 16);
	printf("K3(111) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0xA001ULL,128-1, 16);
	printf("K3(127) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0xA001ULL,144-1, 16);
	printf("K3(143) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0xA001ULL,160-1, 16);
	printf("K3(159) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0xA001ULL,176-1, 16);
	printf("K3(175) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0xA001ULL,192-1, 16);
	printf("K3(191) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0xA001ULL,208-1, 16);
	printf("K3(207) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0xA001ULL,240-1, 16);
	printf("K3(239) = %04llX (N)\n", k);

	crc64b_gen(0xA001ULL, 16);

	crc	= CRC16M_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC16M_update(crc, data[i]);
	}
	printf("CRC16M = %04X\n", crc^CRC16M_XOUT);

	crc	= CRC16M_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC16M_update_8(crc, &data[i]);
	}
	printf("CRC16M = %04X (x8)\n", crc^CRC16M_XOUT);

	crc	= CRC16M_INIT;
	for (i=0; i< len; i+=2){
		crc = CRC16M_update_16(crc, &data[i]);
	}
	printf("CRC16M = %04X (x16)\n", crc^CRC16M_XOUT);

	crc	= CRC16M_INIT;
	for (i=0; i< len; i+=4){
		crc = CRC16M_update_32(crc, &data[i]);
	}
	printf("CRC16M = %04X (x32)\n", crc^CRC16M_XOUT);
	
	crc	= CRC16M_INIT;
	for (i=0; i< len; i+=8){
		crc = CRC16M_update_64(crc, &data[i]);
	}
	printf("CRC16M = %04X (x64)\n", crc^CRC16M_XOUT);

	crc	= CRC16M_INIT;
	crc = CRC16M_update_N(crc, &data[0], len);
	printf("CRC16M = %04X (xN)\n", crc^CRC16M_XOUT);

	int n;
	for (n=1; n<len; n++) {
		crc = CRC16M_INIT;
		for(i=0; i<n; i+=1){
			crc = CRC16M_update(crc, data[i]);
		}
		uint32_t crc1;
		crc1 = CRC16M_INIT;
		crc1 = CRC64B_update_N(&CRC16M_ctx, crc1, &data[0], n);

		if (crc1!=crc) printf("CRC16M = fail %04"PRIX32" (%d)\n", crc ^ CRC16M_XOUT, n);
	}
	printf("CRC-16M = ok\n\n");
	
	
}
if (0) {// poly=0x1021 init=0xffff refin=true refout=true xorout=0xffff check=0x906e
#define CRC16B_INIT 0xFFFF
#define CRC16B_POLY 0x1021
#define CRC16B_XOUT 0xFFFF
#define CRC16B_CHECK 0x906e
	printf("CRC-16/X-25 BACnet\n");
	crc_gen_inv_table(bit_reflect(0x1021ULL<<48),16);

	uint32_t crc;
	crc = CRC16B_INIT;
	for(i=0; i<9; i++){
		crc = CRC16B_update(crc, test[i]);
	}	
	printf("Check =%04X ..%s\n", crc^CRC16B_XOUT, (crc^CRC16B_XOUT)==CRC16B_CHECK?"ok":"fail");
	barret_calc_ref(0x8408ULL, 16);
	barret_calc64_ref(0x8408ULL, 64);

	uint64_t k;
	k = xt_mod_P_ref(0x8408ULL, 16-1, 16);
	printf("K7( 15) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0x8408ULL, 32-1, 16);
	printf("K6( 31) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0x8408ULL, 48-1, 16);
	printf("K5( 47) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0x8408ULL, 64-1, 16);
	printf("K4( 63) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0x8408ULL, 80-1, 16);
	printf("K3( 79) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0x8408ULL, 96-1, 16);
	printf("K3( 95) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0x8408ULL,112-1, 16);
	printf("K3(111) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0x8408ULL,128-1, 16);
	printf("K3(127) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0x8408ULL,144-1, 16);
	printf("K3(143) = %04llX (N)\n", k);
	k = xt_mod_P_ref(0x8408ULL,192-1, 16);
	printf("K3(191) = %04llX (N)\n", k);

	for(i=0; i<16;i++){
		int sh1 = 8*i+15-56;
		k = xt_mod_P_ref(0x8408ULL, sh1, 16);
		printf("[%2d] = {0x%04llX, ",(i+1) & 15, k);
		int sh2 = 8*i+15-64-56;
		k = xt_mod_P_ref(0x8408ULL, sh2, 16);
		printf("0x%04llX},// x^{%d}, x^{%d}\n", k, sh1, sh2);
	}
	uint64_t ts;

	ts = __builtin_ia32_rdtsc();
	crc	= CRC16B_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC16B_update(crc, data[i]);
	}
	ts-= __builtin_ia32_rdtsc();
	printf("CRC16B = %04X %"PRId64" clk\n", crc^CRC16B_XOUT, -ts);
/*
	crc	= CRC16B_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC16B_update_8(crc, &data[i]);
	}
	printf("CRC16M = %04X (x8)\n", crc^CRC16B_XOUT);
*/
	ts = __builtin_ia32_rdtsc();
	crc	= CRC16B_INIT;
	crc = CRC64B_update_N(&CRC16B_ctx, crc, &data[0], len);
	ts-= __builtin_ia32_rdtsc();
	printf("CRC16B = %04X (xN) %"PRId64" clk\n", crc^CRC16B_XOUT, -ts);
	
	int n;
	for (n=1; n<len; n++) {
		crc = CRC16B_INIT;
		for(i=0; i<n; i+=1){
			crc = CRC16B_update(crc, data[i]);
		}
		uint32_t crc1;
		crc1 = CRC16B_INIT;
		crc1 = CRC64B_update_N(&CRC16B_ctx, crc1, &data[0], n);

		if (crc1!=crc) printf("CRC16B = fail %04"PRIX32" (%d)\n", crc ^ CRC16B_XOUT, n);
	}
	printf("CRC-16B = ok\n\n");
	
}
if (0) {// CRC-16
	printf("CRC-16\n");
#define CRC16_INIT 0xFFFF
#define CRC16_POLY 0x1021
#define CRC16_XOUT 0xFFFF
#define CRC16_CHECK 0xd64e
	crc_gen_table(CRC16_POLY, 16,16);//CRC32
	uint32_t crc;
	crc = CRC16_INIT;
	for(i=0; i<9; i++){
		crc = CRC16_update(crc, test[i]);
	}	
	printf("Check =%04X ..%s\n", crc^CRC16_XOUT, (crc^CRC16_XOUT)==CRC16_CHECK?"ok":"fail");
	barrett_k(CRC16_POLY, 16);
	uint64_t k;
	k = xt_mod_P(CRC16_POLY, 16,16);
	printf("K^{%d} = %04llX\n", 16, k);
	k = xt_mod_P(CRC16_POLY, 16+16,16);
	printf("K^{%d} = %04llX\n", 16, k);
	k = xt_mod_P_neg(CRC16_POLY, 8,16);
	printf("K^{-%d} = %04llX\n", 8, k);
	k = xt_mod_P_neg(CRC16_POLY,16,16);
	printf("K^{-%d} = %04llX\n",16, k);
crc64_gen(CRC16_POLY, 16);
	uint64_t ts;

	ts = __builtin_ia32_rdtsc();
	crc	= CRC16_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC16_update(crc, data[i]);
	}
	ts-= __builtin_ia32_rdtsc();
	printf("CRC16 = %04X %"PRId64" clk\n", crc ^ CRC16_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC16_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC16_update1(crc, data[i]);
	}
	ts-= __builtin_ia32_rdtsc();
	printf("CRC16 = %04X %"PRId64" clk\n", crc ^ CRC16_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC16_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC16_update_(crc, data[i]);
//			crc = CRC16_update_8(crc, &data[i]);
	}
	ts-= __builtin_ia32_rdtsc();
	printf("CRC16 = %04X %"PRId64" clk\n", crc ^ CRC16_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC16_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC16_update_8(crc, &data[i]);
	}
	ts-= __builtin_ia32_rdtsc();
	printf("CRC16 = %04X (x8) %"PRId64" clk\n", crc ^ CRC16_XOUT, -ts);

		crc	= CRC16_INIT;
		for (i=0; i< len; i+=2){
			crc = CRC16_update_16(crc, &data[i]);
		}
		printf("CRC16 = %04X (x16)\n", crc ^ CRC16_XOUT);
#if 1
		crc	= CRC16_INIT;
		for (i=0; i< len; i+=3){
			crc = CRC16_update_24(crc, &data[i]);
		}
		printf("CRC16 = %04X (x24)\n", crc ^ CRC16_XOUT);
#endif
		crc	= CRC16_INIT;
		for (i=0; i< len; i+=4){
			crc = CRC16_update_32(crc, &data[i]);
		}
		printf("CRC16 = %04X (x32)\n", crc ^ CRC16_XOUT);

		crc = CRC16_INIT;
		crc = CRC16_update_N(crc, data, len);
		printf("CRC16 = %04X (N)\n", crc ^ CRC16_XOUT);

		crc = CRC16_INIT;
		crc = CRC16_update_64(crc, data, len);
		printf("CRC16 = %04X (xN)\n", crc ^ CRC16_XOUT);

	CRC64 crc64;
	ts = __builtin_ia32_rdtsc();
	crc64	= (uint64_t)CRC16_INIT<<(48);
	crc64 = CRC64_update_N(&CRC16_ctx, crc64, data,len);
	ts-= __builtin_ia32_rdtsc();
	printf("CRC16 = %04X (xN) %"PRId64" clk\n", (crc64>>48)^CRC16_XOUT, -ts);

	int n;
	for (n=1; n<len; n++) {
		crc = CRC16_INIT;
		for(i=0; i<n; i+=1){
			crc = CRC16_update(crc, data[i]);
		}
		crc64	= (uint64_t)CRC16_INIT<<48;
		crc64 = CRC64_update_N(&CRC16_ctx, crc64, data,n);

		if ((crc64>>48)!=crc) printf("CRC-16 = fail %04"PRIX32" (%d)\n", crc^CRC16_XOUT, n);
	}
	printf("CRC16 done\n\n");

}



// расчет коэффициентов для CRC
//	barrett_k(0x04C11DB70000001ULL, 64);
//	barrett_k(0x04C11DB700000000ULL, 64);
	printf("CRC-32\n");
	uint64_t k;
	k = xt_mod_P(0x04C11DB7, 32, 32);
	printf("K6( 64) = %08llX (N)\n", k);
	k = xt_mod_P(0x04C11DB7, 64, 32);
	printf("K5( 96) = %08llX (N)\n", k);
	k = xt_mod_P(0x04C11DB7, 96, 32);
	printf("K4(128) = %08llX (N)\n", k);
	k = xt_mod_P(0x04C11DB7, 160, 32);
	printf("K3(192) = %08llX (N)\n", k);
	k = xt_mod_P(0x04C11DB7, 480, 32);
	printf("K2(512) = %08llX (N)\n", k);
	k = xt_mod_P(0x04C11DB7, 544, 32);
	printf("K1(576) = %08llX (N)\n", k);

//	barrett_k(0x04C11DB7, 32);
//	printf("CRC32C %08llX\n", bit_reflect(0x1EDC6F41ULL<<32));
//	barrett_k(0x82F63B78, 32);
//	printf("CRC32K\n");
//	barrett_k(0xEB31D82E, 32);
//	barrett_k(0x1021000000000000ULL, 64);
//	barrett_k(0x1021, 16);
//	barrett_k(0x1021ULL<<48, 64);
//	barrett_k(0x8005, 16);
//	barrett_k(0xA001, 16);
//	barrett_k(0x81,8);
//	barrett_k(0xC3,8);
//	barrett_k(0xC300000000000000ULL,64);
// расчет таблиц

if (0) {// GF2m-64
//	printf("GF2m-64\n"); crc_gen_table(0x1BULL, 64, 16);
//	printf("GF2m-128\n"); crc_gen_table(0x87ULL, 16, 16);
	
	barrett_k64(0x1BULL, 64);
	printf("CRC-64/GO-ISO\n");
	crc_gen_inv_table(bit_reflect(0x1BULL), 64);

	CRC64 crc64 = ~0ULL;
	for(i=0; i<9; i++){
		crc64 = CRC64GO_update(crc64, test[i]);
	}
	printf("Test =%0llX ..%s\n", crc64^~0ULL, (crc64^~0ULL)==CRC64GO_CHECK?"ok":"fail");

}
if (1) {// CRC-64/XZ
	printf("CRC-64/XZ\n"); crc_gen_inv_table(bit_reflect(0x42F0E1EBA9EA3693ULL), 64);
	CRC64 crc64 = ~0ULL;
	for(i=0; i<9; i++){
		crc64 = CRC64XZ_update(crc64, test[i]);
	}
	printf("Test =%0llX ..%s\n", crc64^~0ULL, (crc64^~0ULL)==CRC64XZ_CHECK?"ok":"fail");
	barret_calc64_ref(0xC96C5795D7870F42ULL, 64);
	uint64_t k;
	k = xt_mod_P_ref(0xC96C5795D7870F42ULL, 64-1, 64);
	printf("K5( 63) = %016llX \n", k);
	k = xt_mod_P_ref(0xC96C5795D7870F42ULL,128-1, 64);
	printf("K4(127) = %016llX \n", k);
	k = xt_mod_P_ref(0xC96C5795D7870F42ULL,192-1, 64);
	printf("K3(191) = %016llX \n", k);
	k = xt_mod_P_ref(0xC96C5795D7870F42ULL,256-1, 64);
	printf("F2(255) = %016llX \n", k);
	k = xt_mod_P_ref(0xC96C5795D7870F42ULL,320-1, 64);
	printf("F2(319) = %016llX \n", k);

	for(i=0; i<16;i++){
		k = xt_mod_P_ref(0xC96C5795D7870F42ULL, 8*i+7, 64);
		printf("[%2d] = {0x%016llXULL, ",(i+1) & 15, k);
		k = xt_mod_P_ref(0xC96C5795D7870F42ULL, 8*i+7-64, 64);
		printf("0x%016llXULL},// x^{%d}, x^{%d}\n", k, 8*i+7, 8*i+7-64);
	}

	
	len=96;
	crc64 = ~0ULL;
	for(i=0; i<len; i++){
		crc64 = CRC64XZ_update(crc64, data[i]);
	}
	printf("CRC64XZ = %016"PRIX64"\n", crc64 ^ ~0ULL);

	crc64 = ~0ULL;
	for(i=0; i<len; i+=8){
		crc64 = CRC64XZ_update_64(crc64, &data[i]);
	}
	printf("CRC64XZ = %016"PRIX64" (x64)\n", crc64 ^ ~0ULL);
	
	crc64 = ~0ULL;
	for(i=0; i<len; i+=16){
		crc64 = CRC64XZ_update_128(crc64, &data[i]);
	}
	printf("CRC64XZ = %016"PRIX64" (x128)\n", crc64 ^ ~0ULL);

	crc64 = ~0ULL;
	crc64 = CRC64XZ_update_N(crc64, &data[0], len);
	printf("CRC64XZ = %016"PRIX64" (xN)\n", crc64 ^ ~0ULL);

	int n;
	for (n=1; n<len; n++) {
		crc64 = ~0ULL;
		for(i=0; i<n; i+=1){
			crc64 = CRC64XZ_update(crc64, data[i]);
		}
		uint64_t crc641;
		crc641 = ~0ULL;
		crc641 = CRC64XZ_update_N(/*&CRC64XZ_ctx, */crc641, &data[0], n);

		if (crc641!=crc64) printf("CRC64/XZ = fail %016"PRIX64" (%d)\n", crc64 ^ ~0ULL, n);
	}
	printf("CRC64XZ = ok\n\n");


}
if (1) {// CRC-64/WE
	printf("CRC-64/WE\n"); crc_gen_table(0x42F0E1EBA9EA3693ULL, 64,16);//CRC32
	CRC64 crc64 = ~0ULL;
	for(i=0; i<9; i++){
		crc64 = CRC64WE_update(crc64, test[i]);
	}
	printf("Test =%0llX ..%s\n", crc64^~0ULL, (crc64^~0ULL)==CRC64WE_CHECK?"ok":"fail");

	barrett_k64((0x42F0E1EBA9EA3693ULL), 64);
	uint64_t k;
	k = xt_mod_P(0x42F0E1EBA9EA3693ULL, 64, 64);
	printf("K4(128) = %016llX (N)\n", k);
	k = xt_mod_P(0x42F0E1EBA9EA3693ULL, 128, 64);
	printf("K4(192) = %016llX (N)\n", k);


	for(i=0; i<16;i++){
		k = xt_mod_P(0x42F0E1EBA9EA3693ULL, 8*i+8-64, 64);
		printf("[%2d] = {0x%016llXULL, ",(i+1) & 15, k);
		k = xt_mod_P(0x42F0E1EBA9EA3693ULL, 8*i+8, 64);
		printf("0x%016llXULL},// x^{%d}, x^{%d}\n", k, 8*i+8-64, 8*i+8);
	}

	
	len=96;
	crc64 = ~0ULL;
	for(i=0; i<len; i++){
		crc64 = CRC64WE_update(crc64, data[i]);
	}
	printf("CRC64/WE = %016"PRIX64"\n", crc64 ^ ~0ULL);
	crc64 = ~0ULL;
	for(i=0; i<len; i+=1){
		crc64 = CRC64WE_update_8(crc64, &data[i]);
	}
	printf("CRC64/WE = %016"PRIX64" (x8)\n", crc64 ^ ~0ULL);

	crc64 = ~0ULL;
	for(i=0; i<len; i+=2){
		crc64 = CRC64WE_update_16(crc64, &data[i]);
	}
	printf("CRC64/WE = %016"PRIX64" (x16)\n", crc64 ^ ~0ULL);

	crc64 = ~0ULL;
	for(i=0; i<len; i+=6){
		crc64 = CRC64WE_update_48(crc64, &data[i]);
	}
	printf("CRC64/WE = %016"PRIX64" (x48)\n", crc64 ^ ~0ULL);

	crc64 = ~0ULL;
	for(i=0; i<len; i+=8){
		crc64 = CRC64WE_update_64(crc64, &data[i]);
	}
	printf("CRC64/WE = %016"PRIX64" (x64)\n", crc64 ^ ~0ULL);

	crc64 = ~0ULL;
	for(i=0; i<len; i+=16){
		crc64 = CRC64WE_update_128(crc64, &data[i]);
	}
	printf("CRC64/WE = %016"PRIX64" (x128)\n", crc64 ^ ~0ULL);

	crc64 = ~0ULL;
	crc64 = CRC64WE_update_N(crc64, &data[0], len);
	printf("CRC64/WE = %016"PRIX64" (xN)\n", crc64 ^ ~0ULL);

	int n;
	for (n=1; n<len; n++) {
		crc64 = ~0ULL;
		for(i=0; i<n; i+=1){
			crc64 = CRC64WE_update(crc64, data[i]);
		}
		uint64_t crc641;
		crc641 = ~0ULL;
		crc641 = CRC64WE_update_N(crc641, &data[0], n);

		if (crc641!=crc64) printf("CRC64/WE = fail %016"PRIX64" (%d)\n", crc64 ^ ~0ULL, n);
	}
	printf("CRC64/WE = ok\n\n");

}
if (0) {// CRC-24/OpenPGP
	printf("CRC-24/OpenPGP\n"); 
	crc_gen_table(0x864CFB, 24,16);//CRC32
	CRC32 crc24 = 0xB704CE;
	for(i=0; i<9; i++){
		crc24 = CRC24_update(crc24, test[i]);
	}
	printf("Test =%0X ..%s\n", crc24, (crc24)==CRC24_CHECK?"ok":"fail");
	barrett_k(0x864CFB, 24);
	uint64_t k;
	k = xt_mod_P(0x864CFB, 64-24, 24);
    printf("K6( 64) = %08llX\n", k);
	k = xt_mod_P(0x864CFB, 64, 24);
    printf("K6( 88) = %08llX\n", k);
	k = xt_mod_P(0x864CFB, 64+24, 24);
    printf("K6(112) = %08llX\n", k);
//	uint64_t u = barret_calc(0x864CFB,24);
//	printf("Barrett u = x^%d/P(x) U =0x1%0*llX\n", 48, 6, u);
}
if (0) {// CRC-8_I/CODE 
	printf("CRC-8/I-CODE\n");//  poly=0x1d init=0xfd refin=false refout=false xorout=0x00 check=0x7e
#define CRC8I_INIT 0xFD
#define CRC8I_POLY 0x1D
#define CRC8I_XOUT 0x00
#define CRC8I_CHECK 0x7E
	crc_gen_table(CRC8I_POLY, 8,16);//CRC32
	uint32_t crc;
	crc = CRC8I_INIT;
	for(i=0; i<9; i++){
		crc = CRC8I_update(crc, test[i]);
	}	
	printf("Check =%0X ..%s\n", crc^CRC8I_XOUT, (crc^CRC8I_XOUT)==CRC8I_CHECK?"ok":"fail");
	barrett_k(CRC8I_POLY, 8);

	uint64_t ts;
	ts = __builtin_ia32_rdtsc();
	crc	= CRC8I_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC8I_update(crc, data[i]);
	}
	ts-= __builtin_ia32_rdtsc();
	printf("CRC8I = %02X  %"PRId64" clk\n", crc ^ CRC8I_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC8I_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC8I_update_8(crc, data[i]);
	}
	ts-= __builtin_ia32_rdtsc();
	printf("CRC8I = %02X (x8) %"PRId64" clk\n", crc ^ CRC8I_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC8I_INIT;
	for (i=0; i< len; i+=2){
		crc = CRC8I_update_16(crc, &data[i]);
	}
	ts-= __builtin_ia32_rdtsc();
	printf("CRC8I = %02X (x16) %"PRId64" clk\n", crc ^ CRC8I_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC8I_INIT;
	for (i=0; i< len; i+=4){
		crc = CRC8I_update_32(crc, &data[i]);
	}
	ts-= __builtin_ia32_rdtsc();
	printf("CRC8I = %02X (x32) %"PRId64" clk\n", crc ^ CRC8I_XOUT, -ts);

	crc	= CRC8I_INIT;
	for (i=0; i< len; i+=8){
		crc = CRC8I_update_64(crc, &data[i]);
	}
	printf("CRC8I = %02X (x64)\n", crc ^ CRC8I_XOUT);

	ts = __builtin_ia32_rdtsc();

	crc	= CRC8I_INIT;
	crc = CRC8I_update_128(crc, &data[0], len);
	ts-= __builtin_ia32_rdtsc();
	printf("CRC8I = %02X (xN) %"PRId64" clk\n", crc ^ CRC8I_XOUT, -ts);

}
if (0) {// CRC-8/BAC
	printf("CRC-8/BAC\n");//  poly=0x81 init=0xff refin=true refout=true xorout=0xff check=0x89
#define CRC8B_INIT 0xFF
#define CRC8B_POLY 0x81
#define CRC8B_XOUT 0xFF
#define CRC8B_CHECK 0x89
	crc_gen_inv_table(CRC8B_POLY, 8);//CRC32
	uint32_t crc;
	crc = CRC8B_INIT;
	for(i=0; i<9; i++){
		crc = CRC8B_update(crc, test[i]);
	}
	printf("Check =%0X ..%s\n", crc^CRC8B_XOUT, (crc^CRC8B_XOUT)==CRC8B_CHECK?"ok":"fail");
    barret_calc_ref(CRC8B_POLY, 8);
    barret_calc64_ref(CRC8B_POLY, 64);
	uint64_t k, g;
	k = xt_mod_P_ref(0x81, 8-1, 8); //g = gmul_mod_P_ref(k, 0xFF, 0x81, 8);
	printf("K7( 7) = %02llX \n", k);
	k = xt_mod_P_ref(0x81, 16-1, 8);
	printf("K6(15) = %02llX (N)\n", k);
	k = xt_mod_P_ref(0x81, 24-1, 8);
	printf("K6(23) = %02llX (N)\n", k);
	k = xt_mod_P_ref(0x81, 32-1, 8);
	printf("K6(31) = %02llX (N)\n", k);
	k = xt_mod_P_ref(0x81, 40-1, 8);
	printf("K6(39) = %02llX (N)\n", k);
	k = xt_mod_P_ref(0x81, 48-1, 8);
	printf("K6(47) = %02llX (N)\n", k);
	k = xt_mod_P_ref(0x81, 56-1, 8);
	printf("K6(55) = %02llX (N)\n", k);
	k = xt_mod_P_ref(0x81, 64-1, 8);
	printf("K6(63) = %02llX (N)\n", k);
	k = xt_mod_P_ref(0x81, 72-1, 8);
	printf("K6(71) = %02llX (N)\n", k);
	k = xt_mod_P_ref(0x81, 136-1, 8);
	printf("K6(135) = %02llX (N)\n", k);

	for(i=0; i<16;i++){
		int sh1 = 8*i+8-56-1;
		k = xt_mod_P_ref(0x81, sh1, 8);
		printf("[%2d] = {0x%02llX, ",(i+1) & 15, k);
		int sh2 = 8*i+8-64-56-1;
		k = xt_mod_P_ref(0x81, sh2, 8);
		printf("0x%02llX},// x^{%d}, x^{%d}\n", k, sh1, sh2);
	}
	uint64_t ts;
	ts = __builtin_ia32_rdtsc();
	crc	= CRC8B_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC8B_update(crc, data[i]);
	}
	ts -= __builtin_ia32_rdtsc();
	printf("CRC8B = %02X  %"PRId64" clk\n", crc ^ CRC8B_XOUT, -ts);

	crc	= CRC8B_INIT;
	ts = __builtin_ia32_rdtsc();
	for (i=0; i< len; i+=1){
		crc = CRC8B_update_8(crc, data[i]);
	}
	ts -= __builtin_ia32_rdtsc();
	printf("CRC8B = %02X (x8) %"PRId64" clk\n", crc ^ CRC8B_XOUT, -ts);

	crc	= CRC8B_INIT;
	ts = __builtin_ia32_rdtsc();
	for (i=0; i< len; i+=4){
		crc = CRC8B_update_32(crc, &data[i]);
	}
	ts -= __builtin_ia32_rdtsc();
	printf("CRC8B = %02X (x32) %"PRId64" clk\n", crc ^ CRC8B_XOUT, -ts);
	
	crc	= CRC8B_INIT;
	ts = __builtin_ia32_rdtsc();
	for (i=0; i< len; i+=8){
		uint64_t val = *(uint64_t*)&data[i];
		crc = CRC8B_update_64(crc, val);
	}
	ts -= __builtin_ia32_rdtsc();
	printf("CRC8B = %02X (x64) %"PRId64" clk\n", crc ^ CRC8B_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC8B_INIT;
	for (i=0; i< len; i+=16){
		crc = CRC8B_update_128(crc, &data[i]);
	}
	ts -= __builtin_ia32_rdtsc();
	printf("CRC8B = %02X (x128) %"PRId64" clk\n", crc ^ CRC8B_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC8B_INIT;
	crc = CRC8B_update_N(crc, &data[0], len);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC8B = %02X (xN) %"PRId64" clk\n", crc ^ CRC8B_XOUT, -ts);

	ts = __builtin_ia32_rdtsc();
	crc	= CRC8B_INIT;
	crc = CRC64B_update_N(&CRC8B_ctx, crc, &data[0], len);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC8B = %02X (xN) %"PRId64" clk\n", crc ^ CRC8B_XOUT, -ts);

	
	int n;
	uint64_t clocks=0;
	for (n=1; n<len; n++) {
		crc = CRC8B_INIT;
		for(i=0; i<n; i+=1){
			crc = CRC8B_update(crc, data[i]);
		}
		uint32_t crc1;
		crc1 = CRC8B_INIT;
		crc1 = CRC64B_update_N(&CRC8B_ctx, crc1, &data[0], n);
		if (crc1!=crc) printf("CRC8B = fail %02"PRIX32" (%d)\n", crc ^ CRC8B_XOUT, n);
	}
	printf("CRC8B = ok\n\n");

	
}
if (0) {// CRC-8/SMBus
	printf("CRC-8/SMBus\n");//  poly=0x07 init=0x00 refin=false refout=false xorout=0x00 check=0xf4
#define CRC8_INIT 0x00
#define CRC8_POLY 0x07
#define CRC8_XOUT 0x00
#define CRC8_CHECK 0xF4
	crc_gen_table(CRC8_POLY, 8,16);//CRC32

crc64_gen(CRC8_POLY, 8);

	uint32_t crc;
	crc = CRC8_INIT;
	for(i=0; i<9; i++){
		crc = CRC8_update(crc, test[i]);
	}	
	printf("Check =%0X ..%s\n", crc^CRC8_XOUT, (crc^CRC8_XOUT)==CRC8_CHECK?"ok":"fail");
	barrett_k(CRC8_POLY, 8);



	crc = CRC8_INIT;
	crc = CRC8_update_128(crc, &test[0], 9);
	printf("Check =%0X (x128) ..%s\n", crc^CRC8_XOUT, (crc^CRC8_XOUT)==CRC8_CHECK?"ok":"fail");
uint64_t ts;
	ts = __builtin_ia32_rdtsc();
	crc	= CRC8_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC8_update(crc, data[i]);
	}
	ts-= __builtin_ia32_rdtsc();
	printf("CRC8 = %02X %"PRId64" clk\n", crc ^ CRC8_XOUT, -ts);

	crc	= CRC8_INIT;
	for (i=0; i< len; i+=1){
		crc = CRC8_update_8(crc, data[i]);
	}
	printf("CRC8 = %02X (x8)\n", crc ^ CRC8_XOUT);

	crc	= CRC8_INIT;
	for (i=0; i< len; i+=2){
		crc = CRC8_update_16(crc, &data[i]);
	}
	printf("CRC8 = %02X (x16)\n", crc ^ CRC8_XOUT);

	crc	= CRC8_INIT;
	for (i=0; i< len; i+=3){
		crc = CRC8_update_24(crc, &data[i]);
	}
	printf("CRC8 = %02X (x24)\n", crc ^ CRC8_XOUT);

	crc	= CRC8_INIT;
	for (i=0; i< len; i+=4){
		crc = CRC8_update_32(crc, &data[i]);
	}
	printf("CRC8 = %02X (x32)\n", crc ^ CRC8_XOUT);

	crc	= CRC8_INIT;
	for (i=0; i< len; i+=8){
		crc = CRC8_update_64(crc, &data[i]);
	}
	printf("CRC8 = %02X (x64)\n", crc ^ CRC8_XOUT);

	crc	= CRC8_INIT;
	for (i=0; i< len; i+=12){
		crc = CRC8_update_128(crc, &data[i], 12);
	}
	printf("CRC8 = %02X (x96)\n", crc ^ CRC8_XOUT);

	crc	= CRC8_INIT;
	for (i=0; i< len; i+=16){
		crc = CRC8_update_128(crc, &data[i], 16);
	}
	printf("CRC8 = %02X (x128)\n", crc ^ CRC8_XOUT);

	crc	= CRC8_INIT;
	crc = CRC8_update_128(crc, &data[0], len);
	printf("CRC8 = %02X (xN)\n", crc ^ CRC8_XOUT);

CRC64 crc64;
	ts = __builtin_ia32_rdtsc();
	crc64 = (uint64_t)CRC8_INIT<<(64-8);
	crc64 = CRC64_update_N(&CRC8_ctx, crc64, &data[0], len);
	ts -= __builtin_ia32_rdtsc();
	printf("CRC8 = %02X (xN) %"PRId64" clk\n", (crc64>>(64-8)) ^ CRC8_XOUT, -ts);

	
	int n;
	uint64_t clocks=0;
	for (n=1; n<len; n++) {
		crc = CRC8_INIT;
		for(i=0; i<n; i+=1){
			crc = CRC8_update(crc, data[i]);
		}
		crc64 = (uint64_t)CRC8_INIT<<(64-8);
		crc64 = CRC64_update_N(&CRC8_ctx, crc64, &data[0], n);
		if (crc64>>(64-8)!=crc) printf("CRC8 = fail %02"PRIX32" (%d)\n", crc ^ CRC8B_XOUT, n);
	}
	printf("CRC8 = ok\n\n");


}


//	printf("Modbus\n"); crc_gen_inv_table(0xA001,16);//modbus
//	printf("CRC-16/X-25 BACnet\n"); crc_gen_inv_table(bit_reflect(0x1021ULL<<48),16);
	//printf("CRC-8 BACnet: "); crc_gen_inv_table(0x81,8);
	// операция умножения без переноса для Кузнечика
//	gfmul8_C3()
	uint64_t u;
	printf("AES GF(2^8)\n");
	u = barret_calc(0x11B, 8);
	crc_gen_table(0x1B, 8,16);
	printf("Barrett u = x^%d/P(x) U =0x1%0*llX P =0x11B\n", 8, 2, u);
	u = barret_calc(0x11D, 8);
	crc_gen_table(0x1D, 8,16);
	printf("Barrett u = x^%d/P(x) U =0x1%0*llX P =0x11D\n", 8, 2, u);
	u = barret_calc(0x12B, 8);
	printf("Barrett u = x^%d/P(x) U =0x1%0*llX P =0x12B\n", 8, 2, u);
	u = barret_calc(0x12D, 8);
	printf("Barrett u = x^%d/P(x) U =0x1%0*llX P =0x12D\n", 8, 2, u);
	u = barret_calc(0x165, 8);
//	crc_gen_table(0x65, 8,16);
	u = barret_calc(0x171, 8);
	printf("Barrett u = x^%d/P(x) U =0x1%0*llX P =0x171\n", 8, 2, u);
	u = barret_calc(0x187, 8);
	printf("Barrett u = x^%d/P(x) U =0x1%0*llX P =0x187\n", 8, 2, u);
	u = barret_calc(0x18D, 8);
	printf("Barrett u = x^%d/P(x) U =0x1%0*llX P =0x18D\n", 8, 2, u);
	u = barret_calc(0x1C3, 8);
	crc_gen_table(0xC3, 8,16);
	printf("Barrett u = x^%d/P(x) U =0x1%0*llX P =0x1C3\n", 8, 2, u);
	u = barret_calc(0x1CF, 8);
	printf("Barrett u = x^%d/P(x) U =0x1%0*llX P =0x1CF\n", 8, 2, u);
	u = barret_calc(0x1E7, 8);
	printf("Barrett u = x^%d/P(x) U =0x1%0*llX P =0x1E7\n", 8, 2, u);
	u = barret_calc(0x1F5, 8);
	printf("Barrett u = x^%d/P(x) U =0x1%0*llX P =0x1F5\n", 8, 2, u);
	
	printf("GF2m-64\n");
	uint64_t a, b, r, r_, r2;
	a = 0x0102030405060708ULL;
	b = 0x010ULL;
 	r = gfmul64(a, b);
	r_= gfmul64_(a, b);
	r2= gfmul64_2(a, b);
	printf("r: 0x%016"PRIX64" %s %s\n", r, r==r_? "ok":"fail", r==r2? "ok":"fail");
	b = 0x011ULL;
	r = gfmul64(a, b);
	r_= gfmul64_(a, b);
	r2= gfmul64_2(a, b);
	printf("r: 0x%016"PRIX64" %s %s\n", r, r==r_? "ok":"fail", r==r2? "ok":"fail");
	b = 0xFEDCBA9876543210ULL;
	r = gfmul64(a, b);
	r_= gfmul64_(a, b);
	r2= gfmul64_2(a, b);
	printf("r: 0x%016"PRIX64" %s %s\n", r, r==r_? "ok":"fail", r==r2? "ok":"fail");
	r2 = GF64_mulm(a,b);
	printf("r: 0x%016"PRIX64" %s \n", r, r==r2? "ok":"fail");
	
	a = 0xFEDCBA9876543210ULL;
	r = gfmul64(a, b);
	r_= gfmul64_(a, b);
	r2= gfmul64_2(a, b);
	printf("r: 0x%016"PRIX64" %s %s\n", r, r==r_? "ok":"fail", r==r2? "ok":"fail");
	r2 = GF64_mulm(a,b);
	printf("r: 0x%016"PRIX64" %s \n", r, r==r2? "ok":"fail");
	if (1) {//GF(2m) Reflect P(x) = x64 + x4 + x3 + x + 1
		uint64_t a,b,c,r;
		a = 0x0102030405060708ULL;
		b = 0xFEDCBA9876543210ULL;
		c = 0xE49212E923C485BBULL;
		r = REFLECT64(gfmul64(REFLECT64(a), REFLECT64(b)));
		printf("GF(2m) Reflect P(x) = x64 + x4 + x3 + x + 1\n");
		//crc_gen_inv_table(bit_reflect(0x1BULL), 64);// POLY=0xD800000000000000
		crc_gen_inv_table(0xD8, 8);
		
		
		printf("r: 0x%016"PRIX64" %s\n", r, r==c? "ok":"fail");
		r = gfmul64r(a, b);
		printf("r: 0x%016"PRIX64" %s\n", r, r==c? "ok":"fail");
		r = gfmul64r_(a, b);
		printf("r: 0x%016"PRIX64" %s\n", r, r==c? "ok":"fail");
	}
	if (1) {
/*  GFMUL128 (a, b) is the multiplication results of a and b, in GF(2^128) 
	defined by the reduction polynomial g = g(x) = x128 + x7 + x2 + x + 1)
*/
		poly64x2_t a = {0x63746f725d53475dULL, 0x7b5b546573745665ULL};
		poly64x2_t b = {0x5b477565726f6e5dULL, 0x4869285368617929ULL};
		poly64x2_t c = {0x7e4e10da323506d2ULL, 0x040229a09a5ed12eULL};
		poly64x2_t r,r_;
		r = gfmul128(a,b);
		r_= gfmul128_(a,b);
		printf("GF(2m) P(x) = 128 + x7 + x2 + x + 1\n");
		printf("a: 0x%016"PRIX64"%016"PRIX64"\n", a[1], a[0]); 
		printf("b: 0x%016"PRIX64"%016"PRIX64"\n", b[1], b[0]); 
		printf("r: 0x%016"PRIX64"%016"PRIX64" %s\n", r[1], r[0], 
			(c[0]==r[0] && c[1]==r[1])? "ok":"fail");
		printf("r: 0x%016"PRIX64"%016"PRIX64" %s\n", r_[1], r_[0], 
			(c[0]==r_[0] && c[1]==r_[1])? "ok":"fail");
		int i;
		if (1) for(i=0; i< 0x10000; i++){
//			r0= REFLECT(gfmul128(REFLECT(a),REFLECT(b)));
			r = gfmul128(a,b);
			r_= gfmul128_(a,b);
			if (!(r[0]==r_[0] && r[1]==r_[1])){
				printf("r%04X: 0x%016"PRIX64"%016"PRIX64" %s\n",i, r[1], r[0], 
					(r[0]==r_[0] && r[1]==r_[1])? "ok":"fail");
				break;
			}
			//if (i&1)a = r;
			//else 
				b = r;
		}
	}
	if (1) {
		poly64x2_t a = {0xb32b6656a05b40b6ULL, 0x952b2a56a5604ac0ULL};
		poly64x2_t b = {0xffcaff95f830f061ULL, 0xdfa6bf4ded81db03ULL};
		poly64x2_t c = {0x4fc4802cc3feda60ULL, 0xda53eb0ad2c55bb6ULL};
		poly64x2_t r0,r,r_;
		printf("GF(2m) Reflect(A)*Reflect(B) P(x) = x128 + x7 + x2 + x + 1\n");
		r0= REFLECT(gfmul128(REFLECT(a),REFLECT(b)));
		r = gfmul128r(a,b);
		r_= gfmul128r_(a,b);
		printf("a: 0x%016"PRIX64"%016"PRIX64"\n", a[1], a[0]); 
		printf("b: 0x%016"PRIX64"%016"PRIX64"\n", b[1], b[0]); 
		printf("r: 0x%016"PRIX64"%016"PRIX64" %s\n", r0[1], r0[0], 
			(c[0]==r0[0] && c[1]==r0[1])? "ok":"fail");
		printf("r: 0x%016"PRIX64"%016"PRIX64" %s\n", r[1], r[0], 
			(c[0]==r[0] && c[1]==r[1])? "ok":"fail");
		printf("r: 0x%016"PRIX64"%016"PRIX64" %s\n", r_[1], r_[0], 
			(c[0]==r_[0] && c[1]==r_[1])? "ok":"fail");
		int i;
		if (1) for(i=0; i< 0x10000; i++){
			r0= REFLECT(gfmul128(REFLECT(a),REFLECT(b)));
			r = gfmul128r(a,b);
			r_= gfmul128r_(a,b);
			if (!(r0[0]==r[0] && r0[1]==r[1]) || !(r0[0]==r_[0] && r0[1]==r_[1])) {
				printf("r%04X: 0x%016"PRIX64"%016"PRIX64" %s %s\n",i, r0[1], r0[0], 
					(r0[0]==r[0] && r0[1]==r[1])? "ok":"fail", 
					(r0[0]==r_[0] && r0[1]==r_[1])? "ok":"fail");

				break;
			}
			if (i&1)a = r;
			else b = r;
		}
	}
	if(0) {// CRC-8/SMBUS
		printf("CRC-8/SMBUS\n");
		#define CRC8S_POLY 0x07
		#define CRC8S_INIT 0x0
		#define CRC8S_XOUT 0x0
		#define CRC8S_CHECK 0xf4
		crc_gen_table(CRC8S_POLY, 8, 256);
		uint32_t crc;
		crc = CRC8S_INIT;
		for(i=0; i<9; i++){
			crc = CRC8S_update(crc, test[i]);
		}	
		printf("Check =%0X ..%s\n", crc^CRC8S_XOUT, (crc^CRC8S_XOUT)==CRC8S_CHECK?"ok":"fail");
	}
	if(1) {// CRC-8/SENSIRION
		printf("CRC-8/SENS\n");
		#define CRC8SN_POLY 0x31
		#define CRC8SN_INIT 0xFF
		#define CRC8SN_XOUT 0x00
		#define CRC8SN_CHECK 0xF7
		crc_gen_table(CRC8SN_POLY, 8, 256);
		uint32_t crc;
		crc = CRC8SN_INIT;
		for(i=0; i<9; i++){
			crc = CRC8SN_update(crc, test[i]);
		}	
		printf("Check =%0X ..%s\n", crc^CRC8SN_XOUT, (crc^CRC8SN_XOUT)==CRC8SN_CHECK?"ok":"fail");
	}
	if(0) {// CRC-15/CAN
		printf("CRC-15/CAN\n");
		#define CRC15_POLY 0x4599
		#define CRC15_INIT 0x0
		#define CRC15_XOUT 0x0
		#define CRC15_CHECK 0x059e
		crc_gen_table(CRC15_POLY, 15, 16);
		uint32_t crc;
		crc = CRC15_INIT;
		for(i=0; i<9; i++){
			crc = CRC15_update(crc, test[i]);
		}	
		printf("Check =%0X ..%s\n", crc^CRC15_XOUT, (crc^CRC15_XOUT)==CRC15_CHECK?"ok":"fail");
		crc = CRC15_INIT;
		for(i=0; i<9; i++){
			crc = CRC15_update8(crc, test[i]);
		}	
		printf("Check =%0X ..%s\n", crc^CRC15_XOUT, (crc^CRC15_XOUT)==CRC15_CHECK?"ok":"fail");
	}
	if(0) {// CRC-5/USB
		printf("CRC-5/USB = x5 + x2 + 1\n");
/* CRC-5/USB
    width=5 poly=0x05 init=0x1f refin=true refout=true xorout=0x1f check=0x19 name="CRC-5/USB"
	*/
		crc_gen_inv_table(bit_reflect(0x05ULL<<(64-5)), 5);

		#define CRC5B_INIT 0x1F
		#define CRC5B_XOUT 0x1F
		#define CRC5B_CHECK 0x19
		uint32_t crc;
		crc = CRC5B_INIT;
		for(i=0; i<9; i++){
			crc = CRC5B_update(crc, test[i]);
		}	
		printf("Check =%0X ..%s\n", crc^CRC5B_XOUT, (crc^CRC5B_XOUT)==CRC5B_CHECK?"ok":"fail");
	
	
	
		//crc_gen_table(0x15, 5,16);
	}
	if(1) {// CRC-5/BITMAIN
		printf("CRC-5/BITMAIN = x5 + x2 + 1\n");
/* CRC-5/BITMAIN
    width=5 poly=0x05 init=0x1f refin=false refout=false xorout=0x00 check=0x0f name="CRC-5/BITMAIN"
	*/
		crc_gen_table(0x05, 5, 16);
// barrett_k(0x5<<3, 8);
//crc64_gen(CRC8_POLY, 8);

		#define CRC5_INIT 0x1F
		#define CRC5_XOUT 0
		#define CRC5_CHECK 0x0F
		uint32_t crc;
		crc = CRC5_INIT;
		for(i=0; i<9; i++){
			crc = CRC5_update(crc, test[i]);
		}	
		printf("Check =%0X ..%s\n", crc^CRC5_XOUT, (crc^CRC5_XOUT)==CRC5_CHECK?"ok":"fail");
		crc = CRC5_INIT;
		for(i=0; i<9; i++){
			crc = CRC5_update8(crc, test[i]);
		}	
		printf("Check =%0X ..%s\n", crc^CRC5_XOUT, (crc^CRC5_XOUT)==CRC5_CHECK?"ok":"fail");
		crc = CRC5_INIT;
		crc = CRC5_update_len(test, 9*8);
		printf("Check =%0X ..%s\n", crc^CRC5_XOUT, (crc^CRC5_XOUT)==CRC5_CHECK?"ok":"fail");
		crc = CRC5_BITMAIN(test, 9*8);
		printf("Check =%0X\n", crc);

		uint32_t crc5;
		int i;
		for (i=0; i<9*8; i++) {
			crc = CRC5_BITMAIN(test, i);
			crc5 = CRC5_update_len(test, i);
			if (crc!= crc5) break;
//			printf("Check =%02X %02X\n", crc, crc5);
		}
		if (crc!=crc5) printf("%d:Check =%02X %02X\n", i, crc, crc5);
		else printf("...ok\n");
		//crc_gen_table(0x15, 5,16);
	}
	return 0;
}
#endif
