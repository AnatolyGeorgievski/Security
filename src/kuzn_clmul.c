/*! \file kuzn_clmul.c
	Copyright(c) 2019-2022 Anatoly Georgievskii <anatoly.georgievski@gmail.com>
	
	Для некоммерческого использования. Если планируете использовать в коммерческом проекте, 
	поделитесь финансированием. 
	
	[RFC9058](https://www.rfc-editor.org/rfc/rfc9058.html) Multilinear Galois Mode (MGM), June 2021
	
$ gcc -O3 -march=native -o kuzn kuzn_clmul.c
$ arm-eabi-gcc -march=armv7-a -mthumb -mtune=cortex-a7 -mfpu=neon-vfpv4 -mfloat-abi=hard -O3 -S -o - kuzn_clmul.c | less
//
	cortex-a7 архитектура armv7-a + neon +SIMDv2 +VFPv4-D32
	cortex-a8 архитектура armv7-a + neon +SIMD 	+VFPv3-D32
	cortex-a9 архитектура armv7-a + neon +SIMD 	+VFPv3-D32

	\see the Cortex-A7 MPCore Floating-Point Unit Technical Reference Manual and Cortex-A7 MPCore NEON Media Processing Engine Technical Reference Manual, for implementation-specific information
	Если Neon не представлен то надо расчитывать на VFPv4-D16, всего в Cortex-A7 NEON MPE S32+D32+Q16 регистра
	* 8 or 16-bit polynomial computation 
	* SIMD 8, 16, 32, and 64-bit signed and unsigned integer computation

$(CROSS)-gcc -march=armv7-a+simd -mthumb -mtune=cortex-a7 -mfpu=neon-vfpv4 -mfloat-abi=hard

	\see the ARM® Cortex®-A9 NEON™ Media Processing Engine Technical Reference Manual

$(CROSS)-gcc -march=armv7-a+simd -mthumb -mtune=cortex-a8 -mfpu=neon-vfpv3 -mfloat-abi=hard

__builtin_ia32_vpclmulqdq_v4di
__builtin_ia32_vpclmulqdq_v8di

*/
#define Karatsuba 1
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
/*! 4.1.1 Нелинейное биективное преобразование */
static uint8_t sbox[] = {
252, 238, 221,  17, 207, 110,  49,  22, 251, 196, 250, 218,  35, 197,   4,  77, 
233, 119, 240, 219, 147,  46, 153, 186,  23,  54, 241, 187,  20, 205,  95, 193, 
249,  24, 101,  90, 226,  92, 239,  33, 129,  28,  60,  66, 139,   1, 142,  79,
  5, 132,   2, 174, 227, 106, 143, 160,   6,  11, 237, 152, 127, 212, 211,  31, 
235,  52,  44,  81, 234, 200,  72, 171, 242,  42, 104, 162, 253,  58, 206, 204,
181, 112,  14,  86,   8,  12, 118,  18, 191, 114,  19,  71, 156,
183,  93, 135,  21, 161, 150,  41,  16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178,
177,  50, 117,  25,  61, 255,  53, 138, 126, 109,  84, 198, 128, 195, 189,  13,  87, 223,
245,  36, 169,  62, 168,  67, 201, 215, 121, 214, 246, 124,  34, 185,   3, 224,  15, 236,
222, 122, 148, 176, 188, 220, 232,  40,  80,  78,  51,  10,  74, 167, 151,  96, 115,  30, 0,
 98,  68,  26, 184,  56, 130, 100, 159,  38,  65, 173,  69,  70, 146,  39,  94,  85,  47, 140, 163,
165, 125, 105, 213, 149,  59,   7,  88, 179,  64, 134, 172,  29, 247,  48,  55, 107, 228, 136,
217, 231, 137, 225,  27, 131,  73,  76,  63, 248, 254, 141,  83, 170, 144, 202, 216, 133,
 97,  32, 113, 103, 164,  45,  43,   9,  91, 203, 155,  37, 208, 190, 229, 108,  82,  89, 166,
116, 210, 230, 244, 180, 192, 209, 102, 175, 194,  57,  75,  99, 182
};


#ifdef __ARM_NEON
#include <arm_neon.h>
/* транспонированная матрица преобразования L = LM*A */
static const poly8x16_t LMT[16] = {
{0x01,	0x94,	0x84,	0xdd,	0x10,	0xbd,	0x27,	0x5d,	0xb8,	0x7a,	0x48,	0x6c,	0x72,	0x76,	0xa2,	0x6e},
{0x94,	0xa5,	0x64,	0x0d,	0x89,	0xa2,	0x7f,	0x4b,	0x6e,	0x16,	0xc3,	0x4c,	0xe8,	0xe3,	0xd0,	0x4d},
{0x20,	0x3c,	0x48,	0xf8,	0x48,	0x48,	0xc8,	0x8e,	0x2a,	0xf5,	0x02,	0xdd,	0x14,	0x30,	0x44,	0x8e},
{0x85,	0x44,	0xdf,	0x52,	0x7f,	0xc6,	0x98,	0x60,	0xd4,	0x52,	0x0e,	0x65,	0x07,	0x9f,	0x86,	0xea},
{0x10,	0xd1,	0xd3,	0x91,	0x91,	0xfe,	0xf3,	0x01,	0xb1,	0x78,	0x58,	0x01,	0x49,	0x6b,	0x2d,	0xa9},
{0xc2,	0x8d,	0x31,	0x64,	0xec,	0xeb,	0x0f,	0x2a,	0x37,	0x99,	0x90,	0xc4,	0xf6,	0x30,	0xb8,	0xf6},
{0xc0,	0xb4,	0xa6,	0xff,	0x39,	0x2f,	0x54,	0x6c,	0xaf,	0xeb,	0xe1,	0xd4,	0xd7,	0x63,	0x64,	0xbf},
{0x01,	0x54,	0x30,	0x7b,	0xef,	0x84,	0x08,	0x09,	0xd4,	0xd5,	0xa3,	0x8d,	0xa6,	0xa1,	0xc1,	0x0a},
{0xfb,	0xde,	0xe0,	0xaf,	0x10,	0xc9,	0xf6,	0x49,	0xbe,	0xe7,	0x6e,	0xa4,	0x6a,	0x2b,	0x9c,	0xf3},
{0x01,	0x6f,	0x5a,	0x3d,	0xbf,	0xad,	0xee,	0xab,	0xf1,	0xc4,	0xaf,	0x02,	0xd6,	0x1c,	0x89,	0xf2},
{0xc0,	0x77,	0x44,	0x94,	0x60,	0x7c,	0x12,	0x8d,	0x2e,	0x2d,	0xbc,	0xeb,	0x11,	0x43,	0x48,	0x8e},
{0xc2,	0x5d,	0x97,	0xf3,	0xe9,	0x1a,	0x8d,	0xcb,	0xbb,	0x06,	0xc5,	0x20,	0x1c,	0x68,	0x90,	0x93},
{0x10,	0x96,	0xca,	0xd9,	0x30,	0x68,	0x2f,	0x14,	0x1a,	0x17,	0x0c,	0xca,	0x0c,	0x70,	0xda,	0xbf},
{0x85,	0x74,	0x75,	0xd0,	0x5e,	0xbe,	0xb8,	0x87,	0x4e,	0x62,	0xec,	0x6b,	0x10,	0x87,	0xc6,	0x74},
{0x20,	0x2d,	0x99,	0xe9,	0x95,	0x9f,	0xd4,	0x49,	0xe6,	0xd5,	0x76,	0xf2,	0x33,	0xc8,	0x20,	0x98},
{0x94,	0x84,	0xdd,	0x10,	0xbd,	0x27,	0x5d,	0xb8,	0x7a,	0x48,	0x6c,	0x72,	0x76,	0xa2,	0x6e,	0xcf},
};
//static inline
/*
poly8x8_t BR_p8(poly16x8_t v) {
	const poly8x8_t B5 = vdup_n_p8(0xB5);
	const poly8x8_t C3 = vdup_n_p8(0xC3);
    poly8x8_t t0 = (poly8x8_t) vshrn_n_u16((uint16x8_t)v, 8);
    poly16x8_t t  = vmull_p8(t0,B5);
    t0^= (poly8x8_t) vshrn_n_u16((uint16x8_t)t, 8);// сдвиг вправо с заужением
    v ^= vmull_p8(t0, C3);
	return (poly8x8_t)vmovn_u16((uint16x8_t)v);
} */
/* этот вариант кажется достаточно быстрым */
static uint8x16_t LS4(uint8x16_t a)
{
    poly16x8_t v0 = {0};
    poly16x8_t v1 = {0};
	int i;
// #pragma GCC unroll 1
    for(i=0;i<16;i++){
        poly8x8_t a8 = (poly8x8_t)vdup_n_u8(sbox[a[i]]);// размножаем значение на все элементы
		poly8x16_t p8 = LMT[i];
        v0 ^= vmull_p8(a8, vget_low_p8 (p8));// младшая часть вектора poly8x8 бит 
        v1 ^= vmull_p8(a8, vget_high_p8(p8));// старшая часть вектора poly8x8 бит 
    }
    /// редуцирование вынесли из цикла
    poly8x8_t t0, t1;
	poly16x8_t t;
	const poly8x8_t B5 = vdup_n_p8(0xB5);
	const poly8x8_t C3 = vdup_n_p8(0xC3);
    t0 = (poly8x8_t) vshrn_n_u16((uint16x8_t)v0, 8);
    t  = vmull_p8(t0, B5);
    t0^= (poly8x8_t) vshrn_n_u16((uint16x8_t)t, 8);// сдвиг вправо с заужением
    v0^= vmull_p8(t0, C3);

    t1 = (poly8x8_t) vshrn_n_u16((uint16x8_t)v1, 8);
    t  = vmull_p8(t1, B5);
    t1^= (poly8x8_t) vshrn_n_u16((uint16x8_t)t, 8);// сдвиг вправо с заужением
    v1^= vmull_p8(t1, C3);
	
	uint8x16x2_t v = vuzpq_u8((uint8x16_t)v0, (uint8x16_t)v1);
	return v.val[0];// сдвиг на один байт
//    return vcombine_u8(vmovn_u16((uint16x8_t)v0), vmovn_u16((uint16x8_t)v1));
}
poly64x2_t CL_MUL64xPx(poly64x2_t r0)
{
	const poly8x8_t Px =vdup_n_p8(0x87);
	const poly8x8_t Z  ={0};
	poly16x8_t   t = vmull_p8(vget_high_p8(r1),Px)
	uint8x16x2_t v = vuzpq_u8(t, Z);
	return v.val[0] ^  vextq_u8(Z, v.val[1], 15);
}
poly64x2_t CL_MUL128(poly64x2_t a, poly64x2_t b)
{
	const poly8x8_t Z  ={0};
	poly16x8_t   t;
	uint8x16x2_t v;
shift 
for (i=0; i<8; i++){
	q1 = vextq_u16(q0,q1,7);
	q0 = vextq_u16(Z,q0,7);
	q0^= vmull_lane_p8(a, vget_low_p8(b), i);
}
v = vuzpq_u8(q0, q1);
return v.val[0] ^  vextq_u8(Z, v.val[1], 15);

	t = vmull_p8(vget_high_p8(r1), Px);
	t = vmull_lane_p8(vget_high_p8(r1), b, 1);

	p = vdup_lane_p8(b,1);
	t = vmull_p8(vget_high_p8(r1), p);
	v = vuzpq_u8(t^v.val[0], v.val[1]);
	
	
      for (i = 0; i < 64; i++, x >>= 1) {
         if (x & 1ULL) {
			r ^= v;
         }
         if (v[1] & 0x8000000000000000ULL) {
			 v[1] = (v[0] >> 63)|(v[1] << 1);
             v[0] = (v[0] << 1) ^ 0x87;
         } else {
			 v[1] = (v[0] >> 63)|(v[1] << 1);
             v[0] = (v[0] << 1);
         }
      }
	
	return r;
}

poly64x2_t gf128_reduction(poly64x2_t r0, poly64x2_t r1)
{
	const poly8x8_t Px =vdup_n_p8(0x87);// (1 || 0^120 || x87)
	t= vmull_p8(vget_high_p8(r1),Px)
	uint8x16x2_t v = vuzpq_u8(t, Z);
	t = v.val[0] ^  vextq_u8(v.val[0], Z, 1)
	
	poly64x2_t b  = vmull_p8(vget_high_p8(r1),Px) ^ SLL128U(r1, 64);
	poly64x2_t d  = CL_MUL128( b,Px, 0x01) ^ SLL128U( b, 64);
	return r0 ^ d;
#if 0// 
	const poly64x2_t Px ={0x86ULL};// (1 || 0^120 || x87)
	poly64x2_t b  = CL_MUL128(r1,Px, 0x01) ^ (poly64x2_t){r1[1],r1[0]};
	poly64x2_t d  = CL_MUL128( b,Px, 0x01) ^ (poly64x2_t){ b[1], b[0]};
	return r0 ^ d;
#endif
}

#else
typedef  int64_t  int64x2_t __attribute__((__vector_size__(16)));
typedef uint64_t uint64x2_t __attribute__((__vector_size__(16)));
typedef uint64_t poly64x2_t __attribute__((__vector_size__(16)));
typedef uint8_t  poly8x16_t __attribute__((__vector_size__(16)));
typedef uint8_t  poly16x8_t __attribute__((__vector_size__(16)));
typedef uint8_t  uint8x16_t __attribute__((__vector_size__(16)));
typedef char     int8x16_t __attribute__((__vector_size__(16)));
typedef uint16_t uint16x8_t __attribute__((__vector_size__(16)));

static inline uint8x16_t vld1q_u8(const uint8_t* p) {
	uint8x16_t v;
	__builtin_memcpy(&v, p, 16);
	return v;
    //return (uint8x16_t)__builtin_ia32_loaddqu(p);
	// return *(uint8x16_t*)p;
}
#ifdef __clang__
#define CL_MUL128(a,b,im) __builtin_ia32_pclmulqdq128(a,b,im)
#define SLL128U(a,bits)   __builtin_ia32_pslldqi128_byteshift(a, bits>>3)
#define SRL128U(a,bits)   __builtin_ia32_psrldqi128_byteshift(a, bits>>3)
#define UNPACKLBW128(a,b) __builtin_shufflevector((int8x16_t)a, b, 0, 16+0, 1, 16+1,  2, 16+ 2,  3, 16+ 3,  4, 16+ 4,  5, 16+ 5,  6, 16+ 6,  7, 16+ 7);
#define UNPACKHBW128(a,b) __builtin_shufflevector((int8x16_t)a, b, 8, 16+8, 9, 16+9, 10, 16+10, 11, 16+11, 12, 16+12, 13, 16+13, 14, 16+14, 15, 16+15);
#define REV128(v) __builtin_shufflevector((uint8x16_t)(v),(uint8x16_t)(v),15,14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#else
	
#define UNPACKLBW128(a,b) __builtin_shuffle((int8x16_t)a, b, (int8x16_t){0, 16+0, 1, 16+1,  2, 16+ 2,  3, 16+ 3,  4, 16+ 4,  5, 16+ 5,  6, 16+ 6,  7, 16+ 7});
#define UNPACKHBW128(a,b) __builtin_shuffle((int8x16_t)a, b, (int8x16_t){8, 16+8, 9, 16+9, 10, 16+10, 11, 16+11, 12, 16+12, 13, 16+13, 14, 16+14, 15, 16+15});

static inline
poly64x2_t CL_MUL128(poly64x2_t a, poly64x2_t b, const int c) __attribute__ ((__target__("pclmul")));
static inline poly64x2_t CL_MUL128(poly64x2_t a, poly64x2_t b, const int c) {
    return (poly64x2_t)__builtin_ia32_pclmulqdq128 ((int64x2_t)a,(int64x2_t)b,c);
}
poly64x2_t CL_MUL128x64(poly64x2_t r, poly64x2_t v, const int c)
{
	uint64_t x = r[c & 1];
	int i;
	for (i = 0; i < 64; i++, x >>= 1) {
		if (x & 1ULL) {
			r ^= v;
		}
		if (v[1] & 0x8000000000000000ULL) {
			v[1] = (v[0] >> 63)|(v[1] << 1);
			v[0] = (v[0] << 1) ^ 0x87;
		} else {
			v[1] = (v[0] >> 63)|(v[1] << 1);
			v[0] = (v[0] << 1);
		}
	}
	return r;
}


static inline poly64x2_t SLL128U(poly64x2_t a, const int bits) {
	
    return (poly64x2_t)__builtin_ia32_pslldqi128((int64x2_t)a, bits);
}
static inline poly64x2_t SRL128U(poly64x2_t a, const int bits) {
    return (poly64x2_t)__builtin_ia32_psrldqi128((int64x2_t)a, bits);
}
static inline uint8x16_t REV128(uint8x16_t v) {
    return __builtin_shuffle(v, (uint8x16_t){15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0});
}
#endif


#if 1
#include "kuznechik256.h" // таблицы
static uint8x16_t LS4(uint8x16_t a)
{
    poly64x2_t r0={0};
    poly64x2_t r1={0};
    int i;
	poly64x2_t bb= (poly64x2_t)a;
	uint64_t b0 = bb[0];
	uint64_t b1 = bb[1];
//#pragma GCC unroll 8
    for(i=0;i<8;i++) {
        uint64_t aa = a[i];
        r0 ^= _LH[i  ][(b0>>(i*8))&0xFF];
        r1 ^= _LH[i+8][(b1>>(i*8))&0xFF];
    }
	return (uint8x16_t)(r0 ^ r1);
}

static uint8x16_t LS4_1(uint8x16_t a)
{
	poly64x2_t bb= (poly64x2_t)a;
        uint64_t b = bb[0];
    poly64x2_t r0 = _LH[0][(uint8_t)(b>>0)];
    poly64x2_t r1 = _LH[1][(uint8_t)(b>>8)];
    poly64x2_t r2 = _LH[2][(uint8_t)(b>>16)];
    poly64x2_t r3 = _LH[3][(uint8_t)(b>>24)];
        r0 ^= _LH[5][(uint8_t)(b>>32)];
        r1 ^= _LH[6][(uint8_t)(b>>40)];
        r2 ^= _LH[7][(uint8_t)(b>>48)];
        r3 ^= _LH[8][(uint8_t)(b>>56)];
	b = bb[1];
        r0 ^= _LH[9][(uint8_t)(b>>0)];
        r1 ^= _LH[10][(uint8_t)(b>>8)];
        r2 ^= _LH[11][(uint8_t)(b>>16)];
        r3 ^= _LH[12][(uint8_t)(b>>24)];
        r0 ^= _LH[13][(uint8_t)(b>>32)];
        r1 ^= _LH[14][(uint8_t)(b>>40)];
        r2 ^= _LH[15][(uint8_t)(b>>48)];
        r3 ^= _LH[16][(uint8_t)(b>>56)];
	return (uint8x16_t)(r0^r1^r2^r3);
}
#include "kuznechik.h" // таблицы
static uint8x16_t LS4_(uint8x16_t a)
{
    poly64x2_t r={0}, rh={0};
    int i;
	#pragma GCC unroll 16
    for(i=0;i<16;i++) {
        //uint32_t aa = a[i];
        unsigned int aa = sbox[a[i]];
//        r ^= _LH[i][aa];
        r  ^= _L[i][aa & 0xF];
		rh ^= _H[i][(aa>>4)];
    }
	return (uint8x16_t)(r ^ rh);
}
void gen_table16x256()
{
	printf ("poly64x2_t _LH[16][256] = {\n");
	int j;
	for (j=0;j<16;j++){
		printf ("[%d]={\n", j);
		int i;
		for (i=0;i<256;i++) {
			unsigned int aa = sbox[i];
			poly64x2_t r = _L[j][aa & 0xF] ^ _H[j][(aa>>4)];
			printf("\t{0x%016llX, 0x%016llX},\n", r[0], r[1]);
		}
		printf ("},// [%d]\n", j);
	}
	printf ("};\n");
}
#elif 0//defined(__VPCLMULQDQ__)
typedef uint8_t  poly8x32_t __attribute__((__vector_size__(32)));
typedef  int8_t   int8x32_t __attribute__((__vector_size__(32)));
typedef uint64_t poly64x4_t __attribute__((__vector_size__(32)));
typedef  int64_t  int64x4_t __attribute__((__vector_size__(32)));
typedef union {
	poly64x4_t val[4];
} poly64x4x4_t;
static inline poly64x4_t CL_MUL256(poly64x4_t a, poly64x4_t b, const int c) __attribute__ ((__target__("vpclmulqdq,avx")));
static inline poly64x4_t CL_MUL256(poly64x4_t a, poly64x4_t b, const int c) {
    return (poly64x4_t)__builtin_ia32_vpclmulqdq_v4di  ((int64x4_t)a,(int64x4_t) b,c);
}
#define UNPACKLBW128(a,b) __builtin_shuffle((int8x32_t)a, b, (int8x32_t){0, 16+0, 1, 16+1,  2, 16+ 2,  3, 16+ 3,  4, 16+ 4,  5, 16+ 5,  6, 16+ 6,  7, 16+ 7,  8, 16+0, 1, 16+1,  2, 16+ 2,  3, 16+ 3,  4, 16+ 4,  5, 16+ 5,  6, 16+ 6,  7, 16+ 7 });
#define UNPACKHBW128(a,b) __builtin_shuffle((int8x32_t)a, b, (int8x32_t){8, 16+8, 9, 16+9, 10, 16+10, 11, 16+11, 12, 16+12, 13, 16+13, 14, 16+14, 15, 16+15});


static const poly8x32_t LMT[8] = {
{0x01,	0x94,	0x84,	0xdd,	0x10,	0xbd,	0x27,	0x5d,	0xb8,	0x7a,	0x48,	0x6c,	0x72,	0x76,	0xa2,	0x6e,
 0x94,	0xa5,	0x64,	0x0d,	0x89,	0xa2,	0x7f,	0x4b,	0x6e,	0x16,	0xc3,	0x4c,	0xe8,	0xe3,	0xd0,	0x4d},
{0x20,	0x3c,	0x48,	0xf8,	0x48,	0x48,	0xc8,	0x8e,	0x2a,	0xf5,	0x02,	0xdd,	0x14,	0x30,	0x44,	0x8e,
 0x85,	0x44,	0xdf,	0x52,	0x7f,	0xc6,	0x98,	0x60,	0xd4,	0x52,	0x0e,	0x65,	0x07,	0x9f,	0x86,	0xea},
{0x10,	0xd1,	0xd3,	0x91,	0x91,	0xfe,	0xf3,	0x01,	0xb1,	0x78,	0x58,	0x01,	0x49,	0x6b,	0x2d,	0xa9,
 0xc2,	0x8d,	0x31,	0x64,	0xec,	0xeb,	0x0f,	0x2a,	0x37,	0x99,	0x90,	0xc4,	0xf6,	0x30,	0xb8,	0xf6},
{0xc0,	0xb4,	0xa6,	0xff,	0x39,	0x2f,	0x54,	0x6c,	0xaf,	0xeb,	0xe1,	0xd4,	0xd7,	0x63,	0x64,	0xbf,
 0x01,	0x54,	0x30,	0x7b,	0xef,	0x84,	0x08,	0x09,	0xd4,	0xd5,	0xa3,	0x8d,	0xa6,	0xa1,	0xc1,	0x0a},
{0xfb,	0xde,	0xe0,	0xaf,	0x10,	0xc9,	0xf6,	0x49,	0xbe,	0xe7,	0x6e,	0xa4,	0x6a,	0x2b,	0x9c,	0xf3,
 0x01,	0x6f,	0x5a,	0x3d,	0xbf,	0xad,	0xee,	0xab,	0xf1,	0xc4,	0xaf,	0x02,	0xd6,	0x1c,	0x89,	0xf2},
{0xc0,	0x77,	0x44,	0x94,	0x60,	0x7c,	0x12,	0x8d,	0x2e,	0x2d,	0xbc,	0xeb,	0x11,	0x43,	0x48,	0x8e,
 0xc2,	0x5d,	0x97,	0xf3,	0xe9,	0x1a,	0x8d,	0xcb,	0xbb,	0x06,	0xc5,	0x20,	0x1c,	0x68,	0x90,	0x93},
{0x10,	0x96,	0xca,	0xd9,	0x30,	0x68,	0x2f,	0x14,	0x1a,	0x17,	0x0c,	0xca,	0x0c,	0x70,	0xda,	0xbf,
 0x85,	0x74,	0x75,	0xd0,	0x5e,	0xbe,	0xb8,	0x87,	0x4e,	0x62,	0xec,	0x6b,	0x10,	0x87,	0xc6,	0x74},
{0x20,	0x2d,	0x99,	0xe9,	0x95,	0x9f,	0xd4,	0x49,	0xe6,	0xd5,	0x76,	0xf2,	0x33,	0xc8,	0x20,	0x98,
 0x94,	0x84,	0xdd,	0x10,	0xbd,	0x27,	0x5d,	0xb8,	0x7a,	0x48,	0x6c,	0x72,	0x76,	0xa2,	0x6e,	0xcf},
};

static uint8x16_t LS4(uint8x16_t a) __attribute__ ((__target__("vpclmulqdq,avx")));
static uint8x16_t LS4(uint8x16_t a)
{
    int i;
    register int8x32_t Z = {0};
    register poly64x4_t v0 = {0};
    register poly64x4_t v1 = {0};
    register poly64x4_t v2 = {0};
    register poly64x4_t v3 = {0};
    register poly64x4_t a32= {0};
#pragma GCC unroll 8
    for(i=0;i<8;i+=1){
		a32[0] = sbox[a[2*i]];//(poly64x2_t)(v2di){a[i],a[i]};
		a32[2] = sbox[a[2*i+1]];//(poly64x2_t)(v2di){a[i],a[i]};
		poly64x4_t L = (poly64x4_t)UNPACKLBW128x2((int8x32_t)LMT[i], Z);
		poly64x4_t H = (poly64x4_t)UNPACKHBW128x2((int8x32_t)LMT[i], Z); 
        v0 ^= CL_MUL256(a32, L, 0x00);
        v1 ^= CL_MUL256(a32, L, 0x10);
        v2 ^= CL_MUL256(a32, H, 0x00);
        v3 ^= CL_MUL256(a32, H, 0x10);
    }
}
#else
static const poly8x16_t LMT[16] = {
{0x01,	0x94,	0x84,	0xdd,	0x10,	0xbd,	0x27,	0x5d,	0xb8,	0x7a,	0x48,	0x6c,	0x72,	0x76,	0xa2,	0x6e},
{0x94,	0xa5,	0x64,	0x0d,	0x89,	0xa2,	0x7f,	0x4b,	0x6e,	0x16,	0xc3,	0x4c,	0xe8,	0xe3,	0xd0,	0x4d},
{0x20,	0x3c,	0x48,	0xf8,	0x48,	0x48,	0xc8,	0x8e,	0x2a,	0xf5,	0x02,	0xdd,	0x14,	0x30,	0x44,	0x8e},
{0x85,	0x44,	0xdf,	0x52,	0x7f,	0xc6,	0x98,	0x60,	0xd4,	0x52,	0x0e,	0x65,	0x07,	0x9f,	0x86,	0xea},
{0x10,	0xd1,	0xd3,	0x91,	0x91,	0xfe,	0xf3,	0x01,	0xb1,	0x78,	0x58,	0x01,	0x49,	0x6b,	0x2d,	0xa9},
{0xc2,	0x8d,	0x31,	0x64,	0xec,	0xeb,	0x0f,	0x2a,	0x37,	0x99,	0x90,	0xc4,	0xf6,	0x30,	0xb8,	0xf6},
{0xc0,	0xb4,	0xa6,	0xff,	0x39,	0x2f,	0x54,	0x6c,	0xaf,	0xeb,	0xe1,	0xd4,	0xd7,	0x63,	0x64,	0xbf},
{0x01,	0x54,	0x30,	0x7b,	0xef,	0x84,	0x08,	0x09,	0xd4,	0xd5,	0xa3,	0x8d,	0xa6,	0xa1,	0xc1,	0x0a},
{0xfb,	0xde,	0xe0,	0xaf,	0x10,	0xc9,	0xf6,	0x49,	0xbe,	0xe7,	0x6e,	0xa4,	0x6a,	0x2b,	0x9c,	0xf3},
{0x01,	0x6f,	0x5a,	0x3d,	0xbf,	0xad,	0xee,	0xab,	0xf1,	0xc4,	0xaf,	0x02,	0xd6,	0x1c,	0x89,	0xf2},
{0xc0,	0x77,	0x44,	0x94,	0x60,	0x7c,	0x12,	0x8d,	0x2e,	0x2d,	0xbc,	0xeb,	0x11,	0x43,	0x48,	0x8e},
{0xc2,	0x5d,	0x97,	0xf3,	0xe9,	0x1a,	0x8d,	0xcb,	0xbb,	0x06,	0xc5,	0x20,	0x1c,	0x68,	0x90,	0x93},
{0x10,	0x96,	0xca,	0xd9,	0x30,	0x68,	0x2f,	0x14,	0x1a,	0x17,	0x0c,	0xca,	0x0c,	0x70,	0xda,	0xbf},
{0x85,	0x74,	0x75,	0xd0,	0x5e,	0xbe,	0xb8,	0x87,	0x4e,	0x62,	0xec,	0x6b,	0x10,	0x87,	0xc6,	0x74},
{0x20,	0x2d,	0x99,	0xe9,	0x95,	0x9f,	0xd4,	0x49,	0xe6,	0xd5,	0x76,	0xf2,	0x33,	0xc8,	0x20,	0x98},
{0x94,	0x84,	0xdd,	0x10,	0xbd,	0x27,	0x5d,	0xb8,	0x7a,	0x48,	0x6c,	0x72,	0x76,	0xa2,	0x6e,	0xcf},
};

static
uint8x16_t LS4(uint8x16_t a)
{
    int i;
    register int8x16_t Z = {0};
    register poly64x2_t v0 = {0};
    register poly64x2_t v1 = {0};
    register poly64x2_t v2 = {0};
    register poly64x2_t v3 = {0};
    register poly64x2_t a16= {0};
#pragma GCC unroll 16
    for(i=0;i<16;i+=1){
		a16[0] = sbox[a[i]];//(poly64x2_t)(v2di){a[i],a[i]};
		poly64x2_t L = (poly64x2_t)UNPACKLBW128((int8x16_t)LMT[i], Z);//__builtin_ia32_punpcklbw128 ((int8x16_t)LMT[i], Z);//
		poly64x2_t H = (poly64x2_t)UNPACKHBW128((int8x16_t)LMT[i], Z);//__builtin_ia32_punpckhbw128 ((int8x16_t)LMT[i], Z);//
        v0 ^= CL_MUL128(a16, L, 0x00);
        v1 ^= CL_MUL128(a16, L, 0x10);
        v2 ^= CL_MUL128(a16, H, 0x00);
        v3 ^= CL_MUL128(a16, H, 0x10);
    }
    /// редуцирование вынесли из цикла
    poly64x2_t t;
    const poly64x2_t KBP = {0x1B5, 0x1C3}; // коэффициенты редукции Barrett'a
    t  = CL_MUL128((poly64x2_t)((uint16x8_t)v0>>8),KBP, 0x00);
    v0^= CL_MUL128((poly64x2_t)((uint16x8_t)t>>8), KBP, 0x10);
    t  = CL_MUL128((poly64x2_t)((uint16x8_t)v1>>8),KBP, 0x00);
    v1^= CL_MUL128((poly64x2_t)((uint16x8_t)t>>8), KBP, 0x10);
	v0 = (poly64x2_t){v0[0], v1[0]};
    t  = CL_MUL128((poly64x2_t)((uint16x8_t)v2>>8),KBP, 0x00);
    v2^= CL_MUL128((poly64x2_t)((uint16x8_t)t>>8), KBP, 0x10);
    t  = CL_MUL128((poly64x2_t)((uint16x8_t)v3>>8),KBP, 0x00);
    v3^= CL_MUL128((poly64x2_t)((uint16x8_t)t>>8), KBP, 0x10);
	v2 = (poly64x2_t){v2[0], v3[0]};
#ifdef __clang__
	return __builtin_shufflevector((uint8x16_t)v0,(uint8x16_t)v2, 0,2,4,6, 8,10,12,14, 16,18,20,22, 24,26,28,30);
#else
	return __builtin_shuffle((uint8x16_t)v0,(uint8x16_t)v2, (uint8x16_t){0,2,4,6, 8,10,12,14, 16,18,20,22, 24,26,28,30});
#endif // __clang__
}
#endif//0
#endif

typedef struct {
  uint8x16_t K[10];
} KuznCtx;

uint8x16_t kuzn_encrypt(KuznCtx* ctx, const uint8x16_t a)
{
    uint8x16_t S = a ^ ctx->K[0];
    int i;
    for (i=0; i<9; i++){
        S = LS4(S) ^ ctx->K[i+1];
    }
    return S;
}

static const uint8x16_t Cx [32] = {
{0x01, 0x94, 0x84, 0xdd, 0x10, 0xbd, 0x27, 0x5d, 0xb8, 0x7a, 0x48, 0x6c, 0x72, 0x76, 0xa2, 0x6e },
{0x02, 0xeb, 0xcb, 0x79, 0x20, 0xb9, 0x4e, 0xba, 0xb3, 0xf4, 0x90, 0xd8, 0xe4, 0xec, 0x87, 0xdc },
{0x03, 0x7f, 0x4f, 0xa4, 0x30, 0x04, 0x69, 0xe7, 0x0b, 0x8e, 0xd8, 0xb4, 0x96, 0x9a, 0x25, 0xb2 },
{0x04, 0x15, 0x55, 0xf2, 0x40, 0xb1, 0x9c, 0xb7, 0xa5, 0x2b, 0xe3, 0x73, 0x0b, 0x1b, 0xcd, 0x7b },
{0x05, 0x81, 0xd1, 0x2f, 0x50, 0x0c, 0xbb, 0xea, 0x1d, 0x51, 0xab, 0x1f, 0x79, 0x6d, 0x6f, 0x15 },
{0x06, 0xfe, 0x9e, 0x8b, 0x60, 0x08, 0xd2, 0x0d, 0x16, 0xdf, 0x73, 0xab, 0xef, 0xf7, 0x4a, 0xa7 },
{0x07, 0x6a, 0x1a, 0x56, 0x70, 0xb5, 0xf5, 0x50, 0xae, 0xa5, 0x3b, 0xc7, 0x9d, 0x81, 0xe8, 0xc9 },
{0x08, 0x2a, 0xaa, 0x27, 0x80, 0xa1, 0xfb, 0xad, 0x89, 0x56, 0x05, 0xe6, 0x16, 0x36, 0x59, 0xf6 },
{0x09, 0xbe, 0x2e, 0xfa, 0x90, 0x1c, 0xdc, 0xf0, 0x31, 0x2c, 0x4d, 0x8a, 0x64, 0x40, 0xfb, 0x98 },
{0x0a, 0xc1, 0x61, 0x5e, 0xa0, 0x18, 0xb5, 0x17, 0x3a, 0xa2, 0x95, 0x3e, 0xf2, 0xda, 0xde, 0x2a },
{0x0b, 0x55, 0xe5, 0x83, 0xb0, 0xa5, 0x92, 0x4a, 0x82, 0xd8, 0xdd, 0x52, 0x80, 0xac, 0x7c, 0x44 },
{0x0c, 0x3f, 0xff, 0xd5, 0xc0, 0x10, 0x67, 0x1a, 0x2c, 0x7d, 0xe6, 0x95, 0x1d, 0x2d, 0x94, 0x8d },
{0x0d, 0xab, 0x7b, 0x08, 0xd0, 0xad, 0x40, 0x47, 0x94, 0x07, 0xae, 0xf9, 0x6f, 0x5b, 0x36, 0xe3 },
{0x0e, 0xd4, 0x34, 0xac, 0xe0, 0xa9, 0x29, 0xa0, 0x9f, 0x89, 0x76, 0x4d, 0xf9, 0xc1, 0x13, 0x51 },
{0x0f, 0x40, 0xb0, 0x71, 0xf0, 0x14, 0x0e, 0xfd, 0x27, 0xf3, 0x3e, 0x21, 0x8b, 0xb7, 0xb1, 0x3f },
{0x10, 0x54, 0x97, 0x4e, 0xc3, 0x81, 0x35, 0x99, 0xd1, 0xac, 0x0a, 0x0f, 0x2c, 0x6c, 0xb2, 0x2f },
{0x11, 0xc0, 0x13, 0x93, 0xd3, 0x3c, 0x12, 0xc4, 0x69, 0xd6, 0x42, 0x63, 0x5e, 0x1a, 0x10, 0x41 },
{0x12, 0xbf, 0x5c, 0x37, 0xe3, 0x38, 0x7b, 0x23, 0x62, 0x58, 0x9a, 0xd7, 0xc8, 0x80, 0x35, 0xf3 },
{0x13, 0x2b, 0xd8, 0xea, 0xf3, 0x85, 0x5c, 0x7e, 0xda, 0x22, 0xd2, 0xbb, 0xba, 0xf6, 0x97, 0x9d },
{0x14, 0x41, 0xc2, 0xbc, 0x83, 0x30, 0xa9, 0x2e, 0x74, 0x87, 0xe9, 0x7c, 0x27, 0x77, 0x7f, 0x54 },
{0x15, 0xd5, 0x46, 0x61, 0x93, 0x8d, 0x8e, 0x73, 0xcc, 0xfd, 0xa1, 0x10, 0x55, 0x01, 0xdd, 0x3a },
{0x16, 0xaa, 0x09, 0xc5, 0xa3, 0x89, 0xe7, 0x94, 0xc7, 0x73, 0x79, 0xa4, 0xc3, 0x9b, 0xf8, 0x88 },
{0x17, 0x3e, 0x8d, 0x18, 0xb3, 0x34, 0xc0, 0xc9, 0x7f, 0x09, 0x31, 0xc8, 0xb1, 0xed, 0x5a, 0xe6 },
{0x18, 0x7e, 0x3d, 0x69, 0x43, 0x20, 0xce, 0x34, 0x58, 0xfa, 0x0f, 0xe9, 0x3a, 0x5a, 0xeb, 0xd9 },
{0x19, 0xea, 0xb9, 0xb4, 0x53, 0x9d, 0xe9, 0x69, 0xe0, 0x80, 0x47, 0x85, 0x48, 0x2c, 0x49, 0xb7 },
{0x1a, 0x95, 0xf6, 0x10, 0x63, 0x99, 0x80, 0x8e, 0xeb, 0x0e, 0x9f, 0x31, 0xde, 0xb6, 0x6c, 0x05 },
{0x1b, 0x01, 0x72, 0xcd, 0x73, 0x24, 0xa7, 0xd3, 0x53, 0x74, 0xd7, 0x5d, 0xac, 0xc0, 0xce, 0x6b },
{0x1c, 0x6b, 0x68, 0x9b, 0x03, 0x91, 0x52, 0x83, 0xfd, 0xd1, 0xec, 0x9a, 0x31, 0x41, 0x26, 0xa2 },
{0x1d, 0xff, 0xec, 0x46, 0x13, 0x2c, 0x75, 0xde, 0x45, 0xab, 0xa4, 0xf6, 0x43, 0x37, 0x84, 0xcc },
{0x1e, 0x80, 0xa3, 0xe2, 0x23, 0x28, 0x1c, 0x39, 0x4e, 0x25, 0x7c, 0x42, 0xd5, 0xad, 0xa1, 0x7e },
{0x1f, 0x14, 0x27, 0x3f, 0x33, 0x95, 0x3b, 0x64, 0xf6, 0x5f, 0x34, 0x2e, 0xa7, 0xdb, 0x03, 0x10 },
{0x20, 0xa8, 0xed, 0x9c, 0x45, 0xc1, 0x6a, 0xf1, 0x61, 0x9b, 0x14, 0x1e, 0x58, 0xd8, 0xa7, 0x5e }
};
/*! разгибание ключа
    Nk -- длина ключа 4 слова (128 бит)
 */
static void kuzn_key_expansion_(KuznCtx * ctx, const uint8_t* key, int klen, int ekb)
{
    uint8x16_t *K = ctx->K;
	uint8x16_t a, b;
    K[0] = a = vld1q_u8(key+16);//__builtin_memcpy(&K[0],&key[16], 16);
    K[1] = b = vld1q_u8(key+ 0);//__builtin_memcpy(&K[1],&key[ 0], 16);
    int j, n = 0;
    for(j=2; j<9; j+=2) {
        int i;
        for (i=0;i<8;i+=2){
            /* можно вычислять констранты налету
            Сx = L((v16qi){n+1,0...0})
            */
            //register uint8x16_t v = a;
            b = LS4(a ^ Cx[n++]) ^ b;
            a = LS4(b ^ Cx[n++]) ^ a;
            //b = v;
        }
        K[j] = a; K[j+1] = b;
    }
}
static void kuzn_key_expansion(KuznCtx * ctx, const uint8_t* key, int klen, int ekb)
{
    uint8x16_t *K = ctx->K;
	uint8x16_t a, b;
    K[0] = a = REV128(vld1q_u8(key+0));//__builtin_memcpy(&K[0],&key[16], 16);
    K[1] = b = REV128(vld1q_u8(key+16));//__builtin_memcpy(&K[1],&key[ 0], 16);
    int j, n = 0;
    for(j=2; j<9; j+=2) {
        int i;
        for (i=0;i<8;i+=2){
            /* можно вычислять констранты налету
            Сx = L((v16qi){n+1,0...0})
            */
            //register uint8x16_t v = a;
            b = LS4(a ^ Cx[n++]) ^ b;
            a = LS4(b ^ Cx[n++]) ^ a;
            //b = v;
        }
        K[j] = a; K[j+1] = b;
    }
}
/*
typedef struct poly16x8x4_t
{
  poly16x8_t val[4];
} poly16x8x4_t; */
typedef union {
	poly64x2_t val[4];
} poly64x2x4_t;
typedef union {
	poly64x2_t val[2];
} poly64x2x2_t;

#if 0
/*! Реализация режима шифрования MGM */
static void CL_MLA(poly16x8x4_t *s, uint8x16_t p, uint8x16_t v) {
	poly8x8_t p0 = vget_low_p8 ((poly8x16_t)p);
	poly8x8_t p1 = vget_high_p8((poly8x16_t)p);
	poly8x8_t v0 = vget_low_p8 ((poly8x16_t)v);
	poly8x8_t v1 = vget_high_p8((poly8x16_t)v);
	s->val[0] = vmull_p8(p0, v0);
	s->val[1] = vmull_p8(p0, v1);
	s->val[2] = vmull_p8(p1, v0);
	s->val[3] = vmull_p8(p1, v1);
}
static uint64x2_t SLL64x2 (uint64x2_t x, const int n)
{
	return (x<<n) ^ (uint64x2_t){0,x[0]}>>(64-n);
}
/*! Финальное редуцирование */
static uint8x16_t RED128_(poly64x2x2_t *s) {
	uint64x2_t q0 = s->val[0];
	uint64x2_t q1 = s->val[1];
	uint64_t x2 = q1[0];
	uint64_t x3 = q1[1];
	uint64_t d  = (x3>>63) ^ (x3>>62) ^ (x3>>57);
	uint64x2_t h = {x2 ^ d, x3};
	h = h ^ SLL64x2(h, 1) ^ SLL64x2(h, 2)^ SLL64x2(h, 7);
	return (uint8x16_t)(h^q0);
}
#endif


poly64x2_t gf128_reduction(poly64x2_t r0, poly64x2_t r1)
{
#if 0
	const poly64x2_t Px = {0x87ULL};
	poly64x2_t b = CL_MUL128(r1, Px, 0x01);
	poly64x2_t a = CL_MUL128(r1, Px, 0x00);
	poly64x2_t c = CL_MUL128( b, Px, 0x01);
	return r0 ^ a ^ c ^ SLL128U(b,64);
#elif 0// SSE+PCLMUL
	const poly64x2_t Px ={0x87ULL};// (1 || 0^120 || x87)
	poly64x2_t b  = CL_MUL128(r1,Px, 0x01) ^ SLL128U(r1, 64);
	poly64x2_t d  = CL_MUL128( b,Px, 0x01) ^ SLL128U( b, 64);
	return r0 ^ d;
#elif 1// SSE+PCLMUL
	const poly64x2_t Px ={0x86ULL};// (1 || 0^120 || x87)
	poly64x2_t b  = CL_MUL128(r1,Px, 0x01) ^ (poly64x2_t){r1[1],r1[0]};
	poly64x2_t d  = CL_MUL128( b,Px, 0x01) ^ (poly64x2_t){ b[1], b[0]};
	return r0 ^ d;
#else
	uint64_t x0 = r0[0];
	uint64_t x1 = r0[1];
	uint64_t x2 = r1[0];
	uint64_t x3 = r1[1];
	uint64_t b1 = x2 ^ x3>>63 ^ x3>>62 ^ x3>>57; 
	uint64_t b0 = x3 ^ x3<<1  ^ x3<<2  ^ x3<<7; 
	uint64_t d1 = b0 ^ b1>>63 ^ b1>>62 ^ b1>>57; 
	uint64_t d0 = b1 ^ b1<<1  ^ b1<<2  ^ b1<<7; 
	return (poly64x2_t){d0^x0, d1^x1};
#endif
}
/*! brief операция умножения с накоплением в результате получаем 256 бит */

//static 
void CL_MLA(poly64x2x4_t *s, poly64x2_t p, poly64x2_t v) {
	//poly64x2_t q = (poly64x2_t)CL_MUL128(p, v, 0x10) ^ (poly64x2_t)CL_MUL128(p, v, 0x01);// карацуба
#if (Karatsuba==1) // карацуба
	s->val[0] ^= (poly64x2_t)CL_MUL128(p, v, 0x00);// ^ SLL128U(q, 64);
	poly64x2_t t = (poly64x2_t){p[0],v[0]} ^ (poly64x2_t){p[1], v[1]};
	s->val[1] ^= (poly64x2_t)CL_MUL128(t, t, 0x01);
//	s->val[2] ^= (poly64x2_t)CL_MUL128(p, v, 0x10);
	s->val[3] ^= (poly64x2_t)CL_MUL128(p, v, 0x11);// ^ SRL128U(q, 64);
#else
	s->val[0] ^= (poly64x2_t)CL_MUL128(p, v, 0x00);// ^ SLL128U(q, 64);
	s->val[1] ^= (poly64x2_t)CL_MUL128(p, v, 0x01);
	s->val[2] ^= (poly64x2_t)CL_MUL128(p, v, 0x10);
	s->val[3] ^= (poly64x2_t)CL_MUL128(p, v, 0x11);// ^ SRL128U(q, 64);
#endif	
	//return (uint8x16_t)gf128_reduction(s->val[0], s->val[1]);
	
}
#ifdef __VPCLMULQDQ__
typedef uint64_t poly64x4_t __attribute__((__vector_size__(32)));
typedef  int64_t  int64x4_t __attribute__((__vector_size__(32)));
typedef union {
	poly64x4_t val[4];
} poly64x4x4_t;
static inline poly64x4_t CL_MUL256(poly64x4_t a, poly64x4_t b, const int c) __attribute__ ((__target__("vpclmulqdq","avx512vl")));
static inline poly64x4_t CL_MUL256(poly64x4_t a, poly64x4_t b, const int c) {
    return (poly64x4_t)__builtin_ia32_vpclmulqdq_v4di  ((int64x4_t)a,(int64x4_t) b,c);
}

void CL_MLAx2(poly64x4x4_t *s, poly64x4_t p, poly64x4_t v) {
#if (Karatsuba==1) // карацуба
	s->val[0] ^= CL_MUL256(p, v, 0x00);
	// vpunpckhqdq vpunpcklqdq
	poly64x4_t t = (poly64x4_t){p[0],v[0], p[2],v[2]} ^ (poly64x4_t){p[1], v[1], p[3], v[3]};
	s->val[1] ^= CL_MUL256(t, t, 0x01);
	s->val[3] ^= CL_MUL256(p, v, 0x11);
#else
	s->val[0] ^= CL_MUL256(p, v, 0x00);// ^ SLL128U(q, 64);
	s->val[1] ^= CL_MUL256(p, v, 0x01);
	s->val[2] ^= CL_MUL256(p, v, 0x10);
	s->val[3] ^= CL_MUL256(p, v, 0x11);// ^ SRL128U(q, 64);
#endif
}
#endif
static inline uint8x16_t INCR_L(uint8x16_t v) {
    uint64x2_t v64 = (uint64x2_t)v + (uint64x2_t){0,1};// может понадобится выворачивать байты
    return (uint8x16_t)v64;
}
static inline uint8x16_t INCR_R(uint8x16_t v) {
    uint64x2_t v64 = (uint64x2_t)v + (uint64x2_t){1,0};
    return (uint8x16_t)v64;
}
typedef struct {
	KuznCtx *ctx;
	uint8x16_t iv;
	} Ciph;
typedef uint8x16_t (*CipherEncrypt128)(KuznCtx*, uint8x16_t);
//static 
static void print_hex(const char* fmt, int i, uint8x16_t v)
{
	printf(fmt, i);
	for (i=0; i<16;i++)
		printf(" %02X", v[15-i]);
	printf("\n");
}
static void print_hexstr(const char* fmt, int i, uint8x16_t v)
{
	printf(fmt, i);
	for (i=0; i<16;i++)
		printf(" %02X", v[i]);
	printf("\n");
}
void MGM128_encrypt(Ciph*ciph, uint8x16_t* dst, const uint8_t* src, int length)
{
    CipherEncrypt128 encrypt = kuzn_encrypt;//(CipherEncrypt128)ciph->cipher->encrypt;
    uint8x16_t v, p;
    uint8x16_t y = encrypt(ciph->ctx, ciph->iv);// Y_1 = E_K(0 || ICN),
    int blocks = length>>4;
    int i;
    for(i=0; i<blocks; i++) {
		v = encrypt(ciph->ctx, y);
		if (0) {
			print_hex("Y_%d     : ", i+1, y);
			print_hex("E_K(Y_%d): ", i+1, v);
		}
        p = vld1q_u8(&src[16*i]);
//		__builtin_memcpy(&p, &src[16*i], 16);
        dst[i] = (p) ^ REV128(v);// C_i = P_i (xor) E_K(Y_i),
        y = INCR_R(y);// incr_r(Y_{i-1})
    }
    if (length & 0xF) {
		v = encrypt(ciph->ctx, y);
		if (0){
			print_hex("Y_%d     : ", i+1, y);
			print_hex("E_K(Y_%d): ", i+1, v);
		}
        __builtin_memcpy(&p, &src[16*i], length & 0xF);
        p = (p) ^ REV128(v);
		__builtin_memcpy(&dst[i], &p, length & 0xF);
    }
}
//static 
uint8x16_t MGM128_tag(Ciph*ciph, const uint8_t* aad, int aad_len, const uint8_t* src, int length)
{
    CipherEncrypt128 encrypt = kuzn_encrypt;//(CipherEncrypt128)ciph->cipher->encrypt;
    uint8x16_t v, p;
	poly64x2x4_t sum={{0}};
    v = ciph->iv;// Z_1 = E_K(1 || ICN),
	v[15] |= 0x80;
	uint8x16_t y = encrypt(ciph->ctx, v);// Z_1 = E_K(1 || ICN),
    int i,j, blocks;
    blocks = aad_len>>4;
    for(i=0; i<blocks; i++) {
		v = encrypt(ciph->ctx, y);
		if (0) {
			print_hex("Z_%d     : ", i+1, y);
			print_hex("E_K(Z_%d): ", i+1, v);
		}
        p = vld1q_u8(&aad[16*i]);
        CL_MLA(&sum, (poly64x2_t)REV128(p), (poly64x2_t)(v));//sum (xor) ( H_i (x) A_i )
		//if (1) print_hex("sum_%d   : ", i+1, p);
        y = INCR_L(y);// incr_l(Z_{i-1})
    }
    if (aad_len & 0xF) {
		v = encrypt(ciph->ctx, y);
		if (0) {
			print_hex("Z_%d     : ", i+1, y);
			print_hex("E_K(Z_%d): ", i+1, v);
		}
		p ^=p;// vld1q_u8(&aad[16*i]);// A_h = A*_h || 0^{n-t}, -- зачистить старшие биты
		__builtin_memcpy(&p, &aad[16*i], aad_len & 0xF);
		if (0) print_hexstr("A_q%d   : ", 0, p);
		CL_MLA(&sum, (poly64x2_t)REV128(p), (poly64x2_t)v);//sum (xor) ( H_i (x) A_i )
		//if (1) print_hex("sum_%d   : ", i+1, p);
		y = INCR_L(y);// incr_l(Z_{i-1})
		i++;
    }
	
    blocks = length>>4;
    for(j=0; j<blocks; j++) {
		v = encrypt(ciph->ctx, y);
		if (0) {
			print_hex("Z_%d     : ", i+j+1, y);
			print_hex("E_K(Z_%d): ", i+j+1, v);
		}
        p = vld1q_u8(&src[16*j]);
        CL_MLA(&sum, (poly64x2_t)REV128(p), (poly64x2_t)v);//sum (xor) ( H_i (x) A_i )
        y = INCR_L(y);
    }
    if (length & 0xF) {
		v = encrypt(ciph->ctx, y);
		if (0) {
			print_hex("Z_%d     : ", i+j+1, y);
			print_hex("E_K(Z_%d): ", i+j+1, v);
		}
		p ^= p;//vld1q_u8(&src[16*j]);// A_h = A*_h || 0^{n-t}, -- зачистить старшие биты
		__builtin_memcpy(&p, &src[16*j], length & 0xF);
		CL_MLA(&sum, (poly64x2_t)REV128(p), (poly64x2_t)v);//sum (xor) ( H_i (x) A_i )
		y = INCR_L(y);
		j++;
    }
	v = encrypt(ciph->ctx, y);
	if (0) {
		print_hex("Z_%d     : ", i+j+1, y);
		print_hex("E_K(Z_%d): ", i+j+1, v);
	}
	p = (uint8x16_t)(uint64x2_t){length*8, aad_len*8};	// поменять порядок следования?
	if (0) print_hex("len(A) || len(C):\n%04X0:    ", 0, p);
	CL_MLA(&sum, (poly64x2_t)p, (poly64x2_t)v);
#if (Karatsuba==1)
	poly64x2_t q = sum.val[1] ^ sum.val[0] ^ sum.val[3];
#else
	poly64x2_t q = sum.val[1] ^ sum.val[2];
#endif
	poly64x2_t r0= sum.val[0];// ^ SLL128U(q, 64);
	poly64x2_t r1= sum.val[3];// ^ SRL128U(q, 64);
// редуцирование по модулю, работает!
	q^= (poly64x2_t){r1[1],r1[0]};//SHUFFLE(H);
    q^= CL_MUL128(r1, (poly64x2_t){0x86ULL}, 0x01);
// редуцирование по модулю, работает!
	r0^= (poly64x2_t){q[1],q[0]};//SHUFFLE(M);
    r0^= CL_MUL128(q, (poly64x2_t){0x86ULL}, 0x01);
	v = (uint8x16_t)r0;

	v = encrypt(ciph->ctx, v);
	return REV128(v);
}

#include <stdio.h>
int main()
{
	if (0) {
		gen_table16x256();
		return 0;
	}
    KuznCtx ctx;
    uint8x16_t key[2] = {
        {0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01,0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe},
        {0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88},
    };
    kuzn_key_expansion(&ctx, (uint8_t*)key, 0, 0);
	int i;
    printf("4.4.1 Алгоритм зашифрования\n");
    uint8x16_t a = {0x88, 0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x77,0x66,0x55,0x44,0x33,0x22,0x11};
    printf("plain text:\n");
    for (i=0; i<16; i++) printf("%02x", a[15-i]);// 1122334455667700ffeeddccbbaa9988
    printf("\n");
    uint8x16_t b = kuzn_encrypt(&ctx, a);
    printf("cipher text:\n");
    for (i=0; i<16; i++) printf("%02x", b[15-i]);// 7f679d90bebc24305a468d42b9d4edcd
    printf("\n");
	if (0) {
		uint64_t u;
		for (u=0; u< 1000000; u++)
			a = kuzn_encrypt(&ctx, a);
		printf("enc 100k a: %016"PRIX64"\n",((uint64x2_t)a)[0]);
	}
	if (1){
//		"\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77"
//		"\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF";

//		uint8x16_t key[2] =  {
//			{0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77},
//			{0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF}};
		uint8_t aad[] =  {
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
		0xEA, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05};
		uint8_t pt[] =  {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x00,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x00, 0x11,
		0xAA, 0xBB, 0xCC};
		Ciph ciph = {.ctx = &ctx, 
		.iv = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88}};
		ciph.iv = REV128(ciph.iv);
		uint8x16_t dst[8];
		kuzn_key_expansion(&ctx, (uint8_t*)key, 0, 0);
//		_Exit(1);
		MGM128_encrypt(&ciph, dst, pt, sizeof(pt));
		if (0){
			printf("C:\n");
			int i;
			for (i=0; i*16< sizeof(pt);i++){
				print_hexstr("%04X0:", i, dst[i]);
			}
		}
		if (1) {
			uint8x16_t tag =
			MGM128_tag(&ciph, aad, sizeof(aad), (uint8_t *)dst, sizeof(pt));
			print_hex("Tag:\n%04X0:", 0, tag);
		}
		if (0) {
			uint8x16_t tag ={0};
			int i, count = 100000;
			for (i=0; i<count; i++){
				tag ^= MGM128_tag(&ciph, aad, sizeof(aad), (uint8_t *)dst, sizeof(pt));
			}
			
			print_hex("Tag:\n%04X0:", 0, tag);
			printf("%d\n", (sizeof(pt)+sizeof(aad))*count);
		}
	}
	if (1) {// https://datatracker.ietf.org/doc/html/draft-smyshlyaev-mgm-20
		printf(
		"[RFC????] Smyshlyaev, et al. Multilinear Galois Mode (MGM), April 2021\n"
		"A.1.  Test Vectors for the Kuznyechik block cipher\n");
		printf("--Example 1--\n");
		const uint8_t key1[] = 
		"\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77"
		"\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF";
		uint8x16_t icn =
		{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88};
		const uint8_t aad[] =
		"\x02\x02\x02\x02\x02\x02\x02\x02\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x04\x04\x04\x04\x04\x04\x04\x04\x03\x03\x03\x03\x03\x03\x03\x03"
		"\xEA\x05\x05\x05\x05\x05\x05\x05\x05";
		const uint8_t pt[] =
		"\x11\x22\x33\x44\x55\x66\x77\x00\xFF\xEE\xDD\xCC\xBB\xAA\x99\x88"
		"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xEE\xFF\x0A"
		"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xEE\xFF\x0A\x00"
		"\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xEE\xFF\x0A\x00\x11"
		"\xAA\xBB\xCC";
		const uint8_t ct[] =
		"\xA9\x75\x7B\x81\x47\x95\x6E\x90\x55\xB8\xA3\x3D\xE8\x9F\x42\xFC"
		"\x80\x75\xD2\x21\x2B\xF9\xFD\x5B\xD3\xF7\x06\x9A\xAD\xC1\x6B\x39"
		"\x49\x7A\xB1\x59\x15\xA6\xBA\x85\x93\x6B\x5D\x0E\xA9\xF6\x85\x1C"
		"\xC6\x0C\x14\xD4\xD3\xF8\x83\xD0\xAB\x94\x42\x06\x95\xC7\x6D\xEB"
		"\x2C\x75\x52";
		const uint8_t tag[] =
		"\xCF\x5D\x65\x6F\x40\xC3\x4F\x5C\x46\xE8\xBB\x0E\x29\xFC\xDB\x4C";
		KuznCtx ctx;
		kuzn_key_expansion(&ctx, (uint8_t*)key1, 32,0);
		Ciph ciph;
		ciph.ctx = &ctx;
		ciph.iv = REV128(icn);
		uint8x16_t ct_[(sizeof(pt)+15)/16]= {0};
		MGM128_encrypt(&ciph, ct_, pt, sizeof(pt)-1);
		int i;
		printf("C:\n");
		for (i=0; i*16< sizeof(pt)-1;i++){
			print_hexstr("%04X0:", i, ct_[i]);
		}
		if (__builtin_memcmp(ct, ct_, sizeof(ct)-1)==0) printf("..ok\n");
		uint8x16_t T = 
		MGM128_tag(&ciph, aad, sizeof(aad)-1, ct, sizeof(ct)-1);
		printf("Tag T:\n");
		print_hexstr("%04X0:", 0, T);
		if (__builtin_memcmp(&T, tag, sizeof(tag)-1)==0) printf("..ok\n");
if (1){
		uint64_t ts;
		ts = __builtin_ia32_rdtsc();
		for (i=0; i< 1000000; i++) {
			MGM128_encrypt(&ciph, ct_, pt, 64);
		}
		ts -= __builtin_ia32_rdtsc();
		printf("Enc  : ts = %d\n", -ts/1000000/64);

		ts = __builtin_ia32_rdtsc();
		for (i=0; i< 1000000; i++) {
			T ^= 
			MGM128_tag(&ciph, aad, sizeof(aad)-1, ct, 64);
		}
		ts -= __builtin_ia32_rdtsc();
		printf("Tag T: ts = %d\n", -ts/1000000/64);
		print_hexstr("%04X0:", 0, T);
}
		printf("--Example 2--\n");
		const uint8_t key2[] = 
		"\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77\xFE"
		"\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF\x88";
		uint8x16_t icn2 =
		{0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x00,0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88};
		ciph.iv = REV128(icn2);
		kuzn_key_expansion(&ctx, (uint8_t*)key2, 32,0);
		const uint8_t aad2[] =
		"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";
		const uint8_t tag2[] =
		"\x79\x01\xE9\xEA\x20\x85\xCD\x24\x7E\xD2\x49\x69\x5F\x9F\x8A\x85";
		T = 
		MGM128_tag(&ciph, aad2, sizeof(aad2)-1, ct, 0);
		printf("Tag T:\n");
		print_hexstr("%04X0:", 0, T);
		if (__builtin_memcmp(&T, tag2, sizeof(tag2)-1)==0) printf("..ok\n");
	}
}
