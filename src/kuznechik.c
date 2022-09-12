/*! TC26 кузнечик
	ГОСТ Р 34.12-2015 Информационная технология. КРИПТОГРАФИЧЕСКАЯ ЗАЩИТА ИНФОРМАЦИИ. Блочные шифры
	[RFC7801] GOST R 34.12-2015: Block Cipher "Kuznyechik" March 2016

__builtin_ia32_vpclmulqdq_v4di
__builtin_ia32_vpclmulqdq_v8di


Полиномы нередуцируемые
11B: x^8 + x^4 + x^3 + x^1 + 1
11D: x^8 + x^4 + x^3 + x^2 + 1
12B: x^8 + x^5 + x^3 + x^1 + 1
12D: x^8 + x^5 + x^3 + x^2 + 1
139: x^8 + x^5 + x^4 + x^3 + 1
x^8 + x^5 + x^4 + x^3 + x^2 + x^1 + 1
14D: x^8 + x^6 + x^3 + x^2 + 1
15F: x^8 + x^6 + x^4 + x^3 + x^2 + x^1 + 1
163: x^8 + x^6 + x^5 + x^1 + 1
165: x^8 + x^6 + x^5 + x^2 + 1
169: x^8 + x^6 + x^5 + x^3 + 1
171: x^8 + x^6 + x^5 + x^4 + 1
x^8 + x^6 + x^5 + x^4 + x^2 + x^1 + 1
x^8 + x^6 + x^5 + x^4 + x^3 + x^1 + 1
187: x^8 + x^7 + x^2 + x^1 + 1
18B: x^8 + x^7 + x^3 + x^1 + 1
18D: x^8 + x^7 + x^3 + x^2 + 1
x^8 + x^7 + x^4 + x^3 + x^2 + x^1 + 1
x^8 + x^7 + x^5 + x^1 + 1
x^8 + x^7 + x^5 + x^3 + 1
x^8 + x^7 + x^5 + x^4 + 1
x^8 + x^7 + x^5 + x^4 + x^3 + x^2 + 1
1C3: x^8 + x^7 + x^6 + x^1 + 1 -- этот
x^8 + x^7 + x^6 + x^3 + x^2 + x^1 + 1
x^8 + x^7 + x^6 + x^4 + x^2 + x^1 + 1
x^8 + x^7 + x^6 + x^4 + x^3 + x^2 + 1
1E7: x^8 + x^7 + x^6 + x^5 + x^2 + x^1 + 1
1F3: x^8 + x^7 + x^6 + x^5 + x^4 + x^1 + 1
1F5: x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1
1F9: x^8 + x^7 + x^6 + x^5 + x^4 + x^3 + 1

x^16 + x^9 + x^8 + x^7 + x^6 + x^4 + x^3 + x^2 + 1
1100B: x^16 + x^12 + x^3 + x^1 + 1
11085: x^16 + x^12 + x^7 + x^2 + 1
x^16 + x^13 + x^12 + x^10 + x^9 + x^7 + x^6 + x^1 + 1
x^16 + x^13 + x^12 + x^11 + x^7 + x^6 + x^3 + x^1 + 1
x^16 + x^13 + x^12 + x^11 + x^10 + x^6 + x^2 + x^1 + 1
1450B: x^16 + x^14 + x^10 + x^8 + x^3 + x^1 + 1
x^16 + x^14 + x^13 + x^12 + x^6 + x^5 + x^3 + x^2 + 1
17481: x^16 + x^14 + x^13 + x^12 + x^10 + x^7 + 1
1846F: x^16 + x^15 + x^10 + x^6 + x^5 + x^3 + x^2 + x^1 + 1
x^16 + x^15 + x^11 + x^9 + x^8 + x^7 + x^5 + x^4 + x^2 + x^1 + 1
x^16 + x^15 + x^11 + x^10 + x^7 + x^6 + x^5 + x^3 + x^2 + x^1 + 1
x^16 + x^15 + x^11 + x^10 + x^9 + x^6 + x^2 + x^1 + 1
x^16 + x^15 + x^11 + x^10 + x^9 + x^8 + x^6 + x^4 + x^2 + x^1 + 1

 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "cipher.h"


#if __ARM_NEON
#include <arm_neon.h>
/*Advanced SIMD intrinsics are now available to use.
Есть предложение использовать
 */

// переворот вектора
static inline uint8x16_t REV(uint8x16_t v) {
	v = vrev64q_u8(v);
	return vextq_u64(v,v,8);
}

#else
typedef uint8_t uint8x16_t __attribute__((__vector_size__(16)));
typedef  int8_t  int8x16_t __attribute__((__vector_size__(16)));
// переворот вектора
static inline uint8x16_t REV(uint8x16_t v) {
#if defined(__clang__) //&&  __has_builtin(__builtin_shufflevector)
    return __builtin_shufflevector((uint8x16_t)(v),(uint8x16_t)(v),15,14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
#else
    return __builtin_shuffle(v, (uint8x16_t){15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0});
#endif // __clang__
}

#endif
static inline int EQU128(uint8x16_t a, uint8x16_t  b) {
	return __builtin_memcmp(&a, &b, 16)==0;
}
typedef uint32_t v2si __attribute__((__vector_size__(8)));
//typedef uint8_t v16qi __attribute__((__vector_size__(16)));
typedef  int64_t v2di __attribute__((__vector_size__(16)));
typedef  int64_t v2du __attribute__((__vector_size__(16)));
typedef uint16_t v8hu __attribute__((__vector_size__(16)));

/* типы данных для полиномиальных операций */
typedef uint8_t  poly8x16_t __attribute__((__vector_size__(16)));
typedef uint16_t poly16x8_t __attribute__((__vector_size__(16)));
typedef uint64_t poly64x2_t __attribute__((__vector_size__(16)));
typedef uint64_t uint64x2_t __attribute__((__vector_size__(16)));

//typedef uint16_t v16hi __attribute__((__vector_size__(32)));
typedef struct _KuznCtx KuznCtx;
struct _KuznCtx {
    uint8x16_t K[10];
};
/*! 4.1.1 Нелинейное биективное преобразование */
static uint8_t sbox[] = {
252, 238, 221,  17, 207, 110,  49,  22, 251, 196, 250, 218,  35, 197,   4,  77, 233,
119, 240, 219, 147,  46, 153, 186,  23,  54, 241, 187,  20, 205,  95, 193, 249,  24, 101,
90, 226, 92, 239, 33, 129, 28, 60,  66, 139,   1, 142,  79,   5, 132,   2, 174, 227, 106, 143,
160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42,
104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156,
183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178,
177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223,
245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236,
222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0,
98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163,
165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136,
217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133,
97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166,
116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182
};
/*! обратное преобразование Sbox-1 */
static uint8_t sbox_[] = {
0xa5,0x2d,0x32,0x8f,0x0e,0x30,0x38,0xc0,0x54,0xe6,0x9e,0x39,0x55,0x7e,0x52,0x91,
0x64,0x03,0x57,0x5a,0x1c,0x60,0x07,0x18,0x21,0x72,0xa8,0xd1,0x29,0xc6,0xa4,0x3f,
0xe0,0x27,0x8d,0x0c,0x82,0xea,0xae,0xb4,0x9a,0x63,0x49,0xe5,0x42,0xe4,0x15,0xb7,
0xc8,0x06,0x70,0x9d,0x41,0x75,0x19,0xc9,0xaa,0xfc,0x4d,0xbf,0x2a,0x73,0x84,0xd5,
0xc3,0xaf,0x2b,0x86,0xa7,0xb1,0xb2,0x5b,0x46,0xd3,0x9f,0xfd,0xd4,0x0f,0x9c,0x2f,
0x9b,0x43,0xef,0xd9,0x79,0xb6,0x53,0x7f,0xc1,0xf0,0x23,0xe7,0x25,0x5e,0xb5,0x1e,
0xa2,0xdf,0xa6,0xfe,0xac,0x22,0xf9,0xe2,0x4a,0xbc,0x35,0xca,0xee,0x78,0x05,0x6b,
0x51,0xe1,0x59,0xa3,0xf2,0x71,0x56,0x11,0x6a,0x89,0x94,0x65,0x8c,0xbb,0x77,0x3c,
0x7b,0x28,0xab,0xd2,0x31,0xde,0xc4,0x5f,0xcc,0xcf,0x76,0x2c,0xb8,0xd8,0x2e,0x36,
0xdb,0x69,0xb3,0x14,0x95,0xbe,0x62,0xa1,0x3b,0x16,0x66,0xe9,0x5c,0x6c,0x6d,0xad,
0x37,0x61,0x4b,0xb9,0xe3,0xba,0xf1,0xa0,0x85,0x83,0xda,0x47,0xc5,0xb0,0x33,0xfa,
0x96,0x6f,0x6e,0xc2,0xf6,0x50,0xff,0x5d,0xa9,0x8e,0x17,0x1b,0x97,0x7d,0xec,0x58,
0xf7,0x1f,0xfb,0x7c,0x09,0x0d,0x7a,0x67,0x45,0x87,0xdc,0xe8,0x4f,0x1d,0x4e,0x04,
0xeb,0xf8,0xf3,0x3e,0x3d,0xbd,0x8a,0x88,0xdd,0xcd,0x0b,0x13,0x98,0x02,0x93,0x80,
0x90,0xd0,0x24,0x34,0xcb,0xed,0xf4,0xce,0x99,0x10,0x44,0x40,0x92,0x3a,0x01,0x26,
0x12,0x1a,0x48,0x68,0xf5,0x81,0x8b,0xc7,0xd6,0x20,0x0a,0x08,0x00,0x4c,0xd7,0x74
};
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
/* матрица преобразования L = LM*A */
#if 0
static v16qi LM [16] = {
    {0x01,0x94,0x20,0x85,0x10,0xc2,0xc0,0x01,0xfb,0x01,0xc0,0xc2,0x10,0x85,0x20,0x94},
    {0x94,0xa5,0x3c,0x44,0xd1,0x8d,0xb4,0x54,0xde,0x6f,0x77,0x5d,0x96,0x74,0x2d,0x84},
    {0x84,0x64,0x48,0xdf,0xd3,0x31,0xa6,0x30,0xe0,0x5a,0x44,0x97,0xca,0x75,0x99,0xdd},
    {0xdd,0x0d,0xf8,0x52,0x91,0x64,0xff,0x7b,0xaf,0x3d,0x94,0xf3,0xd9,0xd0,0xe9,0x10},
    {0x10,0x89,0x48,0x7f,0x91,0xec,0x39,0xef,0x10,0xbf,0x60,0xe9,0x30,0x5e,0x95,0xbd},
    {0xbd,0xa2,0x48,0xc6,0xfe,0xeb,0x2f,0x84,0xc9,0xad,0x7c,0x1a,0x68,0xbe,0x9f,0x27},
    {0x27,0x7f,0xc8,0x98,0xf3,0x0f,0x54,0x08,0xf6,0xee,0x12,0x8d,0x2f,0xb8,0xd4,0x5d},
    {0x5d,0x4b,0x8e,0x60,0x01,0x2a,0x6c,0x09,0x49,0xab,0x8d,0xcb,0x14,0x87,0x49,0xb8},
    {0xb8,0x6e,0x2a,0xd4,0xb1,0x37,0xaf,0xd4,0xbe,0xf1,0x2e,0xbb,0x1a,0x4e,0xe6,0x7a},
    {0x7a,0x16,0xf5,0x52,0x78,0x99,0xeb,0xd5,0xe7,0xc4,0x2d,0x06,0x17,0x62,0xd5,0x48},
    {0x48,0xc3,0x02,0x0e,0x58,0x90,0xe1,0xa3,0x6e,0xaf,0xbc,0xc5,0x0c,0xec,0x76,0x6c},
    {0x6c,0x4c,0xdd,0x65,0x01,0xc4,0xd4,0x8d,0xa4,0x02,0xeb,0x20,0xca,0x6b,0xf2,0x72},
    {0x72,0xe8,0x14,0x07,0x49,0xf6,0xd7,0xa6,0x6a,0xd6,0x11,0x1c,0x0c,0x10,0x33,0x76},
    {0x76,0xe3,0x30,0x9f,0x6b,0x30,0x63,0xa1,0x2b,0x1c,0x43,0x68,0x70,0x87,0xc8,0xa2},
    {0xa2,0xd0,0x44,0x86,0x2d,0xb8,0x64,0xc1,0x9c,0x89,0x48,0x90,0xda,0xc6,0x20,0x6e},
    {0x6e,0x4d,0x8e,0xea,0xa9,0xf6,0xbf,0x0a,0xf3,0xf2,0x8e,0x93,0xbf,0x74,0x98,0xcf},
};
#endif
/* транспонированная матрица преобразования L = LM*A */
static const uint8x16_t LMT[16] = {
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
/*! вариант таблицы */
static const v8hu LMTh[32] = {
{0x01,	0x94,	0x84,	0xdd,	0x10,	0xbd,	0x27,	0x5d}, {0xb8,	0x7a,	0x48,	0x6c,	0x72,	0x76,	0xa2,	0x6e},
{0x94,	0xa5,	0x64,	0x0d,	0x89,	0xa2,	0x7f,	0x4b}, {0x6e,	0x16,	0xc3,	0x4c,	0xe8,	0xe3,	0xd0,	0x4d},
{0x20,	0x3c,	0x48,	0xf8,	0x48,	0x48,	0xc8,	0x8e}, {0x2a,	0xf5,	0x02,	0xdd,	0x14,	0x30,	0x44,	0x8e},
{0x85,	0x44,	0xdf,	0x52,	0x7f,	0xc6,	0x98,	0x60}, {0xd4,	0x52,	0x0e,	0x65,	0x07,	0x9f,	0x86,	0xea},
{0x10,	0xd1,	0xd3,	0x91,	0x91,	0xfe,	0xf3,	0x01}, {0xb1,	0x78,	0x58,	0x01,	0x49,	0x6b,	0x2d,	0xa9},
{0xc2,	0x8d,	0x31,	0x64,	0xec,	0xeb,	0x0f,	0x2a}, {0x37,	0x99,	0x90,	0xc4,	0xf6,	0x30,	0xb8,	0xf6},
{0xc0,	0xb4,	0xa6,	0xff,	0x39,	0x2f,	0x54,	0x6c}, {0xaf,	0xeb,	0xe1,	0xd4,	0xd7,	0x63,	0x64,	0xbf},
{0x01,	0x54,	0x30,	0x7b,	0xef,	0x84,	0x08,	0x09}, {0xd4,	0xd5,	0xa3,	0x8d,	0xa6,	0xa1,	0xc1,	0x0a},
{0xfb,	0xde,	0xe0,	0xaf,	0x10,	0xc9,	0xf6,	0x49}, {0xbe,	0xe7,	0x6e,	0xa4,	0x6a,	0x2b,	0x9c,	0xf3},
{0x01,	0x6f,	0x5a,	0x3d,	0xbf,	0xad,	0xee,	0xab}, {0xf1,	0xc4,	0xaf,	0x02,	0xd6,	0x1c,	0x89,	0xf2},
{0xc0,	0x77,	0x44,	0x94,	0x60,	0x7c,	0x12,	0x8d}, {0x2e,	0x2d,	0xbc,	0xeb,	0x11,	0x43,	0x48,	0x8e},
{0xc2,	0x5d,	0x97,	0xf3,	0xe9,	0x1a,	0x8d,	0xcb}, {0xbb,	0x06,	0xc5,	0x20,	0x1c,	0x68,	0x90,	0x93},
{0x10,	0x96,	0xca,	0xd9,	0x30,	0x68,	0x2f,	0x14}, {0x1a,	0x17,	0x0c,	0xca,	0x0c,	0x70,	0xda,	0xbf},
{0x85,	0x74,	0x75,	0xd0,	0x5e,	0xbe,	0xb8,	0x87}, {0x4e,	0x62,	0xec,	0x6b,	0x10,	0x87,	0xc6,	0x74},
{0x20,	0x2d,	0x99,	0xe9,	0x95,	0x9f,	0xd4,	0x49}, {0xe6,	0xd5,	0x76,	0xf2,	0x33,	0xc8,	0x20,	0x98},
{0x94,	0x84,	0xdd,	0x10,	0xbd,	0x27,	0x5d,	0xb8}, {0x7a,	0x48,	0x6c,	0x72,	0x76,	0xa2,	0x6e,	0xcf},
};

//static const v16qi C3= {0xC3,0xC3,0xC3,0xC3, 0xC3,0xC3,0xC3,0xC3, 0xC3,0xC3,0xC3,0xC3, 0xC3,0xC3,0xC3,0xC3};
/*! умножение вектора на число в поле GF 2^8 c полиномом 0xС3
Всего 16+16 таблиц и можно преобразовать GMUL16C в две команды загрузки и один PXOR. 256*32 = 8kБ

 */

/*
static inline
v2du CL_MUL128(poly64x2_t a, poly64x2_t b, const uint8_t c) __attribute__ ((__target__("pclmul")));
static __inline __attribute__((always_inline))
v2du CL_MUL128(poly64x2_t a, poly64x2_t b, const uint8_t im) {
    return (v2du)__builtin_ia32_pclmulqdq128 ((v2di)a,(v2di)b, im);
}*/
#define CL_MUL128(a,b,im) (v2du)__builtin_ia32_pclmulqdq128 ((v2di)a,(v2di)b, im)




#if defined(__ARM_NEON)
static
uint8x16_t LS4(uint8x16_t a)
{
    poly16x8_t v0 = {0};
    poly16x8_t v1 = {0};
    for(i=0;i<16;i++){
        poly8x8_t a8 = vdup_n_p8(a[i]);
        v0 ^= vmull_p8(a8, vgetq_high_p8((poly8x16_t)LMT[i]));
        v1 ^= vmull_p8(a8, vgetq_low_p8 ((poly8x16_t)LMT[i]));
    }
    /// редуцирование вынесли из цикла
    poly8x8_t t0, t1;
    t0 = (poly8x8_t) vshrn_n_u16(v0, 8);
    poly16x8_t t = vmull_p8(t0,(poly8x8_t)0xB5) ^ v0;
    t0 = (poly8x8_t) vshrn_n_u16(t, 8);/// сдвиг вправо с заужением
    v0^= vmull_p8(t0, (poly8x8_t)0xC3);

    t1 = (poly8x8_t) vshrn_n_u16(v1, 8);
    t  = vmull_p8(t0, (poly8x8_t)0xB5) ^ v1;
    t1 = (poly8x8_t) vshrn_n_u16(t, 8);/// сдвиг вправо с заужением
    v1^= vmull_p8(t0, (poly8x8_t)0xC3);
    return vcombine_u8(vmovn_u16(v0), vmovn_u16(v1));
}
#endif // __ARM_NEON

//#define CL_MUL128 __builtin_ia32_pclmulqdq128
//#pragma GCC optimize ("Os")
#if 0 // вариант рабочий
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
		a16[0] = a[i];//(poly64x2_t)(v2di){a[i],a[i]};
		poly64x2_t L = (poly64x2_t)UNPACKLBW128((int8x16_t)LMT[i], Z);
		poly64x2_t H = (poly64x2_t)UNPACKHBW128((int8x16_t)LMT[i], Z);
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

#else
static
uint8x16_t LS4(uint8x16_t a)
{
    int i;
    v2di v0 = {0};
    v2di v1 = {0};
    v2di v2 = {0};
    v2di v3 = {0};
    poly64x2_t a16={0};
    for(i=0;i<16;i+=2){
		a16[0] = a[i];//(poly64x2_t)(v2di){a[i],a[i]};
		a16[1] = a[i+1];//(poly64x2_t)(v2di){a[i],a[i]};
        v0 ^= CL_MUL128(a16, (poly64x2_t)LMTh[2*i+0], 0x00);
        v1 ^= CL_MUL128(a16, (poly64x2_t)LMTh[2*i+0], 0x10);
        v2 ^= CL_MUL128(a16, (poly64x2_t)LMTh[2*i+1], 0x00);
        v3 ^= CL_MUL128(a16, (poly64x2_t)LMTh[2*i+1], 0x10);
        v0 ^= CL_MUL128(a16, (poly64x2_t)LMTh[2*i+2], 0x01);
        v1 ^= CL_MUL128(a16, (poly64x2_t)LMTh[2*i+2], 0x11);
        v2 ^= CL_MUL128(a16, (poly64x2_t)LMTh[2*i+3], 0x01);
        v3 ^= CL_MUL128(a16, (poly64x2_t)LMTh[2*i+3], 0x11);
    }
    /// редуцирование вынесли из цикла
    v2di t;
    const poly64x2_t KBP = {0x1B5, 0x1C3}; // коэффициенты редукции Barrett'a
    t  = CL_MUL128((poly64x2_t)((v8hu)v0>>8),KBP, 0x00);
    v0^= CL_MUL128((poly64x2_t)((v8hu)t>>8), KBP, 0x10);
    t  = CL_MUL128((poly64x2_t)((v8hu)v1>>8),KBP, 0x00);
    v1^= CL_MUL128((poly64x2_t)((v8hu)t>>8), KBP, 0x10);
    t  = CL_MUL128((poly64x2_t)((v8hu)v2>>8),KBP, 0x00);
    v2^= CL_MUL128((poly64x2_t)((v8hu)t>>8), KBP, 0x10);
    t  = CL_MUL128((poly64x2_t)((v8hu)v3>>8),KBP, 0x00);
    v3^= CL_MUL128((poly64x2_t)((v8hu)t>>8), KBP, 0x10);
#ifdef __clang__
    v0 = (v2di)__builtin_shufflevector((uint8x16_t)v0,(uint8x16_t)v1, 0,2,4,6,16,18,20,22,0,0,0,0,0,0,0,0);
    v1 = (v2di)__builtin_shufflevector((uint8x16_t)v2,(uint8x16_t)v3, 0,2,4,6,16,18,20,22,0,0,0,0,0,0,0,0);
#else
    v0 = (v2di)__builtin_shuffle((uint8x16_t)v0,(uint8x16_t)v1, (uint8x16_t){0,2,4,6,16,18,20,22});
    v1 = (v2di)__builtin_shuffle((uint8x16_t)v2,(uint8x16_t)v3, (uint8x16_t){0,2,4,6,16,18,20,22});
#endif // __clang__
    return (uint8x16_t)(v2di){v0[0], v1[0]};
}
#endif
#if 1
/*! \brief вариант функции параллельного умножения GF(2^8)

    для отладки операции, использует редуцирование barrett'a
    финальное редуцирование можно вынести из цикла
 */
static
uint8x16_t GMUL16C_4(const uint8x16_t m, uint8_t a) {
    const poly64x2_t KBP = {0x1B5, 0x1C3}; // коэффициенты редукции Barrett'a
    v2di r,r1, v, t;
    poly64x2_t m0 = (poly64x2_t)__builtin_shuffle(m, (uint8x16_t){0}, (uint8x16_t){0,16,2,18,4,20,6,22,8,24,10,26,12,28,14,30});
    poly64x2_t m1 = (poly64x2_t)__builtin_shuffle(m, (uint8x16_t){0}, (uint8x16_t){1,17,3,19,5,21,7,23,9,25,11,27,13,29,15,31});
    v = CL_MUL128((poly64x2_t)(v2du){ a }, m0, 0x00);
    t = CL_MUL128((poly64x2_t)((v8hu)v>>8), KBP, 0x00);
    v^= CL_MUL128((poly64x2_t)((v8hu)t>>8), KBP, 0x10);
    r = v;
    v = CL_MUL128((poly64x2_t){ a }, m0, 0x10);
    t = CL_MUL128((poly64x2_t)((v8hu)v>>8), KBP, 0x00);
    v^= CL_MUL128((poly64x2_t)((v8hu)t>>8), KBP, 0x10);
    r1= v;
    v = CL_MUL128((poly64x2_t){ a }, m1, 0x00);
    t = CL_MUL128((poly64x2_t)((v8hu)v>>8), KBP, 0x00);
    v^= CL_MUL128((poly64x2_t)((v8hu)t>>8), KBP, 0x10);
    r^= v<<8;
    v = CL_MUL128((poly64x2_t){ a }, m1, 0x10);
    t = CL_MUL128((poly64x2_t)((v8hu)v>>8), KBP, 0x00);
    v^= CL_MUL128((poly64x2_t)((v8hu)t>>8), KBP, 0x10);
    r1^= v<<8;
	return (uint8x16_t)(v2di){r[0], r1[0]};
}
/*! \brief вариант функции параллельного умножения GF(2^8)
    для отладки операции, использует редуцирование barrett'a
 */

static inline
uint32_t CL_MUL16L(const uint32_t a, const uint32_t b)
{
	v2di r = CL_MUL128((poly64x2_t){a}, (poly64x2_t){ b}, 0x00);
	return (r[0] & 0xFFFF);
}
static inline
uint8_t GMUL1C3(const uint8_t m, uint8_t a) {
	uint32_t v = CL_MUL16L(m, a);
	uint32_t t = CL_MUL16L(v>>8, 0x1B5);// barrett U
	v^=CL_MUL16L(t>>8, 0x1C3);// Poly
	//if (v>255) printf("#");
	return v;
}

static
uint8x16_t GMUL16C(const uint8x16_t m, uint8_t a) {
	int i;
	uint8x16_t r;
	for (i=0;i<16;i++)
		r[i] = GMUL1C3(m[i], a);
	return r;
}
/*! \brief этот вариант функции параллельного умножения GF(2^8)
    если на платформе нет операции умножения без переноса
 */
static
uint8x16_t GMUL16C_(const uint8x16_t m, uint8_t a)
{
    int i;
    uint8x16_t v = {a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a};
    //v = __builtin_shuffle(v, (v16qi){0});
    //v = v & m
    uint8x16_t r;
    r = ((uint8x16_t)(v>127) & m);
    for(i=0;i<7;i++){
        v = v+v;
        //r = (r+r) ^ ((v16qi)(v>127) & m) ^ ((v16qi)(r>127) & 0xC3);// v+=v;
        r = (r+r) /* ^ ((v16qi)(v>127) & m)*/ ^ ((uint8x16_t)(r>127) & 0xC3);
        r ^= ((uint8x16_t)(v>127) & m);
		//m  = (m<<1) ^ ((v16qi)(m>127) & 0xC3);
		//m  = (m<<1) ^ ((v16qi)(m>127) & 0xC3);
		//m  = (m<<1) ^ ((v16qi)(m>>7) & 0xC3);
    }
    return r;
}
#include "kuznechik.h" // таблицы

static
uint8x16_t LS4_1(uint8x16_t a)
{
    uint8x16_t r={0};
    int i;
    for(i=0;i<16;i++)
        r ^= GMUL16C_4(LMT[i], a[i]);
    return r;
}
// этот вариант демонстрирует возможность разложения, функция линейна
static
uint8x16_t LS4_2(uint8x16_t a)
{// рабочий вариант
    uint8x16_t r={0};
    int i;
    for(i=0;i<16;i++)
        r ^= GMUL16C_4(LMT[i], a[i] & 0xF) ^ GMUL16C_4(LMT[i], a[i] & 0xF0);
    return r;
}
//v2di _LH[16][256];
static
uint8x16_t LS4_(uint8x16_t a)
{
    uint8x16_t r={0};//, rh={0};
    int i;
    for(i=0;i<16;i++) {
        unsigned int aa = a[i];
        //unsigned int aa = sbox[a[i]];
        //r ^= (v16qi)(_LH[i][aa]);
        r ^= (uint8x16_t)(_L[i][aa & 0xF]) ^ (uint8x16_t)(_H[i][(aa>>4) & 0xF]);
    }
    return (uint8x16_t)r;// ^ rh;
}
#if 0
void __attribute__((constructor)) init_(){

    uint32_t a,i;
    printf("v2di _L[16][16] = {\n");
    for (i=0; i<16; i++) {
        printf("[%d] = {\n", i);
        for (a=0; a<16; a++) {
            v2du v = (v2du) GMUL16C_4(LMT[i], a);
            printf("  {0x%016llX, 0x%016llX},\n", v[0],v[1]);
        }
        printf(" },\n");
    }
    printf("};\n");
    printf("v2di _H[16][16] = {\n");
    for (i=0; i<16; i++) {
        printf("[%d] = {\n", i);
        for (a=0; a<256; a+=16) {
            v2du v = (v2du) GMUL16C_4(LMT[i], a & 0xF0);
            printf("  {0x%016llX, 0x%016llX},\n", v[0],v[1]);
        }
        printf(" },\n");
    }
    printf("};\n");
}
#endif // 0
#endif // 0

#ifdef TEST_KUZN
static uint8_t gmul(uint8_t a, uint8_t m)
{
    int i;
    uint8_t r=0;
    for(i=0;i<8;i++){
        if (a&(1<<i)) r ^= m;
        m  = (m<<1) ^ (m>127?0xC3:0);
        //m = (m<<1) ^ v;//((m>>7) & 0xC3);/* расширение знака */
    }
    return r;
}
/*!
    для генереации таблиц используется свойство
 */
void CC(uint8_t* v,uint8_t* a, int idx) {
    int j,i;
    uint8_t r;
    for(j=0; j<16;j++){
        r = j<idx?0:a[j-idx];
        uint8_t c = 148;
        int8_t m = a[j];
        for (i=0; i<8; i++){
            if (c & (1<<i)) r ^= m;
            m = (m<<1) ^ ((m>>7) & 0xC3);
        }
        v[j] = r;
    }
}
void CC2(uint8_t *a, int idx)
{
    int j,k;
    uint8_t r;
    for(j=0; j<16;j++){
        r = j<idx?0:a[j-idx];
        for (k=0; k<idx; k++){
            uint8_t c = a[16-idx+k];// коэффициенты по первой строке таблицы
            int8_t m = a[k*16+j]; //все выше по колонке
            r ^= gmul(m,c);
/*
            for (i=0; i<8; i++){
                if (c & (1<<i)) r ^= m;
                m = (m<<1) ^ ((m>>7) & 0xC3);
            } */
        }
        a[idx*16+j] = r;
    }
}
static const uint8_t Co[] = {1, 148, 32,133,16,194,192,1,251,1,192,194,16,133,32,148};
uint8x16_t R(uint8x16_t a, const uint8_t* C)
{
    uint8_t r = 0;//v[0];
    int j;

    for(j=0; j<16;j++){
        uint8_t m = a[j];
        r ^= gmul(m, C[j]);
    }
    uint8x16_t v = __builtin_shuffle(a, (uint8x16_t){1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0});
//    for(j=0; j<15;j++) v[j] = a[j+1];
    v[15] = r;
    return v;
}
/*! преобразование, обратное к преобразованию R */
static uint8x16_t R_(uint8x16_t a, const uint8_t* C)
{
    a = REV(a);
    a = R(a,C);
    a = REV(a);
    return a;
}
#endif // TEST_KUZN
#if 0
v16qi L_(v16qi a)
{
    int i;
    for (i=0; i< 16;i++) a = R_(a,Co);
    return a;
}
#endif
static uint8x16_t SL_(uint8x16_t a)
{
    int i;
    uint8x16_t v = LS4(a);
    for (i=0; i< 16;i++) a[i] = sbox_[v[i]];
    return a;
}
static uint8x16_t LS(uint8x16_t a)
{
    int i;
    for(i=0; i< 16;i++) a[i] = sbox[a[i]];
    uint8x16_t v = LS4(a);
    return v;
}

static
uint8x16_t kuzn_encrypt(KuznCtx* ctx, const uint8x16_t a)
{
    uint8x16_t S = a^ctx->K[0];
    int i;
    for (i=0; i<9; i++){
        S = LS(S) ^ ctx->K[i+1];
    }
    return S;// ^ ctx->K[9];
}
static
uint8x16_t kuzn_decrypt(KuznCtx* ctx, const uint8x16_t a)
{
    uint8x16_t S = REV(a);
    int i;
    for (i=0; i<9; i++){
        S = SL_(S ^ REV(ctx->K[9-i]));
    }
    return REV(S) ^ ctx->K[0];
}

/*! разгибание ключа
    Nk -- длина ключа 4 слова (128 бит)
 */
#if 0
static void kuzn_key_expansion_(KuznCtx * ctx, uint8_t* key, int klen, int ekb)
{
    uint8x16_t *K = ctx->K;
    __builtin_memcpy(&K[0],&key[16], 16);
    __builtin_memcpy(&K[1],&key[ 0], 16);
    uint8x16_t a = K[0];
    uint8x16_t b = K[1];
    int j, n = 0;
    for(j=2; j<9; j+=2) {
        int i;
        for (i=0;i<8;i+=2){
            /* можно вычислять констранты налету
            Сx = L((v16qi){n+1,0...0})
            */
            //register uint8x16_t v = a;
            b = LS(a ^ Cx[n++]) ^ b;
            a = LS(b ^ Cx[n++]) ^ a;
            //b = v;
        }
        K[j] = a; K[j+1] = b;
    }
}
#endif
static void kuzn_key_expansion(KuznCtx * ctx, const uint8_t* key, int klen, int ekb)
{
    uint8x16_t *K = ctx->K;
	uint8x16_t a, b;
    K[0] = a = REV(*(uint8x16_t*)(key+0));//__builtin_memcpy(&K[0],&key[16], 16);
    K[1] = b = REV(*(uint8x16_t*)(key+16));//__builtin_memcpy(&K[1],&key[ 0], 16);
    int j, n = 0;
    for(j=2; j<9; j+=2) {
        int i;
        for (i=0;i<8;i+=2){
            /* можно вычислять констранты налету
            Сx = L((v16qi){n+1,0...0})
            */
            //register uint8x16_t v = a;
            b = LS(a ^ Cx[n++]) ^ b;
            a = LS(b ^ Cx[n++]) ^ a;
            //b = v;
        }
        K[j] = a; K[j+1] = b;
    }
}

// Обмен ключами, вынести куда-нибудь в отдельный файл
/*! \brief кручение ключа */
void kuzn_ACPKM(KuznCtx * ctx)
{
	const uint8_t d[] =
		"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F"
		"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F";
	uint8_t* src = (uint8_t*)d;
	uint8x16_t k[2];
	int i;
	for (i=0; i<2; i++) {
		uint8x16_t v = REV(*(uint8x16_t*) src); src+=16;
		v = kuzn_encrypt(ctx, v);
		k[i] = REV(v);
	}
	kuzn_key_expansion(ctx, (uint8_t*) k, 32, 0);
if(0) {
	src = (uint8_t*)k;
	for (i=0; i< 32; i++) {
		printf(" %02X", src[i]);
		if ((i&0xF)==0xF) printf("\n");
	}
	printf("\n");
}
}
/*! \brief Режим гаммирования с кручением ключа */
void kuzn_ctr_acpkm(KuznCtx * ctx,  uint64_t iv, uint8_t* data, size_t len)
{
    const int n=2;// частота смены ключа
	uint8x16_t m,v;
    uint64x2_t ctr;
    ctr[0] =  0;
    ctr[1] = iv;
	int i=0, j=0;
    int blocks = (len)>>4;
	for (; i<blocks; i++){
		__builtin_memcpy(&v, &data[16*i], 16);
		m = kuzn_encrypt(ctx, (uint8x16_t)ctr);
		v^= REV(m);
		__builtin_memcpy(&data[16*i], &v, 16);
		ctr[0]++;
		if (++j==n) {
			kuzn_ACPKM(ctx);
			j=0;
		}
	}
	int r = len&0xF;
	if (r){
		__builtin_memcpy(&v, &data[16*i], r);
		m = kuzn_encrypt(ctx, (uint8x16_t)ctr);
		v^= REV(m);
		__builtin_memcpy(&data[16*i], &v, r);
	}
}


/*! \brief Режим гаммирования */
void kuzn_ctr(KuznCtx * ctx, uint64_t iv, uint8_t* data, size_t len)
{
	uint8x16_t m,v;
	uint64x2_t ctr;
    ctr[0] =  0;
    ctr[1] = iv;
	int i;
    int blocks = (len)>>4;
	for (i=0; i<blocks; i++){
		__builtin_memcpy(&v, &data[16*i], 16);
		m = kuzn_encrypt(ctx, (uint8x16_t)ctr);
		v^= REV(m);
		__builtin_memcpy(&data[16*i], &v, 16);
		ctr[0]++;
	}
	int r = len&0xF;
	if (r){
		__builtin_memcpy(&v, &data[16*i], r);
		m = kuzn_encrypt(ctx, (uint8x16_t)ctr);
		v^= REV(m);
		__builtin_memcpy(&data[16*i], &v, r);
	}
}
/*! \brief Режим выработки имитовставки */

typedef struct _CCM CCM_t;
struct _CCM {
    uint8x16_t last_block;
    uint8x16_t sum;
    KuznCtx *ctx;
    uint32_t len;
};
static void kuzn_cmac_init(CCM_t *ctx, KuznCtx * kctx)
{
    ctx->ctx = kctx;
    ctx->last_block = (uint8x16_t){0};
    ctx->sum = (uint8x16_t){0};
    ctx->len = 0;
}
/*! \brief */
static void kuzn_cmac_update(CCM_t *ctx, uint8_t* data, size_t len)
{
    const unsigned int s=16;
    if ((ctx->len %s)!=0) {// не полный блок.
        int slen = s - ctx->len; // длину берем из данных
        if (slen > len) slen = len;
        __builtin_memcpy(((uint8_t*)&ctx->last_block) + ctx->len, data, slen);
        data+=slen;
        len -=slen;
        ctx->len += slen;
    }
    if (len>0) {
        uint8x16_t m = ctx->sum;
        if (ctx->len == s) {// полный блок и
            m^= REV(ctx->last_block);
            m = kuzn_encrypt(ctx->ctx, m);
            ctx->last_block = (uint8x16_t){0};
        }
        int blocks = (len-1)/s;// число целых блоков
        int i;
        for (i=0; i<blocks; i++){
            //printf("P = %016"PRIx64"\n", *(uint64_t*)data);
            uint8x16_t v;
            __builtin_memcpy(&v, data, s); data+=s;
            m^= REV(v);
            m = kuzn_encrypt(ctx->ctx, m);
        }
        ctx->sum = m;
        ctx->len = len - blocks*s;
        if (ctx->len) {
            __builtin_memcpy((uint8_t*)&ctx->last_block, data, ctx->len);
            //printf("L = %016"PRIx64"\n", ctx->last_block);
        }
    }
}
static uint8x16_t GF128_shift(uint8x16_t v)
{


//    v4si m = v>>31;
#if 0 // llvm
    v = (v4si)(((v16qi)v<<1) ^ (__builtin_shufflevector((v16qi)((v16qi)v<0),(v16qi)v, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0) & (v16qi){0x1,0x1,0x1,0x1, 0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1, 0x87})) ;
#else
    v = (uint8x16_t)(((int8x16_t)v<<1) ^ (__builtin_shuffle(((int8x16_t)v<0), (int8x16_t){15, 0, 1,2,3,4,5,6,7,8,9,10,11,12,13,14}) & (int8x16_t){0x87, 0x1,0x1,0x1,0x1, 0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1})) ;
#endif
    return v;
}
static uint8x16_t kuzn_cmac_fini(CCM_t *ctx)
{
    const int s=16;
	uint8x16_t K1 = kuzn_encrypt(ctx->ctx, (uint8x16_t){0});
	K1 = GF128_shift(K1);
	//printf("K1= %016"PRIx64"\n", K1);
	if (ctx->len%s) {// не полный блок
//		K1 = REV(GF128_shift(REV(K1)));
		K1 = GF128_shift(K1);
        ((uint8_t*)&ctx->last_block)[(ctx->len%s)] = 0x80;
	}
	uint8x16_t m = ctx->sum;
	m^= REV(ctx->last_block)^K1;
	return kuzn_encrypt(ctx->ctx, m);
}


uint8x16_t kuzn_cmac(KuznCtx* ctx, uint8_t *iv, size_t vlen, uint8_t* data, size_t len)
{
    CCM_t cc;
    kuzn_cmac_init(&cc, ctx);
    if (vlen) kuzn_cmac_update(&cc, iv, vlen);
    if (len) kuzn_cmac_update(&cc, data, len);
    return kuzn_cmac_fini(&cc);
}
/*! \brief Режим гаммирования с кручением ключа */
//void magma_ctr_acpkm(uint32_t *K, uint32_t iv, uint8_t* data, size_t len)
/*! \brief Алгоритм экспорта закрытого ключа KExp15
	\param data буфер обмена, на котором происходит шифрование ключа.
	K - экспортируемый ключ, копируется в буфер.
	\param klen - длина ключа. Длина выходного буфера должна быть не менее klen+8
	\param key_exp_mac - ключ выработки иммитовставки
	\param key_exp_enc - ключ шифрования экспортируемого ключа
	\param iv - вектор инициализации

	\see Р 1323565.1.017—2018  KExp15 KImp15
 */
void kuzn_KExp15(uint8_t* data, int klen,
	uint8_t* key_exp_mac, uint8_t* key_exp_enc, uint8_t* iv)
{
	const int iv_len = 8;
	KuznCtx ctx;
	kuzn_key_expansion(&ctx, key_exp_mac, 32, 0);
	uint8x16_t keymac = kuzn_cmac(&ctx, iv, iv_len, data, klen);
if (0) {
	printf("KEYMAC ", keymac);// 75A76618E90F4973
	int i;
	for(i=0; i<16; i++) printf(" %02X", keymac[i]);
	printf("\n");
}
	kuzn_key_expansion(&ctx, key_exp_enc, 32, 0);
	*(uint8x16_t* )(data+klen) = REV(keymac);
	kuzn_ctr(&ctx, __builtin_bswap64(*(uint64_t*)iv), data, klen+16);
}
/*! \brief Алгоритм импорта ключа KImp15
	\return TRUE если иммитовставка от ключа OMAC сходится.

	\see Р 1323565.1.017—2018  KExp15 KImp15
 */
int kuzn_KImp15(uint8_t* data, int klen,
	uint8_t* key_exp_mac, uint8_t* key_exp_enc, uint8_t* iv)
{
	const int iv_len = 8;
	KuznCtx ctx;
	kuzn_key_expansion(&ctx, key_exp_enc, 32, 0);
	kuzn_ctr(&ctx, __builtin_bswap64(*(uint64_t*)iv), data, klen+16);
	kuzn_key_expansion(&ctx, key_exp_mac, 32, 0);
	uint8x16_t keymac = kuzn_cmac(&ctx, iv, iv_len, data, klen);
	return EQU128(REV(keymac), *(uint8x16_t* )(data+klen));// сравнение векторов
}



#ifndef TEST_KUZN
CIPHER(GOST_R_3412_2015_KUZN)
{
    .id = CIPH_KUZNYECHIK,
    .name = "GOST R 34.12-2015 (Kuznyechik)",
    .block_len = 128,
    .ctx_size = sizeof(KuznCtx),
    .key_exp = (void*)kuzn_key_expansion,
    .encrypt = (void*)kuzn_encrypt,
    .decrypt = (void*)kuzn_decrypt,
};
#else //def TEST_KUZN
int main()
{
    uint8_t C[] = {1, 148, 32,133,16,194,192,1,251,1,192,194,16,133,32,148};
    uint8_t* in = "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x11\x22\x33\x44\x55\x66\x77\x00";
    uint8_t* ou = "\xb6\x6c\xd8\x88\x7d\x38\xe8\xd7\x77\x65\xae\xea\x0c\x9a\x7e\xfc";
    uint8_t x[16];

    int i;
    printf("A.1.1 Преобразование S\n");
    for (i=0; i<16; i++) {
        x[i] = sbox[in[i]];
        printf("%02x ", x[i]);
    }
    printf("\n");
    for (i=0; i<16; i++) printf("%02x ", ou[i]);
    printf("\n");
    for (i=0; i<16; i++) {
        x[i] = sbox[x[i]];
        printf("%02x ", x[i]);
    }
    printf("\n");
    for (i=0; i<16; i++) {
        x[i] = sbox[x[i]];
        printf("%02x ", x[i]);
    }
    printf("\n");
    for (i=0; i<16; i++) {
        x[i] = sbox[x[i]];
        printf("%02x ", x[i]);
    }
    printf("\n");

unsigned char* r0 = "\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    printf("A.1.2 Преобразование R\n");
    for (i=0; i<16; i++) printf("%02x ", r0[i]);
    printf("\n");
//unsigned char r1[16];
//unsigned char r2[16];
    uint8x16_t r;
    for (i=0; i<16; i++) r[i] = r0[i];
    r = R(r, C);
    for (i=0; i<16; i++) printf("%02x ", r[i]);
    printf("\n");
    r = R(r, C);
    for (i=0; i<16; i++) printf("%02x ", r[i]);
    printf("\n");
    r = R(r, C);
    for (i=0; i<16; i++) printf("%02x ", r[i]);
    printf("\n");
    r = R(r, C);
    for (i=0; i<16; i++) printf("%02x ", r[i]);
    printf("\n");
    printf("обратное преобразование\n");
    r = R_(r, C);
    for (i=0; i<16; i++) printf("%02x ", r[i]);
    printf("\n");
    r = R_(r, C);
    for (i=0; i<16; i++) printf("%02x ", r[i]);
    printf("\n");
    r = R_(r, C);
    for (i=0; i<16; i++) printf("%02x ", r[i]);
    printf("\n");
    r = R_(r, C);
    for (i=0; i<16; i++) printf("%02x ", r[i]);
    printf("\n");

    printf("A.1.3 Преобразование L\n");
    int j;
    r = (uint8x16_t){0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0x94,0xa5,0x64};
    for (j=0;j<16;j++) r=R(r, C); /* L */
    for (i=0; i<16; i++) printf("%02x ", r[i]);
    printf("\n");
    for (j=0;j<16;j++) r=R(r, C);
    for (i=0; i<16; i++) printf("%02x ", r[i]);
    printf("\n");
    for (j=0;j<16;j++) r=R(r, C);
    for (i=0; i<16; i++) printf("%02x ", r[i]);
    printf("\n");
    for (j=0;j<16;j++) r=R(r, C);
    for (i=0; i<16; i++) printf("%02x ", r[i]);
    printf("\n");

    KuznCtx ctx;
	const uint8_t key1[] =
		"\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77"
		"\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF";
/*
    uint8x16_t key[2] = {
        {0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01,0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe},
        {0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88},
    };
	uint8x16_t key_[2];
	key_[0] = REV(key[1]);
	key_[1] = REV(key[0]); */
    kuzn_key_expansion(&ctx, (uint8_t*)key1, 0, 0);

    for (i=0; i<16; i++) printf("%02x ", C[i]);
    printf("\n");
    uint8_t Cm[16][16]; memset(Cm,0, 256);
    for (i=0; i<16; i++)  Cm[0][i] = C[i];
    for (i=1; i<16; i++) CC2(&Cm[0][0], i);
    printf("\n");
    printf("CM:\n");
    for(j=0;j<16;j++){
        printf("{");
        for (i=0; i<16; i++) printf("0x%02x,", Cm[j][i]);
        printf("},\n");
    }
    printf("\n");
    if (0) {
        printf("Sbox-1:\n");
        uint8_t S_[256];
        int i;
        for (i=0; i<256; i++) S_[sbox[i]] = i;
            printf("{");
            for (i=0; i<256; i++) printf("0x%02x,", S_[i]);
            printf("},\n");
        printf("\n");
    }

    printf("4.4.1 Алгоритм зашифрования\n");
    uint8x16_t a = {0x88, 0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x77,0x66,0x55,0x44,0x33,0x22,0x11};
    printf("plain text:\n");
    for (i=0; i<16; i++) printf("%02x", a[15-i]);// 1122334455667700ffeeddccbbaa9988
    printf("\n");
    uint8x16_t b = kuzn_encrypt(&ctx, a);
    printf("cipher text:\n");
    for (i=0; i<16; i++) printf("%02x", b[15-i]);// 7f679d90bebc24305a468d42b9d4edcd
    printf("\n");
    printf("4.4.2 Алгоритм расшифрования\n");
    a = kuzn_decrypt(&ctx, b);
    printf("decrypt text:\n");
    for (i=0; i<16; i++) printf("%02x", a[15-i]);// 1122334455667700ffeeddccbbaa9988
    printf("\n");
#if 0
    uint64_t u;
    for (u=0; u< 1000000; u++)
        a = kuzn_encrypt(&ctx, a);
    printf("decrypt a: %016llX\n",a);
#endif
if (1) {// вращение ключа ACPKM
	uint8_t K[] =
		"\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77"
		"\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF";
	KuznCtx ctx;
	kuzn_key_expansion(&ctx, K, 32, 0);
	uint8_t *k = (uint8_t *)ctx.K;
	for (i=0; i< 32; i++) {
		printf(" %02X", k[i]);
		if ((i&0xF)==0xF) printf("\n");
	}
	printf("\n");
	kuzn_ACPKM(&ctx);
	kuzn_ACPKM(&ctx);
	kuzn_ACPKM(&ctx);
	for (i=0; i< 32; i++) {
		printf(" %02X", k[i^0x1F]);
		if ((i&0xF)==0xF) printf("\n");
	}
	printf("\n");
}
if (1) {// KExp15
	printf("Р 1323565.1.017—2018  KExp15 KImp15\n");
	uint8_t K[] =
		"\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77"
		"\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF";
	uint8_t key_exp_mac[] =
		"\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x00\x01\x02\x03\x04\x05\x06\x07"
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
	uint8_t key_exp_enc[] =
		"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
		"\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\x30\x31\x32\x33\x34\x35\x36\x37";
	uint8_t iv[] = "\x09\x09\x47\x2D\xD9\xF2\x6B\xE8";
	int iv_len = 8;
	int klen = sizeof(K)-1;
	uint8_t data[klen+16];
	__builtin_memcpy(data, K, klen);
	kuzn_KExp15(data, klen, key_exp_mac,  key_exp_enc, iv);
	for (i=0; i< klen+16; i++) {
		printf(" %02X", data[i]);
		if ((i&0xF)==0xF) printf("\n");
	}
	printf("\n");
	printf("KImp15\n");
	// расшифровывание
	if (kuzn_KImp15(data, klen, key_exp_mac,  key_exp_enc, iv) 
		&& __builtin_memcmp(data, K, klen)==0) printf("..ok\n");
	uint8_t iv2[] = "\x12\x34\x56\x78\x90\xAB\xCE\xF0";
	uint8_t msg[] = 
		"\x11\x22\x33\x44\x55\x66\x77\x00\xFF\xEE\xDD\xCC\xBB\xAA\x99\x88"
		"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xEE\xFF\x0A"
		"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xEE\xFF\x0A\x00"
		"\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xEE\xFF\x0A\x00\x11"
		"\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xEE\xFF\x0A\x00\x11\x22"
		"\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xEE\xFF\x0A\x00\x11\x22\x33"
		"\x55\x66\x77\x88\x99\xAA\xBB\xCC\xEE\xFF\x0A\x00\x11\x22\x33\x44";
	KuznCtx ctx;
	kuzn_key_expansion(&ctx, K, 32, 0);
	kuzn_ctr_acpkm(&ctx, __builtin_bswap64(*(uint64_t*)iv2), msg, sizeof(msg)-1);
// шифрованный текст
	for (i=0; i< sizeof(msg)-1; i++) {
		printf(" %02X", msg[i]);
		if ((i&0xF)==0xF) printf("\n");
	}
	printf("\n");
}
if(0) {// ГОСТ Р 34.13-2015 A.1.6.1 Выработка вспомогательных ключей
    uint8_t R[] = "\x94\xbe\xc1\x5e\x26\x9c\xf1\xe5\x06\xf0\x2b\x99\x4c\x0a\x8e\xa0";
	/*
R : 94 BE C1 5E 26 9C F1 E5 06 F0 2B 99 4C 0A 8E A0
K1: 29 7D 82 BC 4D 39 E3 CA 0D E0 57 32 98 15 1D C7
K2: 52 FB 05 78 9A 73 C7 94 1B C0 AE 65 30 2A 3B 8E
	*/
	uint8x16_t K1;
	__builtin_memcpy(&K1, R, 16);
	K1 = REV(K1);
	printf("R :");
	for (i=0; i< 16; i++) {
		printf(" %02X", K1[i]);
	}
	printf("\n");
	K1 = GF128_shift(K1);
	printf("K1:");
	for (i=0; i< 16; i++) {
		printf(" %02X", K1[i]);
	}
	printf("\n");
	K1 = GF128_shift(K1);
	printf("K2:");
	for (i=0; i< 16; i++) {
		printf(" %02X", K1[i]);
	}
	printf("\n");

}
    return 0;
}
#endif // TEST_KUZN
