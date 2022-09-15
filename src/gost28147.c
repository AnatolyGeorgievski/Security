/*! ГОСТ 28147-89 http://www.tc26.ru/metodiki/draft/CPSBOX12-TC26.pdf
    \see [RFC 4357] Crypto-Pro Cryptographic Algorithms, January 2006
    \see [RFC 5830] GOST 28147-89,                   March 2010
    \see http://www.tc26.ru/metodiki/draft/CPSBOX12-TC26.pdf
    \see [ТК26УЗ] ЗАДАНИЕ УЗЛОВ ЗАМЕНЫ БЛОКА ПОДСТАНОВКИ АЛГОРИТМА ШИФРОВАНИЯ ГОСТ 28147-89
        http://www.tc26.ru/metodiki/%D0%A2%D0%9A26%D0%A3%D0%97.pdf
    \see [RFC 7836] Cryptographic Algorithms for GOST, March 2016
    Appendix C.  GOST 28147-89 Parameter Set
 */
#include <inttypes.h>
#include <malloc.h>
#include <stdlib.h>
#include <stdio.h>
#include "cipher.h"

#if defined(__sun__) || defined(__linux__)
#define _aligned_malloc(size, align) memalign(align, size)
#define _aligned_free(ptr) free(ptr)
#endif // __sun__

typedef char v16qi __attribute__((__vector_size__(16)));
typedef uint32_t v4si __attribute__((__vector_size__(16)));
typedef uint32_t v2si __attribute__((__vector_size__(8)));
/* Internal representation of GOST substitution blocks */
typedef struct _GostSubstBlock gost_subst_block;
struct _GostSubstBlock {
	v16qi k8;
	v16qi k7;
	v16qi k6;
	v16qi k5;
	v16qi k4;
	v16qi k3;
	v16qi k2;
	v16qi k1;
};
typedef struct _gost_block gost_sbox;
struct _gost_block {
    v16qi k87[16],k65[16],k43[16],k21[16];
};

typedef struct _GostCtx GostCtx;
struct _GostCtx {
		v4si  k[2];
		const gost_sbox* sbox;
		/* Constant s-boxes -- set up in gost_init(). */

};
/*! применяется для всех кроме тестового
 */
static const uint8_t CryptoProKeyMeshingKey[] ={
0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23,
0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4,
0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12,
0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B
};
/*
:     4C DE 38 9C 29 89 EF B6 FF EB 56 C5 5E C2 9B 02
:     98 75 61 3B 11 3F 89 60 03 97 0C 79 8A A1 D5 5D
:     E2 10 AD 43 37 5D B3 8E B4 2C 77 E7 CD 46 CA FA
:     D6 6A 20 1F 70 F4 1E A4 AB 03 F2 21 65 B8 44 D8
*/

static const gost_subst_block Gost28147_TestParamSet = {
    {0xC,0x6,0x5,0x2,0xB,0x0,0x9,0xD,0x3,0xE,0x7,0xA,0xF,0x4,0x1,0x8},
    {0x9,0xB,0xC,0x0,0x3,0x6,0x7,0x5,0x4,0x8,0xE,0xF,0x1,0xA,0x2,0xD},
    {0x8,0xF,0x6,0xB,0x1,0x9,0xC,0x5,0xD,0x3,0x7,0xA,0x0,0xE,0x2,0x4},
    {0x3,0xE,0x5,0x9,0x6,0x8,0x0,0xD,0xA,0xB,0x7,0xC,0x2,0x1,0xF,0x4},
    {0xE,0x9,0xB,0x2,0x5,0xF,0x7,0x1,0x0,0xD,0xC,0x6,0xA,0x4,0x3,0x8},
    {0xD,0x8,0xE,0xC,0x7,0x3,0x9,0xA,0x1,0x5,0x2,0x4,0x6,0xF,0x0,0xB},
    {0xC,0x9,0xF,0xE,0x8,0x1,0x3,0xA,0x2,0x7,0x4,0xD,0x6,0x0,0xB,0x5},
    {0x4,0x2,0xF,0x5,0x9,0x1,0x0,0x8,0xE,0x3,0xB,0xC,0xD,0x7,0xA,0x6}
};
/*
      --  K1 K2 K3 K4 K5 K6 K7 K8
      --  9  3  E  E  B  3  1  B
      --  6  7  4  7  5  A  D  A
      --  3  E  6  A  1  D  2  F
      --  2  9  2  C  9  C  9  5
      --  8  8  B  D  8  1  7  0
      --  B  A  3  1  D  2  A  C
      --  1  F  D  3  F  0  6  E
      --  7  0  8  9  0  B  0  8
      --  A  5  C  0  E  7  8  6
      --  4  2  F  2  4  5  C  2
      --  E  6  5  B  2  9  4  3
      --  F  C  A  4  3  4  5  9
      --  C  B  0  F  C  8  F  1
      --  0  4  7  8  7  F  3  7
      --  D  D  1  5  A  E  B  D
      --  5  1  9  6  6  6  E  4

:     93 EE B3 1B 67 47 5A DA 3E 6A 1D 2F 29 2C 9C 95
:     88 BD 81 70 BA 31 D2 AC 1F D3 F0 6E 70 89 0B 08
:     A5 C0 E7 86 42 F2 45 C2 E6 5B 29 43 FC A4 34 59
:     CB 0F C8 F1 04 78 7F 37 DD 15 AE BD 51 96 66 E4
*/
static const gost_subst_block Gost28147_CryptoProParamSetA = {
    {0xB,0xA,0xF,0x5,0x0,0xC,0xE,0x8,0x6,0x2,0x3,0x9,0x1,0x7,0xD,0x4},
    {0x1,0xD,0x2,0x9,0x7,0xA,0x6,0x0,0x8,0xC,0x4,0x5,0xF,0x3,0xB,0xE},
    {0x3,0xA,0xD,0xC,0x1,0x2,0x0,0xB,0x7,0x5,0x9,0x4,0x8,0xF,0xE,0x6},
    {0xB,0x5,0x1,0x9,0x8,0xD,0xF,0x0,0xE,0x4,0x2,0x3,0xC,0x7,0xA,0x6},
    {0xE,0x7,0xA,0xC,0xD,0x1,0x3,0x9,0x0,0x2,0xB,0x4,0xF,0x8,0x5,0x6},
    {0xE,0x4,0x6,0x2,0xB,0x3,0xD,0x8,0xC,0xF,0x5,0xA,0x0,0x7,0x1,0x9},
    {0x3,0x7,0xE,0x9,0x8,0xA,0xF,0x0,0x5,0x2,0x6,0xC,0xB,0x4,0xD,0x1},
    {0x9,0x6,0x3,0x2,0x8,0xB,0x1,0x7,0xA,0x4,0xE,0xF,0xC,0x0,0xD,0x5}
};
/*
:     80 E7 28 50 41 C5 73 24 B2 00 C2 AB 1A AD F6 BE
:     34 9B 94 98 5D 26 5D 13 05 D1 AE C7 9C B2 BB 31
:     29 73 1C 7A E7 5A 41 42 A3 8C 07 D9 CF FF DF 06
:     DB 34 6A 6F 68 6E 80 FD 76 19 E9 85 FE 48 35 EC
*/
static const gost_subst_block Gost28147_CryptoProParamSetB = {
    {0x0,0x4,0xB,0xE,0x8,0x3,0x7,0x1,0xA,0x2,0x9,0x6,0xF,0xD,0x5,0xC},
    {0x5,0x2,0xA,0xB,0x9,0x1,0xC,0x3,0x7,0x4,0xD,0x0,0x6,0xF,0x8,0xE},
    {0x8,0x3,0x2,0x6,0x4,0xD,0xE,0xB,0xC,0x1,0x7,0xF,0xA,0x0,0x9,0x5},
    {0x2,0x7,0xC,0xF,0x9,0x5,0xA,0xB,0x1,0x4,0x0,0xD,0x6,0x8,0xE,0x3},
    {0x7,0x5,0x0,0xD,0xB,0x6,0x1,0x2,0x3,0xA,0xC,0xF,0x4,0xE,0x9,0x8},
    {0xE,0xC,0x0,0xA,0x9,0x2,0xD,0xB,0x7,0x5,0x8,0xF,0x3,0x6,0x1,0x4},
    {0x0,0x1,0x2,0xA,0x4,0xD,0x5,0xC,0x9,0x7,0x3,0xF,0xB,0x8,0x6,0xE},
    {0x8,0x4,0xB,0x1,0x3,0x5,0x0,0x9,0x2,0xE,0xA,0xC,0xD,0x6,0x7,0xF}
};
/*
:     10 83 8C A7 B1 26 D9 94 C7 50 BB 60 2D 01 01 85
:     9B 45 48 DA D4 9D 5E E2 05 FA 12 2F F2 A8 24 0E
:     48 3B 97 FC 5E 72 33 36 8F C9 C6 51 EC D7 E5 BB
:     A9 6E 6A 4D 7A EF F0 19 66 1C AF C3 33 B4 7D 78
*/
static const gost_subst_block Gost28147_CryptoProParamSetC = {
    {0x7,0x4,0x0,0x5,0xA,0x2,0xF,0xE,0xC,0x6,0x1,0xB,0xD,0x9,0x3,0x8},
    {0xA,0x9,0x6,0x8,0xD,0xE,0x2,0x0,0xF,0x3,0x5,0xB,0x4,0x1,0xC,0x7},
    {0xC,0x9,0xB,0x1,0x8,0xE,0x2,0x4,0x7,0x3,0x6,0x5,0xA,0x0,0xF,0xD},
    {0x8,0xD,0xB,0x0,0x4,0x5,0x1,0x2,0x9,0x3,0xC,0xE,0x6,0xF,0xA,0x7},
    {0x3,0x6,0x0,0x1,0x5,0xD,0xA,0x8,0xB,0x2,0x9,0x7,0xE,0xF,0xC,0x4},
    {0x8,0x2,0x5,0x0,0x4,0x9,0xF,0xA,0x3,0x7,0xC,0xD,0x6,0xE,0x1,0xB},
    {0x0,0x1,0x7,0xD,0xB,0x4,0x5,0x2,0x8,0xE,0xF,0xC,0x9,0xA,0x6,0x3},
    {0x1,0xB,0xC,0x2,0x9,0xD,0x0,0xF,0x4,0x5,0x8,0xE,0xA,0x7,0x6,0x3}
};
/*
FB 11 08 31 C6 C5 C0 0A 23 BE 8F 66 A4 0C 93 F8
6C FA D2 1F 4F E7 25 EB 5E 60 AE 90 02 5D BB 24
77 A6 71 DC 9D D2 3A 83 E8 4B 64 C5 D0 84 57 49
15 99 4C B7 BA 33 E9 AD 89 7F FD 52 31 28 16 7E
*/
static const gost_subst_block Gost28147_CryptoProParamSetD = {
    {0x1,0xA,0x6,0x8,0xF,0xB,0x0,0x4,0xC,0x3,0x5,0x9,0x7,0xD,0x2,0xE},
    {0x3,0x0,0x6,0xF,0x1,0xE,0x9,0x2,0xD,0x8,0xC,0x4,0xB,0xA,0x5,0x7},
    {0x8,0x0,0xF,0x3,0x2,0x5,0xE,0xB,0x1,0xA,0x4,0x7,0xC,0x9,0xD,0x6},
    {0x0,0xC,0x8,0x9,0xD,0x2,0xA,0xB,0x7,0x3,0x6,0x5,0x4,0xE,0xF,0x1},
    {0x1,0x5,0xE,0xC,0xA,0x7,0x0,0xD,0x6,0x2,0xB,0x4,0x9,0x3,0xF,0x8},
    {0x1,0xC,0xB,0x0,0xF,0xE,0x6,0x5,0xA,0xD,0x4,0x8,0x9,0x3,0x7,0x2},
    {0xB,0x6,0x3,0x4,0xC,0xF,0xE,0x2,0x7,0xD,0x8,0x0,0x5,0xA,0x9,0x1},
    {0xF,0xC,0x2,0xA,0x6,0x4,0x5,0x0,0x7,0x9,0xE,0xD,0x1,0xB,0x8,0x3}
};
/* \see [ТК26УЗ]
id-tc26-gost-28147-param-Z
c6 bc 75 81 48 38 fd e7 62 52 5f 2e 23 81 a6 5d
a9 2d 89 60 5a f4 12 95 b5 af 6c 18 9c d6 da c3
e1 e7 0b f4 8e 10 97 4f d4 7a 38 ba 77 45 e1 06
0b c3 b4 d9 3d 9e 43 ac f0 69 2e 3b 1f 0b c0 72

x  K8(x) K7(x) K6(x) K5(x) K4(x) K3(x) K2(x) K1(x)
---------------------------------------------------------------------------------
0 | 1 8 5 7 c b 6 c
1 | 7 e d f 8 3 8 4
2 | e 2 f 5 2 5 2 6
3 | d 5 6 a 1 8 3 2
4 | 0 6 9 8 d 2 9 a
5 | 5 9 2 1 4 f a 5
6 | 8 1 c 6 f a 5 b
7 | 3 c a d 6 d c 9
8 | 4 f b 0 7 e 1 e
9 | f 4 7 9 0 1 e 8
a | a b 8 3 a 7 4 d
b | 6 0 1 e 5 4 7 7
c | 9 d 4 b 3 c b 0
d | c a 3 4 e 9 d 3
e | b 3 e 2 9 6 0 f
f | 2 7 0 c b 0 f 1

 */
static const gost_subst_block Gost28147_TC26_paramZ = {
/* K8 */  {0x1,0x7,0xE,0xD,0x0,0x5,0x8,0x3,0x4,0xF,0xA,0x6,0x9,0xC,0xB,0x2},
/* K7 */  {0x8,0xE,0x2,0x5,0x6,0x9,0x1,0xC,0xF,0x4,0xB,0x0,0xD,0xA,0x3,0x7},
/* K6 */  {0x5,0xD,0xF,0x6,0x9,0x2,0xC,0xA,0xB,0x7,0x8,0x1,0x4,0x3,0xE,0x0},
/* K5 */  {0x7,0xF,0x5,0xA,0x8,0x1,0x6,0xD,0x0,0x9,0x3,0xE,0xB,0x4,0x2,0xC},
/* K4 */  {0xC,0x8,0x2,0x1,0xD,0x4,0xF,0x6,0x7,0x0,0xA,0x5,0x3,0xE,0x9,0xB},
/* K3 */  {0xB,0x3,0x5,0x8,0x2,0xF,0xA,0xD,0xE,0x1,0x7,0x4,0xC,0x9,0x6,0x0},
/* K2 */  {0x6,0x8,0x2,0x3,0x9,0xA,0x5,0xC,0x1,0xE,0x4,0x7,0xB,0xD,0x0,0xF},
/* K1 */  {0xC,0x4,0x6,0x2,0xA,0x5,0xB,0x9,0xE,0x8,0xD,0x7,0x0,0x3,0xF,0x1}
};
// TODO надо найти Oscar 1.0 1.1 и RIC
static const gost_subst_block Gost28147_UKR_SBOX_1 = {
    {0x1,0x2,0x3,0xE,0x6,0xD,0xB,0x8,0xF,0xA,0xC,0x5,0x7,0x9,0x0,0x4},
    {0x3,0x8,0xB,0x5,0x6,0x4,0xE,0xA,0x2,0xC,0x1,0x7,0x9,0xF,0xD,0x0},
    {0x2,0x8,0x9,0x7,0x5,0xf,0x0,0xb,0xc,0x1,0xd,0xe,0xa,0x3,0x6,0x4},
    {0xf,0x8,0xe,0x9,0x7,0x2,0x0,0xd,0xc,0x6,0x1,0x5,0xb,0x4,0x3,0xa},
    {0x3,0x8,0xd,0x9,0x6,0xb,0xF,0x0,0x2,0x5,0xc,0xa,0x4,0xE,0x1,0x7},
    {0xf,0x6,0x5,0x8,0xe,0xb,0xA,0x4,0xc,0x0,0x3,0x7,0x2,0x9,0x1,0xd},
    {0x8,0x0,0xc,0x4,0x9,0x6,0x7,0xb,0x2,0x3,0x1,0xf,0x5,0xe,0xa,0xd},
    {0xa,0x9,0xd,0x6,0xe,0xb,0x4,0x5,0xf,0x1,0x3,0xc,0x7,0x0,0x8,0x2}
};
/* Украина
                             ДКЕ N 1
------------------------------------------------------------------
| К1 | a | 9 | d | 6 | e | b |4 |5 |f |1 | 3 | c | 7 | 0 | 8 | 2 |
| К2 | 8 | 0 | c | 4 | 9 | 6 |7 |b |2 |3 | 1 | f | 5 | e | a | d |
| К3 | f | 6 | 5 | 8 | e | b |a |4 |c |0 | 3 | 7 | 2 | 9 | 1 | d |
| К4 | 3 | 8 | d | 9 | 6 | b |f |0 |2 |5 | c | a | 4 | e | 1 | 7 |
| К5 | f | 8 | e | 9 | 7 | 2 |0 |d |c |6 | 1 | 5 | b | 4 | 3 | a |
| К6 | 2 | 8 | 9 | 7 | 5 | f |0 |b |c |1 | d | e | a | 3 | 6 | 4 |
| К7 | 3 | 8 | b | 5 | 6 | 4 |e |a |2 |c | 1 | 7 | 9 | f | d | 0 |
| К8 | 1 | 2 | 3 | e | 6 | d |b |8 |f |a | c | 5 | 7 | 9 | 0 | 4 |
------------------------------------------------------------------

                             ДКЕ N 2
------------------------------------------------------------------
| К1 | e | 9 | 3 | 7 | f | 4 |c |b |6 |a | d | 1 | 0 | 5 | 8 | 2 |
| К2 | a | d | c | 7 | 6 | e |8 |1 |f |3 | b | 4 | 0 | 9 | 5 | 2 |
| К3 | 4 | b | 1 | f | 9 | 2 |e |c |6 |a | 8 | 7 | 3 | 5 | 0 | d |
| К4 | 4 | 5 | 1 | c | 7 | e |9 |2 |a |f | b | d | 0 | 8 | 6 | 3 |
| К5 | c | b | 3 | 9 | f | 0 |4 |5 |7 |2 | e | d | 1 | a | 8 | 6 |
| К6 | 8 | 7 | 3 | a | 9 | 6 |e |5 |d |0 | 4 | c | 1 | 2 | f | b |
| К7 | f | 0 | e | 6 | 8 | d |5 |9 |a |3 | 1 | c | 4 | b | 7 | 2 |
| К8 | 4 | 3 | e | d | 5 | 0 |2 |b |1 |a | 7 | 6 | 9 | f | 8 | c |
------------------------------------------------------------------

                             ДКЕ N 3

------------------------------------------------------------------
| К1 | d | 9 | 1 | e | 7 | 2 |c |5 |4 |b | 6 | f | 3 | 8 | a | 0 |
| К2 | 7 | 8 | 6 | b | 0 | 3 |4 |d |9 |5 | f | e | a | c | 2 | 1 |
| К3 | a | 5 | 3 | c | 9 | 8 |d |6 |4 |f | e | 0 | 2 | b | 1 | 7 |
| К4 | b | a | c | 1 | 5 | 6 |9 |e |2 |d | f | 7 | 0 | 4 | 3 | 8 |
| К5 | 5 | b | 3 | 0 | f | 9 |e |4 |1 |c | 8 | 6 | 2 | a | 7 | d |
| К6 | 4 | 3 | b | d | 1 | f |8 |2 |7 |e | c | 9 | a | 0 | 6 | 5 |
| К7 | 3 | 7 | 8 | b | 1 | e |5 |0 |d |4 | c | a | 2 | 9 | f | 6 |
| К8 | 6 | d | c | a | b | 7 |9 |3 |f |e | 1 | 2 | 0 | 8 | 4 | 5 |
------------------------------------------------------------------

                             ДКЕ N 4

------------------------------------------------------------------
| К1 | 9 | c | 3 | d | 7 | 6 |e |1 |a |2 | 0 | 4 | 8 | f | 5 | b |
| К2 | a | 5 | b | e | 7 | 6 |0 |c |2 |8 | f | 4 | d | 3 | 9 | 1 |
| К3 | 4 | c | 3 | 0 | d | 2 |e |b |7 |f | 5 | 9 | 1 | 8 | a | 6 |
| К4 | 3 | 9 | 4 | 5 | e | 7 |8 |6 |d |0 | 2 | f | b | c | a | 1 |
| К5 | 2 | 9 | c | f | d | b |4 |1 |7 |5 | 3 | e | 6 | 8 | a | 0 |
| К6 | e | 5 | d | b | 1 | 9 |4 |2 |f |8 | 7 | 0 | 3 | c | a | 6 |
| К7 | e | 6 | 5 | a | 9 | d |4 |8 |b |c | 0 | 3 | 7 | 1 | f | 2 |
| К8 | 1 | 9 | c | b | 7 | 6 |8 |3 |2 |f | e | 0 | 5 | a | 4 | d |
------------------------------------------------------------------

                             ДКЕ N 5

------------------------------------------------------------------
| К1 | 3 | 4 | d | 8 | c | 7 |a |2 |0 |e | 9 | f | b | 1 | 5 | 6 |
| К2 | c | 7 | 6 | 9 | 3 | 8 |b |5 |f |a | 0 | d | 4 | 2 | 1 | e |
| К3 | e | 4 | 8 | 7 | b | 3 |a |c |1 |2 | 6 | 9 | d | f | 0 | 5 |
| К4 | 3 | 9 | 6 | d | 8 | f |a |2 |7 |e | c | 0 | b | 4 | 1 | 5 |
| К5 | 5 | c | a | 7 | 2 | 1 |f |d |e |3 | b | 4 | 0 | 8 | 9 | 6 |
| К6 | 1 | 8 | b | e | 7 | 4 |a |0 |c |3 | 5 | d | 9 | f | 6 | 2 |
| К7 | 9 | b | a | d | 5 | e |2 |3 |0 |6 | 4 | c | f | 1 | 7 | 8 |
| К8 | e | 9 | 1 | 8 | 5 | f |b |0 |6 |2 | c | 7 | a | 4 | d | 3 |
------------------------------------------------------------------

                             ДКЕ N 6

------------------------------------------------------------------
| К1 | f | c | 9 | 6 | e | 2 |1 |b |0 |d | 4 | a | 7 | 8 | 3 | 5 |
| К2 | e | c | 5 | 0 | 7 | 4 |a |3 |2 |6 | 1 | d | 9 | b | f | 8 |
| К3 | 5 | 6 | d | 9 | b | e |a |3 |f |2 | 8 | 1 | 4 | 0 | 7 | c |
| К4 | 1 | f | 7 | 4 | 2 | e |c |3 |6 |b | 9 | 8 | 0 | 5 | a | d |
| К5 | f | 9 | e | 6 | d | 1 |5 |8 |4 |2 | 3 | c | a | b | 0 | 7 |
| К6 | b | 0 | d | 7 | c | e |1 |4 |2 |3 | 6 | 8 | a | 5 | f | 9 |
| К7 | 7 | e | f | 8 | d | 0 |b |3 |a |1 | 4 | 2 | 9 | c | 6 | 5 |
| К8 | 1 | 5 | e | b | 2 | c |3 |8 |a |0 | 9 | 7 | f | 6 | 4 | d |
------------------------------------------------------------------

                             ДКЕ N 7

------------------------------------------------------------------
| К1 | f | d | a | 5 | c | 0 |1 |6 |9 |2 | e | 7 | 3 | b | 4 | 8 |
| К2 | 2 | 5 | a | 0 | 6 | 9 |1 |f |d |4 | 7 | e | b | 3 | 8 | c |
| К3 | 3 | e | 4 | b | 5 | 9 |1 |2 |f |6 | 8 | d | 7 | 0 | a | c |
| К4 | 4 | a | b | 9 | f | 2 |e |5 |d |1 | 3 | 6 | 0 | 7 | c | 8 |
| К5 | f | 6 | 5 | 8 | 9 | 7 |c |b |0 |a | 3 | 1 | 2 | 4 | d | e |
| К6 | c | b | f | 4 | 5 | 1 |e |9 |0 |8 | d | 2 | a | 7 | 3 | 6 |
| К7 | d | 2 | 4 | 8 | b | c |1 |3 |a |5 | 9 | e | 7 | f | 0 | 6 |
| К8 | 1 | 5 | 0 | f | 6 | a |3 |e |7 |2 | c | d | b | 8 | 9 | 4 |
------------------------------------------------------------------

                             ДКЕ N 8

------------------------------------------------------------------
| К1 | e | 4 | b | 2 | 8 | 7 |5 |c |9 |d | 0 | 3 | 1 | f | 6 | a |
| К2 | 3 | e | c | a | 6 | 2 |d |1 |9 |8 | 7 | 4 | 0 | f | 5 | b |
| К3 | 5 | 2 | 8 | 7 | 1 | f |e |6 |4 |d | b | 0 | a | 3 | c | 9 |
| К4 | c | a | 7 | d | e | 3 |0 |2 |9 |5 | 1 | 6 | b | 4 | f | 8 |
| К5 | 6 | 3 | f | 7 | 0 | 9 |a |8 |b |c | 4 | 1 | 5 | 2 | d | e |
| К6 | 6 | d | f | 1 | 5 | 3 |8 |0 |b |a | e | 4 | 9 | c | 2 | 7 |
| К7 | 2 | f | c | 5 | b | 1 |3 |e |0 |6 | d | a | 7 | 9 | 4 | 8 |
| К8 | 3 | 0 | 5 | c | 8 | f |d |e |b |6 | 2 | 9 | 7 | 1 | 4 | a |
------------------------------------------------------------------

                             ДКЕ N 9

------------------------------------------------------------------
| К1 | 9 | 0 | b | c | 2 | 4 |3 |f |d |6 | e | 1 | a | 7 | 5 | 8 |
| К2 | 3 | 5 | 0 | f | 8 | 7 |e |c |d |a | 1 | 6 | b | 2 | 4 | 9 |
| К3 | 8 | 4 | 5 | a | e | b |d |6 |c |f | 7 | 9 | 3 | 1 | 2 | 0 |
| К4 | 5 | 4 | f | 0 | c | b |a |9 |1 |e | 8 | 6 | 3 | 2 | d | 7 |
| К5 | 7 | c | 3 | 0 | 6 | 8 |e |b |1 |f | d | a | 9 | 5 | 2 | 4 |
| К6 | 7 | 4 | 3 | b | 6 | a |8 |1 |9 |c | e | d | 0 | f | 2 | 5 |
| К7 | 7 | e | 9 | f | 1 | 4 |8 |3 |b |d | 0 | 2 | 6 | a | 5 | c |
| К8 | e | 2 | 8 | f | 3 | 0 |7 |c |b |d | 1 | 5 | 6 | 4 | 9 | a |
------------------------------------------------------------------

                             ДКЕ N 10

------------------------------------------------------------------
| К1 | 8 | 4 | 6 | 9 | b | c |1 |2 |3 |7 | e | 0 | d | a | f | 5 |
| К2 | 7 | d | 1 | 8 | a | e |4 |f |9 |0 | 6 | 3 | 2 | c | b | 5 |
| К3 | c | 8 | d | 1 | a | 2 |9 |6 |3 |4 | e | 7 | 5 | f | 0 | b |
| К4 | 2 | b | 3 | 4 | c | 7 |9 |d |f |8 | 5 | 0 | 1 | e | a | 6 |
| К5 | 8 | 3 | d | a | e | f |5 |1 |4 |7 | b | c | 2 | 0 | 6 | 9 |
| К6 | 4 | c | 9 | b | e | a |7 |6 |3 |5 | 0 | f | 1 | 2 | 8 | d |
| К7 | 5 | 8 | e | 7 | 3 | 0 |1 |d |a |6 | 9 | 2 | f | b | c | 4 |
| К8 | a | 3 | 5 | 9 | 0 | d |7 |8 |c |4 | 1 | 6 | b | f | 2 | e |
------------------------------------------------------------------
*/
const gost_subst_block* Gost_subst_blocks[] = {
[Gost28147_Test_ParamSet] = &Gost28147_TestParamSet,
[Gost28147_CryptoProParamSet_A] = &Gost28147_CryptoProParamSetA,
[Gost28147_CryptoProParamSet_B] = &Gost28147_CryptoProParamSetB,
[Gost28147_CryptoProParamSet_C] = &Gost28147_CryptoProParamSetC,
[Gost28147_CryptoProParamSet_D] = &Gost28147_CryptoProParamSetD,
[Gost28147_TC26_ParamSet_Z] = &Gost28147_TC26_paramZ,
[Gost28147_UKR_SBOX1] = &Gost28147_UKR_SBOX_1,
};


/*!
В данной реализации таблицы занимают 4*256*8бит = 1кБайт.
Минимум 4*16 = 64 байт - упакованное представление
Можно сделать 4*256* 32бит. = 4кбайт таблиц и хранить уже сдвинутое значение на 24,16,8,0 и ROL(11)
 */
static inline
uint32_t f(const GostCtx *c, uint32_t  x)
{
    const uint8_t* k87 = (uint8_t*)c->sbox->k87;
    const uint8_t* k65 = (uint8_t*)c->sbox->k65;
    const uint8_t* k43 = (uint8_t*)c->sbox->k43;
    const uint8_t* k21 = (uint8_t*)c->sbox->k21;
    //uint32_t h = x>>16;
    x = k87[x>>24 & 0xFF]<<24 | k65[x>>16 & 0xFF]<<16 | k43[x>>8 & 0xFF]<<8 | k21[x & 0xFF];
    return x<<11 | x>>(32-11);
}

/* Используются первые 16 раундов из 32 */
//static v2si gost_imit(const GostCtx *c, const v2si in) __attribute__((used));
v2si gost_imit(const GostCtx *c, const v2si in)
{
    const uint32_t * s= (uint32_t*)c->k;
	register uint32_t n1 = in[0], n2 = in[1];

	n2 ^= f(c,n1+s[0]); n1 ^= f(c,n2+s[1]);
	n2 ^= f(c,n1+s[2]); n1 ^= f(c,n2+s[3]);
	n2 ^= f(c,n1+s[4]); n1 ^= f(c,n2+s[5]);
	n2 ^= f(c,n1+s[6]); n1 ^= f(c,n2+s[7]);

	n2 ^= f(c,n1+s[0]); n1 ^= f(c,n2+s[1]);
	n2 ^= f(c,n1+s[2]); n1 ^= f(c,n2+s[3]);
	n2 ^= f(c,n1+s[4]); n1 ^= f(c,n2+s[5]);
	n2 ^= f(c,n1+s[6]); n1 ^= f(c,n2+s[7]);

    return (v2si){n1,n2};//((uint64_t)n1)<<32 | n2;
}
/* Low-level encryption routine - encrypts one 64 bit block*/
static v2si gost_encrypt(const GostCtx *c, const v2si in)
{
    const uint32_t * s= (uint32_t*)c->k;
	register uint32_t n1 = in[0], n2 = in[1];

	n2 ^= f(c,n1+s[0]); n1 ^= f(c,n2+s[1]);
	n2 ^= f(c,n1+s[2]); n1 ^= f(c,n2+s[3]);
	n2 ^= f(c,n1+s[4]); n1 ^= f(c,n2+s[5]);
	n2 ^= f(c,n1+s[6]); n1 ^= f(c,n2+s[7]);

	n2 ^= f(c,n1+s[0]); n1 ^= f(c,n2+s[1]);
	n2 ^= f(c,n1+s[2]); n1 ^= f(c,n2+s[3]);
	n2 ^= f(c,n1+s[4]); n1 ^= f(c,n2+s[5]);
	n2 ^= f(c,n1+s[6]); n1 ^= f(c,n2+s[7]);

	n2 ^= f(c,n1+s[0]); n1 ^= f(c,n2+s[1]);
	n2 ^= f(c,n1+s[2]); n1 ^= f(c,n2+s[3]);
	n2 ^= f(c,n1+s[4]); n1 ^= f(c,n2+s[5]);
	n2 ^= f(c,n1+s[6]); n1 ^= f(c,n2+s[7]);

	n2 ^= f(c,n1+s[7]); n1 ^= f(c,n2+s[6]);
	n2 ^= f(c,n1+s[5]); n1 ^= f(c,n2+s[4]);
	n2 ^= f(c,n1+s[3]); n1 ^= f(c,n2+s[2]);
	n2 ^= f(c,n1+s[1]); n1 ^= f(c,n2+s[0]);

    return (v2si){n2,n1};//((uint64_t)n1)<<32 | n2;
}
/* Low-level decryption routine - decrypts one 64 bit block*/
static v2si gost_decrypt(const GostCtx *c, const v2si in)
{
    const uint32_t * s= (uint32_t*)c->k;
	register uint32_t n1 = in[0], n2 = in[1];//>>32; /* As named in the GOST */
	/* Instead of swapping halves, swap names each round */

	n2 ^= f(c,n1+s[0]); n1 ^= f(c,n2+s[1]);
	n2 ^= f(c,n1+s[2]); n1 ^= f(c,n2+s[3]);
	n2 ^= f(c,n1+s[4]); n1 ^= f(c,n2+s[5]);
	n2 ^= f(c,n1+s[6]); n1 ^= f(c,n2+s[7]);

	n2 ^= f(c,n1+s[7]); n1 ^= f(c,n2+s[6]);
	n2 ^= f(c,n1+s[5]); n1 ^= f(c,n2+s[4]);
	n2 ^= f(c,n1+s[3]); n1 ^= f(c,n2+s[2]);
	n2 ^= f(c,n1+s[1]); n1 ^= f(c,n2+s[0]);

	n2 ^= f(c,n1+s[7]); n1 ^= f(c,n2+s[6]);
	n2 ^= f(c,n1+s[5]); n1 ^= f(c,n2+s[4]);
	n2 ^= f(c,n1+s[3]); n1 ^= f(c,n2+s[2]);
	n2 ^= f(c,n1+s[1]); n1 ^= f(c,n2+s[0]);

	n2 ^= f(c,n1+s[7]); n1 ^= f(c,n2+s[6]);
	n2 ^= f(c,n1+s[5]); n1 ^= f(c,n2+s[4]);
	n2 ^= f(c,n1+s[3]); n1 ^= f(c,n2+s[2]);
	n2 ^= f(c,n1+s[1]); n1 ^= f(c,n2+s[0]);

    return (v2si){n2,n1};
}
static gost_sbox* Gost_sboxes[GOST28147_PARAMSET_COUNT]={NULL};
/* Initalize context. Provides default value for subst_block */
static void gost_init(GostCtx *c, uint8_t * key, int klen, int ekb)
{
    v4si k0,k1;
    __builtin_memcpy(&k0, &key[ 0], 16);
    __builtin_memcpy(&k1, &key[16], 16);
    c->k[0] = k0; c->k[1] =  k1;
    int paramset_id = ekb&0xF;
    if (paramset_id >= GOST28147_PARAMSET_COUNT) paramset_id=0;
    if (Gost_sboxes[paramset_id]==NULL)
    {
        gost_sbox *s = _aligned_malloc(sizeof(gost_sbox),16);
        const gost_subst_block * b = Gost_subst_blocks[paramset_id];
        const v16qi k7 = b->k7;
        const v16qi k5 = b->k5;
        const v16qi k3 = b->k3;
        const v16qi k1 = b->k1;
        v16qi k;
        int i;
        for (i = 0; i < 16; i++) {
            k[0] = b->k8[i]<<4;
            k = __builtin_shuffle(k, (v16qi){0});
            s->k87[i] = k ^ k7;
            k[0] = b->k6[i]<<4;
            k = __builtin_shuffle(k, (v16qi){0});
            s->k65[i] = k ^ k5;
            k[0] = b->k4[i]<<4;
            k = __builtin_shuffle(k, (v16qi){0});
            s->k43[i] = k ^ k3;
            k[0] = b->k2[i]<<4;
            k = __builtin_shuffle(k, (v16qi){0});
            s->k21[i] = k ^ k1;
        }
        Gost_sboxes[paramset_id] =s;
    }
    c->sbox = Gost_sboxes[paramset_id];

}

CIPHER(CIPH_GOST)
{
    .id = CIPH_GOST,
    .name = "GOST 28147-89",
    .block_len = 64,
    .ctx_size = sizeof(GostCtx),
    .key_exp = (void*)gost_init,
    .encrypt = (void*)gost_encrypt,
    .decrypt = (void*)gost_decrypt,
};
#ifdef GOST28147_IMIT

static void gost_mac(GostCtx *ctx, uint8_t* mac, const uint8_t* src, int length)
{
//    CipherEncrypt64 encrypt = (CipherEncrypt64)ciph->cipher->encrypt;
    v2si d, v;
    v = (v2si){0};
    //__builtin_memcpy(&v, ciph->iv, 8);
    int blocks = length>>3;
    int i;
    for (i=0;i<blocks;i++)
    {
        __builtin_memcpy(&d, &src[8*i], 8);
        d ^= v;
        v = gost_imit(ctx, d);
    }
    __builtin_memcpy(mac, &v, 8);
}

int main()
{
    struct {
        int sbox;
		int plen;
        char* key;
        char* pt;
        char* mac;
//        char* iv;
    } tests[] ={
    {Gost28147_UKR_SBOX1, 16,
"\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00"
"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
"\x55\x55\x55\x55\xAA\xAA\xAA\xAA\x55\x55\x55\x55\xCC\xCC\xCC\xCC",
"\xBA\x94\x82\xCC",
//"\x00\x00\x00\x00\x00\x00\x00\x00",
    },
    };
    GostCtx ctx;
    uint8_t mac[8];
    int i;
    for (i=0;i<1;i++){
        printf("test #%d\n", i);
        gost_init(&ctx, tests[i].key, 32, tests[i].sbox);
        gost_mac (&ctx, mac, tests[i].pt, tests[i].plen);

        int k; for (k=0;k<4;k++) printf(" %02X", mac[k]);
        printf("\n");
    }
    return 0;
}
#endif // GOST28147_IMIT
