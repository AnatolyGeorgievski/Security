/*! \defgroup _aes_ алгоритмы шифрования AES-128

    Алгоритм применяется в режиме ECB, CBC, CTR, CFB, OFB, CMAC, CCM, GCM
ECB -- Electronic Codebook (ECB) mode
CBC -- The Cipher Block Chaining (CBC) mode
CTR -- Counter mode
CFB -- Cipher Feedback (CFB),
OFB -- Output Feedback (OFB),
CMAC-- Cipher-based MAC (MAC -- Message Authentication Code)
CCM -- Counter with CBC-MAC
GCM -- Galois/Counter mode
XTS -- XEX-based(Xor-Encrypt-Xor) Tweaked CodeBook mode (TCB) with CipherText Stealing (CTS)

    \sa [IEEE 1619.1] 1619-2007-NIST-Submission.pdf

	\see [FIPS 197] http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

    тестирование
	\see [NIST SP 800-38A] Recommendation for Block Cipher Modes of Operation
тестовые вектора
	http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
    http://csrc.nist.gov/groups/ST/toolkit/examples.html
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_ECB.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_CBC.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_CTR.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_OFB.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_CFB.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_CCM.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_GCM.pdf
    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_CMAC.pdf

протестирован ECB-AES-128, CBC-AES-128, CMAC-AES-128, CTR-AES-128, CCM-AES-128,
CCM*-AES-128 из стандарта IEEE 802.15.4 Annex C

	ECB: p -> CIPH(P_i) -> C_i
	CBC encryt:
        p, C_0 = 0^128 -> CIPH_k(P_i oplus C_{i-1}) -> C_i
    CBC decrypt:
        c, C_0 = 0^128 -> CIPH^{-1}_k(C_i) oplus C_{i-1} -> P_i
    IEEE 802.15.4 используется CCM* режим

[NIST SP 800-38A] Recommendation for Block Cipher Modes of Operation: Methods and Techniques
    http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf

[NIST SP 800-38B] Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication
    http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf

[NIST SP 800-38C] Recommendation for Block Cipher Modes of Operation: The CCM Mode for Authentication and Confidentiality
    http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C_updated-July20_2007.pdf
[X9.63] ANSI X9.63-2001 Public Key Cryptography for the Financial Services Industry—Key Agreement and
Key Transport Using Elliptic Curve Cryptography. (Appendix A)


[NIST SP 800-38D] Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC
    http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf

[NIST SP 800-38E] Recommendation for Block Cipher Modes of Operation: The XTS-AES Mode for Confidentiality on Storage Devices
    http://csrc.nist.gov/publications/nistpubs/800-38E/nist-sp-800-38E.pdf

[RFC 3610] Counter with CBC-MAC (CCM)
    http://tools.ietf.org/html/rfc3610

[RFC 4309] Using Advanced Encryption Standard (AES) CCM Mode with IPsec Encapsulating Security Payload (ESP)
    http://tools.ietf.org/html/rfc4309

[IEEE 802.15.4] Part 15.4: Wireless Medium Access Control (MAC) and Physical Layer (PHY)
    Specifications for Low-Rate WirelessPersonal Area Networks (WPANs)
    http://standards.ieee.org/getieee802/download/802.15.4-2006.pdf
Определяет моду CCM* параметр
    L - длина пакета должен быть равен 2.
    M - длина поля тега 0,4,8, или 16
    длина поля Nonce == 15-L = 13 байт


    \todo сформулировать защищенную область исполнения. Security Module
    Чтобы небыло возможности пользователю подсмотреть ключ
    \todo надо чтобы на стеке не было прямой или косвенной информации о работе модуля, стек должен быть в защищенной области
    и затирать переменные перед выходом из модуля. Исключать возможность прерывания в процессе исполнения,
    исключать возможность аппаратной отладки.
    \todo надо придумать систему чтобы ПО собиралось для целей отладки под
    Windows, GNU/Linux и под все модели контроллеров с архитектурой ARM:
    ARM926, ARM7TDMI, Cortex-M3 и далее что понадобится.
    \todo на ARM926 надо сделать защищенную моду. С виртуальной памятью, с своим стеком и со своей областью памяти.
    С защищенной областью для хранения ключей.


    #pragma GCC target("vaes,avx")
#define __DISABLE_VAES__
#endif // __VAES__

extern __inline __m256i
__attribute__((__gnu_inline__, __always_inline__, __artificial__))
_mm256_aesdec_epi128 (__m256i __A, __m256i __B)
{
  return (__m256i)__builtin_ia32_vaesdec_v32qi ((__v32qi) __A, (__v32qi) __B);
}

extern __inline __m256i
__attribute__((__gnu_inline__, __always_inline__, __artificial__))
_mm256_aesdeclast_epi128 (__m256i __A, __m256i __B)
{
  return (__m256i)__builtin_ia32_vaesdeclast_v32qi ((__v32qi) __A,
								(__v32qi) __B);
}

extern __inline __m256i
__attribute__((__gnu_inline__, __always_inline__, __artificial__))
_mm256_aesenc_epi128 (__m256i __A, __m256i __B)
{
  return (__m256i)__builtin_ia32_vaesenc_v32qi ((__v32qi) __A, (__v32qi) __B);
}

extern __inline __m256i
__attribute__((__gnu_inline__, __always_inline__, __artificial__))
_mm256_aesenclast_epi128 (__m256i __A, __m256i __B)
{
  return (__m256i)__builtin_ia32_vaesenclast_v32qi ((__v32qi) __A,
								(__v32qi) __B);
}

AES GF(2^8)
POLY=0x1B
Таблица умножения:
0x00, 0x1B, 0x36, 0x2D,
0x6C, 0x77, 0x5A, 0x41,
0xD8, 0xC3, 0xEE, 0xF5,
0xB4, 0xAF, 0x82, 0x99,
Barrett u = x^8/P(x) U =0x11B P =0x11B


 */
//#include "aes.h"
#include <stdint.h>
//#include "cipher.h"
#if defined(__ARM_NEON)
#include <arm_neon.h>

#else
typedef  int8_t   int8x16_t __attribute__((__vector_size__(16)));
typedef uint8_t  uint8x16_t __attribute__((__vector_size__(16)));
typedef  char     int8x32_t __attribute__((__vector_size__(32)));
typedef  char     int8x64_t __attribute__((__vector_size__(64)));
typedef uint8_t  uint8x32_t __attribute__((__vector_size__(32)));
typedef uint32_t uint32x4_t __attribute__((__vector_size__(16)));
typedef  int32_t  int32x4_t __attribute__((__vector_size__(16)));
typedef uint64_t uint64x2_t __attribute__((__vector_size__(16)));
typedef  int64_t  int64x2_t __attribute__((__vector_size__(16)));
typedef uint64_t uint64x4_t __attribute__((__vector_size__(32)));
typedef uint32_t uint32x8_t __attribute__((__vector_size__(32)));
typedef  int32_t  int32x8_t __attribute__((__vector_size__(32)));
typedef uint64_t uint64x8_t __attribute__((__vector_size__(64)));
#endif
typedef struct _AES_Ctx AES_Ctx;

struct _AES_Ctx {
    int Nk; // 4,6,8
    uint32x4_t K[15];
};

//! S-Box lookup table,
static const uint8_t S_Box[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};
//! InvS-Box lookup table,
static const uint8_t InvS_Box[256]={
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

#define ROTL(x,n) ((x)<<(n)) ^ ((x)>>(32-(n)))
#define ROTR(x,n) ((x)>>(n)) ^ ((x)<<(32-(n)))
/*! базовые операции для работы с числами 128 бит */
/*! побитовая операция XOR с векторами 128 бит */
#if 0
static inline void XOR128(uint32_t *y, uint32_t *x)
{
//    *y ^= *x;
    y[0] ^= x[0], y[1] ^= x[1], y[2] ^= x[2], y[3] ^= x[3];
}
/*! копирование вектора */
static inline void MOV128(uint32_t* y, const uint32_t * x)
{
//    *y = *x;
    y[0] = x[0], y[1] = x[1], y[2] = x[2], y[3] = x[3];
}
/*! Обнулить вектор */
static inline void CLR128(uint32_t* y)
{
//    *y ^= *y;
    y[0] = 0, y[1] = 0, y[2] = 0, y[3] = 0;
}
#endif

static uint32_t SubWord(uint32_t V)
{
    return S_Box[(uint8_t)V] | (S_Box[(uint8_t)(V>>8)]<<8) | (S_Box[(uint8_t)(V>>16)]<<16) | (S_Box[(uint8_t)(V>>24)]<<24);
}

// SubBytes (73744765635354655d5b56727b746f5d) = 8f92a04dfbed204d4c39b1402192a84c
/*! побайтовое преобразование y = A x^{-1} + b над вектором 128 бит */
static
void SubBytes(uint8_t * d)
{
    int i; for(i=0;i<16;i++) d[i] = S_Box[d[i]];
}
static inline
uint32x4_t SubBytes4_(uint32x4_t S)
{
	uint8x16_t d = (uint8x16_t)S;
    int i; for(i=0;i<16;i++) d[i] = S_Box[d[i]];
	return (uint32x4_t)d;
}

#if 0
/*! перестановка элементов матрицы 4х4 */
static inline
uint32_t MUX(uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
    return  (a & 0x000000FF) | (b & 0x0000FF00) | (c & 0x00FF0000) |  (d & 0xFF000000);
}

// (15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,4,3,2,1,0) (11,6,1, 12,7,2, 13,8,3, 14,9,4, 15,10,5, 0)
// ShiftRows (7b5b54657374566563746f725d53475d) = 73744765635354655d5b56727b746f5d
// PSHUFB128
static void ShiftRows(uint32_t *d)
{
    const uint32_t r0 = d[0];
    const uint32_t r1 = d[1];
    const uint32_t r2 = d[2];
    const uint32_t r3 = d[3];
    d[0] = MUX(r0,r1,r2,r3);
    d[1] = MUX(r1,r2,r3,r0);
    d[2] = MUX(r2,r3,r0,r1);
    d[3] = MUX(r3,r0,r1,r2);
}
#endif
//static inline 
uint32x4_t ShiftRows4(uint32x4_t S){
#if defined(__clang__)
    return (uint32x4_t) __builtin_shufflevector((uint8x16_t)S, (uint8x16_t)S, 0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11);
#else
    return (uint32x4_t) __builtin_shuffle((uint8x16_t)S, (uint8x16_t){0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11});
#endif // defined
}

/*! побайтовое обратное преобразование x = [A^{-1}(y - b)]^{-1} над вектором 128 бит
тестирование
    InvSubBytes (5d7456657b536f65735b47726374545d) = 8dcab9bc035006bc8f57161e00cafd8d
 */
static void InvSubBytes(uint8_t * d)
{
	int i; for(i=0;i<16;i++) d[i] = InvS_Box[d[i]];
}
#if 0
//  (15,14,13,12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0) (3,6,9,12,15, 2,5,8,11,14, 1,4,7,10,13, 0)
// InvShiftRows (7b5b54657374566563746f725d53475d) = 5d7456657b536f65735b47726374545d
static void InvShiftRows(uint32_t *d)
{
    const uint32_t r0 = d[0];
    const uint32_t r1 = d[1];
    const uint32_t r2 = d[2];
    const uint32_t r3 = d[3];
    d[0] = MUX(r0,r3,r2,r1);
    d[1] = MUX(r1,r0,r3,r2);
    d[2] = MUX(r2,r1,r0,r3);
    d[3] = MUX(r3,r2,r1,r0);
}
#endif
static inline uint32x4_t InvShiftRows4(uint32x4_t S){
#if defined(__clang__)
	return (uint32x4_t) __builtin_shufflevector((uint8x16_t)S, (uint8x16_t)S, 0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3);
#else
    return (uint32x4_t) __builtin_shuffle((uint8x16_t)S, (uint8x16_t){0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3});
#endif // __clang__
}
//static 
uint8x16_t SubBytes4(uint8x8x4_t *t, uint8x16_t s)
{
	uint8x8_t r0 = {0};
	uint8x8_t r1 = {0};
	uint8x16_t d = vdupq_n_u8(32);
	uint8x8x4_t tt = vld4_u8(t); t++;
	r0 = vtbl4_u8(tt, vget_low_u8(s));
	r1 = vtbl4_u8(tt, vget_high_u8(s));
	int i;
	for (i=1; i<8; i++){
		s = vsubq_u8(s, d);
		tt = vld4_u8(t); t++;
		r0 = vtbx4_u8(r0, tt, vget_low_u8(s));
		r1 = vtbx4_u8(r1, tt, vget_high_u8(s));
	}
	return vcombine_u8(r0,r1);
}
static
uint32x4_t SubBytes_ShiftRows4(uint32x4_t s)
{
	uint8x16_t a = (uint8x16_t)s;
	uint8x16_t r;
	
	r[ 0] = S_Box[a[0]];
	r[ 5] = S_Box[a[1]];
	r[10] = S_Box[a[2]];
	r[15] = S_Box[a[3]];

	r[ 4] = S_Box[a[4]];
	r[ 9] = S_Box[a[5]];
	r[14] = S_Box[a[6]];
	r[ 3] = S_Box[a[7]];

	r[ 8] = S_Box[a[8]];
	r[13] = S_Box[a[9]];
	r[ 2] = S_Box[a[10]];
	r[ 7] = S_Box[a[11]];

	r[12] = S_Box[a[12]];
	r[ 1] = S_Box[a[13]];
	r[ 6] = S_Box[a[14]];
	r[11] = S_Box[a[15]];
	return (uint32x4_t)r;
}
static inline
uint32x4_t SubBytes_ShiftRows(uint32x4_t a)
{
	register uint32x4_t r;
	r[0] = (uint32_t)S_Box[(uint8_t)(a[0]>>0)]	<<0;
	r[3] = (uint32_t)S_Box[(uint8_t)(a[0]>>8)]	<<8;
	r[2] = (uint32_t)S_Box[(uint8_t)(a[0]>>16)]	<<16;
	r[1] = (uint32_t)S_Box[(uint8_t)(a[0]>>24)]	<<24;

	r[1]^= (uint32_t)S_Box[(uint8_t)(a[1]>>0)]	<<0;
	r[0]^= (uint32_t)S_Box[(uint8_t)(a[1]>>8)]	<<8;
	r[3]^= (uint32_t)S_Box[(uint8_t)(a[1]>>16)]	<<16;
	r[2]^= (uint32_t)S_Box[(uint8_t)(a[1]>>24)]	<<24;

	r[2]^= (uint32_t)S_Box[(uint8_t)(a[2]>>0)]	<<0;
	r[1]^= (uint32_t)S_Box[(uint8_t)(a[2]>>8)]	<<8;
	r[0]^= (uint32_t)S_Box[(uint8_t)(a[2]>>16)]	<<16;
	r[3]^= (uint32_t)S_Box[(uint8_t)(a[2]>>24)]	<<24;

	r[3]^= (uint32_t)S_Box[(uint8_t)(a[3]>>0)]	<<0;
	r[2]^= (uint32_t)S_Box[(uint8_t)(a[3]>>8)]	<<8;
	r[1]^= (uint32_t)S_Box[(uint8_t)(a[3]>>16)]	<<16;
	r[0]^= (uint32_t)S_Box[(uint8_t)(a[3]>>24)]	<<24;
	return (uint32x4_t) r;
}
static inline
uint32x4_t InvSubBytes_ShiftRows(uint32x4_t a)
{
	register uint32x4_t r;
	r[0] = (uint32_t)InvS_Box[(uint8_t)(a[0]>>0)]	<<0;
	r[1] = (uint32_t)InvS_Box[(uint8_t)(a[0]>>8)]	<<8;
	r[2] = (uint32_t)InvS_Box[(uint8_t)(a[0]>>16)]	<<16;
	r[3] = (uint32_t)InvS_Box[(uint8_t)(a[0]>>24)]	<<24;

	r[1]^= (uint32_t)InvS_Box[(uint8_t)(a[1]>>0)]	<<0;
	r[2]^= (uint32_t)InvS_Box[(uint8_t)(a[1]>>8)]	<<8;
	r[3]^= (uint32_t)InvS_Box[(uint8_t)(a[1]>>16)]	<<16;
	r[0]^= (uint32_t)InvS_Box[(uint8_t)(a[1]>>24)]	<<24;

	r[2]^= (uint32_t)InvS_Box[(uint8_t)(a[2]>>0)]	<<0;
	r[3]^= (uint32_t)InvS_Box[(uint8_t)(a[2]>>8)]	<<8;
	r[0]^= (uint32_t)InvS_Box[(uint8_t)(a[2]>>16)]	<<16;
	r[1]^= (uint32_t)InvS_Box[(uint8_t)(a[2]>>24)]	<<24;

	r[3]^= (uint32_t)InvS_Box[(uint8_t)(a[3]>>0)]	<<0;
	r[0]^= (uint32_t)InvS_Box[(uint8_t)(a[3]>>8)]	<<8;
	r[1]^= (uint32_t)InvS_Box[(uint8_t)(a[3]>>16)]	<<16;
	r[2]^= (uint32_t)InvS_Box[(uint8_t)(a[3]>>24)]	<<24;
	return (uint32x4_t) r;
}
/*! умножение элементов вектора 16*8бит на x по модулю x^8 + x^4 + x^3 + x^1 + 1 */
static inline
uint32x4_t XT4x4(uint32x4_t v)
{
	const int8x16_t poly =vdupq_n_s8(0x1B);
	int8x16_t sign =vshrq_n_s8((int8x16_t)v,7);
	int8x16_t q = vshlq_n_s8((int8x16_t)v,1);
	return (uint32x4_t)vbslq_s8((uint8x16_t)sign, q^poly, q);
}
static inline uint32x4_t InvMixColumns4(uint32x4_t V)
{
    uint32x4_t r1 = XT4x4(V);// *0e 0b 0d 09
    uint32x4_t r2 = XT4x4(r1);
    uint32x4_t r3 = XT4x4(r2);
    uint32x4_t a = r3^r2^r1;
    r3^=V; r1^=r3; r2 ^=r3;
    return  a ^ ROTR(r1,8) ^ ROTR(r2,16) ^ ROTR(r3,24);
};

static inline uint32x4_t MixColumns4(uint32x4_t v)
{
    uint32x4_t r = XT4x4(v) ^ (uint32x4_t)vrev32q_u16((uint16x8_t)v);
	v^= r;
	uint32x4_t q;
	q = vshlq_n_u32(v, 24);
	q = vsriq_n_u32(q, v, 8);
    return q^r;
//    uint32x4_t r = XT4x4(V) ^ ROTR(V,16);
//    return r^ROTR(r^V,8);
};

/*! AES-128-ENC шифрование с использованием ключей 128 бит
    \param state -- буфер 128 бит над которым выполняется операция шифрации
    \param key -- развернутый набор ключей 11 шт по 128 бит
 */
//static 
uint32x4_t AES_encrypt(AES_Ctx* ctx, const uint32x4_t state)//, uint32_t key[][4], int Nr)
{
    uint32x4_t *key = (void*)ctx->K;
    int Nr=6+ctx->Nk;
    uint32x4_t S = state;
    int round=0;
    do {
		S ^= key[round++];
		S = SubBytes_ShiftRows4(S);
//        S = (uint32x4_t)SubBytes4((uint8x8x4_t*)S_Box, (uint8x16_t)S);
//        S = ShiftRows4(S);
		if (round==10) break;
        S = MixColumns4(S);
    } while (1);
    S^= key[round++];
    return S;
}

#include <stdio.h>
#include <string.h>
int main()
{
{ // Тестирование операций
{// ShiftRows (7b5b54657374566563746f725d53475d) = 73744765 63535465 5d5b5672 7b746f5d
    uint32_t V[4] = {0x5d53475d, 0x63746f72, 0x73745665, 0x7b5b5465};
    ShiftRows(V);
    printf("ShiftRows  %08X %08X %08X %08X \n", V[3],V[2],V[1],V[0]);
}
{// MixColumns  627A6F66 44B109C8 2B18330A 81C3B3E5 -> 7B5B5465 73745665 63746F72 5D53475D,
    uint32_t V[4] = {0x81c3b3e5,0x2b18330a, 0x44b109c8,0x627a6f66};
    printf("MixColumns  %08X %08X %08X %08X -> ", V[3],V[2],V[1],V[0]);
    MixColumns (V,4);
    printf("%08X %08X %08X %08X, \n", V[3],V[2],V[1],V[0]);
}
{// InvMixColumns  8DCAB9DC 035006BC 8F57161E 00CAFD8D -> D635A667 928B5EAE EEC9CC3B C55F5777,
    uint32_t H[4] = {0x00cafd8d,0x8f57161e, 0x035006bc,0x8dcab9dc};
    printf("InvMixColumns  %08X %08X %08X %08X -> ", H[3],H[2],H[1],H[0]);
    InvMixColumns (H,4);
    printf("%08X %08X %08X %08X, \n", H[3],H[2],H[1],H[0]);
}
{// SubWord(73744765) - 8f92a04d
    uint32_t W = 0x73744765;
    printf("SubWord %08X -> %08X, \n", W, SubWord(W));
}
{// SubBytes
    int i;
    uint8_t sw[16] = {0x73,0x74,0x47,0x65,0x63,0x53,0x54,0x65,0x5d,0x5b,0x56,0x72,0x7b,0x74,0x6f,0x5d};
    printf("SubBytes (");
    for(i=0;i<16;i++) printf("%02X", sw[i]);
    printf(") = ");
    SubBytes(sw);
    for(i=0;i<16;i++) printf("%02X", sw[i]);
    printf("\n");
}
{// InvSubBytes
    uint8_t is[16] = {0x5d,0x74,0x56,0x65,0x7b,0x53,0x6f,0x65,0x73,0x5b,0x47,0x72,0x63,0x74,0x54,0x5d};
    printf("InvSubBytes(");
    int i; for(i=0;i<16;i++) printf("%02X", is[i]);
    printf(") = ");
    InvSubBytes(is);
    for(i=0;i<16;i++) printf("%02X", is[i]);
    printf("\n");
}
}
{ // AES-128 ENC/DEC
    uint32_t key[4] = {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c};
    uint32_t w[11][4];
    KeyExpansion(key, (uint32_t*)w, 4);
    int i; for (i=0; i < 11; i++)
        printf("%08X %08X %08X %08X\n", w[i][3], w[i][2], w[i][1], w[i][0]);
    uint32_t d[4] = {0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc};
    printf("AES-INPUT:\n");
    printf("%08X %08X %08X %08X\n", d[3], d[2], d[1], d[0]);
    AES_encrypt(d, (void*)w,10);
    printf("AES-ENC-128:\n");
    printf("%08X %08X %08X %08X\n", d[3], d[2], d[1], d[0]);

    InvKeyExpansion((uint32_t*)w, 4);
    AES_decrypt(d, (void*)w, 10);
    printf("AES-DEC-128:\n");
    printf("%08X %08X %08X %08X\n", d[3], d[2], d[1], d[0]);
}
{   printf("ECB-AES-128\n");
    uint32_t key[4] = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};
    N2H128(key);
    uint32_t w[11][4];
    KeyExpansion(key, (uint32_t*)w, 4);
    uint32_t d[4] =  {0x6bc1bee2, 0x2e409f96, 0xe93d7e11, 0x7393172a};
    N2H128(d);
//    ae2d8a571e03ac9c9eb76fac45af8e51
//    30c81c46a35ce411e5fbc1191a0a52ef
    AES_encrypt(d, w, 10);
    printf("AES 128:\n");
    N2H128(d);
    printf("%08X %08X %08X %08X\n", (d[0]), (d[1]), (d[2]), (d[3]));

char p[] __attribute__((__aligned__(16))) = //Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10";
char c[] __attribute__((__aligned__(16)))= //Ciphertext
"\x3A\xD7\x7B\xB4\x0D\x7A\x36\x60\xA8\x9E\xCA\xF3\x24\x66\xEF\x97"
"\xF5\xD3\xD5\x85\x03\xB9\x69\x9D\xE7\x85\x89\x5A\x96\xFD\xBA\xAF"
"\x43\xB1\xCD\x7F\x59\x8E\xCE\x23\x88\x1B\x00\xE3\xED\x03\x06\x88"
"\x7B\x0C\x78\x5E\x27\xE8\xAD\x3F\x82\x23\x20\x71\x04\x72\x5D\xD4";

    int i;
    for (i=0;i<4;i++) {
        memcpy(d, &p[i*128/8], 128/8);
        AES_encrypt(d, w, 10);
        if(memcmp(d, &c[i*128/8], 128/8)==0) printf("%d encrypt..ok\n", i);
    }
    InvKeyExpansion((uint32_t*)w, 4);
    for (i=0;i<4;i++) {
        memcpy(d, &c[i*128/8], 128/8);
        AES_decrypt(d, w, 10);
        if(memcmp(d, &p[i*128/8], 128/8)==0) printf("%d decrypt..ok\n", i);
    }
}
	return 0;
}