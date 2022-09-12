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

 */
//#include "aes.h"
#include <stdint.h>
#include "cipher.h"
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
uint32x4_t SubBytes4(uint32x4_t S)
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
static inline uint32x4_t ShiftRows4(uint32x4_t S){
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

/*! умножение элементов вектора 4*8бит на x по модулю x^8 + x^4 + x^3 + x^1 + 1 */
static inline uint32_t XT4(uint32_t v)
{
    static const uint32_t lsb  = 0x01010101UL;
    return  ((v<<1)&~lsb) ^ (0x1B*((v>>7) & lsb));
}
static inline
uint32x4_t XT4x4(uint32x4_t v)
{
#if 1
    int8x16_t m = (int8x16_t) v;
    return (uint32x4_t)((m<<1) ^ ((m<(int8x16_t){0}) & 0x1B));//(uint8x16_t){0x1B,0x1B,0x1B,0x1B, 0x1B,0x1B,0x1B,0x1B, 0x1B,0x1B,0x1B,0x1B, 0x1B,0x1B,0x1B,0x1B}));
#else
    static const uint32_t lsb  = 0x01010101UL;
    return  ((v<<1)&~lsb) ^ (0x1B*((v>>7) & lsb));
#endif
}
#if 0
/*! операция циклического сдвига на i элементов влево */
/* оптимизация для прямого замеса */
static uint32_t gmul_vec4(uint32_t V)
{
    uint32_t r = XT4(V);
    r = r ^ ROTR(V,16);
    return r^ROTR(r^V,8);
//    return r ^ ROTR(r,8) ^ ROTR(V,8) ^ ROTR(V,16) ^ ROTR(V,24);
}
#endif
static uint32_t gmul_ivec4(uint32_t V)
{
    uint32_t r1 = XT4(V);// *0e 0b 0d 09
    uint32_t r2 = XT4(r1);
    uint32_t r3 = XT4(r2);
    uint32_t a = r3^r2^r1;
    r3^=V; r1^=r3; r2 ^=r3;
    return  a ^ ROTR(r1,8) ^ ROTR(r2,16) ^ ROTR(r3,24);
}

static inline uint32x4_t InvMixColumns4(uint32x4_t V)
{
#ifdef __AES__
    return (uint32x4_t)__builtin_ia32_aesimc128((int64x2_t)V);
#else
    uint32x4_t r1 = XT4x4(V);// *0e 0b 0d 09
    uint32x4_t r2 = XT4x4(r1);
    uint32x4_t r3 = XT4x4(r2);
    uint32x4_t a = r3^r2^r1;
    r3^=V; r1^=r3; r2 ^=r3;
    return  a ^ ROTR(r1,8) ^ ROTR(r2,16) ^ ROTR(r3,24);
#endif
};

static inline
uint32x4_t MixColumns4(uint32x4_t V)
{
    uint32x4_t r = XT4x4(V) ^ ROTR(V,16);/* (uint32x4_t)vrev32q_u16((uint16x8_t)V); */
    return r^ROTR(r^V,8);
//    return r ^ ROTR(r,8) ^ ROTR(V, 8) ^ ROTR(V,16) ^ ROTR(V,24);
};
#if 0
static void MixColumns(uint32_t V[], int Nb)
{
	int i;
	for (i=0; i<Nb; i++)
		V[i] = gmul_vec4(V[i]);
};
#endif
/*! Обратное преобразование по матице */
static void InvMixColumns(uint32_t V[], int Nb)
{
	int i;
	for (i=0; i<Nb; i++)
		V[i] = gmul_ivec4(V[i]);
};
/*! Добавление ключа */
#if 0
static void AddRoundKey(uint32_t *y, uint32_t *x)
{
    y[0] ^= x[0], y[1] ^= x[1], y[2] ^= x[2], y[3] ^= x[3];
//    XOR128(state, key);
//    int i;  for (i=0; i<4; i++) state[i] ^= key[i];
}
#endif
/*! AES-128 разгибание ключа
    Nk -- длина ключа 4 слова (128 бит)
 */
static void KeyExpansion(AES_Ctx * ctx, uint32_t* key, int klen, int ekb)
{
    uint32_t *w = (uint32_t*)ctx->K;//,
    int Nk = ctx->Nk = (ekb&0xFFFF)/32;
    int Nbr = 4*(7+Nk);
    uint32_t rcon = 1;
    int i;
    for (i=0;i<Nk; i++) w[i] = key[i];
    for (i = Nk;i < Nbr/*Nb*(Nr+1)*/; i++)
    {
        uint32_t temp = w[i-1];
        if ((i%Nk)==0)//Nk)
        {
            temp = (ROTR(SubWord(temp),8)) ^ rcon;
            rcon <<=1;
            if (rcon & 0x100) rcon ^= 0x11b;
        } else if (Nk==8 && (i&7) == 4)
        {
            temp = SubWord(temp);
        }
        w[i] = w[i-Nk] ^ temp;
    }
    if (ekb>>16) {
        //InvMixColumns(&w[4],4*(Nk+5));//-Nk-4);
        for (i=1;i<(6+Nk);i++)
            ctx->K[i] = InvMixColumns4(ctx->K[i]);
    }
}
/*! AES-128 инверсия равернутого ключа для обратного преобразования
    первый и последний ключи остаются без изменений, остальные инвертируются
 */
void InvKeyExpansion(uint32_t *w, int Nk)
{
    InvMixColumns(&w[4],4*(Nk+5));//-Nk-4);
}
/*! AES-128-ENC шифрование с использованием ключей 128 бит
    \param state -- буфер 128 бит над которым выполняется операция шифрации
    \param key -- развернутый набор ключей 11 шт по 128 бит
 */
static uint32x4_t AES_encrypt(AES_Ctx* ctx, const uint32x4_t state)//, uint32_t key[][4], int Nr)
{
    uint32x4_t *key = (void*)ctx->K;
    int Nr=6+ctx->Nk;
    uint32x4_t S = state;
    int round=0;
//__asm volatile("# LLVM-MCA-BEGIN AES_encrypt");
    goto into;
    do {
        S = SubBytes4(S);
        S = ShiftRows4(S);
        if (round!=Nr) {
                S = MixColumns4(S);
        }
    into:
        S ^= key[round++];
        //round++;
    } while (round <= Nr);
//__asm volatile("# LLVM-MCA-END AES_encrypt");
    return S;
}
#if 1//defined(__VAES__)
//static
uint64x4_t VAES_NI_encrypt(AES_Ctx* ctx, const uint64x4_t state)  __attribute__ ((__target__("vaes")));
uint64x4_t VAES_NI_encrypt2x4(AES_Ctx* ctx, const uint64x4_t state)  __attribute__ ((__target__("vaes")));
//static uint64x4_t VAES_NI_decrypt(AES_Ctx* ctx, const uint64x2_t state)  __attribute__ ((__target__("vaes,avx")));
//static
uint64x4_t VAES_NI_encrypt(AES_Ctx* ctx, const uint64x4_t state)
{
    int8x32_t S = (int8x32_t)state;
    int8x32_t *key = (void*)ctx->K;
    S ^= (int8x32_t)key[0];
    S = __builtin_ia32_vaesenc_v32qi(S,key[1]);
    S = __builtin_ia32_vaesenc_v32qi(S,key[2]);
    S = __builtin_ia32_vaesenc_v32qi(S,key[3]);
    S = __builtin_ia32_vaesenc_v32qi(S,key[4]);
    S = __builtin_ia32_vaesenc_v32qi(S,key[5]);
    S = __builtin_ia32_vaesenc_v32qi(S,key[6]);
    S = __builtin_ia32_vaesenc_v32qi(S,key[7]);
    S = __builtin_ia32_vaesenc_v32qi(S,key[8]);
    S = __builtin_ia32_vaesenc_v32qi(S,key[9]);
    S = __builtin_ia32_vaesenclast_v32qi(S,key[10]);
    return (uint64x4_t)S;
}
uint64x4_t VAES_NI_encrypt2x4(AES_Ctx* ctx, const uint64x4_t state)
{
    int8x32_t S = (int8x32_t)state;
    int8x32_t *key = (void*)ctx->K;
    S ^= (int8x32_t)key[0];
    S = __builtin_ia32_vaesenc_v32qi(S,key[1]);
    S = __builtin_ia32_vaesenc_v32qi(S,key[2]);
    S = __builtin_ia32_vaesenc_v32qi(S,key[3]);
    S = __builtin_ia32_vaesenc_v32qi(S,key[4]);
    S = __builtin_ia32_vaesenc_v32qi(S,key[5]);
    S = __builtin_ia32_vaesenc_v32qi(S,key[6]);
    S = __builtin_ia32_vaesenc_v32qi(S,key[7]);
    S = __builtin_ia32_vaesenc_v32qi(S,key[8]);
    S = __builtin_ia32_vaesenc_v32qi(S,key[9]);
    S = __builtin_ia32_vaesenclast_v32qi(S,key[10]);
    return (uint64x4_t)S;
}
static inline
uint64x8_t VAES_NI_encrypt4(int8x64_t key[11], const uint64x8_t state)  __attribute__ ((__target__("vaes","avx512f")));
//static uint64x4_t VAES_NI_decrypt(AES_Ctx* ctx, const uint64x2_t state)  __attribute__ ((__target__("vaes,avx")));
static inline
uint64x8_t VAES_NI_encrypt4(int8x64_t key[11], const uint64x8_t state)
{
	int8x64_t S = (int8x64_t)state;
//	int8x64_t *key = (void*)ctx->K;
    S ^= key[0];
    S = __builtin_ia32_vaesenc_v64qi(S,key[1]);
    S = __builtin_ia32_vaesenc_v64qi(S,key[2]);
    S = __builtin_ia32_vaesenc_v64qi(S,key[3]);
    S = __builtin_ia32_vaesenc_v64qi(S,key[4]);
    S = __builtin_ia32_vaesenc_v64qi(S,key[5]);
    S = __builtin_ia32_vaesenc_v64qi(S,key[6]);
    S = __builtin_ia32_vaesenc_v64qi(S,key[7]);
    S = __builtin_ia32_vaesenc_v64qi(S,key[8]);
    S = __builtin_ia32_vaesenc_v64qi(S,key[9]);
    S = __builtin_ia32_vaesenclast_v64qi(S,key[10]);
    return (uint64x8_t)S;
}
#endif
#if 1//defined(__AES__)
static uint64x2_t AES_NI_encrypt(AES_Ctx* ctx, const uint64x2_t state)  __attribute__ ((__target__("aes")));
static uint64x2_t AES_NI_decrypt(AES_Ctx* ctx, const uint64x2_t state)  __attribute__ ((__target__("aes")));
static uint64x2_t AES_NI_encrypt(AES_Ctx* ctx, const uint64x2_t state)
{
     int64x2_t S = (int64x2_t)state;
     int64x2_t Z = (int64x2_t){0};
     int64x2_t *key = (void*)ctx->K;
    //S = __builtin_ia32_aesenc128(S,key[0]);
    S ^= key[0];
    S = __builtin_ia32_aesenc128(S,key[1]);
    S = __builtin_ia32_aesenc128(S,key[2]);
    S = __builtin_ia32_aesenc128(S,key[3]);
    S = __builtin_ia32_aesenc128(S,key[4]);
    S = __builtin_ia32_aesenc128(S,key[5]);
    S = __builtin_ia32_aesenc128(S,key[6]);
    S = __builtin_ia32_aesenc128(S,key[7]);
    S = __builtin_ia32_aesenc128(S,key[8]);
    S = __builtin_ia32_aesenc128(S,key[9]);
    switch (ctx->Nk) {
    case 6:
        S = __builtin_ia32_aesenc128(S,key[10]);
        S = __builtin_ia32_aesenc128(S,key[11]);
        S = __builtin_ia32_aesenclast128(S,key[12]);
        break;
    case 8:
        S = __builtin_ia32_aesenc128(S,key[10]);
        S = __builtin_ia32_aesenc128(S,key[11]);
        S = __builtin_ia32_aesenc128(S,key[12]);
        S = __builtin_ia32_aesenc128(S,key[13]);
        S = __builtin_ia32_aesenclast128(S,key[14]);
        break;
    default:
        S = __builtin_ia32_aesenclast128(S,key[10]);
        break;
    }
    return (uint64x2_t)S;
}
static uint64x2_t AES_NI_decrypt(AES_Ctx* ctx, const uint64x2_t state)
{
     int64x2_t S = (int64x2_t)state;
     int64x2_t *key = (void*)ctx->K;
    //S = __builtin_ia32_aesenc128(S,key[0]);
    switch (ctx->Nk) {
    case 8:
        S ^= key[14];
        S = __builtin_ia32_aesdec128(S,key[13]);
        S = __builtin_ia32_aesdec128(S,key[12]);
        S = __builtin_ia32_aesdec128(S,key[11]);
        S = __builtin_ia32_aesdec128(S,key[10]);
        break;
    case 6:
        S ^= key[12];
        S = __builtin_ia32_aesdec128(S,key[11]);
        S = __builtin_ia32_aesdec128(S,key[10]);
        break;
    default:
        S ^= key[10];
        break;
    }
    S = __builtin_ia32_aesdec128(S,key[9]);
    S = __builtin_ia32_aesdec128(S,key[8]);
    S = __builtin_ia32_aesdec128(S,key[7]);
    S = __builtin_ia32_aesdec128(S,key[6]);
    S = __builtin_ia32_aesdec128(S,key[5]);
    S = __builtin_ia32_aesdec128(S,key[4]);
    S = __builtin_ia32_aesdec128(S,key[3]);
    S = __builtin_ia32_aesdec128(S,key[2]);
    S = __builtin_ia32_aesdec128(S,key[1]);
    S = __builtin_ia32_aesdeclast128(S,key[0]);
    return (uint64x2_t)S;
}
#endif

/*! AES-128-DEC шифрование с использованием ключей 128 бит
    \param state -- буфер 128 бит над которым выполняется операция дешифрации
    \param key -- набор инвертированных ключей 11 шт по 128 бит
 */
static uint32x4_t AES_decrypt(AES_Ctx* ctx, const uint32x4_t state)
{
    uint32x4_t *key;
    key = (void*)ctx->K;
    int round=6+ctx->Nk;
    uint32x4_t S = state;
    goto into;
    do{
        InvSubBytes((uint8_t*)&S);
        //InvShiftRows((uint32_t*)&S);
        S = InvShiftRows4(S);
        //printf("ShiftRows   %08X %08X %08X %08X\n", state[3], state[2], state[1], state[0]);
        //printf("Rround %d\n", round);
        if (round!=0){
            S = InvMixColumns4(S);
            //    InvMixColumns((uint32_t*)&S,4);
        }
    into:
        //printf("AddRoundKey %08X %08X %08X %08X\n", state[3], state[2], state[1], state[0]);
        //AddRoundKey((uint32_t*)&S, (uint32_t*)&key[round]);
        S ^= key[round];
    } while (round--);
    return S;
}
#if 0
// умножение и редуцирование по полиному, только порядок бит вывернут
// x^128 + x^7 + x^2 + x^1 + 1
static void SRM128(uint32_t * d)
{
    uint32_t r0 = d[0];
    const uint32_t r1 = d[1];
    const uint32_t r2 = d[2];
    const uint32_t r3 = d[3];
	if (r3&1) d[0] = (r0>>1) ^ 0xe1000000;
	else d[0] = (r0>>1);
    d[1] = (r1>>1) | (r0<<31);
    d[2] = (r2>>1) | (r1<<31);
    d[3] = (r3>>1) | (r2<<31);
}
static inline void N2H128(uint32_t* y)
{
    y[0] = __builtin_bswap32(y[0]), y[1] = __builtin_bswap32(y[1]), y[2] = __builtin_bswap32(y[2]), y[3] = __builtin_bswap32(y[3]);
}
#endif
#if 0
/*! операция умножения на 2 для полинома x^128 + x^7 + x^2 + x^1 + 1
    \param P - полином, его младшая часть
 */
static /*inline*/ void XTM128(uint32_t * d, uint32_t P)
{
    const uint32_t r0 = d[0];
    const uint32_t r1 = d[1];
    const uint32_t r2 = d[2];
    const uint32_t r3 = d[3];
//    int t= (r0>>31)*P;
    d[0] = (r0<<1) | (r1>>31);
    d[1] = (r1<<1) | (r2>>31);
    d[2] = (r2<<1) | (r3>>31);
	if (!(r0>>31)) P=0;
    d[3] = (r3<<1) ^ P;
//    if (r0>>31) y[3] ^= P;
}

/*! сдвиг вправо */
// GHASH 1110 0001 || 0^120
static void MUL128(uint32_t *y, uint32_t *H)
{
    uint32_t z[4];
    CLR128(z);
    int i;
    for (i=0; i<4; i++)
    {
        uint32_t xi = H[i];
        int j;
        for (j=0; j<32; j++)
        {
            if (xi>>31) XOR128(z, y);
			SRM128(y); // сдвиг и редуцирование по модулю
			xi<<=1;
        }// while (xi<<=1);
    }
    MOV128(y,z);
}
#endif
#define CIPH_K(y,key, Nr)   AES_encrypt(y,(void*) key, Nr)
/*! \brief декодирование AES-128 в режиме CBC
    \param buffer -- буфер сообщений, шифрованное сообщение возвращается в том же буфере
    \param blocks -- число блоков 128бит в буфере
    \param iv  -- начальный вектор для свертки
    \param key -- набор развернутых ключей 11 шт
 */


//! полином степени 128 x^128 + x^7 + x^2 + x^1 + 1 для получения вторичных ключей методом умножения на 02 в поле GF(2^128).
#define Rb128 0x87
/*! процесс генерации субключей для CMAC
    \param key -- expanded key 128b 11шт.
    \param [out] k1,k2 -- пара вторичных ключей
 */
#if 0
static void CBC_MAC_subk(uint32_t key[][4], uint32_t *k1, uint32_t*k2, int Nr)
{
    CLR128(k2);
    CIPH_K(k2, key, Nr);// AES_encrypt
    N2H128(k2);
    XTM128(k2, Rb128);
    MOV128(k1, k2);
    XTM128(k2, Rb128);
    N2H128(k1);
    N2H128(k2);
}
/*! CBC-MAC вычисляется от форматированного пакета, выровненного по 128б (16 байт)
    \param mac -- на первом проходе её следует обнулить.
    \param key -- expanded key 128b 11шт.
    \return используются Tlen байт со стороны MSB
 */
void CBC_MAC(uint32_t* mac, uint32_t* buffer, int n_blocks,  uint32_t key[][4], int Nr)
{
    do {
        XOR128(mac,buffer); buffer+=4;
        CIPH_K(mac, key, Nr);
    } while (--n_blocks);
}

typedef struct _CMAC_t CMAC_t;
/*! контекст вычисления CMAC */
struct _CMAC_t{
    uint32_t *key;      //!< развернутые ключи для AES-128-ENC
    uint32_t Nr;        //!< число раундов (10,12,14)
    uint32_t k1 [4];    //!< вторичный ключ 1
    uint32_t k2 [4];    //!< вторичный ключ 2
    uint32_t mac[4];    //!< результат вычисления MAC
    uint32_t buf[4];    //!< буферизация сообщения
    uint32_t length;    //!< полная длина сообщения
};
/*! CMAC производит форматирование пакета, вычисляет CBC_MAC и вовращает Tag
    \param length -- длина пакета в байтах
 */
void CMAC_init(CMAC_t *ctx, uint32_t key[][4], int Nr)
{
    ctx->key = &key[0][0];
	ctx->Nr = Nr;
    CBC_MAC_subk(key, ctx->k1, ctx->k2, ctx->Nr);
    CLR128(ctx->mac);
    ctx->length = 0;
}
/*! \todo доделать для дописыания целыми буферами?
 */
void CMAC_update(CMAC_t *ctx, uint8_t *msg, int len)
{
    ctx->length += len;
    if (len > 16)
    {
        uint32_t * buf = (void*)msg;
        int nb = (len-1)>>4;
        CBC_MAC(ctx->mac, buf, nb,  (void*)ctx->key, ctx->Nr);
        msg+=nb<<4, len -= nb<<4;
    }
    uint8_t *buf = (void*)ctx->buf;
    if (len) __builtin_memcpy(buf, msg, len);
}
/*! \brief Процедура завершения MAC
    если последний блок полный, то M' = M + k1;
    если блок не полный, то в конец сообщения дописывается 1'b1 и добавляются нули до конца блока
    M' = {M,10..0} + k2;
 */
void CMAC_final (CMAC_t *ctx)
{
    int offset = ctx->length&0xF;
    if (offset==0 && ctx->length)
    {
        XOR128(ctx->buf, ctx->k1);
    } else
    {
        uint8_t* buffer = (void*)ctx->buf;
        buffer[offset] = 0x80;
        if (offset < 15) __builtin_memset(&buffer[offset+1], 0, 15 - offset);
        XOR128(ctx->buf, ctx->k2);
    }
    CBC_MAC(ctx->mac, ctx->buf, 1,  (void*)ctx->key, ctx->Nr);
}

typedef struct _CCM_t CCM_t;
struct _CCM_t{
    uint32_t *key;  //!< развернутый набор ключей для AES
    int tlen;  //!< длина тега в байтах
    int nlen;  //!< длина поля nonce в байтах
    int alen;  //!< длина поля AAD в байтах
    uint32_t  mac[4]; //!< MAC
};
#endif

CIPHER(CIPH_AES)
{
    .id = CIPH_AES,
    .name = "AES-SSE",
    .block_len = 128,
    .ctx_size = sizeof(AES_Ctx),
    .key_exp = (void*)KeyExpansion,
    .encrypt = (void*)AES_encrypt,//AES_encrypt,
    .decrypt = (void*)AES_decrypt,//AES_decrypt
};
#if 1//defined(__AES__)
CIPHER(CIPH_AES_NI)
{
    .id = CIPH_AES,
    .name = "AES-NI",
    .block_len = 128,
    .ctx_size = sizeof(AES_Ctx),
    .key_exp = (void*)KeyExpansion,
    .encrypt = (void*)AES_NI_encrypt,//AES_encrypt,
    .decrypt = (void*)AES_NI_decrypt,//AES_decrypt
};
#endif

#if 0//defined(__VAES__)
CIPHER(CIPH_VAES)
{
    .id = CIPH_AES,
    .name = "AES-VAES",
    .block_len = 128,
    .ctx_size = sizeof(AES_Ctx),
    .key_exp = (void*)KeyExpansion,
    .encrypt = (void*)VAES_NI_encrypt,//AES_encrypt,
//    .decrypt = (void*)VAES_NI_decrypt,//AES_decrypt
};
#endif

#ifdef TEST_XTS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
void hexstr(uint8_t * dst, uint8_t *src, int len)
{
	uint8_t v, ch;
	int i;
	for (i=0; i<len; i++){
		ch = *src++;
		if (!isxdigit(ch)) break;
		v = (ch>='a')?ch-'a'+10:ch-'0';
		ch = *src++;
		if (!isxdigit(ch)) break;
		v<<=4;
		v |= (ch>='a')?ch-'a'+10:ch-'0';
		*dst++ = v;
	}
}
void printhex(uint8_t *str, uint8_t *data, int len)
{
	printf(str);
	int i;
	for(i=0; i<len; i++){
		printf("%02x", data[i]);
	}
	printf("\n");
}
void cipher_register(const Cipher* ciph)
{
	
}


#include <intrin.h>

typedef uint32_t v4si __attribute__((__vector_size__(16)));
typedef uint64_t uint64x2_t __attribute__((__vector_size__(16)));
typedef  int64_t  int64x2_t __attribute__((__vector_size__(16)));
typedef uint64_t poly64x2_t __attribute__((__vector_size__(16)));
typedef int8_t v16qi __attribute__((__vector_size__(16)));
typedef v4si (*CipherEncrypt128)(void *ctx, v4si src);
typedef uint64x8_t (*CipherEncrypt512)(void *ctx, uint64x8_t src);
static inline
v4si LOADU128(const void* src)
{
// defined(__SSE2__) 
	return (v4si)_mm_loadu_si128(src);
}



typedef struct _XTS XTS_t;
struct _XTS {
	uint64x2_t iv;
	poly64x2_t aj;
	AES_Ctx* key1;
	AES_Ctx* key2;
};
//uint32x8_t GF128_shift4(uint32x8_t v) __attribute__((__target__("avx2"))); 
/* Сдвиг на два разряда с редуцированием */
static 
uint64x4_t GF128_shift2(uint64x4_t v, int n) __attribute__((__target__("avx512vl","vpclmulqdq","avx2"))); 
static 
uint64x4_t GF128_shift2(uint64x4_t v, int n)
{
	uint64x4_t q = (uint64x4_t)_mm256_shuffle_epi32 ((__m256i)v, 78)>>(64-n);// перестановка 2301
    v = (v<<n);
	uint64x4_t m = (uint64x4_t)_mm256_clmulepi64_epi128((__m256i)q, _mm256_setr_epi32(0x87,0,0,0,0x87,0,0,0), 0x00);
	return (uint64x4_t)_mm256_ternarylogic_epi64((__m256i)v,(__m256i)q,(__m256i)m, 0x96);// v^m^q; -- использование тернарной логики экономит один такт, одну инструкцию
}
/* Сдвиг на четыре разряда с редуцированием */
static 
uint64x8_t GF128_shift4(uint64x8_t v) __attribute__((__target__("avx512f","vpclmulqdq"))); 
static 
uint64x8_t GF128_shift4(uint64x8_t v)
{
	uint64x8_t q = (uint64x8_t)_mm512_shuffle_epi32 ((__m512i)v, 78)>>60;// перестановка 2301
    v = (v<<4);
	uint64x8_t m = (uint64x8_t)_mm512_clmulepi64_epi128((__m512i)q, 
				_mm512_setr_epi32(0x86,0,0,0, 0x86,0,0,0, 0x86,0,0,0, 0x86,0,0,0), 0x00);
/*	a^b^c=r - 0x96 логическая таблица тернарной логики 
	0 0 0 0
	0 0 1 1
	0 1 0 1
	0 1 1 0
	1 0 0 1
	1 0 1 0
	1 1 0 0
	1 1 1 1
*/				
/*	a^(b&c)=r - 0x78 логическая таблица тернарной логики 
	0 0 0 0
	0 0 1 0
	0 1 0 0
	0 1 1 1
	1 0 0 1
	1 0 1 1
	1 1 0 1
	1 1 1 0
*/				
	return (uint64x8_t)_mm512_ternarylogic_epi64((__m512i)v,(__m512i)q,(__m512i)m, 0x96);// v^m^q; -- использование тернарной логики экономит один такт, одну инструкцию
}
static 
uint64x8_t GF128_shiftN(uint64x8_t v, int n) __attribute__((__target__("avx512f","vpclmulqdq"))); 
//static 
uint64x8_t GF128_shiftN(uint64x8_t v, int n)
{
	uint64x8_t q = (uint64x8_t)_mm512_shuffle_epi32 ((__m512i)v, 78)>>(64-n);// перестановка 2301
    v = (v<<n);
	uint64x8_t m = (uint64x8_t)_mm512_clmulepi64_epi128((__m512i)q, 
				_mm512_setr_epi32(0x87,0,0,0, 0x87,0,0,0, 0x87,0,0,0, 0x87,0,0,0), 0x00);
/*	a^b^c=r - 0x96 логическая таблица тернарной логики 
	0 0 0 0
	0 0 1 1
	0 1 0 1
	0 1 1 0
	1 0 0 1
	1 0 1 0
	1 1 0 0
	1 1 1 1
*/				
/*	a^(b&c)=r - 0x78 логическая таблица тернарной логики 
	0 0 0 0
	0 0 1 0
	0 1 0 0
	0 1 1 1
	1 0 0 1
	1 0 1 1
	1 1 0 1
	1 1 1 0
*/				
	return (uint64x8_t)_mm512_ternarylogic_epi64((__m512i)v,(__m512i)q,(__m512i)m, 0x96);// v^m^q; -- использование тернарной логики экономит один такт, одну инструкцию
}
//static 
uint32x4_t GF128_shift(uint32x4_t v)
{
//    v4si m = v>>31;
#if 0 // llvm
    v = (v4si)(((v16qi)v<<1) ^ (__builtin_shufflevector((v16qi)((v16qi)v<0),(v16qi)v, 15,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14) & (v16qi){0x87, 0x1,0x1,0x1,0x1, 0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1})) ;
#elif 0
    v = (v4si)(((v16qi)v<<1) ^ (__builtin_shuffle(((v16qi)v<0), (v16qi){15,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14}) & (v16qi){0x87, 0x1,0x1,0x1,0x1, 0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1})) ;
#elif defined(__SSE2__)// этот вариант короче
    v = (v<<1) ^ (__builtin_shuffle((uint32x4_t)((int32x4_t)v>>31), (uint32x4_t){3,0,1,2}) & (uint32x4_t){0x87, 0x1, 0x1, 0x1}) ;
#else /* этот вариант без векторизации для 64 бит -- взят из gcrypt
  uint64_t carry = -(hi >> 63) & 0x87;

  hi = (hi << 1) ^ (lo >> 63);
  lo = (lo << 1) ^ carry;
*/
/* этот вариант без векторизации для 32 бит */
	uint32_t carry = -(v[3]>>31) & 0x87;
	v[3] = (v[3]<<1) ^ (v[2]>>31);
	v[2] = (v[2]<<1) ^ (v[1]>>31);
	v[1] = (v[1]<<1) ^ (v[0]>>31);
	v[0] = (v[1]<<1) ^ carry;
#endif // 1
    return v;
}
static inline
uint64x2_t CL_MUL128(uint64x2_t a, uint64x2_t b, const int c) __attribute__ ((__target__("pclmul")));
static inline uint64x2_t CL_MUL128(uint64x2_t a, uint64x2_t b, const int c) {
    return (uint64x2_t)__builtin_ia32_pclmulqdq128 ((int64x2_t)a,(int64x2_t)b,c);
}
static poly64x2_t gf128_reduction(poly64x2_t r0, poly64x2_t r1)
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
#elif defined(__PCLMUL__)// SSE+PCLMUL
//#warning "__PCLMUL__"
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
static poly64x2_t GF128_shlm(poly64x2_t r, int i)
{
	poly64x2_t sh = {1ULL<<i};
	poly64x2_t r0  = CL_MUL128(r, sh, 0x00);
	poly64x2_t r1  = CL_MUL128(r, sh, 0x01);
	r0 ^= (poly64x2_t){0,r1[0]};
	r1  = (poly64x2_t){r1[1],0};
// редуцирование
	const poly64x2_t Px ={0x86ULL};// (1 || 0^120 || x87)
	poly64x2_t b  = CL_MUL128(r1,Px, 0x01) ^ (poly64x2_t){r1[1],r1[0]};// первая часть лишняя??
	poly64x2_t d  = CL_MUL128( b,Px, 0x01) ^ (poly64x2_t){ b[1], b[0]};
	return r0 ^ d;
}
static inline
	uint64x2_t encrypt(int64x2_t *key, const uint64x2_t state)
	{
		 int64x2_t S = (int64x2_t)state;
//		 int64x2_t *key = (void*)ctx->K;
		//S = __builtin_ia32_aesenc128(S,key[0]);
		S ^= key[0];
		S = __builtin_ia32_aesenc128(S,key[1]);
		S = __builtin_ia32_aesenc128(S,key[2]);
		S = __builtin_ia32_aesenc128(S,key[3]);
		S = __builtin_ia32_aesenc128(S,key[4]);
		S = __builtin_ia32_aesenc128(S,key[5]);
		S = __builtin_ia32_aesenc128(S,key[6]);
		S = __builtin_ia32_aesenc128(S,key[7]);
		S = __builtin_ia32_aesenc128(S,key[8]);
		S = __builtin_ia32_aesenc128(S,key[9]);
		S = __builtin_ia32_aesenclast128(S,key[10]);
		return (uint64x2_t)S;
	}
static inline
uint64x2_t decrypt(int64x2_t *key, const uint64x2_t state)
{
	 int64x2_t S = (int64x2_t)state;
	S ^= key[10];
    S = __builtin_ia32_aesdec128(S,key[9]);
    S = __builtin_ia32_aesdec128(S,key[8]);
    S = __builtin_ia32_aesdec128(S,key[7]);
    S = __builtin_ia32_aesdec128(S,key[6]);
    S = __builtin_ia32_aesdec128(S,key[5]);
    S = __builtin_ia32_aesdec128(S,key[4]);
    S = __builtin_ia32_aesdec128(S,key[3]);
    S = __builtin_ia32_aesdec128(S,key[2]);
    S = __builtin_ia32_aesdec128(S,key[1]);
    S = __builtin_ia32_aesdeclast128(S,key[0]);
    return (uint64x2_t)S;
}

void XTS128_encrypt(XTS_t* xex, v4si* dst, const uint8_t* src, int length)
{
    //CipherEncrypt128 encrypt = (CipherEncrypt128)AES_NI_encrypt;
    uint64x2_t d, v;
	v = encrypt((int64x2_t*)xex->key2->K, (uint64x2_t)xex->iv);// Key2
	
	int64x2_t key[11];
    int i;
	int64x2_t *K = (int64x2_t *)xex->key1->K;
	#pragma GCC unroll 11
	for (i=0; i<11;i++) key[i] = *K++;
    int blocks = length>>4;// 128 bit
//__asm volatile("# LLVM-MCA-BEGIN XTS128_encrypt");
    for (i=0;i<blocks-1;i++)
    {
		d = (uint64x2_t)LOADU128(src); src+=16;
		//v  = (v4si)GF128_shlm ((poly64x2_t)v, i);// сдвиг и редуцирование. i<64 для блоков <8к
        d = v^encrypt(key, d^v);// Key1
		dst[i] = (v4si) d;
		v = (uint64x2_t) GF128_shift((v4si)v);
    }
//__asm volatile("# LLVM-MCA-END XTS128_encrypt");
	if (length& 0xF) {
        d = (uint64x2_t)LOADU128(src); src+=16;
        d = v^encrypt(key, d^v);// Key1
		v = (uint64x2_t) GF128_shift((v4si)v);
		__builtin_memcpy(&dst[i+1], &d, length& 0xF);
		__builtin_memcpy(&d, src, length& 0xF);
		d = v^encrypt(key, d^v);// Key1
		dst[i] = (v4si) d;
	} else {
        d = (uint64x2_t)LOADU128(src);//__builtin_memcpy(&d, src, 16);
        d = v^encrypt(key, d^v);// Key1
		dst[i] = (v4si) d;
	}
}

void encrypt128x4(int64x2_t *K, int64x2_t * state)
{
	int i;
	int64x2_t key[11];
	int64x2_t S0,S1,S2,S3;

	#pragma GCC unroll 11
	for (i=0; i<11;i++) key[i] = *K++;
	S0 = state[0] ^ key[0];
	S1 = state[1] ^ key[0];
	S2 = state[2] ^ key[0];
	S3 = state[3] ^ key[0];
//__asm volatile("# LLVM-MCA-BEGIN encrypt128x4");
	#pragma GCC unroll 11
	for (i=1; i<10;i++) {
		S0 = __builtin_ia32_aesenc128(S0,key[i]);
		S1 = __builtin_ia32_aesenc128(S1,key[i]);
		S2 = __builtin_ia32_aesenc128(S2,key[i]);
		S3 = __builtin_ia32_aesenc128(S3,key[i]);
	}
	S0 = __builtin_ia32_aesenclast128(S0,key[i]);
	S1 = __builtin_ia32_aesenclast128(S1,key[i]);
	S2 = __builtin_ia32_aesenclast128(S2,key[i]);
	S3 = __builtin_ia32_aesenclast128(S3,key[i]);
//__asm volatile("# LLVM-MCA-END encrypt128x4");
	state[0] = S0;
	state[1] = S1;
	state[2] = S2;
	state[3] = S3;
}
#ifdef __AVX512F__
static
void encrypt512x4_XEX(int8x64_t key[11], int8x64_t state[4], int8x64_t v)
{
	int i;
	int8x64_t S0,S1,S2,S3;
__asm volatile("# LLVM-MCA-BEGIN encrypt512x4");
	int8x64_t t = key[0]^v;
	S0 = state[0] ^ t;
	S1 = state[1] ^ t;
	S2 = state[2] ^ t;
	S3 = state[3] ^ t;
	#pragma GCC unroll 10
	for (i=1; i<10;i++) {
		S0 = __builtin_ia32_vaesenc_v64qi(S0,key[i]);
		S1 = __builtin_ia32_vaesenc_v64qi(S1,key[i]);
		S2 = __builtin_ia32_vaesenc_v64qi(S2,key[i]);
		S3 = __builtin_ia32_vaesenc_v64qi(S3,key[i]);
	}
	t = key[10]^v;
	S0 = __builtin_ia32_vaesenclast_v64qi(S0,t);
	S1 = __builtin_ia32_vaesenclast_v64qi(S1,t);
	S2 = __builtin_ia32_vaesenclast_v64qi(S2,t);
	S3 = __builtin_ia32_vaesenclast_v64qi(S3,t);
__asm volatile("# LLVM-MCA-END encrypt512x4");
	state[0] = S0;
	state[1] = S1;
	state[2] = S2;
	state[3] = S3;
}
static inline
uint64x8_t encrypt4_xex(int8x64_t key[11], const uint64x8_t state, const uint64x8_t v)
{
	int8x64_t S = (int8x64_t)state;
//	int8x64_t *key = (void*)ctx->K;
	S = (int8x64_t)_mm512_ternarylogic_epi64((__m512i)S,(__m512i)v, (__m512i)key[0], 0x96);
	S = __builtin_ia32_vaesenc_v64qi(S,key[1]);
	S = __builtin_ia32_vaesenc_v64qi(S,key[2]);
	S = __builtin_ia32_vaesenc_v64qi(S,key[3]);
	S = __builtin_ia32_vaesenc_v64qi(S,key[4]);
	S = __builtin_ia32_vaesenc_v64qi(S,key[5]);
	S = __builtin_ia32_vaesenc_v64qi(S,key[6]);
	S = __builtin_ia32_vaesenc_v64qi(S,key[7]);
	S = __builtin_ia32_vaesenc_v64qi(S,key[8]);
	S = __builtin_ia32_vaesenc_v64qi(S,key[9]);
	S = __builtin_ia32_vaesenclast_v64qi(S,(int8x64_t)v^key[10]);
	return (uint64x8_t)S;
}
static inline
uint64x4_t encrypt2_xex(int8x32_t key[11], const uint64x4_t state, const uint64x4_t v)
{
	int8x32_t S = (int8x32_t)(state);
	S = (int8x32_t)_mm256_ternarylogic_epi64((__m256i)S,(__m256i)v, (__m256i)key[0], 0x96);
	S = __builtin_ia32_vaesenc_v32qi(S,key[1]);
	S = __builtin_ia32_vaesenc_v32qi(S,key[2]);
	S = __builtin_ia32_vaesenc_v32qi(S,key[3]);
	S = __builtin_ia32_vaesenc_v32qi(S,key[4]);
	S = __builtin_ia32_vaesenc_v32qi(S,key[5]);
	S = __builtin_ia32_vaesenc_v32qi(S,key[6]);
	S = __builtin_ia32_vaesenc_v32qi(S,key[7]);
	S = __builtin_ia32_vaesenc_v32qi(S,key[8]);
	S = __builtin_ia32_vaesenc_v32qi(S,key[9]);
	S = __builtin_ia32_vaesenclast_v32qi(S,key[10]);
	return (uint64x4_t)S^v;
}

void XTS128_encrypt2(XTS_t* xex, uint8_t* dst, const uint8_t* src, int length) 
__attribute__((__target__("avx512vl","avx512bw","avx512dq","avx512f", "vaes", "vpclmulqdq")));
void XTS128_encrypt2(XTS_t* xex, uint8_t* dst, const uint8_t* src, int length)
{
    //CipherEncrypt128 encrypt = (CipherEncrypt128)AES_NI_encrypt;
	uint32x4_t* k_src = xex->key1->K;
	int i;
	v4si v0  = (v4si)encrypt((int64x2_t *)xex->key2->K, (uint64x2_t)xex->iv);// Key2
	v4si v1  = GF128_shift(v0);
	uint64x4_t v = (uint64x4_t)_mm256_set_m128i((__m128i)v1, (__m128i)v0);
	uint64x4_t d;
	int8x32_t key[11];
#pragma GCC unroll 11
	for (i=0; i<11;i++) 
	{
		key[i] = (int8x32_t)_mm256_broadcast_i32x4(_mm_loadu_si128((void*)k_src)); k_src+=1;
		//key[1] = (int8x64_t)_mm512_broadcast_i32x4(_mm_loadu_si128((void*)k_src)); k_src+=16/4;
	}
	int blocks = length>>5;// 512 bit
	if (blocks>0) {
		int i;
		for (i=0;i<blocks;i++)
		{
__asm volatile("# LLVM-MCA-BEGIN XTS128_encrypt2");

			d = (uint64x4_t)_mm256_loadu_si256((void*)src); src+=32;
			d = encrypt2_xex(key, d,v);// Key1
			v = GF128_shift2(v,2);// сдвиг и редуцирование.
			_mm256_storeu_si256((void*)dst, (__m256i)d); dst+=32;
__asm volatile("# LLVM-MCA-END XTS128_encrypt2");
		}
	}
	// кратно целым блокам минус 1
	if (length& 0x1F) {
		__mmask32 mask = ~0UL>>(-length & 0x1F);
		d = (uint64x4_t)_mm256_maskz_loadu_epi8(mask, src);
		d = encrypt2_xex(key, d,v);// Key1
		_mm256_mask_storeu_epi8(dst, mask, (__m256i)d);
		if (length& 0x0F) {// выполнить перестановку 
			printf("ACHTUNG!!!\n");
		}
	}
}
void XTS128_encrypt4(XTS_t* xex, uint8_t* dst, const uint8_t* src, int length) 
__attribute__((__target__("avx512bw","avx512dq","avx512f", "vaes", "vpclmulqdq")));
void XTS128_encrypt4(XTS_t* xex, uint8_t* dst, const uint8_t* src, int length)
{


    //CipherEncrypt128 encrypt = (CipherEncrypt128)AES_NI_encrypt;
	uint32x4_t* k_src = xex->key1->K;
	int i;
	v4si v0  = (v4si)encrypt((int64x2_t *)xex->key2->K, (uint64x2_t)xex->iv);// Key2
	v4si v1  = GF128_shift(v0);
	__m256i v01 = _mm256_set_m128i((__m128i)v1, (__m128i)v0);
	uint64x8_t d, v;
	int8x64_t key[11];
#pragma GCC unroll 11
	for (i=0; i<11;i++) 
	{
		key[i] = (int8x64_t)_mm512_broadcast_i32x4(_mm_loadu_si128((void*)k_src)); k_src+=16/4;
		//key[1] = (int8x64_t)_mm512_broadcast_i32x4(_mm_loadu_si128((void*)k_src)); k_src+=16/4;
	}
	int blocks = length>>6;// 512 bit
	if (blocks>0) {
		uint64x4_t v23 = GF128_shift2((uint64x4_t)v01, 2);
		v = (uint64x8_t)_mm512_castsi256_si512(v01);
		v = (uint64x8_t)_mm512_inserti32x8((__m512i)v, (__m256i)v23, 1);	
		int i;
		for (i=0;i<blocks;i++)
		{
__asm volatile("# LLVM-MCA-BEGIN XTS128_encrypt4");

			d = (uint64x8_t)_mm512_loadu_si512(src); src+=64;
			d = encrypt4_xex(key, d,v);// Key1
			v = GF128_shiftN(v,4);// сдвиг и редуцирование.
			_mm512_storeu_si512(dst, (__m512i)d); dst+=64;
__asm volatile("# LLVM-MCA-END XTS128_encrypt4");
		}
		i*=2;
	}
	// кратно целым блокам минус 1
	if (length& 0x3F) {
		printf("ACHTUNG!!!\n");
		__mmask64 mask = ~0ULL>>(-length & 0x3F);
		d = (uint64x8_t)_mm512_maskz_loadu_epi8(mask, src);
		d = encrypt4_xex(key, d,v);// Key1
		_mm512_mask_storeu_epi8(dst, mask, (__m512i)d);
		if (length& 0x0F) {// выполнить перестановку 
			
		}
	}
}
#endif // AVX512F
/*! \brief 
	работает с выравниванием на байт */
void XTS128_decrypt(XTS_t* xex, v4si* dst, const uint8_t* src, int length)
{
//    CipherEncrypt128 encrypt = (CipherEncrypt128)AES_NI_encrypt;
//    CipherEncrypt128 decrypt = (CipherEncrypt128)AES_NI_decrypt;
    uint64x2_t d, v;
	v = encrypt((int64x2_t*)xex->key2->K, (uint64x2_t)xex->iv);// Key2

	int64x2_t key[11];
    int i;
	int64x2_t *K = (int64x2_t *)xex->key1->K;
	#pragma GCC unroll 11
	for (i=0; i<11;i++) key[i] = *K++;

    int blocks = length>>4;// 128 bit
//__asm volatile("# LLVM-MCA-BEGIN XTS128_decrypt");
	for (i=0;i<blocks-1;i++)
    {
//        __builtin_memcpy(&d, &src[16*i], 16);
		d = (uint64x2_t)LOADU128(src); src+=16;
        d = v^decrypt(key, d^v);// Key1;
		dst[i] = (v4si)d;
		v = (uint64x2_t)GF128_shift((v4si)v);
    }
//__asm volatile("# LLVM-MCA-END XTS128_decrypt");
	if (length& 0xF) {
//__asm volatile("# LLVM-MCA-BEGIN XTS128_decrypt_tail");
		d = (uint64x2_t)LOADU128(src); src+=16;
		uint64x2_t v1 = (uint64x2_t)GF128_shift((v4si)v);
		d = v1^decrypt(key, d^v1);
		__builtin_memcpy(&dst[i+1], &d, length & 0xF);
		__builtin_memcpy(&d, src, length & 0xF);
		d = v^decrypt(key, d^v);
		dst[i] =(v4si) d;
//__asm volatile("# LLVM-MCA-END XTS128_decrypt_tail");
	} else {
		d = (uint64x2_t)LOADU128(src);
		d = v^decrypt(key, d^v);
		dst[i] =(v4si) d; 
	}
}
int  main()
{
	// XTSGenAES128.rsp XTSGenAES256.rsp
	uint8_t buf[1024];
	FILE *fp =fopen("XTSGenAES128.rsp", "r");
	if (fp==NULL) return (1);
	
	int pt_load = 0, ct_load = 0, decrypt = 0;
	uint32_t DataUnitLen=0, count=0;
	uint32_t key[32/4]={0};
	uint8_t iv [32]={0};
	uint8_t ct [32];
	uint8_t pt [32]={0};
	 v4si dst[4];
	AES_Ctx ctx[2];
	CipherEncrypt128 encrypt = (CipherEncrypt128)AES_NI_encrypt;
	XTS_t xts_ctx = {.key1 = &ctx[0], .key2 = &ctx[1], .iv={0}, .aj={1}};
/*	
Vector 1
Key1 00000000000000000000000000000000
14 Key2 00000000000000000000000000000000
15 Data Unit Sequence number 0
16 PTX 0000000000000000000000000000000000000000000000000000000000000000
17 TWK 66e94bd4ef8a2c3b884cfa59ca342b2eccd297a8df1559761099f4b39469565c
18 CTX 917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e	
*/
if (0) {
	KeyExpansion(&ctx[0], key+0, 4, 128);
	KeyExpansion(&ctx[1], key+4, 4, 128);
	dst[0]  = encrypt(xts_ctx.key2, (v4si)xts_ctx.iv);// Key2
	//dst[1]  = (v4si)GF128_shlm ((poly64x2_t)dst[0], 1);
	dst[1]  = (v4si)GF128_shift(dst[0]);
	printhex("TWK = ", (uint8_t*)dst, 256/8);
	v4si v;
	__builtin_memcpy(&v, pt, 16);
	dst[0] ^= encrypt(xts_ctx.key1, v^dst[0]);// Key1
	__builtin_memcpy(&v, pt+16, 16);
	dst[1] ^= encrypt(xts_ctx.key1, v^dst[1]);// Key1
	printhex("CTX = ", (uint8_t*)dst, 256/8);
	return 0;
}
	while (fgets(buf, 1024, fp)!=NULL) {
		if (strncmp("COUNT = ", buf, 8)==0) {
			count = atol(buf+8);
		} else
		if (strncmp("DataUnitLen = ", buf, 14)==0) {
			DataUnitLen = atol(buf+14);
		} else
		if (strncmp("Key = ", buf, 6)==0) {
			hexstr((uint8_t*)key, buf+6, 32);
		} else
		if (strncmp("i = ", buf, 4)==0) {
			hexstr((uint8_t*)&xts_ctx.iv, buf+4, 16);
		} else
		if (strncmp("DataUnitSeqNumber = ", buf, 20)==0) {
			xts_ctx.iv[0] = atol(buf+20);
			xts_ctx.iv[1] = 0;
		} else
		if (strncmp("PT = ", buf, 5)==0) {
			hexstr(pt, buf+5, (DataUnitLen+7)/8);
			pt_load = 1;
		} else
		if (strncmp("CT = ", buf, 5)==0) {
			hexstr(ct, buf+5, (DataUnitLen+7)/8);
			ct_load = 1;
		} else 
		if (strncmp("[DECRYPT]", buf, 9)==0){
			decrypt = 1;
			break;
		}
		
		if (pt_load && ct_load) {// выполнить проверку
			printf("COUNT = %d\n", count);
			printf("DataUnitLen = %d\n", DataUnitLen);
			printhex("Key = ", (uint8_t*)key, 32);
			printhex("i = ", (uint8_t*)&xts_ctx.iv, 16);
//			N2H128(key);
//			N2H128(key+4);
			KeyExpansion(&ctx[0], key+0, 4, 128);
			KeyExpansion(&ctx[1], key+4, 4, 128);
			
			if (1){// !decrypt
				printhex("PT = ", pt, (DataUnitLen+7)/8);
				printhex("CT = ", ct, (DataUnitLen+7)/8);

//				XTS128_encrypt(&xts_ctx, dst, pt, DataUnitLen/8);
				XTS128_encrypt2(&xts_ctx, (uint8_t*)dst, pt, (DataUnitLen+7)/8);
				printhex("ct = ", (uint8_t*)dst,(DataUnitLen+7)/8);
				if (memcmp(ct, dst, (DataUnitLen+7)/8)!=0) {
					printf("..FAIL\n");
					//break;
				}
				InvKeyExpansion((uint32_t*)ctx[0].K, ctx[0].Nk);
				XTS128_decrypt(&xts_ctx, dst, ct, DataUnitLen/8);
				printhex("pt = ", (uint8_t*)dst,(DataUnitLen+7)/8);
				if (memcmp(pt, dst, (DataUnitLen)/8)!=0) {
					printf("..FAIL\n");
					//break;
				}
			} else {
				printhex("CT = ", ct, DataUnitLen/8);
				printhex("PT = ", pt, DataUnitLen/8);
			}
			printf("\n\n");
			pt_load =  ct_load = 0;
		}
		//if (count ==10) break;
	}
	printf("done\n");
	fclose(fp);
	return 0;
}
#endif

#ifdef TEST_AES
#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

#if 0//defined(__ARM_NEON)
	const uint32x4_t x63 = {0x63636363,0x63636363,0x63636363,0x63636363};
	const poly8x8_t  x1F = vdup_n_p8(0x1F);
	uint16x8_t q0,q1;
	q0 = (uint16x8_t)vmull_p8(vget_low_p8 ((poly8x16_t)S), x1F);
	q1 = (uint16x8_t)vmull_p8(vget_high_p8((poly8x16_t)S), x1F);
	q0 ^= q0>>8;
	q1 ^= q1>>8;
	// операция vuzp.8  q9, q3
	S = (uint32x4_t) __builtin_shuffle((uint8x16_t)q0,(uint8x16_t)q1, (uint8x16_t){0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30});
	//S = (uint32x4_t) __builtin_shuffle((uint8x16_t)q0,(uint8x16_t)q1, (uint8x16_t){0,10,20,30,8,18,28,6,16,26,4,14,24,2,12,22});
	//S = (uint32x4_t) __builtin_shuffle((uint8x16_t)S, (uint8x16_t)                {0, 5,10,15,4, 9,14,3, 8,13,2, 7,12,1, 6,11});
	return S ^ x63;
// второй вариант
	uint8x4_t v = (uint8x4_t)S[0];
	uint8x4_t v1 = v ^ ROTL8(v, 2);
	v = v1 ^ ROTL8(v1, 1) ^ ROTL8(v, 4) ^ (uint8x4_t){0x63,0x63,0x63,0x63};
	S[0]=v;
	return S;
// третий вариант
	uint8x16_t v =  (uint8x16_t)S;
	const uint8x16_t x63 = {0x63,0x63,0x63,0x63, 0x63,0x63,0x63,0x63, 0x63,0x63,0x63,0x63, 0x63,0x63,0x63,0x63};//vdupq_n_u8(0x63);
	uint8x16_t v1 = v ^ ROTL8(v, 2);
	v = v1 ^ ROTL8(v1, 1) ^ ROTL8(v, 4) ^ x63;
	// return v ^ ROTL8(v, 1) ^ ROTL8(v, 2) ^ ROTL8(v, 3) ^ ROTL8(v, 4) ^ 0x63;
	return (uint32x4_t)v;
#endif

/*! \brief 
теория генерации: берем генератор g=3 и возводим в степень 
B = M*A + C 
M= 
11111000 // rotl(0,1,2,3,4)
01111100
00111110
00011111
10001111
11000111
11100011
11110001

Как расчитать матрицу обратного аффинного преобразования?

C= 0x63
A = M^{-1}*(B-C) = M^{-1}*B + D
D= 00000101 = 0x05
M-= 
01010010 // rotl(1,3,6) 
00101001
10010100
01001010
00100101
10010010
01001001
10100100
*/
void initialize_aes_sbox(uint8_t sbox[256]) {
	uint8_t p = 1, q = 1;

	/* loop invariant: p * q == 1 in the Galois field */
	do {
		/* multiply p by 3 */
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

		/* divide q by 3 (equals multiplication by 0xf6) */
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;

		/* compute the affine transformation 
		
		*/
		uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);
		sbox[p] = xformed ^ 0x63;
	} while (p != 1);

	/* 0 is a special case since it has no inverse */
	sbox[0] = 0x63;
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
{   printf("ECB-AES-192\n");
    uint32_t key[8] = {0x8E73B0F7, 0xDA0E6452, 0xC810F32B, 0x809079E5, 0x62F8EAD2, 0x522C6B7B};
    uint32_t w[13][4];
    uint32_t d[4*4];
    N2H128(key);N2H128(&key[4]);
    KeyExpansion(key, (uint32_t*)w, 6);
    int i; for (i=0; i < 13; i++)
        printf("%08X %08X %08X %08X\n", w[i][3], w[i][2], w[i][1], w[i][0]);
char pt[] =//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10";
char ct[] =//
"\xBD\x33\x4F\x1D\x6E\x45\xF2\x5F\xF7\x12\xA2\x14\x57\x1F\xA5\xCC"
"\x97\x41\x04\x84\x6D\x0A\xD3\xAD\x77\x34\xEC\xB3\xEC\xEE\x4E\xEF"
"\xEF\x7A\xFD\x22\x70\xE2\xE6\x0A\xDC\xE0\xBA\x2F\xAC\xE6\x44\x4E"
"\x9A\x4B\x41\xBA\x73\x8D\x6C\x72\xFB\x16\x69\x16\x03\xC1\x8E\x0E";

    for (i=0;i<4;i++) {
        memcpy(d, &pt[i*128/8], 128/8);
        AES_encrypt(d, w, 12);
        if(memcmp(d, &ct[i*128/8], 128/8)==0) printf("%d encrypt..ok\n", i);
    }
    InvKeyExpansion((uint32_t*)w, 6);
    for (i=0;i<4;i++) {
        memcpy(d, &ct[i*128/8], 128/8);
        AES_decrypt(d, w, 12);
        if(memcmp(d, &pt[i*128/8], 128/8)==0) printf("%d decrypt..ok\n", i);
    }
}
{   printf("ECB-AES-256\n");
    uint32_t key[8] = {
        0x603DEB10, 0x15CA71BE, 0x2B73AEF0, 0x857D7781,
        0x1F352C07, 0x3B6108D7, 0x2D9810A3, 0x0914DFF4
    };
    uint32_t w[15][4];
    uint32_t d[4*4];
    N2H128(key);N2H128(&key[4]);
    KeyExpansion(key, (uint32_t*)w, 8);
    int i; for (i=0; i < 15; i++)
        printf("%08X %08X %08X %08X\n", w[i][3], w[i][2], w[i][1], w[i][0]);
char pt[] =//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10";
char ct[] =//
"\xF3\xEE\xD1\xBD\xB5\xD2\xA0\x3C\x06\x4B\x5A\x7E\x3D\xB1\x81\xF8"
"\x59\x1C\xCB\x10\xD4\x10\xED\x26\xDC\x5B\xA7\x4A\x31\x36\x28\x70"
"\xB6\xED\x21\xB9\x9C\xA6\xF4\xF9\xF1\x53\xE7\xB1\xBE\xAF\xED\x1D"
"\x23\x30\x4B\x7A\x39\xF9\xF3\xFF\x06\x7D\x8D\x8F\x9E\x24\xEC\xC7";

    for (i=0;i<4;i++) {
        memcpy(d, &pt[i*128/8], 128/8);
        AES_encrypt(d, w, 14);
        if(memcmp(d, &ct[i*128/8], 128/8)==0) printf("%d encrypt..ok\n", i);
    }
    InvKeyExpansion((uint32_t*)w, 8);
    for (i=0;i<4;i++) {
        memcpy(d, &ct[i*128/8], 128/8);
        AES_decrypt(d, w, 14);
        if(memcmp(d, &pt[i*128/8], 128/8)==0) printf("%d decrypt..ok\n", i);
    }
}
{
	printf("CBC AES 128:\n");
//key    "2B7E1516 28AED2A6 ABF71588 09CF4F3C
char iv[] __attribute__((__aligned__(16))) = //IV is
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
char pt[] __attribute__((__aligned__(16))) = //Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10";
char ct[] __attribute__((__aligned__(16))) = //Ciphertext is
"\x76\x49\xAB\xAC\x81\x19\xB2\x46\xCE\xE9\x8E\x9B\x12\xE9\x19\x7D"
"\x50\x86\xCB\x9B\x50\x72\x19\xEE\x95\xDB\x11\x3A\x91\x76\x78\xB2"
"\x73\xBE\xD6\xB8\xE3\xC1\x74\x3B\x71\x16\xE6\x9E\x22\x22\x95\x16"
"\x3F\xF1\xCA\xA1\x68\x1F\xAC\x09\x12\x0E\xCA\x30\x75\x86\xE1\xA7";

    uint32_t key[4] = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};
    N2H128(key);
    uint32_t w[11][4];
    uint32_t d[4*4];
    uint32_t IV[4];
    KeyExpansion(key, (uint32_t*)w, 4);
    memcpy(d, pt, 128/8*4);
    memcpy(IV,iv, 128/8);
    CBC_encrypt(d, IV, 4, w, 10);
    if(memcmp(d, ct, 128/8*4)==0) printf("CBC encrypt..ok\n");
    else {
            int i;
        printf("encrypt:\n");
        for (i=0; i<4; i++)
            printf("%08X %08X %08X %08X\n", (d[i*4+0]), (d[i*4+1]), (d[i*4+2]), (d[i*4+3]));

    }
    InvKeyExpansion((uint32_t*)w, 4);
    memcpy(d, ct, 128/8*4);
    CBC_decrypt(d, IV, 4, w, 10);
    if(memcmp(d, pt, 128/8*4)==0) printf("CBC decrypt..ok\n");

}
{
    printf("CBC AES 192:\n");
    uint32_t key[8] = {0x8E73B0F7, 0xDA0E6452, 0xC810F32B, 0x809079E5, 0x62F8EAD2, 0x522C6B7B};
char iv[] __attribute__((__aligned__(16))) = //IV is
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
char pt[] __attribute__((__aligned__(16))) = //Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10";
char ct[] __attribute__((__aligned__(16))) = //Ciphertext is
"\x4F\x02\x1D\xB2\x43\xBC\x63\x3D\x71\x78\x18\x3A\x9F\xA0\x71\xE8"
"\xB4\xD9\xAD\xA9\xAD\x7D\xED\xF4\xE5\xE7\x38\x76\x3F\x69\x14\x5A"
"\x57\x1B\x24\x20\x12\xFB\x7A\xE0\x7F\xA9\xBA\xAC\x3D\xF1\x02\xE0"
"\x08\xB0\xE2\x79\x88\x59\x88\x81\xD9\x20\xA9\xE6\x4F\x56\x15\xCD";
    N2H128(key);N2H128(&key[4]);
    uint32_t w[13][4];
    uint32_t d[4*4];
    uint32_t IV[4];
    KeyExpansion(key, (uint32_t*)w, 6);
    memcpy(d, pt, 128/8*4);
    memcpy(IV,iv, 128/8);
    CBC_encrypt(d, IV, 4, w, 12);
    if(memcmp(d, ct, 128/8*4)==0) printf("CBC encrypt..ok\n");
    InvKeyExpansion((uint32_t*)w, 6);
    memcpy(d, ct, 128/8*4);
    CBC_decrypt(d, IV, 4, w, 12);
    if(memcmp(d, pt, 128/8*4)==0) printf("CBC decrypt..ok\n");
}
{
    printf("CBC AES 256:\n");
    uint32_t key[8] = {0x603DEB10, 0x15CA71BE, 0x2B73AEF0, 0x857D7781,
	0x1F352C07, 0x3B6108D7, 0x2D9810A3, 0x0914DFF4};
char iv[] __attribute__((__aligned__(16))) = //IV is
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
char pt[] __attribute__((__aligned__(16))) = //Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10";
char ct[] __attribute__((__aligned__(16))) = //Ciphertext is
"\xF5\x8C\x4C\x04\xD6\xE5\xF1\xBA\x77\x9E\xAB\xFB\x5F\x7B\xFB\xD6"
"\x9C\xFC\x4E\x96\x7E\xDB\x80\x8D\x67\x9F\x77\x7B\xC6\x70\x2C\x7D"
"\x39\xF2\x33\x69\xA9\xD9\xBA\xCF\xA5\x30\xE2\x63\x04\x23\x14\x61"
"\xB2\xEB\x05\xE2\xC3\x9B\xE9\xFC\xDA\x6C\x19\x07\x8C\x6A\x9D\x1B";
    N2H128(key);N2H128(&key[4]);
    uint32_t w[15][4];
    uint32_t d[4*4];
    uint32_t IV[4];
    KeyExpansion(key, (uint32_t*)w, 8);
    memcpy(d, pt, 128/8*4);
    memcpy(IV,iv, 128/8);
    CBC_encrypt(d, IV, 4, w, 14);
    if(memcmp(d, ct, 128/8*4)==0) printf("CBC encrypt..ok\n");
    InvKeyExpansion((uint32_t*)w, 8);
    memcpy(d, ct, 128/8*4);
    CBC_decrypt(d, IV, 4, w, 14);
    if(memcmp(d, pt, 128/8*4)==0) printf("CBC decrypt..ok\n");
}
{
    printf("CTR AES 128:\n");
char ic[] __attribute__((__aligned__(16))) = //Initial Counter is
"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF";
char pt[] __attribute__((__aligned__(16))) = //Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10";
char ct[] __attribute__((__aligned__(16))) = //
"\x87\x4D\x61\x91\xB6\x20\xE3\x26\x1B\xEF\x68\x64\x99\x0D\xB6\xCE"
"\x98\x06\xF6\x6B\x79\x70\xFD\xFF\x86\x17\x18\x7B\xB9\xFF\xFD\xFF"
"\x5A\xE4\xDF\x3E\xDB\xD5\xD3\x5E\x5B\x4F\x09\x02\x0D\xB0\x3E\xAB"
"\x1E\x03\x1D\xDA\x2F\xBE\x03\xD1\x79\x21\x70\xA0\xF3\x00\x9C\xEE";
    uint32_t key[4] = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};
    N2H128(key);
    uint32_t w[11][4];
    uint32_t d[4*4];
    uint32_t C[4];
    KeyExpansion(key, (uint32_t*)w, 4);
    memcpy(d, pt, 128/8*4);
    memcpy(C,ic, 128/8);
    CTR_encrypt(d, C, 4, w, 10);
    if(memcmp(d, ct, 128/8*4)==0) printf("CTR encrypt..ok\n");
    //InvKeyExpansion((uint32_t*)w, 4);
    memcpy(C,ic, 128/8);
    memcpy(d, ct, 128/8*4);
    CTR_encrypt(d, C, 4, w, 10);
    if(memcmp(d, pt, 128/8*4)==0) printf("CTR decrypt..ok\n");

}
{
    printf("CTR AES 192:\n");
char ic[] __attribute__((__aligned__(16))) = //Initial Counter is
"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF";
char pt[] __attribute__((__aligned__(16))) = //Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10";
char ct[] __attribute__((__aligned__(16))) = //
"\x1A\xBC\x93\x24\x17\x52\x1C\xA2\x4F\x2B\x04\x59\xFE\x7E\x6E\x0B"
"\x09\x03\x39\xEC\x0A\xA6\xFA\xEF\xD5\xCC\xC2\xC6\xF4\xCE\x8E\x94"
"\x1E\x36\xB2\x6B\xD1\xEB\xC6\x70\xD1\xBD\x1D\x66\x56\x20\xAB\xF7"
"\x4F\x78\xA7\xF6\xD2\x98\x09\x58\x5A\x97\xDA\xEC\x58\xC6\xB0\x50";
    uint32_t key[8] = {0x8E73B0F7, 0xDA0E6452, 0xC810F32B, 0x809079E5, 0x62F8EAD2, 0x522C6B7B};
    N2H128(key);N2H128(&key[4]);
    uint32_t w[13][4];
    uint32_t d[4*4];
    uint32_t C[4];
    KeyExpansion(key, (uint32_t*)w, 6);
    memcpy(d, pt, 128/8*4);
    memcpy(C,ic, 128/8);
    CTR_encrypt(d, C, 4, w, 12);
    if(memcmp(d, ct, 128/8*4)==0) printf("CTR encrypt..ok\n");

    memcpy(C,ic, 128/8);
    memcpy(d, ct, 128/8*4);
    CTR_encrypt(d, C, 4, w, 12);
    if(memcmp(d, pt, 128/8*4)==0) printf("CTR decrypt..ok\n");
}
{
    printf("CTR AES 256:\n");
char ic[] __attribute__((__aligned__(16))) = //Initial Counter is
"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF";
char pt[] __attribute__((__aligned__(16))) = //Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10";
char ct[] __attribute__((__aligned__(16))) = //
"\x60\x1E\xC3\x13\x77\x57\x89\xA5\xB7\xA7\xF5\x04\xBB\xF3\xD2\x28"
"\xF4\x43\xE3\xCA\x4D\x62\xB5\x9A\xCA\x84\xE9\x90\xCA\xCA\xF5\xC5"
"\x2B\x09\x30\xDA\xA2\x3D\xE9\x4C\xE8\x70\x17\xBA\x2D\x84\x98\x8D"
"\xDF\xC9\xC5\x8D\xB6\x7A\xAD\xA6\x13\xC2\xDD\x08\x45\x79\x41\xA6";
    uint32_t key[8] = {0x603DEB10, 0x15CA71BE, 0x2B73AEF0, 0x857D7781,
	0x1F352C07, 0x3B6108D7, 0x2D9810A3, 0x0914DFF4};
    N2H128(key);N2H128(&key[4]);
    uint32_t w[15][4];
    uint32_t d[4*4];
    uint32_t C[4];
    KeyExpansion(key, (uint32_t*)w, 8);
    memcpy(d, pt, 128/8*4);
    memcpy(C,ic, 128/8);
    CTR_encrypt(d, C, 4, w, 14);
    if(memcmp(d, ct, 128/8*4)==0) printf("CTR encrypt..ok\n");

    memcpy(C,ic, 128/8);
    memcpy(d, ct, 128/8*4);
    CTR_encrypt(d, C, 4, w, 14);
    if(memcmp(d, pt, 128/8*4)==0) printf("CTR decrypt..ok\n");
}


    return 0;
}
#endif
