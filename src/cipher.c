/*!
    \see Recommendation for Block Cipher Modes of Operation Methods and Techniques, 2001
    http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf

    \see [NIST 800-38B] Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication
    <http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf>
    \see [NIST 800-38C] Recommendation for Block Cipher Modes of Operation: The CCM Mode for Authentication and Confidentiality
    <http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf>
    \see [NIST 800-38D] Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC, 2007
    <http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf>
    <http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf>
    \see [RFC 4493] The AES-CMAC Algorithm June 2006
    <https://tools.ietf.org/html/rfc4493>
    \see [RFC 3711] The Secure Real-time Transport Protocol (SRTP), March 2004

    https://tools.ietf.org/html/rfc3711
    \see [RFC 6188] The Use of AES-192 and AES-256 in Secure RTP, March 2011
    https://tools.ietf.org/html/rfc6188
    \see [RFC 7714] AES-GCM for SRTP, December 2015
    https://tools.ietf.org/html/rfc7714
    \see Internet-Draft        Multilinear Galois Mode (MGM)        December 2019
	\see [RFC 8452] AES-GCM-SIV, April 2019
	
*/
#include <stdint.h>
#include <malloc.h>
#include <stdlib.h>
#include "cipher.h"
#include "r3_slist.h"

#if defined(__sun__) || defined(__linux__)
#define _aligned_malloc(size, align) memalign(align, size)
#define _aligned_free(ptr) free(ptr)
#endif // __sun__ __linux__

//#define VECTOR(n) __attribute__((__vector_size__(n)));
typedef uint64_t uint64x2_t __attribute__((__vector_size__(16)));
typedef uint64_t poly64x2_t __attribute__((__vector_size__(16)));
typedef int32_t v4ss __attribute__((__vector_size__(16)));
typedef uint32_t v4si __attribute__((__vector_size__(16)));
typedef int8_t v16qi __attribute__((__vector_size__(16)));
typedef   int8_t v8qi __attribute__((__vector_size__(8)));
typedef uint16_t v4hi __attribute__((__vector_size__(8)));
typedef uint32_t v2si __attribute__((__vector_size__(8)));
typedef v4hi (*CipherEncrypt64 )(void *ctx, v4hi src);
typedef v2si (*CipherEncrypt2x32 )(void *ctx, v2si src);
typedef v4si (*CipherEncrypt128)(void *ctx, v4si src);

static void ECB128_encrypt(Ciph*ciph, v4si* dst, const uint8_t* src, int length)
{
    CipherEncrypt128 encrypt = (CipherEncrypt128)ciph->cipher->encrypt;
    v4si v;
    int blocks = length>>4;
    int i;
    for (i=0;i<blocks; i++)
    {
        __builtin_memcpy(&v, &src[16*i], 16);
        dst[i] = encrypt(ciph->ctx, v);
    }
}
static void ECB128_decrypt(Ciph*ciph, v4si* dst, const uint8_t* src, int length)
{
    CipherEncrypt128 decrypt = (CipherEncrypt128)ciph->cipher->decrypt;
    v4si v;
    int blocks = length>>4;
    int i;
    for (i=0;i<blocks; i++)
    {
        __builtin_memcpy(&v, &src[16*i], 16);
        dst[i] = decrypt(ciph->ctx, v);
    }
}

void CBC128_encrypt(Ciph*ciph, v4si* dst, const uint8_t* src, int length)
{
    CipherEncrypt128 encrypt = (CipherEncrypt128)ciph->cipher->encrypt;
    v4si d, v;
    __builtin_memcpy(&v, ciph->iv, 16);
    int blocks = length>>4;
    int i;
    for (i=0;i<blocks;i++)
    {
        __builtin_memcpy(&d, &src[16*i], 16);
        d ^= v;
        v = encrypt(ciph->ctx, d);
        dst[i] = v;
    }
}
#if 0
typedef struct _XTS XTS_t;
/*	Key is the 256 or 512 bit XTS-AES key, which is composed by two fieldsof equal size, 
		namely Key1 and Key2, such that Key=Key1|Key2
	i is a 128-bit value representing the position address
	j is the sequential number of the 128-bit block inside the data unit
 */
struct _XTS {
	uint64x2_t i;
	poly64x2_t aj;
	void* key1;
	void* key2;
};
static v4si GF128_shift(v4si v);
static poly64x2_t gf128_reduction(poly64x2_t r0, poly64x2_t r1)
{
#if 0
	const poly64x2_t Px = {0x87ULL};
	poly64x2_t b = CL_MUL128(r1, Px, 0x01);
	poly64x2_t a = CL_MUL128(r1, Px, 0x00);
	poly64x2_t c = CL_MUL128( b, Px, 0x01);
	return r0 ^ a ^ c ^ SLL128U(b,64);
#elif 1// SSE+PCLMUL
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
static poly64x2_t GF128_shlm(poly64x2_t r0, int i)
{
	poly64x2_t sh = {1ULL<<i};
	poly64x2_t b  = CL_MUL128(r0,sh, 0x01);
// редуцирование
	const poly64x2_t Px ={0x86ULL};// (1 || 0^120 || x87)
	poly64x2_t b  = CL_MUL128(r1,Px, 0x01) ^ (poly64x2_t){r1[1],r1[0]};
	poly64x2_t d  = CL_MUL128( b,Px, 0x01) ^ (poly64x2_t){ b[1], b[0]};
	return r0 ^ d;
}

void XTS128_encrypt(Ciph*ciph, v4si* dst, const uint8_t* src, int length)
{
    CipherEncrypt128 encrypt = (CipherEncrypt128)ciph->cipher->encrypt;
	XTS_t* xex= (XTS_t*)ciph;
	v4si aj = (v4si)xex->aj;
    v4si d, v;
    int blocks = length>>4;// 128 bit
    int i;
    for (i=0;i<blocks;i++)
    {
		v  = encrypt(xex->key2, (v4si)xex->i);// Key2
		v  = GF128_shlm (v, i);// сдвиг и редуцирование. i<64 для блоков <8к
        __builtin_memcpy(&d, &src[16*i], 16);
        v ^= encrypt(xex->key1, d^v);// Key1
        dst[i] = v^d;
		aj = GF128_shift(aj);// aj*2
    }
}
void XTS128_decrypt(Ciph*ciph, v4si* dst, const uint8_t* src, int length)
{
    CipherEncrypt128 encrypt = (CipherEncrypt128)ciph->cipher->encrypt;
    CipherEncrypt128 decrypt = (CipherEncrypt128)ciph->cipher->decrypt;
	XTS_t* xex= (XTS_t*)ciph;
	v4si aj = (v4si)xex->aj;
    v4si d, v;
    int blocks = length>>4;// 128 bit
    int i;
    for (i=0;i<blocks;i++)
    {
		v  = encrypt(xex->key2, (v4si)xex->i);// Key2
		v  = GF128_shlm (v, i);// 
        __builtin_memcpy(&d, &src[16*i], 16);
        v ^= decrypt(xex->key1, d^v);// Key1
        dst[i] = v^d;
		aj = GF128_shift(aj);// aj*2
    }
}
#endif
static void CBC128_decrypt(Ciph *ciph, v4si* dst, const uint8_t* src, int length)
{
    CipherEncrypt128 decrypt = (CipherEncrypt128)ciph->cipher->decrypt;
    int i=length>>4;
    v4si d,v;
    __builtin_memcpy(&v, &src[16*i-16],16);
//    v = src[i-1];
    do {
        d = decrypt(ciph->ctx, v);
        if ((--i)==0) break;
        __builtin_memcpy(&v, &src[16*i-16],16);
        //v = src[i-1];
        dst[i] = d^v;
    } while(1);
    __builtin_memcpy(&v, ciph->iv, 16);
    dst[i] = d^v;
}

static inline v4si CTR128(v4si x)
{
    //uint16_t * y = (void*)x;
    x[3] = __builtin_bswap32(__builtin_bswap32(x[3])+1);
    return x;
}
/*! \brief кодирование в режиме CTR
    Функция используется и для кодирования и для декодирования CTR моды
 */
static void CTR128_encrypt(Ciph*ciph, v4si* dst, const uint8_t* src, int length)
{
    CipherEncrypt128 encrypt = (CipherEncrypt128)ciph->cipher->encrypt;
    v4si d, v, p;
    __builtin_memcpy(&v, ciph->iv, 16);
    int blocks = length>>4;
    int i;
    for (i=0;i<blocks;i++) {
        d = v;
        v = CTR128(v); // счетчик добавить и копировать
        //printf("%0x8 %0x8 %0x8 %0x8\n", v[3],v[2],v[1],v[0]);
        d = encrypt(ciph->ctx, d);
        __builtin_memcpy(&p, &src[16*i], 16);
        dst[i] =  p ^ d;
    }
    if (length & 0xF){// если длина сообщения не выровнена на 128 бит

    }
    //__builtin_memcpy(ciph->iv, &v, 16);
}
static inline v2si CTR64(v2si x)
{
    //uint16_t * y = (void*)x;
    //uint32_t v = __builtin_bswap32(x[1])+1;
    x = (v2si)__builtin_shuffle((v8qi)x, (v8qi){7,6,5,4,3,2,1,0});
    x+=(v2si){1,0};// = __builtin_bswap32(v);
    x = (v2si)__builtin_shuffle((v8qi)x, (v8qi){7,6,5,4,3,2,1,0});
    return x;
}
/*! \bag сборит по полной */
static void CTR64_encrypt(Ciph*ciph, v2si* dst, const uint8_t* src, int length)
{
    CipherEncrypt2x32 encrypt = (CipherEncrypt2x32)ciph->cipher->encrypt;
    v2si d, v, p;
   // __builtin_memcpy(&v[2], ciph->iv, 8);
#if 0
    v[0]=v[1]=0;
    v[2] = *(uint16_t*)ciph->iv;
    v[3] = ((uint16_t*)ciph->iv)[1];
#else
v[0] =0;
v[1] = *(uint32_t*)ciph->iv;
#endif
    int blocks = length>>3;
    int i;
    for (i=0;i<blocks;i++) {
        d = v;
        v = CTR64(v); // счетчик добавить и копировать
        d = encrypt(ciph->ctx, d);
        //__builtin_memcpy(&p, &src[8*i], 8);
        p = *(v2si*)(&src[8*i]);
        dst[i] =  p ^ d;
    }
    //__builtin_memcpy(ciph->iv, &v, 16);
}

//static void CCM128_encrypt(Ciph*ciph, v4si* dst, const uint8_t* src, int length)
//static void GCM128_encrypt(Ciph*ciph, v4si* dst, const uint8_t* src, int length)

static inline v4si GCTR128(v4si x)
{
    //uint16_t * y = (void*)x;
    x[0]++;// = __builtin_bswap32(__builtin_bswap32(x[0])+1);
    return x;
}

static void GCTR128_encrypt(Ciph*ciph, v4si* dst, const uint8_t* src, int length)
{
    CipherEncrypt128 encrypt = (CipherEncrypt128)ciph->cipher->encrypt;
    v4si d, v, p;
    //__builtin_memcpy(&v[2], ciph->iv, 8);
    v[0]= v[1]=0; v[2] = ((uint32_t*)ciph->iv)[0]; v[3] = ((uint32_t*)ciph->iv)[1];
    int blocks = length>>4;
    int i;
    for (i=0;i<blocks;i++) {
        d = v;
        v = GCTR128(v); // счетчик добавить и копировать
        d = encrypt(ciph->ctx, d);
        __builtin_memcpy(&p, &src[16*i], 16);
        dst[i] =  p ^ d;
    }
    //__builtin_memcpy(ciph->iv, &v, 16);
}
static inline v2si GCTR64(v2si x)
{
    //x[0]++;
    return x + (v2si){1,0};
}
static void GCTR64_encrypt(Ciph*ciph, v2si* dst, const uint8_t* src, int length)
{
    CipherEncrypt2x32 encrypt = (CipherEncrypt2x32)ciph->cipher->encrypt;
    v2si d, v, p;
    //__builtin_memcpy(&v[2], ciph->iv, 4);
#if 0
    v[0]=v[1]=0;
    v[2] = *(uint16_t*)ciph->iv;
    v[3] = ((uint16_t*)ciph->iv)[1];
#else
    v[0] = 0;
    v[1] = *(uint32_t*)ciph->iv;
#endif
    int blocks = length>>3;
    int i;
    for (i=0;i<blocks;i++) {
        d = v;
        v = GCTR64(v); // счетчик добавить и копировать
        d = encrypt(ciph->ctx, d);
        //__builtin_memcpy(&p, &src[8*i], 8);
        p = *(v2si*)(&src[8*i]);
        dst[i] =  p ^ d;
    }
    //__builtin_memcpy(ciph->iv, &v, 16);
}

/*! CFB для случая длина сегмента равна длине блока
 */
static void CFB128_encrypt(Ciph*ciph, v4si* dst, const uint8_t* src, int length)
{
    CipherEncrypt128 encrypt = (CipherEncrypt128)ciph->cipher->encrypt;
    v4si v, p;
    __builtin_memcpy(&v, ciph->iv, 16);
    int blocks = length>>4;
    int i;
    for (i=0;i<blocks;i++) {
        v = encrypt(ciph->ctx, v);
        __builtin_memcpy(&p, &src[16*i], 16);
        dst[i] = v = p ^ v;
    }
}
static void CFB128_decrypt(Ciph*ciph, v4si* dst, const uint8_t* src, int length)
{
    CipherEncrypt128 encrypt = (CipherEncrypt128)ciph->cipher->encrypt;
    v4si v, p;
    __builtin_memcpy(&v, ciph->iv, 16);
    int blocks = length>>4;
    int i;
    for (i=0;i<blocks;i++) {
        v = encrypt(ciph->ctx, v);
        __builtin_memcpy(&p, &src[16*i], 16);
        dst[i] =  p ^ v;
        v = p;
    }
}

static void OFB128_encrypt(Ciph*ciph, v4si* dst, const uint8_t* src, int length)
{
    CipherEncrypt128 encrypt = (CipherEncrypt128)ciph->cipher->encrypt;
    v4si v, p;
    __builtin_memcpy(&v, ciph->iv, 16);
    int blocks = length>>4;
    int i;
    for (i=0;i<blocks;i++) {
        v = encrypt(ciph->ctx, v);
        __builtin_memcpy(&p, &src[16*i], 16);
        dst[i] = p ^ v;
    }
}
static void OFB128_decrypt(Ciph*ciph, v4si* dst, const uint8_t* src, int length)
{
    CipherEncrypt128 encrypt = (CipherEncrypt128)ciph->cipher->encrypt;
    v4si v, p;
    __builtin_memcpy(&v, ciph->iv, 16);
    int blocks = length>>4;
    int i;
    for (i=0;i<blocks;i++) {
        v = encrypt(ciph->ctx, v);
        __builtin_memcpy(&p, &src[16*i], 16);
        dst[i] =  p ^ v;
    }
}

/*! набор функций для размера блока 64 бита
 */
static void ECB64_encrypt(Ciph*ciph, v4hi* dst, const uint8_t* src, int length)
{
    CipherEncrypt64 encrypt = (CipherEncrypt64)ciph->cipher->encrypt;
    v4hi v;
    int blocks = length>>3;
    int i;
    for (i=0;i<blocks; i++)
    {
        __builtin_memcpy(&v, &src[8*i], 8);
        dst[i] = encrypt(ciph->ctx, v);
    }
}
static void ECB64_decrypt(Ciph*ciph, v4hi* dst, const uint8_t* src, int length)
{
    CipherEncrypt64 decrypt = (CipherEncrypt64)ciph->cipher->decrypt;
    v4hi v;
    int blocks = length>>3;
    int i;
    for (i=0;i<blocks; i++)
    {
        __builtin_memcpy(&v, &src[8*i], 8);
        dst[i] = decrypt(ciph->ctx, v);
    }
}

static void CBC64_encrypt(Ciph *ciph, v4hi* dst, const uint8_t* src, int length)
{
    CipherEncrypt64 encrypt = (CipherEncrypt64)ciph->cipher->encrypt;
    v4hi d, v;
    __builtin_memcpy(&v, ciph->iv, 8);
    int blocks = length>>3;
    int i;
    for (i=0;i<blocks;i++)
    {
        __builtin_memcpy(&d, &src[8*i], 8);
        d ^= v;
        v = encrypt(ciph->ctx, d);
        dst[i] = v;
    }
}
static void CBC64_decrypt(Ciph *ciph, v4hi* dst, const uint8_t* src, int length)
{
    CipherEncrypt64 decrypt = (CipherEncrypt64)ciph->cipher->decrypt;
    int i=length>>3;
    v4hi d,v;
    __builtin_memcpy(&v, &src[8*i-8],8);
    //v = src[i-1];
    do {
        d = decrypt(ciph->ctx, v);
        if ((--i)==0) break;
        __builtin_memcpy(&v, &src[8*i-8],8);
        //v = src[i-1];
        dst[i] = d^v;
    } while(1);
    __builtin_memcpy(&v, ciph->iv,8);
    dst[0] = d^v;
}
#if 0
extern v4si gost_imit(void*ctx, const v4si in);
static void GOST64_IMIT_encrypt(Ciph *ciph, v4hi* mac, const uint8_t* src, int length)
{
    CipherEncrypt64 encrypt = (CipherEncrypt64)gost_imit;
    v4hi m = {0}/**mac*/, v;
    int blocks = (length)>>3;
    int i;
    for (i=0;i<blocks;i++) {
        __builtin_memcpy(&v, &src[8*i], 8);
        m ^= v;
        m = encrypt(ciph->ctx, m);
    }
    *mac = m;
}
#endif // 0
static v4si GF128_shift(v4si v)
{


//    v4si m = v>>31;
#if 0 // llvm
    v = (v4si)(((v16qi)v<<1) ^ (__builtin_shufflevector((v16qi)((v16qi)v<0),(v16qi)v, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0) & (v16qi){0x1,0x1,0x1,0x1, 0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1, 0x87})) ;
#elif 1
    v = (v4si)(((v16qi)v<<1) ^ (__builtin_shuffle(((v16qi)v<0), (v16qi){1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0}) & (v16qi){0x1,0x1,0x1,0x1, 0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1, 0x87})) ;
#else
    v = (v4si)__builtin_shuffle((v16qi)v, (v16qi){15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0});
    v = v<<1 ^ (__builtin_shuffle((v4si)((v4ss)v<(v4ss){0}), (v4si){3,0,1,2}) & (v4si){0x87, 0x1, 0x1, 0x1}) ;

//    v = (v4si){v[3]>>31 | v[0]<<1,v[0]>>31 | v[1]<<1,v[1]>>31 | v[2]<<1,v[2]>>31 | v[3]<<1};
//    if (v[0]&1) v[0] ^= 0x86;// 0x87
    v = (v4si)__builtin_shuffle((v16qi)v, (v16qi){15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0});
#endif // 1
    return v;
}
static void CBC_MAC128(Ciph *ciph, v4si* mac, const uint8_t* src, int length)
{
    CipherEncrypt128 encrypt = (CipherEncrypt128)ciph->cipher->encrypt;
    int blocks=(length-1)>>4;// /16
    v4si m = {0}/*mac*/,v;
    int i;
    for (i=0;i<blocks;i++) {
        v4si v;
        __builtin_memcpy(&v, &src[16*i],16);
        //v4si v = *(v4si*)&src[16*i];
        m = encrypt(ciph->ctx, m^v);
        //printf("Block #%d\n  %08X %08X %08X %08X\n", i, __builtin_bswap32(m[0]), __builtin_bswap32(m[1]), __builtin_bswap32(m[2]), __builtin_bswap32(m[3]));
    }
    v = (v4si){0};
    v4si K1 = encrypt(ciph->ctx, v);
//    printf("K1: %08X %08X %08X %08X\n", __builtin_bswap32(K1[0]), __builtin_bswap32(K1[1]), __builtin_bswap32(K1[2]), __builtin_bswap32(K1[3]));
    K1 = GF128_shift(K1);
    if (length==0 || (length & 0xF)){// если длина сообщения не выровнена на 128 бит
        K1 = GF128_shift(K1);
        if ((length & 0xF)) __builtin_memcpy((void*)&v, &src[16*i],(length & 0xF));// тут не правильно
        v[((length)>>2)&0x3]^=0x80<<((length&3));
//        printf("K2: %08X %08X %08X %08X\n", __builtin_bswap32(K1[0]), __builtin_bswap32(K1[1]), __builtin_bswap32(K1[2]), __builtin_bswap32(K1[3]));
//        printf("K2: %08X %08X %08X %08X\n", K1[0], K1[1], K1[2], K1[3]);
    } else {
        __builtin_memcpy(&v, &src[16*i],16);
    }
    m ^= v^K1;
//    printf("Block #%d in\n  %08X %08X %08X %08X\n", i, __builtin_bswap32(m[0]), __builtin_bswap32(m[1]), __builtin_bswap32(m[2]), __builtin_bswap32(m[3]));
    m = encrypt(ciph->ctx, m);
//    printf("Block #%d out\n  %08X %08X %08X %08X\n", i, __builtin_bswap32(m[0]), __builtin_bswap32(m[1]), __builtin_bswap32(m[2]), __builtin_bswap32(m[3]));
    *mac = m;
}
static v2si GF64_shift(v2si v)
{


//    v4si m = v>>31;
#if 0 // llvm
    v = (v4si)(((v16qi)v<<1) ^ (__builtin_shufflevector((v16qi)((v16qi)v<0),(v16qi)v, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0) & (v16qi){0x1,0x1,0x1,0x1, 0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1, 0x87})) ;
#elif 1
    v = (v2si)(((v8qi)v<<1) ^ (__builtin_shuffle(((v8qi)v<0), (v8qi){1,2,3,4,5,6,7,0}) & (v8qi){0x1,0x1,0x1,0x1,0x1,0x1,0x1, 0x1B})) ;
#else
    v = (v4si)__builtin_shuffle((v16qi)v, (v16qi){15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0});
    v = v<<1 ^ (__builtin_shuffle((v4si)((v4ss)v<(v4ss){0}), (v4si){3,0,1,2}) & (v4si){0x87, 0x1, 0x1, 0x1}) ;

//    v = (v4si){v[3]>>31 | v[0]<<1,v[0]>>31 | v[1]<<1,v[1]>>31 | v[2]<<1,v[2]>>31 | v[3]<<1};
//    if (v[0]&1) v[0] ^= 0x86;// 0x87
    v = (v4si)__builtin_shuffle((v16qi)v, (v16qi){15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0});
#endif // 1
    return v;
}
static void CBC_MAC64(Ciph *ciph, v2si* mac, const uint8_t* src, int length)
{
    CipherEncrypt2x32 encrypt = (CipherEncrypt2x32)ciph->cipher->encrypt;
    int blocks=(length-1)>>3;// /8
    v2si m = {0}/*mac*/,v;
    int i;
    for (i=0;i<blocks;i++) {
        v2si v;
        __builtin_memcpy(&v, &src[8*i],8);
        //v4si v = *(v4si*)&src[16*i];
        m = encrypt(ciph->ctx, m^v);
        //printf("Block #%d\n  %08X %08X %08X %08X\n", i, __builtin_bswap32(m[0]), __builtin_bswap32(m[1]), __builtin_bswap32(m[2]), __builtin_bswap32(m[3]));
    }
    v = (v2si){0};
    v2si K1 = encrypt(ciph->ctx, v);
//    printf("K1: %08X %08X %08X %08X\n", __builtin_bswap32(K1[0]), __builtin_bswap32(K1[1]), __builtin_bswap32(K1[2]), __builtin_bswap32(K1[3]));
    K1 = GF64_shift(K1);
    if (length==0 || (length & 0x7)){// если длина сообщения не выровнена на 128 бит
        K1 = GF64_shift(K1);
        if ((length & 0x7)) __builtin_memcpy((void*)&v, &src[8*i],(length & 0x7));// тут не правильно
        v[((length)>>2)&0x1]^=0x80<<((length&3));
//        printf("K2: %08X %08X %08X %08X\n", __builtin_bswap32(K1[0]), __builtin_bswap32(K1[1]), __builtin_bswap32(K1[2]), __builtin_bswap32(K1[3]));
//        printf("K2: %08X %08X %08X %08X\n", K1[0], K1[1], K1[2], K1[3]);
    } else {
        __builtin_memcpy(&v, &src[8*i],8);
    }
    m ^= v^K1;
//    printf("Block #%d in\n  %08X %08X %08X %08X\n", i, __builtin_bswap32(m[0]), __builtin_bswap32(m[1]), __builtin_bswap32(m[2]), __builtin_bswap32(m[3]));
    m = encrypt(ciph->ctx, m);
//    printf("Block #%d out\n  %08X %08X %08X %08X\n", i, __builtin_bswap32(m[0]), __builtin_bswap32(m[1]), __builtin_bswap32(m[2]), __builtin_bswap32(m[3]));
    *mac = m;
}



/*! CFB для случая длина сегмента равна длине блока
 */
//static void CFB64_encrypt(Ciph*ciph, v4hi* dst, const uint8_t* src, int length) __attribute__((__target__("inline-all-stringops")));
static void CFB64_encrypt(Ciph*ciph, v4hi* dst, const uint8_t* src, int length)
{
    CipherEncrypt64 encrypt = (CipherEncrypt64)ciph->cipher->encrypt;
    v4hi v, p;
    __builtin_memcpy(&v, ciph->iv, 8);
    int blocks = length>>3;
    int i;
    for (i=0;i<blocks;i++) {
        v = encrypt(ciph->ctx, v);
        __builtin_memcpy(&p, &src[8*i], 8);
        //p = *(v4hi*) (&src[8*i]);
        v^=p;
        dst[i] = v;
    }
    length &= 0x7;
    if (length){
        v = encrypt(ciph->ctx, v);
        __builtin_memcpy(&p, &src[8*i], length);
        v^=p;
        __builtin_memcpy(&dst[i], &v, length);
    }
}
//static void CFB64_decrypt(Ciph*ciph, v4hi* dst, const uint8_t* src, int length) __attribute__((__target__("inline-all-stringops")));
static void CFB64_decrypt(Ciph*ciph, v4hi* dst, const uint8_t* src, int length)
{
    CipherEncrypt64 encrypt = (CipherEncrypt64)ciph->cipher->encrypt;
    v4hi v, p;
    __builtin_memcpy(&v, ciph->iv, 8);
    int blocks = (length)>>3;
    int i;
    for (i=0;i<blocks;i++) {
        v = encrypt(ciph->ctx, v);
        __builtin_memcpy(&p, &src[8*i], 8);
//        p = *(v4hi*)&src[8*i];
        dst[i] =  p ^ v;
        v = p;
    }
    length &= 0x7;
    if (length){
        v = encrypt(ciph->ctx, v);
        __builtin_memcpy(&p, &src[8*i], length);
        v ^=p;
        __builtin_memcpy(&dst[i], &v, length);
    }
    //printf (" !!! CFB64_decrypt !!!! \n");
}

static
Ciph* cipher_mode_select(Ciph* ciph, int mode)
{

    if (ciph->cipher->block_len == 64){
        switch (mode){
        case CIPH_MODE_ECB:
            ciph->encrypt = (void*)ECB64_encrypt;
            ciph->decrypt = (void*)ECB64_decrypt;
            break;
        case CIPH_MODE_CBC:
            ciph->encrypt = (void*)CBC64_encrypt;
            ciph->decrypt = (void*)CBC64_decrypt;
            break;
        case CIPH_MODE_CFB:
            ciph->encrypt = (void*)CFB64_encrypt;
            ciph->decrypt = (void*)CFB64_decrypt;
            break;
        case CIPH_MODE_CTR:
            ciph->encrypt = (void*)CTR64_encrypt;
            ciph->decrypt = (void*)CTR64_encrypt;
            break;
        case CIPH_MODE_CMAC:
            ciph->encrypt = (void*)CBC_MAC64;
            ciph->decrypt = NULL;//(void*)CBC_MAC64;
            break;
        case CIPH_MODE_GCTR:
            ciph->encrypt = (void*)GCTR64_encrypt;
            ciph->decrypt = (void*)GCTR64_encrypt;
            break;
        case CIPH_MODE_IMIT:
            ciph->encrypt = NULL;//(void*)GOST64_IMIT_encrypt;
            ciph->decrypt = NULL;
            //ciph->decrypt = (void*)GIMIT_encrypt;
            break;
        default:
            ciph->encrypt = NULL;
            ciph->decrypt = NULL;
            break;
        }
    } else {
        switch (mode){
        case CIPH_MODE_ECB:
            ciph->encrypt = (void*)ECB128_encrypt;
            ciph->decrypt = (void*)ECB128_decrypt;
            break;
        case CIPH_MODE_CBC:
            ciph->encrypt = (void*)CBC128_encrypt;
            ciph->decrypt = (void*)CBC128_decrypt;
            break;
        case CIPH_MODE_CTR:
            ciph->encrypt = (void*)CTR128_encrypt;
            ciph->decrypt = (void*)CTR128_encrypt;
            break;
        case CIPH_MODE_CFB:
            ciph->encrypt = (void*)CFB128_encrypt;
            ciph->decrypt = (void*)CFB128_decrypt;
            break;
        case CIPH_MODE_OFB:
            ciph->encrypt = (void*)OFB128_encrypt;
            ciph->decrypt = (void*)OFB128_decrypt;
            break;
        case CIPH_MODE_CMAC:
            ciph->encrypt = (void*)CBC_MAC128;
            ciph->decrypt = NULL;//(void*)CBC_MAC128;
            break;
        case CIPH_MODE_GCTR:
            ciph->encrypt = (void*)GCTR128_encrypt;
            ciph->decrypt = (void*)GCTR128_encrypt;
            break;
        default:
            ciph->encrypt = NULL;
            ciph->decrypt = NULL;
            break;
        }
    }
    return ciph;
}

//extern const Cipher __start__Cipher[];
//extern const Cipher __stop__Cipher[];
static GSList* cipher_list = NULL;
void cipher_register(const Cipher* ciph)
{
    cipher_list = g_slist_append(cipher_list, (void*)ciph);
}
static void __attribute__((destructor)) cipher_fini()
{
    g_slist_free(cipher_list);cipher_list=NULL;
}

/*! \brief выбор хеш-функции по идентификатору
 */
Ciph* cipher_select(int id, int mode)
{
    GSList* list = cipher_list;
    while (list){
        const Cipher *ciph = list->data;
        if (ciph->id == id) {
            Ciph *ci = malloc(sizeof(struct _CiphAEAD));
            ci->ctx = _aligned_malloc( ciph->ctx_size, 16);
            ci->iv = NULL;
            ci->cipher = ciph;
            return cipher_mode_select(ci, mode);
        }
        list=list->next;
    }
    return NULL;
}
void cipher_set_key(Ciph* ciph, uint8_t* key, int klen, int ekb)
{
    ciph->cipher->key_exp(ciph->ctx, key, klen, ekb);
}
void cipher_free(Ciph* ciph)
{
    _aligned_free(ciph->ctx);
    free(ciph);
}
#ifdef TEST_CIPH

#include <stdio.h>
#include <string.h>
int main()
{

//    const Cipher *ciph = SEGMENT_START(Cipher);
//    const Cipher *ciph_top = SEGMENT_STOP(Cipher);
    int i=0;
    GSList* list = cipher_list;
    while (list){
        const Cipher* ciph = list->data;
        printf("%d %s\n",i, ciph->name);
        list= list->next; i++;
    }
{
    struct {
        int ciph_id;
        int ekb;
        int mode;
		int plen;
        char* key;
        char* pt;
        char* ct;
        char* iv;
    } ciph_tests [] = {
{ CIPH_TDES, 64*3, CIPH_MODE_ECB,32,// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_ECB.pdf
//Key
"\x01\x23\x45\x67\x89\xAB\xCD\xEF\x23\x45\x67\x89\xAB\xCD\xEF\x01\x45\x67\x89\xAB\xCD\xEF\x01\x23",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51",
//Ciphertext
"\x71\x47\x72\xF3\x39\x84\x1D\x34\x26\x7F\xCC\x4B\xD2\x94\x9C\xC3"
"\xEE\x11\xC2\x2A\x57\x6A\x30\x38\x76\x18\x3F\x99\xC0\xB6\xDE\x87"
},
{ CIPH_TDES, 64*3, CIPH_MODE_CBC,32,// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CBC.pdf
//Key
"\x01\x23\x45\x67\x89\xAB\xCD\xEF\x23\x45\x67\x89\xAB\xCD\xEF\x01\x45\x67\x89\xAB\xCD\xEF\x01\x23",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51",
//Ciphertext
"\x20\x79\xC3\xD5\x3A\xA7\x63\xE1\x93\xB7\x9E\x25\x69\xAB\x52\x62"
"\x51\x65\x70\x48\x1F\x25\xB5\x0F\x73\xC0\xBD\xA8\x5C\x8E\x0D\xA7",
// iv
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17"
},
{ CIPH_TDES, 64*2, CIPH_MODE_CBC,32,// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CBC.pdf
//Key
"\x01\x23\x45\x67\x89\xAB\xCD\xEF\x23\x45\x67\x89\xAB\xCD\xEF\x01",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51",
//Ciphertext
"\x74\x01\xCE\x1E\xAB\x6D\x00\x3C\xAF\xF8\x4B\xF4\x7B\x36\xCC\x21"
"\x54\xF0\x23\x8F\x9F\xFE\xCD\x8F\x6A\xCF\x11\x83\x92\xB4\x55\x81",
// iv
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17"
},
#if 1
{ CIPH_TDES, 64*3, CIPH_MODE_CTR,32,// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CBC.pdf
//Key
"\x01\x23\x45\x67\x89\xAB\xCD\xEF\x23\x45\x67\x89\xAB\xCD\xEF\x01\x45\x67\x89\xAB\xCD\xEF\x01\x23",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51",
//Ciphertext
"\x07\x8B\xB7\x4E\x59\xCE\x7E\xD6\x19\xAA\x11\xD2\x50\x04\xFB\x65"
"\xA0\x3C\xED\xF1\xBA\x0B\x09\xBA\xA3\xBC\x81\xB8\xF6\x9C\x1D\xA9",
// iv
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17"
},
#endif
{ CIPH_TDES, 64*2, CIPH_MODE_CTR,32,// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CBC.pdf
//Key
"\x01\x23\x45\x67\x89\xAB\xCD\xEF\x23\x45\x67\x89\xAB\xCD\xEF\x01",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51",
//Ciphertext
"\x61\x95\xB9\xC2\xC3\x99\x09\xC5\xDB\xDF\x92\xDA\xDB\xAD\x5A\x5D"
"\x15\x68\x48\x2B\xF2\x5C\x42\xC9\x6D\x38\x53\xA8\xE7\x1B\x01\x0E",
// iv
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17"
},
{ CIPH_TDES, 64*3, CIPH_MODE_CMAC,0,// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CMAC.pdf
//Key
"\x01\x23\x45\x67\x89\xAB\xCD\xEF\x23\x45\x67\x89\xAB\xCD\xEF\x01\x45\x67\x89\xAB\xCD\xEF\x01\x23",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51",
//Ciphertext
"\x7D\xB0\xD3\x7D\xF9\x36\xC5\x50",
},
{ CIPH_TDES, 64*3, CIPH_MODE_CMAC,16,// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CMAC.pdf
//Key
"\x01\x23\x45\x67\x89\xAB\xCD\xEF\x23\x45\x67\x89\xAB\xCD\xEF\x01\x45\x67\x89\xAB\xCD\xEF\x01\x23",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51",
//Ciphertext
"\x30\x23\x9C\xF1\xF5\x2E\x66\x09",
},
{ CIPH_TDES, 64*3, CIPH_MODE_CMAC,20,// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CMAC.pdf
//Key
"\x01\x23\x45\x67\x89\xAB\xCD\xEF\x23\x45\x67\x89\xAB\xCD\xEF\x01\x45\x67\x89\xAB\xCD\xEF\x01\x23",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51",
//Ciphertext
"\x6C\x9F\x3E\xE4\x92\x3F\x6B\xE2",
},
{ CIPH_TDES, 64*3, CIPH_MODE_CMAC,32,// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_CMAC.pdf
//Key
"\x01\x23\x45\x67\x89\xAB\xCD\xEF\x23\x45\x67\x89\xAB\xCD\xEF\x01\x45\x67\x89\xAB\xCD\xEF\x01\x23",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51",
//Ciphertext
"\x99\x42\x9B\xD0\xBF\x79\x04\xE5",
},

{ CIPH_AES, 128, CIPH_MODE_ECB,64,
//Key
"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
//Ciphertext
"\x3A\xD7\x7B\xB4\x0D\x7A\x36\x60\xA8\x9E\xCA\xF3\x24\x66\xEF\x97"
"\xF5\xD3\xD5\x85\x03\xB9\x69\x9D\xE7\x85\x89\x5A\x96\xFD\xBA\xAF"
"\x43\xB1\xCD\x7F\x59\x8E\xCE\x23\x88\x1B\x00\xE3\xED\x03\x06\x88"
"\x7B\x0C\x78\x5E\x27\xE8\xAD\x3F\x82\x23\x20\x71\x04\x72\x5D\xD4"},
{ CIPH_AES, 192, CIPH_MODE_ECB,64,
"\x8E\x73\xB0\xF7\xDA\x0E\x64\x52\xC8\x10\xF3\x2B\x80\x90\x79\xE5"
"\x62\xF8\xEA\xD2\x52\x2C\x6B\x7B",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
//
"\xBD\x33\x4F\x1D\x6E\x45\xF2\x5F\xF7\x12\xA2\x14\x57\x1F\xA5\xCC"
"\x97\x41\x04\x84\x6D\x0A\xD3\xAD\x77\x34\xEC\xB3\xEC\xEE\x4E\xEF"
"\xEF\x7A\xFD\x22\x70\xE2\xE6\x0A\xDC\xE0\xBA\x2F\xAC\xE6\x44\x4E"
"\x9A\x4B\x41\xBA\x73\x8D\x6C\x72\xFB\x16\x69\x16\x03\xC1\x8E\x0E"
},
{CIPH_AES, 256, CIPH_MODE_ECB,64,
"\x60\x3D\xEB\x10\x15\xCA\x71\xBE\x2B\x73\xAE\xF0\x85\x7D\x77\x81"
"\x1F\x35\x2C\x07\x3B\x61\x08\xD7\x2D\x98\x10\xA3\x09\x14\xDF\xF4",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
//
"\xF3\xEE\xD1\xBD\xB5\xD2\xA0\x3C\x06\x4B\x5A\x7E\x3D\xB1\x81\xF8"
"\x59\x1C\xCB\x10\xD4\x10\xED\x26\xDC\x5B\xA7\x4A\x31\x36\x28\x70"
"\xB6\xED\x21\xB9\x9C\xA6\xF4\xF9\xF1\x53\xE7\xB1\xBE\xAF\xED\x1D"
"\x23\x30\x4B\x7A\x39\xF9\xF3\xFF\x06\x7D\x8D\x8F\x9E\x24\xEC\xC7"
},
{ CIPH_AES, 128, CIPH_MODE_CBC,64,
//Key
"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
//Ciphertext
"\x76\x49\xAB\xAC\x81\x19\xB2\x46\xCE\xE9\x8E\x9B\x12\xE9\x19\x7D"
"\x50\x86\xCB\x9B\x50\x72\x19\xEE\x95\xDB\x11\x3A\x91\x76\x78\xB2"
"\x73\xBE\xD6\xB8\xE3\xC1\x74\x3B\x71\x16\xE6\x9E\x22\x22\x95\x16"
"\x3F\xF1\xCA\xA1\x68\x1F\xAC\x09\x12\x0E\xCA\x30\x75\x86\xE1\xA7",
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
},
{ CIPH_AES, 192, CIPH_MODE_CBC,64,
"\x8E\x73\xB0\xF7\xDA\x0E\x64\x52\xC8\x10\xF3\x2B\x80\x90\x79\xE5"
"\x62\xF8\xEA\xD2\x52\x2C\x6B\x7B",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
//
"\x4F\x02\x1D\xB2\x43\xBC\x63\x3D\x71\x78\x18\x3A\x9F\xA0\x71\xE8"
"\xB4\xD9\xAD\xA9\xAD\x7D\xED\xF4\xE5\xE7\x38\x76\x3F\x69\x14\x5A"
"\x57\x1B\x24\x20\x12\xFB\x7A\xE0\x7F\xA9\xBA\xAC\x3D\xF1\x02\xE0"
"\x08\xB0\xE2\x79\x88\x59\x88\x81\xD9\x20\xA9\xE6\x4F\x56\x15\xCD",
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
},
{CIPH_AES, 256, CIPH_MODE_CBC,64,
"\x60\x3D\xEB\x10\x15\xCA\x71\xBE\x2B\x73\xAE\xF0\x85\x7D\x77\x81"
"\x1F\x35\x2C\x07\x3B\x61\x08\xD7\x2D\x98\x10\xA3\x09\x14\xDF\xF4",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
//
"\xF5\x8C\x4C\x04\xD6\xE5\xF1\xBA\x77\x9E\xAB\xFB\x5F\x7B\xFB\xD6"
"\x9C\xFC\x4E\x96\x7E\xDB\x80\x8D\x67\x9F\x77\x7B\xC6\x70\x2C\x7D"
"\x39\xF2\x33\x69\xA9\xD9\xBA\xCF\xA5\x30\xE2\x63\x04\x23\x14\x61"
"\xB2\xEB\x05\xE2\xC3\x9B\xE9\xFC\xDA\x6C\x19\x07\x8C\x6A\x9D\x1B",
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
},
{CIPH_AES, 128, CIPH_MODE_CTR,64,
//Key
"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
//
"\x87\x4D\x61\x91\xB6\x20\xE3\x26\x1B\xEF\x68\x64\x99\x0D\xB6\xCE"
"\x98\x06\xF6\x6B\x79\x70\xFD\xFF\x86\x17\x18\x7B\xB9\xFF\xFD\xFF"
"\x5A\xE4\xDF\x3E\xDB\xD5\xD3\x5E\x5B\x4F\x09\x02\x0D\xB0\x3E\xAB"
"\x1E\x03\x1D\xDA\x2F\xBE\x03\xD1\x79\x21\x70\xA0\xF3\x00\x9C\xEE",
//Initial Counter is
"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"
},
{CIPH_AES, 192, CIPH_MODE_CTR,64,
//Key
"\x8E\x73\xB0\xF7\xDA\x0E\x64\x52\xC8\x10\xF3\x2B\x80\x90\x79\xE5"
"\x62\xF8\xEA\xD2\x52\x2C\x6B\x7B",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
//
"\x1A\xBC\x93\x24\x17\x52\x1C\xA2\x4F\x2B\x04\x59\xFE\x7E\x6E\x0B"
"\x09\x03\x39\xEC\x0A\xA6\xFA\xEF\xD5\xCC\xC2\xC6\xF4\xCE\x8E\x94"
"\x1E\x36\xB2\x6B\xD1\xEB\xC6\x70\xD1\xBD\x1D\x66\x56\x20\xAB\xF7"
"\x4F\x78\xA7\xF6\xD2\x98\x09\x58\x5A\x97\xDA\xEC\x58\xC6\xB0\x50",
//IV is
"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"
},
{CIPH_AES, 256, CIPH_MODE_CTR,64,
"\x60\x3D\xEB\x10\x15\xCA\x71\xBE\x2B\x73\xAE\xF0\x85\x7D\x77\x81"
"\x1F\x35\x2C\x07\x3B\x61\x08\xD7\x2D\x98\x10\xA3\x09\x14\xDF\xF4",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
//
"\x60\x1E\xC3\x13\x77\x57\x89\xA5\xB7\xA7\xF5\x04\xBB\xF3\xD2\x28"
"\xF4\x43\xE3\xCA\x4D\x62\xB5\x9A\xCA\x84\xE9\x90\xCA\xCA\xF5\xC5"
"\x2B\x09\x30\xDA\xA2\x3D\xE9\x4C\xE8\x70\x17\xBA\x2D\x84\x98\x8D"
"\xDF\xC9\xC5\x8D\xB6\x7A\xAD\xA6\x13\xC2\xDD\x08\x45\x79\x41\xA6",
//IV is
"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"
},
{ CIPH_AES, 128, CIPH_MODE_CMAC,0,// Example #2 https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
//Key
"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A",
//Ciphertext
"\xBB\x1D\x69\x29\xE9\x59\x37\x28\x7F\xA3\x7D\x12\x9B\x75\x67\x46"
},
{ CIPH_AES, 128, CIPH_MODE_CMAC,16,// Example #2 https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
//Key
"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A",
//Ciphertext
"\x07\x0A\x16\xB4\x6B\x4D\x41\x44\xF7\x9B\xDD\x9D\xD0\x4A\x28\x7C"
},
{ CIPH_AES, 128, CIPH_MODE_CMAC,20,// Example #2 https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
//Key
"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57",
//Ciphertext
"\x7D\x85\x44\x9E\xA6\xEA\x19\xC8\x23\xA7\xBF\x78\x83\x7D\xFA\xDE"
},
{ CIPH_AES, 128, CIPH_MODE_CMAC,64,// Example #2 https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
//Key
"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
//Ciphertext
"\x51\xF0\xBE\xBF\x7E\x3B\x9D\x92\xFC\x49\x74\x17\x79\x36\x3C\xFE"
},
{CIPH_AES, 128, CIPH_MODE_CFB,64,
//Key
"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
//
"\x3B\x3F\xD9\x2E\xB7\x2D\xAD\x20\x33\x34\x49\xF8\xE8\x3C\xFB\x4A"
"\xC8\xA6\x45\x37\xA0\xB3\xA9\x3F\xCD\xE3\xCD\xAD\x9F\x1C\xE5\x8B"
"\x26\x75\x1F\x67\xA3\xCB\xB1\x40\xB1\x80\x8C\xF1\x87\xA4\xF4\xDF"
"\xC0\x4B\x05\x35\x7C\x5D\x1C\x0E\xEA\xC4\xC6\x6F\x9F\xF7\xF2\xE6",
//IV is
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
},
{CIPH_AES, 192, CIPH_MODE_CFB,64,
//Key
"\x8E\x73\xB0\xF7\xDA\x0E\x64\x52\xC8\x10\xF3\x2B\x80\x90\x79\xE5"
"\x62\xF8\xEA\xD2\x52\x2C\x6B\x7B",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
//
"\xCD\xC8\x0D\x6F\xDD\xF1\x8C\xAB\x34\xC2\x59\x09\xC9\x9A\x41\x74"
"\x67\xCE\x7F\x7F\x81\x17\x36\x21\x96\x1A\x2B\x70\x17\x1D\x3D\x7A"
"\x2E\x1E\x8A\x1D\xD5\x9B\x88\xB1\xC8\xE6\x0F\xED\x1E\xFA\xC4\xC9"
"\xC0\x5F\x9F\x9C\xA9\x83\x4F\xA0\x42\xAE\x8F\xBA\x58\x4B\x09\xFF",
//IV is
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
},
{CIPH_AES, 256, CIPH_MODE_CFB,64,
"\x60\x3D\xEB\x10\x15\xCA\x71\xBE\x2B\x73\xAE\xF0\x85\x7D\x77\x81"
"\x1F\x35\x2C\x07\x3B\x61\x08\xD7\x2D\x98\x10\xA3\x09\x14\xDF\xF4",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
//
"\xDC\x7E\x84\xBF\xDA\x79\x16\x4B\x7E\xCD\x84\x86\x98\x5D\x38\x60"
"\x39\xFF\xED\x14\x3B\x28\xB1\xC8\x32\x11\x3C\x63\x31\xE5\x40\x7B"
"\xDF\x10\x13\x24\x15\xE5\x4B\x92\xA1\x3E\xD0\xA8\x26\x7A\xE2\xF9"
"\x75\xA3\x85\x74\x1A\xB9\xCE\xF8\x20\x31\x62\x3D\x55\xB1\xE4\x71",
//IV is
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
},
{CIPH_AES, 128, CIPH_MODE_OFB,64,
//Key
"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
//
"\x3B\x3F\xD9\x2E\xB7\x2D\xAD\x20\x33\x34\x49\xF8\xE8\x3C\xFB\x4A"
"\x77\x89\x50\x8D\x16\x91\x8F\x03\xF5\x3C\x52\xDA\xC5\x4E\xD8\x25"
"\x97\x40\x05\x1E\x9C\x5F\xEC\xF6\x43\x44\xF7\xA8\x22\x60\xED\xCC"
"\x30\x4C\x65\x28\xF6\x59\xC7\x78\x66\xA5\x10\xD9\xC1\xD6\xAE\x5E",
//IV is
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
},
{CIPH_AES, 192, CIPH_MODE_OFB,64,
//Key
"\x8E\x73\xB0\xF7\xDA\x0E\x64\x52\xC8\x10\xF3\x2B\x80\x90\x79\xE5"
"\x62\xF8\xEA\xD2\x52\x2C\x6B\x7B",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
//
"\xCD\xC8\x0D\x6F\xDD\xF1\x8C\xAB\x34\xC2\x59\x09\xC9\x9A\x41\x74"
"\xFC\xC2\x8B\x8D\x4C\x63\x83\x7C\x09\xE8\x17\x00\xC1\x10\x04\x01"
"\x8D\x9A\x9A\xEA\xC0\xF6\x59\x6F\x55\x9C\x6D\x4D\xAF\x59\xA5\xF2"
"\x6D\x9F\x20\x08\x57\xCA\x6C\x3E\x9C\xAC\x52\x4B\xD9\xAC\xC9\x2A",
//IV is
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
},
{CIPH_AES, 256, CIPH_MODE_OFB, 64,
"\x60\x3D\xEB\x10\x15\xCA\x71\xBE\x2B\x73\xAE\xF0\x85\x7D\x77\x81"
"\x1F\x35\x2C\x07\x3B\x61\x08\xD7\x2D\x98\x10\xA3\x09\x14\xDF\xF4",
//Plaintext is
"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A"
"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51"
"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF"
"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10",
//
"\xDC\x7E\x84\xBF\xDA\x79\x16\x4B\x7E\xCD\x84\x86\x98\x5D\x38\x60"
"\x4F\xEB\xDC\x67\x40\xD2\x0B\x3A\xC8\x8F\x6A\xD8\x2A\x4F\xB0\x8D"
"\x71\xAB\x47\xA0\x86\xE8\x6E\xED\xF3\x9D\x1C\x5B\xBA\x97\xC4\x08"
"\x01\x26\x14\x1D\x67\xF3\x7B\xE8\x53\x8F\x5A\x8B\xE7\x40\xE4\x84",
//IV is
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
},
// [ТК26УЗ] http://www.tc26.ru/methods/recommendation/%D0%A2%D0%9A26%D0%A3%D0%97.pdf
{CIPH_GOST, Gost28147_TC26_ParamSet_Z, CIPH_MODE_ECB, 16,
// key
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x80"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xd0",
// plaintext
"\x01\x02\x03\x04\x05\x06\x07\x08\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8",
// ciphertext
"\xce\x5a\x5e\xd7\xe0\x57\x7a\x5f\xd0\xcc\x85\xce\x31\x63\x5b\x8b",
},
{CIPH_GOST, Gost28147_Test_ParamSet, CIPH_MODE_ECB, 8,
// key
"\x75\x71\x31\x34\xB6\x0F\xEC\x45\xA6\x07\xBB\x83\xAA\x37\x46\xAF"
"\x4F\xF9\x9D\xA6\xD1\xB5\x3B\x5B\x1B\x40\x2A\x1B\xAA\x03\x0D\x1B",
// plaintext
"\x11\x22\x33\x44\x55\x66\x77\x88",
// ciphertext
"\x03\x25\x1E\x14\xF9\xD2\x8A\xCB",
},
// Р 50.1.113-2016
{CIPH_GOST,  Gost28147_TC26_ParamSet_Z , CIPH_MODE_ECB, 32,
// key
"\xa1\xaa\x5f\x7d\xe4\x02\xd7\xb3\xd3\x23\xf2\x99\x1c\x8d\x45\x34"
"\x01\x31\x37\x01\x0a\x83\x75\x4f\xd0\xaf\x6d\x7c\xd4\x92\x2e\xd9",
// plaintext
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f",
// ciphertext
"\xd1\x55\x47\xf8\xee\x85\x12\x1b\xc8\x7d\x4b\x10\x27\xd2\x60\x27"
"\xec\xc0\x71\xbb\xa6\xe7\x2f\x3f\xec\x6f\x62\x0f\x56\x83\x4c\x5a",
},
#if 0 // сбоит??
{CIPH_GOST, Gost28147_TC26_ParamSet_Z, CIPH_MODE_IMIT, 32+8,
// key
"\xa1\xaa\x5f\x7d\xe4\x02\xd7\xb3\xd3\x23\xf2\x99\x1c\x8d\x45\x34"
"\x01\x31\x37\x01\x0a\x83\x75\x4f\xd0\xaf\x6d\x7c\xd4\x92\x2e\xd9",
// plaintext
"\xaf\x21\x43\x41\x45\x65\x63\x78"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f",
// иммитовставка
"\xbe\x33\xf0\x52"
},
#endif // 0

{CIPH_GOST, Gost28147_Test_ParamSet, CIPH_MODE_CFB, 16,
// крипто про
"\x75\x71\x31\x34\xB6\x0F\xEC\x45\xA6\x07\xBB\x83\xAA\x37\x46\xAF"
"\x4F\xF9\x9D\xA6\xD1\xB5\x3B\x5B\x1B\x40\x2A\x1B\xAA\x03\x0D\x1B",
"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\x80\x00\x00",
"\x6E\xE8\x45\x86\xDD\x2B\xCA\x0C\xAD\x36\x16\x94\x0E\x16\x42\x42",
"\x01\x02\x03\x04\x05\x06\x07\x08"
},
{CIPH_RC2, 63, CIPH_MODE_ECB, 8,
"\x00\x00\x00\x00\x00\x00\x00\x00",
"\x00\x00\x00\x00\x00\x00\x00\x00",
"\xeb\xb7\x73\xf9\x93\x27\x8e\xff"
},
{CIPH_RC2, 64, CIPH_MODE_ECB, 8,
"\xff\xff\xff\xff\xff\xff\xff\xff",
"\xff\xff\xff\xff\xff\xff\xff\xff",
"\x27\x8b\x27\xe4\x2e\x2f\x0d\x49"
},
{CIPH_RC2, 64, CIPH_MODE_ECB, 8,
"\x30\x00\x00\x00\x00\x00\x00\x00",
"\x10\x00\x00\x00\x00\x00\x00\x01",
"\x30\x64\x9e\xdf\x9b\xe7\xd2\xc2"
},
/* крипто про http://cryptomanager.com/tv.html
{CIPH_RC2, 80, CIPH_MODE_ECB, 32,
"\x26\x1E\x57\x8E\xC9\x62\xBF\xB8\x3E\x96",
"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00",
"\xF9\x9A\x3A\xDB\x00\x3B\x7A\xEB\x81\xE3\x6B\xA9\xE5\x37\x10\xD1\xF9\x9A\x3A\xDB\x00\x3B\x7A\xEB\x81\xE3\x6B\xA9\xE5\x37\x10\xD1"
},
*/
{CIPH_GOST, Gost28147_UKR_SBOX1, CIPH_MODE_CMAC, 16,
"\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00"
"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
"\x55\x55\x55\x55\xAA\xAA\xAA\xAA\x55\x55\x55\x55\xCC\xCC\xCC\xCC",
"\xBA\x94\x82\xCC",
"\x00\x00\x00\x00\x00\x00\x00\x00",
},
{CIPH_MAGMA, 64, CIPH_MODE_ECB, 32,
"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6\xf5\xf4\xf3\xf2\xf1\xf0"
"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
//"\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00"
//"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
"\x59\x0a\x13\x3c\x6b\xf0\xde\x92"
"\x20\x9d\x18\xf8\x04\xc7\x54\xdb"
"\x4c\x02\xa8\x67\x2e\xfb\x98\x4a"
"\x41\x7e\xb5\x17\x9b\x40\x12\x89"
,
"\xa0\x72\xf3\x94\x04\x3f\x07\x2b"
"\x48\x6e\x55\xd3\x15\xe7\x70\xde"
"\x1e\xbc\xcf\xea\xe9\xd9\xd8\x11"
"\xfb\x7e\xc6\x96\x09\x26\x68\x7c"
},
{CIPH_MAGMA, 64, CIPH_MODE_ECB, 8,
"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6\xf5\xf4\xf3\xf2\xf1\xf0"
"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
//"\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00"
//"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
"\x10\x32\x54\x76\x98\xba\xdc\xfe"
/*
92def06b3c130a59	2b073f0494f372a0
db54c704f8189d20    de70e715d3556e48
4a98fb2e67a8024c	11d8d9e9eacfbc1e
8912409b17b57e41	7c68260996c67efb
*/
,
"\x3d\xca\xd8\xc2\xe5\x01\xe9\x4e"
},
// А.2.2 Режим гаммирования
{CIPH_MAGMA, 64, CIPH_MODE_GCTR, 32,
"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6\xf5\xf4\xf3\xf2\xf1\xf0"
"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
//"\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00"
//"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
"\x59\x0a\x13\x3c\x6b\xf0\xde\x92"
"\x20\x9d\x18\xf8\x04\xc7\x54\xdb"
"\x4c\x02\xa8\x67\x2e\xfb\x98\x4a"
"\x41\x7e\xb5\x17\x9b\x40\x12\x89"
,
"\x3c\xb9\xb7\x97\x0c\x11\x98\x4e"
"\x69\x5d\xe8\xd6\x93\x0d\x25\x3e"
"\xef\xdb\xb2\x07\x88\x86\x6d\x13"
"\x2d\xa1\x52\xab\x80\xb6\x8e\x56"
,
"\x78\x56\x34\x12"
},
// ГОСТ Р 34.13 -2015  А.2.5 Режим гаммирования с обратной связью по шифртексту
// работать не будет потому что длинный IV
{CIPH_MAGMA, 64, CIPH_MODE_CFB, 32,
"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6\xf5\xf4\xf3\xf2\xf1\xf0"
"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
"\x59\x0a\x13\x3c\x6b\xf0\xde\x92"
"\x20\x9d\x18\xf8\x04\xc7\x54\xdb"
"\x4c\x02\xa8\x67\x2e\xfb\x98\x4a"
"\x41\x7e\xb5\x17\x9b\x40\x12\x89"
,
"\x6E\xE8\x45\x86\xDD\x2B\xCA\x0C\xAD\x36\x16\x94\x0E\x16\x42\x42",
"\x12\x34\x56\x78\x90\xab\xcd\xef\x23\x45\x67\x89\x0a\xbc\xde\xf1"
},

{CIPH_KUZNYECHIK, 128, CIPH_MODE_ECB, 64,
"\xef\xcd\xab\x89\x67\x45\x23\x01\x10\x32\x54\x76\x98\xba\xdc\xfe"
"\x77\x66\x55\x44\x33\x22\x11\x00\xff\xee\xdd\xcc\xbb\xaa\x99\x88",
//"\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77"
//"\xfe\xdc\xba\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xab\xcd\xef",
"\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x77\x66\x55\x44\x33\x22\x11"
"\x0a\xff\xee\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00"
"\x00\x0a\xff\xee\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11"
"\x11\x00\x0a\xff\xee\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22"
,
"\xcd\xed\xd4\xb9\x42\x8d\x46\x5a\x30\x24\xbc\xbe\x90\x9d\x67\x7f"
"\x8b\xd0\x18\x67\xd7\x52\x54\x28\xf9\x32\x00\x6e\x2c\x91\x29\xb4"
"\x57\xb1\xd4\x3b\x31\xa5\xf5\xf3\xee\x7c\x24\x9d\x54\x33\xca\xf0"
"\x98\xda\x8a\xaa\xc5\xc4\x02\x3a\xeb\xb9\x30\xe8\xcd\x9c\xb0\xd0"
},
{CIPH_KUZNYECHIK, 128, CIPH_MODE_GCTR, 64,
"\xef\xcd\xab\x89\x67\x45\x23\x01\x10\x32\x54\x76\x98\xba\xdc\xfe"
"\x77\x66\x55\x44\x33\x22\x11\x00\xff\xee\xdd\xcc\xbb\xaa\x99\x88",
//"\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77"
//"\xfe\xdc\xba\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xab\xcd\xef",
"\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x77\x66\x55\x44\x33\x22\x11"
"\x0a\xff\xee\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00"
"\x00\x0a\xff\xee\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11"
"\x11\x00\x0a\xff\xee\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22"
,
"\xb8\xa1\xbd\x40\xa2\x5f\x7b\xd5\xdb\xd1\x0e\xc1\xbe\xd8\x95\xf1"
"\xe4\xde\x45\x3c\xb3\xe4\x3c\xf3\x5d\x3e\xa1\xf6\x33\xe7\xee\x85"
"\xa5\xa3\x64\x35\xf1\x77\xe8\xd5\xd3\x6e\x35\xe6\x8b\xe8\xea\xa5"
"\x73\xba\xbd\x20\x58\xd1\xc6\xd1\xb6\xba\x0c\xf2\xb1\xfa\x91\xcb"
,
//"\x00\x00\x00\x00\x00\x00\x00\x00"
"\xf0\xce\xab\x90\x78\x56\x34\x12"
},
{CIPH_RC5, 0, CIPH_MODE_ECB, 8,
"\x00\x00\x00\x00\x00\x00\x00\x00",
"\x00\x00\x00\x00\x00\x00\x00\x00",
"\x7a\x7b\xba\x4d\x79\x11\x1d\x1e",
"\x00\x00\x00\x00\x00\x00\x00\x00"
},
{CIPH_RC5, 2, CIPH_MODE_ECB, 8,
"\x00\x00\x00\x00\x00\x00\x00\x00",
"\x00\x00\x00\x00\x00\x00\x00\x00",
"\xdc\xa2\x69\x4b\xf4\x0e\x07\x88",
//"\x7a\x7b\xba\x4d\x79\x11\x1d\x1e",
"\x00\x00\x00\x00\x00\x00\x00\x00"
},
{CIPH_RC5, 12, CIPH_MODE_CBC, 8,
"\x00\x00\x00\x00\x00\x00\x00\x00",
"\x10\x20\x30\x40\x50\x60\x70\x80",
"\xb2\xb3\x20\x9d\xb6\x59\x4d\xa4",
"\x01\x02\x03\x04\x05\x06\x07\x08"
},
#if 0
RC5_CBC     R =  0 Key = 00 IV = 0000000000000000
   P = 0000000000000000 C = 7a7bba4d79111d1e
  RC5_CBC     R =  0 Key = 00 IV = 0000000000000000
   P = ffffffffffffffff C = 797bba4d78111d1e
  RC5_CBC     R =  0 Key = 00 IV = 0000000000000001
   P = 0000000000000000 C = 7a7bba4d79111d1f
  RC5_CBC     R =  0 Key = 00 IV = 0000000000000000
   P = 0000000000000001 C = 7a7bba4d79111d1f
  RC5_CBC     R =  0 Key = 00 IV = 0102030405060708
   P = 1020304050607080 C = 8b9ded91ce7794a6
  RC5_CBC     R =  1 Key = 11 IV = 0000000000000000
   P = 0000000000000000 C = 2f759fe7ad86a378
  RC5_CBC     R =  2 Key = 00 IV = 0000000000000000
   P = 0000000000000000 C = dca2694bf40e0788
  RC5_CBC     R =  2 Key = 00000000 IV = 0000000000000000
   P = 0000000000000000 C = dca2694bf40e0788
  RC5_CBC     R =  8 Key = 00 IV = 0000000000000000
   P = 0000000000000000 C = dcfe098577eca5ff
  RC5_CBC     R =  8 Key = 00 IV = 0102030405060708
   P = 1020304050607080 C = 9646fb77638f9ca8
  RC5_CBC     R = 12 Key = 00 IV = 0102030405060708
   P = 1020304050607080 C = b2b3209db6594da4
  RC5_CBC     R = 16 Key = 00 IV = 0102030405060708
   P = 1020304050607080 C = 545f7f32a5fc3836
  RC5_CBC     R =  8 Key = 01020304 IV = 0000000000000000
   P = ffffffffffffffff C = 8285e7c1b5bc7402
  RC5_CBC     R = 12 Key = 01020304 IV = 0000000000000000
   P = ffffffffffffffff C = fc586f92f7080934
  RC5_CBC     R = 16 Key = 01020304 IV = 0000000000000000
   P = ffffffffffffffff C = cf270ef9717ff7c4
  RC5_CBC     R = 12 Key = 0102030405060708 IV = 0000000000000000
   P = ffffffffffffffff C = e493f1c1bb4d6e8c
#endif // 0
{
},
};

    char* mode_name[] = {
    [CIPH_MODE_ECB]  ="ECB",
    [CIPH_MODE_CBC]  ="CBC",
    [CIPH_MODE_CFB]  ="CFB",
    [CIPH_MODE_OFB]  ="OFB",
    [CIPH_MODE_CTR]  ="CTR",
	[CIPH_MODE_XTS]  ="XTS",
    [CIPH_MODE_CCM]  ="CCM",
    [CIPH_MODE_GCM]  ="GCM",
    [CIPH_MODE_MGM]  ="MGM",
    [CIPH_MODE_CMAC] ="CMAC",
    [CIPH_MODE_GCTR] ="CTR_GOST",
    [CIPH_MODE_IMIT] ="IMIT",
//    [CIPH_MODE_MAC_GOST]  ="MAC_GOST",
    };
    uint8_t buf[16*4] __attribute__((__aligned__(16)));
    printf("Encryption:\n");
    for (i=0;i<64 && ciph_tests[i].ciph_id>0;i++){
        Ciph* ci = cipher_select(ciph_tests[i].ciph_id, ciph_tests[i].mode);
        cipher_set_key(ci, (uint8_t*)ciph_tests[i].key, ci->cipher->block_len/8, ciph_tests[i].ekb);
        ci->iv = (uint8_t*)ciph_tests[i].iv;
        if (ciph_tests[i].mode==CIPH_MODE_CMAC) __builtin_memset(buf,0,ci->cipher->block_len/8);
        ci->encrypt(ci, buf, (uint8_t*)ciph_tests[i].pt, ciph_tests[i].plen);
//        if (ciph_tests[i].mode==CIPH_MODE_CMAC)
        int len = ciph_tests[i].mode!=CIPH_MODE_CMAC?ciph_tests[i].plen: ci->cipher->block_len/8;
        if (memcmp(buf, ciph_tests[i].ct, len)==0)
            printf("%s-%d %s OK\n", ci->cipher->name, ciph_tests[i].ekb, mode_name[ciph_tests[i].mode]);
        else {
            printf("%s-%d %s Fail\n", ci->cipher->name, ciph_tests[i].ekb, mode_name[ciph_tests[i].mode]);
            int k;
            for (k=0;k<len;k++) printf(" %02X", buf[k]);
            printf("\n");
            for (k=0;k<len;k++) printf(" %02X", (uint8_t)ciph_tests[i].ct[k]);
            printf("\n");

        }
        cipher_free(ci);
    }
    printf("Decryption:\n");
    for (i=0;i<32 && ciph_tests[i].ciph_id>0;i++){
        Ciph* ci = cipher_select(ciph_tests[i].ciph_id, ciph_tests[i].mode);
        int ekb = ciph_tests[i].ekb;
        if (ciph_tests[i].ciph_id==CIPH_AES && (ciph_tests[i].mode== CIPH_MODE_ECB || ciph_tests[i].mode==CIPH_MODE_CBC || ciph_tests[i].mode==CIPH_MODE_XTS ))  ekb |= 0x10000;// генерация обратного ключа только для AES
        cipher_set_key(ci, (uint8_t*)ciph_tests[i].key, ci->cipher->block_len/8, ekb);
        ci->iv = (uint8_t*)ciph_tests[i].iv;
        if (ci->decrypt!=NULL){
            ci->decrypt(ci, buf, (uint8_t*)ciph_tests[i].ct, ciph_tests[i].plen);
            if (memcmp(buf, ciph_tests[i].pt, ciph_tests[i].plen)==0)
                printf("%s-%d %s OK\n", ci->cipher->name, ciph_tests[i].ekb, mode_name[ciph_tests[i].mode]);
            else {
                printf("%s-%d %s Fail\n", ci->cipher->name, ciph_tests[i].ekb, mode_name[ciph_tests[i].mode]);
                int k;
                for (k=0;k<8;k++) printf(" %02X", buf[k]);
                printf("\n");
                for (k=0;k<8;k++) printf(" %02X", (uint8_t)ciph_tests[i].pt[k]);
                printf("\n");

            }
        }
        cipher_free(ci);
    }
}
    return 0;
}
#endif
