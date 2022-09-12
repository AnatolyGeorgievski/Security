/*!
	\see [RFC7714] AES-GCM Authenticated Encryption in the Secure Real-time Transport Protocol (SRTP)
 GHASH
    https://pdfs.semanticscholar.org/114a/4222c53f1a6879f1a77f1bae2fc0f8f55348.pdf
    https://www.intel.com/content/dam/www/public/us/en/documents/software-support/enabling-high-performance-gcm.pdf
    https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/communications-ia-galois-counter-mode-paper.pdf
	https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf

// полином 2^128 + 2^7 + 2^2 + 2^1 + 1 (0x87)
// reflected (A)*reflected (B) =reflected (A*B) >>1
// reflected (A)*reflected (H<<1 mod g(x)) = reflected (A*H) mod g(x)
//
GHASH64
// полином 2^64  + 2^4 + 2^3 + 2^1 + 1 (0x1b)

  Aggr2 
  Yi = [(Xi • H) + (Xi-1+Yi-2) •H2] mod P
  Aggr4 
  Yi = [(Xi • H) + (Xi-1 • H2) + (Xi-2 • H3) + (Xi-3+Yi-4) •H4] mod P


linear folding 

gcc -I. -I:/msys64/mingw64/include/glib-2.0 -O3 -march=native -o ghash ghash.c aes.c cipher.c -lglib-2.0

$ gcc -I. -I:/msys64/mingw64/include/glib-2.0 -O3 -march=icelake-server -o ghash ghash.c aes.c cipher.c -lglib-2.0
Тестирование на симуляторе
$ /sde/sde.exe -icx -- ./ghash.exe
Оптимизация
$ llvm-mca --mcpu=skx -timeline ghash.s

*/
#include "cipher.h"
#include <stdint.h>
#include <stdio.h>
#include <intrin.h>
// использование карацубы дает выигрыш буквально в один такт.
#define Karatsuba 1

typedef  uint32_t v4si __attribute__((__vector_size__(16)));
typedef  int64_t v2di __attribute__((__vector_size__(16)));
typedef  uint8_t v16qi __attribute__((__vector_size__(16)));
typedef  uint8_t v32qi __attribute__((__vector_size__(32)));
typedef  uint8_t v64qi __attribute__((__vector_size__(64)));
typedef v4si (*CipherEncrypt128)(void *ctx, v4si src);

static inline
v2di CL_MUL128(v2di x, v2di y, const int c) __attribute__ ((__target__("pclmul")));
/*! Значение с =0x00 (a0*b0) 0x11 (a1*b1)
 */
static inline
v2di CL_MUL128(v2di x, v2di y, const int c)
{
    return __builtin_ia32_pclmulqdq128 (x,y,c);
}
static inline
v2di SHUFFLE(v2di x)
{
    return __builtin_shuffle (x,(v2di){1,0});
}
static inline
v16qi REVERSE(v16qi x)
{
    return __builtin_shuffle ((v16qi)x,(v16qi){15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0});
}
static inline
__m256i REV128x2(__m256i x)
{// _mm256_shuffle_epi8 AVX2
    return (__m256i)__builtin_shuffle ((v32qi)x,(v32qi)
		{15,14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
		 31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16});
}
static inline
v4si LOADU128(const void* src)
{
// defined(__SSE2__) 
	return (v4si)_mm_loadu_si128(src);
}
static inline
void STOREU128(void* dst, v4si x)
{
// defined(__SSE2__) 
	_mm_storeu_si128(dst, (__m128i)x);
}

static inline
__m256i LOADU256(const void* src)
{
// defined(__AVX__) 
	return _mm256_loadu_si256(src);
}
#ifdef __AVX512F__
static inline
__m512i LOADU512(const void* src)
{
// defined(__AVX__) 
	return _mm512_loadu_si512(src);
}
static inline
__m512i REV128x4(__m512i x)
{//  AVX512BW
	const v64qi REV_SHUF = 
		{15,14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
		 31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,
		 47,46,45,44,43,42,41,40,39,38,37,36,35,34,33,32,
		 63,62,61,60,59,58,57,56,55,54,53,52,51,50,49,48};
	return _mm512_shuffle_epi8 (x, (__m512i)REV_SHUF);
}
#endif
static inline
v16qi LOADZU(const uint8_t* src, int len)
{
#if defined(__AVX512VL__) && defined(__AVX512BW__)// AVX512VL + AVX512BW
	__mmask16 mm = ~0;
	return (v16qi)_mm_maskz_loadu_epi8 (mm>>(-len & 0xF), src);
#else
	v16qi x;
	x^=x;
	__builtin_memcpy((uint8_t*)&x, src, len&0xF);
	return x;
#endif
}
static inline
void STOREU(uint8_t* dst, v16qi x, int len)
{
#if defined(__AVX512VL__) && defined(__AVX512BW__)// AVX512VL + AVX512BW
	__mmask16 mm = ~0;
	_mm_mask_storeu_epi8 (dst, mm>>(-len & 0xF),(__m128i) x);
#else
	__builtin_memcpy(dst, (uint8_t*)&x, len&0xF);
#endif
}
/*! перед использованием один из аргументов следует сдвинуть влево SLM 
	Редуцирование можно вынести из цикла.
 */
typedef uint64_t poly64x2_t __attribute__((__vector_size__(16)));
/*! \brief этот алгоритм короче чем в референсном варианте */
static
v4si gmul128(v4si a, const v4si b)
{
	const __m128i  poly = _mm_setr_epi32(0x1,0,0,0xc2000000);//{1,0xc2ULL<<56};
    __m128i  M,L,H;
#if (Karatsuba==1) // карацуба
	L = _mm_clmulepi64_si128((__m128i)a, (__m128i)b, 0x00);
	H = _mm_clmulepi64_si128((__m128i)a, (__m128i)b, 0x11);
	v4si t;
	t = (v4si){a[0],a[1],b[0],b[1]} ^ (v4si){a[2],a[3], b[2],b[3]};
	M = _mm_clmulepi64_si128((__m128i)t, (__m128i)t, 0x01) ^ L ^ H;
#else
    L = _mm_clmulepi64_si128((__m128i)a, (__m128i)b, 0x00);
    M = _mm_clmulepi64_si128((__m128i)a, (__m128i)b, 0x01);
    H = _mm_clmulepi64_si128((__m128i)a, (__m128i)b, 0x11);
    M^= _mm_clmulepi64_si128((__m128i)a, (__m128i)b, 0x10);
#endif
// редуцирование по модулю, работает!
	M^= _mm_shuffle_epi32(L, 78);//(poly64x2_t){L[1],L[0]};//SHUFFLE(L);
    M^= _mm_clmulepi64_si128(L, poly, 0x10);
// редуцирование по модулю, работает! это можно использовать как отдельную функцию
	H^= _mm_shuffle_epi32(M, 78);//(poly64x2_t){M[1],M[0]};//SHUFFLE(M);
    H^= _mm_clmulepi64_si128(M, poly, 0x10);
    return (v4si)H;
}
static 
v4si gmul128x4(__m512i a,  const __m512i b) __attribute__((__target__("avx512f","vpclmulqdq")));
static 
v4si gmul128x4(__m512i a,  const __m512i b)
{
	const __m512i  poly = _mm512_setr_epi32(0x1,0,0,0xc2000000, 0x1,0,0,0xc2000000,0x1, 0,0,0xc2000000, 0x1,0,0,0xc2000000);
    __m512i  M,L,H;
//__asm volatile("# LLVM-MCA-BEGIN gmul128x4");
#if (Karatsuba==1) // карацуба быстрее
	L = _mm512_clmulepi64_epi128(a, b, 0x00);
	H = _mm512_clmulepi64_epi128(a, b, 0x11);
	__m512i t;// не проверял -- работает медленно
	t = (__m512i)_mm512_shuffle_ps((__m512)a, (__m512)b, 68) 
	  ^ (__m512i)_mm512_shuffle_ps((__m512)a, (__m512)b, 238);
	M = _mm512_clmulepi64_epi128((__m512i)t, (__m512i)t, 0x01);
	M^=  L ^ H;// _mm512_ternarylogic_epi64(M, H, L, 0x96);//
#else
    L = _mm512_clmulepi64_epi128(a, b, 0x00);
    M = _mm512_clmulepi64_epi128(a, b, 0x01);
    H = _mm512_clmulepi64_epi128(a, b, 0x11);
    M^= _mm512_clmulepi64_epi128(a, b, 0x10);
#endif
// редуцирование по модулю, работает!
	__m512i m1 = _mm512_shuffle_epi32(L, 78);//(poly64x2_t){L[1],L[0]};//SHUFFLE(L);
    __m512i m2 = _mm512_clmulepi64_epi128(L, poly, 0x10);
	M = _mm512_ternarylogic_epi64(M, m1, m2, 0x96);// M^m1^m2
//	M^= m1 ^ m2;
// редуцирование по модулю, работает!
	m1 = _mm512_shuffle_epi32(M, 78);//(poly64x2_t){M[1],M[0]};//SHUFFLE(M);
    m2 = _mm512_clmulepi64_epi128(M, poly, 0x10);
	H = _mm512_ternarylogic_epi64(H, m1, m2, 0x96);// H^m1^m2
//__asm volatile("# LLVM-MCA-END gmul128x4");
	__m256i h = _mm512_castsi512_si256(H) ^ _mm512_extracti32x8_epi32(H, 1);
	return (v4si)(_mm256_castsi256_si128(h) ^ _mm256_extracti32x4_epi32(h, 1));
}

static 
v4si gmul128x2(__m256i a,  const v4si h1, const v4si h2) __attribute__((__target__("avx512vl","vpclmulqdq")));
static 
v4si gmul128x2(__m256i a,  const v4si h1, const v4si h2)
{
	__m256i b = _mm256_setr_m128i((__m128i)h2,(__m128i)h1);
	const __m256i  poly = _mm256_setr_epi32(0x1,0,0,0xc2000000,0x1,0,0,0xc2000000);
    __m256i  M,L,H;
//__asm volatile("# LLVM-MCA-BEGIN gmul128x2");

    L = _mm256_clmulepi64_epi128(a, b, 0x00);
    M = _mm256_clmulepi64_epi128(a, b, 0x01);
    H = _mm256_clmulepi64_epi128(a, b, 0x11);
    M^= _mm256_clmulepi64_epi128(a, b, 0x10);
// редуцирование по модулю, работает!
	M^= _mm256_shuffle_epi32(L, 78);//(poly64x2_t){L[1],L[0]};//SHUFFLE(L);
    M^= _mm256_clmulepi64_epi128(L, poly, 0x10);
// редуцирование по модулю, работает!
	H^= _mm256_shuffle_epi32(M, 78);//(poly64x2_t){M[1],M[0]};//SHUFFLE(M);
    H^= _mm256_clmulepi64_epi128(M, poly, 0x10);
//__asm volatile("# LLVM-MCA-END gmul128x2");
	return (v4si)(_mm256_castsi256_si128(H) ^ _mm256_extractf128_si256(H, 1));
}
static
v4si gmul128_aggr2(v4si x0, v4si x1, const v4si h, const v4si h2)
{
	const __m128i  poly = _mm_setr_epi32(0x1,0,0,0xc2000000);//{1,0xc2ULL<<56};
    __m128i  L,M,H;
//__asm volatile("# LLVM-MCA-BEGIN gmul128_aggr2");
    L = _mm_clmulepi64_si128((__m128i)x1, (__m128i)h, 0x00);
    M = _mm_clmulepi64_si128((__m128i)x1, (__m128i)h, 0x01);
    H = _mm_clmulepi64_si128((__m128i)x1, (__m128i)h, 0x11);
    M^= _mm_clmulepi64_si128((__m128i)x1, (__m128i)h, 0x10);

    L^= _mm_clmulepi64_si128((__m128i)x0, (__m128i)h2, 0x00);
    M^= _mm_clmulepi64_si128((__m128i)x0, (__m128i)h2, 0x01);
    H^= _mm_clmulepi64_si128((__m128i)x0, (__m128i)h2, 0x11);
    M^= _mm_clmulepi64_si128((__m128i)x0, (__m128i)h2, 0x10);

// редуцирование по модулю, работает!
	M^= _mm_shuffle_epi32(L, 78);//(poly64x2_t){L[1],L[0]};//SHUFFLE(L);
    M^= _mm_clmulepi64_si128(L, poly, 0x10);
// редуцирование по модулю, работает! это можно использовать как отдельную функцию
	H^= _mm_shuffle_epi32(M, 78);//(poly64x2_t){M[1],M[0]};//SHUFFLE(M);
    H^= _mm_clmulepi64_si128(M, poly, 0x10);
//__asm volatile("# LLVM-MCA-END gmul128_aggr2");
    return (v4si)H;
}
static 
v4si gmul128_aggr4(v4si x0, v4si x1, v4si x2, v4si x3, const v4si h, const v4si h2, const v4si h3, const v4si h4)
{
	const __m128i  poly = _mm_setr_epi32(0x1,0,0,0xc2000000);//{1,0xc2ULL<<56};
    __m128i  L,M,H;
//__asm volatile("# LLVM-MCA-BEGIN gmul128_aggr4");
    L = _mm_clmulepi64_si128((__m128i)x3, (__m128i)h, 0x00);
    M = _mm_clmulepi64_si128((__m128i)x3, (__m128i)h, 0x01);
    H = _mm_clmulepi64_si128((__m128i)x3, (__m128i)h, 0x11);
    M^= _mm_clmulepi64_si128((__m128i)x3, (__m128i)h, 0x10);

    L^= _mm_clmulepi64_si128((__m128i)x2, (__m128i)h2, 0x00);
    M^= _mm_clmulepi64_si128((__m128i)x2, (__m128i)h2, 0x01);
    H^= _mm_clmulepi64_si128((__m128i)x2, (__m128i)h2, 0x11);
    M^= _mm_clmulepi64_si128((__m128i)x2, (__m128i)h2, 0x10);
	
    L^= _mm_clmulepi64_si128((__m128i)x1, (__m128i)h3, 0x00);
    M^= _mm_clmulepi64_si128((__m128i)x1, (__m128i)h3, 0x01);
    H^= _mm_clmulepi64_si128((__m128i)x1, (__m128i)h3, 0x11);
    M^= _mm_clmulepi64_si128((__m128i)x1, (__m128i)h3, 0x10);
	
    L^= _mm_clmulepi64_si128((__m128i)x0, (__m128i)h4, 0x00);
    M^= _mm_clmulepi64_si128((__m128i)x0, (__m128i)h4, 0x01);
    H^= _mm_clmulepi64_si128((__m128i)x0, (__m128i)h4, 0x11);
    M^= _mm_clmulepi64_si128((__m128i)x0, (__m128i)h4, 0x10);

// редуцирование по модулю, работает!
	M^= _mm_shuffle_epi32(L, 78);//(poly64x2_t){L[1],L[0]};//SHUFFLE(L);
    M^= _mm_clmulepi64_si128(L, poly, 0x10);
// редуцирование по модулю, работает! это можно использовать как отдельную функцию
	H^= _mm_shuffle_epi32(M, 78);//(poly64x2_t){M[1],M[0]};//SHUFFLE(M);
    H^= _mm_clmulepi64_si128(M, poly, 0x10);
//__asm volatile("# LLVM-MCA-END gmul128_aggr4");
    return (v4si)H;
}
/*! \brief возведение в квадрат 
	Сложность 4М (четыре операции умножения)
 */
static 
v4si gsqr128(const v4si b)
{
	const __m128i poly = _mm_setr_epi32(0x1,0,0,0xc2000000);
    __m128i L,H;
    L = _mm_clmulepi64_si128((__m128i)b, (__m128i)b, 0x00);
    H = _mm_clmulepi64_si128((__m128i)b, (__m128i)b, 0x11);//(a*x + b)^2= a^2*x^2 + b^2
	L = _mm_shuffle_epi32(L, 78)
      ^ _mm_clmulepi64_si128(L, poly, 0x10);
	L = _mm_shuffle_epi32(L, 78)
      ^ _mm_clmulepi64_si128(L, poly, 0x10);
    return (v4si)(H^L);
}
/* сдвиг влево на один разряд */
static 
v4si SLM128(v4si d)
{
#if 1
	__m128i r;// = _mm_alignr_epi8 ((__m128i)d,(__m128i)d, 12);
	r = _mm_slli_epi32((__m128i)d, 1);
	r^= _mm_srli_epi32(_mm_alignr_epi8 ((__m128i)d,(__m128i)d, 12), 31);
	r^= _mm_srai_epi32((__m128i)d, 31) & _mm_setr_epi32(0,0,0,0xc2000000);// сдвиг арифметический
    return  (v4si)(r);
#else
    v4si r = (v4si){d[3],d[0],d[1],d[2]};
	r >>=31;
    if (r[0]!=0) r[3] ^= 0xc2000000;
	return (d<<1) ^ r;
#endif
}

#if 0
//static inline 
v2di GMUL128(v2di a, const v2di b)
{
	const v2di Px = {0xc2ULL<<56};
    v2di M,L,H;
    L = CL_MUL128(a, b, 0x00);
    M = CL_MUL128(a, b, 0x01);
    M^= CL_MUL128(a, b, 0x10);
    H = CL_MUL128(a, b, 0x11);
// редуцирование по модулю, работает!
	M^= SHUFFLE(L);
    M^= CL_MUL128(L, Px, 0x00);
// редуцирование по модулю, работает! это можно использовать как отдельную функцию
	H^= SHUFFLE(M);
    H^= CL_MUL128(M, Px, 0x00);
    return H;// ^ SHUFFLE(M ^ L);
}

/*! An alternative technique trades-off one multiplication for additional XOR operations. It
can be viewed as “one iteration carry-less Karatsuba” multiplication [7, 9].
Algorithm 2
Step 1: multiply carry-less the following operands: A1 with B1, A0 with B0, and A0 + A1
with B0 + B1. Let the results of the above three multiplications be: [C1:C0], [D1:D0] and
[E1:E0], respectively.
Step 2: construct the 256-bit output of the multiplication [A1:A0] * [B1:B0] as follows:
[A1 : A0]*[B1 : B0] * [C1 : C0+C1 + D1 + E1 : D1 + C0 + D0 + E0 : D0] (6)
*/

// умножение и редуцирование по полиному, только порядок бит вывернут
// x^128 + x^7 + x^2 + x^1 + 1
v4si SRM128(v4si d)
{
    v4si r = (v4si){d[1],d[2],d[3],d[0]};
    r <<=31;
    r = (r!=0) & (v4si){1<<31,1<<31,1<<31,0xe1000000};
    return  (d>>1) ^ r;
}
v4si SLM128(v4si d)
{
    v4si r = (v4si){d[3],d[0],d[1],d[2]};
    r >>=31;
    if (r[0]!=0) r[3] ^= 0xc2000000;
    //r = (r!=0) & (v4si){1,1,1,0xc2000000};
    return  (d<<1) ^ r;
}

void SRM128_(uint32_t* d) {
    const uint32_t r0 = d[0];
    const uint32_t r1 = d[1];
    const uint32_t r2 = d[2];
    const uint32_t r3 = d[3];
    d[0] = (r0>>1) | (r1<<31);
    d[1] = (r1>>1) | (r2<<31);
    d[2] = (r2>>1) | (r3<<31);
	if (r0&1) d[3] = (r3>>1) ^ 0xe1000000;
	else d[3] = (r3>>1);
}
uint64_t SRM64_(uint64_t d) {
	if (d&1) d = (d>>1) ^ 0xd800000000000000ULL;
	else d = (d>>1);
	return d;
}
/*! сдвиг вправо */
// GHASH 1110 0001 || 0^120
v4si MUL128(v4si y, uint32_t *H)
{
    v4si z = {0};
    int i;
    for (i=0; i<4; i++)
    {
        uint32_t xi = H[3-i];
        int j;
        for (j=0; j<32; j++)
        {
            if (xi>>31) z ^= y;
			//SRM128_((void*)&y); // сдвиг и редуцирование по модулю
			y = SRM128(y); // сдвиг и редуцирование по модулю
			xi<<=1;
        }// while (xi<<=1);
    }
    return z;
}
#endif
/*! \brief Функция хеши основана на умножении в поле GF(2^128)
 */
v4si GHASH_(v4si y, v4si h, uint8_t *data, int len)
{
    int i;
//    h = SLM128(h);
	int blocks;
#if defined(__VPCLMULQDQ__)
	v4si h2 = gsqr128(h);// 4М -- эту операцию можно выполнить снаружи
	blocks = len>>6;
	if (blocks){
		// todo умножение {h3, h4} = {h, h2} * {h2,h2} можно выполнить параллельно на векторе 256 бит
		v4si h3 = gmul128(h2, h);
		v4si h4 = gsqr128(h2);
		__m512i b = _mm512_zextsi128_si512((__m128i)h4);
		b = _mm512_inserti32x4(b, (__m128i)h, 3);
		b = _mm512_inserti32x4(b, (__m128i)h2,2);
		b = _mm512_inserti32x4(b, (__m128i)h3,1);
//__asm volatile("# LLVM-MCA-BEGIN GHASH_");
		for (i=0; i<blocks; i++){
			__m512i x1, y1;
			y1 = _mm512_zextsi128_si512((__m128i)y);
			x1 = LOADU512(data); data+=64;
			x1 = REV128x4(x1);
			y = gmul128x4((y1^x1), b);
		}
//__asm volatile("# LLVM-MCA-END GHASH_");
	}
	if(len&32){
		__m256i x1, y1;
		y1 = _mm256_zextsi128_si256((__m128i)y);
        x1 = LOADU256(data); data+=32;
		x1 = REV128x2(x1);
		y = gmul128x2((y1^x1), h, h2);
    }
	if(len&16){
		v4si x;
        x = LOADU128(data); data+=16;
		x = (v4si)REVERSE((v16qi)x);
        y = gmul128((y^x), h);
    }
#else
	blocks = len>>4;
//__asm volatile("# LLVM-MCA-BEGIN GHASH_");
	for (i=0; i<blocks; i++){
		v4si x;
		x = LOADU128(data); data+=16;
		x = (v4si)REVERSE((v16qi)x);
		y = gmul128((y^x), h);
//			y = gmul128_aggr2((y^x0), x1, h, h2);
	}
//__asm volatile("# LLVM-MCA-END GHASH_");
#endif
	if (len &0xF){
		v4si x;
		x = (v4si)LOADZU(data, len);
		x = (v4si)REVERSE((v16qi)x);
		y = gmul128((y^x), h);
	}
    return y;
}


typedef struct {
	uint8_t * K;
	uint8_t * A;
	uint8_t * P;
	uint8_t * iv;
	uint8_t * H;
	uint8_t * G;
	uint8_t * C;
	uint8_t * T;
	int lenA, lenC, klen, ivlen;
	
} Test_t;
Test_t test_vectors[] = {
	// https://github.com/coruus/nist-testvectors/blob/master/csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_GCM.txt
	{
		.K = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.P = "", 
		.iv= "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.H = "\x2e\x2b\x34\xca\x59\xfa\x4c\x88\x3b\x2c\x8a\xef\xd4\x4b\xe9\x66",
		.lenA=0, .lenC=0, .klen=16, .ivlen=96,
		.G = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.C = "",
		.T = "\x5a\x45\xe7\xa4\x57\x1d\x7f\x36\x61\x30\x7e\xfa\xce\xfc\xe2\x58",
	},
	{
		.K = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.P = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.iv= "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.H = "\x2e\x2b\x34\xca\x59\xfa\x4c\x88\x3b\x2c\x8a\xef\xd4\x4b\xe9\x66",
		.lenA=0, .lenC=16,.klen=16, .ivlen=96,
		.G = "\x85\xf8\xb0\xb6\xe5\x7a\x45\xc3\xdc\x23\x92\xd6\x1a\xbb\x8c\xf3",
		.C = "\x78\xfe\xb2\x71\xb9\xc2\x28\xf3\x92\xa3\xb6\x60\xce\xda\x88\x03",
		.T = "\xdf\xbd\x57\x12\xb2\x67\x3a\xf5\xbd\x13\xec\x2c\xd4\x47\x6e\xab",
	},
	{// 
		.K = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
		.P = "\x9a\x26\xf5\xaf\xc5\x09\x59\xa5\xe5\x06\x84\xf8\x25\x32\x31\xd9"
			 "\x72\x8a\x31\x8a\x3d\x30\x4c\x2e\xda\xf7\x34\x15\x53\xa9\xa7\x86"
			 "\x25\xb5\xa6\x49\x24\x0e\xcf\x2f\x53\x09\x68\x95\x95\x0c\x3c\x1c"
			 "\x55\xd2\xaf\x1a\x39\x7b\x63\xba\x57\xe6\x0d\xaa\xf5\xed\x6a\xb1",
		.iv= "",
		.H = "\x78\x3b\xd5\x80\x29\xe5\xa6\x0a\x5d\x53\xbf\x08\x37\x53\x3b\xb8",
		.lenA = 0, .lenC = 16*4,.klen=16, .ivlen=0,
		.G = "\xac\x4e\x1d\xac\x95\x88\x4f\x61\x02\x0d\x82\x1b\xb8\x32\x1b\x7f",
		.C = "\x9c\xd4\xd0\x84\xb7\x21\x72\x4b\x24\x74\x77\x21\xc2\x1e\x83\x42"
			 "\x2e\xa1\xac\x29\x23\x7e\xc1\x35\xe0\xa4\x02\x2c\x2f\x21\xaa\xe3"
			 "\x05\xaa\x84\xac\x5a\x6a\x8f\x7d\x1c\x93\x66\x54\xb2\x14\xd5\x21"
			 "\x85\x59\x3f\x47\x91\xe0\x58\x3d\x97\xac\x0a\x6a\x39\x0b\xa3\x1b",
		.T = "\xb4\xfa\xa6\x2b\xbd\x5a\xf3\x2c\xa6\x64\xcd\x27\xf3\x2a\x5c\x4d"
	},
	{
		.K = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
		.P = "\x9a\x26\xf5\xaf\xc5\x09\x59\xa5\xe5\x06\x84\xf8\x25\x32\x31\xd9"
			 "\x72\x8a\x31\x8a\x3d\x30\x4c\x2e\xda\xf7\x34\x15\x53\xa9\xa7\x86"
			 "\x25\xb5\xa6\x49\x24\x0e\xcf\x2f\x53\x09\x68\x95\x95\x0c\x3c\x1c"
			 "\x39\x7b\x63\xba\x57\xe6\x0d\xaa\xf5\xed\x6a\xb1",
		.A = "\xef\xbe\xad\xde\xce\xfa\xed\xfe\xef\xbe\xad\xde\xce\xfa\xed\xfe"
			 "\xd2\xda\xad\xab", 
		.iv= "\x88\xf8\xca\xde\xad\xdb\xce\xfa\xbe\xba\xfe\xca",
		.H = "\x78\x3b\xd5\x80\x29\xe5\xa6\x0a\x5d\x53\xbf\x08\x37\x53\x3b\xb8",
		.lenA = 0xa0>>3, .lenC = 0x1e0>>3,.klen=16,.ivlen=96,
		.G = "\x5f\xae\xa9\x60\x72\x3b\x46\xd9\x7f\xcc\x6e\x0e\xf7\x57\x8e\x69",
		.C = "\x9c\xd4\xd0\x84\xb7\x21\x72\x4b\x24\x74\x77\x21\xc2\x1e\x83\x42"
			 "\x2e\xa1\xac\x29\x23\x7e\xc1\x35\xe0\xa4\x02\x2c\x2f\x21\xaa\xe3"
			 "\x05\xaa\x84\xac\x5a\x6a\x8f\x7d\x1c\x93\x66\x54\xb2\x14\xd5\x21"
			 "\x91\xe0\x58\x3d\x97\xac\x0a\x6a\x39\x0b\xa3\x1b",
		.T = "\x47\x1a\x12\xe7\x5a\xe9\xfa\x94\xdb\xa5\x21\x32\xbc\x4f\xc9\x5b"
	},
	{// Test Case 5
		.K = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
		.P = "\x9a\x26\xf5\xaf\xc5\x09\x59\xa5\xe5\x06\x84\xf8\x25\x32\x31\xd9"
			 "\x72\x8a\x31\x8a\x3d\x30\x4c\x2e\xda\xf7\x34\x15\x53\xa9\xa7\x86"
			 "\x25\xb5\xa6\x49\x24\x0e\xcf\x2f\x53\x09\x68\x95\x95\x0c\x3c\x1c"
			 "\x39\x7b\x63\xba\x57\xe6\x0d\xaa\xf5\xed\x6a\xb1",
		.A = "\xef\xbe\xad\xde\xce\xfa\xed\xfe\xef\xbe\xad\xde\xce\xfa\xed\xfe"
			 "\xd2\xda\xad\xab",
		.iv= "\xad\xdb\xce\xfa\xbe\xba\xfe\xca",
		.H = "\x78\x3b\xd5\x80\x29\xe5\xa6\x0a\x5d\x53\xbf\x08\x37\x53\x3b\xb8",
		.lenA = 0xa0>>3, .lenC = 0x1e0>>3,.klen=16,.ivlen=64,
		.G = "\x7b\xd3\x44\xe4\x77\x28\x92\xb6\x2c\xb9\x49\xc2\xb4\x6b\x58\xdf",
		.C = "\x55\x47\x2a\xa2\x1f\xf5\x7f\x77\x4a\x93\x06\x28\x4c\x3b\x35\x61"
			 "\x23\x74\x6c\x7b\xf9\xe5\x66\x37\xf8\xc6\xcd\x4f\x71\x2a\x9b\x69"
			 "\x42\x6b\x89\xd4\x44\x75\x09\x2b\xb2\x24\x9f\xe4\x00\x69\x80\x73"
			 "\x98\x45\x3f\xc2\x07\x0f\xac\xeb\xe1\xb5\x89\x49",
		.T = "\xcb\xfc\xa2\xac\x4a\xe1\x1b\x56\x85\x07\x3b\x9e\xe7\xd2\x12\x36"
	},
	{// Test Case 6
		.K = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
		.P = "\x9a\x26\xf5\xaf\xc5\x09\x59\xa5\xe5\x06\x84\xf8\x25\x32\x31\xd9"
			 "\x72\x8a\x31\x8a\x3d\x30\x4c\x2e\xda\xf7\x34\x15\x53\xa9\xa7\x86"
			 "\x25\xb5\xa6\x49\x24\x0e\xcf\x2f\x53\x09\x68\x95\x95\x0c\x3c\x1c"
			 "\x39\x7b\x63\xba\x57\xe6\x0d\xaa\xf5\xed\x6a\xb1",
		.A = "\xef\xbe\xad\xde\xce\xfa\xed\xfe\xef\xbe\xad\xde\xce\xfa\xed\xfe"
			 "\xd2\xda\xad\xab",
		.iv= "\xaa\x69\x52\xff\x5a\x9c\x90\x55\xe5\x06\x84\xf8\x5d\x22\x13\x93"
			 "\x28\xa7\x18\xa3\xd2\x03\xc3\xe4\xa1\x7d\x4f\x53\x38\x95\x7a\x6a"
			 "\x54\x52\x6b\x9a\x42\xe2\xf0\xfc\x39\x95\x80\x56\x51\xc9\xc0\xc3"
			 "\x9b\xb3\x37\xa6\x57\x6a\xde\xa0\xf5\xdb\xae\x16",
		.H = "\x78\x3b\xd5\x80\x29\xe5\xa6\x0a\x5d\x53\xbf\x08\x37\x53\x3b\xb8",
		.lenA = 0xa0>>3, .lenC = 0x1e0>>3,.klen=16,.ivlen=128*4-32,
		.G = "\xde\xc3\x3d\xac\x8a\x87\x9a\x3c\x2f\x93\xd3\x60\x97\xfe\x5a\x1c",
		.C = "\x94\xb8\x3f\xa1\xac\x33\xa0\x03\xb6\x15\x56\x62\x98\x49\xe2\x8c"
			 "\xa7\x2c\x7e\xca\x3c\x2a\x26\xba\xa8\x11\xa2\xc3\xa5\x12\x91\xbe"
			 "\x6f\x7c\x8c\xd4\x81\xb2\xdc\xcc\x90\x3c\xa4\xfb\xa4\xa9\xe4\x01"
			 "\xe5\xae\x34\x4c\x03\x17\xa4\xac\xd2\x75\x28\xd6",
		.T = "\x50\xd0\x99\x16\x3c\xf4\x2a\x46\xfa\x0b\xfe\xff\xae\xc5\x9c\x61"
	},
	{// Test Case 7
		.K = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			 "\x00\x00\x00\x00\x00\x00\x00\x00",
		.P = "",
		.iv= "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.H = "\xd7\x0b\x30\xc9\x6e\xa9\xf4\xe8\xa3\x52\xbf\xac\x92\x69\xe0\xaa",
		.lenA = 0, .lenC = 0,.klen=24,.ivlen=96,
		.G = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.C = "",
		.T = "\x35\x24\x57\x12\xf3\xd1\x0e\xa0\x4b\xf7\x73\xc7\x8a\xb2\x33\xcd"
	},
	{// Test Case 8
		.K = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			 "\x00\x00\x00\x00\x00\x00\x00\x00",
		.P = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.iv= "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.H = "\xd7\x0b\x30\xc9\x6e\xa9\xf4\xe8\xa3\x52\xbf\xac\x92\x69\xe0\xaa",
		.lenA = 0, .lenC = 0x80>>3,.klen=24,.ivlen=96,
		.G = "\xce\xd4\x43\x67\xab\x05\xfa\x2e\xe0\xd0\x4a\xc4\x0a\x3f\xc6\xe2",
		.C = "\x00\xf6\xb0\x84\x43\x7e\x26\x1c\x41\xfe\xf0\x07\x7c\x24\xe7\x98",
		.T = "\xfb\xf0\x14\x75\x58\xd4\xf4\x8e\xab\x27\x39\x03\x80\x8d\xf5\x2f"
	},
	{// Test Case 9
		.K = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"
			 "\xfe\xff\xe9\x92\x86\x65\x73\x1c",
		.P = "\x9a\x26\xf5\xaf\xc5\x09\x59\xa5\xe5\x06\x84\xf8\x25\x32\x31\xd9"
			 "\x72\x8a\x31\x8a\x3d\x30\x4c\x2e\xda\xf7\x34\x15\x53\xa9\xa7\x86"
			 "\x25\xb5\xa6\x49\x24\x0e\xcf\x2f\x53\x09\x68\x95\x95\x0c\x3c\x1c"
			 "\x55\xd2\xaf\x1a\x39\x7b\x63\xba\x57\xe6\x0d\xaa\xf5\xed\x6a\xb1",
		.iv= "\x88\xf8\xca\xde\xad\xdb\xce\xfa\xbe\xba\xfe\xca",
		.H = "\x49\x92\xb3\xad\x2b\x08\x2c\x4f\x21\x82\xe6\x9a\xec\x23\x69\x46",
		.lenA = 0, .lenC = 0x200>>3,.klen=24,.ivlen=96,
		.G = "\xf0\x89\xa8\x45\x34\xe3\x1a\xeb\xf0\xff\xc8\xf6\x40\x0d\x11\x51",
		.C = "\x57\x27\x2a\x87\xc4\xfa\x06\xeb\x41\xe8\x00\x3c\x0b\xca\x80\x39"
			 "\x9c\xe1\xa1\x0c\xb4\x93\x85\x62\x84\xd9\xef\xa6\xea\x1c\x9e\x85"
			 "\x47\x3f\x4a\xc8\x18\x9d\x61\xac\x25\xc5\x44\xc1\x00\x3d\x77\x7d"
			 "\x56\xe2\xad\xac\x10\x27\xda\xcc\xd9\x24\xe3\x2f\x8b\x44\xe2\x18",
		.T = "\x14\x4a\x67\xb8\x4d\x02\x18\xb1\xbf\x36\x73\x58\xc8\xa7\x24\x99"
	},
	{// Test Case 10
		.K = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"
			 "\xfe\xff\xe9\x92\x86\x65\x73\x1c",
		.P = "\x9a\x26\xf5\xaf\xc5\x09\x59\xa5\xe5\x06\x84\xf8\x25\x32\x31\xd9"
			 "\x72\x8a\x31\x8a\x3d\x30\x4c\x2e\xda\xf7\x34\x15\x53\xa9\xa7\x86"
			 "\x25\xb5\xa6\x49\x24\x0e\xcf\x2f\x53\x09\x68\x95\x95\x0c\x3c\x1c"
			 "\x39\x7b\x63\xba\x57\xe6\x0d\xaa\xf5\xed\x6a\xb1",
		.A = "\xef\xbe\xad\xde\xce\xfa\xed\xfe\xef\xbe\xad\xde\xce\xfa\xed\xfe"
			 "\xd2\xda\xad\xab",
		.iv= "\x88\xf8\xca\xde\xad\xdb\xce\xfa\xbe\xba\xfe\xca",
		.H = "\x49\x92\xb3\xad\x2b\x08\x2c\x4f\x21\x82\xe6\x9a\xec\x23\x69\x46",
		.lenA = 0xa0>>3, .lenC = 0x1e0>>3,.klen=24,.ivlen=96,
		.G = "\x68\xa2\xe8\x90\xc4\xb4\xb8\x6d\xc0\x8e\x4a\x2e\x06\xe3\x2c\xed",
		.C = "\x57\x27\x2a\x87\xc4\xfa\x06\xeb\x41\xe8\x00\x3c\x0b\xca\x80\x39"
			 "\x9c\xe1\xa1\x0c\xb4\x93\x85\x62\x84\xd9\xef\xa6\xea\x1c\x9e\x85"
			 "\x47\x3f\x4a\xc8\x18\x9d\x61\xac\x25\xc5\x44\xc1\x00\x3d\x77\x7d"
			 "\x10\x27\xda\xcc\xd9\x24\xe3\x2f\x8b\x44\xe2\x18",
		.T = "\x8c\x61\x27\x6d\xbd\x55\xba\x37\x8f\x47\xf1\x80\x8e\x49\x19\x25"
	},
	{// Test Case 11
		.K = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"
			 "\xfe\xff\xe9\x92\x86\x65\x73\x1c",
		.P = "\x9a\x26\xf5\xaf\xc5\x09\x59\xa5\xe5\x06\x84\xf8\x25\x32\x31\xd9"
			 "\x72\x8a\x31\x8a\x3d\x30\x4c\x2e\xda\xf7\x34\x15\x53\xa9\xa7\x86"
			 "\x25\xb5\xa6\x49\x24\x0e\xcf\x2f\x53\x09\x68\x95\x95\x0c\x3c\x1c"
			 "\x39\x7b\x63\xba\x57\xe6\x0d\xaa\xf5\xed\x6a\xb1",
		.A = "\xef\xbe\xad\xde\xce\xfa\xed\xfe\xef\xbe\xad\xde\xce\xfa\xed\xfe"
			 "\xd2\xda\xad\xab",
		.iv= "\xad\xdb\xce\xfa\xbe\xba\xfe\xca",
		.H = "\x49\x92\xb3\xad\x2b\x08\x2c\x4f\x21\x82\xe6\x9a\xec\x23\x69\x46",
		.lenA = 0xa0>>3, .lenC = 0x1e0>>3,.klen=24,.ivlen=64,
		.G = "\x89\x40\x06\x37\xf2\xea\x80\xee\x58\x78\x60\x06\x38\x13\x6a\x1e",
		.C = "\xb8\x4d\x32\x25\x6e\xb3\x24\xed\x54\xa1\x14\xae\x99\xf5\x10\x0f"
			 "\x57\x70\x50\xc4\x0f\x28\x47\x83\x4f\xb3\xbb\xf2\x2e\x63\x66\xc5"
			 "\xc9\xd1\xda\xd4\xd4\x41\x65\xc6\x75\x1f\x47\x9a\xdf\x29\xdc\xfd"
			 "\xf7\x62\xf0\xa0\x3f\x47\x8b\x8e\xa5\x19\x3a\xe9",
		.T = "\xf8\x33\x35\x0d\xa4\xcc\x4f\x09\x24\x3a\x62\xcf\x7f\xc5\xdc\x65"
	},
	{// Test Case 12
		.K = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"
			 "\xfe\xff\xe9\x92\x86\x65\x73\x1c",
		.P = "\x9a\x26\xf5\xaf\xc5\x09\x59\xa5\xe5\x06\x84\xf8\x25\x32\x31\xd9"
			 "\x72\x8a\x31\x8a\x3d\x30\x4c\x2e\xda\xf7\x34\x15\x53\xa9\xa7\x86"
			 "\x25\xb5\xa6\x49\x24\x0e\xcf\x2f\x53\x09\x68\x95\x95\x0c\x3c\x1c"
			 "\x39\x7b\x63\xba\x57\xe6\x0d\xaa\xf5\xed\x6a\xb1",
		.A = "\xef\xbe\xad\xde\xce\xfa\xed\xfe\xef\xbe\xad\xde\xce\xfa\xed\xfe"
			 "\xd2\xda\xad\xab",
		.iv= "\xaa\x69\x52\xff\x5a\x9c\x90\x55\xe5\x06\x84\xf8\x5d\x22\x13\x93"
			 "\x28\xa7\x18\xa3\xd2\x03\xc3\xe4\xa1\x7d\x4f\x53\x38\x95\x7a\x6a"
			 "\x54\x52\x6b\x9a\x42\xe2\xf0\xfc\x39\x95\x80\x56\x51\xc9\xc0\xc3"
			 "\x9b\xb3\x37\xa6\x57\x6a\xde\xa0\xf5\xdb\xae\x16",
		.H = "\x49\x92\xb3\xad\x2b\x08\x2c\x4f\x21\x82\xe6\x9a\xec\x23\x69\x46",
		.lenA = 0xa0>>3, .lenC = 0x1e0>>3,.klen=24,.ivlen=128*4-32,
		.G = "\x94\x8e\x96\x05\xc0\xde\xea\x01\x18\x37\xcc\xb4\xb0\x7f\x56\x82",
		.C = "\xff\xf9\xdc\x8f\x5a\x16\x30\x48\x3c\x24\xe3\x1c\x68\x88\x7e\xd2"
			 "\x45\x6e\x66\x28\x98\xb7\xf7\x6e\xef\x47\xb4\xe6\xd8\xa1\xe9\x1d"
			 "\xb3\x2d\x29\x9b\x58\x37\xf0\xe2\xd9\xdd\x34\xaf\x12\x90\xe7\x81"
			 "\x3b\x37\xb7\xe9\xe7\x22\xfa\x45\x67\x03\x7c\xe6",
		.T = "\xd9\xa6\x76\xd3\xc3\x8f\x56\xb8\xbb\x25\x1c\x29\xff\x66\xf5\xdc"
	},
	{// Test Case 13
		.K = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.P = "",
		.iv= "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.H = "\x87\x20\x84\x92\x14\xa2\x48\xad\x89\x89\x40\xa2\x78\xc0\x95\xdc",
		.lenA = 0x0>>3, .lenC = 0x0>>3,.klen=32,.ivlen=96,
		.G = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.C = "",
		.T = "\x8b\x73\xcb\xc4\xf1\xb4\x63\xa9\xb9\x36\x45\xc7\xfb\x8a\x0f\x53"
	},
	{// Test Case 14
		.K = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.P = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.iv= "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.H = "\x87\x20\x84\x92\x14\xa2\x48\xad\x89\x89\x40\xa2\x78\xc0\x95\xdc",
		.lenA = 0x0>>3, .lenC = 0x80>>3,.klen=32,.ivlen=96,
		.G = "\x92\xca\x41\x10\x44\x2c\x38\x8f\x49\x5d\xdc\x5e\x5c\x42\xde\x83",
		.C = "\x18\x9d\xf3\xba\xd3\xc5\x4e\x07\x6e\x6b\x60\x4d\x3d\x40\xa7\xce",
		.T = "\x19\xb9\x8a\xd4\xb5\x98\x5b\x26\xf0\x6b\x99\x99\xa7\xc8\xd1\xd0"
	},
	{// Test Case 15
		.K = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"
			 "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
		.P = "\x9a\x26\xf5\xaf\xc5\x09\x59\xa5\xe5\x06\x84\xf8\x25\x32\x31\xd9"
			 "\x72\x8a\x31\x8a\x3d\x30\x4c\x2e\xda\xf7\x34\x15\x53\xa9\xa7\x86"
			 "\x25\xb5\xa6\x49\x24\x0e\xcf\x2f\x53\x09\x68\x95\x95\x0c\x3c\x1c"
			 "\x55\xd2\xaf\x1a\x39\x7b\x63\xba\x57\xe6\x0d\xaa\xf5\xed\x6a\xb1",
		.iv= "\x88\xf8\xca\xde\xad\xdb\xce\xfa\xbe\xba\xfe\xca",
		.H = "\xd7\xda\x32\x87\xac\x9b\x88\xce\xeb\xb8\xb4\x79\x05\xf2\xbe\xac",
		.lenA = 0x0>>3, .lenC = 0x200>>3,.klen=32,.ivlen=96,
		.G = "\x12\x16\x0d\x23\x36\x7c\x09\x46\xcb\x5f\xb7\x7c\xd3\x70\xb8\x4d",
		.C = "\x7d\x42\x84\x2a\xa3\x37\x7f\xf4\x07\x7d\x56\x99\xf0\xc1\x2d\x52"
			 "\xaa\xd1\x55\x25\xbd\xa2\x98\x75\xc9\xc0\xe5\xbf\xdc\x8c\x3a\x64"
			 "\x38\x88\x82\x56\x10\x8b\xb0\xa7\x3d\xbb\x0d\x59\x48\x8e\xb0\x8c"
			 "\xad\x15\x80\x89\x62\xf6\xc9\xbc\x0a\x7a\xba\x93\x63\x1e\xf6\xc5",
		.T = "\x6c\xcc\xe3\x70\x22\x50\x1a\xec\xbd\x71\x34\xd9\xc5\xda\x94\xb0"
	},
	{// Test Case 16
		.K = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"
			 "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
		.P = "\x9a\x26\xf5\xaf\xc5\x09\x59\xa5\xe5\x06\x84\xf8\x25\x32\x31\xd9"
			 "\x72\x8a\x31\x8a\x3d\x30\x4c\x2e\xda\xf7\x34\x15\x53\xa9\xa7\x86"
			 "\x25\xb5\xa6\x49\x24\x0e\xcf\x2f\x53\x09\x68\x95\x95\x0c\x3c\x1c"
			 "\x39\x7b\x63\xba\x57\xe6\x0d\xaa\xf5\xed\x6a\xb1",
		.A = "\xef\xbe\xad\xde\xce\xfa\xed\xfe\xef\xbe\xad\xde\xce\xfa\xed\xfe"
			 "\xd2\xda\xad\xab",
		.iv= "\x88\xf8\xca\xde\xad\xdb\xce\xfa\xbe\xba\xfe\xca",
		.H = "\xd7\xda\x32\x87\xac\x9b\x88\xce\xeb\xb8\xb4\x79\x05\xf2\xbe\xac",
		.lenA = 0xa0>>3, .lenC = 0x1e0>>3,.klen=32,.ivlen=96,
		.G = "\x65\x8f\xc3\xe8\x47\xa4\xcc\x67\x1e\x39\xcd\xaa\xd8\xc4\xd0\x8b",
		.C = "\x7d\x42\x84\x2a\xa3\x37\x7f\xf4\x07\x7d\x56\x99\xf0\xc1\x2d\x52"
			 "\xaa\xd1\x55\x25\xbd\xa2\x98\x75\xc9\xc0\xe5\xbf\xdc\x8c\x3a\x64"
			 "\x38\x88\x82\x56\x10\x8b\xb0\xa7\x3d\xbb\x0d\x59\x48\x8e\xb0\x8c"
			 "\x62\xf6\xc9\xbc\x0a\x7a\xba\x93\x63\x1e\xf6\xc5",
		.T = "\x1b\x55\x2d\xbb\x53\x88\xdf\xcd\x68\x17\x4e\x0f\xce\x6e\xfc\x76"
	},
	{// CaseTest17
		.K = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"
			 "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
		.P = "\x9a\x26\xf5\xaf\xc5\x09\x59\xa5\xe5\x06\x84\xf8\x25\x32\x31\xd9"
			 "\x72\x8a\x31\x8a\x3d\x30\x4c\x2e\xda\xf7\x34\x15\x53\xa9\xa7\x86"
			 "\x25\xb5\xa6\x49\x24\x0e\xcf\x2f\x53\x09\x68\x95\x95\x0c\x3c\x1c"
			 "\x39\x7b\x63\xba\x57\xe6\x0d\xaa\xf5\xed\x6a\xb1",
		.A = "\xef\xbe\xad\xde\xce\xfa\xed\xfe\xef\xbe\xad\xde\xce\xfa\xed\xfe"
			 "\xd2\xda\xad\xab",
		.iv= "\xad\xdb\xce\xfa\xbe\xba\xfe\xca",
		.H = "\xd7\xda\x32\x87\xac\x9b\x88\xce\xeb\xb8\xb4\x79\x05\xf2\xbe\xac",
		.lenA = 0xa0>>3, .lenC = 0x1e0>>3,.klen=32,.ivlen=64,
		.G = "\x63\x7f\xf9\xa2\xe9\xb2\x52\x1c\x81\x8f\xc6\xb8\x88\x42\xa3\x75",
		.C = "\xcb\x44\x98\xf1\x3b\xc1\x47\xae\x32\x7d\x78\xca\xf1\x2d\x76\xc3"
			 "\xe0\x9d\xba\x9b\xd7\xf7\x2f\xc5\xfa\x6a\x97\x0b\x4d\xe1\x1a\xaf"
			 "\x78\x3f\xc7\x3b\x36\xc2\x4c\x95\xf0\xa4\x34\x39\xd3\x82\xb5\xfe"
			 "\x1f\x9b\x7c\xf4\x99\xe4\xab\x64\x0e\x43\xac\x62",
		.T = "\xf2\xa8\x2e\xfe\x13\x49\x45\x5e\xc4\x92\xa7\x46\xbf\x7d\x33\x3a"
	},
	{// Test Case 18
		.K = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"
			 "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
		.P = "\x9a\x26\xf5\xaf\xc5\x09\x59\xa5\xe5\x06\x84\xf8\x25\x32\x31\xd9"
			 "\x72\x8a\x31\x8a\x3d\x30\x4c\x2e\xda\xf7\x34\x15\x53\xa9\xa7\x86"
			 "\x25\xb5\xa6\x49\x24\x0e\xcf\x2f\x53\x09\x68\x95\x95\x0c\x3c\x1c"
			 "\x39\x7b\x63\xba\x57\xe6\x0d\xaa\xf5\xed\x6a\xb1",
		.A = "\xef\xbe\xad\xde\xce\xfa\xed\xfe\xef\xbe\xad\xde\xce\xfa\xed\xfe"
			 "\xd2\xda\xad\xab",
		.iv= "\xaa\x69\x52\xff\x5a\x9c\x90\x55\xe5\x06\x84\xf8\x5d\x22\x13\x93"
			 "\x28\xa7\x18\xa3\xd2\x03\xc3\xe4\xa1\x7d\x4f\x53\x38\x95\x7a\x6a"
			 "\x54\x52\x6b\x9a\x42\xe2\xf0\xfc\x39\x95\x80\x56\x51\xc9\xc0\xc3"
			 "\x9b\xb3\x37\xa6\x57\x6a\xde\xa0\xf5\xdb\xae\x16",
		.H = "\xd7\xda\x32\x87\xac\x9b\x88\xce\xeb\xb8\xb4\x79\x05\xf2\xbe\xac",
		.lenA = 0xa0>>3, .lenC = 0x1e0>>3,.klen=32,.ivlen=128*4-32,
		.G = "\x0b\x17\x7f\x1a\x42\x87\x21\x72\x69\x4d\xac\xc5\x6f\xcf\xff\xd5",
		.C = "\x20\x2a\x9e\x65\x53\x78\x5d\xf7\xf1\x53\x9e\x0c\x2f\xef\x8d\x5a"
			 "\xf4\x6b\x74\x6f\x4f\xab\x58\xa0\x19\x64\xde\xaf\x2a\xb2\xb2\xee"
			 "\xde\x2c\xd8\xc5\xf1\xeb\xa3\x2d\x45\x44\xf2\x80\xb7\xc3\xc0\x0f"
			 "\x3f\x7e\xae\x44\x2e\xf8\x0e\x20\x97\x89\x41\xa2",
		.T = "\x9a\xf1\xe9\x5a\xcf\xd4\xb5\xc8\xb0\x8e\x1c\xee\x66\x82\x4a\xa4"
	}
};
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
static inline v4si CTR128(v4si x)
{
    //uint16_t * y = (void*)x;
    x[3] = __builtin_bswap32(__builtin_bswap32(x[3])+1);
	//x[0]++;
    return x;
}

/*! \brief кодирование в режиме CTR
    Функция используется и для кодирования и для декодирования CTR моды
 */
static void CTR128_encrypt(Ciph*ciph, v4si v, uint8_t* dst, const uint8_t* src, int length)
{
    CipherEncrypt128 encrypt = (CipherEncrypt128)ciph->cipher->encrypt;
    v4si d, p;
    int blocks = length>>4;
    int i;
    for (i=0;i<blocks;i++) {
        d = v;
        v = CTR128(v);
        d = encrypt(ciph->ctx, d);
        __builtin_memcpy(&p, src, 16); src+=16;
        *(v4si*)dst = d ^ p;//(v4si) REVERSE((v16qi)( d)) ^ p; 
		dst+=16;
    }
    if (length & 0xF){// если длина сообщения не выровнена на 128 бит
        d = encrypt(ciph->ctx, v);
/*		p^=p;
		__builtin_memcpy((uint8_t*)&p, src, length & 0xF);
		p = d ^ p;
		__builtin_memcpy(dst, (uint8_t*)&p, length & 0xF);
*/
		p = (v4si)LOADZU(src, length);
		p = d ^ p;
		STOREU(dst, (v16qi)p, length);
    }
}
// authenticated encryption with associated data (AEAD) block cipher
int aead_gcm_encrypt(AEAD_t * aead, uint8_t *dst, uint8_t *data, size_t data_len) 
{
	CipherEncrypt128 encrypt = (CipherEncrypt128)aead->cipher->encrypt;
	v4si h = {0};
	h = encrypt(aead->ctx, h);
	h = SLM128((v4si)REVERSE((v16qi)h));
// 1.set_iv
	v4si icb={0};
	if (aead->iv_len==96) {
		icb = (v4si)LOADZU( aead->iv, 96/8);
		icb[3] = 1<<24;
	} else {
		icb = GHASH_(icb, h, aead->iv, aead->iv_len/8);
		v4si x = (v4si){aead->iv_len, 0, 0, 0};
		//x = (v4si)REVERSE((v16qi)x);
		//icb = GHASH_(icb, h, (uint8_t*)&x, 16);
		icb = gmul128((icb^x), h);
		icb = (v4si)REVERSE((v16qi)icb);
	}
// 2.encrypt
	if (data_len) {// шифрование пакета
		v4si icb2 = CTR128(icb);
//		aead->iv = (uint8_t*)&icb2;
		CTR128_encrypt((Ciph*)aead, icb2, dst, data, data_len);
		//printhex("C: ", (uint8_t*)dst, data_len);
		//if (memcmp(&dst, test_vectors[j].C,test_vectors[j].lenC)==0) printf("..ok\n");
	}
// 3.tag расчет тега атуентификации
	if (aead->tag!=NULL && aead->tag_len>0) {
		v4si t ={0};
		if (aead->aad_len) {
			t = GHASH_(t, h, aead->aad, aead->aad_len);
		}
		if (data_len){
			t = GHASH_(t, h, dst, data_len);
		}
		v4si x = (v4si){data_len<<3, 0, aead->aad_len<<3, 0};
		//x = (v4si)REVERSE((v16qi)x);
		//t = GHASH_(t, h, (uint8_t*)&x, 16);
		t = gmul128((t^x), h);
		t = (v4si)REVERSE((v16qi)t);
		x = encrypt(aead->ctx, icb);
		t = x ^ t;
//		STOREU(aead->tag, (v16qi)t, aead->tag_len);
		__builtin_memcpy(aead->tag, (uint8_t*)&t,  aead->tag_len);// +(16-aead->tag_len)
	}
	return 0;
}
int aead_gcm_decrypt(AEAD_t * aead, uint8_t *dst, uint8_t *data, size_t data_len)
{
	CipherEncrypt128 encrypt = (CipherEncrypt128)aead->cipher->encrypt;
	v4si h = {0};
	h = encrypt(aead->ctx, h);
	h = SLM128((v4si)REVERSE((v16qi)h));

// 1.set_iv
	v4si icb={0};
	if (aead->iv_len==96) {
		//__builtin_memcpy((uint8_t*)&icb, aead->iv, 96/8);
		icb = (v4si)LOADZU( aead->iv, 96/8);
		icb[3] = 1<<24;
	} else {
		icb = GHASH_(icb, h, aead->iv, aead->iv_len/8);
		v4si x = (v4si){aead->iv_len, 0, 0, 0};
		icb = gmul128((icb^x), h);
		icb = (v4si)REVERSE((v16qi)icb);
	}
// 3.tag расчет тега атуентификации
	if (aead->tag!=NULL && aead->tag_len>0) {
		v4si t ={0};
		if (aead->aad_len) {
			t = GHASH_(t, h, aead->aad, aead->aad_len);
		}
		if (data_len){
			t = GHASH_(t, h, data, data_len);
		}
		v4si x = (v4si){data_len<<3, 0, aead->aad_len<<3, 0};
		t = gmul128((t^x), h);
		t = (v4si)REVERSE((v16qi)t);
		x = encrypt(aead->ctx, icb);
		t = x ^ t;
		if(__builtin_memcmp(aead->tag, &t,  aead->tag_len)!=0) {
//			printf("FAIL!!!\n");
			return 1;// FAIL
		}
	}
	if (dst!=NULL && data_len>0) {// шифрование пакета
		v4si icb2 = CTR128(icb);
		CTR128_encrypt((Ciph*)aead, icb2, dst, data, data_len);
	}
	return 0;
}
int main ()
{
Ciph* cipher = cipher_select(CIPH_AES, CIPH_MODE_GCM);
printf("Cipher '%s'\n", cipher->cipher->name);

//  gcc -I. -I:/msys64/mingw64/include/glib-2.0 -O3 -march=native -o ghash ghash.c aes.c cipher.c -lglib-2.0
if (0){// не знаю откуда взял, но не сходится.
uint32_t K[8]={0};
uint8_t tag[32]={0};
uint8_t dst[16*16];
int i,j;
for (j=0; j < sizeof(test_vectors)/sizeof(Test_t); j++)
{
	printf("Tast case %d\n", j+1);
	cipher_set_key(cipher, test_vectors[j].K, test_vectors[j].klen, test_vectors[j].klen<<3);
//	cipher_set_iv (cipher, test_vectors[j].iv,test_vectors[j].ivlen);
//	cipher_set_aad(cipher, test_vectors[j].A, test_vectors[j].lenA);
//	cipher_set_tag(cipher, tag, 16);
	AEAD_t* aead = (AEAD_t*) cipher;
	aead->iv = test_vectors[j].iv, aead->iv_len  = test_vectors[j].ivlen;
	aead->aad = test_vectors[j].A, aead->aad_len = test_vectors[j].lenA;
	aead->tag = tag, aead->tag_len = 16;
	//cipher->encrypt(cipher, dst, tag, 16);
	aead_gcm_encrypt(aead, dst, test_vectors[j].P, test_vectors[j].lenC);
	
	if (__builtin_memcmp(dst, test_vectors[j].C,test_vectors[j].lenC)==0) printf("CT ..ok\n");
	if (__builtin_memcmp(tag, test_vectors[j].T,16)==0) printf("Tag..ok\n");
	
	aead->tag = test_vectors[j].T;
	int res = 
	aead_gcm_decrypt(aead, dst, test_vectors[j].C, test_vectors[j].lenC);
	
	if (res==0) printf("Dec..ok\n");
	if (__builtin_memcmp(dst, test_vectors[j].P,test_vectors[j].lenC)==0) printf("PT ..ok\n");
}
}
if (1){
	uint8_t buf[1024];
	char* filename = "gcmEncryptExtIV128.rsp";
	FILE *fp =fopen(filename, "r");
	if (fp==NULL) return (1);
printf(" %s -- Test Vectors\n", filename);	



	int pt_load = 0, ct_load = 0, decrypt = 0;
	uint32_t Keylen=0, Taglen=0, AADlen=0, PTlen=0, IVlen=0, Count=0;
	uint32_t key[32/4]={0};
	uint8_t iv [1024/8]={0};
	uint8_t aad[1024/8];
	uint8_t ct [1024/8];
	uint8_t pt [1024/8]={0};
	uint8_t tag[32];
	v4si tag2;
	
	AEAD_t* aead = (AEAD_t*) cipher;
	aead->iv  = iv;
	aead->aad = aad;
	aead->tag = (uint8_t*)&tag2;
	int err = 0;
	while (fgets(buf, 1024, fp)!=NULL) {
		if (strncmp("Count = ", buf, 8)==0) {
			Count = atol(buf+8);
		} else
		if (strncmp("Key = ", buf, 6)==0) {
			hexstr((uint8_t*)&key, buf+6, Keylen/8);
		} else
		if (strncmp("IV = ", buf, 5)==0) {
			hexstr(iv, buf+5, IVlen/8);
		} else
		if (strncmp("PT = ", buf, 5)==0) {
			hexstr(pt, buf+5, PTlen/8);
		} else
		if (strncmp("CT = ", buf, 5)==0) {
			hexstr(ct, buf+5, PTlen/8);
		} else
		if (strncmp("AAD = ", buf, 6)==0) {
			hexstr(aad, buf+6, AADlen/8);
		} else
		if (strncmp("Tag = ", buf, 6)==0) {
			hexstr(tag, buf+6, Taglen/8);
			ct_load =1;
		} else
		if (buf[0] == '[')
		{
			if (strncmp("[PTlen = ", buf, 9)==0) {
				PTlen = atol(buf+9);
				printf ("[PTlen = %d]\n", PTlen);
			} else
			if (strncmp("[IVlen = ", buf, 9)==0) {
				IVlen = atol(buf+9);
				aead->iv_len = IVlen;
				printf ("[IVlen = %d]\n", IVlen);
			} else
			if (strncmp("[Keylen = ", buf, 10)==0) {
				Keylen = atol(buf+10);
			} else
			if (strncmp("[AADlen = ", buf, 10)==0) {
				AADlen = atol(buf+10);
				aead->aad_len = AADlen/8;
				printf ("[AADlen = %d]\n", AADlen);
			} else
			if (strncmp("[Taglen = ", buf, 10)==0) {
				Taglen = atol(buf+10);
				aead->tag_len = Taglen/8;
				printf ("[Taglen = %d]\n", Taglen);
			}
		}
		if (ct_load) {
			printf("Count = %d\n", Count);
			printhex("Key = ", (uint8_t*)key, Keylen/8);
			printhex("IV  = ", (uint8_t*)iv,  IVlen/8);
			printhex("AAD = ", (uint8_t*)aad, AADlen/8);
			printhex("Tag = ", (uint8_t*)tag, Taglen/8);

//v4si k = *(v4si*)key;
//k = (v4si)REVERSE((v16qi)k);
			cipher_set_key(cipher, (uint8_t*)key, Keylen/8, Keylen);

			uint8_t dst[8*16];
			//CTR128_encrypt(cipher, dst, pt, PTlen/8);
			aead_gcm_encrypt(aead, dst, pt, PTlen/8);
			printhex("CT  = ", (uint8_t*)ct, PTlen/8);
			printhex("ct  = ", (uint8_t*)dst, PTlen/8);
			//tag2 = (v4si)REVERSE((v16qi)tag2);
			printhex("tag = ", (uint8_t*)&tag2, 16);
			printf("Enc..%s\n", (memcmp(ct, dst, PTlen/8)==0)?"ok":"fail");
			printf("Tag..%s\n", (memcmp(&tag2, tag, Taglen/8)==0)?"ok":"fail");
			int res = 
			aead_gcm_decrypt(aead, dst, ct, PTlen/8);
			printf("Dec..%s\n", (res==0 && memcmp(pt, dst, PTlen/8)==0)?"ok":"fail");
			if (res!=0) break;

			printf("\n");
			ct_load = 0;
		}
	}
	printf("done\n");
	fclose(fp);
}
	if (0){
		uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
		uint8_t iv2[] = "\x51\x75\x3c\x65\x80\xc2\x72\x6f\x20\x71\x84\x14\x00\x00\x00\x02";
		uint8_t pt2[] = "\x47\x61\x6c\x6c\x69\x61\x20\x65\x73\x74\x20\x6f\x6d\x6e\x69\x73"
		"\x20\x64\x69\x76\x69\x73\x61\x20\x69\x6e\x20\x70\x61\x72\x74\x65"
        "\x73\x20\x74\x72\x65\x73";
		v4si icb,v;
		v4si dst[8];
		__builtin_memcpy(&icb, iv2, 16);
		CipherEncrypt128 encrypt = (CipherEncrypt128)cipher->cipher->encrypt;
		cipher_set_key((Ciph*)cipher, (uint8_t*)key, 16, 128);
		dst[0] = encrypt(cipher->ctx, icb);
		printhex("block # 0  = ", (uint8_t*)dst, 16);// ok
		__builtin_memcpy(&v, pt2, 16);
		dst[0] ^= v;
		printhex("block # pt = ", (uint8_t*)pt2, 16);// ok
		printhex("block # ct = ", (uint8_t*)dst, 16);// ok
		
	}
	if (0){
		uint8_t key[] = "\xFE\xFF\xE9\x92\x86\x65\x73\x1C\x6D\x6A\x8F\x94\x67\x30\x83\x08";
		uint8_t iv2[] = "\xCA\xFE\xBA\xBE\xFA\xCE\xDB\xAD\xDE\xCA\xF8\x88\x00\x00\x00\x02";
		uint8_t pt2[] = "\xD9\x31\x32\x25\xF8\x84\x06\xE5\xA5\x59\x09\xC5\xAF\xF5\x26\x9A"
						"\x86\xA7\xA9\x53\x15\x34\xF7\xDA\x2E\x4C\x30\x3D\x8A\x31\x8A\x72"
						"\x1C\x3C\x0C\x95\x95\x68\x09\x53\x2F\xCF\x0E\x24\x49\xA6\xB5\x25"
						"\xB1\x6A\xED\xF5\xAA\x0D\xE6\x57\xBA\x63\x7B\x39\x1A\xAF\xD2\x55";
		CipherEncrypt128 encrypt = (CipherEncrypt128)cipher->cipher->encrypt;
		cipher_set_key((Ciph*)cipher, (uint8_t*)key, 16, 128);
		v4si icb,v;
		__builtin_memcpy(&icb, iv2, 16);
		v4si dst[4];
		dst[0] = encrypt(cipher->ctx, icb);
		printhex("CT  = ", (uint8_t*)dst, 16);// ok
	}
return 0;
}
