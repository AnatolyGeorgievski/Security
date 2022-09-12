/*! 
	Intel® Carry-Less Multiplication Instruction and its Usage for Computing the GCM Mode 

	\see [RFC 8452] AES-GCM-SIV, April 2019
	\see https://github.com/Shay-Gueron/AES-GCM-SIV
	
POLYVAL(H, X_1, X_2, ...) is equal to
   ByteReverse(GHASH(ByteReverse(H) * x, ByteReverse(X_1),
   ByteReverse(X_2), ...))
   
  Aggr2 
  Yi = [(Xi • H) + (Xi-1+Yi-2) •H2] mod P
  Aggr4 
  Yi = [(Xi • H) + (Xi-1 • H2) + (Xi-2 • H3) + (Xi-3+Yi-4) •H4] mod P
*/

#include <stdio.h>
#include <stdint.h>
#include <intrin.h>
//#include <wmmintrin.h>
//#include <tmmintrin.h>

#define Karatsuba 0
typedef uint64_t poly64x2_t __attribute__((__vector_size__(16)));
typedef  int64_t  int64x2_t __attribute__((__vector_size__(16)));


static inline
poly64x2_t LOADU128(const void* src)
{// defined(__SSE2__) 
	return (poly64x2_t)_mm_loadu_si128(src);
}
/*! \brief этот алгоритм короче чем в референсном варианте */
poly64x2_t gmul128r_(poly64x2_t a, const poly64x2_t b)
{
	const __m128i  poly = _mm_setr_epi32(0x1,0,0,0xc2000000);//{1,0xc2ULL<<56};
    __m128i  M,L,H;
    L = _mm_clmulepi64_si128((__m128i)a, (__m128i)b, 0x00);
    M = _mm_clmulepi64_si128((__m128i)a, (__m128i)b, 0x01);
    M^= _mm_clmulepi64_si128((__m128i)a, (__m128i)b, 0x10);
    H = _mm_clmulepi64_si128((__m128i)a, (__m128i)b, 0x11);
// редуцирование по модулю, работает!
	M^= _mm_shuffle_epi32(L, 78);//(poly64x2_t){L[1],L[0]};//SHUFFLE(L);
    M^= _mm_clmulepi64_si128(L, poly, 0x10);
// редуцирование по модулю, работает! это можно использовать как отдельную функцию
	H^= _mm_shuffle_epi32(M, 78);//(poly64x2_t){M[1],M[0]};//SHUFFLE(M);
    H^= _mm_clmulepi64_si128(M, poly, 0x10);
    return (poly64x2_t)H;
}

static inline
poly64x2_t CL_MUL128(poly64x2_t a, poly64x2_t b, const int c) __attribute__ ((__target__("pclmul")));
static inline poly64x2_t CL_MUL128(poly64x2_t a, poly64x2_t b, const int c) {
    return (poly64x2_t)__builtin_ia32_pclmulqdq128 ((int64x2_t)a,(int64x2_t)b,c);
}
static 
poly64x2_t gf128r_reduction(poly64x2_t L, poly64x2_t M, poly64x2_t H)
{
#if 0// доделать вариант
	uint64x2_t d = (uint64x2_t){0, r0[1]};//SLL128U(r0,64);
	uint64x2_t h = r0 ^ (d<<63) ^ (d<<62) ^ (d<<57);
	d = (uint64x2_t){h[1], 0};//SRL128U(h,64);
	d = r1 ^ (d<<63) ^ (d<<62) ^ (d<<57);
//	printf("d: 0x%016"PRIX64"%016"PRIX64" \n", d[1], d[0]);
	h = h ^ h>>1 ^ h>>2 ^ h>>7;//SRL64x2(h, d, 1) ^ SRL64x2(h, d, 2)^ SRL64x2(h, d, 7);
// b1 = x1 ^ x0<<63 ^ x0<<62 ^ x0<<57 
// h0 = x0 ^ x0>>1  ^ x0>>2  ^ x0>>7
// d0 = x0<<63 ^ x0<<62 ^ x0<<57
// h1 = b1 ^ b1>>1 ^ b1>>2 ^ b1>>7
	
	
	return (h^d);
#elif 0
	M[0]^= L[1] ^ L[0]<<57 ^ L[0]<<62 ^ L[0]<<63;
	M[1]^= L[0] ^ L[0]>>7  ^ L[0]>>2  ^ L[0]>>1;
	H[0]^= M[1] ^ M[0]<<57 ^ M[0]<<62 ^ M[0]<<63;
	H[1]^= M[0] ^ M[0]>>7  ^ M[0]>>2  ^ M[0]>>1;
#else
	const poly64x2_t poly = (poly64x2_t){1,0xc2ULL<<56};
	M ^= (poly64x2_t){L[1],L[0]} ^ CL_MUL128(L,poly, 0x10);
	H ^= (poly64x2_t){M[1],M[0]} ^ CL_MUL128(M,poly, 0x10);
#endif
	return H;
}
/*! \brief этот алгоритм короче чем в референсном варианте */
static 
poly64x2_t gmul128r(poly64x2_t a, const poly64x2_t b)
{
	const poly64x2_t poly = (poly64x2_t){1,0xc2ULL<<56};
    poly64x2_t M,L,H;
#if (Karatsuba==1) // карацуба
	poly64x2_t t;
	L = CL_MUL128(a, b, 0x00);
	H = CL_MUL128(a, b, 0x11);

	t = (poly64x2_t){a[0],b[0]} ^ (poly64x2_t){a[1], b[1]};
	M = CL_MUL128(t, t, 0x01) ^ L ^ H;

#else
    L = CL_MUL128(a, b, 0x00);
    M = CL_MUL128(a, b, 0x01);
    M^= CL_MUL128(a, b, 0x10);
    H = CL_MUL128(a, b, 0x11);
#endif
	return gf128r_reduction(L,M,H);
#if 0
// редуцирование по модулю, работает!
	M^= (poly64x2_t){L[1],L[0]};//SHUFFLE(L);
    M^= CL_MUL128(L, poly, 0x10);
// редуцирование по модулю, работает! это можно использовать как отдельную функцию
	H^= (poly64x2_t){M[1],M[0]};//SHUFFLE(M);
    H^= CL_MUL128(M, poly, 0x10);
    return H;
#endif
}
//(a^n + a)^2= a^2*n^2 + a^2
/* возведение в квадрат */
static 
poly64x2_t gsqr128r(const poly64x2_t b)
{
	const poly64x2_t poly = (poly64x2_t){1,0xc2ULL<<56};
    poly64x2_t M,L,H;
    L = CL_MUL128(b, b, 0x00);
    H = CL_MUL128(b, b, 0x11);//(a*x + b)^2= a^2*x^2 + b^2
	M = (poly64x2_t){0,0};
	return gf128r_reduction(L,M,H);
#if 0
// редуцирование по модулю, работает!
	M = (poly64x2_t){L[1],L[0]}//SHUFFLE(L);
      ^ CL_MUL128(L, poly, 0x10);
// редуцирование по модулю, работает! это можно использовать как отдельную функцию
	H^= (poly64x2_t){M[1],M[0]}//SHUFFLE(M);
      ^ CL_MUL128(M, poly, 0x10);
    return H;
#endif
}
static 
poly64x2_t gmul128r_aggr2(poly64x2_t x0, poly64x2_t x1, 
			const poly64x2_t h, const poly64x2_t h2 )
{
	const poly64x2_t poly = (poly64x2_t){1,0xc2ULL<<56};
    poly64x2_t M,L,H;
#if (Karatsuba==1) // карацуба -- лучше без карацубы
	poly64x2_t t;
	L = CL_MUL128(x1, h, 0x00);
	H = CL_MUL128(x1, h, 0x11);

	t = (poly64x2_t){x1[0],h[0]} ^ (poly64x2_t){x1[1], h[1]};
	M = CL_MUL128(t, t, 0x01);
	t = (poly64x2_t){x0[0],h2[0]} ^ (poly64x2_t){x0[1], h2[1]};

    L^= CL_MUL128(x0, h2, 0x00);
    H^= CL_MUL128(x0, h2, 0x11);
	M^= CL_MUL128(t, t, 0x01);

	M^=L^H;
#else
    L = CL_MUL128(x1, h, 0x00);
    M = CL_MUL128(x1, h, 0x01);
    M^= CL_MUL128(x1, h, 0x10);
    H = CL_MUL128(x1, h, 0x11);
    L^= CL_MUL128(x0, h2, 0x00);
    M^= CL_MUL128(x0, h2, 0x01);
    M^= CL_MUL128(x0, h2, 0x10);
    H^= CL_MUL128(x0, h2, 0x11);
#endif
	return gf128r_reduction(L,M,H);
#if 0
// редуцирование по модулю, работает!
	M^= (poly64x2_t){L[1],L[0]};//SHUFFLE(L);
    M^= CL_MUL128(L, poly, 0x10);
// редуцирование по модулю, работает! это можно использовать как отдельную функцию
	H^= (poly64x2_t){M[1],M[0]};//SHUFFLE(M);
    H^= CL_MUL128(M, poly, 0x10);
    return H;
#endif
}
poly64x2_t POLYVAL(poly64x2_t y, poly64x2_t h, const uint8_t *data, int len)
{
	poly64x2_t x, x1;
    int i=0;
	int blocks = len>>5;
	if (blocks){
		poly64x2_t h2 = gsqr128r(h);// 4М -- эту операцию можно выполнить снаружи
//__asm volatile("# LLVM-MCA-BEGIN gmul128r_aggr2");
		for (i=0; i<blocks; i++){
			x = LOADU128(data); data+=16;
			x1= LOADU128(data); data+=16;
			y = gmul128r_aggr2((y^x), x1, h, h2);// 8M
		}
//__asm volatile("# LLVM-MCA-END gmul128r_aggr2");
	}
	blocks = len>>4;
__asm volatile("# LLVM-MCA-BEGIN gmul128r");
    for (i=i*2; i<blocks; i++){
        x = LOADU128(data); data+=16;
        y = gmul128r((y^x), h);// 6M
    }
__asm volatile("# LLVM-MCA-END gmul128r");
	if (len & 0xF){
		x ^= x;
		__builtin_memcpy(&x, data, len&0xF);
		y = gmul128r((y^x), h);
	}
    return y;
}
#ifdef DEBUG_POLYVAL
typedef uint8_t  uint8x16_t __attribute__((__vector_size__(16)));
static inline
poly64x2_t REVERSE(poly64x2_t x)
{
    return (poly64x2_t)__builtin_shuffle ((uint8x16_t)x,(uint8x16_t){15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0});
}

#if 0 // ложный шаг
/*! расчитывает баррета */
poly64x2_t barret128_calc()
{
//	poly <<=8;
	poly64x2_t poly = {1, 0xC2ULL<<56};
	poly64x2_t r = poly;
		poly[0] = (poly[0] >>1) | (poly[1]<<63);
		poly[1] = (poly[1] >>1) | (1ULL<<63);
	uint64_t n = 64;
	poly64x2_t v = {0};
	while (--n){
		if (r[1] & (1ULL<<n)) {
			r ^= poly;
			v[1] |= 1ULL<<n;
		}
		poly[0] = (poly[0] >>1) | (poly[1]<<63);
		poly[1] = (poly[1] >>1);
	}
//	if (r[1]) v[1]|=1;
//	return v;
	n=64;
	while (--n){
		if (r[0] & (1ULL<<n)) {
			r ^= poly;
			v[0] |= 1ULL<<n;
		}
		poly[0] = (poly[0] >>1) | (poly[1]<<63);
		poly[1] = (poly[1] >>1);
		
	}
	if (r[0]) v[0]|=1;
	return v;
}
// работает
poly64x2_t gmul128_(poly64x2_t a, poly64x2_t b)
{
	poly64x2_t P = {0x1ULL, 0xC2ULL<<56};
	poly64x2_t r = {0};
	int i;
	for (i=0; i<64; i++) {
		if (a[0]& (1ULL<<(i))) r ^= b;
		if (b[1]>>63) {
			b[1] = (b[0]>>63) | (b[1]<<1); 
			b[0] = (b[0]<<1);
			b ^= P;
		} else {
			b[1] = (b[0]>>63) | (b[1]<<1); 
			b[0] = (b[0]<<1);
		}
	}
	for (i=0; i<64; i++) {
		if (a[1]& (1ULL<<(i))) r ^= b;
		if (b[1]>>63) {
			b[1] = (b[0]>>63) | (b[1]<<1); 
			b[0] = (b[0]<<1);
			b ^= P;
		} else {
			b[1] = (b[0]>>63) | (b[1]<<1); 
			b[0] = (b[0]<<1);
		}
	}
	return r;
}
poly64x2_t gmul128(poly64x2_t a, poly64x2_t b)
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
#endif
static poly64x2_t SRM128(poly64x2_t d)
{
    poly64x2_t r = {d[1],d[0]};
    r <<=63;
    r = (r!=0) & (poly64x2_t){1ULL<<63,0xE1ULL<<56};
    return  (d>>1) ^ r;	
}
static poly64x2_t mulX_POLYVAL(poly64x2_t d)
{
#if 1	
	poly64x2_t r;
	r[1] = d[1]<<1 | d[0]>>63;
	r[0] = d[0]<<1;
	if (d[1]>>63) {
		r ^= (poly64x2_t){1, 0x42ULL<<56};
	}
	return r;
#else
    poly64x2_t r = {d[1],d[0]};
    r >>=63;
    if (r[0]!=0) r[1] ^= 0x42ULL<<56;// x^-128 x^128 + x^127 + x^126 + x^121 +1
    return  (d<<1) ^ r;
#endif
}
static poly64x2_t mulX_GHASH(poly64x2_t d)
{
    poly64x2_t r = {d[1],d[0]};
    r <<=63;
    r = (r!=0) & (poly64x2_t){1ULL<<63,0xe1ULL<<56};
    return  (d>>1) ^ r;
}
static poly64x2_t SLM128(poly64x2_t d)
{
    poly64x2_t r = {d[1],d[0]};
    r >>=63;
    if (r[0]!=0) r[1] ^= 0xc2ULL<<56;
    return  (d<<1) ^ r;
}


#include <stdio.h>
int main() {
	//  7.  Field Operation Examples
	uint8_t A[] = "\x66\xe9\x4b\xd4\xef\x8a\x2c\x3b\x88\x4c\xfa\x59\xca\x34\x2b\x2e";
	uint8_t B[] = "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t X_[] = "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x92";
	poly64x2_t a,b;
	poly64x2_t t,h;
	__builtin_memcpy(&a, A, 16);
	a = (a);
	__builtin_memcpy(&b, B, 16);
	b = (b);
	t = gmul128r(a,b);
	printf("a * b = %016llx %016llx\n", t[1], t[0]);
	__builtin_memcpy(&h, X_, 16);
	t = gmul128r(t,h);
	printf("dot(a, b) = %016llx %016llx\n", t[1], t[0]);// ebe563401e7e91ea3ad6426b8140c394
	uint8_t t1[] = "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t t2[] = "\x9c\x98\xc0\x4d\xf9\x38\x7d\xed\x82\x81\x75\xa9\x2b\xa6\x52\xd8";
	__builtin_memcpy(&a, t1, 16);
	t = mulX_POLYVAL(a);
	printf("mulX_POLYVAL: %016llx %016llx\n", t[1], t[0]);
	t = REVERSE(mulX_GHASH(REVERSE(a)));
	printf("mulX_GHASH  : %016llx %016llx\n", t[1], t[0]);
	__builtin_memcpy(&a, t2, 16);
	t = mulX_POLYVAL(a);
	printf("mulX_POLYVAL: %016llx %016llx\n", t[1], t[0]);
	t = REVERSE(mulX_GHASH(REVERSE(a)));
	printf("mulX_GHASH  : %016llx %016llx\n", t[1], t[0]);
	uint8_t H[] = "\x25\x62\x93\x47\x58\x92\x42\x76\x1d\x31\xf8\x26\xba\x4b\x75\x7b";
	__builtin_memcpy(&h, H, 16);
	t = mulX_POLYVAL(REVERSE(h));
	printf("mulX_POLYVAL(ByteReverse(H)) = : %016llx %016llx\n", t[1], t[0]);
	t = SRM128(mulX_POLYVAL(REVERSE(h)));
	printf("SRM128(mulX_POLYVAL(ByteReverse(H)) = : %016llx %016llx\n", t[1], t[0]);
	t = mulX_GHASH(SLM128(h));
	printf("mulX_GHASH(SLM128(H)) = : %016llx %016llx\n", t[1], t[0]);
	t = mulX_GHASH((h));
	printf("mulX_GHASH(ByteReverse(H)) = : %016llx %016llx\n", t[1], t[0]);
	uint8_t X[] = "\x4f\x4f\x95\x66\x8c\x83\xdf\xb6\x40\x17\x62\xbb\x2d\x01\xa2\x62"
          "\xd1\xa2\x4d\xdd\x27\x21\xd0\x06\xbb\xe4\x5f\x20\xd3\xc9\xf3\x62";

	uint8_t tag[16];
	t^=t;
	t = POLYVAL(t, h, X, 32); // -- рабочий вариант
	printf("POLYVAL(H, X_1, X_2) = %016llx %016llx\n", t[1], t[0]);

#if 0
	t = mulX_GHASH((h));
	__builtin_memcpy(&a, X, 16);
	__builtin_memcpy(&b, X+16, 16);
	t = REVERSE(t);
	a = REVERSE(a);
	b = REVERSE(b);
	t^=t;
	h = SLM128(REVERSE(mulX_GHASH((h))));
	t = GHASH(t, h, X, 32);
	printf("GHASH(H, X_1, X_2) = %016llx %016llx\n", t[1], t[0]);
	t = barret128_calc();
	printf("Barrett = %016llx %016llx\n", t[1], t[0]);
	poly64x2_t p = {0, 0xC2ULL<<56};//t[1]^=1;
	poly64x2_t M, L;
    M = CL_MUL128(t, p, 0x01);
    M^= CL_MUL128(t, p, 0x10);
    h = CL_MUL128(t, p, 0x11) ^ (poly64x2_t){M[1], 0};
    L = CL_MUL128(t, p, 0x00) ^ (poly64x2_t){0, M[0]};
	h^=p;
	h^=t;
	printf("Barrett *Px = %016llx %016llx %016llx %016llx\n", h[1], h[0], L[1], L[0]);
#endif
	return 0;
}
#endif