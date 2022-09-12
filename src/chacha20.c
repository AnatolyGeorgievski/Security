/* ChaCha20  SSE implementation of ChaCha20 cipher
	[RFC 8439] ChaCha20 & Poly1305, June 2018
	
	Copyright (C) 2021 Anatoly Georgievskii <Anatoly.Georgievski@gmail.com>
*/

#include <stdint.h>
#define ROL(v, n) (((v)<<(n)) ^ ((v)>>(32-(n))))
#define SHUFFLE(v, a,b,c,d) __builtin_shuffle((v), (uint32x4_t){a,b,c,d})
#define SHUFFLE2(v, w, a,b,c,d) __builtin_shuffle((v),(w), (uint32x4_t){a,b,c,d})
#if 1
void QUARTERROUND(uint32_t *s, int a, int b, int c, int d) {
	s[a] += s[b]; s[d] ^= s[a]; s[d] = ROL(s[d],16);
	s[c] += s[d]; s[b] ^= s[c]; s[b] = ROL(s[b],12);
	s[a] += s[b]; s[d] ^= s[a]; s[d] = ROL(s[d], 8);
	s[c] += s[d]; s[b] ^= s[c]; s[b] = ROL(s[b], 7);
}
void ChaCha20_(uint32_t *S) {
	
	int i;
	uint32_t s[16];
	for (i=0;i<16;i++) s[i] = S[i];
	for (i=0;i<10;i++) {
		QUARTERROUND(s, 0, 4,  8, 12);
		QUARTERROUND(s, 1, 5,  9, 13);
		QUARTERROUND(s, 2, 6, 10, 14);
		QUARTERROUND(s, 3, 7, 11, 15);
		QUARTERROUND(s, 0, 5, 10, 15);
		QUARTERROUND(s, 1, 6, 11, 12);
		QUARTERROUND(s, 2, 7,  8, 13);
		QUARTERROUND(s, 3, 4,  9, 14);
	}
	for (i=0;i<16;i++) S[i]+= s[i];
}
#endif
#if 0
#include <arm_neon.h>
void columnround_asm_neon(uint32_t y[16])
{
__asm (
	"vldm.32 %[y], {q0, q1, q2, q3}\n\t"
	/*
	* y[0], y[4], y[8], y[12]
	* y[1], y[5], y[9], y[13]
	* y[2], y[6], y[10], y[14]
	* y[3], y[7], y[11], y[15]
	* q0 = a, q1 = b q2 = c, q3 = d
	*/
	"vadd.i32 q0, q1\n\t" // a += b;
	"veor q4, q3, q0\n\t" // e = d ^ a;
	"vshl.i32 q3, q4, #16\n\t" // d = e <<< 16;
	"vsri.32 q3, q4, #16\n\t"
	"vadd.i32 q2, q3\n\t" // c += d;
	"veor q4, q1, q2\n\t" // e = b ^ c;
	"vshl.i32 q1, q4, #12\n\t" // b = e <<< 12;
	"vsri.32 q1, q4, #20\n\t"
	"vadd.i32 q0, q1\n\t" // a += b;
	"veor q4, q3, q0\n\t" // e = d ^ a;
	"vshl.i32 q3, q4, #8\n\t" // d = e <<< 8;
	"vsri.32 q3, q4, #24\n\t"
	"vadd.i32 q2, q3 \n\t" // c += d;
	"veor q4, q1, q2\n\t" // e = b ^ c;
	"vshl.i32 q1, q4, #7\n\t" // b = e <<< 7;
	"vsri.32 q1, q4, #25\n\t"
	"vstm.32 %[y], {q0, q1, q2, q3}\n\t"
	:
	: [y] "r" (y)
	: "q0", "q1", "q2", "q3", "q4");
}

void ChaCha20_neon(uint32_t *s) 
{
	uint32x4x4_t q = vld4q_u32(s);
	uint32x4_t q0 = q.val[0];
	uint32x4_t q1 = q.val[1];
	uint32x4_t q2 = q.val[2];
	uint32x4_t q3 = q.val[3];
	int i;
	for (i=0; i<10; i++){
		q0 = vaddq_u32(q0, q1);// a += b;
		q4 = veorq_u32(q3, q0);
		q3 = vshlq_u32(q4, 16);// d = e <<< 16;
		q3 = vsriq_u32(q4, 16);
		q2 = vaddq_u32(q2, q3);// c += d;
		q4 = veorq_u32(q1, q2);
		q1 = vshlq_u32(q4, 12);// b = e <<< 12;
		q1 = vsriq_u32(q4, 20);
		q0 = vaddq_u32(q0, q1);// a += b;
		q4 = veorq_u32(q3, q0);
		q3 = vshlq_u32(q4,  8);// d = e <<< 16;
		q3 = vsriq_u32(q4, 24);
		q2 = vaddq_u32(q2, q3);// c += d;
		q4 = veorq_u32(q1, q2);
		q1 = vshlq_u32(q4,  7);// b = e <<< 12;
		q1 = vsriq_u32(q4, 25);

		q1 = vextq_u32(q1, q1,q1, 1);
		q2 = vextq_u32(q2, q2,q2, 2);
		q3 = vextq_u32(q3, q3,q3, 3);

		q0 = vaddq_u32(q0, q1);// a += b;
		q4 = veorq_u32(q3, q0);
		q3 = vshlq_u32(q4, 16);// d = e <<< 16;
		q3 = vsriq_u32(q4, 16);
		q2 = vaddq_u32(q2, q3);// c += d;
		q4 = veorq_u32(q1, q2);
		q1 = vshlq_u32(q4, 12);// b = e <<< 12;
		q1 = vsriq_u32(q4, 20);
		q0 = vaddq_u32(q0, q1);// a += b;
		q4 = veorq_u32(q3, q0);
		q3 = vshlq_u32(q4,  8);// d = e <<< 8;
		q3 = vsriq_u32(q4, 24);
		q2 = vaddq_u32(q2, q3);// c += d;
		q4 = veorq_u32(q1, q2);
		q1 = vshlq_u32(q4,  7);// b = e <<< 7;
		q1 = vsriq_u32(q4, 25);
		
		q1 = vextq_u32(q1, q1,q1, 3);
		q2 = vextq_u32(q2, q2,q2, 2);
		q3 = vextq_u32(q3, q3,q3, 1);
	}
	q.val[0] = vaddq_u32(q.val[0], q0);
	q.val[1] = vaddq_u32(q.val[1], q1);
	q.val[2] = vaddq_u32(q.val[2], q2);
	q.val[3] = vaddq_u32(q.val[3], q3);
	vst4q_type(s, q);
}
#endif

#define ROTL(v, n) (((v)<<(n)) ^ ((v)>>(32-(n))))

typedef uint32_t uint32x4_t __attribute__((__vector_size__(16)));
void ChaCha20(uint32x4_t *s) 
{
	uint32x4_t a = s[0];
	uint32x4_t b = s[1];
	uint32x4_t c = s[2];
	uint32x4_t d = s[3];
	int i;
	for (i=0;i<10;i++) {
		a += b; d ^= a; d = ROTL(d,16);//16,0
		c += d; b ^= c; b = ROTL(b,12);//12
		a += b; d ^= a; d = ROTL(d, 8);//24,
		c += d; b ^= c; b = ROTL(b, 7);//19
		b = SHUFFLE(b, 1, 2, 3, 0);// vext.32 q1, q1,q1, #1  
		c = SHUFFLE(c, 2, 3, 0, 1);// vext.32 q2, q2,q2, #2
		d = SHUFFLE(d, 3, 0, 1, 2);// vext.32 q3, q3,q3, #3
		a += b; d ^= a; d = ROTL(d,16);// 8
		c += d; b ^= c; b = ROTL(b,12);//31
		a += b; d ^= a; d = ROTL(d, 8);//16
		c += d; b ^= c; b = ROTL(b, 7);//
		b = SHUFFLE(b, 3, 0, 1, 2);// vext.32 q1, q1,q1, #3  
		c = SHUFFLE(c, 2, 3, 0, 1);// vext.32 q2, q2,q2, #2
		d = SHUFFLE(d, 1, 2, 3, 0);// vext.32 q3, q3,q3, #1
	}
	s[0] += a;
	s[1] += b;
	s[2] += c;
	s[3] += d;
}


static inline 
void transpose_4x4 (uint32x4_t *r, uint32x4_t *s)
{
    uint32x4_t x0 = SHUFFLE2 (s[0], s[1], 0, 1, 4, 5); // 0 1 4 5
    uint32x4_t x1 = SHUFFLE2 (s[0], s[1], 2, 3, 6, 7); // 2 3 6 7
    uint32x4_t x2 = SHUFFLE2 (s[2], s[3], 0, 1, 4, 5); // 8 9 12 13
    uint32x4_t x3 = SHUFFLE2 (s[2], s[3], 2, 3, 6, 7); // 10 11 14 15
    r[0] = SHUFFLE2 (x0, x2, 0, 2, 4, 6);// 0 4  8 12
    r[1] = SHUFFLE2 (x0, x2, 1, 3, 5, 7);// 1 5  9 13
    r[2] = SHUFFLE2 (x1, x3, 0, 2, 4, 6);// 2 6 10 14
    r[3] = SHUFFLE2 (x1, x3, 1, 3, 5, 7);// 3 7 11 15
}
static void quarterround(uint32_t *s, int a, int b, int c, int d) {
	s[b] ^= ROL(s[a] + s[d], 7);
	s[c] ^= ROL(s[b] + s[a], 9);
	s[d] ^= ROL(s[c] + s[b],13);
	s[a] ^= ROL(s[d] + s[c],18);
}
void Salsa20_(uint32_t *S) 
{
	int i;
	uint32_t s[16];
	for (i=0;i<16;i++) s[i] = S[i];
	for (i=0;i<10;i++) {
		quarterround(s, 0, 4, 8,12);
		quarterround(s, 5, 9,13, 1);
		quarterround(s,10,14, 2, 6);
		quarterround(s,15, 3, 7,11);

		quarterround(s, 0, 1, 2, 3);
		quarterround(s, 5, 6, 7, 4);
		quarterround(s,10,11, 8, 9);
		quarterround(s,15,12,13,14);
	}		
	for (i=0;i<16;i++) S[i] += s[i];
}
void Salsa20(uint32x4_t *S) 
{
#if 1 // совместил сдвиги и транспонирование
    uint32x4_t s0 = SHUFFLE2 (S[0], S[1], 0, 1, 5, 6); // 0 1 4 5
    uint32x4_t s1 = SHUFFLE2 (S[0], S[1], 2, 3, 7, 4); // 2 3 6 7
    uint32x4_t s2 = SHUFFLE2 (S[2], S[3], 2, 3, 7, 4); // 8 9 12 13
    uint32x4_t s3 = SHUFFLE2 (S[2], S[3], 0, 1, 5, 6); // 10 11 14 15
    uint32x4_t x0 = S[0] = SHUFFLE2 (s0, s2, 0, 2, 4, 6);// 0 4  8 12
    uint32x4_t x3 = S[1] = SHUFFLE2 (s0, s2, 1, 3, 5, 7);// 1 5  9 13
    uint32x4_t x2 = S[2] = SHUFFLE2 (s1, s3, 0, 2, 4, 6);// 2 6 10 14
    uint32x4_t x1 = S[3] = SHUFFLE2 (s1, s3, 1, 3, 5, 7);// 3 7 11 15
#elif 1
	S[1] = SHUFFLE(S[1], 1, 2, 3, 0);
	S[2] = SHUFFLE(S[2], 2, 3, 0, 1);
	S[3] = SHUFFLE(S[3], 3, 0, 1, 2); 
	transpose_4x4(S, S);
	uint32x4_t x0 = S[0];
	uint32x4_t x3 = S[1];
	uint32x4_t x2 = S[2];
	uint32x4_t x1 = S[3];
#else	
	uint32_t* s = (uint32_t*)S;
	
	uint32x4_t x0 = {s[0],s[ 5],s[10],s[15]};
	uint32x4_t x3 = {s[1],s[ 6],s[11],s[12]};
	uint32x4_t x2 = {s[2],s[ 7],s[ 8],s[13]};
	uint32x4_t x1 = {s[3],s[ 4],s[ 9],s[14]};
/*
	uint32x4_t x0 = {s[0],s[ 5],s[10],s[15]};
	uint32x4_t x1 = {s[4],s[ 9],s[14],s[ 3]};
	uint32x4_t x2 = {s[8],s[13],s[ 2],s[ 7]};
	uint32x4_t x3 = {s[12],s[1],s[ 6],s[11]};*/
#endif
	int i;
	for (i=0;i<20;i++) {
		// замена столбцов x3<=>x1
		x1 = SHUFFLE(x1, 1, 2, 3, 0);
		x2 = SHUFFLE(x2, 2, 3, 0, 1);
		x3 = SHUFFLE(x3, 3, 0, 1, 2); 
		x1 ^= ROL(x0 + x3, 7);
		x2 ^= ROL(x1 + x0, 9);
		x3 ^= ROL(x2 + x1,13);
		x0 ^= ROL(x3 + x2,18);
		// замена столбцов x3<=>x1
		x3 = SHUFFLE(x3, 1, 2, 3, 0);
		x2 = SHUFFLE(x2, 2, 3, 0, 1);
		x1 = SHUFFLE(x1, 3, 0, 1, 2);
		x3 ^= ROL(x0 + x1, 7);
		x2 ^= ROL(x3 + x0, 9);
		x1 ^= ROL(x2 + x3,13);
		x0 ^= ROL(x1 + x2,18);
    }
#if 1 // совместил транспонирование и сдвиги
	S[0] = x0;
	S[1] = x3;
	S[2] = x2;
	S[3] = x1;
    x0 = SHUFFLE2 (S[0], S[1], 0, 1, 4, 5); // 0 1 4 5
    x1 = SHUFFLE2 (S[0], S[1], 2, 3, 6, 7); // 2 3 6 7
    x2 = SHUFFLE2 (S[2], S[3], 0, 1, 4, 5); // 8 9 12 13
    x3 = SHUFFLE2 (S[2], S[3], 2, 3, 6, 7); // 10 11 14 15
    S[0] = SHUFFLE2 (x0, x2, 0, 2, 4, 6);// 0 4  8 12
    S[1] = SHUFFLE2 (x0, x2, 7, 1, 3, 5);// 1 5  9 13
    S[2] = SHUFFLE2 (x1, x3, 4, 6, 0, 2);// 2 6 10 14
    S[3] = SHUFFLE2 (x1, x3, 3, 5, 7, 1);// 3 7 11 15
#elif 1
	S[0] = x0;
	S[1] = x3;
	S[2] = x2;
	S[3] = x1;
	transpose_4x4(S, S);
	S[1] = SHUFFLE(S[1], 3, 0, 1, 2); 
	S[2] = SHUFFLE(S[2], 2, 3, 0, 1);
	S[3] = SHUFFLE(S[3], 1, 2, 3, 0);
#else
	s[0] = x0[0];s[5] = x0[1];s[10] = x0[2];s[15] = x0[3];
	s[1] = x3[0];s[6] = x3[1];s[11] = x3[2];s[12] = x3[3];
	s[2] = x2[0];s[7] = x2[1];s[ 8] = x2[2];s[13] = x2[3];
	s[3] = x1[0];s[4] = x1[1];s[ 9] = x1[2];s[14] = x1[3];
#endif

}
#include <stdio.h>
int main() 
{
	uint64_t ts;

	int i;
	uint32x4_t S2[16] = {
		{0x00000001, 0x00000000, 0x00000000, 0x00000000},
		{0x00000000, 0x00000000, 0x00000000, 0x00000000},
		{0x00000000, 0x00000000, 0x00000000, 0x00000000},
		{0x00000000, 0x00000000, 0x00000000, 0x00000000},
	};
	//Salsa20_((uint32_t*)S2);
	Salsa20(S2);
	if (1) for (i=0; i<4; i++){
		uint32x4_t v = S2[i];
		printf("%08x %08x %08x %08x\n", v[0], v[1], v[2], v[3]);
	}
	uint32x4_t S3[16] = {
		{0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57},
		{0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36},
		{0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11},
		{0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1},
	};
	for(i=0; i<4; i++) (void)S3[i];
	ts = __builtin_ia32_rdtsc();
//	Salsa20_((uint32_t*)S3);
	Salsa20(S3);
	ts -= __builtin_ia32_rdtsc();
	printf("Salsa20  %lld clk\n", -ts);

	//transpose_4x4(S3,S3);
	if (1) for (i=0; i<4; i++){
		uint32x4_t v = S3[i];
		printf("%08x %08x %08x %08x\n", v[0], v[1], v[2], v[3]);
	}

#if 0
	uint32_t S0[16] = {
		0x879531e0,  0xc5ecf37d,  0x516461b1,  0xc9a62f8a,
		0x44c20ef3,  0x3390af7f,  0xd9fc690b,  0x2a5f714c,
		0x53372767,  0xb00a5631,  0x974c541a,  0x359e9963,
		0x5c971061,  0x3d631689,  0x2098d9d6,  0x91dbd320,
	};
	QUARTERROUND(S0, 2,7,8,13);
	for (i=0; i<4; i++){
		uint32_t *v = &S0[4*i];
		printf("%08x %08x %08x %08x\n", v[0], v[1], v[2], v[3]);
	}
#endif
#if 1

	ChaCha20_((uint32_t*)S3);
	uint32x4_t S[16] = {
		{0x61707865,  0x3320646e,  0x79622d32,  0x6b206574},
		{0x03020100,  0x07060504,  0x0b0a0908,  0x0f0e0d0c},
		{0x13121110,  0x17161514,  0x1b1a1918,  0x1f1e1d1c},
		{0x00000001,  0x09000000,  0x4a000000,  0x00000000}
	};
	if(0)for (i=0; i<4; i++){
		uint32x4_t v = S[i];
		printf("%08x %08x %08x %08x\n", v[0], v[1], v[2], v[3]);
	}
	for(i=0; i<4; i++) (void)S[i];
	ts = __builtin_ia32_rdtsc();
	ChaCha20_((uint32_t*)S);
	ts -= __builtin_ia32_rdtsc();
	printf("ChaCha20_ %lld clk\n", -ts);
	if(0)for (i=0; i<4; i++){
		uint32x4_t v = S[i];
		printf("%08x %08x %08x %08x\n", v[0], v[1], v[2], v[3]);
	}
#endif
	ChaCha20(S3);
	uint32x4_t S1[16] = {
		{0x61707865,  0x3320646e,  0x79622d32,  0x6b206574},
		{0x03020100,  0x07060504,  0x0b0a0908,  0x0f0e0d0c},
		{0x13121110,  0x17161514,  0x1b1a1918,  0x1f1e1d1c},
		{0x00000001,  0x09000000,  0x4a000000,  0x00000000}
	};
	for(i=0; i<4; i++) (void)S1[i];
	ts = __builtin_ia32_rdtsc();
	ChaCha20(S1);
	ts -= __builtin_ia32_rdtsc();
	printf("ChaCha20  %lld clk\n", -ts);
	if (1)for (i=0; i<4; i++){
		uint32x4_t v = S1[i];
		printf("%08x %08x %08x %08x\n", v[0], v[1], v[2], v[3]);
	}
// ChaCha state at the end of the ChaCha20 operation
	uint32x4_t S1e[16] = {
		{0xe4e7f110,  0x15593bd1,  0x1fdd0f50,  0xc47120a3},
		{0xc7f4d1c7,  0x0368c033,  0x9aaa2204,  0x4e6cd4c3},
		{0x466482d2,  0x09aa9f07,  0x05d7c214,  0xa2028bd9},
		{0xd19c12b5,  0xb94e16de,  0xe883d0cb,  0x4e3c50a2}
	};
	if (__builtin_memcmp(S1, S1e, sizeof(S1e))==0) printf("..ok\n");
	uint32x4_t S4[16] = {
        {0x61707865,  0x3320646e,  0x79622d32,  0x6b206574},
		{0x83828180,  0x87868584,  0x8b8a8988,  0x8f8e8d8c},
		{0x93929190,  0x97969594,  0x9b9a9998,  0x9f9e9d9c},
        {0x00000000,  0x00000000,  0x03020100,  0x07060504}
	};
	ChaCha20(S4);
	uint32x4_t S4e[16] = {
        {0x8ba0d58a,  0xcc815f90,  0x27405081,  0x7194b24a},
        {0x37b633a8,  0xa50dfde3,  0xe2b8db08,  0x46a6d1fd},
        {0x7da03782,  0x9183a233,  0x148ad271,  0xb46773d1},
        {0x3cc1875a,  0x8607def1,  0xca5c3086,  0x7085eb87}
	};
	if (__builtin_memcmp(S4, S4e, sizeof(S1e))==0) printf("..ok\n");
	return 0;
}
