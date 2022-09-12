/* ChaCha20  SSE implementation of ChaCha20 cipher
	[RFC 8439] ChaCha20 & Poly1305, June 2018
	
	Copyright (C) 2021-2022 Anatoly Georgievskii <Anatoly.Georgievski@gmail.com>
	
	
	$ gcc -march=native -O3 -DVEC -o salsa20 salsa20.c
*/

#include <stdlib.h>
#include <stdint.h>
#define ROTL(v, n) (((v)<<(n)) ^ ((v)>>(32-(n))))
#define SHUFFLE(v, a,b,c,d) __builtin_shuffle((v), (uint32x4_t){a,b,c,d})
#define SHUFFLE2(v, w, a,b,c,d) __builtin_shuffle((v),(w), (uint32x4_t){a,b,c,d})
typedef uint32_t uint32x4_t __attribute__((__vector_size__(16)));

static inline 
void transpose_4x4 (uint32x4_t *r, uint32x4_t *s)
{
#if 1
    uint32x4_t x0 = SHUFFLE2 (s[0], s[1], 0, 1, 4, 5); // 0 1 4 5
    uint32x4_t x1 = SHUFFLE2 (s[0], s[1], 2, 3, 6, 7); // 2 3 6 7
    uint32x4_t x2 = SHUFFLE2 (s[2], s[3], 0, 1, 4, 5); // 8 9 12 13
    uint32x4_t x3 = SHUFFLE2 (s[2], s[3], 2, 3, 6, 7); // 10 11 14 15
    r[0] = SHUFFLE2 (x0, x2, 0, 2, 4, 6);// 0 4  8 12
    r[1] = SHUFFLE2 (x0, x2, 1, 3, 5, 7);// 1 5  9 13
    r[2] = SHUFFLE2 (x1, x3, 0, 2, 4, 6);// 2 6 10 14
    r[3] = SHUFFLE2 (x1, x3, 1, 3, 5, 7);// 3 7 11 15
#else	
	uint32x4_t x0 = SHUFFLE2 (s[0], s[1], 0, 4, 2, 6);// 0  4  2  6
	uint32x4_t x1 = SHUFFLE2 (s[0], s[1], 1, 5, 3, 7);// 1  5  3  7
	uint32x4_t x2 = SHUFFLE2 (s[2], s[3], 0, 4, 2, 6);// 8 12 10 14
	uint32x4_t x3 = SHUFFLE2 (s[2], s[3], 1, 5, 3, 7);// 9 13 11 15
    r[0] = SHUFFLE2 (x0, x2, 0, 1, 4, 5);
    r[1] = SHUFFLE2 (x1, x3, 0, 1, 4, 5);
    r[2] = SHUFFLE2 (x0, x2, 2, 3, 6, 7);
    r[3] = SHUFFLE2 (x1, x3, 2, 3, 6, 7);
#endif
}
//static 
void rotate_cw_4x4(uint32x4_t *S){
	//uint32x4_t *S = (uint32x4_t *)s;
#if 0
	uint32x4_t x0 = SHUFFLE2 (S[0], S[1], 0, 5, 2, 7);// 0  4  2  6
	uint32x4_t x1 = SHUFFLE2 (S[0], S[1], 1, 6, 3, 4);// 1  5  3  7
	uint32x4_t x2 = SHUFFLE2 (S[2], S[3], 2, 7, 0, 5);// 8 12 10 14
	uint32x4_t x3 = SHUFFLE2 (S[2], S[3], 3, 4, 1, 6);// 9 13 11 15
    S[0] = SHUFFLE2 (x0, x2, 0, 1, 4, 5);
    S[1] = SHUFFLE2 (x1, x3, 0, 1, 4, 5);
    S[2] = SHUFFLE2 (x0, x2, 2, 3, 6, 7);
    S[3] = SHUFFLE2 (x1, x3, 2, 3, 6, 7);
#elif 0
	uint32x4_t s0,s1,s2,s3;
    s0 = SHUFFLE2 (S[0], S[1], 0, 1, 5, 6); // 0 1 4 5
    s1 = SHUFFLE2 (S[0], S[1], 2, 3, 7, 4); // 2 3 6 7
    s2 = SHUFFLE2 (S[2], S[3], 2, 3, 7, 4); // 8 9 12 13
    s3 = SHUFFLE2 (S[2], S[3], 0, 1, 5, 6); // 10 11 14 15
    S[0] = SHUFFLE2 (s0, s2, 0, 2, 4, 6);// 0 4  8 12
    S[1] = SHUFFLE2 (s0, s2, 7, 1, 3, 5);// 1 5  9 13
    S[2] = SHUFFLE2 (s1, s3, 4, 6, 0, 2);// 2 6 10 14
    S[3] = SHUFFLE2 (s1, s3, 3, 5, 7, 1);// 3 7 11 15
#else
	S[1] = SHUFFLE(S[1], 1, 2, 3, 0);
	S[2] = SHUFFLE(S[2], 2, 3, 0, 1);
	S[3] = SHUFFLE(S[3], 3, 0, 1, 2); 
	transpose_4x4(S, S);
	S[1] = SHUFFLE(S[1], 3, 0, 1, 2); 
	S[2] = SHUFFLE(S[2], 2, 3, 0, 1);
	S[3] = SHUFFLE(S[3], 1, 2, 3, 0);

#endif
}
//static 
void rotate_ccw_4x4(uint32x4_t *S){
	//uint32x4_t *S = (uint32x4_t *)s;
#if 0 // эта реализация использует vtrnq 
	uint32x4_t x0 = SHUFFLE2 (S[0], S[1], 0, 4, 2, 6);// 0  4  2  6
	uint32x4_t x1 = SHUFFLE2 (S[0], S[1], 1, 5, 3, 7);// 1  5  3  7
	uint32x4_t x2 = SHUFFLE2 (S[2], S[3], 0, 4, 2, 6);// 8 12 10 14
	uint32x4_t x3 = SHUFFLE2 (S[2], S[3], 1, 5, 3, 7);// 9 13 11 15
    S[0] = SHUFFLE2 (x0, x2, 0, 1, 4, 5);
    S[1] = SHUFFLE2 (x1, x3, 5, 0, 1, 4);
    S[2] = SHUFFLE2 (x0, x2, 6, 7, 2, 3);
    S[3] = SHUFFLE2 (x1, x3, 3, 6, 7, 2);
#elif 1
	uint32x4_t x0,x1,x2,x3;
	x0 = SHUFFLE2 (S[0], S[1], 0, 1, 5, 6); // 0 1 4 5
    x1 = SHUFFLE2 (S[0], S[1], 2, 3, 7, 4); // 2 3 6 7
    x2 = SHUFFLE2 (S[2], S[3], 2, 3, 7, 4); // 8 9 12 13
    x3 = SHUFFLE2 (S[2], S[3], 0, 1, 5, 6); // 10 11 14 15
    S[0] = SHUFFLE2 (x0, x2, 0, 2, 4, 6);// 0 4  8 12
    S[1] = SHUFFLE2 (x0, x2, 7, 1, 3, 5);// 1 5  9 13
    S[2] = SHUFFLE2 (x1, x3, 4, 6, 0, 2);// 2 6 10 14
    S[3] = SHUFFLE2 (x1, x3, 3, 5, 7, 1);// 3 7 11 15
#else
	S[1] = SHUFFLE(S[1], 1, 2, 3, 0);
	S[2] = SHUFFLE(S[2], 2, 3, 0, 1);
	S[3] = SHUFFLE(S[3], 3, 0, 1, 2); 
	transpose_4x4(S, S);
	S[1] = SHUFFLE(S[1], 3, 0, 1, 2); 
	S[2] = SHUFFLE(S[2], 2, 3, 0, 1);
	S[3] = SHUFFLE(S[3], 1, 2, 3, 0);
#endif
}
static inline void _salsa20_8(uint32x4_t *S, uint32x4_t *Bx) 
{
	uint32x4_t x0,x1,x2,x3;
    x0 = S[0]^=Bx[0];
    x3 = S[1]^=Bx[1];
    x2 = S[2]^=Bx[2];
    x1 = S[3]^=Bx[3];
	int i;
	for (i=0;i<8;i+=2) {
		x1 ^= ROTL(x0 + x3, 7);
		x2 ^= ROTL(x1 + x0, 9);
		x3 ^= ROTL(x2 + x1,13);
		x0 ^= ROTL(x3 + x2,18);
		x1 = SHUFFLE(x1, 3, 0, 1, 2);
		x2 = SHUFFLE(x2, 2, 3, 0, 1);
		x3 = SHUFFLE(x3, 1, 2, 3, 0);
		x3 ^= ROTL(x0 + x1, 7);
		x2 ^= ROTL(x3 + x0, 9);
		x1 ^= ROTL(x2 + x3,13);
		x0 ^= ROTL(x1 + x2,18);
		x1 = SHUFFLE(x1, 1, 2, 3, 0);
		x2 = SHUFFLE(x2, 2, 3, 0, 1);
		x3 = SHUFFLE(x3, 3, 0, 1, 2); 
    }
	S[0] += x0;
	S[1] += x3;
	S[2] += x2;
	S[3] += x1;
}
static void salsa20_8_2(uint32x4_t X[8]) 
{
	_salsa20_8(&X[0], &X[4]);
	_salsa20_8(&X[4], &X[0]);
	
}
static inline void eor32_vect(uint32x4_t* S, uint32x4_t* B, int len){
	int i;
	for(i=0; i<len; i++)
		S[i] ^= B[i];
}
static inline void cpy32_vect(uint32x4_t* S, uint32x4_t* B, int len){
	int i;
	for(i=0; i<len; i++)
		S[i] = B[i];
}
/**
 * salsa20_8(B):
 * Apply the salsa20/8 core to the provided block.
 */
void salsa20_8(uint32_t B[16], const uint32_t Bx[16])
{
	uint32_t x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
	size_t i;

	x00=(B[ 0] ^= Bx[ 0]);
	x01=(B[ 1] ^= Bx[ 1]);
	x02=(B[ 2] ^= Bx[ 2]);
	x03=(B[ 3] ^= Bx[ 3]);
	x04=(B[ 4] ^= Bx[ 4]);
	x05=(B[ 5] ^= Bx[ 5]);
	x06=(B[ 6] ^= Bx[ 6]);
	x07=(B[ 7] ^= Bx[ 7]);
	x08=(B[ 8] ^= Bx[ 8]);
	x09=(B[ 9] ^= Bx[ 9]);
	x10=(B[10] ^= Bx[10]);
	x11=(B[11] ^= Bx[11]);
	x12=(B[12] ^= Bx[12]);
	x13=(B[13] ^= Bx[13]);
	x14=(B[14] ^= Bx[14]);
	x15=(B[15] ^= Bx[15]);
	for(i=0; i < 8; i += 2) {
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
		/* Operate on columns. */
/*	
	Вращение строк <<{0,1,2,3}
	00 01 02 03
	05 06 07 04
	10 11 08 09
	15 12 13 14
	Транспонирование матрицы
	00 05 10 15 
	01 06 11 12 
	02 07 08 13
	03 04 09 14
	Вращение строк >>{0,1,2,3}
	00 05 10 15 
	12 01 06 11
	08 13 02 07
	04 09 14 03 */
		x04 ^= R(x00+x12, 7);	x09 ^= R(x05+x01, 7);	x14 ^= R(x10+x06, 7);	x03 ^= R(x15+x11, 7);
		x08 ^= R(x04+x00, 9);	x13 ^= R(x09+x05, 9);	x02 ^= R(x14+x10, 9);	x07 ^= R(x03+x15, 9);
		x12 ^= R(x08+x04,13);	x01 ^= R(x13+x09,13);	x06 ^= R(x02+x14,13);	x11 ^= R(x07+x03,13);
		x00 ^= R(x12+x08,18);	x05 ^= R(x01+x13,18);	x10 ^= R(x06+x02,18);	x15 ^= R(x11+x07,18);

		/* Operate on rows. */
/*	Вращене строк <<{0,1,2,3}
	Transpose 
	00 05 10 15 
	01 06 11 12 >>>3
	02 07 08 13 >>>2
	03 04 09 14 >>>1 */

		x01 ^= R(x00+x03, 7);	x06 ^= R(x05+x04, 7);	x11 ^= R(x10+x09, 7);	x12 ^= R(x15+x14, 7);
		x02 ^= R(x01+x00, 9);	x07 ^= R(x06+x05, 9);	x08 ^= R(x11+x10, 9);	x13 ^= R(x12+x15, 9);
		x03 ^= R(x02+x01,13);	x04 ^= R(x07+x06,13);	x09 ^= R(x08+x11,13);	x14 ^= R(x13+x12,13);
		x00 ^= R(x03+x02,18);	x05 ^= R(x04+x07,18);	x10 ^= R(x09+x08,18);	x15 ^= R(x14+x13,18);
#undef R
	}
	B[ 0] += x00;
	B[ 1] += x01;
	B[ 2] += x02;
	B[ 3] += x03;
	B[ 4] += x04;
	B[ 5] += x05;
	B[ 6] += x06;
	B[ 7] += x07;
	B[ 8] += x08;
	B[ 9] += x09;
	B[10] += x10;
	B[11] += x11;
	B[12] += x12;
	B[13] += x13;
	B[14] += x14;
	B[15] += x15;
}
#include <stdio.h>
int main() 
{
	uint64_t ts;

	int i;
	uint32_t V[1024*32];
	uint32x4_t Bx[4] = {
		{0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57},
		{0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11},
		{0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36},
		{0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1},
	};
	uint32x4_t S2[4] = {
		{0x00000001, 0x00000000, 0x00000000, 0x00000000},
		{0x00000000, 0x00000000, 0x00000000, 0x00000000},
		{0x00000000, 0x00000000, 0x00000000, 0x00000000},
		{0x00000000, 0x00000000, 0x00000000, 0x00000000},
	};
#ifdef VEC
	rotate_cw_4x4(S2);
	rotate_cw_4x4(Bx);
	_salsa20_8(S2,Bx);
	rotate_ccw_4x4(S2);
	rotate_ccw_4x4(Bx);
#else
	salsa20_8((uint32_t*)S2,(uint32_t*)Bx);
#endif
	if (1) for (i=0; i<4; i++){
		uint32x4_t v = S2[i];
		printf("%08x %08x %08x %08x\n", v[0], v[1], v[2], v[3]);
	}

	uint32x4_t X[8] = {
		{0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57},
		{0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11},
		{0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36},
		{0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36},
		{0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1},
		{0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11},
		{0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57},
		{0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1},
	};
	ts = __builtin_ia32_rdtsc();
#ifdef VEC
	rotate_cw_4x4(&X[0]);
	rotate_cw_4x4(&X[4]);
	for (i=0; i<1024; i++){
		cpy32_vect((uint32x4_t*)&V[i * 32], X, 8);
		salsa20_8_2(X);
	}	
	for (i=0; i<1024; i++){
		int j = X[4][0] & 1023; 
		eor32_vect(X, (uint32x4_t*)&V[j * 32],8);
		salsa20_8_2(X);
	}	
	rotate_ccw_4x4(&X[0]);
	rotate_ccw_4x4(&X[4]);
#else
	for (i=0; i<1024; i++){
		cpy32_vect((uint32x4_t*)&V[i * 32], X, 8);
		salsa20_8((uint32_t*)&X[0],(uint32_t*)&X[4]);
		salsa20_8((uint32_t*)&X[4],(uint32_t*)&X[0]);
	}	
	for (i=0; i<1024; i++){
		int j = X[4][0] & 1023; 
		eor32_vect(X, (uint32x4_t*)&V[j * 32],8);
		salsa20_8((uint32_t*)&X[0],(uint32_t*)&X[4]);
		salsa20_8((uint32_t*)&X[4],(uint32_t*)&X[0]);
	}	
#endif
	ts -= __builtin_ia32_rdtsc();
	printf("Salsa20  %lld clk\n", -ts);


	if (1) for (i=0; i<4; i++){
		uint32x4_t v = X[i];
		printf("%08x %08x %08x %08x\n", v[0], v[1], v[2], v[3]);
	}

}
