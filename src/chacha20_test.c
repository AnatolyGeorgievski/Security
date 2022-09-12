/* ChaCha20 test
	[RFC 8439] ChaCha20 & Poly1305, June 2018
	
	Copyright (C) 2021 Anatoly Georgievskii <Anatoly.Georgievski@gmail.com>
*/

#include <stdint.h>
#include <stdio.h>
#ifdef __ARM_NEON
#include <arm_neon.h>
void ChaCha20_neon(uint32_t *s);
#define ChaCha20 ChaCha20_neon
#endif

int main() 
{
	uint64_t ts;

	int i;
#if 0
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
#endif
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

	//ChaCha20_((uint32_t*)S3);
	uint32x4_t S[16] = {
		{0x61707865,  0x3320646e,  0x79622d32,  0x6b206574},
		{0x03020100,  0x07060504,  0x0b0a0908,  0x0f0e0d0c},
		{0x13121110,  0x17161514,  0x1b1a1918,  0x1f1e1d1c},
		{0x00000001,  0x09000000,  0x4a000000,  0x00000000}
	};
	if(1)for (i=0; i<4; i++){
		uint32x4_t v = S[i];
		printf("%08x %08x %08x %08x\n", v[0], v[1], v[2], v[3]);
	}
	for(i=0; i<4; i++) (void)S[i];
//	ts = __builtin_ia32_rdtsc();
	ChaCha20((uint32_t*)S);
//	ts -= __builtin_ia32_rdtsc();
//	printf("ChaCha20_ %lld clk\n", -ts);
	if(1)for (i=0; i<4; i++){
		uint32x4_t v = S[i];
		printf("%08x %08x %08x %08x\n", v[0], v[1], v[2], v[3]);
	}
#endif
	//ChaCha20(S3);
	uint32x4_t S1[] = {
		{0x61707865,  0x3320646e,  0x79622d32,  0x6b206574},
		{0x03020100,  0x07060504,  0x0b0a0908,  0x0f0e0d0c},
		{0x13121110,  0x17161514,  0x1b1a1918,  0x1f1e1d1c},
		{0x00000001,  0x09000000,  0x4a000000,  0x00000000}
	};
	for(i=0; i<4; i++) (void)S1[i];
	//ts = __builtin_ia32_rdtsc();
	ChaCha20((uint32_t*)S1);
	//ts -= __builtin_ia32_rdtsc();
	//printf("ChaCha20  %lld clk\n", -ts);
	if (1)for (i=0; i<4; i++){
		uint32x4_t v = S1[i];
		printf("%08x %08x %08x %08x\n", v[0], v[1], v[2], v[3]);
	}
// ChaCha state at the end of the ChaCha20 operation
	uint32x4_t S1e[] = {
		{0xe4e7f110,  0x15593bd1,  0x1fdd0f50,  0xc47120a3},
		{0xc7f4d1c7,  0x0368c033,  0x9aaa2204,  0x4e6cd4c3},
		{0x466482d2,  0x09aa9f07,  0x05d7c214,  0xa2028bd9},
		{0xd19c12b5,  0xb94e16de,  0xe883d0cb,  0x4e3c50a2}
	};
	if (__builtin_memcmp(S1, S1e, sizeof(S1e))==0) printf("..ok\n");
	uint32x4_t S4[] = {
        {0x61707865,  0x3320646e,  0x79622d32,  0x6b206574},
		{0x83828180,  0x87868584,  0x8b8a8988,  0x8f8e8d8c},
		{0x93929190,  0x97969594,  0x9b9a9998,  0x9f9e9d9c},
        {0x00000000,  0x00000000,  0x03020100,  0x07060504}
	};
	ChaCha20((uint32_t*)S4);
	uint32x4_t S4e[] = {
        {0x8ba0d58a,  0xcc815f90,  0x27405081,  0x7194b24a},
        {0x37b633a8,  0xa50dfde3,  0xe2b8db08,  0x46a6d1fd},
        {0x7da03782,  0x9183a233,  0x148ad271,  0xb46773d1},
        {0x3cc1875a,  0x8607def1,  0xca5c3086,  0x7085eb87}
	};
	if (__builtin_memcmp(S4, S4e, sizeof(S1e))==0) printf("..ok\n");
	return 0;
}
