/*!
	The SM3 cryptographic hash algorithm takes input of a message m of
   length l (where l < 2^64), and after padding and iterative
   compression, creates a hash value of 256-bits long.


	https://datatracker.ietf.org/doc/html/draft-sca-cfrg-sm3-02

	GM/T 0004-2012: SM3 cryptographic hash algorithm[1]
    GB/T 32905-2016: Information security techniques—SM3 cryptographic hash algorithm[7]
    ISO/IEC 10118-3:2018—IT Security techniques—Hash-functions—Part 3: Dedicated hash-functions[3]
Internet-Draft           SM3 Cryptographic Hash             January 2018
	\sa
	https://github.com/gpg/libgcrypt/blob/master/cipher/sm3.c
 */
#include "hmac.h"
#include <stdint.h>


 /* Operations */
 /* Rotate Left 32-bit number */

 /* Functions for SM3 algorithm */
 #define FF1(X,Y,Z) ((X) ^ (Y) ^ (Z))
 /*
 x y z R 0x96
 0 0 0 0
 1 0 0 1
 0 1 0 1
 1 1 0 0
 0 0 1 1
 1 0 1 0
 0 1 1 0
 1 1 1 1
  */


 #define FF2(X,Y,Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
 #define GG1(X,Y,Z) ((X) ^ (Y) ^ (Z))
 #define GG2(X,Y,Z) (((X) & (Y)) | ((~X) & (Z)))

static inline uint32_t ROTL(uint32_t x, int n){
	return (x<<n) ^ (x>>(32-n));
}
static inline uint32_t P_0(uint32_t x){
	return x ^ ROTL(x,9) ^ ROTL(x,17);
}
static inline uint32_t P_1(uint32_t x){
	return x ^ ROTL(x,15) ^ ROTL(x,23);
}
static void ME(uint32_t* E, const uint32_t* B)
{
}
#define ROUND1(a,b,c,d,e,f,g,h, w, j)  \
do{\
	const uint32_t t1 = 0x79cc4519;\
	uint32_t ss1, ss2;\
	ss2 = ROTL(a,12);\
	ss1 = ROTL(ss2 + e + ROTL(t1,(j)&31),7);\
	ss2^= ss1;\
	d += FF1(a, b, c) + ss2 +(w[j]^w[j+4]);\
	h += GG1(e, f, g) + ss1 + w[j];\
	b  = ROTL(b,9);\
	f  = ROTL(f,19);\
	h  = P_0(h);\
} while(0)

#define ROUND2(a,b,c,d,e,f,g,h, w, j)  \
do{\
	const uint32_t t2 = 0x7a879d8a;\
	uint32_t ss1, ss2;\
	ss2 = ROTL(a,12);\
	ss1 = ROTL(ss2 + e + ROTL(t2,(j)&31),7);\
	ss2^= ss1;\
	d += FF2(a, b, c) + ss2 +(w[j]^w[j+4]);\
	h += GG2(e, f, g) + ss1 + w[j];\
	b  = ROTL(b,9);\
	f  = ROTL(f,19);\
	h  = P_0(h);\
} while(0)

static void CF(uint32_t* S, const uint32_t* w)
{
	uint32_t a, b, c, d, e, f, g, h;
	a = S[0];
	b = S[1];
	c = S[2];
	d = S[3];
	e = S[4];
	f = S[5];
	g = S[6];
	h = S[7];

	int j;
	for(j=0; j<16; j+=4) {
		ROUND1(a,b,c,d,e,f,g,h, w, j);
		ROUND1(d,a,b,c,h,e,f,g, w, j+1);
		ROUND1(c,d,a,b,g,h,e,f, w, j+2);
		ROUND1(b,c,d,a,f,g,h,e, w, j+3);
	}
	for(; j<64; j+=4) {
		ROUND2(a,b,c,d,e,f,g,h, w, j);
		ROUND2(d,a,b,c,h,e,f,g, w, j+1);
		ROUND2(c,d,a,b,g,h,e,f, w, j+2);
		ROUND2(b,c,d,a,f,g,h,e, w, j+3);
	}

	/* Update Context */
	S[0] ^= a;
	S[1] ^= b;
	S[2] ^= c;
	S[3] ^= d;
	S[4] ^= e;
	S[5] ^= f;
	S[6] ^= g;
	S[7] ^= h;
}
// TODO дописать
#if 0
MESSAGE_DIGEST(MD_SM3){
    .id=MD_SM3,
    .name = "SM3",
    .block_len = 32,
    .hash_len = 32,
    .ctx_size = sizeof(sm3_ctx),
    .init   = (void*)sm3_init,
    .update = (void*)sm3_update,
    .final  = (void*)sm3_final,
};
#endif
