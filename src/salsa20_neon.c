/* Salsa20_8  ARM Neon implementation of Salsa20 cipher for 
	[RFC 8439] ChaCha20 & Poly1305, June 2018

	Copyright (C) 2022 Anatoly Georgievskii <Anatoly.Georgievski@gmail.com>

# arm-none-eabi-gcc -mthumb -march=armv7-a+simd -mfloat-abi=hard -O3 -S -o - salsa20_neon.c
*/
#ifdef __ARM_NEON
#include <stdint.h>
#include <arm_neon.h>
static inline void _salsa20_8_neon(uint32x4_t *s, const uint32x4_t *b)
{
	uint32x4x4_t q = *(uint32x4x4_t*)s;
	uint32x4x4_t p = *(uint32x4x4_t*)b;
	q.val[0] = veorq_u32(q.val[0], p.val[0]);
	q.val[1] = veorq_u32(q.val[1], p.val[1]);
	q.val[2] = veorq_u32(q.val[2], p.val[2]);
	q.val[3] = veorq_u32(q.val[3], p.val[3]);

	uint32x4_t q0 = q.val[0];
	uint32x4_t q1 = q.val[1];
	uint32x4_t q2 = q.val[2];
	uint32x4_t q3 = q.val[3];
	uint32x4_t q4, q5;
	int i;
	for (i=0; i<8; i+=2){
		q1 = vextq_u32(q1, q1, 1);
		q2 = vextq_u32(q2, q2, 2);
		q3 = vextq_u32(q3, q3, 3);

		q4 = vaddq_u32(q0, q3);
		q5 = vshlq_n_u32(q4, 7);//  <<< 7;
		q5 = vsriq_n_u32(q5,q4, 25);
		q1 = veorq_u32(q1, q5);
		q4 = vaddq_u32(q1, q0);
		q5 = vshlq_n_u32(q4, 9);//  <<< 9;
		q5 = vsriq_n_u32(q5,q4, 23);
		q2 = veorq_u32(q2, q5);
		q4 = vaddq_u32(q2, q1);
		q5 = vshlq_n_u32(q4, 13);//  <<< 13;
		q5 = vsriq_n_u32(q5,q4, 19);
		q3 = veorq_u32(q3, q5);
		q4 = vaddq_u32(q3, q2);
		q5 = vshlq_n_u32(q4, 18);//  <<< 18;
		q5 = vsriq_n_u32(q5,q4, 14);
		q0 = veorq_u32(q0, q5);

		q3 = vextq_u32(q3, q3, 1);
		q2 = vextq_u32(q2, q2, 2);
		q1 = vextq_u32(q1, q1, 3);

		q4 = vaddq_u32(q0, q1);
		q5 = vshlq_n_u32(q4, 7);//  <<< 7;
		q5 = vsriq_n_u32(q5,q4, 25);
		q3 = veorq_u32(q3, q5);
		q4 = vaddq_u32(q3, q0);
		q5 = vshlq_n_u32(q4, 9);//  <<< 9;
		q5 = vsriq_n_u32(q5,q4, 23);
		q2 = veorq_u32(q2, q5);
		q4 = vaddq_u32(q2, q3);
		q5 = vshlq_n_u32(q4, 13);//  <<< 13;
		q5 = vsriq_n_u32(q5,q4, 19);
		q1 = veorq_u32(q1, q5);
		q4 = vaddq_u32(q1, q2);
		q5 = vshlq_n_u32(q4, 18);//  <<< 18;
		q5 = vsriq_n_u32(q5,q4, 14);
		q0 = veorq_u32(q0, q5);
	}
	q.val[0] = vaddq_u32(q.val[0], q0);
	q.val[1] = vaddq_u32(q.val[1], q3);
	q.val[2] = vaddq_u32(q.val[2], q2);
	q.val[3] = vaddq_u32(q.val[3], q1);
	*(uint32x4x4_t*)s = q;
}
void salsa20_8_2(uint32x4_t X[8]) 
{
	_salsa20_8_neon(&X[0], &X[4]);
	_salsa20_8_neon(&X[4], &X[0]);
	
}

//transpose_4x4_part1
#if 0
void _transpose_4x4_neon_u32(uint32x4_t * matrix)
{
  uint32x4_t     row0 = matrix[0];
  uint32x4_t     row1 = matrix[1];
  uint32x4_t     row2 = matrix[2];
  uint32x4_t     row3 = matrix[3];
 /*
#define transpose_4x4_part1(_q0, _q1, _q2, _q3)	\
	vtrn.32 _q0, _q1;			\
	vtrn.32 _q2, _q3;
#define transpose_4x4_part2(_q0, _q1, _q2, _q3)	\
	vswp _q0##h, _q2##l;			\
	vswp _q1##h, _q3##l;
*/
  uint32x4x2_t   row01 = vtrnq_u32(row0, row1);
  uint32x4x2_t   row23 = vtrnq_u32(row2, row3);
// vswpq 
	uint32x4x4_t r0;
  r0.val[0] = vcombine_u32(vget_low_u32(row01.val[0]), vget_low_u32(row23.val[0]));
  r0.val[1] = vcombine_u32(vget_low_u32(row01.val[1]), vget_low_u32(row23.val[1]));
  r0.val[2] = vcombine_u32(vget_high_u32(row01.val[0]), vget_high_u32(row23.val[0]));
  r0.val[3] = vcombine_u32(vget_high_u32(row01.val[1]), vget_high_u32(row23.val[1]));
  *(uint32x4x4_t*)matrix = r0;
}
#endif
#endif
