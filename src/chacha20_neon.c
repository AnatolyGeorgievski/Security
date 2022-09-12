/* ChaCha20  ARM Neon implementation of ChaCha20 cipher
	[RFC 8439] ChaCha20 & Poly1305, June 2018

	Copyright (C) 2021 Anatoly Georgievskii <Anatoly.Georgievski@gmail.com>

# arm-none-eabi-gcc -mthumb -march=armv7-a+simd -mfloat-abi=hard -O3 -S -o - chacha20_neon.c
# gcc -march=native -mfpu=neon-vfpv4 -O3 -o chacha20 chacha20_neon.c chacha20_test.c
*/
#ifdef __ARM_NEON
#include <stdint.h>
#include <arm_neon.h>
void ChaCha20_neon(uint32_t *s)
{
	uint32x4x4_t q = *(uint32x4x4_t*)s;
	uint32x4_t q0 = q.val[0];
	uint32x4_t q1 = q.val[1];
	uint32x4_t q2 = q.val[2];
	uint32x4_t q3 = q.val[3];
	uint32x4_t q4;
	int i;
	for (i=0; i<10; i++){
		q0 = vaddq_u32(q0, q1);// a += b;
		q4 = veorq_u32(q3, q0);
		q3 = (uint32x4_t)vrev32q_u16((uint16x8_t)q4);
//		q3 = vshlq_n_u32(q4, 16);// d = e <<< 16;
//		q3 = vsriq_n_u32(q3,q4, 16);
		q2 = vaddq_u32(q2, q3);// c += d;
		q4 = veorq_u32(q1, q2);
		q1 = vshlq_n_u32(q4, 12);// b = e <<< 12;
		q1 = vsriq_n_u32(q1,q4, 20);
		q0 = vaddq_u32(q0, q1);// a += b;
		q4 = veorq_u32(q3, q0);
		q3 = vshlq_n_u32(q4,  8);// d = e <<< 8;
		q3 = vsriq_n_u32(q3,q4, 24);
		q2 = vaddq_u32(q2, q3);// c += d;
		q4 = veorq_u32(q1, q2);
		q1 = vshlq_n_u32(q4,  7);// b = e <<< 7;
		q1 = vsriq_n_u32(q1,q4, 25);

		q1 = vextq_u32(q1, q1, 1);
		q2 = vextq_u32(q2, q2, 2);
		q3 = vextq_u32(q3, q3, 3);

		q0 = vaddq_u32(q0, q1);// a += b;
		q4 = veorq_u32(q3, q0);
		q3 = (uint32x4_t)vrev32q_u16((uint16x8_t)q4);
//		q3 = vshlq_n_u32(q4, 16);// d = e <<< 16;
//		q3 = vsriq_n_u32(q3,q4, 16);
		q2 = vaddq_u32(q2, q3);// c += d;
		q4 = veorq_u32(q1, q2);
		q1 = vshlq_n_u32(q4, 12);// b = e <<< 12;
		q1 = vsriq_n_u32(q1,q4, 20);
		q0 = vaddq_u32(q0, q1);// a += b;
		q4 = veorq_u32(q3, q0);
		q3 = vshlq_n_u32(q4,  8);// d = e <<< 8;
		q3 = vsriq_n_u32(q3,q4, 24);
		q2 = vaddq_u32(q2, q3);// c += d;
		q4 = veorq_u32(q1, q2);
		q1 = vshlq_n_u32(q4,  7);// b = e <<< 7;
		q1 = vsriq_n_u32(q1,q4, 25);

		q1 = vextq_u32(q1, q1, 3);
		q2 = vextq_u32(q2, q2, 2);
		q3 = vextq_u32(q3, q3, 1);
	}
	q.val[0] = vaddq_u32(q.val[0], q0);
	q.val[1] = vaddq_u32(q.val[1], q1);
	q.val[2] = vaddq_u32(q.val[2], q2);
	q.val[3] = vaddq_u32(q.val[3], q3);
	*(uint32x4x4_t*)s = q;
}
#endif
