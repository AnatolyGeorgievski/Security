//Instruction: vgf2p8affineqb ymm {k}, ymm, ymm, imm8
//CPUID Flags: GFNI + AVX512VL

//__m128i _mm_maskz_gf2p8affine_epi64_epi8 (__mmask16 k, __m128i x, __m128i A, int b)
#include <stdint.h>
#include <stdio.h>

#include <intrin.h>
static inline __m128i crc8_update(__m128i crc, uint8_t val, __m128i M) {
	__m128i v = _mm_maskz_set1_epi8(1, val);
	return _mm_gf2p8affine_epi64_epi8(v^crc, M, 0);
}

#if 0
static inline uint8_t crc8_update_iso(__m128i crc, uint8_t val, __m128i M){// матрицы изоморфного преобразования {11D, 02} =>{11B, FB}
	uint64_t M =0x57EED8E22A228202;
	uint64_t Mr=0x4F803A301CA0E8C0;
	int i, blocks = length>>4;
	for (i=0; i<blocks; i++) {
		__m128i v = _mm_loadu_epi8(val);
		v = _mm_gf2p8affine_epi64_epi8(v, M, 0);
		crc = _mm_gf2p8mul_epi64_epi8(crc, fold_x128)
			^ _mm_gf2p8mul_epi64_epi8(v, fold);
	}
	if (length & 0xF) {
		__mmask16 mask = 0xFFFF>>( -length & 0xF);
		__m128i v = _mm_maskz_loadu_epi8(mask, val);
		v = _mm_gf2p8affine_epi64_epi8(v, M, 0);
		crc = _mm_gf2p8mul_epi64_epi8(crc, fold_x128)
			^ _mm_gf2p8mul_epi64_epi8(v, fold);
	}
// выполнить горизонтальное суммирование
// обратное аффинное преобразование
	crc = _mm_gf2p8affine_epi64_epi8(crc, Mr, 0);
	return _mm_extract_epi8(crc, 0);
}
#endif

__m128i transpose_8x8 (__m128i m)
{
	const __m128i E = _mm_set1_epi64x(0x0102040810204080ULL);
	return _mm_gf2p8affine_epi64_epi8(E, m, 0);
}

#define CRC8I_INIT 0xFD
#define CRC8I_POLY 0x1D
#define CRC8I_XOUT 0x00
#define CRC8I_CHECK 0x7E
void m_print(uint64_t m)
{
	int x,y;
	for (y=0; y<8; y++){
		uint8_t row = m>>(8*(y));
		for (x=0; x<8; x++){
			printf("%c",(row & (1<<(7-x)))?'1':'0');
		}
		printf(" %02X\n", row);
	}
}
__m128i m_mul(__m128i A, __m128i B) {
	const __m128i E = _mm_set1_epi64x(0x0102040810204080);
	B = _mm_gf2p8affine_epi64_epi8(E, B, 0);
	A = _mm_gf2p8affine_epi64_epi8(A, B, 0);
	return A;
}
__m128i m_muli(__m128i A, __m128i B) {
	const __m128i E = _mm_set1_epi64x(0x0102040810204080);
	B = _mm_gf2p8affine_epi64_epi8(E, B, 0);
	A = _mm_gf2p8affineinv_epi64_epi8(A, B, 0);
	return A;
}
__m128i m_mul2(__m128i A, __m128i B) {
	const __m128i E = _mm_set1_epi64x(0x0102040810204080);
	A = _mm_gf2p8affine_epi64_epi8(E, A, 0);
	A = _mm_gf2p8affine_epi64_epi8(A, B, 0);
	return A;
}
__m128i m_mulC(uint8_t v) {
	__m128i E = _mm_set1_epi64x(0x0102040810204080ULL);
	__m128i m = _mm_gf2p8mul_epi8(E, _mm_set1_epi8(v));
	return _mm_gf2p8affine_epi64_epi8(E, m, 0);
}

__m128i m_mulC_(uint8_t a)
{
	const __m128i S = _mm_set1_epi64x(0x0807060504030201);
	const __m128i E = _mm_set1_epi64x(0x0102040810204080);
    const __m128i Q = _mm_set1_epi64x(0xB1D3A6FD4B962C58);
    const __m128i MLT = _mm_set1_epi64x(0xFFFEFCF8F0E0C080);
    __m128i v  = _mm_set1_epi8(a); // размножить аргумент
    v  = _mm_multishift_epi64_epi8(S, v); // циклические сдвиги
    return  _mm_gf2p8affine_epi64_epi8(E, v, 0)//_mm_and_si128(MLT, v), 0) 
       ^ _mm_gf2p8affine_epi64_epi8(Q^E, _mm_andnot_si128(MLT, v), 0);
}
__m128i m_mulC_bp(uint8_t a)
{
	const __m128i SU = _mm_set1_epi64x(0x0807060504030201);
//	const __m128i SL = _mm_set1_epi64x(~0xFF00010203040506);
	const __m128i SL = _mm_set1_epi64x(0x00FFFEFDFCFBFAF9);

	const __m128i E = _mm_set1_epi64x(0x0102040810204080);
    const __m128i Q = _mm_set1_epi64x(0xB1D3A6FD4B962C58);// матрица редуцирования
__asm volatile("# LLVM-MCA-BEGIN m_mulC_bp");
    __m128i v  = _mm_set1_epi64x(a); // размножить аргумент
    __m128i L  = _mm_multishift_epi64_epi8(SL, v); // циклические сдвиги
    __m128i U  = _mm_multishift_epi64_epi8(SU, v); // циклические сдвиги
    v =  _mm_gf2p8affine_epi64_epi8(E, L, 0)//_mm_and_si128(MLT, v), 0) 
       ^ _mm_gf2p8affine_epi64_epi8(Q, U, 0);
__asm volatile("# LLVM-MCA-END m_mulC_bp");
	 return v;
}
#if 0 //надо отладить!!
__m128i m_mulC_iso(uint8_t c, uint64_t Mt, uint64_t Mr) {
	const __m128i E = _mm_set1_epi64x(0x0102040810204080ULL);
	vc = _mm_gf2p8affine_epi64_epi8(_mm_set1_epi8(c), M, 0);
//	vr = _mm_gf2p8affine_epi64_epi8(E, M, 0);
	__m128i m = _mm_gf2p8mul_epi8(Mt, vc);
	__m128i m = _mm_gf2p8affine_epi64_epi8(m, Mr, 0);
	return _mm_gf2p8affine_epi64_epi8(E, m, 0);// транспонировать
}
#endif
/*! brief две константы преобразует в две матрицы умножения */
__m128i m_mulC_2(uint8_t v0, uint8_t v1) {
	__m128i E = _mm_set1_epi64x(0x0102040810204080);
	__m128i m = _mm_gf2p8mul_epi8(E, _mm_unpacklo_epi64 (_mm_set1_epi8(v0), _mm_set1_epi8(v1)));
	return _mm_gf2p8affine_epi64_epi8(E, m, 0);
}

static inline __m128i affine_lo(uint64_t m){
	const __m128i r = _mm_gf2p8affine_epi64_epi8(
		_mm_setr_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15), 
		_mm_set1_epi64x(m) ,0);
	return r;
}
static inline __m128i affine_hi(uint64_t m){
	const __m128i r = _mm_gf2p8affine_epi64_epi8(
		_mm_setr_epi8(0,1*16,2*16,3*16,4*16,5*16,6*16,7*16,8*16,9*16,10*16,11*16,12*16,13*16,14*16,15*16), 
		_mm_set1_epi64x(m) ,0);
	return r;
}
// эМуляция инструкции
__m128i affine_emu(__m128i v, __m128i lo, __m128i hi) {
//	const uint64_t m = 0xB1D3A6FD4B962C58;
//const __m128i hi = _mm_setr_epi8(0x00,0xAB,0x4D,0xE6,0x9A,0x31,0xD7,0x7C,0x2F,0x84,0x62,0xC9,0xB5,0x1E,0xF8,0x53);
//const __m128i lo = _mm_setr_epi8(0x00,0x1B,0x36,0x2D,0x6C,0x77,0x5A,0x41,0xD8,0xC3,0xEE,0xF5,0xB4,0xAF,0x82,0x99);

//	const __m128i hi = affine_hi(m);
//	const __m128i lo = affine_lo(m);
	const __m128i mask = _mm_set1_epi8(0xF);
	__m128i h = _mm_srli_epi32(_mm_andnot_si128(mask, v), 4);
	__m128i l = _mm_and_si128(mask, v);
	return _mm_shuffle_epi8(hi, h) ^ _mm_shuffle_epi8(lo, l);
}

int main()
{
	__m128i M = _mm_set1_epi64x (0x71E2B51B478E1C38);
	__m128i crc = _mm_maskz_set1_epi8(1, CRC8I_INIT);
	uint8_t data[] = "123456789";
	int i;
	for (i=0; i<9; i++){
		crc = crc8_update(crc, data[i], M);
	}
	uint8_t crc8 = _mm_extract_epi8 (crc, 0);
	printf("CRC=%02hhX ..%s\n", crc8, crc8==CRC8I_CHECK^CRC8I_XOUT?"ok":"fail");
	__m128i m = _mm_set1_epi64x(0x0123456789ABCDEF);
	m_print(_mm_extract_epi64(m, 0));
	printf("\n");
	m_print(_mm_extract_epi64(m, 1));
	printf("\n");
	m = transpose_8x8(m);
	m_print(_mm_extract_epi64(m, 0));
	printf("\n");
	m = transpose_8x8(m);
	m_print(_mm_extract_epi64(m, 0));
	printf("умножение на константу\n");
	m = m_mulC(0x1B);
	printf("M=0x%016llX\n  0x%016llX\n", _mm_extract_epi64(m, 0), _mm_extract_epi64(m, 1));
	m = m_mulC(0xA5);
	printf("M=0x%016llX\n  0x%016llX\n", _mm_extract_epi64(m, 0), _mm_extract_epi64(m, 1));
	
	
	__m128i m_T = _mm_set1_epi64x(0x1122334455667788);
	__m128i R   = _mm_set1_epi64x(0x8040201008040201);
	printf("произведение матриц T*R\n");
	m = m_mul(m_T, R);
	m_print(_mm_extract_epi64(m, 0));
	printf("произведение матриц R*T*R\n");
	m = m_mul(R, m);
	m_print(_mm_extract_epi64(m, 0));
	printf("произведение матриц R^T*T^T\n");
	__m128i m_A = _mm_set1_epi64x(0x123456789ABCDEF0);
	__m128i m_B = _mm_set1_epi64x(0x123456789ABCDEF0);
	m = (m_mul2(m_A, m_B));// affine(A^T, B) = (B*A)^T = B^T*A^T
	m_print(_mm_extract_epi64(m, 0));
	printf("произведение матриц R^T*T^T\n");
	m = transpose_8x8(m_mul(m_B, m_A));// affine(A^T, B) = (B*A)^T = A^T*B^T
	m_print(_mm_extract_epi64(m, 0));

	printf("произведение матриц Inv\n");
if(1){
	//__m128i R = _mm_set1_epi64x(0x8040201008040201);
	__m128i R = _mm_set1_epi64x(0x0804020180402010);
	__m128i E;
	E = _mm_set1_epi64x(0x0104104002082080ULL);// номера строк 1<<n интерливинг столбцов.
	E = _mm_set1_epi64x(0x0804020180402010);
/* циклический сдвиг R>>(8*n)
 24 16  8  0 56 48 40 32
 25 17  9  1 57 49 41 33
 26 18 10  2 58 50 42 34
 27 19 11  3 59 51 43 35
 28 20 12  4 60 52 44 36
 29 21 13  5 61 53 45 37
 30 22 14  6 62 54 46 38
 31 23 15  7 63 55 47 39
*/
	E = _mm_set1_epi64x(0x0102040810204080);
/* Транспонирование
  0  8 16 24 32 40 48 56
  1  9 17 25 33 41 49 57
  2 10 18 26 34 42 50 58
  3 11 19 27 35 43 51 59
  4 12 20 28 36 44 52 60
  5 13 21 29 37 45 53 61
  6 14 22 30 38 46 54 62
  7 15 23 31 39 47 55 63
 */
	E = _mm_set1_epi64x(0x04020180402010);
	__m128i m = _mm_set1_epi64x(0x1818180818081818ULL);
//	m_print(_mm_extract_epi64(m, 0));
	printf("\n");
	int8_t pos[65];
	__builtin_memset(pos, 0xFF, 65);
	__m128i M = _mm_set1_epi64x(0x0000000000004080);
//	M = _mm_set1_epi64x(0x0102040810204080);
	M = _mm_set1_epi64x(0x8040201008040201);
	M = _mm_set1_epi64x(0x8020080200000000);
	E = _mm_set1_epi64x(0x8020080240100401);// пересатновка строк
//	E = _mm_set1_epi64x(0x0102040810204080);
	E = _mm_set1_epi64x(0x00000000000000FF);
	for (i=0; i<64; i++)  {
		m = _mm_set1_epi64x(1ULL<<(i));
//		m = _mm_gf2p8affine_epi64_epi8( m, M, 0);
//		m = _mm_gf2p8affine_epi64_epi8( m, M, 0);
//		m = _mm_gf2p8affine_epi64_epi8( E, m,0);
		m = _mm_gf2p8affine_epi64_epi8( m,E,0);
//		m = _mm_gf2p8affine_epi64_epi8( m, M, 0);
		uint64_t mask = _mm_extract_epi64(m, 0);
//		mask = (mask)>>28 | (mask); 
		while (mask) {
			int idx = 63-__builtin_clzll(mask);
			if (idx>=0){
				pos[idx] = i;
				mask &= ~(1ULL<<idx);
			}
			if (mask ) printf("@%016llX (%d)\n", mask, idx);
		}
	}
	for (i=0; i<64; i++)  {
		printf(" %2d", pos[i]);
		if ((i&7)==7) printf("\n");
	}
	
	m = _mm_gf2p8affine_epi64_epi8(E, m, 0);
	m_print(_mm_extract_epi64(m, 0));
/*	E = _mm_set1_epi64x(~0x06050403020100FF);
  0  1  2  3  4  5  6  7
 63  0  1  2  3  4  5  6
 62 63  0  1  2  3  4  5
 61 62 63  0  1  2  3  4
 60 61 62 63  0  1  2  3
 59 60 61 62 63  0  1  2
 58 59 60 61 62 63  0  1
 57 58 59 60 61 62 63  0
 */
 E = _mm_set1_epi64x(0x0807060504030201);
/*
  8  7  6  5  4  3  2  1
  9  8  7  6  5  4  3  2
 10  9  8  7  6  5  4  3
 11 10  9  8  7  6  5  4
 12 11 10  9  8  7  6  5
 13 12 11 10  9  8  7  6
 14 13 12 11 10  9  8  7
 15 14 13 12 11 10  9  8
*/
E = _mm_set1_epi64x(~0xFF00010203040506);
 //E = _mm_set1_epi64x(0);
printf(" _mm_multishift_epi64_epi8\n");
__builtin_memset(pos, 0xFF, 65);
	for (i=0; i<64; i++)  {
		m = _mm_set1_epi64x(1ULL<<(i));
		m = _mm_multishift_epi64_epi8( E, m);
//		m = _mm_gf2p8affine_epi64_epi8( m, M, 0);
		uint64_t mask = _mm_extract_epi64(m, 0);
//		mask = (mask)>>28 | (mask); 
		while (mask) {
			int idx = 63-__builtin_clzll(mask);
			if (pos[idx]!=-1) printf("@%016llX (%d)\n", mask, idx);
			if (idx>=0){
				pos[idx] = i;
				mask &= ~(1ULL<<idx);
			}
		}
	}
	for (i=0; i<64; i++)  {
		printf(" %2d", pos[i^0x7]);// ^0x38
		if ((i&7)==7) printf("\n");
	}
	E  = _mm_set1_epi64x(0x0102040810204080);
	__m128i S  = _mm_set1_epi64x(0x0807060504030201);
	__m128i v;// todo сделать матрицу выделить в отдельную функцию.
	v  = _mm_set1_epi8(3); // размножить аргумент
	v  = _mm_multishift_epi64_epi8(S, v); // циклические сдвиги
	v  = _mm_gf2p8affine_epi64_epi8(E, v, 0);
	printf("циркулянт\n");
	m_print(_mm_extract_epi64(v, 0));
	
	__m128i m1 = m_mulC(0x7D);
	__m128i m2 = m_mulC_(0x7D);
	__m128i m3 = m_mulC_bp(0x7D);
	printf("m_mulC\n");
	m_print(_mm_extract_epi64(m1, 0));
	printf("m_mulC2\n");
	m_print(_mm_extract_epi64(m2, 0));
	printf("m_mulC_bp\n");
	m_print(_mm_extract_epi64(m3, 0));

}
	
	return 0;
}