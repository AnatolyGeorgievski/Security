#include <stdint.h>
#include <stdio.h>
/*! представляет собой инструментарий для подготовки матриц аффинного преобразования, 
	для 
 */
/*! Единичная диагональная матрица 8x8 */
static const uint64_t E  = 0x0102040810204080ULL;
/*! Единичная анти-диагональная матрица 8x8 используется для отражения порядка бит */
static const uint64_t R  = 0x8040201008040201ULL;

/*! Единичная диагональная матрица 4x4 размещается в старших разрядах */
static const uint64_t E4 = 0x0102040800000000;
/*! Единичная анти-диагональная матрица 4x4 используется для отражения порядка бит */
static const uint64_t R4 = 0x0804020100000000;
/*! \brief Умножение числе в поле GF(2^8) с редуцированием по образующему полиному 
	\param Poly - образующий полином 8-ого порядка, старший бит должен быть выставлен. 
	Примеры полиномов 0x11B, 0x11D, 0x1C2, 0x165, 0x171, 0x1F5
 */
uint32_t gf2p8_mul(uint32_t p, uint32_t i, uint32_t Poly){
	uint32_t r=0;
	while (i) {
		if (i&1)r^=p;
		if (p&0x80){
			p=(p<<1) ^ Poly;
		} else
			p=(p<<1);
		
		i>>=1;
	}
	return r;
}
/*! \brief Транспонирование матрицы

	Более Эффективный способ транспонирования с использованием инструкции gf2p8affine
	\param m - матрица аффинных преобразовани 8x8.
 */
uint64_t m_transpose(uint64_t m)
{
	uint64_t r = 0;
	int x,y;
	for (y=0; y<8; y++){
		uint8_t row = m>>(8*(7-y));
		for (x=0; x<8; x++){
			if(row & (1<<x))
				r |= 1ULL<< ((7-x)*8+y);
		}
	}
	return r;
}
/*! Выделяет строку матрицы */
static inline uint8_t m_row(uint64_t qword, int n)
{
	return qword>>(8*(7-n));
}
/*! Выделяет колонку матрицы */
uint8_t m_column(uint64_t qword, int n)
{
	uint8_t r=0;
	uint8_t mask = 1<<n;
	int i;
	for (i=0;i<8;i++)
		if((qword>>(8*(7-i))) & mask) 
			r |= (1<<i);
	return r;
}
/*! \brief Перемножение матриц аффинного преобразования 8x8

	Более эффективный способ перемножения с использованием инструкции gf2p8affine
	\param m1 матрица m1
	\param m2 матрица m2
	\return m1*m2 - произведение матриц.
 */
uint64_t m_mul(uint64_t m1, uint64_t m2)
{
	uint64_t r=0;
	int x,y;
	for (y=0;y<8;y++)
	for (x=0;x<8;x++)
		r |= (uint64_t)__builtin_parity(m_row(m1, y) & m_column(m2, x)) << ((7-y)*8+x);
	return r;
}
/*! \brief аффинные преобразования по матрице 8x8 
	\param qword - матрица 
	\param byte - вектор из 8 бит.
	\return произведение матрицы на вектор y=A*x.
 */
uint8_t affine(uint64_t qword, uint8_t byte) {
    uint8_t res = 0;
	int i;
    for (i=0; i < 8; i++) {
        uint8_t x = m_row(qword,i) & byte;
        //uint8_t x = (qword>>((7-i)*8)) & byte;
        res |= __builtin_parity(x)<<i;
    }
//	printf("%02X => %02X\t%016llX\n", byte,res, qword);
    return res;
}
/*! \brief умножение в поле GF(2^2) */
uint32_t gf2p2_mul(uint32_t p, uint32_t i, uint32_t Poly){
	uint32_t r=0;
	if (i&1)r^=p;
	if (i&2){
		if (p&0x2){
			p=(p<<1) ^ Poly;
		} else
			p=(p<<1);
		r^=p;
	}
	return r;
}
/*! \brief поиск обатного элемента в поле GF(2^2) */
uint8_t  gf2p2_inv(uint8_t g, uint32_t P)
{
	return g^(g>>1);
}
/*! \brief умножение в поле GF(2^4) */
uint32_t gf2p4_mul(uint32_t p, uint32_t i, uint32_t Poly){
	uint32_t r=0;
	while (i) {
		if (i&1)r^=p;
		if (p&0x8){
			p=(p<<1) ^ Poly;
		} else
			p=(p<<1);
		i>>=1;
	}
	return r;
}
/*! \brief поиск обатного элемента в поле GF(2^4) */
uint8_t  gf2p4_inv(uint8_t g, uint32_t P)
{
	uint32_t p = g & 0xF;
	uint32_t r;
	uint32_t i;
	for (i=1; i<16; i++) {
		r = gf2p4_mul(p, i, P);
		if (r==1) break;
	}
	//printf ("inverse g=0x%02X inv=0x%02X poly=%X\n", g, i, P);
	return i;
}
int initialize_inv4(uint8_t inv[16], uint32_t g, uint32_t Poly)
{
	int count=0;
	uint8_t p = 1, q = 1;
	uint8_t gi = gf2p4_inv(g, Poly);
	__builtin_bzero(inv, sizeof(inv[0])*16);
	do {
		p = gf2p4_mul(p, g, Poly);
		q = gf2p4_mul(q, gi, Poly);
		inv[p] = q;
		if (++count>15) {
			break;
		}
	} while(p != 1);
	inv[0] = 0;
	return (count==15);
}
uint64_t map_b4(uint8_t b, uint32_t P2) {
	uint8_t r=b;
	uint64_t
	m  = 0x01ULL<<(8*7);
	m |= (uint64_t)r<<(8*6);
	int i;
	for (i=2; i<4; i++) {
		r = gf2p4_mul(r, b, P2);
		m |= (uint64_t)r<<(8*(7-i));
	}
	return m_transpose(m);
}
uint64_t map_ab4(uint8_t a, uint32_t P1, uint8_t b, uint32_t P2) {
	int k=1;
	uint8_t v = a, r=b;
	while (v != 0x02) {
		v = gf2p4_mul(v, a, P1);
		r = gf2p4_mul(r, b, P2);
		k++;
	}
	return map_b4(r, P2);
}
uint8_t  map_ab4_test(uint8_t g, uint32_t P1, uint8_t g2, uint32_t P2)
{
	uint64_t map, map1;
	uint64_t E4 = 0x0102040800000000;
	uint8_t inv[16];
	printf("матрица для %02X => %02X\n", P1, P2);
	while (!(initialize_inv4(inv, g, P1))) g = (g+1)&0xF;
	int count=0;
	do {
		g2++;
		while (!(initialize_inv4(inv, g2, P2)) || g==g2) g2 = (g2+1)&0xF;
		map = map_ab4(g, P1, g2, P2);
		map1= map_ab4(g2, P2, g, P1);
		if (m_mul(map1, map)== E4) {
			uint8_t a=1, v=1;
			int i;
			for (i=0;i<15; i++){
				a = gf2p4_mul(a, g, P1);
				v = gf2p4_mul(v, g2, P2);
				if (affine(map, a)!=v || affine(map1, v)!=a) {
					printf("--Fail\n");
					break;
				}
			}
			if (i==15) {
				printf("%02X=>%02X %02X %02X M =%016llX Mt =%016llX\n", P1, P2, g, g2, map, map1);
				if (map == map1 )printf("-- gold\n");
				count++;
			}
			if(count==4) break;
		}
	} while (1);
	return g2;
}


// нахождение обратного числа в поле x8+1 методом перебора
uint8_t inverse_af(uint8_t g, uint32_t P)
{
	uint32_t p = g & 0xFF;
	uint32_t r;
	uint32_t i;
	for (i=1; i<256; i++) {
		r = gf2p8_mul(p, i, P);
		if (r==1) break;
	}
	//printf ("inverse g=0x%02X inv=0x%02X poly=%X\n", g, i, P);
	return i;
}



uint8_t affine_byte(uint64_t qword, uint8_t byte) {
    uint8_t res = 0;
	int i;
    for (i=0; i < 8; i++) {
        uint8_t x = m_row(qword,i) & byte;
        //uint8_t x = (qword>>((7-i)*8)) & byte;
        res |= __builtin_parity(x)<<i;
    }
	printf("%02X => %02X\t%016llX\n", byte,res, qword);
    return res;
}
uint32_t pmul(uint32_t p, uint32_t i){
	printf("%02X x %02X = ", p,i);
	uint32_t r=0;
	while (i) {
		if (i&1)r^=p;
		p<<=1;
		i>>=1;
	}
	printf("%04X\n", r);
	return r;
}
/*! \brief последовательное наложение матриц преобразования */
uint64_t m_exp(uint64_t m, int n)
{
	uint64_t r=E;// диагональная матрица
	int i;
	for (i=0;i<n;i++)
		r = m_mul(m,r);
	return r;
}

int initialize_inv(uint8_t sbox[256], uint32_t g, uint32_t Poly)
{
	int count=0;
	uint8_t p = 1, q = 1;
	uint8_t Inv3 = inverse_af(g, Poly);
	__builtin_bzero(sbox, sizeof(sbox[0])*256);
	do {
		p = gf2p8_mul(p, g, Poly);
		q = gf2p8_mul(q, Inv3, Poly);
		sbox[p] = q;
		if (++count>255) {
			break;
		}
	} while(p != 1);
	sbox[0] = 0;
	return (count==255);
}
/*! \brief вывод на экран матрицы 8x8 */
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
/*! \brief вывод на экран матрицы 4x4 */
void m_print4(uint64_t m)
{
	int x,y;
	for (y=4; y<8; y++){
		uint8_t row = m>>(8*(y));
		for (x=4; x<8; x++){
			printf("%c",(row & (1<<(7-x)))?'1':'0');
		}
		printf(" %02X\n", row);
	}
}
// переставляет строки местами, действует так же как и __builtin_bswap64
uint64_t m_swap(uint64_t m) {
	const uint64_t R=0x8040201008040201ULL;
	return m_mul(R, m);
}
uint64_t m_rev(uint64_t m) {
	const uint64_t R=0x8040201008040201ULL;
	return m_mul(m, R);
}
/* матрица умножения на константу */
uint64_t m_mulC(uint8_t c, uint32_t Poly){
	uint64_t m = c;
	int i;
	for (i=1;i<8;i++){
		uint8_t v = gf2p8_mul(c, 1<<i, Poly);
		m = (m<<8) ^ v;
	}
	return m_transpose(m);
}
/* матрица умножения на константу */
uint64_t m_mulC_4(uint8_t c, uint32_t Poly){
	uint64_t m = c<<8;
	m^= (c&2)?(c<<1) ^ Poly: (c<<1);//gf2p2_mul(c, 2, Poly);
	return m_transpose(m<<48);
}
/* Умножение в изоморфном представлении */
uint64_t m_mulC_iso(uint8_t c, uint64_t M, uint64_t Mr){
	c = affine(M,c);
	uint64_t m = 0;
	int i;
	for (i=0;i<8;i++){
		uint8_t v = gf2p8_mul(c, affine(M,1<<i), 0x11B);
		m = (m<<8) ^ affine(Mr,v);
	}
	return m_transpose(m);
}

/*! \brief Формирует матрицу 8x8 умножение без переноса, старшая часть */
uint64_t m_clmul_hi(uint32_t P) {
	return 
  (P&0x100? E<< 0: 0)
 ^(P&0x080? E<< 8: 0)
 ^(P&0x040? E<<16: 0)
 ^(P&0x020? E<<24: 0)
 ^(P&0x010? E<<32: 0)
 ^(P&0x008? E<<40: 0)
 ^(P&0x004? E<<48: 0)
 ^(P&0x002? E<<56: 0);
}
/*! \brief Формирует матрицу 8x8 умножение без переноса, младшая часть */
uint64_t m_clmul_lo(uint32_t P) {
	return
  (P&0x01? E>> 0: 0)
 ^(P&0x02? E>> 8: 0)
 ^(P&0x04? E>>16: 0)
 ^(P&0x08? E>>24: 0)
 ^(P&0x10? E>>32: 0)
 ^(P&0x20? E>>40: 0)
 ^(P&0x40? E>>48: 0)
 ^(P&0x80? E>>56: 0);
}
	#define m_rotate(M, n) ((uint64_t)(M)<<(8*(8-n))) ^ ((uint64_t)(M)>>(8*(n)))
uint64_t m_circulant(uint8_t C, uint8_t D){
	return D
	^ (C & 0x01 ? E: 0) 
	^ (C & 0x02 ? m_rotate(E,1): 0)
	^ (C & 0x04 ? m_rotate(E,2): 0)
	^ (C & 0x08 ? m_rotate(E,3): 0)
	^ (C & 0x10 ? m_rotate(E,4): 0)
	^ (C & 0x20 ? m_rotate(E,5): 0)
	^ (C & 0x40 ? m_rotate(E,6): 0)
	^ (C & 0x80 ? m_rotate(E,7): 0);
}


/*! Список нередуцируемых полиномов 4 порядка, irreducible polynoms of order 4 */
uint8_t irp4[3] = {0x13, 0x19, 0x1F};
/*!  Список нередуцируемых полиномов 8 порядка, irreducible polynoms order 8 */
uint16_t irp[32] = {
	0x11B,0x11D,0x12B,0x12D,0x139,0x13F,0x14D,0x15F,
	0x163,0x165,0x169,0x171,0x177,0x17B,0x187,0x18B,
	0x18D,0x19F,0x1A3,0x1A9,0x1B1,0x1BD,0x1C3,0x1CF,
	0x1D7,0x1DD,0x1E7,0x1F3,0x1F5,0x1F9, 
	0x101 // не относится
};

/*! расчитывает константы баррета для выполнения редуцирования */
uint64_t barret_calc(uint64_t poly, int bits)
{
//	poly <<=8;
	uint64_t r = (uint64_t)poly;
	uint64_t n = bits;
	uint64_t v = 0;
	while (--n){
		if (r & (1ULL<<n)) {
			if (bits>n)
				r ^= poly>>(bits-n) | (1ULL<<n);
			else
				r ^= poly<<(n-bits);
			v |= 1ULL<<n;
		}
	}
	if (r) v|=1;
	return v;
}

uint64_t map_b(uint8_t b, uint32_t P2) {
	uint8_t r=b;
	uint64_t
	m  = 0x01ULL<<(8*7);
	m |= (uint64_t)r<<(8*6);
	int i;
	for (i=2; i<8; i++) {
		r = gf2p8_mul(r, b, P2);
		m |= (uint64_t)r<<(8*(7-i));
	}
	return m_transpose(m);
}

/*! Этот вариант лучше, но не годится для композитных полей 
 M = [b^7,b^6,b^5,b^4,b^3,b^2,b^1,b^0]
 
 Сначала разыскиваем такое k при котором степени (a^k)^n образуют диагональную матрицу.
 */
uint64_t map_ab_2(uint8_t a, uint32_t P1, uint8_t b, uint32_t P2, uint8_t* beta) {
	int k=1;
	uint8_t v = a, r=b;
	while (v != 0x02) {
		v = gf2p8_mul(v, a, P1);
		r = gf2p8_mul(r, b, P2);
		k++;
	}
	*beta = r;
	return map_b(r, P2);
}
uint64_t map_ab(uint8_t a, uint32_t P1, uint8_t b, uint32_t P2) {
	int k=1;
	uint8_t v = a, r=b;
	while (v != 0x02) {
		v = gf2p8_mul(v, a, P1);
		r = gf2p8_mul(r, b, P2);
		k++;
	}
// Новые {a,b} = {a^k, b^k}, такие что a^k=0x2.
//printf("a^k=%02X b^k=%02X  k=%d\n", v,r, k);
	b = r;
	uint64_t
	m  = 0x01ULL<<(8*7);
	m |= (uint64_t)r<<(8*6);
	int i;
	for (i=2; i<8; i++) {
		r = gf2p8_mul(r, b, P2);
		m |= (uint64_t)r<<(8*(7-i));
	}
	return m_transpose(m);
}
/*! \brief Алгоритм нахождения матрицы обратного преобразования из матрицы прямого.

The matrix,T−1 is obtained by placing in the i-th column the element H(2^i)
in the standard basis representation for all i. H(x) = Tx
 */
uint64_t map_ab_inv(uint64_t m, uint32_t P2)
{
	uint8_t b = affine(m, 2);
	uint8_t r = b;
	m  = 0x01ULL<<(8*7);
	m |= (uint64_t)r<<(8*6);
	int i;
	for (i=2; i<8; i++) {
		r = gf2p8_mul(r, b, P2);
		m |= (uint64_t)r<<(8*(7-i));
	}
	return m_transpose(m);
	
}
uint64_t map_ab_(uint8_t a, uint32_t P1, uint8_t b, uint32_t P2)
{
	//  найти такое k: a^k = (1<<i) {01 02 04 08 10 20 40 80}
	uint64_t m=0;
	uint8_t kk[8];
	int i;
	for(i=0;i<8;i++){
		int k=1;
		uint8_t v=1, r=1;
		while (v != (1<<(i))) {
			v = gf2p8_mul(v, a, P1);
			r = gf2p8_mul(r, b, P2);
			k++;
		}
		kk[i] = k;
//		printf(" %02X=>%02X", k, r);
		m |= (uint64_t)r<<(8*(7-i));
	}
	// матрицу надо транспонировать
	m = m_transpose(m);
//	printf("\t%02X=>%02X mt=0x%016llX\n", P1, P2, m);
//	m_print(m);
	return m;
}

/*!
Осуществляем переход из в GF(2^4) P(x) = x^2+x+lambda  Q(x) = x^4+x+1 0x13
lambda = 1100? lambda == w^14 w-примитивный элемент GF(2^4)
A = a0 + beta*a1 -- состоит из двух частей где beta^2+beta+lambda = 0
B = A^{-1} = b0+beta*b1 -- состоит из частей по 4 бита
D = a0(a0+a1)+lambda*(a1*a1) 
b0 = (a0+a1)*D^{-1}
b1 =     a1 *D^{-1}
Матрица трансформации из GF(2^8)=>GF(2^4)
1 0 1 0 0 0 0 0
1 0 1 0 1 1 0 0
1 1 0 1 0 0 1 0
0 1 1 1 0 0 0 0
1 1 0 0 0 1 1 0
0 1 0 1 0 0 1 0
0 0 0 0 1 0 1 0
1 1 0 1 1 1 0 1

The matrix,T−1 is obtained by placing in the i-th column the element H(2^i)
in the standard basis representation for all i. H(x) = Tx
 */
/*! 
D. Canright, A Very Compact S-box for AES
 */
uint8_t gf2p8_composite_inverse(uint8_t x, uint32_t Poly) {
	const uint8_t inv13[16] = {0x0,0x1,0x9,0xE,0xD,0xB,0x7,0x6,0xF,0x2,0xC,0x5,0xA,0x4,0x3,0x8};
	const uint8_t N = 0xC, P4 = Poly;
	uint8_t a1 = x>>4;
	uint8_t a0 = x&0xF;
	uint8_t D  = gf2p4_mul(a0,a0^a1, P4) 
		^ gf2p4_mul(gf2p4_mul(a1, a1, P4), N, P4); // это тоже таблица, объединить возведение в квадрат
	uint8_t d  = inv13[D];
	uint8_t b0 = gf2p4_mul(a0^a1, d, P4);
	uint8_t b1 = gf2p4_mul(a1, d, P4);
	return b1<<4 | b0;
}
/*! Инверсия в композитном поле GF((2^2)^2) */
uint8_t gf2p4_composite_inverse(uint8_t x, uint32_t Poly) {
	const uint8_t N = 0x2, P2 = 0x7;
	uint8_t a1 = x>>2;
	uint8_t a0 = x&0x3;
	uint8_t D  = gf2p2_mul(a0,a0^a1, P2) 
		^ gf2p2_mul(gf2p2_mul(a1, a1, P2), N, P2); // это тоже таблица, объединить возведение в квадрат
	uint8_t d  = gf2p2_inv(D, P2);
	uint8_t b0 = gf2p2_mul(a0^a1, d, P2);
	uint8_t b1 = gf2p2_mul(a1, d, P2);
	return b1<<2 | b0;
}
/*! Умножение в композитном поле GF((2^2)^2) */
uint8_t gf2p4_composite_mul(uint8_t a, uint8_t b, uint32_t Poly) {
	const uint8_t N=0x2, P2 = 0x7;
	uint8_t a1 = (a>>2) & 0x3, a0 =  a & 0x3;
	uint8_t b1 = (b>>2) & 0x3, b0 =  b & 0x3;

	uint8_t d  = gf2p2_mul( b0,a0, P2);
	uint8_t r1 = gf2p2_mul((a0^a1), (b0^b1), P2) ^ d;
	uint8_t r0 = gf2p2_mul(gf2p2_mul(b1,a1, P2),N,P2) ^ d;
	return (r1<<2) | r0;
}
uint64_t map_ab_composite4(uint8_t a, uint32_t P1, uint8_t b, uint32_t P2)
{	//  найти такое k: a^k = (1<<i) {01 02 04 08 10 20 40 80}
	uint64_t m=0;
	int i;
	for(i=0;i<4;i++){
		uint8_t v=1, r=1;
		while (v != (1<<(i))) {
			v = gf2p4_mul(v, a, P1);
			r = gf2p4_composite_mul(r, b, P2);
		}
		m |= (uint64_t)r<<(8*(7-i));
	}
	return m_transpose(m);
}
uint64_t map_ba_composite4(uint8_t a, uint32_t P1, uint8_t b, uint32_t P2)
{	//  найти такое k: a^k = (1<<i) {01 02 04 08 10 20 40 80}
	uint64_t m=0;
	int i;
	for(i=0;i<4;i++){
		uint8_t v=1, r=1;
		while (v != (1<<(i))) {
			v = gf2p4_composite_mul(v, a, P1);
			r = gf2p4_mul(r, b, P2);
		}
		m |= (uint64_t)r<<(8*(7-i));
	}
	return m_transpose(m);
}
// Вычисляет таблицу инверсии в композитном поле GF((2^2)^2)
int initialize_composite_inv4(uint8_t inv[16], uint8_t g, uint32_t Poly)
{
	int count=0;
	uint8_t p = 1, q = 1;
	uint8_t gi = gf2p4_composite_inverse(g, Poly);
	__builtin_bzero(inv, sizeof(inv[0])*16);
	do {
		p = gf2p4_composite_mul(p, g, Poly);
		q = gf2p4_composite_mul(q, gi, Poly);
		inv[p] = q;
		if (++count>15) {
			break;
		}
	} while(p != 1);
	inv[0] = 0;
	return (count==15);
}

/*! Умножение в композитном поле GF((2^4)^2)
можно сделать таблицу умножения на константу 0xC
 */
uint8_t gf2p8_composite_mul(uint8_t a, uint8_t b, uint32_t Poly) {
	const uint8_t N=0xC, P4 = Poly;
	uint8_t a1 = (a>>4) & 0xF, a0 =  a & 0xF;
	uint8_t b1 = (b>>4) & 0xF, b0 =  b & 0xF;

	uint8_t d  = gf2p4_mul(b0,a0, P4);
	uint8_t r1 = gf2p4_mul((a0^a1), (b0^b1), P4) ^ d;
	uint8_t r0 = gf2p4_mul(gf2p4_mul(b1,a1, P4),N,P4) ^ d;
	return (r1<<4) | r0;
}
uint64_t map_ab_composite(uint8_t a, uint32_t P1, uint8_t b, uint32_t P2)
{	//  найти такое k: a^k = (1<<i) {01 02 04 08 10 20 40 80}
	uint64_t m=0;
	int i;
	for(i=0;i<8;i++){
		uint8_t v=1, r=1;
		while (v != (1<<(i))) {
			v = gf2p8_mul(v, a, P1);
			r = gf2p8_composite_mul(r, b, P2);
		}
		m |= (uint64_t)r<<(8*(7-i));
	}
	return m_transpose(m);
}
uint64_t map_ba_composite(uint8_t a, uint32_t P1, uint8_t b, uint32_t P2)
{	//  найти такое k: a^k = (1<<i) {01 02 04 08 10 20 40 80}
	uint64_t m=0;
	int i;
	for(i=0;i<8;i++){
		uint8_t v=1, r=1;
		while (v != (1<<(i))) {
			v = gf2p8_composite_mul(v, a, P1);
			r = gf2p8_mul(r, b, P2);
		}
		m |= (uint64_t)r<<(8*(7-i));
	}
	return m_transpose(m);
}
int initialize_composite_inv(uint8_t sbox[256], uint32_t g, uint32_t Poly)
{
	int count=0;
	uint8_t p = 1, q = 1;
	uint8_t gi = gf2p8_composite_inverse(g, Poly);
	__builtin_bzero(sbox, sizeof(sbox[0])*256);
	do {
		p = gf2p8_composite_mul(p, g, Poly);
		q = gf2p8_composite_mul(q, gi, Poly);
		sbox[p] = q;
		if (++count>255) {
			break;
		}
	} while(p != 1);
	sbox[0] = 0;
	return (count==255);
}

int gf2p8_is_root(uint8_t a, uint32_t p, uint32_t Poly)
{
	uint8_t v=1, r=0;
//	uint32_t p = Poly;
	while (p) {
		if(p&1) r ^= v;
		v = gf2p8_mul(v, a, Poly);
		p>>=1;
	}
	return (r==0);
}
int gf2p4_is_root(uint8_t a, uint32_t Poly)
{
	uint8_t v=1, r=0;
	uint32_t p = Poly;
	while (p) {
		v = gf2p4_mul(v, a, Poly);
		if(p&1) r ^= v;
		p>>=1;
	}
	return (r==0);
}
int gf2p2_is_root(uint8_t a, uint32_t Poly)
{
	uint8_t v=1, r=0;
	uint32_t p = Poly;
	while (p) {
		v = gf2p2_mul(v, a, Poly);
		if(p&1) r ^= v;
		p>>=1;
	}
	return (r==0);
}

int main(){
	uint8_t x, y;
	uint64_t m;
	printf("нет действия\n");
	y = affine_byte(m=E, x=0xA5);
	printf("обратный порядок бит\n");
	y = affine_byte(m=0x8040201008040201ULL, x=0x55);
	printf("циклический сдвиг влево\n");
	y = affine_byte(m=0x8001020408102040ULL, x=0x81);
	printf("циклический сдвиг вправо\n");
	y = affine_byte(m=0x0204081020408001ULL, x=0x81);
	printf("логический сдвиг влево \n");
	y = affine_byte(m=0x0001020408102040ULL, x=0x81);
	printf("арифметический сдвиг вправо \n");
	y = affine_byte(m=0x0204081020408080ULL, x=0x81);
	printf("арифметический сдвиг вправо на два разряда\n");
	y = affine_byte(m=0x0408102040808080ULL, x=0x81);
	printf("умножение без переноса на 3 младшая часть\n");
	y = affine_byte(m=E^0x0001020408102040ULL, x=0x81);
	printf("умножение без переноса x3 mod x8+1\n");
	y = affine_byte(m=E^0x8001020408102040ULL, x=0x81);
	printf("умножение без переноса x3 mod x8+x+1\n");
	y = affine_byte(m=E^0x8081020408102040ULL, x=0x81);
	y = affine_byte(m, x=0x80);
	printf("умножение без переноса x2 mod x8+x7+x6 +x+1\n");
	y = affine_byte(m=0x808102040810A0C0ULL, x=0x81);
	y = affine_byte(m, x=0x80);
	y = affine_byte(m, x=0xA5);
	printf("умножение без переноса x2 mod x8+x7+x6 +x+1\n");
	y = affine_byte(m=E>>(8*1)
	^0x8080000000008080ULL// маска от полинома С3
	, x=0x81);
	y = affine_byte(m=E>>(8*1)
	^m_transpose(0xC3)// маска от полинома С3
	, x=0x81);
	y = affine_byte(m, x=0x80);
	y = affine_byte(m, x=0xA5);
	// более сложная операция - умножене без переноса и сдвиги -- сложение матриц
	int N=5;
	printf("логический сдвиг влево N=%d\n",N);
	y = affine_byte(m=E>>(8*N), x=0x81);
	// применил экспонирование M^N
	y = affine_byte(m=m_exp(E>>(8*1),N), x=0x81);
	printf("логический сдвиг вправо N=%d\n",N);
	y = affine_byte(m=E<<(8*N), x=0x81);
	y = affine_byte(m=m_exp(E<<(8*1),N), x=0x81);

	printf("умножене на 0x1B5\n");// проверить все числа
	y = affine_byte(m=E>>(8*0)// от младщего к старшему
	^E>>(8*2)
	^E>>(8*4)
	^E>>(8*5)
	^E>>(8*7)
	, x=0x81);
	printf("старшая часть умноженя на 0x1B5\n");
	y = affine_byte(
	m=E// от старшего к младшему x100
	^E<<(8*1)// x80
	^E<<(8*3)// x20
	^E<<(8*4)// x10
	^E<<(8*6)// x04
	, x=0x81);
pmul(x, 0x1B5);
// функция синтеза матрицы умножение без переноса на константу
// функция синтеза матрицы умножение без переноса на константу старшая часть
// функция синтеза матрицы возведение в квадрат без переноса на константу
// сложение матриц M = A+B, см выше составные операции
// произведение матриц M = A*B, последовательное применение операций
// экспонирование матриц M = A^n
// применение матрицы "сдвиг вправо -уполовинивание -редуцирование" 
// обращение матриц M = A^{-1} -- обратная операция? обратная матрица не означает обратимость, биты могут теряться.
// применение матрицы "сдвиг редуцирование" q-1 раз дает саму матрицу
	printf("XTimeNeg в поле Poly=0x11B\n");
	uint64_t
	m0=(E<<(8*1))^m_transpose((0x11BULL>>1)<<56);// маска от полинома 11B
	y = affine_byte(m_exp(m0, N), x=0x81);
	printf("XTime в поле Poly=0x11B\n");
	uint64_t m_XT_11B =
	m=(E>>(8*1))^m_transpose(0x1B);// маска от полинома 11B
	y = affine_byte(m_exp(m, N), y);
	y = affine_byte(m_mul(m, m0), y);
	printf("инверсия XT^254 = XT^{-1} в поле Poly=0x1С3\n");
	y = affine_byte(m=m_exp(m,N=254), x=0x1);
	y = affine_byte(m, x=0x2);
	y = affine_byte(m, x=0x3);
	y = affine_byte(m, x=0x4);
	y = affine_byte(m, x=0x5);
	y = affine_byte(m, x=0x6);
	y = affine_byte(m, x=0x8);
	y = affine_byte(m, x=0x10);
	y = affine_byte(m, x=0x20);
	y = affine_byte(m, x=0x40);
	y = affine_byte(m, x=0x80);
	printf("инверсия XT^254 = XT^{-1} в поле Poly=0x1С3\n");
	y = affine_byte(m=m_mul(m,N=254), x=0x1);
	y = affine_byte(m=m_exp(m,N=254), x=0x2);
	y = affine_byte(m=m_exp(m,N=254), x=0x3);
	y = affine_byte(m=m_exp(m,N=254), x=0x4);
	printf("возведение квадрат с редуцированием по 11B\n");
	// битовые маски компонент:
	y = affine_byte(m_exp(m_XT_11B,N=0), x=0x1);
	y = affine_byte(m_exp(m_XT_11B,N=2), x=0x1);
	y = affine_byte(m_exp(m_XT_11B,N=4), x=0x1);
	y = affine_byte(m_exp(m_XT_11B,N=6), x=0x1);
	y = affine_byte(m_exp(m_XT_11B,N=8), x=0x1);
	y = affine_byte(m_exp(m_XT_11B,N=10), x=0x1);
	y = affine_byte(m_exp(m_XT_11B,N=12), x=0x1);
	y = affine_byte(m_exp(m_XT_11B,N=14), x=0x1);
	printf("возведение квадрат с редуцированием по 11B\n");
	uint64_t m2;
	m2 =0x0100000000000000ULL
	  ^0x0000020000000000ULL
	  ^0x0000000004000000ULL
	  ^0x0000000000000800ULL
	  ^0x1010001010000000ULL// Poly 0x11B
	  ^0x0000202000202000ULL// Poly 0x11B*00
	  ^0x4040004000400040ULL// Poly 0x11B*00
	  ^0x0080008080000080ULL;// Poly 0x11B*00
	y = affine_byte(m2, x=0xA5);
	y = gf2p8_mul(x, x, 0x11B);
	printf("y=x^2: %02X\n", y);
	
	
	printf("линейное преобразование AES\n");
	uint64_t m_A, m_A_;
	m_A = E ^ E<<56 ^ E>>8 ^ E<<48 ^ E>>16 ^ E<<40 ^ E>>24 ^ E<<32 ^ E>>32;// 0 1 2 3 4
	m_A_ = (E<<56 ^ E>>8) ^ (E<<40 ^ E>>24) ^ (E<<16 ^ E>>48);//  1 3 6
	printf("AES A =%016llX\n", m_A);
	m_print(m_A);
printf("AES A^{-1}=%016llX\n", m_A_);
	m_print(m_A_);
	m=m_mul(m_A_, m_A);
	printf("AES A^{-1}*A=%016llX\n", m);
	m_print(m);
	printf("поиск минимального примитивного элемента поля\n");
	// примитивный элемент - это тот который может использоваться как генератор поля, т.е за 255 шагов не дает повторов
	
	uint8_t g;
	uint8_t inv[256], sbox[256];
	int i; for (i=0; i< 256; i++) inv[i]=0;

	initialize_inv(inv, 3, 0x11B);
	printf("AES S-Box:");
	for (i=0; i< 256; i++) {
		if ((i&15)==0) printf ("\n");
		printf (" 0x%02X,", affine(m_A, inv[i])^0x63);
	}
	printf ("\n");
	printf("AES InvS-Box:");
	for (i=0; i< 256; i++) {
		if ((i&15)==0) printf ("\n");
		printf (" 0x%02X,", inv[affine(m_A_, i)^0x05]);
	}
	printf ("\n");
	affine_byte(m_A_, 0x63);

	
	uint32_t g2=0x3, P2=0x11B;
	while (!initialize_inv(sbox, g2, P2)) g2--;
	printf("Pmin root, primitive g=0%02X P=%02X\n", g2,P2);
	uint32_t g1=0x3, P1=0x1f5;
	while (!(initialize_inv(sbox, g1, P1))) g1++;
	printf("Pmin root, primitive g=0%02X P=%02X\n", g1,P1);

	printf("отображение между представлениями полей GF()\n");
	uint64_t map = map_ab(g1, P1, g2, P2);
	uint64_t map1= map_ab(g2, P2, g1, P1);
    printf("map*map{-1} = %016llX\n", m_mul(map1, (map)));
/*	map(a+b) = map(a)+map(b)
	map(a*b) = map(a)*map(b)
	
	a - примитивный элемент поля A
	b - примитивный элемент поля B
	b^k = map(a^k) 
	a^k = map^{-1}(b^k)
Важное - отображений много!! 
между любыми примитивными элементами поля.
Но примитивные элементы поля не должны быть равны
	*/
	uint64_t m_sm4 = (0x62EA3C860426DE51), m_sm4_;
	uint64_t m_A1  =m_mul(E, m_mul(0xA74F9E3D7AF4E9D3, E));
	uint64_t m_A2  =m_mul(R, m_mul(0xCB972F5EBC79F2E5, R));

	m_sm4  =0x51DE2604863CEA62;  
	m_sm4_ =0x71BA0862FCB68CA2;

	g=2;
	while(!initialize_inv(inv, g, 0x1F5))g++;
	printf("SM4 S-Box:");
	for (i=0; i< 256; i++) {
		if ((i&15)==0) printf ("\n");
		printf (" 0x%02X,", affine(m_A1, inv[affine((m_A1), i)^0xD3])^0xD3);
	}
	printf ("\n");
	g=2;
	while(!initialize_inv(inv, g, 0x11B))g++;
	printf("SM4 S-Box:");
	uint8_t C3 = affine_byte(m_sm4, 0xD3);
	printf("A2 =%016llX\n", m_mul(m_A1, m_sm4_));// 
	printf("A3 =%016llX\n", m_mul(m_sm4,  m_A1));
	for (i=0; i< 256; i++) {
		if ((i&15)==0) printf ("\n");
		printf (" 0x%02X,",
			affine(m_mul(m_A1, m_sm4_), inv[affine(m_mul(m_sm4, m_A1), i)^ C3]) ^0xD3);
		//printf (" 0x%02X,", affine(m_A1, affine(m_sm4_, inv[affine(m_sm4, affine((m_A1), i)^0xD3)]))^0xD3);
	}
	printf ("\n");
uint8_t icb = inverse_af(0xCB, 0x1f5);
uint8_t id3 = inverse_af(0xD3, 0x1f5);

	printf("M_sm4=%016llX\n", m_sm4);
	m_print(m_sm4);
	printf("M_A1=%016llX\n", m_A1);
	m_print(m_A1);
	affine_byte(m_rev(0x51DE2604863CEA62), 0xCB);// CB->65
	printf("M_A2=%016llX\n", m_A2);
	m_print(m_A2);
	m = m_mul(R, m_mul(m_A2, R));// транспонирование?
	printf("R*M_A2*R=%016llX %c= m_A1\n", m, m==m_A1?'=':'!');
	m_print(m);
	printf("Tr A2=%016llX\n", m=m_transpose(m_A2));
	m_print(m);
	
	printf("M*A1=%016llX\n",m=m_mul(m_sm4, m_A1));
	m_print(m);
	m = m_mul(m_A2, m_mul(m_swap(0x71BA0862FCB68CA2), m_A_));// транспонирование?
	printf("A2*M-*A-=%016llX\n",m);
	m_print(m);
	m = m_mul((0x51DE2604863CEA62), (0x71BA0862FCB68CA2));
	printf("M*M-=%016llX\n",m);
	m_print(m);
	
	uint8_t v= 1;

	map = map_ab(2, 0x1F5, 0xD6, 0x11B);
	map1= map_ab(0xD6, 0x11B, 2, 0x1F5);
	printf("map*map{-1} = %016llX\n", m_mul(map1, map));
	map = map_ab(3, 0x1F5, 0xD7, 0x11B);
	map1= map_ab(0xD7, 0x11B, 3, 0x1F5);
	printf("map*map{-1} = %016llX\n", m_mul(map1, map));
uint8_t map_ab_test(uint8_t g, uint32_t P1, uint8_t g2, uint32_t P2)
{
	uint64_t map, map1, map2;
	uint8_t inv1[256];
	uint8_t inv2[256];
	//g=2; P1=0x1C3;
	//g2=1;P2=0x11B;
	printf("матрица для %02X => %02X\n", P1, P2);
	while (!(initialize_inv(inv1, g, P1))) g++;
	int count=0;
	do {
		g2++;
		while (!(initialize_inv(inv2, g2, P2)) || g==g2) g2++;
		uint8_t m_a, m_b;
		map = map_ab_2(g, P1, g2, P2, &m_b);
		map1= map_ab_2(g2, P2, g, P1, &m_a);
		if (m_mul(map1, map)== E) {
/*
			map2= map_ab_inv(map, P2);
			if (m_mul(map2, map)!= E) printf("FAIL matrix inversion\n");
			else printf("GOOD matrix inversion Mt =%016llX\n", map2);
			if (map2!= map1) printf("FAIL matrix inversion 1\n");
			else printf("GOOD matrix inversion 1\n");
			*/
			uint8_t a=1, v=1;
			int i;
			for (i=0;i<255; i++){
				a = gf2p8_mul(a, g, P1);
				v = gf2p8_mul(v, g2, P2);
				if (affine(map, a)!=v || affine(map1, v)!=a) {
					//printf("--Fail\n");
					break;
				}
			}
			if (i==255) {
				printf("%02X=>%02X %02X %02X M =%016llX Mt =%016llX\n", P1, P2, g, g2, map, map1);
//				printf("%02X=>%02X %02X %02X M =%016llX Mt =%016llX\n", P1, P2, m_b, m_a, map, map1);
				if (map == map1 )printf("-- gold\n");
				// дополнительный тест APA
				for (i=0; i<256; i++)
					if (affine(map, inv1[affine(map1,i)])!=inv2[i]) break;
				if(i!=256)printf("-- fail\n");
				count++;
			}
			if(count==8) break;
		}
	} while (1);
	return g2;
}
if (0){// вывод всех матриц изоморфного преобразования
	P1 = 0x11B;
	for (i=0;i<30; i++) {
		//if (P1!=irp[i]) 
		map_ab_test(2, irp[i], 1, P1);
	}
printf("матрицы гомоморфных преобразований\n");
	for (i=0;i<30; i++) {
		//if (P1!=irp[i]) 
		map_ab_test(2, irp[i], 2, irp[i]);
	}
	// 18D=>1F5 02 03 M =FFAACC88F0A0C080 Mt =FFAACC88F0A0C080
	m_print(0xFFAACC88F0A0C080);
	return 0;
}
if (0) {
	map_ab_test(2, 0x1C3, 1, 0x11B);// Streebog
	map_ab_test(2, 0x1F5, 1, 0x11B);// SM4
	map_ab_test(2, 0x165, 1, 0x11B);// BelT
	map_ab_test(2, 0x11D, 1, 0x11B);// Kalyna
	map_ab_test(2, 0x171, 1, 0x11B);// Stribog
	map_ab_test(2, 0x177, 1, 0x11B);// ??
	y = map_ab_test(2, 0x11B, 1, 0x11B);// AES
	y = map_ab_test(3, 0x11B, y, 0x11B);// AES
	y = map_ab_test(3, 0x11B, y, 0x11B);// AES
	y = map_ab_test(3, 0x11B, y, 0x11B);// AES

	y = map_ab_test(2, 0x1C3, 1, 0x1C3);// 


//	map_ab_test(2, 0x1B1, 1, 0x11B);
	v=2;
	printf("квадраты\n");
	printf("%02X", v);
	for (i=0; i<8; i++) {
		v = gf2p8_mul(v, v, 0x1C3);
		printf(" %02X", v);
	}
	printf("\n");
	printf("порядок следования бит\n");
	uint64_t m_T = 0x1122334455667788;
	m_print(m_T);
	printf("порядок отражение на входе\n");
	m_print(m_mul(m_T, R));
	printf("порядок отражение на выходе\n");
	m_print(m_mul(R, m_T));
	printf("порядок отражение транспонирование\n");
	m_print(m_mul(R, m_mul(m_T,R)));
	
	P1=0x1C3;
	P2=P1;
	//uint8_t inv[256];
	uint64_t m_1c3 = 0xA34EE6EA26B84054;
	uint64_t m_1c3_1 = 0x075E3CE41C48A21A;
	uint64_t m_1c3_1_= 0x91CA5AF8B214D89E;
	initialize_inv(inv, 2, P1);
	printf("изоморфизм %02X=>%02X\n", P1, P2); 
	x = 0xF1;
	printf("y = %02X\n", inv[x]);
	printf("y = %02X\n", affine(m_1c3, inv[affine(m_1c3, x)]));
	printf("изоморфизм %02X=>%02X\n", P1, P2); 
	printf("y = %02X\n", affine(m_1c3_1_, inv[affine(m_1c3_1, x)]));
	P2=0x11B;
	initialize_inv(inv, 3, P2);
	printf("изоморфизм %02X=>%02X\n", P1, P2); 
	uint64_t m_2 = 0xC90C4A9E5604C632;
	uint64_t m_2_= 0x195A202216CC7C46;
	printf("y = %02X\n", affine(m_2_, inv[affine(m_2, x)]));
}
static const uint8_t crc8_lut[16] = {// POLY=0x11B
	0x00, 0x1B, 0x36, 0x2D,
	0x6C, 0x77, 0x5A, 0x41,
	0xD8, 0xC3, 0xEE, 0xF5,
	0xB4, 0xAF, 0x82, 0x99
};
static const uint8_t CRC8I_Lookup4[] = {// POLY=0x11D
	0x00, 0x1D, 0x3A, 0x27,
	0x74, 0x69, 0x4E, 0x53,
	0xE8, 0xF5, 0xD2, 0xCF,
	0x9C, 0x81, 0xA6, 0xBB,
};
static const uint8_t CRC8C_Lookup4[] = {// POLY=0x1C3
	0x00, 0xC3, 0x45, 0x86,
	0x8A, 0x49, 0xCF, 0x0C,
	0xD7, 0x14, 0x92, 0x51,
	0x5D, 0x9E, 0x18, 0xDB,
};
uint8_t    CRC8_update(uint8_t crc, uint8_t val) {
	crc^= val;
	crc = (crc << 4) ^ crc8_lut[(crc&0xFF) >> 4];
	crc = (crc << 4) ^ crc8_lut[(crc&0xFF) >> 4];
	return crc & 0xFF;
}
uint8_t    CRC8C_update(uint8_t crc, uint8_t val) {
	crc^= val;
	crc = (crc << 4) ^ CRC8C_Lookup4[(crc&0xFF) >> 4];
	crc = (crc << 4) ^ CRC8C_Lookup4[(crc&0xFF) >> 4];
	return crc & 0xFF;
}
uint8_t    CRC8I_update(uint8_t crc, uint8_t val) {
	crc^= val;
	crc = (crc << 4) ^ CRC8I_Lookup4[(crc&0xFF) >> 4];
	crc = (crc << 4) ^ CRC8I_Lookup4[(crc&0xFF) >> 4];
	return crc & 0xFF;
}
	const uint64_t m_CRC_1C3 = m_exp((E>>(8*1))^m_transpose(0xC3), 8);
	const uint64_t m_CRC_11B = m_exp((E>>(8*1))^m_transpose(0x1B), 8);// маска от полинома 11B
	const uint64_t m_CRC_11D = m_exp((E>>(8*1))^m_transpose(0x1D), 8);// маска от полинома 11D
uint8_t    CRC8_affine(uint8_t crc, uint8_t val) {
	return affine_byte(m_CRC_11B, crc^val);
}
//	const uint64_t m_CRC_11D_i = m_mul(0x7BC0D4F446A078E8, m_mul(m_CRC_11B, 0x95D4EA8EEC0C2E2C));
	const uint64_t m_CRC_11D_i = m_mul(0x95D4EA8EEC0C2E2C, m_mul(m_CRC_11B, 0x7BC0D4F446A078E8));
	const uint64_t m_CRC_1C3_1i = m_mul(0xC90C4A9E5604C632, m_mul(m_CRC_1C3, 0x195A202216CC7C46));
	const uint64_t m_CRC_1C3_i  = m_mul(0x0340F81A7C8C1EBA, m_mul(m_CRC_1C3, 0x87864834BAD4025C));
	const uint64_t m_CRC_1C3_3i = m_mul(0x5BD81880DC3CDA0A, m_mul(m_CRC_1C3, 0x494212C2C6360E08));
/*

1C3=>11B 02 30 M =5D0CE430CEE6BCD0 Mt =0xC9248C8EB6BE7C4A
1C3=>11B 02 70 M =61D8CC543E9296A4 Mt =0x359C60B0663A0EDA
1C3=>11B 02 77 M =2FA2EA44FA5AD66C Mt =0x6332D8D6145ED06E
1C3=>11B 02 7A M =59A208A62EC29AF4 Mt =0x61EC0A04B4F2D01C
1C3=>11B 02 98 M =ED406082D258646E Mt =0x89F844381A0602F0
1C3=>11B 02 C1 M =5BD81880DC3CDA0A Mt =0x494212C2C6360E08
1C3=>11B 02 C9 M =0340F81A7C8C1EBA Mt =0x87864834BAD4025C
1C3=>11B 02 DC M =C90C4A9E5604C632 Mt =0x195A202216CC7C46

*/

uint8_t    CRC8_affine_iso(uint8_t crc, uint8_t val, uint64_t M, uint32_t Poly) {
	val = affine(M, val);
//	crc = affine(m_CRC_1C3, crc^val);
	crc = gf2p8_mul(affine(M,0x1B), crc^val, Poly);
	return crc;
}

printf("расчет CRC %02X=>%02X\n", P1, P2); 
	uint8_t crc;
	for (i=0, crc=0xFF; i<9; i++)
		crc = CRC8_update(crc, '1'+i);
	printf("CRC8 = %02X\n", crc);
	for (i=0, crc=0xFF; i<9; i++)
		crc = affine(m_CRC_11B, crc ^ ('1'+i));
	printf("CRC8 = %02X\n", crc);
uint64_t M[8], Mr[8];
struct {
	uint32_t poly;
	uint64_t M, Mr;
} MX[] = { 
//1C3=>11B 02 30 
{0x1C3, 0x5D0CE430CEE6BCD0, 0xC9248C8EB6BE7C4A},
//1C3=>11B 02 70 
{0x1C3, 0x61D8CC543E9296A4, 0x359C60B0663A0EDA},
//1C3=>11B 02 77 
{0x1C3, 0x2FA2EA44FA5AD66C, 0x6332D8D6145ED06E},
//1C3=>11B 02 7A 
{0x1C3, 0x59A208A62EC29AF4, 0x61EC0A04B4F2D01C},
//1C3=>11B 02 98 
{0x1C3, 0xED406082D258646E, 0x89F844381A0602F0},
//1C3=>11B 02 C1 
{0x1C3, 0x5BD81880DC3CDA0A, 0x494212C2C6360E08},
//1C3=>11B 02 C9 
{0x1C3, 0x0340F81A7C8C1EBA, 0x87864834BAD4025C},
//1C3=>11B 02 DC 
{0x1C3, 0xC90C4A9E5604C632, 0x195A202216CC7C46},
//171=>11B 02 52
{0x171, 0xB1A27CD0765CD234, 0xF5481A5CBE24D86E},
//11B=>11B 03 05 
{0x11B, 0x51D022F0946028C0, 0xA90E384A820A2AAA},
//11B=>11B 03 5F
{0x11B, 0x7102D6DA628C9E2C, 0x7102D6DA628C9E2C},
//11D=>11B 02 03
{0x11D, 0xFFAACC88F0A0C080, 0xFFAACC88F0A0C080},
};
int j;
for (j=0; j<sizeof(MX)/sizeof(MX[0]); j++) {	
	uint8_t p = affine_byte(MX[j].Mr,0x1B);
	//m = m_exp((E>>(8*1))^m_transpose(p), 8);
	
	for (i=0, crc=affine(MX[j].Mr,0xFF); i<9; i++)
		crc = CRC8_affine_iso(crc, ('1'+i), MX[j].Mr, MX[j].poly);
	printf("CRC8 i%d = %02X Poly=%02X %016llX\n", j, affine(MX[j].M, crc), MX[j].poly, m);
}
#define CRC8I_INIT 0xFD
#define CRC8I_POLY 0x1D
#define CRC8I_XOUT 0x00
#define CRC8I_CHECK 0x7E
{// матрицы изоморфного преобразования {11D, 02} =>{11B, FB}
	uint64_t M =0x57EED8E22A228202;
	uint64_t Mr=0x4F803A301CA0E8C0;

	uint8_t crc = affine_byte(M, 0xFD);// начальное значение
	uint8_t x8  = affine_byte(M, 0x1D);// преобразование 0x11D=>0x11B
	for (i=0; i<9; i++) {
		crc = gf2p8_mul(crc ^ affine(M, ('1'+i)), x8, 0x11B);
	}
	crc = affine_byte(Mr, crc);// обратное преобразование 0x11B=>0x11D
	printf("CRC8I = %02X ..%s\n", crc^CRC8I_XOUT, crc==CRC8I_XOUT^CRC8I_CHECK? "ok":"fail");
}

	for (i=0, crc=CRC8I_INIT; i<9; i++)
		crc = CRC8I_update(crc, '1'+i);
	printf("CRC8I = %02X\n", crc^CRC8I_XOUT);
	for (i=0, crc=CRC8I_INIT; i<9; i++)
		crc = affine_byte(m_CRC_11D, crc ^ ('1'+i));
	printf("CRC8I = %02X ..%s\n", crc^CRC8I_XOUT, crc==CRC8I_XOUT^CRC8I_CHECK? "ok":"fail");

	for (i=0, crc=0xFF; i<9; i++)
		crc = CRC8C_update(crc, '1'+i);
	printf("CRC8_C3 = %02X\n", crc);
	for (i=0, crc=0xFF; i<9; i++)
		crc = affine(m_CRC_1C3, crc ^ ('1'+i));
	printf("CRC8_C3 = %02X %016llX\n", crc, m_CRC_1C3);
	for (i=0, crc=0xFF; i<9; i++)
		crc = affine(m_CRC_1C3_i, crc ^ ('1'+i));
	printf("CRC8_C3 = %02X %016llX\n", crc, m_CRC_1C3_i);
uint64_t m_;

if (0) {// константы Барретт
	printf("константы Барретт'а:\n"); 
	for (i=0; i<30; i++){
		g= 0x7D;
		P1 = irp[i];
		uint32_t u = barret_calc(P1, 8);
		m = m_mulC(P1&0xFF, P1);
		uint64_t m_A5 = m_mulC(g, P1);
		uint64_t m_A5_= m_mul(m, m_clmul_hi(g)) ^ m_clmul_lo(g);
		uint64_t m_A5_1= m_mul(m_clmul_lo(P1), m_mul(m_clmul_hi(u|0x100), m_clmul_hi(g))) ^ m_clmul_lo(g);
		printf("0x%03X, 0x1%02X, %016llX, %016llX ..%s\n", P1, u, m, m_A5, (m_A5==m_A5_ && m_A5==m_A5_1)?"ok":"fail");
	}
	return 0;
}
if (0) {// циркулянты
	printf("циркулянты\n"); 	
uint64_t m_circulant_a(uint8_t C, uint8_t D){
	return D
	^ (C & 0x01 ? m_rotate(E,7): 0) 
	^ (C & 0x02 ? m_rotate(E,6): 0)
	^ (C & 0x04 ? m_rotate(E,5): 0)
	^ (C & 0x08 ? m_rotate(E,4): 0)
	^ (C & 0x10 ? m_rotate(E,3): 0)
	^ (C & 0x20 ? m_rotate(E,2): 0)
	^ (C & 0x40 ? m_rotate(E,1): 0)
	^ (C & 0x80 ? E: 0);
}
	m = m_circulant(0x4A, 0);
	m_print(m);
	m_print(m_A_);
	printf("циркулянт 0x1F\n");
	m = m_circulant(0x1F, 0);
	m_print(m);
	m_print(m_A);
int m_circulant_order(uint8_t A, uint8_t* Ar) {
	uint8_t r= A, r_;
	int i;
	for (i=1; i<8; i++){
		r_= r;
		r = gf2p8_mul(r,A, 0x101);
		if (r==1) {
			if(Ar) *Ar = r_;
			break;
		}
	}
	return i;
}
	printf("циркулянты\n"); 
	int count=0;
	for(i=1; i<=255; i+=1) {
		uint8_t r = 0;
		int order = m_circulant_order(i, &r);
		if (order<8) {
			uint64_t m, mr;
			m =m_circulant(i,0);
			mr=m_circulant(r,0);
			count++;
			printf("%02X=> %016llX, %02X=> %016llX, order=%d", i, m, r, mr, order);
			if (m_transpose(m)==mr) printf("-- transposed");
			printf("\n");
		}
	}
	printf("total: %d\n", count);
	printf("циркулянт 0x15\n"); 
	m_print(m =0x51A2458A152A54A8);//0x15
	printf("циркулянт 0x51\n"); 
	m_print(m_=0x152A54A851A2458A);//0x51
	// 2C=> 68D0A143860D1A34, 79=> 3D7AF4E9D3A74F9E
	printf("циркулянт 0x2C\n"); 
	m_print(m =0x68D0A143860D1A34);//0x15
	printf("циркулянт 0x79\n"); 
	m_print(m_=0x3D7AF4E9D3A74F9E);//0x51
	return 0;
}// циркулянты
if (0) {// стрибог
static uint8_t sbox_stribog[] = {
252, 238, 221,  17, 207, 110,  49,  22, 251, 196, 250, 218,  35, 197,   4,  77, 
233, 119, 240, 219, 147,  46, 153, 186,  23,  54, 241, 187,  20, 205,  95, 193, 
249,  24, 101,  90, 226,  92, 239,  33, 129,  28,  60,  66, 139,   1, 142,  79,
  5, 132,   2, 174, 227, 106, 143, 160,   6,  11, 237, 152, 127, 212, 211,  31, 
235,  52,  44,  81, 234, 200,  72, 171, 242,  42, 104, 162, 253,  58, 206, 204,
181, 112,  14,  86,   8,  12, 118,  18, 191, 114,  19,  71, 156,
183,  93, 135,  21, 161, 150,  41,  16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178,
177,  50, 117,  25,  61, 255,  53, 138, 126, 109,  84, 198, 128, 195, 189,  13,  87, 223,
245,  36, 169,  62, 168,  67, 201, 215, 121, 214, 246, 124,  34, 185,   3, 224,  15, 236,
222, 122, 148, 176, 188, 220, 232,  40,  80,  78,  51,  10,  74, 167, 151,  96, 115,  30, 0,
 98,  68,  26, 184,  56, 130, 100, 159,  38,  65, 173,  69,  70, 146,  39,  94,  85,  47, 140, 163,
165, 125, 105, 213, 149,  59,   7,  88, 179,  64, 134, 172,  29, 247,  48,  55, 107, 228, 136,
217, 231, 137, 225,  27, 131,  73,  76,  63, 248, 254, 141,  83, 170, 144, 202, 216, 133,
 97,  32, 113, 103, 164,  45,  43,   9,  91, 203, 155,  37, 208, 190, 229, 108,  82,  89, 166,
116, 210, 230, 244, 180, 192, 209, 102, 175, 194,  57,  75,  99, 182
};
static const uint8_t LMT[256] = {
0x01,	0x94,	0x84,	0xdd,	0x10,	0xbd,	0x27,	0x5d,	0xb8,	0x7a,	0x48,	0x6c,	0x72,	0x76,	0xa2,	0x6e,
0x94,	0xa5,	0x64,	0x0d,	0x89,	0xa2,	0x7f,	0x4b,	0x6e,	0x16,	0xc3,	0x4c,	0xe8,	0xe3,	0xd0,	0x4d,
0x20,	0x3c,	0x48,	0xf8,	0x48,	0x48,	0xc8,	0x8e,	0x2a,	0xf5,	0x02,	0xdd,	0x14,	0x30,	0x44,	0x8e,
0x85,	0x44,	0xdf,	0x52,	0x7f,	0xc6,	0x98,	0x60,	0xd4,	0x52,	0x0e,	0x65,	0x07,	0x9f,	0x86,	0xea,
0x10,	0xd1,	0xd3,	0x91,	0x91,	0xfe,	0xf3,	0x01,	0xb1,	0x78,	0x58,	0x01,	0x49,	0x6b,	0x2d,	0xa9,
0xc2,	0x8d,	0x31,	0x64,	0xec,	0xeb,	0x0f,	0x2a,	0x37,	0x99,	0x90,	0xc4,	0xf6,	0x30,	0xb8,	0xf6,
0xc0,	0xb4,	0xa6,	0xff,	0x39,	0x2f,	0x54,	0x6c,	0xaf,	0xeb,	0xe1,	0xd4,	0xd7,	0x63,	0x64,	0xbf,
0x01,	0x54,	0x30,	0x7b,	0xef,	0x84,	0x08,	0x09,	0xd4,	0xd5,	0xa3,	0x8d,	0xa6,	0xa1,	0xc1,	0x0a,
0xfb,	0xde,	0xe0,	0xaf,	0x10,	0xc9,	0xf6,	0x49,	0xbe,	0xe7,	0x6e,	0xa4,	0x6a,	0x2b,	0x9c,	0xf3,
0x01,	0x6f,	0x5a,	0x3d,	0xbf,	0xad,	0xee,	0xab,	0xf1,	0xc4,	0xaf,	0x02,	0xd6,	0x1c,	0x89,	0xf2,
0xc0,	0x77,	0x44,	0x94,	0x60,	0x7c,	0x12,	0x8d,	0x2e,	0x2d,	0xbc,	0xeb,	0x11,	0x43,	0x48,	0x8e,
0xc2,	0x5d,	0x97,	0xf3,	0xe9,	0x1a,	0x8d,	0xcb,	0xbb,	0x06,	0xc5,	0x20,	0x1c,	0x68,	0x90,	0x93,
0x10,	0x96,	0xca,	0xd9,	0x30,	0x68,	0x2f,	0x14,	0x1a,	0x17,	0x0c,	0xca,	0x0c,	0x70,	0xda,	0xbf,
0x85,	0x74,	0x75,	0xd0,	0x5e,	0xbe,	0xb8,	0x87,	0x4e,	0x62,	0xec,	0x6b,	0x10,	0x87,	0xc6,	0x74,
0x20,	0x2d,	0x99,	0xe9,	0x95,	0x9f,	0xd4,	0x49,	0xe6,	0xd5,	0x76,	0xf2,	0x33,	0xc8,	0x20,	0x98,
0x94,	0x84,	0xdd,	0x10,	0xbd,	0x27,	0x5d,	0xb8,	0x7a,	0x48,	0x6c,	0x72,	0x76,	0xa2,	0x6e,	0xcf,
};
	printf("S-Box Kuznyechik 0x1C3 [0x11B]=\n"); 
m = 0x5D0CE430CEE6BCD0, m_ =0xC9248C8EB6BE7C4A;
	uint8_t sbox_kuzn_11b[256]={0};
	for (i=0;i<256; i++) {
		sbox_kuzn_11b[i] = affine(m, sbox_stribog[affine(m_,i)]);
		if ((i&0xF)==0)printf("\n");
		printf("0x%02X,", sbox_kuzn_11b[i]);
	}
	printf("\n");
	printf("S-Box Stribog 0x171 [0x11B]=\n"); 
m = 0x49A24EE22C984CF0, m_ =0xFB44BAF0CC5A0A1C;
	uint8_t sbox_stribog_11b[256]={0};
	for (i=0;i<256; i++) {
		sbox_stribog_11b[i] = affine(m, sbox_stribog[affine(m_,i)]);
		if ((i&0xF)==0)printf("\n");
		printf("0x%02X,", sbox_stribog_11b[i]);
	}
	printf("\n");
	printf("LM[0x11B]=");
	uint8_t LM_iso[64] = {0};
	const uint8_t LM[8*8]={
	0x71, 0x05, 0x09, 0xB9, 0x61, 0xA2, 0x27, 0x0E,
	0x04, 0x88, 0x5B, 0xB2, 0xE4, 0x36, 0x5F, 0x65,
	0x5F, 0xCB, 0xAD, 0x0F, 0xBA, 0x2C, 0x04, 0xA5,
	0xE5, 0x01, 0x54, 0xBA, 0x0F, 0x11, 0x2A, 0x76,
	0xD4, 0x81, 0x1C, 0xFA, 0x39, 0x5E, 0x15, 0x24,
	0x05, 0x71, 0x5E, 0x66, 0x17, 0x1C, 0xD0, 0x02,
	0x2D, 0xF1, 0xE7, 0x28, 0x55, 0xA0, 0x4C, 0x9A,
	0x0E, 0x02, 0xF6, 0x8A, 0x15, 0x9D, 0x39, 0x71,
	};
	for (i=0;i<8*8; i++) {
		LM_iso[i] = affine(m, LM[i]); 
		if ((i&0x7)==0)printf("\n");
		printf("0x%02X,", LM_iso[i]);
	}	
	printf("\n");
	printf("\n LMT\n");
	for (i=0;i<256; i++) {
		uint8_t v = affine(m, LMT[i]);
		if ((i&0xF)==0)printf("\n");
		printf("0x%02hhX,", v);
	}
	printf("\n");
}
//11B=>11B 03 4C M =437CC26EA4444EE4 Mt =ED7CB01C764890E8
	printf("M=0x%016llX M_=0x%016llX\n", m,m_);
printf("Матрица умножения на константу [g, 0x11B]=\n"); 
for (g1 = 0; g1<=255; g1++) {
//	g1 = 0xA5;
	P1 = 0x1C3;
	for (i=0; i<= 255; i++) {
		m = m_mulC(g1, P1);
		if(affine(m, i)!= gf2p8_mul(i, g1, P1)) break;
	}
	if (i!=256) break;
}
	printf("0x%03X: M=0x%016llX ..%s\n", P1, m, i==256?"ok":"fail");
for (g1 = 0; g1<=255; g1++) {
//	g1 = 0xA5;
	P1 = 0x171;
	for (i=0; i<= 255; i++) {
		m = m_mulC(g1, P1);
		if(affine(m, i)!= gf2p8_mul(i, g1, P1)) break;
	}
	if (i!=256) break;
}
	printf("0x%03X: M=0x%016llX ..%s\n", P1, m, i==256?"ok":"fail");
	m_print(m);
	P1 = 0x11B, g1=0x1B;
	m = m_mulC(g1, P1);
printf("Матрица умножения на константу [%02X, 0x%03X]= 0x%016llX\n", g1, P1, m); 
	g1=0xA5; m = m_mulC(g1, P1);
printf("Матрица умножения на константу [%02X, 0x%03X]= 0x%016llX\n", g1, P1, m); 
	P1 = 0x171, g1=0x71;
	m = m_mulC(g1, P1);
printf("Матрица умножения на константу [%02X, 0x%03X]= 0x%016llX\n", g1, P1, m); 
	//171=>11B 02 0E M =49A24EE22C984CF0 Mt =FB44BAF0CC5A0A1C
	m = m_mulC_iso(g1, 0x49A24EE22C984CF0, 0xFB44BAF0CC5A0A1C);
printf("Матрица умножения на константу iso [%02X, 0x%03X]= 0x%016llX\n", g1, P1, m); 
	P1 = 0x1C3, g1=0xC3;
	m = m_mulC(g1, P1);
printf("Матрица умножения на константу [%02X, 0x%03X]= 0x%016llX\n", g1, P1, m); 
	//1C3=>11B 02 70 M =61D8CC543E9296A4 Mt =359C60B0663A0EDA	
	m = m_mulC_iso(g1, 0x61D8CC543E9296A4, 0x359C60B0663A0EDA);
printf("Матрица умножения на константу iso [%02X, 0x%03X]= 0x%016llX\n", g1, P1, m); 
printf("Матрица редуцирования [g, 0x11B]=\n"); 
	P1 = 0x11B;
	for (i=0; i<= 255; i++) {
		m = m_mulC(P1&0xFF, P1);
		if(affine(m, i)!= gf2p8_mul(i, P1&0xFF, P1)) break;
	}
	printf("M=0x%016llX ..%s\n", m, i==256?"ok":"fail");
	
	P1 = 0x11B; printf("0x%03X: M=0x%016llX\n", P1, m = m_mulC(P1&0xFF, P1));
	P1 = 0x11D; printf("0x%03X: M=0x%016llX\n", P1, m_mulC(P1&0xFF, P1));
	P1 = 0x1C3; printf("0x%03X: M=0x%016llX\n", P1, m_mulC(P1&0xFF, P1));
	P1 = 0x165; printf("0x%03X: M=0x%016llX\n", P1, m_mulC(P1&0xFF, P1));
	P1 = 0x171; printf("0x%03X: M=0x%016llX\n", P1, m_mulC(P1&0xFF, P1));
	P1 = 0x177; printf("0x%03X: M=0x%016llX\n", P1, m_mulC(P1&0xFF, P1));
	P1 = 0x1F5; printf("0x%03X: M=0x%016llX\n", P1, m_mulC(P1&0xFF, P1));
printf("Разложение линейного преобразования m=0x%016llX\n", m); 
printf("Разложение линейного преобразования hi[16]=\n"); 
	uint8_t lo[16],hi[16];
	for (i=0; i<16; i++) {
		hi[i]=affine(m, i<<4);
		printf("0x%02X,", hi[i]);
	}
	printf("\n");
printf("Разложение линейного преобразования lo[16]=\n"); 
	for (i=0; i<16; i++) {
		lo[i]=affine(m, i<<0);
		printf("0x%02X,", lo[i]);
	}
	printf("\n");
	
	for (i=0; i<255; i++) {
		if((hi[i>>4]^lo[i&0xF]) != affine(m, i)) break;
	}
	if (i==255) printf("..ok\n");

if (1) {// Композитные поля GF((2^2)^2)
	printf("Композитные поля GF(2^2^2)\n");
	m = 0x01060A0800000000;
	m_= 0x010C0E0800000000;
	m_print(m_);
	printf("m*m-=\n");

	m_print(m_mul(m, m_));

	for(i=0;i<16; i++) {
		uint8_t v = affine(m, i);
		if(affine(m_, v)!=i) printf("..fail\n");
	}

	printf("Композитные поля \n");
	m |= 0x000000001060A080;
	m_|= 0x0000000010C0E080;
	m_print(m_);
	printf("m*m-=\n");
	m_print(m_mul(m, m_));
	for(i=0;i<16; i++) {
		uint8_t v = affine(m, i<<4);
		if(affine(m_, v)!=(i<<4)) printf("..fail %02X\n", v);
	}

/*
0x13 p1(x) =x4+x+1
0x19 p2(x) =x4+x3+1
0x1F p3(x) =x4+x3+x2+x+1

полином 2й степени
0x7 p1(x) =x2+x+1

*/
/* формирует матрицу 8x8 из матрицы 2х2 */
uint64_t m_2x2(uint32_t x, int n) {
	return
	    (uint64_t)(x&0x30)<<(56- 4)
	  | (uint64_t)(x&0x03)<<(48- 0);
}
/* формирует матрицу 8x8 из матрицы 4х4 */
uint64_t m_4x4_lo(uint32_t x) {
	return
		(uint64_t)(x&0xF000)<<(56-12)
	  | (uint64_t)(x&0x0F00)<<(48- 8)
	  | (uint64_t)(x&0x00F0)<<(40- 4)
	  | (uint64_t)(x&0x000F)<<(32- 0);
}
uint64_t m_4x4_hi(uint32_t x) {
	return
    	(uint64_t)(x&0xF000)<<(16)
	  | (uint64_t)(x&0x0F00)<<(12)
	  | (uint64_t)(x&0x00F0)<<(8)
	  | (uint64_t)(x&0x000F)<<(4);
}
/* примитивные полиномы 
	x3+0 +x+1, 0xB
	x3+x2+0+1  0xD */
	g = 0x0D;
	P1 = 0x13;
void poly4(uint8_t g, uint8_t P1){
	uint8_t a = 1;
	printf("полином %02X\n", P1);
	int i;
	for (i=0;i<16; i++) {
		a = gf2p4_mul(a, g, P1);
		printf("%X,", a);
	}
	printf("\n");
}
void poly2(uint8_t g, uint8_t P1){
	uint8_t a = 1;
	printf("полином %02X\n", P1);
	int i;
	for (i=0;i<4; i++) {
		a = gf2p2_mul(a, g, P1);
		printf("%X,", a);
	}
	printf("\n");
}
	poly4(0x2, 0x13);
//	poly4(0x2, 0x19);
//	poly4(0x3, 0x1F);
	uint8_t inv13[16];
	uint8_t inv19[16];
	uint8_t inv1F[16];
	initialize_inv4(inv13, 0x2, P1=0x13);
	printf("полином %02X инверсия\n", P1);
	for (i=0;i<16; i++)	printf("%X,", inv13[i]);
	printf("\n");
	printf("полином %02X редуцирование\n", P1);
	for (i=0;i<16; i++)	printf("%X,", gf2p4_mul(P1&0xF, i, P1));
	printf("\n");
	
	initialize_inv4(inv19, 0x2, P1=0x19);
	printf("полином %02X инверсия\n", P1);
	for (i=0;i<16; i++)	printf("%X,", inv19[i]);
	printf("\n");
	printf("полином %02X редуцирование\n", P1);
	for (i=0;i<16; i++)	printf("%X,", gf2p4_mul(P1&0xF, i, P1));
	printf("\n");
	initialize_inv4(inv1F, 0x3, P1=0x1F);
	printf("полином %02X инверсия\n", P1);
	for (i=0;i<16; i++)	printf("%X,", inv1F[i]);
	printf("\n");
	printf("полином %02X редуцирование\n", P1);
	for (i=0;i<16; i++)	printf("%X,", gf2p4_mul(P1&0xF, i, P1));
	printf("\n");
	// 


#define m_rotate4(M, n) ((uint64_t)(M)<<(8*(4-n))) ^ ((uint64_t)(M)>>(8*(n)))
uint64_t m_circulant4(uint8_t C){
	return 0xFFFFFFFF00000000ULL & (
	  (C & 0x01 ? E4: 0) 
	^ (C & 0x02 ? m_rotate(E4,1): 0)
	^ (C & 0x04 ? m_rotate(E4,2): 0)
	^ (C & 0x08 ? m_rotate(E4,3): 0));
}
// Magma
uint8_t sbox16_0[16]= {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1};
uint8_t sbox16_1[16]= {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15};
// Это два алтернативный и реальный S-box для PRESENT
uint8_t sbox16_x[16]= {0x7, 0xE, 0xF, 0x0, 0xD, 0xB, 0x8, 0x1, 0x9, 0x3, 0x4, 0xC, 0x2, 0x5, 0xA, 0x6};
uint8_t sbox16_p[16]= {0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2};// PRESENT
void decompose4(const char *title, uint8_t sbox[16]) {
	uint32_t k;
	for (k=0x11111111;k<0xFFFEFFFF;k++) {
		//m = m_circulant4(k&0xF);
		//m_= m_circulant4(k>>4);
		m = m_4x4_lo(k&0xFFFF);
		m_ = m_4x4_lo(k>>16);
		if (m_mul(m, m_)!=E4) continue;
		if(0)for (i=0;i<16; i++)
			if(affine(m_, inv13[affine(m, i)]!=(sbox[i]^sbox[0]))) {
				break;
			}
		//if (m_mul(m, m_)==E4 && i==16) 
		{
			printf("%s 0x%016llX 0x%016llX\n", title, m, m_); 
		}
	}
}
if (0){// циркулянты 4 порядка
	for (i=0;i<256; i++){
		m = m_circulant4(i&0xF);
		m_= m_circulant4(i>>4);
	//	m = m_mul(m, R4);
	//	m_= m_mul(R4, m_);
		if (m_mul(m, m_)!=E4) continue;
		printf("circulant: 0x%08llX 0x%08llX\n", m>>32, m_>>32); 
		m_print4(m);
		printf("-\n");
		m_print4(m_);
	}
}

/* circulant: 0x08040209 0x09040201
inverse_affine
1001 09
0010 02
0100 04
1000 08
1 1 1 0 = 0x0E
-
affine
0001 01
0010 02
0100 04
1001 09
0 1 1 1 = 0x7

1 0 0 0 =8 
1 1 1 0 =E
1 1 0 0 =C
0 0 0 1 =1

E 6 4 1

1 0 0 0 =8
1 0 1 0 =A 
0 1 1 0 =6
0 0 0 1 =1 

C 2 6 1 
*/
	m = 0x0804020900000000;
	m_= 0x0904020100000000;
	if (m_mul(m, m_)==E4){
		printf("circulant: 0x%08llX 0x%08llX\n", m>>32, m_>>32);
		for (i=0;i<16;i++)
			printf(" %X",affine(m, affine(m_, i)^0x7)^0xE);
		printf("\n");
	}
	
//  decompose4("декомпозиция п0:", sbox16_x);
//	decompose4("декомпозиция п1:", sbox16_1);

	map_ab4_test(0x2, P1, 0x3, 0x13);
	map_ab4_test(0x2, P1, 0x2, 0x19);
	map_ab4_test(0x2, P1, 0x2, 0x1F);
	P1 = 0x13;
	map_ab4_test(0x2, P1, 0x2, 0x13);
	map_ab4_test(0x2, P1, 0x2, 0x19);
	map_ab4_test(0x2, P1, 0x2, 0x1F);

	//printf("mul %X: %X\n", 1, gf2p2_mul(c, 2, Poly)(0x1, 0x7));
	printf("mul %X: %016llX\n", 1, m_mulC_4(0x1, 0x7));
	printf("mul %X: %016llX\n", 2, m_mulC_4(0x2, 0x7));
	printf("mul %X: %016llX\n", 3, m_mulC_4(0x3, 0x7));
	poly2(0x2, 0x7);
	printf("inv %X=>%X\n", 0, gf2p2_inv(0x0, 0x7));
	printf("inv %X=>%X\n", 1, gf2p2_inv(0x1, 0x7));
	printf("inv %X=>%X\n", 2, gf2p2_inv(0x2, 0x7));
	printf("inv %X=>%X\n", 3, gf2p2_inv(0x3, 0x7));
	m = m_2x2(0x32,0);// инверсия, возведение в квадрат
	m_print(m);
	printf("inv %X=>%X\n", 0, affine(m, 0x0));
	printf("inv %X=>%X\n", 1, affine(m, 0x1));
	printf("inv %X=>%X\n", 2, affine(m, 0x2));
	printf("inv %X=>%X\n", 3, affine(m, 0x3));
	
//	m = map_b4(0x4, 0x13);
//	m_print4(m);
/* 1 1 
   0 1 -- инверсия, возведение в квадрат x^-1 = x^2
*/
}
if (0) {// композитное поле поиск инверсии
	printf("композитное поле GF((2^4)^2)\n"); 
	uint64_t m_comp[128];
	uint64_t m_aes [128];
	g1=0x00;
	for(j=0; j<128; j++) {
		g1++;
		uint8_t inv_comp[256];
		while (!initialize_composite_inv(inv_comp, g1, 0x13)) g1 = (g1+1)&0xFF;
		//printf ("%02X: %016llX\n", g1, m);
		if (1) {
			printf("генератор поля %02X\n", g1);
			for (i=0; i<256; i++) {
				if ((i&0xF)==0) printf("\n");
				printf(" %02X", inv_comp[i]);
			}
			printf("\n");
		}
	}
}
if (0) {// композитное поле изоморфизм
//	m = map_b_composite(0xBC, 0x13);
//	m_print(m);
	printf("\n");
uint8_t map_ab_comp_test(uint8_t g, uint32_t P1, uint8_t g2, uint32_t P2)
{
	uint64_t map, map1;
	uint8_t inv1[256];
	uint8_t inv2[256];
	//g=2; P1=0x1C3;
	//g2=1;P2=0x11B;
	printf("матрица для %02X => %02X\n", P1, P2);
	while (!(initialize_inv(inv1, g, P1))) g++;
	int count=0;
	do {
		g2++;
		while (!(initialize_composite_inv(inv2, g2, P2))) g2++;
		map = map_ab_composite(g, P1, g2, P2);
		map1= map_ba_composite(g2, P2, g, P1);
		if (m_mul(map1, map)== E) {
			uint8_t a=1, v=1;
			int i;
			for (i=0;i<255; i++){
				a = gf2p8_mul(a, g, P1);
				v = gf2p8_composite_mul(v, g2, P2);
				if (affine(map, a)!=v || affine(map1, v)!=a) {
					printf("--Fail\n");
					break;
				}
			}
			if (i==255) {
				printf("%02X=>%02X %02X %02X M =%016llX Mt =%016llX\n", P1, P2, g, g2, map, map1);
				if (map == map1 )printf("-- gold\n");
				count++;
			}
			if(count==8) break;
		}
	} while (1);
	return g2;
}
	map_ab_comp_test(3, 0x11B, 0xbb, 0x13);
	map_ab_comp_test(2, 0x11D, 0xbb, 0x13);
}
if (0) {// AES в композитном поле
	m = 0xA7EADA6AA20CD2A0; m_ = 0x759064448C8A560A;
	uint64_t A1 = 0xF1E3C78F1F3E7CF8;
	uint8_t inv_comp[256];
	g2=2, P2 = 0x13;
//	while (!(initialize_composite_inv(inv_comp, g2, P2))) g2++;
	printf("AES в композитном поле A*M- =%016llX\n", m_mul(A1, m_));
	uint64_t mr = m_mul(A1, m_);
	for (i=0; i<256; i++) {
		if ((i&0xF)==0) printf("\n");
	// оба способа работают
		printf(" %02X", affine(mr, gf2p8_composite_inverse(affine(m, i), P2))^0x63);
//		printf(" %02X", affine(mr, inv_comp[affine(m, i)])^0x63);
	}
	printf("\n");
}
if (0) {// композитное поле
	printf("композитное поле Тауэр\n"); 
	m = (0xf1f0a6869e3ab4ba);	m_= (0x03349c68700cdea0);
	m = (0xf1f0a6869e3ab4ba);	m_= (0x03349c68700cdea0);
	// 0xBC -- примитивный элемент F_Tower
	m_print(m);
	printf("композитное поле Тауэр A-\n"); 
	m_print(m_);
	if (m_mul(m, m_)==E) printf("композитное поле Тауэр ..ok\n"); 
	uint8_t a=0xBC, a2= 0x5D;
//	uint8_t a=0x41, a2= 0x66, a4=0x6C;
//	uint8_t a=0x5F, a2= 0x7C;
	for (i=0x101;i<=0x1FF; i++) {
		if (gf2p8_mul(a, a, i) == a2) {
			printf("%03X ..ok\n", i);
		}
	}
}
if (0) {// нахождение корней

	printf("нахождение корней полинома 8-ого порядка\n");
	for(j=0;j<30;j++) {
		P1 = irp[j];
		if(1){
			printf("%03X:", P1);
			for(i=1; i< 256; i++)
				if (gf2p8_is_root(i, P1, P1)) printf(" %02X", i);
			printf("\n");
		} 
		if (0){// второй метод более эффективный
			printf("%03X:", P1);
			uint8_t b = P1&0xFF;
			for(i=0; i< 8; i++) {
				printf(" %02X", b);
				b = gf2p8_mul(b,b, P1);
			}
			printf("\n");
		}
		if (1){// третий метод более эффективный
			uint8_t b = P1 & 0xFF;
			printf("%03X: 02 04 10 %02X", P1, b);
			for(i=0; i< 4; i++) {
				b = gf2p8_mul(b,b, P1);
				printf(" %02X", b);
			}
			printf("\n");
		}
	}
	printf("нахождение корней полинома 4-ого порядка\n");
	for(j=0;j<3;j++) {
		P1 = irp4[j];
		if (0) {
			printf("%02X:", P1);
			for(i=1; i< 16; i++)
				if (gf2p4_is_root(i, P1)) printf(" %X", i);
			printf("\n");
		} 
		if(1) {// более эффективный метод
			uint8_t b = P1 & 0xF;
			printf("%02X: 2 4 %X %X\n", P1, b, gf2p4_mul(b,b, P1));
			
		}
	}
}
if (0) {// CLEFIA https://ru.wikipedia.org/wiki/CLEFIA
	P1 = 0x11D; // полином
	uint64_t A1 = 0x81605C6503015118;//__builtin_bswap64(0x18510103655C6081); // f
	uint64_t A2 = 0x449002302058410A;//__builtin_bswap64(0x0A41582030029044); // g
	uint8_t  C1 = 0x1E;//affine(R, 0x78);
	uint8_t  C2 = 0x69;//affine(R, 0x96);
	g1 = 2;
	uint8_t inv_11d[256];
	uint8_t inv_11b[256];
	while (!initialize_inv(inv_11d, g1, P1)) g1++;
	while (!initialize_inv(inv_11b, g1, 0x11B)) g1++;
//	uint8_t inv_comp[256];
//	while (!initialize_composite_inv(inv_comp, g2, 0x13)) g2++;
	printf("CLEFIA A1 =%016llX C1=%02X\n", A1, C1);
	m_print(A1);
	printf("CLEFIA A2 =%016llX C2=%02X\n", A2, C2);
	m_print(A2);
	printf("CLEFIA S-Box Poly=0x%03X\n", P1);
	for (i=0; i<256; i++) {
		if ((i&0xF)==0) printf("\n");
		printf(" %02X", affine(A2, inv_11d[affine(A1, i) ^ C1]) ^ C2);
	}
	printf("\n");
	printf("CLEFIA S-Box Poly=0x%03X=> 0x13\n", P1);
//11D=>13 02 5E M =B9C292428A441A20 Mt =9F547C4E5A805C0A
	uint64_t m =0xB9C292428A441A20;
	uint64_t m_=0x9F547C4E5A805C0A;
	printf("CLEFIA M*A1  =%016llX M*C1 =%02X\n", m_mul(m,A1), affine(m, C1));
	printf("CLEFIA A2*M_ =%016llX\n", m_mul(A2,m_));
	for (i=0; i<256; i++) {
		if ((i&0xF)==0) printf("\n");
		printf(" %02X", affine(m_mul(A2,m_), gf2p8_composite_inverse(affine(m_mul(m,A1), i) ^ affine(m,C1), 0x13)) ^ C2);
	}
	printf("\n");
	// 11D=>11B 02 11 
//	uint64_t m =0x5BD4D0B4F6487068;
//	uint64_t m_=0xD9B2068A4AA0AAE4;
	// 11D=>11B 02 03 M =FFAACC88F0A0C080 Mt =FFAACC88F0A0C080
	m =0xFFAACC88F0A0C080;
	m_=0xFFAACC88F0A0C080;
	m_print(m);
	printf("CLEFIA S-Box Iso Poly=0x%03X\n", P1);
	for (i=0; i<256; i++) {
		if ((i&0xF)==0) printf("\n");
		printf(" %02X", affine(m_mul(A2,m_), inv_11b[affine(m_mul(m, A1), i) ^ affine(m,C1)]) ^ C2);
	}
	printf("\n");
	printf("A2*M- =%016llX\n", m_mul(A2, m_));
	m_print(m_mul(A2, m_));
	printf("M*A1  =%016llX + %02X\n", m_mul(m, A1), affine(m,C1));
	m_print(m_mul(m, A1));
}
if (0) {// странные приложения аффинных преобразований Преобразование в код грея

uint32_t greay_encode(uint32_t g){ return g ^ (g>>1); }
	m = E ^ (E<<8);
	printf("Преобразование в код Грея %016llX\n", m);
	m_print(m);
	if (0) for (i = 0; i<256; i++){
		printf ("%02X: %02X == %02X\n", i, affine(m, i), greay_encode(i));
	}
	m_ = E ^ (E<<8) ^ (E<<16)^ (E<<24)^ (E<<32)^ (E<<40)^ (E<<48)^ (E<<56);
	printf("Преобразование из кода Грея %016llX\n", m_);
	m_print(m_);
	printf("Преобразование M*M-= %016llX\n", m_mul(m_, m));
	
	if (0) for (i = 0; i<256; i++){
		printf ("%02X: %02X == %02X\n", i, affine(m, i), greay_encode(i));
	}

}
if (0) {// странный полином GF(257) SAFER
	g1 = 45, P1 = 0x101;
	uint8_t inv_257[256];
	uint32_t p = 1;
	for (i=0; i<256; i++){
		printf(" %02X", p& 0xFF);//inv_257[i]);
		p = (p * g1) % 257;
		if ((i&0xF)==0xF) printf("\n");
	}
}
if (0) {// композитное поле; e1^2+e1+1, e2^2+e2+e1,  отображение на x4+x+1
	g2=1;
	uint8_t inv_comp4[16];
	while(!initialize_composite_inv4(inv_comp4, g2, 0x7)) g2= (g2+1)&0xF;
	printf("композитное поле; e1^2+e1+1, e2^2+e2+e1,  отображение на x4+x+1, g=%X\n", g2);
	for(i=0; i<16;i++) printf(" %X", inv_comp4[i]);
	printf("\n");
uint8_t map_ab_comp4_test(uint8_t g, uint32_t P1, uint8_t g2, uint32_t P2)
{
	uint64_t map, map1;
	uint8_t inv1[16];
	uint8_t inv2[16];
	//g=2; P1=0x1C3;
	//g2=1;P2=0x11B;
	printf("матрица для %02X => %02X\n", P1, P2);
	while (!(initialize_inv4(inv1, g, P1))) g = (g+1)&0xF;
	int count=0;
	do {
		g2++;
		while (!(initialize_composite_inv4(inv2, g2, P2))) g2 = (g2+1)&0xF;
		map = map_ab_composite4(g, P1, g2, P2);
		map1= map_ba_composite4(g2, P2, g, P1);
		if (m_mul(map1, map)== E4) {
			uint8_t a=1, v=1;
			int i;
			for (i=0;i<15; i++){
				a = gf2p4_mul(a, g, P1);
				v = gf2p4_composite_mul(v, g2, P2);
				if (affine(map, a)!=v || affine(map1, v)!=a) {
					printf("--Fail\n");
					break;
				}
			}
			if (i==15) {
				printf("%02X=>%02X %02X %02X M =%016llX Mt =%016llX\n", P1, P2, g, g2, map, map1);
				
				if (map == map1 )printf("-- gold\n");
				count++;
			}
			if(count==4) break;
		}
	} while (1);
	return g2;
}
	
	map_ab_comp4_test(2, 0x1F, 1, 0x7);
	map_ab_comp4_test(2, 0x19, 1, 0x7);
	map_ab_comp4_test(2, 0x13, 1, 0x7);
	// 13=>07 02 04 M =010C0E0800000000 Mt =01060A0800000000
	m_print4(0x010C0E0800000000); 
	printf("M-=\n");
	m_print4(0x01060A0800000000); 
	
}
if (0) {// конструирование S-Box A1(x) = ax + b and A2(x) = cx + d  S = A1*f*A2
	// For our S-boxes, we choose a = 13, b = 14 and c = 102 and d = 210. 
	uint8_t inv[256];
	uint64_t A1 = m_circulant(13,0);
	uint64_t A2 = m_circulant(102,0);
	g2=3; P2 = 0x11B;
	while (!initialize_inv(inv, g2, P2)) g2++;
	for (i=0; i<256; i++){
		printf(" %02hhX", gf2p8_mul(13, inv[gf2p8_mul(102, i, P2) ^ 210], P2)^14);
		if((i&0xF) == 0xF) printf("\n");
	}
}
if (1) {
	P1 = 0x11B;
	m = m_mulC(P1&0xFF, P1);
	m_print(m);
	printf("матрица L\n");
	m = m_clmul_lo(0x3);
	m_print(m);
	printf("матрица C\n");
	m = m_circulant(0x3,0);
	m_print(m);
	uint64_t m_L = m & 0x0103070F1F3F7FFF;
	printf("матрица L\n");
	m_print(m_L);
	uint64_t m_U = m & ~0x0103070F1F3F7FFF;
	m_print(m_U);
uint8_t gf2p8_mul_affine(uint8_t a, uint8_t b, uint32_t Poly) {
    const uint64_t mask = 0x0103070F1F3F7FFF;
	uint64_t Q = m_mulC(Poly&0xFF, Poly);
    uint64_t C = m_circulant(a,0);
    uint64_t L = C &  mask;
    uint64_t U = C & ~mask;
    return affine(L, b) ^ affine(Q, affine(U, b));
}
	uint32_t a,b;
	for (a=0; a<256; a++) 
		for (b=0; b<256; b++) {
			if (gf2p8_mul_affine(a,b, P1)!=gf2p8_mul(a,b, P1)) break;
		}
	if (a==256 && b==256) printf("..ok");
	m = m_transpose(0x0103070F1F3F7FFF);
	printf("LU транспонированная %016llX\n", m);
	m_print(m);
	m= m_mulC(0x7D, 0x11B);
	printf("MulC %016llX\n", m);// 3D468D2773E7CF9E
	m_print(m);
}
	return 0;
}