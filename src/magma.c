/*! Национальый алгоритм блочного шифрования с длиной блока 64 бит. TC26 Магма

	Copyright (c) 2015-2022 Anatoly Georgievskii <anatoly.georgievski@gmail.com>

	\see ГОСТ Р 34.12-2015 Информационная технология. КРИПТОГРАФИЧЕСКАЯ ЗАЩИТА ИНФОРМАЦИИ. Блочные шифры
	\see http://tc26.ru



Multilinear Galois Mode (MGM)
	[Р 1323565.1.026—2019] Режимы работы блочных шифров, реализующие
аутентифицированное шифрование
	https://datatracker.ietf.org/doc/html/rfc9058
	https://datatracker.ietf.org/doc/html/draft-smyshlyaev-mgm-20
Отладка
$ gcc -DTEST_MAGMA -march=native -o magma magma.c

 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

typedef struct _MagmaCtx MagmaCtx;
struct _MagmaCtx {
    uint32_t K[32];
};
/* 5.1.1 Нелинейное биективное преобразование */
static const uint8_t sbox[8][16] = {
/* π0' = */ {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
/* π1' = */ {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
/* π2' = */ {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
/* π3' = */ {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
/* π4' = */ {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
/* π5' = */ {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
/* π6' = */ {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
/* π7' = */ {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2}
};

#define ROL(x, n) (((x)<<(n))|((x)>>(32-n)))
// Bit Field Extract
#define BEXTR(x, n, len) (((x) >> (n)) & ((1 << (len))-1))
#define BFI(x, y, n, len) x = ((x) & ~(((1 << (len))-1)<<(n))) | ((y & ((1 << (len))-1))<<(n))
//static uint32_t t(uint32_t a) __attribute__((optimize("O3")));
//typedef uint8_t v4qi __attribute__((__vector_size__(4)));


//#pragma GCC optimize("O3")
/*! \brief Подстановка SBOX

    Реализация эффективно работает на архитектуре ARM, задействует команды
    UBFX -- Unsigned Bit Field Extract
    BFI  -- Bit Field Insert
*/
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
static inline uint64_t htonll(uint64_t a){
    return __builtin_bswap64(a);// LE
}
static inline uint32_t ntohl (uint32_t a){
    return __builtin_bswap32(a);// LE
}
static inline uint16_t htons (uint16_t a){
    return __builtin_bswap16(a);// LE
}
#else
static inline uint64_t htonll(uint64_t a){
    return (a);// BE
}
static inline uint32_t ntohl (uint32_t a){
    return (a);// BE
}
static inline uint16_t htons (uint16_t a){
    return (a);// BE
}
#endif
//static inline
uint32_t t(uint32_t a)
{
    register union {
        struct {
            uint32_t u0:4;
            uint32_t u1:4;
            uint32_t u2:4;
            uint32_t u3:4;
            uint32_t u4:4;
            uint32_t u5:4;
            uint32_t u6:4;
            uint32_t u7:4;
        };
        uint32_t x;
    } r;
	r.x  = a;
    r.u0 = sbox[0][r.u0];
    r.u1 = sbox[1][r.u1];
    r.u2 = sbox[2][r.u2];
    r.u3 = sbox[3][r.u3];
    r.u4 = sbox[4][r.u4];
    r.u5 = sbox[5][r.u5];
    r.u6 = sbox[6][r.u6];
    r.u7 = sbox[7][r.u7];
	return r.x;
}

static inline uint32_t t1(uint32_t a)
{
	uint32_t r=0;
	int i;
	for (i=0; i<8; i++){
		register uint32_t s = sbox[i][BEXTR(a,(i*4),4)];
		r |= s<<(i*4);
	}
	return r;
}

static uint32_t g(uint32_t k, uint32_t a)
{
	return ROL(t(k+a), 11);
}
uint64_t magma_encrypt(const uint32_t *Key, uint64_t v){
	uint32_t n1 = v, n2 = v>>32;
	const uint32_t *K=Key;
	int count = 12;
	do{
		if (K==Key) K = Key+8;
		n2 ^= g(*--K, n1);
		n1 ^= g(*--K, n2);
	} while (--count);
	count = 4;
	do{
		n2 ^= g(*K++, n1);
		n1 ^= g(*K++, n2);
	} while(--count);
	return (uint64_t)n1<<32 | n2;
}
#if 0
uint64_t magma_decrypt(const uint32_t *K, uint64_t v){
	uint32_t a0 = v, a1 = v>>32;
	int i;
	for (i=31; i>=0; i-=2){
		a1 ^= g(K[i  ], a0);
		a0 ^= g(K[i-1], a1);
	}
	return (uint64_t)a0<<32 | a1;
}
#else
uint64_t magma_decrypt(const uint32_t *Key, uint64_t v){
	uint32_t a0 = v, a1 = v>>32;
	int count = 4;
	const uint32_t *K=Key+8;
    do {
		a1 ^= g(*--K, a0);
		a0 ^= g(*--K, a1);
	} while(--count);
	count = 12;
    do {
		if (K==Key+8) K = Key;
		a1 ^= g(*K++, a0);
		a0 ^= g(*K++, a1);
	} while(--count);
	return (uint64_t)a0<<32 | a1;
}
#endif // 0
/*! \brief Режим выработки имитовставки
    \param K ключ шифрования длиной...
    \param iv начальное значение или вектор инициализации
    \param data сегмент данных от которого вычисляется имитовставка
*/
typedef struct _CCM CCM_t;
struct _CCM {
    uint64_t last_block;
    uint64_t sum;
    const uint32_t *K;
    uint32_t len;
};
static void magma_cmac_init(CCM_t *ctx, const uint32_t * Key)
{
    ctx->K = Key;
    ctx->last_block = 0;
    ctx->sum = 0;
    ctx->len = 0;
}
/*! \brief */
static void magma_cmac_update(CCM_t *ctx, uint8_t* data, size_t len)
{
    const int s=8;
    if ((ctx->len % s)!=0) {// не полный блок.
        int slen = s - ctx->len; // длину берем из данных
        if (slen > len) slen = len;
        __builtin_memcpy(((uint8_t*)&ctx->last_block) + ctx->len, data, slen);
        data+=slen;
        len -=slen;
        ctx->len += slen;
    }
    if (len) {
        uint64_t m = ctx->sum;
        if (ctx->len == s) {// полный блок и
            m^= htonll(ctx->last_block);
            m = magma_encrypt(ctx->K, m);
            ctx->last_block = 0;
        }
        int blocks = (len-1)/s;// число целых блоков
        int i;
        for (i=0; i<blocks; i++){
            //printf("P = %016"PRIx64"\n", *(uint64_t*)data);
            m^= htonll(*(uint64_t*)data); data+=s;
            m = magma_encrypt(ctx->K, m);
        }
        ctx->sum = m;
        ctx->len = len - blocks*s;
        if (ctx->len) {
            __builtin_memcpy((uint8_t*)&ctx->last_block, data, ctx->len);
            //printf("L = %016"PRIx64"\n", ctx->last_block);
        }
    }
}
typedef  int64_t  int64x2_t __attribute__((__vector_size__(16)));
typedef uint64_t poly64x2_t __attribute__((__vector_size__(16)));
// Little Endian
#define REV64(v) __builtin_bswap64(v)
/*! brief операция умножения с накоплением без редуцирования в результате получаем 128 бит */
static inline void CL_MLA64(poly64x2_t *s, uint64_t p, uint64_t v) {
	(*s) ^= (poly64x2_t)__builtin_ia32_pclmulqdq128((int64x2_t){p},(int64x2_t){v}, 0x00);
}
static uint64_t gf64_reduction(poly64x2_t s)
{
#if defined(__PCLMUL__)// Intel PCLMUL
	poly64x2_t t = (poly64x2_t)__builtin_ia32_pclmulqdq128((int64x2_t)s, (int64x2_t){0x145ULL,0x1BULL}, 0x11) ^ s;
	s ^=  (poly64x2_t)__builtin_ia32_pclmulqdq128((int64x2_t)t, (int64x2_t){0x145ULL,0x1BULL}, 0x11);// todo уточнить коэффициенты
	return s[0];
#else
	uint64_t x1 = s[1];
	uint64_t x0 = s[0];
	x1 = x1 ^ x1>>63 ^ x1>>61 ^ x1>>60;
	x1 = x1 ^ x1<<3;
	return x0 ^ x1 ^ x1<<1;// ^ x1<<3 ^ x1<<4;
#endif
}
/*! таблица для редуцирования после умножения
	перенос (4бита) по таблице добавить к остатку
*/
static const uint8_t gf2m_64[] = {
0x00, 0x1B, 0x36, 0x2D,
0x6C, 0x77, 0x5A, 0x41,
0xD8, 0xC3, 0xEE, 0xF5,
0xB4, 0xAF, 0x82, 0x99,
};
/*! \brief Умножение 64х64 в поле GF(2^64) с полиномом по четыре бита без редуцирования */
static uint64_t gf64_mulm   (uint64_t a, uint64_t b)
{
	const uint64_t P = 0x1BULL;
	int i,n;
	uint64_t aa[16];// таблица умножения 128 байт, 16 элементов
	// расчитать таблицу умножения для 16 значений
	for (n=0; n<16;n++) aa[n] = 0;
	for (i=0; i<4; i++){
		for (n=0; n<16; n++)
			if (n & (1<<i)) aa[n] ^= a;
		if (a&(1ULL<<63))
			a = (a<<1) ^ P;
		else
			a = (a<<1);
	}
	uint64_t r = 0;
	for (i=15; i>=0; i--){
		r = (r<<4) ^ gf2m_64[r>>60] ^ aa[(b>>(4*i))&0xF];// умножение и редуцирование
	}
	return r;
}
static
void CL_MLA64_(poly64x2_t *s, uint64_t a, uint64_t b) {
	const uint64_t P = 0x1BULL;
	int i,n;
	uint64_t aa[16];// таблица умножения 128 байт, 16 элементов
	// расчитать таблицу умножения для 16 значений
	for (n=0; n<16;n++) aa[n] = 0;
	for (i=0; i<4; i++){
		for (n=0; n<16; n++)
			if (n & (1<<i)) aa[n] ^= a;
		if (a&(1ULL<<63))
			a = (a<<1) ^ P;
		else
			a = (a<<1);
	}
	uint64_t r = 0, cy=0;
	for (i=15; i>=0; i--){
		cy = (cy<<4)|(r>>60);
		r = (r<<4) ^ aa[(b>>(4*i))&0xF];
	}
	(*s)^=(poly64x2_t){r,cy};
}

static inline uint64_t incr_l(uint64_t v64) {
	union {
		uint32_t u32[2];
		uint64_t u64;
	} v;
    v.u64 = v64;// может понадобится выворачивать байты
	v.u32[1]++;
    return v.u64;
}
static inline uint64_t incr_r(uint64_t v64) {
	union {
		uint32_t u32[2];
		uint64_t u64;
	} v;
    v.u64 = v64;// может понадобится выворачивать байты
	v.u32[1]++;
    return v.u64;
}
static void print_hex(const char* fmt, int i, uint64_t v)
{
	printf(fmt, i);
	for (i=0; i<8;i++)
		printf(" %02llX", 0xFF&(v>>((7-i)*8)));
	printf("\n");
}
typedef uint64_t (*CipherEncrypt64)(const uint32_t *Key, uint64_t v);
typedef struct _XTS64 XTS_t;
struct _XTS64 {
	CipherEncrypt64 encrypt;
	uint64_t iv;
	uint32_t * key1;
	uint32_t * key2;
};
static inline uint64_t gf64_shift(uint64_t a)
{
	const uint64_t P = 0x1BULL;
	if (a>>63)
		a = (a<<1) ^ P;
	else
		a = (a<<1);
	return a;
}
// синтезировал алгоритм для шифрования на носителе
void XTS64_encrypt(XTS_t *xex, uint8_t* dst, const uint8_t* src, int length)
{
	CipherEncrypt64 encrypt = xex->encrypt;
	uint64_t d, v;
	v = encrypt(xex->key2, xex->iv);// Key2
    int blocks = length>>3;// 64 bit
    int i;
    for (i=0;i<blocks-1;i++)
    {
		d = *(uint64_t*)src; src+=8;
		d = v^encrypt(xex->key1, d^v);
		v = gf64_shift(v);// increment
		*(uint64_t*)dst = d; dst+=8;
	}
	int len = length& 0x7;
	if (len) {
		d = *(uint64_t*)src; src+=8;
        d = v^encrypt(xex->key1, d^v);
		v = gf64_shift(v);// increment

		__builtin_memcpy(dst+8, &d, len);
		__builtin_memcpy(&d, src, len);
		d = v^encrypt(xex->key1, d^v);
		*(uint64_t*)dst = d;
	} else {
		d = *(uint64_t*)src; src+=8;
        d = v^encrypt(xex->key1, d^v);
		*(uint64_t*)dst = d;
	}
}
typedef struct _MGM MGM_t;
struct _MGM {
    uint64_t icn;
    uint32_t *K;
};
/*! \brief Режим гаммирования, отличается инициализация счетчика
	\see https://datatracker.ietf.org/doc/html/draft-smyshlyaev-mgm-20

	Этот вариант пригоден для шифрования носителя
*/
void magma_mgm_enc(MGM_t *ctx, uint8_t* ct, const uint8_t* pt, uint32_t len)
{
    const unsigned int s=8;
	uint64_t h,c;
	union {
        uint32_t u[2];
        uint64_t u64;
	} ctr;
	ctr.u64 =  magma_encrypt(ctx->K, ctx->icn & ~(0x1ULL<<63));
	int i;
    int blocks = len/s;
	for (i=0; i<blocks; i++){
		__builtin_memcpy(&c, &pt[8*i], s);
		h = magma_encrypt(ctx->K, ctr.u64);
		if (0) {
			print_hex("Y_%d    : ", i+1, ctr.u64);
			print_hex("E_K(Y_2): ", i+1, h);
		}
		c^= REV64(h);
		__builtin_memcpy(&ct[8*i], &c, s);
		ctr.u[0]++;
	}
	int r = len%s;
	if (r){
		__builtin_memcpy(&c, &pt[8*i], r);
		h = magma_encrypt(ctx->K, ctr.u64);
		c^= REV64(h>>(8*(8-s)));
		__builtin_memcpy(&ct[8*i], &c, r);
	}
}
/*! \brief MGM Tag Generation Procedure

вычисление тега аутентификации в режиме MGM
	\param ctx context
	\param[IN] aad Associated authenticated data A
	\param aad_len Associated authenticated data length
	\param[IN] ct Cipher text Encrypted payload
	\param len Cipher text length
	\return Tag
 */
uint64_t magma_mgm_tag(MGM_t *ctx, const uint8_t* aad, uint32_t aad_len, const uint8_t* ct, uint32_t len)
{
	const unsigned int s = 8;// длина блока
	poly64x2_t sum = {0};
		union {
        uint32_t u[2];
        uint64_t u64;
	} ctr;
	uint64_t h, c;
	ctr.u64 = magma_encrypt(ctx->K, ctx->icn|(0x1ULL<<63));
	int i;
// magma_mgm_tag_update(ctx, data, len);
	int blocks = aad_len/s;
	for (i=0; i<blocks; i++){
		h = magma_encrypt(ctx->K, ctr.u64);
		c = htonll(*(uint64_t*)aad); aad+=8;
		CL_MLA64(&sum, c, h);// sum = sum (xor) ( H_i (x) A_i )
		ctr.u[1]++;
		if (0) {
			print_hex("Z_%d  : ", i+1, ctr.u64);
			print_hex("H_%d  : ", i+1, h);
			print_hex("sum_%d: ", i+1, gf64_reduction(sum));
		}
	}
    if (aad_len % s) {
		h = magma_encrypt(ctx->K, ctr.u64);
		if (0) {
			print_hex("Z_%d     : ", i+1, ctr.u64);
			print_hex("H_%d  : ", i+1, h);
		}
		c = 0;
		__builtin_memcpy(&c, aad, aad_len % s);
		CL_MLA64(&sum, htonll(c), h);
		ctr.u[1]++;
	}
// magma_mgm_tag_update(ctx, data, len);
	blocks = len/s;
	for (i=0; i<blocks; i++){
		h = magma_encrypt(ctx->K, ctr.u64);
		c = htonll(*(uint64_t*)ct); ct+=8;
		CL_MLA64(&sum, (c), h);// sum = sum (xor) ( H_i (x) C_i )
		ctr.u[1]++;
	}
    if (len % s) {
		h = magma_encrypt(ctx->K, ctr.u64);
		c = 0;
		__builtin_memcpy(&c, ct, len % s);
		CL_MLA64(&sum, htonll(c), h);
		ctr.u[1]++;
	}
	h = magma_encrypt(ctx->K, ctr.u64);
	ctr.u[0] =     len*s;
	ctr.u[1] = aad_len*s;
	CL_MLA64(&sum, ctr.u64, h);
	return magma_encrypt(ctx->K, gf64_reduction(sum));
	// Return (ICN, A, C, T)
}

static uint64_t magma_cmac_fini(CCM_t *ctx)
{
    const int s=8;
	uint64_t K1 = magma_encrypt(ctx->K, 0ULL);
	int of = K1>>63;
	//printf("R = %016"PRIx64"\n", K1);
	K1=(K1<<1);
	if(of) K1^=0x1BULL;// RED BULL
	//printf("K1= %016"PRIx64"\n", K1);
	if (ctx->len%s) {// не полный блок
		of = K1>>63;
		K1=(K1<<1);
		if(of) K1^=0x1BULL;
        //printf("K2= %016"PRIx64"\n", K1);
		/// добить нулями и 10000, и единицей
		//ctx->last_block <<= (s - (ctx->len%s))*8;
        ((uint8_t*)&ctx->last_block)[(ctx->len%s)] = 0x80;
        //printf("V = %016"PRIx64"\n", __builtin_bswap64(ctx->last_block));
	}
	uint64_t m = ctx->sum;
	m^= htonll(ctx->last_block)^K1;
	return magma_encrypt(ctx->K, m);
}
/*! \brief Режим имитовставки */
uint64_t magma_cmac(const uint32_t *K, uint8_t *iv, size_t vlen, uint8_t* data, size_t len)
{
    CCM_t ctx;
    magma_cmac_init(&ctx, K);
    if (vlen) magma_cmac_update(&ctx, iv, vlen);
    if ( len) magma_cmac_update(&ctx, data, len);
    return magma_cmac_fini(&ctx);
}

/*! \brief Режим гаммирования */
void magma_ctr(const uint32_t *K, uint32_t iv, uint8_t* data, size_t len)
{
    const int s=8;
	uint64_t m,v;
	union {
        uint32_t u[2];
        uint64_t u64;
	} ctr;
    ctr.u[0] =  0;
    ctr.u[1] = iv;
	int i=0;
    int blocks = (len)>>3;
	for (; i<blocks; i++){
		__builtin_memcpy(&v, &data[8*i], s);
		m = magma_encrypt(K, ctr.u64);
		v^= htonll(m>>(8*(8-s)));
		__builtin_memcpy(&data[8*i], &v, s);
		ctr.u[0]++;
	}
	int r = len&0x7;
	if (r){
		__builtin_memcpy(&v, &data[8*i], r);
		m = magma_encrypt(K, ctr.u64);
		v^= htonll(m>>(8*(8-s)));
		__builtin_memcpy(&data[8*i], &v, r);
	}
}

void magma_ACPKM(uint32_t *K)
{
	const uint8_t d[] =
		"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F"
		"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F";
	uint32_t k[8];
	const uint8_t *src = d;
	uint8_t *dst = (uint8_t *)(k+8);
	int i;
	for (i=0; i<4; i++) {
		uint64_t v = __builtin_bswap64(*(uint64_t*) src); src+=8;
		v = magma_encrypt(K, v);
		dst-=8;
		*(uint64_t*) dst = (v);
	}
	__builtin_memcpy(K, k, 32);
}
/*! \brief Режим гаммирования с кручением ключа */
void magma_ctr_acpkm(uint32_t *K, uint32_t iv, uint8_t* data, size_t len)
{
    const int n=2;// частота смены ключа
    const int s=8;
	uint64_t m,v;
	union {
        uint32_t u[2];
        uint64_t u64;
	} ctr;
    ctr.u[0] =  0;
    ctr.u[1] = iv;
	int i=0, j=0;
    int blocks = (len)>>3;
	for (; i<blocks; i++){
		__builtin_memcpy(&v, &data[8*i], s);
		m = magma_encrypt(K, ctr.u64);
		v^= htonll(m>>(8*(8-s)));
		__builtin_memcpy(&data[8*i], &v, s);
		ctr.u[0]++;
		if (++j==n) {
			magma_ACPKM(K);
			j=0;
		}
	}
	int r = len&0x7;
	if (r){
		__builtin_memcpy(&v, &data[8*i], r);
		m = magma_encrypt(K, ctr.u64);
		v^= htonll(m>>(8*(8-s)));
		__builtin_memcpy(&data[8*i], &v, r);
	}
}

/*! \brief Развертывание ключа
    Загружает сетевое представление ключа в локальное представление
 */
void magma_ekb (uint32_t* K, const uint8_t *key, int klen, int ekb)
{
	//const uint32_t* kk = (const uint32_t*)key;
	key +=klen;
	int i;
	for (i=0;i<8; i++){
		//K[i] = (*(uint32_t*)key); key+=4;
		key-=4;
		*K++ = ntohl(*(uint32_t*)key);
	}
}

/*! \brief Алгоритм экспорта закрытого ключа KExp15
	\param data буфер обмена, на котором происходит шифрование ключа.
	K - экспортируемый ключ, копируется в буфер.
	\param klen - длина ключа. Длина выходного буфера должна быть не менее klen+8
	\param key_exp_mac - ключ выработки иммитовставки
	\param key_exp_enc - ключ шифрования экспортируемого ключа
	\param iv - вектор инициализации

	\see Р 1323565.1.017—2018  KExp15 KImp15
 */
void magma_KExp15(uint8_t* data, int klen,
	uint8_t* key_exp_mac, uint8_t* key_exp_enc, uint8_t* iv)
{
	const int iv_len = 4;
	MagmaCtx ctx;
	magma_ekb(ctx.K, key_exp_mac, 32, 0);
	uint64_t keymac = magma_cmac(ctx.K, iv, iv_len, data, klen);
//	printf("KEYMAC %016llX\n", keymac);// 75A76618E90F4973
	magma_ekb(ctx.K, key_exp_enc, 32, 0);
	*(uint64_t* )(data+klen) = __builtin_bswap64(keymac);
	magma_ctr(ctx.K, __builtin_bswap32(*(uint32_t*)iv), data, klen+8);
}
/*! \brief Алгоритм импорта ключа KImp15
	\return TRUE если иммитовставка от ключа OMAC сходится.

	\see Р 1323565.1.017—2018  KExp15 KImp15
 */
int magma_KImp15(uint8_t* data, int klen,
	uint8_t* key_exp_mac, uint8_t* key_exp_enc, uint8_t* iv)
{
	const int iv_len = 4;
	MagmaCtx ctx;
	magma_ekb(ctx.K, key_exp_enc, 32, 0);
	magma_ctr(ctx.K, __builtin_bswap32(*(uint32_t*)iv), data, klen+8);
	magma_ekb(ctx.K, key_exp_mac, 32, 0);
	uint64_t keymac = magma_cmac(ctx.K, iv, iv_len, data, klen);
	return __builtin_bswap64(keymac)==*(uint64_t* )(data+klen);
}

#ifdef TEST_MAGMA
#include <stdio.h>

#define MAGMA_CTR_CMAC 		1
#define MAGMA_NULL_CMAC 	2
#define MAGMA_CTR_CMAC8 	3
#define MAGMA_NULL_CMAC8 	4

struct _crisp_ctx {
//    uint16_t version;
    uint8_t CS;		//!< режим шифрования 01: MAGMA-CTR-CMAC 02: MAGMA-NULL-CMAC 03:
    uint8_t *KeyId;
    uint8_t klen;
    uint8_t *K;		//!< Базовый ключ
    uint8_t* SourceIdentifier;
};
/*! \brief Выработка производных ключей
    \param K производный ключ
    \param Key базовый ключ
    \param CS режим шифрования
		\arg  01 MAGMA-CTR-CMAC
		\arg  02 MAGMA-NULL-CMAC
		\arg  03 MAGMA_CTR_CMAC8
		\arg  04 MAGMA_NULL_CMAC8
    \param SeqNum последовательный номер обмена
    \param SourceIdentifier идентификатор отправителя
    \param slen длина идентификатора от 4.. байт
*/
uint8_t * crisp_key_derive(uint8_t* K, const uint32_t* Key, uint8_t CS, uint64_t SeqNum, uint8_t *SourceIdentifier, int slen)
{
    uint8_t  iv[18+slen];
    uint8_t* buf = iv;
	int count;
    switch (CS){
    case 0x04:
    case 0x02:
        count = 256/64; break;
	case 0x03:
    case 0x01:
    default:
        count = 512/64; break;
    }
    __builtin_memcpy(buf, (CS&1)?"\x00macenc\x06":"\x00macmac\x06", 8);
    buf+=8;
    uint64_t SN = /* __builtin_bswap64 */((SeqNum>>(48-35)) & ((1ULL<<35)-1));//>>13 48бит 35 бит
    printf("SN = %010"PRIX64"\n", SN);
    *buf++ = SN>>(32);
    *buf++ = SN>>(24);
    *buf++ = SN>>(16);
    *buf++ = SN>>( 8);
    *buf++ = SN;
    __builtin_memcpy(buf, SourceIdentifier, slen);// 22-24 бита
    buf+=slen;
    *buf++ = CS;
    *(uint16_t*)buf = htons(slen+6); buf+=2;//сумма байтовых длин значений SN, SourceIdentifier, CS
    *(uint16_t*)buf = htons(count<<6); buf+=2;// число бит в производном ключе
    int i;
/*	for (i=0; i<18+slen; i++) {
        printf("%02"PRIx8" ", iv[i]);
        if ((i&15)==15) printf("\n");
	}
	printf("\n"); */
    for (i=0; i<count; i++){
        iv[0]++;// от 1...n
        *(uint64_t*)K = htonll(magma_cmac(Key, 0, 0,  iv, slen+18));
        K+=8;
    }
    return NULL;
}
int crisp_header(uint8_t * buf, uint8_t CS, uint64_t SeqNum,  uint8_t *KeyId, int klen)
{
	*buf++ = 0x80;
	*buf++ = 0x00;
	*buf++ = CS;
	if (klen>1) {
		*buf++ = (klen|0x80);
		__builtin_memcpy(buf, KeyId, klen);
		buf+= klen;
	} else
		*buf++ = KeyId[0];
	*buf++ = SeqNum>>40;
	*buf++ = SeqNum>>32;
	*buf++ = SeqNum>>24;
	*buf++ = SeqNum>>16;
	*buf++ = SeqNum>>8;
	*buf++ = SeqNum>>0;
	return klen+9;
}
/*! \brief выполнить кодирование данных и расчет
	\param CS режим шифрования
 */
uint64_t crisp_encode(uint8_t* K, uint8_t CS, uint32_t iv, uint8_t* hdr, int hlen, uint8_t* data, int dlen)
{
    uint32_t key[8];
	uint8_t *k_mac;
	if (CS&1) {
		uint8_t *k_enc = K;
		magma_ekb(key, k_enc, 32, 0);
		magma_ctr(key, iv, data, dlen);
		k_mac = K+32;
	} else
		k_mac = K;
	magma_ekb(key, k_mac, 32, 0);
    return magma_cmac(key, hdr, hlen, data, dlen);
}
static void print_hexstr(const char* fmt, const uint8_t* v, size_t len)
{
	printf(fmt);
	int i;
	for (i=0; i<len;i++){
		if ((i&0xF)==0) printf("\n%05X:\t", i);
		printf(" %02X", v[i]);
	}
	printf("\n");
}
#include <locale.h>
int main()
{
    setlocale(LC_ALL, "");
    setlocale(LC_NUMERIC, "C");
/*	t(fdb97531) = 2a196f34,
	t(2a196f34) = ebd9f03a,
	t(ebd9f03a) = b039bb3d,
	t(b039bb3d) = 68695433.*/
	uint32_t a[] = {0xfdb97531, 0x2a196f34, 0xebd9f03a, 0xb039bb3d};
    int i;
    for (i=0; i<4; i++) {
		printf("t(%08x) = %08x\n", a[i], t(a[i]));
	}

/*	g[87654321](fedcba98) = fdcbc20c,
	g[fdcbc20c](87654321) = 7e791a4b,
	g[7e791a4b](fdcbc20c) = c76549ec,
	g[c76549ec](7e791a4b) = 9791c849.*/
	uint32_t a1 = 0xfedcba98;
	uint32_t k1 = 0x87654321;
	uint32_t r;
    for (i=0; i<4; i++) {
		r = g(k1, a1);
		printf("g[%08x](%08x) = %08x\n", k1, a1, r);
		a1 = k1;
		k1 = r;
	}
#if 1
	uint8_t key[] =
		"\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00"
		"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";
#endif
	uint32_t key_1[] = {
        0xfcfdfeff, 0xf8f9fafb, 0xf4f5f6f7, 0xf0f1f2f3,
        0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc,
        };
	uint64_t r64;
	uint64_t a64 = 0xfedcba9876543210ULL;
	printf("A.2.3 Алгоритм развертывания ключа ГОСТ 34.12-2015\n");// A.2.3 Алгоритм развертывания ключа
	uint8_t *k = (void*)key;
	for (i=0; i<32; i++) {
        printf("\\x%02x",k[i]);
	}
	printf("\n");
	MagmaCtx ctx;
	magma_ekb(ctx.K, (void*)key, 32, 0);
	for (i=0; i<32; i++) {
        printf("\tK_%d=%08x",i+1, ctx.K[i]);
		if ((i&3)==3) printf("\n");
	}


	printf("a   = %016"PRIx64"\n", a64);
	r64 = 0x92def06b3c130a59ULL;
	printf("a   = %016"PRIx64"\n", r64);

	printf("ГОСТ Р 34.12.-2015 A.2.4 Алгоритм зашифрования\n");
	r64 = 0xfedcba9876543210ULL;
	r64 = magma_encrypt(ctx.K, r64);
	printf("enc = %016"PRIx64" (4ee901e5c2d8ca3d)\n", r64);
	if (0x4ee901e5c2d8ca3dULL==r64) printf("..ok\n");
	printf("ГОСТ Р 34.12.-2015 A.2.4 Алгоритм расшифрования\n");
	r64 = magma_decrypt(ctx.K, r64);
	printf("dec = %016"PRIx64" (fedcba9876543210)\n", r64);
	if (0xfedcba9876543210ULL==r64) printf("..ok\n");

	//uint32_t Pt[] = {0x3c130a59, 0x92def06b,0xf8189d20,0xdb54c704,0x67a8024c,0x4a98fb2e,0x17b57e41,0x8912409b};
unsigned char PlainText[32] =
{
     0x92, 0xde, 0xf0, 0x6b, 0x3c, 0x13, 0x0a, 0x59, 0xdb, 0x54, 0xc7, 0x04, 0xf8, 0x18, 0x9d, 0x20,
     0x4a, 0x98, 0xfb, 0x2e, 0x67, 0xa8, 0x02, 0x4c, 0x89, 0x12, 0x40, 0x9b, 0x17, 0xb5, 0x7e, 0x41,
};
unsigned char CtrEncText[32] =
{
     0x4e, 0x98, 0x11, 0x0c, 0x97, 0xb7, 0xb9, 0x3c, 0x3e, 0x25, 0x0d, 0x93, 0xd6, 0xe8, 0x5d, 0x69,
     0x13, 0x6d, 0x86, 0x88, 0x07, 0xb2, 0xdb, 0xef, 0x56, 0x8e, 0xb6, 0x80, 0xab, 0x52, 0xa1, 0x2d
};
	//uint32_t Ct[] = {0x97b7b93c, 0x4e98110c,0xd6e85d69,0x3e250d93,0x07b2dbef,0x136d8688,0xab52a12d,0x568eb680};
	printf("ГОСТ Р 34.13.-2015 A.2.2.1 Зашифрование в режиме гаммирования\n");
	uint32_t iv32=0x12345678;
	uint8_t data[sizeof(PlainText)];
	__builtin_memcpy(data, PlainText, sizeof(PlainText));
	for (i=0; i<sizeof(PlainText)/8; i++) {
        *(uint64_t*)(data+8*i) = (*(uint64_t*)(PlainText+8*i));//31 - i];
	}

	magma_ctr(ctx.K, iv32, (void*)data, sizeof(PlainText));
	int res = 1;
	for (i=0; i<4; i++) {
        printf("%016"PRIx64" ", *(uint64_t*)&data[8*i]);
        res = res && (*(uint64_t*)&data[8*i] == *(uint64_t*)&CtrEncText[8*i]);
		if ((i&3)==3) printf("\n");
	}
	if (res) printf("..ok\n");
	printf("ГОСТ Р 34.13.-2015 A.2.6.2 Вычисление имитовставки MAC = 154e7210.\n");
	r64 = magma_cmac(ctx.K, 0, 0, (uint8_t*)PlainText, sizeof(PlainText));
	printf("cmac32 = %08"PRIx32" (154e7210 0x2030c5bb)\n", (uint32_t)(r64>>32));
	if (0x154e72102030c5bbULL==r64) printf("..ok\n");
/** @brief 89 Imita */
unsigned char ImitaValue[8] =
{
     0x15, 0x4e, 0x72, 0x10, 0x20, 0x30, 0xc5, 0xbb
};

// ТК26УЗ
	uint8_t key2[] = "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x80"
			"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xd0";
	uint8_t pt[] =
		"\x01\x02\x03\x04\x05\x06\x07\x08\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8";
	uint8_t ct[] =
		"\xce\x5a\x5e\xd7\xe0\x57\x7a\x5f\xd0\xcc\x85\xce\x31\x63\x5b\x8b";
	magma_ekb(ctx.K, (void*)key2, 32, 0);
	for (i=0; i<2; i++) {
		r64 = *(uint64_t*)&pt[i*8];
		r64 = magma_encrypt(ctx.K, r64);
		uint32_t r0 = __builtin_bswap32(r64);
		uint32_t r1 = __builtin_bswap32(r64>>32);
        printf("%08X %08X ",r0, r1);
	}
	printf("\n");
    printf("P 50.1.110-2016	tc26\n");
	uint8_t ukm[] = "\xF0\x86\x00\x8A\xB4\x17\x5A\xF7";
	uint8_t Pw_key[] =
		"\x6C\x5C\x3C\xE5\xC6\x66\x57\x6E\x9D\x7B\x63\x00\x31\xB5\x85\x6C"
		"\x50\xAD\xC8\xAA\xD9\x1E\xF9\xB4\x2F\x62\xF9\x0A\x45\x4E\x43\x1C";
	uint8_t session_key[] =
		"\x74\xD1\xB8\x53\x64\x3F\xA0\x01\x54\xE0\xE8\x3D\xAF\x19\x1C\xB3"
		"\x9D\x20\x91\x56\x1B\x07\x5C\x46\x5C\x55\x6A\x5B\xB3\x15\x45\x2D";
	uint8_t wraped_key[] =
		"\xF3\x73\xD2\x4D\x08\xDD\x75\x69\x8B\x78\xDB\x8A\x30\x7C\x90\xF0"
		"\x7D\xE2\x44\xDD\xEE\xAC\x88\x81\x9B\x60\x92\x1D\xB4\x55\x4C\x8C";
	uint64_t iv = *(uint64_t*)ukm;
	magma_ekb(ctx.K, (void*)Pw_key, 32, 0);
	for (i=0; i<1; i++) {
		r64 = *(uint64_t*)&wraped_key[i*8];
		r64 = magma_decrypt(ctx.K, r64);
		uint32_t r0 = __builtin_bswap32(r64);
		uint32_t r1 = __builtin_bswap32(r64>>32);
        printf("\\x%08X %08X",r0, r1);
	}
	printf("\n");
	r64 = magma_cmac(ctx.K, (uint8_t*)&iv, 0, (uint8_t*)session_key, 32);
	printf("cmac32 = %08x (4B 66 2E 58)\n", (uint32_t)(r64>>32));
/*	for(i=0;i<4;i++){
		r64 = magma_encrypt(ctx.K, Pt[i]);
		printf("ECB (%08x%08x) = %08x%08x\n", Pt[i][1],Pt[i][0],r64[1],r64[0]);
		uint32_t p0 = __builtin_bswap32(Pt[i][0]);
		uint32_t p1 = __builtin_bswap32(Pt[i][1]);
		printf("%08x%08x => ", p0, p1);
		uint32_t r0 = __builtin_bswap32(r64[0]);
		uint32_t r1 = __builtin_bswap32(r64[1]);
		printf("%08x%08x\n", r0, r1);
	}
*/

printf("МР 26.4.001-2019 Протокол защищенного обмена для индустриальных систем (CRISP 1.0)\n");

    printf("МР 26.4.001-2019 А.1 Набор MAGMA-CTR-CMAC: CS = 1\n"
            "Выработка производных ключей\n");
	uint8_t d_key[64];
    uint8_t k_enc[] = // ключ шифрования
    "\xe3\x31\x6a\xd2\x8c\x78\x8c\x38\xda\xfd\xeb\x93\x88\xe2\x34\xbd"
    "\x30\xe5\xc9\x01\xee\xeb\x17\x88\xcd\xc1\xec\x5d\xb3\x15\xe1\xa7";
    uint8_t key01[] =
    "\x56\x50\x94\x27\x15\x32\x49\x65\x34\x98\x52\x46\x59\x32\x46\x53"
    "\x04\x53\x29\x45\x34\x65\x93\x84\x50\x73\x24\x95\x76\x35\x12\x90";
    uint8_t data1[]=
    "\x48\x69\x21\x20\x54\x68\x69\x73\x20\x69\x73\x20\x74\x65\x73\x74"
    "\x20\x66\x6f\x72\x20\x43\x52\x49\x53\x50\x20\x6d\x65\x73\x73\x61"
    "\x67\x65\x73\x0a\x03";
    uint8_t sid01[] = "\x30\x32\x30\x35\x31\x38\x30\x30\x30\x30\x30\x31";
    magma_ekb(ctx.K, key01, 32, 0);
    crisp_key_derive(d_key, ctx.K, 1, 0x0b76e6736001ULL, sid01, 12);
    uint8_t k_mac01[] =
    "\xee\xb0\xf6\x81\x42\x57\xad\x08\x96\x4e\xab\xe5\xe0\x99\x3d\x38"
    "\xb2\xaf\xc2\xad\xa2\x4e\x83\x62\xd4\x55\xdb\x06\x95\x1f\x2d\x93";
    uint8_t k_enc01[] =
    "\xe3\x31\x6a\xd2\x8c\x78\x8c\x38\xda\xfd\xeb\x93\x88\xe2\x34\xbd"
    "\x30\xe5\xc9\x01\xee\xeb\x17\x88\xcd\xc1\xec\x5d\xb3\x15\xe1\xa7";
	printf("Значение производного ключа шифрования K_mac\n");
    for (i=0; i<32; i++)   {// распечатываем ключ
        printf("%02"PRIx8" ", d_key[i]);
        if ((i&15)==15) printf("\n");
	}
	if(__builtin_memcmp(k_mac01, d_key, 32)==0)printf("..ok\n");
	printf("Значение производного ключа шифрования K_enc\n");
    for (i=0; i<32; i++)   {// распечатываем ключ
        printf("%02"PRIx8" ", d_key[32+i]);
        if ((i&15)==15) printf("\n");
	}
	if(__builtin_memcmp(k_enc01, d_key+32, 32)==0)printf("..ok\n");
	for (i=0; i<32/8; i++) {// переворачиваем ключ
        *(uint64_t*)(d_key+8*i) =    __builtin_bswap64(*(uint64_t*)(k_enc+24 - 8*i));//31 - i];
	}
	printf("Значение производного ключа шифрования\n");
    for (i=0; i<32; i++)   {// распечатываем ключ
        printf("%02"PRIx8" ", d_key[i]);
        if ((i&15)==15) printf("\n");
	}
    magma_ekb(ctx.K, k_enc, 32, 0);
    magma_ctr(ctx.K, 0xe6736001UL , data1, 37);// SecNum
    printf("Зашифрованное сообщение:\n");
    for (i=0; i<sizeof(data1)-1; i++)   {// распечатываем ключ
        printf("%02"PRIx8" ", data1[i]);
        if ((i&15)==15) printf("\n");
	}
	if ((i&15)!=0) printf("\n(25 fa 90 50 a1)\n");
	uint8_t hdr1[]="\x80\x00\x01\x30\x0b\x76\xe6\x73\x60\x01";
    printf("Имитовставка \n");
    uint8_t k_mac[] =
    "\xee\xb0\xf6\x81\x42\x57\xad\x08\x96\x4e\xab\xe5\xe0\x99\x3d\x38"
    "\xb2\xaf\xc2\xad\xa2\x4e\x83\x62\xd4\x55\xdb\x06\x95\x1f\x2d\x93";
	for (i=0; i<32/8; i++) {// переворачиваем ключ
        *(uint64_t*)(d_key+8*i) =    __builtin_bswap64(*(uint64_t*)(k_mac+24 - 8*i));//31 - i];
	}
	magma_ekb(ctx.K, k_mac, 32, 0);
    uint64_t T = magma_cmac(ctx.K, hdr1, 10, data1, 37);
    printf("Значение имитовставки ICV=%016"PRIx64" (88 7f 0a 32) \n", T);
    if (0x887f0a32==(T>>32)) printf("..ok\n");


    uint8_t key02[] =
    "\x56\x50\x94\x27\x15\x32\x49\x65\x34\x98\x52\x46\x59\x32\x46\x53"
    "\x04\x53\x29\x45\x34\x65\x93\x84\x50\x73\x24\x95\x76\x35\x12\x90";
    uint8_t sid[] = "\x30\x32\x30\x35\x31\x38\x30\x30\x30\x30\x30\x31";
    uint8_t derived_key[] =
//    "\xe3\x31\x6a\xd2\x8c\x78\x8c\x38\xda\xfd\xeb\x93\x88\xe2\x34\xbd"
//    "\x30\xe5\xc9\x01\xee\xeb\x17\x88\xcd\xc1\xec\x5d\xb3\x15\xe1\xa7";
    "\xc3\xe3\x78\x0f\x87\xf2\xca\xf5\x39\xfd\xad\x56\xd9\xcb\x03\x40"
    "\xb1\x05\x2c\x0a\xe8\x27\x2d\xdc\x96\x01\xc9\x21\xf8\x1a\x7c\xa5";
    uint8_t data2[]=
    "\x48\x69\x21\x20\x54\x68\x69\x73\x20\x69\x73\x20\x74\x65\x73\x74"
    "\x20\x66\x6f\x72\x20\x43\x52\x49\x53\x50\x20\x6d\x65\x73\x73\x61"
    "\x67\x65\x73\x0a\x03\x00\x00\x00";
//    uint8_t k_mac[256/8];
    printf("МР 26.4.001-2019 А.2 Набор MAGMA-NULL-CMAC: CS = 2\n"
            "Выработка производных ключей\n");
    magma_ekb(ctx.K, key02, 32, 0);
    crisp_key_derive(k_mac, ctx.K, 2, /* 0x01a06ee6760bULL */0x0b76e66ea001ULL, sid, 12);
    printf("Значение производного ключа имитозащиты\n");
	for (i=0; i<256/8; i++) {
        printf("%02"PRIx8" ", k_mac[i]);
        if ((i&15)==15) printf("\n");
	}
    if(__builtin_memcmp(k_mac, derived_key, 32)==0)printf("..ok\n");

    magma_ekb(ctx.K, derived_key, 32, 0);
    uint8_t hdr[]="\x80\x00\x02\x30\x0b\x76\xe6\x6e\xa0\x01";
//    "\x48\x69\x21\x20\x54\x68\x69\x73\x20\x69\x73\x20\x74\x65\x73\x74"
//    "\x20\x66\x6f\x72\x20\x43\x52\x49\x53\x50\x20\x6d\x65\x73\x73\x61"
//    "\x67\x65\x73\x0a\x03\x00\x00\x00";
    printf("Имитовставка \n");
    T = magma_cmac(ctx.K, hdr, 10, data2, 37);
    printf("Значение имитовставки ICV=%016"PRIx64" (b9 7a de 94) \n", T);
    if (0xb97ade94==(T>>32)) printf("..ok\n");
    printf("МР 26.4.001-2019 А.3 Набор MAGMA-CTR-CMAC8: CS = 3\n");
	uint8_t k_mac03[] =
		"\x74\x2a\xe2\xac\xeb\xae\x5f\xed\x1c\xc7\xac\xfd\x61\x4d\x9c\xf2"
		"\x98\xae\xee\xa7\xa7\x7a\x99\x7b\xc1\x9b\x99\xb9\xbe\xeb\x88\x32";
	uint8_t k_enc03[] =
		"\xc2\x41\xeb\xfa\xc4\x9d\x47\x68\x59\xe1\xe6\x38\x8a\x94\x66\x0b"
        "\x65\xd6\xb7\x40\xa3\x83\x63\xab\xb9\x12\x92\x97\x25\x0d\xdb\x22";
	uint8_t data03[] =
		"\x48\x69\x21\x20\x54\x68\x69\x73\x20\x69\x73\x20\x74\x65\x73\x74"
		"\x20\x66\x6f\x72\x20\x43\x52\x49\x53\x50\x20\x6d\x65\x73\x73\x61"
		"\x67\x65\x73\x0a\x03";
	uint8_t hdr03[]  = "\x80\x00\x03\x30\x0b\x76\xe6\x73\x60\x01";
	uint8_t icv03[] ="\xed\xf3\x39\xa0\xdb\xc0\xb5\xb7";
	printf("Значение производного ключа шифрования K_mac\n");
	magma_ekb(ctx.K, key01, 32, 0);
    crisp_key_derive(d_key, ctx.K, 3, 0x0b76e6736001ULL, sid01, 12);
void print_data(uint8_t * data, size_t len) {
    int i;
    for (i=0; i<len; i++)   {// распечатываем ключ
        printf("%02"PRIx8" ", data[i]);
        if ((i&15)==15) printf("\n");
	}
	if (i&0x1F) printf("\n");
}
	print_data(d_key, 32);
	if(__builtin_memcmp(k_mac03, d_key, 32)==0)printf("..ok\n");
	printf("Значение производного ключа шифрования K_enc\n");
    print_data(d_key+32, 32);
	if(__builtin_memcmp(k_enc03, d_key+32, 32)==0)printf("..ok\n");
    magma_ekb(ctx.K, k_enc03, 32, 0);
    magma_ctr(ctx.K, 0xe6736001UL , data03, 37);// SecNum
    printf("Зашифрованное сообщение:\n");
	print_data(data03, 37);
	magma_ekb(ctx.K, k_mac03, 32, 0);
    T = magma_cmac(ctx.K, hdr03, 10, data03, 37);
    printf("Значение имитовставки ICV=%016"PRIx64"\n", T);
    if (0xedf339a0dbc0b5b7ULL==(T)) printf("..ok\n");
	printf("МР 26.4.001-2019 А.3 Набор MAGMA-NULL-CMAC8: CS = 4\n");
	uint8_t k_mac04[] =
		"\x5d\x48\x85\xa4\x8e\x3b\xee\x6f\x79\xa3\xbd\x09\x9a\xda\x4f\x68"
        "\x21\xdc\xf8\x16\x91\xd6\x71\x0a\xf3\x01\x6c\x85\xae\x06\xeb\xc4";
	uint8_t data04[] =
		"\x48\x69\x21\x20\x54\x68\x69\x73\x20\x69\x73\x20\x74\x65\x73\x74"
		"\x20\x66\x6f\x72\x20\x43\x52\x49\x53\x50\x20\x6d\x65\x73\x73\x61"
		"\x67\x65\x73\x0a\x03";
	uint8_t hdr04[] = "\x80\x00\x04\x30\x0b\x76\xe6\x6e\xa0\x01";
	uint8_t icv04[] = "\xf2\x31\x52\x38\x8e\x61\x58\x25";
    magma_ekb(ctx.K, key02, 32, 0);
    crisp_key_derive(k_mac, ctx.K, 4, /* 0x01a06ee6760bULL */0x0b76e66ea001ULL, sid, 12);
    printf("Значение производного ключа имитозащиты\n");
	print_data(k_mac, 32);
	if(__builtin_memcmp(k_mac04, k_mac, 32)==0)printf("..ok\n");
	magma_ekb(ctx.K, k_mac04, 32, 0);
    T = magma_cmac(ctx.K, hdr04, 10, data04, 37);
    printf("Значение имитовставки ICV=%016"PRIx64"\n", T);
    if (0xf23152388e615825ULL==(T)) printf("..ok\n");

//-------------------------------------------------------
	printf("[RFC9058]Multilinear Galois Mode (MGM), Smyshlyaev, et al.\n"
	"A.2.  Test Vectors for the Magma block cipher \n");
	printf("--Example 1--\n");
	const uint8_t mgm_key[] =
	"\xFF\xEE\xDD\xCC\xBB\xAA\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00"
	"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF";
	MGM_t mgm_ctx;
	mgm_ctx.K  = ctx.K;
	magma_ekb(mgm_ctx.K, mgm_key, 32, 0);
	mgm_ctx.icn = 0x12DEF06B3C130A59;
//	uint64_t icn =
	const uint8_t aad[] =
	"\x01\x01\x01\x01\x01\x01\x01\x01\x02\x02\x02\x02\x02\x02\x02\x02"
	"\x03\x03\x03\x03\x03\x03\x03\x03\x04\x04\x04\x04\x04\x04\x04\x04"
	"\x05\x05\x05\x05\x05\x05\x05\x05\xEA";
	const uint8_t mgm_pt[] =
	"\xFF\xEE\xDD\xCC\xBB\xAA\x99\x88\x11\x22\x33\x44\x55\x66\x77\x00"
	"\x88\x99\xAA\xBB\xCC\xEE\xFF\x0A\x00\x11\x22\x33\x44\x55\x66\x77"
	"\x99\xAA\xBB\xCC\xEE\xFF\x0A\x00\x11\x22\x33\x44\x55\x66\x77\x88"
	"\xAA\xBB\xCC\xEE\xFF\x0A\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99"
	"\xAA\xBB\xCC";
	const uint8_t mgm_ct[] =
	"\xC7\x95\x06\x6C\x5F\x9E\xA0\x3B\x85\x11\x33\x42\x45\x91\x85\xAE"
	"\x1F\x2E\x00\xD6\xBF\x2B\x78\x5D\x94\x04\x70\xB8\xBB\x9C\x8E\x7D"
	"\x9A\x5D\xD3\x73\x1F\x7D\xDC\x70\xEC\x27\xCB\x0A\xCE\x6F\xA5\x76"
	"\x70\xF6\x5C\x64\x6A\xBB\x75\xD5\x47\xAA\x37\xC3\xBC\xB5\xC3\x4E"
	"\x03\xBB\x9C";
	uint8_t mgm_ct_[sizeof(mgm_pt)];
	magma_mgm_enc(&mgm_ctx, mgm_ct_, mgm_pt, sizeof(mgm_pt)-1);
	print_hexstr("Plaintext P:", mgm_pt, sizeof(mgm_pt)-1);
	print_hexstr("C:", mgm_ct_, sizeof(mgm_pt)-1);
	if (__builtin_memcmp(mgm_ct_, mgm_ct, sizeof(mgm_pt)-1)==0) printf("..ok\n");
	T =
	magma_mgm_tag(&mgm_ctx, aad, sizeof(aad)-1, mgm_ct, sizeof(mgm_ct)-1);
	print_hex("Tag T:  ",0, T);// A7 92 80 69 AA 10 FD 10
	uint64_t tag_1 = 0xA7928069AA10FD10;
	if (tag_1 == T) printf("..ok\n");

	printf("--Example 2--\n");
	const uint8_t mgm_key2[] =
	"\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77\xFE"
	"\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF\x88";
	const uint8_t mgm_pt2[] =
	"\x22\x33\x44\x55\x66\x77\x00\xFF";
	const uint8_t mgm_ct2[] =
	"\x6A\x95\xE1\x42\x6B\x25\x9D\x4E";
	magma_ekb(mgm_ctx.K, mgm_key2, 32, 0);
	mgm_ctx.icn = 0x0077665544332211;
	uint8_t mgm_ct2_[sizeof(mgm_pt)];
	magma_mgm_enc(&mgm_ctx, mgm_ct2_, mgm_pt2, sizeof(mgm_pt2)-1);
	print_hexstr("Plaintext P:", mgm_pt2, sizeof(mgm_pt2)-1);
	print_hexstr("C:", mgm_ct2_, sizeof(mgm_pt2)-1);
	if (__builtin_memcmp(mgm_ct2_, mgm_ct2, sizeof(mgm_pt2)-1)==0) printf("..ok\n");
	T =
	magma_mgm_tag(&mgm_ctx, aad, 0, mgm_ct2, sizeof(mgm_ct2)-1);
	print_hex("Tag T:  ",0, T);// 33 4E E2 70 45 0B EC 9E
	uint64_t tag_2 = 0x334EE270450BEC9E;
	if (tag_2 == T) printf("..ok\n");
if (1) {// KExp15

}
if (1) {// Р 1323565.1.017—2018  KExp15 KImp15
	printf("Р 1323565.1.017—2018  KExp15 KImp15\n");
	uint8_t K[] =
		"\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77"
		"\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF";
	uint8_t key_exp_mac[] =
		"\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x00\x01\x02\x03\x04\x05\x06\x07"
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
	uint8_t key_exp_enc[] =
		"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
		"\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\x30\x31\x32\x33\x34\x35\x36\x37";
	uint8_t iv[] = "\x67\xBE\xD6\x54";
	int iv_len = 4;
	int klen = sizeof(K)-1;
	uint8_t data[klen+8];
	__builtin_memcpy(data, K, klen);

	magma_KExp15(data, klen, key_exp_mac,  key_exp_enc, iv);
	for (i=0; i< klen+8; i++) {
		printf(" %02X", data[i]);
		if ((i&0xF)==0xF) printf("\n");
	}
	printf("\n");
	printf("KImp15\n");
	// расшифровывание
	if (magma_KImp15(data, klen, key_exp_mac,  key_exp_enc, iv)
		&& __builtin_memcmp(data, K, klen)==0) printf("..ok\n");
	printf("ACPKM\n");
	magma_ekb(ctx.K, K, 32,0);
	uint8_t *k = (uint8_t *)ctx.K;
	for (i=0; i< klen; i++) {
		printf(" %02X", k[i]);
		if ((i&0xF)==0xF) printf("\n");
	}
	printf("\n");
	magma_ACPKM(ctx.K);
	for (i=0; i< klen; i++) {
		printf(" %02X", k[i]);
		if ((i&0xF)==0xF) printf("\n");
	}
	printf("\n");
	magma_ACPKM(ctx.K);
	for (i=0; i< klen; i++) {
		printf(" %02X", k[i]);
		if ((i&0xF)==0xF) printf("\n");
	}
	printf("\n");
	magma_ACPKM(ctx.K);
	for (i=0; i< klen; i++) {
		printf(" %02X", k[i]);
		if ((i&0xF)==0xF) printf("\n");
	}
	printf("\n");
	uint8_t iv2[] = "\x12\x34\x56\x78";
	uint8_t msg[] =
		"\x11\x22\x33\x44\x55\x66\x77\x00\xFF\xEE\xDD\xCC\xBB\xAA\x99\x88"
		"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xEE\xFF\x0A"
		"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xEE\xFF\x0A\x00"
		"\x22\x33\x44\x55\x66\x77\x88\x99";
	magma_ekb(ctx.K, K, 32,0);
	magma_ctr_acpkm(ctx.K, __builtin_bswap32(*(uint32_t*)iv2), msg, sizeof(msg)-1);
// шифрованный текст
	for (i=0; i< sizeof(msg)-1; i++) {
		printf(" %02X", msg[i]);
		if ((i&0xF)==0xF) printf("\n");
	}
	printf("\n");

}
    return 0;
}
#endif
