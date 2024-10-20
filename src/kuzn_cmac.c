/*! ГОСТ Кузнечик. Национальый алгоритм блочного шифрования с длиной блока 128 бит. 
	
	Copyright (c) 2015-2022,2024 Anatoly Georgievskii <anatoly.georgievski@gmail.com>

	\see ГОСТ Р 34.12-2015 КРИПТОГРАФИЧЕСКАЯ ЗАЩИТА ИНФОРМАЦИИ. Блочные шифры
	\see ГОСТ Р 34.13─2015 КРИПТОГРАФИЧЕСКАЯ ЗАЩИТА ИНФОРМАЦИИ. Режимы работы блочных шифров
	\see http://tc26.ru
	[Р 1323565.1.046—2023] (ProtoQa)
	[Р 1323565.1.017—2018] Криптографические алгоритмы, сопутствующие применению алгоритмов блочного шифрования

Отладка
$ gcc -DTEST_CMAC -march=native -O3 -o kuzn kuzn_clmul.c kuzn_cmac.c
$ gcc -DTEST_CMAC -march=native -O3 -o kuzn kuzn_gfni.c  kuzn_cmac.c
 */

#include <stdint.h>
#include <stdio.h>
#include "net.h" // сетевой порядок следования байт ntohll и htonl
//
typedef  uint8_t uint8x16_t __attribute__((__vector_size__(16)));
typedef uint32_t uint32x4_t __attribute__((__vector_size__(16)));
typedef uint64_t uint64x2_t __attribute__((__vector_size__(16)));
typedef   int8_t  int8x16_t __attribute__((__vector_size__(16)));

typedef struct {
  uint8x16_t K[10];
  uint8x16_t sum;
  uint8x16_t last_block;
  uint64_t iv;
  uint32_t cnt;// число итераций ключа
  uint32_t n;// число итераций до смены ключа
  int len;
} KuznCtx;

extern uint8x16_t kuzn_encrypt(KuznCtx* ctx, const uint8x16_t a);
extern void       kuzn_key_expansion(KuznCtx * ctx, const uint8_t* key, int klen, int ekb);


typedef uint8x16_t (*CipherEncrypt128)(KuznCtx*, uint8x16_t);


#define REV128(v) __builtin_shufflevector((uint8x16_t)(v),(uint8x16_t)(v),15,14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
static uint8x16_t GF128_shift(uint8x16_t v)
{
    v = (uint8x16_t)(((int8x16_t)v<<1) ^ (__builtin_shufflevector((int8x16_t)((int8x16_t)v<0),(int8x16_t)v, 15, 0, 1,2,3,4,5,6,7,8,9,10,11,12,13,14) & (int8x16_t){0x87, 0x1,0x1,0x1,0x1, 0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1})) ;
    return v;
}
static void kuzn_cmac_init(KuznCtx *ctx)
{
//	kuzn_key_expansion(ctx, Key, 32, 0);
    ctx->last_block = (uint8x16_t){0};
    ctx->sum = (uint8x16_t){0};
    ctx->len = 0;
}
static void kuzn_cmac_update(KuznCtx* ctx, const uint8_t* data, int len)
{
	const int s=16;
	if ((ctx->len % s)!=0) {// не полный блок.
        int slen = s - ctx->len; // длину берем из данных
        if (slen > len) slen = len;
        __builtin_memcpy(((uint8_t*)&ctx->last_block) + ctx->len, data, slen);
        data+=slen;
        len -=slen;
        ctx->len += slen;
	}
	if (len) {
		uint8x16_t m = ctx->sum,v;
        if (ctx->len == s) {// полный блок и
			__builtin_memcpy(&v, &ctx->last_block,s);
            m = kuzn_encrypt(ctx, m^REV128(v));
//			for (int i=0; i<16; i++) printf("%02X",m[i]); printf("\n");
            ctx->last_block = (uint8x16_t){0};
//			printf("full %d\n", ctx->len);
        }		
		int blocks=(len-1)>>4;// /16
		for (int i=0;i<blocks;i++) {
			__builtin_memcpy(&v, data, s); data+=s;// может быть потребуется вывернуть
			m = kuzn_encrypt(ctx, m^REV128(v));
//			for (int i=0; i<16; i++) printf("%02X",m[i]); printf("\n");
		}
		ctx->sum = m;
		ctx->len = len - blocks*s;
        if (ctx->len) {
            __builtin_memcpy((uint8_t*)&ctx->last_block, data, ctx->len);
//			printf("last %d\n", ctx->len);
        }

	}
}
static void kuzn_cmac_fini(KuznCtx* ctx)
{
	uint8x16_t m = ctx->sum;
    uint8x16_t v = (uint8x16_t){0};
	const int s=16;
    uint8x16_t K1 = kuzn_encrypt(ctx, v);
    K1 = GF128_shift(K1);
	int length = ctx->len;
    if (length==0 || (length & 0xF)){// если длина сообщения не выровнена на 128 бит
        K1 = GF128_shift(K1);
        if(length & 0xF) __builtin_memcpy((void*)&v, &ctx->last_block,(length & 0xF));
        v [length & 0xF]^=0x80;
    } else {
        __builtin_memcpy(&v, &ctx->last_block,16);
    }
    m ^= REV128(v)^K1;
    m = kuzn_encrypt(ctx, m);
    ctx->sum = m;
}
/*! \brief Режим имитовставки CMAC 
 */
static
void kuzn_cmac(KuznCtx *ctx, uint8_t *iv, size_t vlen, uint8_t* data, size_t len)
{
    kuzn_cmac_init(ctx);
    if (vlen) kuzn_cmac_update(ctx, iv, vlen);
    if ( len) kuzn_cmac_update(ctx, data, len);
    kuzn_cmac_fini(ctx);
	//return ctx.sum;
}
#if 1
static inline uint8x16_t CTR128(uint8x16_t x){
    uint64x2_t v = (uint64x2_t)x;
	v[0]++;
    return (uint8x16_t)v;
}
/*! \brief кодирование в режиме CTR
    Функция используется и для кодирования и для декодирования CTR моды
 */
static void kuzn_ctr(KuznCtx* ctx, uint8_t* dst, const uint8_t* src, int length)
{
    uint8x16_t d, v, p;
    v = (uint8x16_t)((uint64x2_t){0,ctx->iv});
    int blocks = length>>4;
    int i;
    for (i=0;i<blocks;i++) {
        d = v;
        v = CTR128(v); // счетчик добавить и копировать
        d = kuzn_encrypt(ctx, d);
        __builtin_memcpy(&p, &src[16*i], 16);
        p^=  REV128(d);
		__builtin_memcpy(&dst[16*i], &p, 16);
    }
    if (length & 0xF){// если длина сообщения не выровнена на 128 бит

    }
}
void kuzn_ACPKM(KuznCtx* ctx)
{
	uint8x16_t d[2] = {
		{0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8A,0x8B,0x8C,0x8D,0x8E,0x8F},
		{0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9A,0x9B,0x9C,0x9D,0x9E,0x9F},
	};
	uint8x16_t v1 = REV128(d[0]);
	uint8x16_t v2 = REV128(d[1]);
	v1 = kuzn_encrypt(ctx, v1);
	v2 = kuzn_encrypt(ctx, v2);
	uint8x16_t k[2] = {REV128(v1),REV128(v2)};
	if (0) for (int i=0; i<16; i++) { // отладка
		printf("%02x", v1[i]);
		if ((i&15)==15) printf("\n");
	}
	kuzn_key_expansion(ctx, (uint8_t*)k, 32,0);
}
/*! \brief кодирование в режиме CTR
    Функция используется и для кодирования и для декодирования CTR моды
 */
static void kuzn_ctr_acpkm(KuznCtx* ctx, uint8_t* dst, const uint8_t* src, int length)
{
    uint8x16_t d, v, p;
    v = (uint8x16_t)((uint64x2_t){0,ctx->iv});
    int blocks = length>>4;
    int i;
    for (i=0;i<blocks;i++) {
        d = v;
        v = CTR128(v); // счетчик добавить и копировать
        d = kuzn_encrypt(ctx, d);
        __builtin_memcpy(&p, &src[16*i], 16);
        p^=  REV128(d);
		__builtin_memcpy(&dst[16*i], &p, 16);
		if (++ctx->cnt == ctx->n) {
			kuzn_ACPKM(ctx);//вращение ключа
			ctx->cnt=0;
		}
    }
    if (length & 0xF){// если длина сообщения не выровнена на 128 бит

    }
}
#endif
/*! \brief режим простой замены */
void kuzn_ecb(KuznCtx* ctx, uint8_t* dst, const uint8_t* src, int length)
{
    uint8x16_t d, v;
    int blocks = length>>4;
    int i;
    for (i=0;i<blocks;i++) {
        __builtin_memcpy(&d, &src[16*i], 16);
        v = kuzn_encrypt(ctx, REV128(d));
        __builtin_memcpy(&dst[16*i], &v, 16);
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
void kuzn_KExp15(uint8_t* data, int klen,
	uint8_t* key_exp_mac, uint8_t* key_exp_enc, uint8_t* iv)
{
	const int iv_len = 8;
	KuznCtx ctx;
	kuzn_key_expansion(&ctx, key_exp_mac, 32, 0);
	kuzn_cmac(&ctx, iv, iv_len, data, klen);
	*(uint8x16_t* )(data+klen) = REV128(ctx.sum);
	kuzn_key_expansion(&ctx, key_exp_enc, 32, 0);
	ctx.iv = ntohll(*(uint64_t*)iv);
	kuzn_ctr(&ctx, data, data, klen+16);
}
/*! \brief Алгоритм импорта ключа KImp15
	\return TRUE если иммитовставка от ключа OMAC сходится.

	\see Р 1323565.1.017—2018  KExp15 KImp15

Для получения ключей 𝐾𝑀𝐴𝐶 𝐸𝑥𝑝 и 𝐾𝐸𝑁𝐶 𝐸𝑥𝑝, помимо KeyWrapID,
допускается использование заранее распределенного ключа
между СКЗИ-потребителем и узлом СВРК. KeyWrapID-  8байт.
    \see МР 26.4.004–2021

 */
int kuzn_KImp15(uint8_t* data, int klen,
	uint8_t* key_exp_mac, uint8_t* key_exp_enc, uint8_t* iv)
{
	const int iv_len = 8;
	KuznCtx ctx;
	kuzn_key_expansion(&ctx, key_exp_enc, 32, 0);
	ctx.iv = ntohll(*(uint64_t*)iv);
	kuzn_ctr(&ctx, data, data, klen+16);
	kuzn_key_expansion(&ctx, key_exp_mac, 32, 0);
	kuzn_cmac(&ctx, iv, iv_len, data, klen);
	uint64x2_t v = (uint64x2_t)(ctx.sum);
//	for (int i=0; i<16; i++) printf("%02x", ctx.sum[i^0xF]); printf("}\n");
		
	return (ntohll(v[1])==*(uint64_t* )(data+klen))
		&& (ntohll(v[0])==*(uint64_t* )(data+klen+8));
}
/*! \brief формирует метку для выработки ключа */
static int _label (uint8_t*  label, const uint8_t* name, const uint8_t* sender_id, const uint8_t* recipient_id, uint16_t id_mk){
	uint8_t* s = label;
	*s++ = name[0];
	*s++ = name[1];
	__builtin_memcpy(s, sender_id, 16); s+=16;
	__builtin_memcpy(s, recipient_id, 16); s+=16;
	*s++ = (id_mk>>8)&0xFF;
	*s++ = (id_mk   )&0xFF;
	return s - label;
}

static void print_data(const char* title, const uint8_t * data, size_t len) 
{
	if (title) printf("%s\n", title);
    int i;
    for (i=0; i<len; i++)   {// распечатываем ключ
        printf("%02x ", data[i]);
        if ((i&15)==15) printf("\n");
	}
	if (i&0x1F) printf("\n");
}
/*! \brief KDF_TREE_CMAC 
	\param label  (name| SenderID| RecipientID | ID_MK | j | t), name = "cr" для протокола или "qk" для обмена ключами ID_MK - два байта
	\param seed 0
	\param R =4, 
 */
static int _kdf_tree_cmac(uint8_t* dk, const uint8_t* key, const uint8_t* label, int llen, uint32_t t, uint32_t seed, int R)
{
	const uint32_t count = 0x10000000uL;
	uint8_t iv[64];
	uint8_t* buf = iv;
	*(uint32_t*)buf = 0;// номер ключа
	buf+=4;
	__builtin_memcpy(buf, label/*"macenc"*/, llen);
	buf+=llen;
	*buf++ = 0x00;
	*(uint32_t*)buf = htonl(seed); buf+=4;
	*(uint32_t*)buf = htonl(count); buf+=4;
	int len = buf-iv;
//	print_data("P=", iv, len);
	
	KuznCtx ctx;
	kuzn_key_expansion(&ctx, key, 32, 0);
	const int N = 2; 
	int i;
	dk+=16*N;
    for (i=0; i<N; i++){
        *(uint32_t*)iv = htonl(++t);// от 1...n
        kuzn_cmac(&ctx, 0, 0,  iv, len);
		dk-=16;
		*(uint64x2_t*)dk = (uint64x2_t)((ctx.sum));
//		*(uint64_t*)dk = v[0]; dk+=8;
//		*(uint64_t*)dk = v[1]; dk+=8;
//		printf("K(%d) = \n", i);
//		print_data(NULL, dk-16, 16);
    }
	return 16*i;
}
#ifdef TEST_CMAC
int main()
{
	
	uint8_t P[] = 
		"\x11\x22\x33\x44\x55\x66\x77\x00\xff\xee\xdd\xcc\xbb\xaa\x99\x88"
		"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xee\xff\x0a"
		"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xee\xff\x0a\x00"
		"\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xee\xff\x0a\x00\x11";
	uint8_t key[] = 
		"\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77"
		"\xfe\xdc\xba\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xab\xcd\xef";
	uint8_t R[] = 
		"\x94\xbe\xc1\x5e\x26\x9c\xf1\xe5\x06\xf0\x2b\x99\x4c\x0a\x8e\xa0";
	uint8_t MAC[] = "\x33\x6f\x4d\x29\x60\x59\xfb\xe3";
	
	uint8_t C[64];
	KuznCtx ctx;
	printf("А.1.1 Режим простой замены ECB\n");
	kuzn_key_expansion(&ctx, key, 32,0);
	kuzn_ecb(&ctx, C, P, 64);
	for (int i=0; i<64; i++) { 
		printf("%02x", C[i^0xF]);
		if ((i&15)==15) printf("\n");
	}
	printf("А.1.2 Режим гаммирования CTR\n");
	ctx.iv = 0x1234567890abcef0ull;
	kuzn_ctr(&ctx, C, P, 64);
	for (int i=0; i<64; i++) { 
		printf("%02x", C[i^0xF]);// наоборот разворачивает порядок байт в векторе
		if ((i&15)==15) printf("\n");
	}

	printf("А.1.6 Режим выработки иммитовставки CMAC\n");
	kuzn_cmac(&ctx, 0,0, P, 64);
	uint64_t mac = ((uint64x2_t)ctx.sum)[1];
	printf("MAC=%016llx\n", mac);
	
	uint8_t key_ac[] = // экспортируемый ключ
		"\x11\x11\x22\x22\x33\x33\x44\x44\x55\x55\x66\x66\x77\x77\x88\x88"
		"\x99\x99\x00\x00\xaa\xaa\xbb\xbb\xcc\xcc\xdd\xdd\xee\xee\xff\xff";
	uint8_t key1[] =
		"\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77"
		"\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF";
	uint8_t key_exp_mac[] =
		"\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x00\x01\x02\x03\x04\x05\x06\x07"
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
	uint8_t key_exp_enc[] =
		"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
		"\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\x30\x31\x32\x33\x34\x35\x36\x37";
	uint8_t key_mac [] = 		
		"\x10\x02\x2a\xde\x94\xee\x55\xb4\x34\xd2\x07\x7f\x5a\x13\xaf\xf4";
	uint8_t iv[] = //"\x67\xBE\xD6\x54";
		"\x09\x09\x47\x2d\xd9\xf2\x6b\xe8";
	uint8_t	data[64];
	//Р 1323565.1.017—2018 Б.2 Алгоритмы экспорта KExp15 и импорта Klmp15 ключа для шифра «Кузнечик»

	__builtin_memcpy(data, key1, 32);
	kuzn_KExp15(data, 32, key_exp_mac, key_exp_enc, iv);
	for (int i=0; i<32+16; i++) { 
		printf("%02x", data[i]);
		if ((i&15)==15) printf("\n");
	}
	int res = 
	kuzn_KImp15(data, 32, key_exp_mac, key_exp_enc, iv);
	if (res) printf("..ok\n");
	for (int i=0; i<32+16; i++) { 
		printf("%02x", data[i]);
		if ((i&15)==15) printf("\n");
	}
	
/* 	Выработка секционных ключей с помощью функции
	преобразования ключа ACPKM */
// Секционный ключ 𝐾_sec
	uint8_t* k_sec[4] = {
		"\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77"
		"\xfe\xdc\xba\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xab\xcd\xef",
		"\x26\x66\xed\x40\xae\x68\x78\x11\x74\x5c\xa0\xb4\x48\xf5\x7a\x7b"
		"\x39\x0a\xdb\x57\x80\x30\x7e\x8e\x96\x59\xac\x40\x3a\xe6\x0c\x60",
		"\xbb\x3d\xd5\x40\x2e\x99\x9b\x7a\x3d\xeb\xb0\xdb\x45\x44\x8e\xc5"
		"\x30\xf0\x73\x65\xdf\xee\x3a\xba\x84\x15\xf7\x7a\xc8\xf3\x4c\xe8",
		"\x23\x36\x2f\xd5\x53\xca\xd2\x17\x82\x99\xa5\xb5\xa2\xd4\x72\x2e"
		"\x3b\xb8\x3c\x73\x0a\x8b\xf5\x7c\xe2\xdd\x00\x40\x17\xf8\xc5\x65"
	};
	printf("ACPKM\n");
	kuzn_key_expansion(&ctx, k_sec[0], 32,0);
	kuzn_ACPKM(&ctx);
	uint8x16_t k1 = (ctx.K[0]);
	if (__builtin_memcmp(k_sec[1], &k1,16)==0) printf("..ok\n");
	for (int i=0; i<16; i++) { 
		printf("%02x", k1[i]);
		if ((i&15)==15) printf("\n");
	}

	kuzn_ACPKM(&ctx);
	kuzn_ACPKM(&ctx);
if(1){// Изменение № 1 ГОСТ 34.13-2018 А.2.8 Режим гаммирования с преобразованием ключа
	printf("CTR-ACPKM А.2.8\n");
	uint8_t P[] = 
/*𝑃1 =*/"\x11\x22\x33\x44\x55\x66\x77\x00\xff\xee\xdd\xcc\xbb\xaa\x99\x88"
/*𝑃2 =*/"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xee\xff\x0a"
/*𝑃3 =*/"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xee\xff\x0a\x00"
/*𝑃4 =*/"\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xee\xff\x0a\x00\x11"
/*𝑃5 =*/"\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xee\xff\x0a\x00\x11\x22"
/*𝑃6 =*/"\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xee\xff\x0a\x00\x11\x22\x33"
/*𝑃7 =*/"\x55\x66\x77\x88\x99\xaa\xbb\xcc\xee\xff\x0a\x00\x11\x22\x33\x44";
	uint8_t ct[] = 
		"\xf1\x95\xd8\xbe\xc1\x0e\xd1\xdb\xd5\x7b\x5f\xa2\x40\xbd\xa1\xb8"
		"\x85\xee\xe7\x33\xf6\xa1\x3e\x5d\xf3\x3c\xe4\xb3\x3c\x45\xde\xe4"
		"\x4b\xce\xeb\x8f\x64\x6f\x4c\x55\x00\x17\x06\x27\x5e\x85\xe8\x00"
		"\x58\x7c\x4d\xf5\x68\xd0\x94\x39\x3e\x48\x34\xaf\xd0\x80\x50\x46"
		"\xcf\x30\xf5\x76\x86\xae\xec\xe1\x1c\xfc\x6c\x31\x6b\x8a\x89\x6e"
		"\xdf\xfd\x07\xec\x81\x36\x36\x46\x0c\x4f\x3b\x74\x34\x23\x16\x3e"
	//	"\x64\x09\xa9\xc2\x82\xfa\xc8\xd4\x69\xd2\x21\xe7\xfd\xd6\xde\x5d";
		"\x64\x09\xa9\xc2\x82\xfa\xc8\xd4\x69\xd2\x21\xe7\xfb\xd6\xde\x5d";
	uint8_t C[16*7];
	kuzn_key_expansion(&ctx, key, 32,0);
	ctx.iv = 0x1234567890abcef0uLL;
	ctx.cnt=0, ctx.n = 2;
	kuzn_ctr_acpkm(&ctx, C, P, 16*7);
	for (int i=0; i<16*7; i++) { 
		printf("%02x", C[i]);
		if ((i&15)==15) printf("\n");
	}
	if (__builtin_memcmp(ct, C,16*7)==0) printf("..ok\n"); 
}
if (1){// Р 1323565.1.046—2023 А.6.2 Вычисление ключей
	printf("Р 1323565.1.046-2023 (ProtoQa)\n");	
	uint8_t m_key[] = 
		"\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77"
		"\xfe\xdc\xba\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xab\xcd\xef";
	
	uint8_t dk[64]; 
	uint8_t label[40]; 
	uint8_t s_id [] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b";
	uint8_t r_id [] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a";
	uint32_t seed_0 = 0;
	uint32_t T = 0x10000000uL;
	int R=4;
	
	int llen = _label(label, "cr", s_id, r_id, 0);
	int t;
	for (t=0; t<4; t+=2){
		_kdf_tree_cmac(dk, m_key, label, llen, t, seed_0, R);
		printf("K(%d)||K(%d) = \n", t+1, t+2);
		print_data(NULL, dk, 32);
	}
	for (; t<0x200000uL; t+=2){
		_kdf_tree_cmac(dk, m_key, label, llen, t, seed_0, R);
	}
	printf("K(0x%x)||K(0x%x) = \n", t-1, t);
	print_data(NULL, dk, 32);
	
}
	return 0;
}
#endif