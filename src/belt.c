/* belt Национальные алгоритмы республики Беларусь
	
	СТБ34.101.31-2020 /-2011 /-2007
	ГОСУДАРСТВЕННЫЙ СТАНДАРТ РЕСПУБЛИКИ БЕЛАРУСЬ
	Информационные технологии и безопасность 
	АЛГОРИТМЫ ШИФРОВАНИЯ И КОНТРОЛЯ ЦЕЛОСТНОСТИ
	http://apmi.bsu.by/assets/files/std/belt-spec37.pdf
	http://apmi.bsu.by/assets/files/std/belt-spec27.pdf
	http://apmi.bsu.by/assets/files/std/belt-spec14.pdf
*/
#include <stdint.h>
#include <string.h>
#include <stdio.h>

typedef uint32_t uint32x4_t  __attribute__((__vector_size__(16)));
static inline uint32_t buf_get_be32(uint8_t* addr)
{
	return __builtin_bswap32(*(uint32_t*)addr);
}
static inline uint32_t buf_put_be32(uint8_t* addr, uint32_t value)
{
	return *(uint32_t*)addr = __builtin_bswap32(value);
}
static inline uint32_t buf_get_le32(uint8_t* addr)
{
	return (*(uint32_t*)addr);
}
static inline uint32_t buf_put_le32(uint8_t* addr, uint32_t value)
{
	return *(uint32_t*)addr = (value);
}
// Упомянули полином P= x8+x6+x5+x2+1, 0x165 
static uint8_t sbox[256] = {
	0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B, 0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4,
	0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC, 0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D,
	0x5B, 0xE3, 0xD6, 0x12, 0x17, 0xB9, 0x61, 0x81, 0xFE, 0x67, 0x86, 0xAD, 0x71, 0x6B, 0x89, 0x0B,
	0x5C, 0xB0, 0xC0, 0xFF, 0x33, 0xC3, 0x56, 0xB8, 0x35, 0xC4, 0x05, 0xAE, 0xD8, 0xE0, 0x7F, 0x99,
	0xE1, 0x2B, 0xDC, 0x1A, 0xE2, 0x82, 0x57, 0xEC, 0x70, 0x3F, 0xCC, 0xF0, 0x95, 0xEE, 0x8D, 0xF1,
	0xC1, 0xAB, 0x76, 0x38, 0x9F, 0xE6, 0x78, 0xCA, 0xF7, 0xC6, 0xF8, 0x60, 0xD5, 0xBB, 0x9C, 0x4F,
	0xF3, 0x3C, 0x65, 0x7B, 0x63, 0x7C, 0x30, 0x6A, 0xDD, 0x4E, 0xA7, 0x79, 0x9E, 0xB2, 0x3D, 0x31,
	0x3E, 0x98, 0xB5, 0x6E, 0x27, 0xD3, 0xBC, 0xCF, 0x59, 0x1E, 0x18, 0x1F, 0x4C, 0x5A, 0xB7, 0x93,
	0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6, 0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47,
	0x06, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37, 0x39, 0xCB, 0xA3, 0x83, 0x03, 0xA9, 0x8B, 0xF6,
	0x92, 0xBD, 0x9B, 0x1C, 0xE5, 0xD1, 0x41, 0x01, 0x54, 0x45, 0xFB, 0xC9, 0x5E, 0x4D, 0x0E, 0xF2,
	0x68, 0x20, 0x80, 0xAA, 0x22, 0x7D, 0x64, 0x2F, 0x26, 0x87, 0xF9, 0x34, 0x90, 0x40, 0x55, 0x11,
	0xBE, 0x32, 0x97, 0x13, 0x43, 0xFC, 0x9A, 0x48, 0xA0, 0x2A, 0x88, 0x5F, 0x19, 0x4B, 0x09, 0xA1,
	0x7E, 0xCD, 0xA4, 0xD0, 0x15, 0x44, 0xAF, 0x8C, 0xA5, 0x84, 0x50, 0xBF, 0x66, 0xD2, 0xE8, 0x8A,
	0xA2, 0xD7, 0x46, 0x52, 0x42, 0xA8, 0xDF, 0xB3, 0x69, 0x74, 0xC5, 0x51, 0xEB, 0x23, 0x29, 0x21,
	0xD4, 0xEF, 0xD9, 0xB4, 0x3A, 0x62, 0x28, 0x75, 0x91, 0x14, 0x10, 0xEA, 0x77, 0x6C, 0xDA, 0x1D,
};
static inline uint32_t G(uint32_t x, int n) {
	union {
		uint8_t b[4];
		uint32_t u32;
	} v;
	v.u32 = x;
	v.b[0] = sbox[v.b[0]];
	v.b[1] = sbox[v.b[1]];
	v.b[2] = sbox[v.b[2]];
	v.b[3] = sbox[v.b[3]];
	return (v.u32<<n) ^ (v.u32>>(32-n)); 
}

#define BELT_ROUND(a, b, c, d, i)   \
  do {                                  \
		b = b ^ G(a+k[(7*(i)+6)& 0x7],5);	\
		c = c ^ G(d+k[(7*(i)+5)& 0x7],21);\
		a = a - G(b+k[(7*(i)+4)& 0x7],13);\
		e = (i+1) ^ G(b+c+k[(7*(i)+3)& 0x7],21);	\
		b = b + e;	\
		c = c - e;	\
		d = d + G(c+k[(7*(i)+2)& 0x7],13);	\
		b = b ^ G(a+k[(7*(i)+1)& 0x7],21);	\
		c = c ^ G(d+k[(7*(i)+0)& 0x7],5);	\
  } while(0)
#define BELT_ROUND1(a, b, c, d, i)   \
  do {                                  \
		b = b ^ G(a+k[(7*(i)+0)& 0x7],5);	\
		c = c ^ G(d+k[(7*(i)+1)& 0x7],21);\
		a = a - G(b+k[(7*(i)+2)& 0x7],13);\
		e = (i+1) ^ G(b+c+k[(7*(i)+3)& 0x7],21);	\
		b = b + e;	\
		c = c - e;	\
		d = d + G(c+k[(7*(i)+4)& 0x7],13);	\
		b = b ^ G(a+k[(7*(i)+5)& 0x7],21);	\
		c = c ^ G(d+k[(7*(i)+6)& 0x7],5);	\
  } while(0)
uint32x4_t belt_decrypt(uint32_t *k, uint32_t* x)
{
	uint32_t a=(x[0]);// buf_get_be32(x[0])
	uint32_t b=(x[1]);
	uint32_t c=(x[2]);
	uint32_t d=(x[3]);
	uint32_t e;
	
	BELT_ROUND(a, b, c, d, 7);
	BELT_ROUND(c, a, d, b, 6);
	BELT_ROUND(d, c, b, a, 5);
	BELT_ROUND(b, d, a, c, 4);

	BELT_ROUND(a, b, c, d, 3);
	BELT_ROUND(c, a, d, b, 2);
	BELT_ROUND(d, c, b, a, 1);
	BELT_ROUND(b, d, a, c, 0);
	return (uint32x4_t){c,a,d,b};// 
}
uint32x4_t belt_encrypt(uint32_t *k, uint32_t* x)
{
	uint32_t a=(x[0]);
	uint32_t b=(x[1]);
	uint32_t c=(x[2]);
	uint32_t d=(x[3]);
	uint32_t e;

	BELT_ROUND1(a, b, c, d, 0);
	BELT_ROUND1(b, d, a, c, 1);
	BELT_ROUND1(d, c, b, a, 2);
	BELT_ROUND1(c, a, d, b, 3);

	BELT_ROUND1(a, b, c, d, 4);
	BELT_ROUND1(b, d, a, c, 5);
	BELT_ROUND1(d, c, b, a, 6);
	BELT_ROUND1(c, a, d, b, 7);
	return (uint32x4_t){b,d,a,c};
}
void belt_key_expand(uint32_t *K, uint8_t* key, int klen)
{
	if (key!=(uint8_t*)K) {
		K[0] = (*(uint32_t*)key); key+=4;
		K[1] = (*(uint32_t*)key); key+=4;
		K[2] = (*(uint32_t*)key); key+=4;
		K[3] = (*(uint32_t*)key); key+=4;
	}
	if (klen == 4){
		K[4] = K[0];
		K[5] = K[1];
		K[6] = K[2];
		K[7] = K[3];
	}
	else if (klen == 6){
		K[4] = (*(uint32_t*)key); key+=4;
		K[5] = (*(uint32_t*)key); key+=4;
		K[6] = K[0] ^ K[1] ^ K[2];
		K[7] = K[3] ^ K[4] ^ K[5];
	}
}
#ifdef TEST_BELT
#define BE(x) ((x>>24) | (x<<24) | ((x&0xFF0000)>>8) | ((x&0xFF00)<<8))
int main()
{
	uint32_t X[] = {BE(0xB194BAC8UL), BE(0x0A08F53BUL), BE(0x366D008EUL), BE(0x584A5DE4UL)};// начало таблицы s-box
	uint32_t K[] = {BE(0xE9DEE72CUL), BE(0x8F0C0FA6UL), BE(0x2DDB49F4UL), BE(0x6F739647UL), BE(0x06075316UL), BE(0xED247A37UL), BE(0x39CBA383UL), BE(0x03A98BF6UL)};
	uint32_t Y[] = {BE(0x69CCA1C9UL), BE(0x3557C9E3UL), BE(0xD66BC3E0UL), BE(0xFA88FA6EUL)};
	uint32_t rk[8];
	belt_key_expand(rk, (uint8_t*)K, 4);
	uint32x4_t v;
	printf(" А.1 — Зашифрование блока\n");
	v = belt_encrypt(K, X);
	printf("Y= %08X %08X %08X %08X ..%s\n", v[0],v[1],v[2],v[3], __builtin_memcmp(Y, &v, 16)==0? "ok":"fail");
	
	printf(" А.4 — Расшифрование блока\n");
	uint32_t C4[] = {BE(0xE12BDC1AUL), BE(0xE28257ECUL), BE(0x703FCCF0UL), BE(0x95EE8DF1UL)};
	uint32_t K4[] = {BE(0x92BD9B1CUL), BE(0xE5D14101UL), BE(0x5445FBC9UL), BE(0x5E4D0EF2UL), BE(0x682080AAUL), BE(0x227D642FUL), BE(0x2687F934UL), BE(0x90405511UL)};
	uint32_t P4[] = {BE(0x0DC53006UL), BE(0x00CAB840UL), BE(0xB38448E5UL), BE(0xE993F421UL)};
	v = belt_decrypt(K4, C4);
	printf("Y= %08X %08X %08X %08X ..%s\n", v[0],v[1],v[2],v[3], __builtin_memcmp(P4, &v, 16)==0? "ok":"fail");
	return 0;
}
#endif // TEST_BELT
