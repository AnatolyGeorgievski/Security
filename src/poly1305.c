/*! \brief Оптимизация Алгоритма Poly1305
	\see [RFC 8439] ChaCha20 & Poly1305                 June 2018
TEST:
	$ gcc -DTEST_POLY1305 -O3 -march=native -o poly1305 poly1305.c
	$ g++ -march=native -dM -E - </dev/null
	
2.5.1.  The Poly1305 Algorithms in Pseudocode

      clamp(r): r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
      poly1305_mac(msg, key):
         r = le_bytes_to_num(key[0..15])
         clamp(r)
         s = le_bytes_to_num(key[16..31])
         a = 0  // a is the accumulator
         p = (1<<130)-5
         for i=1 upto ceil(msg length in bytes / 16)
            n = le_bytes_to_num(msg[((i-1)*16)..(i*16)] | [0x01])
            a += n
            a = (r * a) % p
            end
         a += s
         return num_to_16_le_bytes(a)
         end
 */
#include <stdint.h>
#include <stdio.h>

#define DBG 0

#if defined(__x86_64__)
#include	<intrin.h>
#if defined(__SIZEOF_INT128__)
	typedef unsigned __int128 uint128_t;
#else
	typedef unsigned uint128_t __attribute__((mode(TI)));
#endif

typedef uint64_t uint64x2_t __attribute__((__vector_size__(16)));
typedef uint32_t uint32x4_t __attribute__((__vector_size__(16)));
static uint32_t add128(uint32_t c, uint64_t *a, uint64x2_t b)
{
	unsigned char cy=0;
	cy = _addcarry_u64(cy,a[0],b[0], &a[0]); 
	cy = _addcarry_u64(cy,a[1],b[1], &a[1]); 
	return c+cy;
}
static void p130_modP(uint32_t cy, uint64_t *a)
{
	if (cy>3 || (cy==3 && a[1]==~0ULL && a[0]>=~4ULL)) {// {cy,a}>=prime
		unsigned char cx=0;
		cx = _addcarry_u64(cx, a[0], 5, &a[0]);
		cx = _addcarry_u64(cx, a[1], 0, &a[1]);
	}
}
static uint32_t mul128(uint32_t cy, uint64_t *a, uint64x2_t r)
{
	uint64x2_t r_modP = (r>>2)*5;
	uint128_t l = a[0]*(uint128_t)r[0] + a[1]*(uint128_t)r_modP[1];// + cy*r_modP[0];
	uint128_t m = a[1]*(uint128_t)r[0] + a[0]*(uint128_t)r[1]      + cy*r_modP[1];
	uint64_t  h =  (r[0])*cy;//(r[0]&3)*cy;
	m+= (l>>64);
	h+= (m>>64);
	unsigned char cx=0;
	cx = _addcarry_u64(cx, (uint64_t)l, (h>>2)*5, &a[0]);
	cx = _addcarry_u64(cx, (uint64_t)m, 0, &a[1]);
	// редуцирование не полное, следим чтобы результат укладывался в 130 бит
	return (h&3) + cx;
}
#else// defined(__i386__)
#include	<intrin.h>
#define NOADDCARRY

typedef uint64_t uint64x4_t __attribute__((__vector_size__(32)));
typedef uint64_t uint64x2_t __attribute__((__vector_size__(16)));
typedef uint32_t uint32x4_t __attribute__((__vector_size__(16)));

static 
uint32_t add128(uint32_t c, uint64_t *a_, uint64x2_t b_)
{
	uint32_t *a = (uint32_t*)a_;
	uint32x4_t b = (uint32x4_t)b_;
#ifdef NOADDCARRY
	uint64_t v;
	a[0] = v = (uint64_t)a[0]+b[0];//+ (uint64_t)(c>>2)*5;
	a[1] = v = (uint64_t)a[1]+b[1]+ (v>>32);
	a[2] = v = (uint64_t)a[2]+b[2]+ (v>>32);
	a[3] = v = (uint64_t)a[3]+b[3]+ (v>>32);
	return (c)+(v>>32);// (c&3)
#else
	unsigned char cy=0;
	cy = _addcarry_u32(cy,a[0],b[0], &a[0]); 
	cy = _addcarry_u32(cy,a[1],b[1], &a[1]); 
	cy = _addcarry_u32(cy,a[2],b[2], &a[2]); 
	cy = _addcarry_u32(cy,a[3],b[3], &a[3]); 
	return c+cy;
#endif
}
static 
void p130_modP(uint32_t cy, uint64_t *a_)
{
	uint32_t *a = (uint32_t*)a_;
	if (cy>3 || (cy==3 && a[3]==~0UL && a[2]==~0UL && a[1]==~0UL && a[0]>=~4UL)) {// {cy,a}>=prime
#ifdef NOADDCARRY
		uint64_t v;
		a[0] = v = (uint32_t)a[0] + (uint64_t)5;
		a[1] = v = (uint32_t)a[1] + (v>>32);
		a[2] = v = (uint32_t)a[2] + (v>>32);
		a[3] = v = (uint32_t)a[3] + (v>>32);
#else
		unsigned char cx=0;
		cx = _addcarry_u32(cx, a[0], 5, &a[0]);
		cx = _addcarry_u32(cx, a[1], 0, &a[1]);
		cx = _addcarry_u32(cx, a[2], 0, &a[2]);
		cx = _addcarry_u32(cx, a[3], 0, &a[3]);
#endif
	}
}
/*! Алгоритм умножения в поле простого числа P=x^130 - 5. вариант для уноженя 32х32=64 бит
 */
static
uint32_t mul128(uint32_t ca, uint64_t *a_,  uint64x2_t r_)
{
	uint32_t *a = (uint32_t*)a_;
	uint32x4_t r = (uint32x4_t)r_;
	uint32x4_t r5 = (r>>2)*5;// (r[i]<<128) mod P
	uint64x4_t v;
	// можно использовать попарное горизонтальное суммирование и умножение с накоплением \see ARM-Neon VMULL VMLAL UMLAL
	// Эту матрицу можно векторизовать VPMULUDQ 256 
	v[0] = (uint64_t)r5[3]*a[1] + (uint64_t)r5[2]*a[2] + (uint64_t)r5[1]*a[3] + (uint64_t)r[0]*a[0]+(uint64_t)r5[0]*ca;
	v[1] = (uint64_t)r5[3]*a[2] + (uint64_t)r5[2]*a[3] + (uint64_t)r [1]*a[0] + (uint64_t)r[0]*a[1]+(uint64_t)r5[1]*ca;//+(v[0]>>32);
	v[2] = (uint64_t)r5[3]*a[3] + (uint64_t)r [2]*a[0] + (uint64_t)r [1]*a[1] + (uint64_t)r[0]*a[2]+(uint64_t)r5[2]*ca;//+(v[1]>>32);
	v[3] = (uint64_t)r [3]*a[0] + (uint64_t)r [2]*a[1] + (uint64_t)r [1]*a[2] + (uint64_t)r[0]*a[3]+(uint64_t)r5[3]*ca;//+(v[2]>>32);

	uint32_t h = (r[0]&3)*ca;
	v[1] += (v[0]>>32);
	v[2] += (v[1]>>32);
	v[3] += (v[2]>>32);
	h    += (v[3]>>32);
// не полное редуцирование по полиному x130-5
#ifdef NOADDCARRY
	a[0] = v[0] = (uint32_t)v[0] + (uint64_t)(h>>2)*5;
	a[1] = v[1] = (uint32_t)v[1] + (v[0]>>32);
	a[2] = v[2] = (uint32_t)v[2] + (v[1]>>32);
	a[3] = v[3] = (uint32_t)v[3] + (v[2]>>32);
	return (h&3) + (v[3]>>32);
#else
	unsigned char cx=0;
	cx = _addcarry_u32(cx, (uint32_t)v[0], (h>>2)*5, &a[0]);
	cx = _addcarry_u32(cx, (uint32_t)v[1], 0, &a[1]);
	cx = _addcarry_u32(cx, (uint32_t)v[2], 0, &a[2]);
	cx = _addcarry_u32(cx, (uint32_t)v[3], 0, &a[3]);
	return (h&3) + cx;
#endif
}
#endif

void poly1305_mac(uint8_t *key, uint8_t *tag, uint8_t *src, int len)
{
	uint64_t a[2] = {0}; 
	uint64x2_t r;
	uint64x2_t s;
	uint64x2_t n;
	__builtin_memcpy(&r, key   , 16);
	r &= (uint64x2_t){0x0ffffffc0fffffffULL,0x0ffffffc0ffffffcULL};
	__builtin_memcpy(&s, key+16, 16);
	uint32_t cy = 0;
	int i;
	int blocks = len>>4;
	for (i=0;i<blocks; i++) {
		__builtin_memcpy(&n, src, 16); src+=16;
		cy = add128(cy, a, n)+0x01U;// бит в разряде x^128
		if(DBG)printf("A+B: %02x%016llx%016llx\n", cy, a[1],a[0]);
		cy = mul128(cy, a, r); // c0+=r[0]*(cy+1);// 2M

	}
	if (len& 0xF){
		n^=n;
		__builtin_memcpy(&n, src, len&0xF);
		n[(len& 0xF)>>3] |= 1ULL<<((len& 0x7)*8);// бит в разряде x^N
		
		cy = add128(cy, a, n);// a+=n
		if(DBG)printf("A+B: %02x%016llx%016llx\n", cy, a[1],a[0]);
		cy = mul128(cy, a, r);// (a+n)*r
	}
	cy = add128(cy, a, s);
	// редуцирование финальное
	p130_modP(cy, a);
	__builtin_memcpy(tag, a, 16);
}
#ifdef TEST_POLY1305
void printhex(uint8_t* str, uint8_t*d, int len)
{
	printf("%s:\n", str);
	int i;
	for(i=0; i< len; i++)
		printf("%02X ", d[i]);
	printf("\n");
}
int main(){
	uint8_t key[] = 
	"\x85\xd6\xbe\x78\x57\x55\x6d\x33\x7f\x44\x52\xfe\x42\xd5\x06\xa8"
	"\x01\x03\x80\x8a\xfb\x0d\xb2\xfd\x4a\xbf\xf6\xaf\x41\x49\xf5\x1b";
  //Message to be Authenticated:
	uint8_t msg[] = 
	"\x43\x72\x79\x70\x74\x6f\x67\x72\x61\x70\x68\x69\x63\x20\x46\x6f" //  Cryptographic Fo
	"\x72\x75\x6d\x20\x52\x65\x73\x65\x61\x72\x63\x68\x20\x47\x72\x6f" //  rum Research Gro
	"\x75\x70";                                                        //  up
	uint8_t tag[] = 
	"\xa8\x06\x1d\xc1\x30\x51\x36\xc6\xc2\x2b\x8b\xaf\x0c\x01\x27\xa9";
	uint8_t dst[16];
	poly1305_mac(key, dst, msg, sizeof(msg)-1);
	if (__builtin_memcmp(dst, tag, 16)==0) printf("..ok\n");

	uint8_t key1[] = 
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t msg1[] = 
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t tag1[] =
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	poly1305_mac(key1, dst, msg1, sizeof(msg1)-1);
	if (__builtin_memcmp(dst, tag1, 16)==0) printf("Test Vector #1: ..ok\n");

	uint8_t key2[] = 
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x36\xe5\xf6\xb5\xc5\xe0\x60\x70\xf0\xef\xca\x96\x22\x7a\x86\x3e";
	uint8_t msg2[] = 
	"\x41\x6e\x79\x20\x73\x75\x62\x6d\x69\x73\x73\x69\x6f\x6e\x20\x74"
	"\x6f\x20\x74\x68\x65\x20\x49\x45\x54\x46\x20\x69\x6e\x74\x65\x6e"
	"\x64\x65\x64\x20\x62\x79\x20\x74\x68\x65\x20\x43\x6f\x6e\x74\x72"
	"\x69\x62\x75\x74\x6f\x72\x20\x66\x6f\x72\x20\x70\x75\x62\x6c\x69"
	"\x63\x61\x74\x69\x6f\x6e\x20\x61\x73\x20\x61\x6c\x6c\x20\x6f\x72"
	"\x20\x70\x61\x72\x74\x20\x6f\x66\x20\x61\x6e\x20\x49\x45\x54\x46"
	"\x20\x49\x6e\x74\x65\x72\x6e\x65\x74\x2d\x44\x72\x61\x66\x74\x20"
	"\x6f\x72\x20\x52\x46\x43\x20\x61\x6e\x64\x20\x61\x6e\x79\x20\x73"
	"\x74\x61\x74\x65\x6d\x65\x6e\x74\x20\x6d\x61\x64\x65\x20\x77\x69"
	"\x74\x68\x69\x6e\x20\x74\x68\x65\x20\x63\x6f\x6e\x74\x65\x78\x74"
	"\x20\x6f\x66\x20\x61\x6e\x20\x49\x45\x54\x46\x20\x61\x63\x74\x69"
	"\x76\x69\x74\x79\x20\x69\x73\x20\x63\x6f\x6e\x73\x69\x64\x65\x72"
	"\x65\x64\x20\x61\x6e\x20\x22\x49\x45\x54\x46\x20\x43\x6f\x6e\x74"
	"\x72\x69\x62\x75\x74\x69\x6f\x6e\x22\x2e\x20\x53\x75\x63\x68\x20"
	"\x73\x74\x61\x74\x65\x6d\x65\x6e\x74\x73\x20\x69\x6e\x63\x6c\x75"
	"\x64\x65\x20\x6f\x72\x61\x6c\x20\x73\x74\x61\x74\x65\x6d\x65\x6e"
	"\x74\x73\x20\x69\x6e\x20\x49\x45\x54\x46\x20\x73\x65\x73\x73\x69"
	"\x6f\x6e\x73\x2c\x20\x61\x73\x20\x77\x65\x6c\x6c\x20\x61\x73\x20"
	"\x77\x72\x69\x74\x74\x65\x6e\x20\x61\x6e\x64\x20\x65\x6c\x65\x63"
	"\x74\x72\x6f\x6e\x69\x63\x20\x63\x6f\x6d\x6d\x75\x6e\x69\x63\x61"
	"\x74\x69\x6f\x6e\x73\x20\x6d\x61\x64\x65\x20\x61\x74\x20\x61\x6e"
	"\x79\x20\x74\x69\x6d\x65\x20\x6f\x72\x20\x70\x6c\x61\x63\x65\x2c"
	"\x20\x77\x68\x69\x63\x68\x20\x61\x72\x65\x20\x61\x64\x64\x72\x65"
	"\x73\x73\x65\x64\x20\x74\x6f";
	uint8_t tag2[] =
	"\x36\xe5\xf6\xb5\xc5\xe0\x60\x70\xf0\xef\xca\x96\x22\x7a\x86\x3e";
	poly1305_mac(key2, dst, msg2, sizeof(msg2)-1);
	if (__builtin_memcmp(dst, tag2, 16)==0) printf("Test Vector #2: ..ok\n");

	uint8_t key3[] = 
	"\x36\xe5\xf6\xb5\xc5\xe0\x60\x70\xf0\xef\xca\x96\x22\x7a\x86\x3e"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t msg3[] = 
	"\x41\x6e\x79\x20\x73\x75\x62\x6d\x69\x73\x73\x69\x6f\x6e\x20\x74"
	"\x6f\x20\x74\x68\x65\x20\x49\x45\x54\x46\x20\x69\x6e\x74\x65\x6e"
	"\x64\x65\x64\x20\x62\x79\x20\x74\x68\x65\x20\x43\x6f\x6e\x74\x72"
	"\x69\x62\x75\x74\x6f\x72\x20\x66\x6f\x72\x20\x70\x75\x62\x6c\x69"
	"\x63\x61\x74\x69\x6f\x6e\x20\x61\x73\x20\x61\x6c\x6c\x20\x6f\x72"
	"\x20\x70\x61\x72\x74\x20\x6f\x66\x20\x61\x6e\x20\x49\x45\x54\x46"
	"\x20\x49\x6e\x74\x65\x72\x6e\x65\x74\x2d\x44\x72\x61\x66\x74\x20"
	"\x6f\x72\x20\x52\x46\x43\x20\x61\x6e\x64\x20\x61\x6e\x79\x20\x73"
	"\x74\x61\x74\x65\x6d\x65\x6e\x74\x20\x6d\x61\x64\x65\x20\x77\x69"
	"\x74\x68\x69\x6e\x20\x74\x68\x65\x20\x63\x6f\x6e\x74\x65\x78\x74"
	"\x20\x6f\x66\x20\x61\x6e\x20\x49\x45\x54\x46\x20\x61\x63\x74\x69"
	"\x76\x69\x74\x79\x20\x69\x73\x20\x63\x6f\x6e\x73\x69\x64\x65\x72"
	"\x65\x64\x20\x61\x6e\x20\x22\x49\x45\x54\x46\x20\x43\x6f\x6e\x74"
	"\x72\x69\x62\x75\x74\x69\x6f\x6e\x22\x2e\x20\x53\x75\x63\x68\x20"
	"\x73\x74\x61\x74\x65\x6d\x65\x6e\x74\x73\x20\x69\x6e\x63\x6c\x75"
	"\x64\x65\x20\x6f\x72\x61\x6c\x20\x73\x74\x61\x74\x65\x6d\x65\x6e"
	"\x74\x73\x20\x69\x6e\x20\x49\x45\x54\x46\x20\x73\x65\x73\x73\x69"
	"\x6f\x6e\x73\x2c\x20\x61\x73\x20\x77\x65\x6c\x6c\x20\x61\x73\x20"
	"\x77\x72\x69\x74\x74\x65\x6e\x20\x61\x6e\x64\x20\x65\x6c\x65\x63"
	"\x74\x72\x6f\x6e\x69\x63\x20\x63\x6f\x6d\x6d\x75\x6e\x69\x63\x61"
	"\x74\x69\x6f\x6e\x73\x20\x6d\x61\x64\x65\x20\x61\x74\x20\x61\x6e"
	"\x79\x20\x74\x69\x6d\x65\x20\x6f\x72\x20\x70\x6c\x61\x63\x65\x2c"
	"\x20\x77\x68\x69\x63\x68\x20\x61\x72\x65\x20\x61\x64\x64\x72\x65"
	"\x73\x73\x65\x64\x20\x74\x6f";
	uint8_t tag3[] =
	"\xf3\x47\x7e\x7c\xd9\x54\x17\xaf\x89\xa6\xb8\x79\x4c\x31\x0c\xf0";
	poly1305_mac(key3, dst, msg3, sizeof(msg3)-1);
	if (__builtin_memcmp(dst, tag3, 16)==0) printf("Test Vector #3: ..ok\n");

	uint8_t key4[] = 
	"\x1c\x92\x40\xa5\xeb\x55\xd3\x8a\xf3\x33\x88\x86\x04\xf6\xb5\xf0"
	"\x47\x39\x17\xc1\x40\x2b\x80\x09\x9d\xca\x5c\xbc\x20\x70\x75\xc0";
	uint8_t msg4[] = 
	"\x27\x54\x77\x61\x73\x20\x62\x72\x69\x6c\x6c\x69\x67\x2c\x20\x61"
	"\x6e\x64\x20\x74\x68\x65\x20\x73\x6c\x69\x74\x68\x79\x20\x74\x6f"
	"\x76\x65\x73\x0a\x44\x69\x64\x20\x67\x79\x72\x65\x20\x61\x6e\x64"
	"\x20\x67\x69\x6d\x62\x6c\x65\x20\x69\x6e\x20\x74\x68\x65\x20\x77"
	"\x61\x62\x65\x3a\x0a\x41\x6c\x6c\x20\x6d\x69\x6d\x73\x79\x20\x77"
	"\x65\x72\x65\x20\x74\x68\x65\x20\x62\x6f\x72\x6f\x67\x6f\x76\x65"
	"\x73\x2c\x0a\x41\x6e\x64\x20\x74\x68\x65\x20\x6d\x6f\x6d\x65\x20"
	"\x72\x61\x74\x68\x73\x20\x6f\x75\x74\x67\x72\x61\x62\x65\x2e";  
	uint8_t tag4[] =
	"\x45\x41\x66\x9a\x7e\xaa\xee\x61\xe7\x08\xdc\x7c\xbc\xc5\xeb\x62";
	poly1305_mac(key4, dst, msg4, sizeof(msg4)-1);
	if (__builtin_memcmp(dst, tag4, 16)==0) printf("Test Vector #4: ..ok\n");
	
	uint8_t key5[] = 
	"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t msg5[] = 
	"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	uint8_t tag5[] =
	"\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	poly1305_mac(key5, dst, msg5, sizeof(msg5)-1);
	if (__builtin_memcmp(dst, tag5, 16)==0) printf("Test Vector #5: ..ok\n");

	uint8_t key6[] = 
	"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	uint8_t msg6[] = 
	"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t tag6[] =
	"\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	poly1305_mac(key6, dst, msg6, sizeof(msg5)-1);
	if (__builtin_memcmp(dst, tag6, 16)==0) printf("Test Vector #6: ..ok\n");

	uint8_t key7[] = 
	"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t msg7[] = 
	"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
	"\xF0\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
	"\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t tag7[] =
	"\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	poly1305_mac(key7, dst, msg7, sizeof(msg7)-1);
	if (__builtin_memcmp(dst, tag7, 16)==0) printf("Test Vector #7: ..ok\n");
	else {
		printhex("tag", dst, 16);
	}

	uint8_t key8[] =
	"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t msg8[] = 
	"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
	"\xFB\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE"
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";
	uint8_t tag8[] =
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	poly1305_mac(key8, dst, msg8, sizeof(msg8)-1);
	if (__builtin_memcmp(dst, tag8, 16)==0) printf("Test Vector #8: ..ok\n");

	uint8_t key9[] =
	"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t msg9[] = 
	"\xFD\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	uint8_t tag9[] =
	"\xFA\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	poly1305_mac(key9, dst, msg9, sizeof(msg9)-1);
	if (__builtin_memcmp(dst, tag9, 16)==0) printf("Test Vector #9: ..ok\n");
	else printhex("tag", dst, 16);

	uint8_t key10[] =
	"\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t msg10[] = 
	"\xE3\x35\x94\xD7\x50\x5E\x43\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x33\x94\xD7\x50\x5E\x43\x79\xCD\x01\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t tag10[] = 
	"\x14\x00\x00\x00\x00\x00\x00\x00\x55\x00\x00\x00\x00\x00\x00\x00";
	poly1305_mac(key10, dst, msg10, sizeof(msg10)-1);
	if (__builtin_memcmp(dst, tag10, 16)==0) printf("Test Vector #10: ..ok\n");
	else printhex("tag", dst, 16);

	uint8_t key11[] =
	"\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t msg11[] = 
	"\xE3\x35\x94\xD7\x50\x5E\x43\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x33\x94\xD7\x50\x5E\x43\x79\xCD\x01\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t tag11[] = 
	"\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	poly1305_mac(key11, dst, msg11, sizeof(msg11)-1);
	if (__builtin_memcmp(dst, tag11, 16)==0) printf("Test Vector #11: ..ok\n");
	else printhex("tag", dst, 16);


	return 0;
}
#endif