/*! AES-CCM 
$ gcc -DTEST_CCM -g -I. -I:/msys64/mingw64/include/glib-2.0 -O3 -march=native -o ccm aes_ccm.c aes.c cipher.c -lglib-2.0
 */
#include <stdint.h>
#include "cipher.h"
#define DBG 0

void printhex(uint8_t *str, uint8_t *data, int len);

typedef  uint32_t uint32x4_t __attribute__((__vector_size__(16)));
typedef  uint16_t uint16x8_t __attribute__((__vector_size__(16)));
typedef   uint8_t uint8x16_t __attribute__((__vector_size__(16)));
typedef uint32x4_t (*CipherEncrypt128)(void *ctx, uint32x4_t src);

static inline uint16x8_t ctr_inc(uint16x8_t ctr)
{
	uint16_t lm = __builtin_bswap16(ctr[7]);
	ctr[7] = __builtin_bswap16(lm+1);
	return ctr;
}
static inline uint16x8_t ctr_init(uint16x8_t ctr)
{
	*(uint8_t*)&ctr&= 0x07;
	ctr[7]  = 0;
	return ctr;
}
static inline uint32x4_t b0_format(AEAD_t *aead, size_t msg_len)
{
	uint32x4_t b = {0};
	uint8_t L = 16- (aead->iv_len+1);
	uint8_t M = (aead->tag_len-2)>>1;
	uint8_t Adata = aead->aad_len>0? 1<<6: 0;
	*(uint8_t*)&b = (uint8_t)(Adata | M<<3 | (L-1)); 
	__builtin_memcpy((uint8_t*)&b+1, aead->iv, aead->iv_len);
	uint16_t lm = __builtin_bswap16(msg_len);
	((uint16_t*)&b)[7] = lm;//	__builtin_memcpy(dst+16-L, &lm, L);
	return b;
}
void aead_ccm_encrypt(AEAD_t *aead, uint8_t *dst, uint8_t *msg, size_t msg_len) 
{
	CipherEncrypt128 encrypt = (CipherEncrypt128)aead->cipher->encrypt;
	uint32x4_t b, y, t;
// 1. Apply the formatting function to (N, A, P) to produce the blocks B0, B1, …, Br.
	b = b0_format(aead, msg_len);
// 2. Set Y0= CIPH_K(B_0).
	y = encrypt(aead->ctx, b);
	uint16x8_t ctr = ctr_init((uint16x8_t)b);// форматирование Flags|| nonce || 0000
	t = encrypt(aead->ctx, (uint32x4_t)ctr);
	// block0_format
	if (aead->aad_len>0) {
		uint8_t * aad = aead->aad;
		int len = aead->aad_len;
		b^=b;
		*(uint16_t*)&b = __builtin_bswap16(aead->aad_len);// могут быть исключения
		__builtin_memcpy((uint8_t*)&b+2, aad, len<14?len:14); 
		y = encrypt(aead->ctx, y ^ b);// B_1
		if (len>14){
			aad+=14; len-=14;
			
			int blocks = len>>4;
			int i;
			for (i=0; i<blocks; i++) {
				__builtin_memcpy(&b, aad, 16); aad+=16;
				y = encrypt(aead->ctx, y ^ b);// B_n
			}
			if (len & 0xF) {
				b ^= b;
				__builtin_memcpy(&b, aad, len&0xF);
				y = encrypt(aead->ctx, y ^ b);// B_n
			}
		}
	}
	if (msg_len>0) {
		int blocks = msg_len>>4;
		int i;
		for (i=0; i<blocks; i++) {
			__builtin_memcpy(&b, msg, 16); msg+=16;
			y = encrypt(aead->ctx, y ^ b);// B_n ^ Y_(n-1)
			ctr = ctr_inc(ctr);
			uint32x4_t s = encrypt(aead->ctx, (uint32x4_t)ctr);
			b^= s;
			__builtin_memcpy(dst, &b, 16); dst+=16;
		}
		if (msg_len & 0xF) {
			b ^= b;
			__builtin_memcpy(&b, msg, msg_len&0xF);
			y = encrypt(aead->ctx, y ^ b);
			ctr = ctr_inc(ctr);
			uint32x4_t s = encrypt(aead->ctx, (uint32x4_t)ctr);
			b^= s;
			__builtin_memcpy(dst, &b, msg_len&0xF); dst+=msg_len&0xF;
		}
	}
	t ^= y;
	__builtin_memcpy(dst, &t, aead->tag_len);
}
int aead_ccm_decrypt(AEAD_t *aead, uint8_t *dst, uint8_t *ct, size_t ct_len) 
{
	int msg_len = ct_len - aead->tag_len;
	if (msg_len < 0) return 1;

	CipherEncrypt128 encrypt = (CipherEncrypt128)aead->cipher->encrypt;
	uint32x4_t b, y, t;
	b = b0_format(aead, msg_len);
	// 8. Set Y0= CIPH_K(B0).
	y = encrypt(aead->ctx, b);
	uint16x8_t ctr = ctr_init((uint16x8_t)b);// форматирование Flags|| nonce || 0000
	t = encrypt(aead->ctx, (uint32x4_t)ctr);
	// 7. apply the formatting function to (N, A, P) to produce the blocks B0, B1, …, Br.
	if (aead->aad_len>0) {
		uint8_t * aad = aead->aad;
		int len = aead->aad_len;
		b^=b;
		*(uint16_t*)&b = __builtin_bswap16(aead->aad_len);// могут быть исключения
		__builtin_memcpy((uint8_t*)&b+2, aad, len<14?len:14); 
		y = encrypt(aead->ctx, y ^ b);// B_1
		if (len>14){
			aad+=14; len-=14;
			
			int blocks = len>>4;
			int i;
			for (i=0; i<blocks; i++) {
				__builtin_memcpy(&b, aad, 16); aad+=16;
				y = encrypt(aead->ctx, y ^ b);
			}
			if (len & 0xF) {
				b ^= b;
				__builtin_memcpy(&b, aad, len&0xF);
				y = encrypt(aead->ctx, y ^ b);
			}
		}
	}
	if (msg_len>0) {
		int blocks = msg_len>>4;
		int i;
		for (i=0; i<blocks; i++) {
			__builtin_memcpy(&b, ct, 16); ct+=16;
			ctr = ctr_inc(ctr);
			uint32x4_t s = encrypt(aead->ctx, (uint32x4_t)ctr);
			b^=s;
			__builtin_memcpy(dst, &b, 16); dst +=16;
			y = encrypt(aead->ctx, y ^ b);
		}
		if (msg_len & 0xF) {
			__builtin_memcpy(&b, ct, msg_len&0xF); ct+=msg_len&0xF;
			ctr = ctr_inc(ctr);
			uint32x4_t s = encrypt(aead->ctx, (uint32x4_t)ctr);
			b^=s;
			__builtin_memcpy(dst, &b, msg_len & 0xF); 
			b^=b;
			__builtin_memcpy(&b, dst, msg_len & 0xF); 
			//__builtin_bzero ((uint8_t*)&b+(msg_len & 0xF), 16-(msg_len & 0xF)); 
			y = encrypt(aead->ctx, y ^ b);
		}
	}
	t ^= y;
	if (__builtin_memcmp(&t, ct, aead->tag_len)!=0) return 1;
	return 0;
}
#ifdef TEST_CCM
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

void hexstr(uint8_t * dst, uint8_t *src, int len)
{
	uint8_t v, ch;
	int i;
	for (i=0; i<len; i++){
		ch = *src++;
		if (!isxdigit(ch)) break;
		v = (ch>='a')?ch-'a'+10:ch-'0';
		ch = *src++;
		if (!isxdigit(ch)) break;
		v<<=4;
		v |= (ch>='a')?ch-'a'+10:ch-'0';
		*dst++ = v;
	}
}
void printhex(uint8_t *str, uint8_t *data, int len)
{
	printf(str);
	int i;
	for(i=0; i<len; i++){
		printf("%02x", data[i]);
	}
	printf("\n");
}
int main ()
{
	Ciph* cipher = cipher_select(CIPH_AES, CIPH_MODE_CCM);
	printf("Cipher '%s'\n", cipher->cipher->name);
if (0) {
	int res, plen =16;
	uint8_t dst[256];
	AEAD_t* aead = (AEAD_t*) cipher;
	printf("C.1 Example 1\n");
	uint8_t key[] = "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f";
	uint8_t N[] = "\x10\x11\x12\x13\x14\x15\x16";
	uint8_t A[] = "\x00\x01\x02\x03\x04\x05\x06\x07";
	uint8_t P[] = "\x20\x21\x22\x23";
	uint8_t T[] = "\x60\x84\x34\x1b";
	uint8_t C[] = "\x71\x62\x01\x5b\x4d\xac\x25\x5d";
	//Klen = 128, Tlen=32, Nlen = 56, Alen = 64, and Plen = 32
	aead->iv  = N;
	aead->aad = A;
	aead->tag = NULL;
	aead->iv_len = 56/8;
	aead->aad_len = 64/8;
	aead->tag_len = 32/8;
	plen = 32/8;
	cipher_set_key(cipher, (uint8_t*)key, 16, 128);
	aead_ccm_encrypt(aead, dst, P, plen);
	printhex("C = ", (uint8_t*)dst, plen + aead->tag_len);
	if (memcmp(dst, C, plen + aead->tag_len)==0) printf("Encrypt ..ok\n");
	res = 
	aead_ccm_decrypt(aead, dst, C, plen + aead->tag_len);
	if (res==0) printf("Tag     ..ok\n");
	if (memcmp(dst, P, plen)==0) printf("Decrypt ..ok\n");
	
	printf("C.2 Example 2\n");
	uint8_t N2[] = "\x10\x11\x12\x13\x14\x15\x16\x17";
	uint8_t A2[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
	uint8_t P2[] = "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f";
	uint8_t C2[] = "\xd2\xa1\xf0\xe0\x51\xea\x5f\x62\x08\x1a\x77\x92\x07\x3d\x59\x3d\x1f\xc6\x4f\xbf\xac\xcd";
	//Klen = 128, Tlen=48, Nlen = 64, Alen = 128, and Plen = 128.
	aead->iv  = N2;
	aead->aad = A2;
	aead->tag = NULL;
	aead->iv_len = 64/8;
	aead->aad_len = 128/8;
	aead->tag_len = 48/8;
	plen = 128/8;
	cipher_set_key(cipher, (uint8_t*)key, 16, 128);
	aead_ccm_encrypt(aead, dst, P2, plen);
	printhex("C = ", (uint8_t*)dst, plen + aead->tag_len);
	if (memcmp(dst, C2, plen + aead->tag_len)==0) printf("Encrypt ..ok\n");
	res = 
	aead_ccm_decrypt(aead, dst, C2, plen + aead->tag_len);
	if (res==0) printf("Tag     ..ok\n");
	if (memcmp(dst, P2, plen)==0) printf("Decrypt ..ok\n");

}
if (1) {
	uint8_t buf[1024];
	char* filename = "VADT128.rsp";//
	FILE *fp =fopen(filename, "r");
	if (fp==NULL) return (1);
	printf(" %s -- Test Vectors\n", filename);
	
	int pt_load = 0, ct_load = 0, decrypt = 0;
	uint32_t Keylen=16, Taglen=0, AADlen=0, PTlen=0, IVlen=0, Count=0;
	uint32_t key[32/4]={0};
	uint8_t iv [1024/8]={0};
	uint8_t aad[1024/8];
	uint8_t ct [1024/8];
	uint8_t pt [1024/8]={0};
	uint8_t tag[32];
	uint32x4_t tag2;
	
	AEAD_t* aead = (AEAD_t*) cipher;
	aead->iv  = iv;
	aead->aad = aad;
	aead->tag = (uint8_t*)&tag2;
	while (fgets(buf, 1024, fp)!=NULL) {
		if (strncmp("Count = ", buf, 8)==0) {
			Count = atol(buf+8);
		} else
		if (strncmp("Key = ", buf, 6)==0) {
			hexstr((uint8_t*)&key, buf+6, Keylen);
			cipher_set_key(cipher, (uint8_t*)key, Keylen, Keylen*8);
		} else
		if (strncmp("Nonce = ", buf, 8)==0) {
			hexstr(iv, buf+8, IVlen);
		} else
		if (strncmp("Payload = ", buf, 10)==0) {
			hexstr(pt, buf+10, PTlen);
			pt_load = 1;
		} else
		if (strncmp("CT = ", buf, 5)==0) {
			hexstr(ct, buf+5, PTlen+Taglen);
			ct_load = 1;
		} else
		if (strncmp("Adata = ", buf, 8)==0) {
			hexstr(aad, buf+8, AADlen);
		} else
		if (strncmp("Plen = ", buf, 7)==0) {
			PTlen = atol(buf+7);
		} else
		if (strncmp("Nlen = ", buf, 7)==0) {
			IVlen = atol(buf+7);
			aead->iv_len = IVlen;
		} else
		if (strncmp("Alen = ", buf, 7)==0) {
			AADlen = atol(buf+7);
			aead->aad_len = AADlen;
		} else
		if (strncmp("Tlen = ", buf, 7)==0) {
			Taglen = atol(buf+7);
			aead->tag_len = Taglen;
		} else
		if (buf[0] == '[')
		{
			if (strncmp("[Plen = ", buf, 8)==0) {
				PTlen = atol(buf+8);
				printf ("[Plen = %d]\n", PTlen);
			} else
			if (strncmp("[Nlen = ", buf, 8)==0) {
				IVlen = atol(buf+8);
				aead->iv_len = IVlen;
				printf ("[Nlen = %d]\n", IVlen);
			} else
			if (strncmp("[Alen = ", buf, 8)==0) {
				AADlen = atol(buf+8);
				aead->aad_len = AADlen;
				printf ("[Alen = %d]\n", AADlen);
			} else
			if (strncmp("[Tlen = ", buf, 8)==0) {
				Taglen = atol(buf+8);
				aead->tag_len = Taglen;
				printf ("[Tlen = %d]\n", Taglen);
			}
		}
		if (ct_load && pt_load) {
			printf("Count = %d\n", Count);
			printhex("Adata = ", (uint8_t*)aad, AADlen);
			printhex("CT = ", (uint8_t*)ct, PTlen+Taglen);

			uint8_t dst[256];
			aead_ccm_encrypt(aead, dst, pt, PTlen);
			//printhex("ct = ", (uint8_t*)dst, PTlen+Taglen);
			if (memcmp(dst, ct, PTlen+Taglen)==0) printf("enc ..ok\n");
			else {
				printf("enc ..fail\n");
				break;
			}
			int res =
			aead_ccm_decrypt(aead, dst, ct, PTlen+Taglen);
			if (res==0) printf("tag ..ok\n");
			else {
				printf("tag ..fail\n");
				break;
			}
			if (memcmp(dst, pt, PTlen)==0) printf("dec ..ok\n");
			else {
				printf("dec ..fail\n");
				break;
			}
			printf("\n");
			ct_load=0; pt_load=0;
		}
	}
	fclose(fp);
}
	return 0;
}
#endif