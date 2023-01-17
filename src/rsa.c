/*! RSA
    PKCS#1 V2.2: RSA CRYPTOGRAPHY STANDARD
    \see http://www.rsa.com/rsalabs/node.asp?id=2125
    \see [RFC 3447] Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography Specifications Version 2.1, February 2003
    \see [RFC 8017] PKCS #1: RSA Cryptography Specifications Version 2.2, November 2016
    примитивы:
    - I20SP преобразование из целого в строку
    - SO2IP из строки в целое
    - RSAEP encryption
    - RSADP decription
    - EME-OAEP схема кодирования сообщения

тестирование
    $ gcc -Os -o rsa.exe rsa.c bn_asm.c sha.c
$ gcc -m64 `pkg-config.exe --cflags --libs glib-2.0` -DDEBUG_RSA1 -O3 -o rsa.exe rsa.c bn_asm.c sha.c hmac.c mpz.c mpz_asm.c sign.c rsa_pkcs_test_1536.c -lglib-2.0

 */
#include "mpz.h"
#include "rsa.h"
#include "hmac.h"
#include "sign.h"
#include <string.h>
#include <stdio.h>
#include <malloc.h>
#if defined(__sun__) || defined(__linux__)
#define _aligned_malloc(size, align) memalign(align, size)
#define _aligned_free(ptr) free(ptr)
#endif // __sun__ __linux__
static inline unsigned int char2bin(char ch)
{
    unsigned int val=0;
    if (ch>='0' && ch<='9') val = ch-'0';
    else if (ch>='a' && ch<='f') val = ch-'a'+10;
    else if (ch>='A' && ch<='F') val = ch-'A'+10;
    return val;
}
int mpz_from_hex(mpz_t x, int xlen, char* m, int mlen)
{
    if (mlen<0) mlen = strlen(m);
    mpz_uint val = 0;
    mpz_limb xval= MPZ_ZERO;
    int i = mlen, j=0, sh=0, k=0;
    while (i>0)
    {
        i--;
        while (i>0 && m[i]==' ')--i;
        //val = char2bin(m[i]);
        val = val | ((mpz_uint) char2bin(m[i])<<sh);
        sh+=4;
        if ((sh&(MPZ_UINT_BITS-1))==0) {
            xval[k++] = val;
            if (k == MPZ_LIMB_BITS/MPZ_UINT_BITS) {
                x[j++]=xval,k=0;
                xval = MPZ_ZERO;
            }
            sh=0, val = 0;
        }
    }
    if (sh!=0) xval[k++] = val;
    if (k!=0) x[j++] = xval;
    for (i=j;i<xlen;i++) x[i]=MPZ_ZERO;
    return j;
}

int str_from_hex(uint8_t* x, char* m, int mlen)
{
    if (mlen<0) mlen = strlen(m);
    unsigned int val = 0;
    int i = 0, j=0, sh=0;
    while (i<mlen)
    {
        while (i<mlen && m[i]==' ')i++;
        if (i==mlen) break;
        val = (val<<4) | char2bin(m[i]);
        if (sh) {
            x[j++] = val;
            val = 0;
        }
        sh = 1-sh;
        i++;
    }
    return j;
}

/*
void str_revert(uint8_t* d, uint8_t* s, int len)
{
    int i;
    for (i=0; i<(len>>1); i++)
    {
        uint8_t t = d[i];
        d[i] = s[len-1-i];
        s[len-1-i] = t;
    }
}

void str_revert2(uint8_t* d, uint8_t* s, int len)
{
    int i;
    for (i=0; i<len; i++)
    {
        d[i] = s[len-1-i];
    }
}
*/

void mpz_print_hex(mpz_t x, int xlen)
{
    unsigned char* s = (void*) x;
    int i;
    for(i=0; i<xlen*(MPZ_LIMB_BITS>>3); i++){
        printf(" %02X", s[i]);
        if ((i&15)==15) printf("\n");
    }
}
void str_print_hex(unsigned char* s, int mlen)
{
    int i;
    for(i=0; i<mlen; i++){
        printf(" %02X", s[i]);
        if ((i&15)==15) printf("\n");
    }
}

#if 0 // тест с которого начиналась разработка алгоритма редуцирования
// 0<=a<p
void mpz_red_test()
{
    uint64_t r, inv,  a = 0x1234567890123145ULL;
    uint64_t p = 0x42400000;
    int c1=0;
    do {
        int clz = __builtin_clzll(p);
        int sh = clz-32;
        uint64_t p0 = p<<sh;//(p<<sh);
        sh=0;
        inv = ((~0x0ULL)>>sh)/p0;
        r = (((a>>(32-sh))*inv)>>32)*p0;
        r = a - r;
        if (r > p0) {
            r = r - p0;
            c1++;
            if (r > p0) {
                r = r - p0;
                c1++;
            }
        }
        if (r != a%p0) break;
        p++;
    } while (p < 0x100000000);
    printf("c1    = %08X\n", c1);
    printf("p     = %08"PRIX64"\n", p);
    printf("a / p = %08"PRIX64"\n", a/p);
    printf("a %% p = %08"PRIX64"\n", a%p);
    printf("inv   = %08"PRIx64"\n", inv);
    printf("mod   = %08"PRIX64"\n", r);

}
#endif

//extern void sha1sum(uint8_t *tag, uint8_t *msg, int length);
//extern void sha2(uint8_t *hash, int id, uint8_t *msg, int length);
/*!
    длина mgf должна быть более tlen+hlen;
    \param klen - длина в байтах
 */
void rsa_mgf(mpz_t mgf, int tlen, char* seed, int slen)
{
    const int hlen = 20;// длина хеш в байтах (SHA1)
    //mpz_uint x[(slen+3+(MPZ_BITS>>3))/(MPZ_BITS>>3)];
    uint8_t x[slen+4];
    memcpy(x, seed, slen);
    const MDigest* md = digest_select(MD_SHA1);
//    int tlen = (klen-hlen-1);
    int i, count;
    char* s = (char*)x+slen;
    for (i=0, count=0; i< tlen; i+=hlen, count++){
        s[0] = count>>24;s[1] = count>>16; s[2] = count>>8; s[3] = count;
        digest(md, (uint8_t*)mgf+count*hlen, hlen, (uint8_t*)x, slen+4);
        //sha2((uint8_t*)mgf+count*hlen, 0, (uint8_t*)x, slen+4);
    }
}
#if 1
int rsa_oaep_encrypt(mpz_t cipher, mpz_t n, int klen, unsigned int exp, unsigned char * msg, int mlen, mpz_t seed, int slen)
{
    int xlen = klen/MPZ_LIMB_BITS;
    mpz_limb x[xlen] MPZ_ALIGN;
printf("\nmsg:\n");
    str_print_hex(msg, mlen);
//printf("\nL\n");
    mpz_limb tag[xlen] MPZ_ALIGN;
    mpz_clr(tag, xlen);
    const MDigest *md = digest_select(MD_SHA1);
    digest(md, (void*)tag,md->hash_len, (void*)x, 0);
//    sha2((void*)tag,0, (void*)x, 0);
//    mpz_print_hex(tag, xlen);

    int tlen = (klen>>3)- 20 -1;

//printf("\nDB:\n");
//    mpz_to_octets(x, &tag[xlen-mlen], mlen);
    memcpy((char*)tag+tlen -mlen, msg, mlen);
    *((char*)tag +tlen -mlen-1)=0x01;
  //  str_print_hex((char*)tag, tlen);
printf("\nMGF seed:\n");
    str_print_hex((uint8_t*)seed, slen);
    mpz_t mgf = _aligned_malloc(klen>>3, MPZ_LIMB_BITS>>3); //bits
    mpz_clr(mgf, xlen);
    rsa_mgf(mgf, tlen, (char*)seed, slen);
//printf("\ndbMaskMGF1:\n");
  //  str_print_hex((char*)mgf, tlen);

//printf("\nmaskedDB:\n");
    mpz_xor(tag, mgf, xlen);
  //  str_print_hex((char*)tag, tlen);
//printf("\nseedMask:\n");
    mpz_t mgf2 = mgf;//_aligned_malloc(klen>>3, MPZ_LIMB_BITS>>3); //bits
    mpz_clr(mgf2, xlen);
    rsa_mgf(mgf2, slen, (char*)tag, tlen);
  //  str_print_hex((char*)mgf2, slen);
//printf("\nmaskedSeed:\n");
    mpz_xor(mgf2, seed, (160+MPZ_LIMB_BITS-1)/MPZ_LIMB_BITS);
  //  str_print_hex((char*)mgf2, slen);

    mpz_limb * em = cipher;
    *((char*)em) = 0x00;
    memcpy((char*)em+1, (char*)mgf2, slen);
    memcpy((char*)em+slen+1, (char*)tag, tlen);
//printf("\nEM:\n");
//    str_print_hex((uint8_t*)em, (klen>>3));
//printf("\ncipher:\n");
    mpz_limb * m = x;
//    mpz_t m = malloc(klen>>3);
    mpz_to_octets(m, em, xlen);
    mpz_powm_ui(cipher, m, exp, n, xlen);
//    str_print_hex((uint8_t*)cipher, (klen>>3));
//printf("\n----\n");
    _aligned_free(mgf2);

    return 0;
}

int rsa_encrypt(mpz_t cipher, RSA_Key * pKey)//int klen, mpz_t n, unsigned int exp)
{
    int xlen = pKey->klen/MPZ_LIMB_BITS;
    mpz_to_octets(cipher, cipher, xlen);
    mpz_powm_ui  (cipher, cipher, pKey->e, pKey->n, xlen);
    mpz_to_octets(cipher, cipher, xlen);
    return 0;
}
int rsa_decrypt(mpz_t cipher, RSA_PrivateKey* pKey)//int klen, mpz_t p, mpz_t q, mpz_t dP, mpz_t dQ, mpz_t qInv)//, mpz_t seed, int slen)
{
/*
printf("\nCiphertext:\n");
    str_print_hex((char*)cipher, (klen>>3));
printf("\np prime:\n");
    str_print_hex((char*)p, (klen>>4));
printf("\nq prime:\n");
    str_print_hex((char*)q, (klen>>4));

printf("\ndP:\n");
    str_print_hex((char*)dP, (klen>>4));
printf("\ndQ:\n");
    str_print_hex((char*)dQ, (klen>>4));
*/
    int xlen = pKey->klen/MPZ_LIMB_BITS;
    mpz_limb x[xlen] MPZ_ALIGN;// = malloc(klen>>3);
//printf("\nc mod p:\n");
    mpz_limb cp[xlen>>1] MPZ_ALIGN;// = malloc(klen>>4);
    mpz_mov(x, cipher, xlen);
    mpz_mod(x, xlen, pKey->p, xlen>>1);
    mpz_mov(cp, x, xlen>>1);
//    str_print_hex((char*)cp, (klen>>4));
//printf("\nc mod q:\n");
    mpz_limb *cq=cipher;//[xlen>>1];// = malloc(klen>>4);
//    mpz_mov(x, cipher, xlen);
    mpz_mod(cipher, xlen, pKey->q, xlen>>1);
//    mpz_mov(cq, cipher, xlen>>1);
//    str_print_hex((char*)cq, (klen>>4));
//printf("\nm1 = (c mod p)^dP mod p:\n");
    mpz_limb *m1 = cp;//malloc(klen>>4);
    mpz_powm(m1, cp, pKey->dP, pKey->p, xlen>>1);
  //  str_print_hex((char*)m1, (klen>>4));
//printf("\nm2 = (c mod q)^dQ mod q:\n");
    mpz_limb *m2 = x;//malloc(klen>>3);
    mpz_powm(m2, cq, pKey->dQ, pKey->q, xlen>>1);
  //  str_print_hex((char*)m2, (klen>>4));
    mpz_limb *h = m1;//malloc(klen>>4);
    int cy = mpz_sub(m1, m2, xlen>>1);
    if (cy<0) cy += mpz_add(h, pKey->p, xlen>>1);
    mpz_mulm(h, h, pKey->qInv, pKey->p, xlen>>1);
//printf("\nh = (m1-m2)*qInv mod p:\n");
//    str_print_hex((char*)h, (klen>>4));
//printf("\nm = m2 + q*h:\n");
    mpz_limb *m = cipher;//malloc(klen>>3);
    mpz_mul(m, pKey->q, h, xlen>>1);
    mpz_clr(&m2[xlen>>1], xlen>>1);
    mpz_add(m, m2, xlen);
///    if (cy) bn_add1_ui(&m[xlen>>1], cy, xlen>>1);
//    str_print_hex((char*)m, (klen>>3));

//    mpz_to_octets(x, mgf, xlen);
//if (mpz_cmp(m, x, xlen)==0) printf("..OK\n");
//int slen = 20, tlen = (klen>>3) - slen -1;
    mpz_to_octets(cipher, m, xlen);

//    printf("\nem:\n");
//    str_print_hex((char*)cipher, (klen>>3));

    return 0;
}

int rsa_oaep_decrypt(mpz_t cipher, int klen, mpz_t p, mpz_t q, mpz_t dP, mpz_t dQ, mpz_t qInv)//, mpz_t seed, int slen)
{
/*
printf("\nCiphertext:\n");
    str_print_hex((char*)cipher, (klen>>3));
printf("\np prime:\n");
    str_print_hex((char*)p, (klen>>4));
printf("\nq prime:\n");
    str_print_hex((char*)q, (klen>>4));

printf("\ndP:\n");
    str_print_hex((char*)dP, (klen>>4));
printf("\ndQ:\n");
    str_print_hex((char*)dQ, (klen>>4));
*/
    int xlen = klen/MPZ_LIMB_BITS;
    mpz_t x = _aligned_malloc(klen>>3, MPZ_LIMB_BITS>>3);
//printf("\nc mod p:\n");
    mpz_t cp = _aligned_malloc(klen>>4, MPZ_LIMB_BITS>>3);
    mpz_mov(x, cipher, xlen);
    mpz_mod(x, xlen, p, xlen>>1);
    mpz_mov(cp, x, xlen>>1);
//    str_print_hex((char*)cp, (klen>>4));
//printf("\nc mod q:\n");
    mpz_t cq = _aligned_malloc(klen>>4, MPZ_LIMB_BITS>>3);
    mpz_mov(x, cipher, xlen);
    mpz_mod(x, xlen, q, xlen>>1);
    mpz_mov(cq, x, xlen>>1);
//    str_print_hex((char*)cq, (klen>>4));
//printf("\nm1 = (c mod p)^dP mod p:\n");
    mpz_t m1 = _aligned_malloc(klen>>4, MPZ_LIMB_BITS>>3);
    mpz_powm(m1, cp, dP, p, xlen>>1);
  //  str_print_hex((char*)m1, (klen>>4));
//printf("\nm2 = (c mod q)^dQ mod q:\n");
    mpz_t m2 = _aligned_malloc(klen>>3, MPZ_LIMB_BITS>>3);
    mpz_powm(m2, cq, dQ, q, xlen>>1);
  //  str_print_hex((char*)m2, (klen>>4));
printf("\nh = (m1-m2)*qInv mod p:\n");
    mpz_limb *h = m1;//malloc(klen>>4);
    mpz_int cy = mpz_sub(m1, m2, xlen>>1);
    if (cy<0) cy += mpz_add(h, p, xlen>>1);
    mpz_mulm(h, h, qInv, p, xlen>>1);
    str_print_hex((uint8_t*)h, (klen>>4));
//printf("\nm = m2 + q*h:\n");
    mpz_t m = _aligned_malloc(klen>>3, MPZ_LIMB_BITS>>3);
    mpz_mul(m, q, h, xlen>>1);
    mpz_clr(&m2[xlen>>1], xlen>>1);
    mpz_add(m, m2, xlen);
///    if (cy) bn_add1_ui(&m[xlen>>1], cy, xlen>>1);
//    str_print_hex((char*)m, (klen>>3));

//    mpz_to_octets(x, mgf, xlen);
//if (mpz_cmp(m, x, xlen)==0) printf("..OK\n");
printf("\nem:\n");
int slen = 20, tlen = (klen>>3) - slen -1;
    mpz_limb * em = x;
    mpz_to_octets(em, m, xlen);
    str_print_hex((uint8_t*)em, (klen>>3));

    mpz_t tag  = _aligned_malloc(klen>>3, MPZ_LIMB_BITS>>3);
    mpz_t seed = _aligned_malloc(klen>>3, MPZ_LIMB_BITS>>3);
    mpz_t mgf2 = _aligned_malloc(klen>>3, MPZ_LIMB_BITS>>3);
    memcpy((char*)tag, (char*)em+slen+1, tlen);
    memcpy((char*)seed, (char*)em+1, slen);
    mpz_clr(mgf2, xlen);
    rsa_mgf(mgf2, slen, (char*)tag, tlen);
    mpz_xor(seed, mgf2, (160+MPZ_LIMB_BITS-1)/MPZ_LIMB_BITS);
printf("\nseed:\n");
    str_print_hex((uint8_t*)seed, slen);
    mpz_clr(mgf2, xlen);
    rsa_mgf(mgf2, tlen, (char*)seed, slen);
    mpz_xor(tag, mgf2, xlen);
//printf("\nDB:\n");
  //  str_print_hex((char*)tag, tlen);
    char* s = (char*)tag;
    int i;
    for (i=slen; i< tlen; i++) {
        if (s[i]!=0x00) break;
    }
    if (i<tlen && s[i]==0x01) {
        printf("\nmsg:\n");
        str_print_hex((uint8_t*)&s[i+1], tlen-i-1);
    }
    printf("\n----\n");
    return 0;
}

/*! Преобазование EMSA-PSS-Encode от сообщения для цифровой подписи RSA.

    Преобразование выполняется в составе алгоритма RSASSA-PSS-SIGN [PKCS#1 v2.2]
    \param EM - возвращает ппреобразование от сообщения
    \param emBits - число бит в модуле минус один
    \param msg - сообщение, для которого выполняется проверка кодирования
    \param mlen - длина сообщения
    \return consistent (0) or inconsistent (1)
 */
int pss_encode(mpz_t EM, int klen, uint8_t* msg, int mlen, uint8_t* salt)
{
    const int hlen = 20, slen = 20, xlen = klen/MPZ_LIMB_BITS;
    uint8_t* M = (uint8_t*)EM;// [hlen+slen+8];
    memset(&M[0], 0x00, 8);
    memcpy(&M[hlen+8], salt, 20);
    const MDigest * md = digest_select(MD_SHA1);
    digest(md,(uint8_t*)&M[8], md->hash_len, msg, mlen);
//    sha2((uint8_t*)&M[8], 0, msg, mlen);
// printf("\nmHash:\n");
//    str_print_hex(&M[8], 20);
//    printf("\nM':\n");
//    str_print_hex((char*)M, hlen+slen+8);
    uint8_t H[hlen];
    digest(md,H,md->hash_len, M, hlen+slen+8);
//    sha2(H, 0, M, hlen+slen+8);
//    printf("\nH:\n");
//    str_print_hex((uint8_t*)H, 20);
    int tlen = (klen>>3)-21;
    mpz_limb *DB = EM;//malloc(klen>>3);
    mpz_clr(DB, xlen);
    *((char*)DB + (klen>>3)-42) = 0x01;
    memcpy((char*)DB + (klen>>3)-41, salt, 20);
//    printf("\nDB:\n");
//    str_print_hex((uint8_t*)DB, tlen);
    mpz_limb mgf[xlen] MPZ_ALIGN;// = malloc(klen>>3);
    //mpz_clr(mgf, xlen);
    rsa_mgf(mgf, tlen, (char*)H, slen);
//    printf("\ndbMask:\n");
//    str_print_hex((uint8_t*)mgf, tlen);
    mpz_xor(DB, mgf, xlen);
    *((uint8_t*)DB)&=0x7F;

//    printf("\nmaskedDB:\n");
//    str_print_hex((uint8_t*)DB, tlen);
    memcpy((uint8_t*)DB+tlen, H, slen);
    *((uint8_t*)DB + (klen>>3)-1)=0xBC;
//    printf("\nEM:\n");
//    str_print_hex((uint8_t*)EM, klen>>3);
    return 0;
}//    mpz_to_octets(mgf, DB, xlen);
/*! Проверка соответствия преобразования и сообщения, алгоритм EMSA-PSS-Verify.

    Проверка выполняется в составе алгоритма RSASSA-PSS-VERIFY [PKCS#1 v2.2]
    \param EM - преобразование от сообщения
    \param emBits - число бит в модуле минус один
    \param msg - сообщение, для которого выполняется проверка кодирования
    \param mlen - длина сообщения
    \return consistent (0) or inconsistent (1)
 */
int pss_verify(mpz_t EM, int emBits, uint8_t* msg, int mlen)
{
    // if mlen > 2^61-1) return 1;
    const int hlen = 20, slen = 20;
    int emLen = (emBits+7)>>3;
    uint8_t M[hlen+slen+8] MPZ_ALIGN;
    uint8_t * mHash = &M[8];
    const MDigest * md = digest_select(MD_SHA1);
    digest(md, mHash, hlen, msg, mlen);
//    sha2(mHash, 0, msg, mlen);
//printf("\nmHash:\n");
//    str_print_hex(mHash, hlen);
    if (emLen<hlen+slen+2) return 1;
    uint8_t* em = (uint8_t*)EM;
    if (em[emLen-1]!=0xBC) return 1;
    uint8_t* H = em + emLen-hlen-1;
    int mask = 0xFF>>((emLen<<3)-emBits);
    if ((em[0] & ~mask)!=0) return 1;
    int xlen = (emBits+MPZ_LIMB_BITS-1)/MPZ_LIMB_BITS;
    mpz_limb dbMask[xlen] MPZ_ALIGN;
    //mpz_clr(dbMask, xlen);
    rsa_mgf(dbMask, emLen-hlen-1, (char*)H, hlen);
    uint8_t Hash[hlen];
    memcpy(Hash, H, hlen);
    //mpz_mov(DB, EM, xlen);
    mpz_xor(dbMask, EM, xlen);
//printf("\nDB:\n");
//    str_print_hex((uint8_t*)dbMask, emLen);
    uint8_t* s = (uint8_t*)dbMask;
    s[0] &= mask;
    int i;
    for (i=0; i< emLen-hlen-slen-2;i++){
        if (s[i]!=0x00) return 1;
    }
    if (s[i++]!=0x01) return 1;
    memset(M, 0, 8);
    memcpy(&M[8+hlen], &s[i], slen);
//printf("\nM:\n");
//    str_print_hex(M, hlen+slen+8);
    digest(md, mHash, hlen, M, hlen+slen+8);
//    sha2(mHash, 0, M, hlen+slen+8);
//printf("\nH':\n");
//    str_print_hex(mHash, hlen);
    return (memcmp(mHash, Hash, hlen)!=0);
}
/* \see RFC 3447 PKCS #1: RSA Cryptography Specifications   February 2003
 DigestInfo ::= SEQUENCE {
  digestAlgorithm DigestAlgorithmIdentifier,
  digest Digest }
4. Generate an octet string PS consisting of emLen - tLen - 3 octets
      with hexadecimal value 0xff.  The length of PS will be at least 8
      octets.
5. Concatenate PS, the DER encoding T, and other padding to form the
      encoded message EM as

         EM = 0x00 || 0x01 || PS || 0x00 || T.

Note:

1. For the six hash functions mentioned in Appendix B.1, the DER
   encoding T of the DigestInfo value is equal to the following:
   ...
      MD5:     (0x)30 20 30 0c
                    06 08 2a 86 48 86 f7 0d 02 05 05 00
                    04 10 || H.
      SHA-1:   (0x)30 21 30 09
                    06 05 2b 0e 03 02 1a 05 00
                    04 14 || H.
      SHA-256: (0x)30 31 30 0d
                    06 09 60 86 48 01 65 03 04 02 01 05 00
                    04 20 || H.
      SHA-384: (0x)30 41 30 0d
                    06 09 60 86 48 01 65 03 04 02 02 05 00
                    04 30 || H.
      SHA-512: (0x)30 51 30 0d
                    06 09 60 86 48 01 65 03 04 02 03 05 00
                    04 40 || H.
\see [RFC8017] 9.2.  EMSA-PKCS1-v1_5
*/
static const uint8_t hash_tag_md5[]
    = {0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x04,0x10};
static const uint8_t hash_tag_sha1[]
    = {0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14};
static const uint8_t hash_tag_sha256[]
    = {0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00, 0x04, 0x20};
static const uint8_t hash_tag_sha384[]
    = {0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00, 0x04, 0x30};
static const uint8_t hash_tag_sha512[]
    = {0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00, 0x04, 0x40};
static void pkcs_encode(const SignCtx *sign_ctx, uint8_t* em, int emlen, uint8_t* msg, int mlen)
{
    int halg, hlen;
    if (sign_ctx==NULL) {
        halg = MD_SHA1, hlen = 20;
    } else {
        halg = sign_ctx->id_hash_alg, hlen = sign_ctx->id_hash_len;
    }
    const uint8_t *tag; //= {0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14};
    switch (halg){
    case MD_MD5:    tag = hash_tag_md5;     break;
    default:
    case MD_SHA1:   tag = hash_tag_sha1;    break;
    case MD_SHA256: tag = hash_tag_sha256;  break;
    case MD_SHA384: tag = hash_tag_sha384;  break;
    case MD_SHA512: tag = hash_tag_sha512;  break;
    }
    const MDigest * md = digest_select(halg);
    if(hlen==0) hlen = md->hash_len;

    int tlen = tag[1]+2/* sizeof(tag)*/, plen = emlen - tlen - 3;
// EM = 0x00 || 0x01 || PS || 0x00 || T.
    em[0] = 0x00, em[1] = 0x01;
    memset(&em[2], 0xFF, plen);
    em[2+plen] = 0x00;

    memcpy(&em[3+plen], tag, tlen-hlen);
    digest(md, &em[emlen-hlen], hlen, msg, mlen);
}
int rsa_pkcs_sign(mpz_t sign, RSA_PrivateKey * pKey, uint8_t* msg, int mlen)
{
    pkcs_encode(NULL, (uint8_t*)sign, pKey->klen>>3, msg, mlen);

    mpz_to_octets(sign, sign, pKey->klen/MPZ_LIMB_BITS);
    rsa_decrypt(sign, pKey);
    return 0;
}
int rsa_pkcs_verify(mpz_t sign, RSA_Key * pKey, uint8_t* msg, int mlen)
{
    rsa_encrypt(sign, pKey);//->klen, pKey->n, pKey->e);
    int xlen = pKey->klen/MPZ_LIMB_BITS;

    mpz_limb em[xlen] MPZ_ALIGN;
    pkcs_encode(NULL, (uint8_t*)em, pKey->klen>>3, msg, mlen);
    return mpz_equ(em, sign, xlen);
}
int rsa_EME_pkcs_verify(uint8_t* signature, RSA_Key * pKey, uint8_t* msg, int mlen)
{
    int xlen = pKey->klen/MPZ_LIMB_BITS;
	mpz_limb sign[xlen] MPZ_ALIGN;
//    mpz_limb em[xlen] MPZ_ALIGN;
	__builtin_memcpy(sign, signature, pKey->klen>>3);
//mpz_print_hex(sign, xlen);
    rsa_encrypt(sign, pKey);//->klen, pKey->n, pKey->e);
//printf("klen = %d\n", pKey->klen);
//mpz_print_hex(sign, xlen);
	return __builtin_memcmp((uint8_t*)sign +(pKey->klen>>3)-mlen, msg, mlen)==0;
//    pkcs_encode_hash(NULL, (uint8_t*)em, pKey->klen>>3, msg, mlen);
//    return mpz_equ(em, sign, xlen);
}
static int rsa_pkcs_verify1(const SignCtx* sign_ctx, mpz_t sign, RSA_Key * pKey, uint8_t* msg, int mlen)
{
    rsa_encrypt(sign, pKey);//->klen, pKey->n, pKey->e);
    int xlen = pKey->klen/MPZ_LIMB_BITS;

    mpz_limb em[xlen] MPZ_ALIGN;
    pkcs_encode(sign_ctx, (uint8_t*)em, pKey->klen>>3, msg, mlen);
    return mpz_equ(em, sign, xlen);
}


/*! \brief декодирование длины поля DER
    \param [in] data - бинарые данные
    \param [out] len - длина поля
    \return количество разобранных октетов
*/
static uint8_t* der_decode_length(uint8_t * data, int * len)
{
    uint32_t length  = *data++;
//    int total_size = 1;
    if (length & 0x80)
    {   // длина больше двух байт может и бывает в теории, но на правктике не встречается
        // кроме того, в теории бывает длина нулевая 0х80 - одним байтом,
        // тогда конец блока обозначается специальным тегом, 0х00 0х00
        if (length == 0x80){
            length = -1; // -1 - значит бесконечность,
        } else {
            uint32_t count = length & 0x7F;
//            total_size += count;
            length = 0;
            do {
                length = (length<<8) + (*data++);
            } while (--count);
        }
    }
    if(len) *len = length;
    return data;
}
/*!
    \todo выделять правильно длину ключа и экспоненту
 */
static int rsa_signature_verify(const SignCtx* sign_ctx,
	uint8_t* public_key, uint8_t* signature, uint8_t * msg, int mlen)
{
//extern uint8_t* der_decode_length(uint8_t * data, int * len);
    uint8_t * buf = public_key;
    int len=0;
    buf = der_decode_length(buf+1, &len);
    buf = der_decode_length(buf+1, &len);// первый параметр - modulus
    if (len>0 && buf[0]==0) { len--, buf++; } // пропускаем нолик - положительное число

    RSA_Key pKey;
    pKey.klen = (len<<3);
    int xlen = (pKey.klen)/MPZ_LIMB_BITS;
    mpz_limb sign[xlen] MPZ_ALIGN;
    mpz_limb pkey[xlen] MPZ_ALIGN;
    __builtin_memcpy(sign, signature, pKey.klen>>3);
    __builtin_memcpy(pkey, buf, pKey.klen>>3);
    pKey.e = 0x010001;
    pKey.n = pkey;
//    mpz_print_hex( pKey.n, xlen);
    mpz_to_octets(pKey.n, pKey.n, xlen);
    //__builtin_memcpy(pKey.n, public_key+9+, (2048>>3));
    return rsa_pkcs_verify1(sign_ctx, sign, &pKey, msg, mlen);
}
/*    RSA_Key Key;
        printf("Modulus (%d):\n", ((form->public_key.bits>>3)-14)<<3);
        print_hex(buf+9, (form->public_key.bits>>3)-9-5);
        printf("Public exponent: ");
        print_hex(buf+(form->public_key.bits>>3)-3, 3);
*/
#endif
SIGNATURE(SIGN_RSA){
    .id = SIGN_RSA,
    .name = "RSA",
    .verify = (void*)rsa_signature_verify,
};

#ifdef DEBUG_RSA
int main(int argc, char** argv)
{
    char nt[] =
"bb f8 2f 09 06 82 ce 9c 23 38 ac 2b 9d a8 71"
"f7 36 8d 07 ee d4 10 43 a4 40 d6 b6 f0 74 54 f5"
"1f b8 df ba af 03 5c 02 ab 61 ea 48 ce eb 6f cd"
"48 76 ed 52 0d 60 e1 ec 46 19 71 9d 8a 5b 8b 80"
"7f af b8 e0 a3 df c7 37 72 3e e6 b4 b7 d9 3a 25"
"84 ee 6a 64 9d 06 09 53 74 88 34 b2 45 45 98 39"
"4e e0 aa b1 2d 7b 61 a5 1f 52 7a 9a 41 f6 c1 68"
"7f e2 53 72 98 ca 2a 8f 59 46 f8 e5 fd 09 1d bd cb";
    char msg[] = "d4 36 e9 95 69 fd 32 a7 c8 a0 5b bc 90 d3 2c 49";
    mpz_t n = malloc(1024>>3); //bits
    mpz_t x = malloc(1024>>3); //bits
    int xlen = 1024/MPZ_LIMB_BITS;
    int mlen = str_from_hex((uint8_t*)x, msg, -1);
printf("\nmodulus n:\n");
    mpz_from_hex(n, xlen, nt, -1);
    str_print_hex((char*)n, (1024>>3));

    char mseed[] = "aa fd 12 f6 59 ca e6 34 89 b4 79 e5 07 6d de c2 f0 6c b5 8f";
    mpz_limb seed[160/MPZ_LIMB_BITS] = {0};
    int slen = str_from_hex((uint8_t*)seed,  mseed, -1);

    mpz_t cipher = malloc(1024>>3); //bits
rsa_oaep_encrypt(cipher, n, 1024, 0x11, (uint8_t*)x, mlen, seed, slen);

    str_print_hex((char*)x, mlen);
printf("\n\n");
    mpz_t tag = malloc(1024>>3); //bits
    mpz_clr(tag, xlen);
    sha2((void*)tag,0, (void*)x, 0);
    mpz_print_hex(tag, xlen);

    int tlen = (1024>>3)- 20 -1;

printf("\nDB:\n");
//    mpz_to_octets(x, &tag[xlen-mlen], mlen);
//    mlen *= (MPZ_BITS>>3);
//    str_revert2((char*)tag +tlen- mlen, (char*)x, mlen);
    memcpy((char*)tag+tlen -mlen, x, mlen);
    *((char*)tag +tlen -mlen-1)=0x01;

    str_print_hex((char*)tag, tlen);
//    mpz_print_hex(x, xlen);
printf("\nMGF seed:\n");
    //str_revert((char*)x, (char*)x, 20);
    str_print_hex((char*)seed, slen);
    mpz_t mgf = malloc(1024>>3); //bits
    mpz_clr(mgf, xlen);
    rsa_mgf(mgf, tlen, (char*)seed, slen);
printf("\ndbMaskMGF1:\n");
    str_print_hex((char*)mgf, tlen);

printf("\nmaskedDB:\n");
    mpz_xor(tag, mgf, xlen);
    str_print_hex((char*)tag, tlen);
printf("\nseedMask:\n");
    mpz_t mgf2 = malloc(1024>>3); //bits
    mpz_clr(mgf2, xlen);
//    str_revert((char*)tag+tlen-20, (char*)tag+tlen-20, 20);
//    str_revert((char*)tag, (char*)tag, 20);
    rsa_mgf(mgf2, slen, (char*)tag, tlen);
    str_print_hex((char*)mgf2, slen);
printf("\nmaskedSeed:\n");
    mpz_xor(mgf2, seed, 160/MPZ_LIMB_BITS);
    str_print_hex((char*)mgf2, slen);
    *((char*)mgf) = 0x00;
    memcpy((char*)mgf+1, (char*)mgf2, slen);
    memcpy((char*)mgf+slen+1, (char*)tag, tlen);
printf("\nEM:\n");
    str_print_hex((char*)mgf, (1024>>3));

//mpz_red_test();

char ct[] =
"12 53 e0 4d c0 a5 39 7b b4 4a 7a b8 7e 9b f2 a0"
"39 a3 3d 1e 99 6f c8 2a 94 cc d3 00 74 c9 5d f7"
"63 72 20 17 06 9e 52 68 da 5d 1c 0b 4f 87 2c f6"
"53 c1 1d f8 23 14 a6 79 68 df ea e2 8d ef 04 bb"
"6d 84 b1 c3 1d 65 4a 19 70 e5 78 3b d6 eb 96 a0"
"24 c2 ca 2f 4a 90 fe 9f 2e f5 c9 c1 40 e5 bb 48"
"da 95 36 ad 87 00 c8 4f c9 13 0a de a7 4e 55 8d"
"51 a7 4d df 85 d8 b5 0d e9 68 38 d6 06 3e 09 55";
// Prime p:
char pt[] =
"ee cf ae 81 b1 b9 b3 c9 08 81 0b 10 a1 b5 60 01"
"99 eb 9f 44 ae f4 fd a4 93 b8 1a 9e 3d 84 f6 32"
"12 4e f0 23 6e 5d 1e 3b 7e 28 fa e7 aa 04 0a 2d"
"5b 25 21 76 45 9d 1f 39 75 41 ba 2a 58 fb 65 99";

// Prime q:
char qt[] =
"c9 7f b1 f0 27 f4 53 f6 34 12 33 ea aa d1 d9 35"
"3f 6c 42 d0 88 66 b1 d0 5a 0f 20 35 02 8b 9d 86"
"98 40 b4 16 66 b4 2e 92 ea 0d a3 b4 32 04 b5 cf"
"ce 33 52 52 4d 04 16 a5 a4 41 e7 00 af 46 15 03";

char dPt[] =// p's CRT exponent dP:
"54 49 4c a6 3e ba 03 37 e4 e2 40 23 fc d6 9a 5a"
"eb 07 dd dc 01 83 a4 d0 ac 9b 54 b0 51 f2 b1 3e"
"d9 49 09 75 ea b7 74 14 ff 59 c1 f7 69 2e 9a 2e"
"20 2b 38 fc 91 0a 47 41 74 ad c9 3c 1f 67 c9 81";

char dQt[] =// q's CRT exponent dQ:
"47 1e 02 90 ff 0a f0 75 03 51 b7 f8 78 86 4c a9"
"61 ad bd 3a 8a 7e 99 1c 5c 05 56 a9 4c 31 46 a7"
"f9 80 3f 8f 6f 8a e3 42 e9 31 fd 8a e4 7a 22 0d"
"1b 99 a4 95 84 98 07 fe 39 f9 24 5a 98 36 da 3d";

char qInvt[] =// CRT coefficient qInv:
"b0 6c 4f da bb 63 01 19 8d 26 5b db ae 94 23 b3"
"80 f2 71 f7 34 53 88 50 93 07 7f cd 39 e2 11 9f"
"c9 86 32 15 4f 58 83 b1 67 a9 67 bf 40 2b 4e 9e"
"2e 0f 96 56 e6 98 ea 36 66 ed fb 25 79 80 39 f7";

    mpz_t p = malloc(1024>>3);
    mpz_t q = malloc(1024>>3);

    mpz_t dP = malloc(1024>>4);
    mpz_t dQ = malloc(1024>>4);
    mpz_t qInv = malloc(1024>>4);

    mpz_t d = malloc(1024>>3);
    int clen = mpz_from_hex(x, xlen, ct, -1);
    int plen = mpz_from_hex(p, xlen, pt, -1);
    int qlen = mpz_from_hex(q, xlen, qt, -1);
    mpz_from_hex(dP, xlen>>1, dPt, -1);
    mpz_from_hex(dQ, xlen>>1, dQt, -1);
    mpz_from_hex(qInv, xlen>>1, qInvt, -1);

printf("\nCiphertext:\n");
    str_print_hex((char*)x, (1024>>3));
printf("\np prime:\n");
    str_print_hex((char*)p, (1024>>4));
printf("\nq prime:\n");
    str_print_hex((char*)q, (1024>>4));

printf("\ndP:\n");
    str_print_hex((char*)dP, (1024>>4));
printf("\ndQ:\n");
    str_print_hex((char*)dQ, (1024>>4));

printf("\nc mod p:\n");
    mpz_t cp = malloc(1024>>4);
    mpz_from_hex(x, xlen, ct, -1);
    mpz_mod(x, xlen, p, xlen>>1);
    mpz_mov(cp, x, xlen>>1);
    str_print_hex((char*)cp, (1024>>4));
printf("\nc mod q:\n");
    mpz_t cq = malloc(1024>>4);
    mpz_from_hex(x, xlen, ct, -1);
    mpz_mod(x, xlen, q, xlen>>1);
    mpz_mov(cq, x, xlen>>1);
    str_print_hex((char*)cq, (1024>>4));
printf("\nm1 = (c mod p)^dP mod p:\n");
    mpz_t m1 = malloc(1024>>4);
    mpz_powm(m1, cp, dP, p, xlen>>1);
    str_print_hex((char*)m1, (1024>>4));
printf("\nm2 = (c mod q)^dQ mod q:\n");
    mpz_t m2 = malloc(1024>>3);
    mpz_powm(m2, cq, dQ, q, xlen>>1);
    str_print_hex((char*)m2, (1024>>4));
printf("\nh = (m1-m2)*qInv mod p:\n");
    mpz_t h = malloc(1024>>4);
    //mpz_int cy = bn_sub(h, m1, m2, xlen>>1);
    mpz_mov(h, m1, xlen>>1);
    mpz_int cy = mpz_sub(h, m2, xlen>>1);
    if (cy<0) cy += mpz_add(h, p, xlen>>1);
    str_print_hex((char*)h, (1024>>4));
    printf("\n\n");
    mpz_mulm(h, h, qInv, p, xlen>>1);
    str_print_hex((char*)h, (1024>>4));
printf("\nm = m2 + q*h:\n");
    mpz_t m = malloc(1024>>3);
    mpz_mul(m, q, h, xlen>>1);
    mpz_clr(&m2[xlen>>1], xlen>>1);
    mpz_add(m, m2, xlen);
//    if (cy) bn_add1_ui(&m[xlen>>1], cy, xlen>>1);
    str_print_hex((char*)m, (1024>>3));
    mpz_to_octets(x, mgf, xlen);
    if (mpz_equ(m, x, xlen>>1)) {
        printf("..OK\n");
    } else {
        printf("\nx:\n");
        str_print_hex((char*)x, (1024>>3));
    }
printf("\nmodulus n = pq:\n");
    mpz_mul(d, p, q, xlen>>1);
    str_print_hex((char*)d, (1024>>3));
printf("\ncipher:\n");
    //mpz_t m = malloc(1024>>3);
    mpz_to_octets(m, mgf, xlen);
    str_print_hex((char*)x, (1024>>3));
printf("\n\n");
    mpz_powm_ui(x, m, 0x11, d, xlen);
    str_print_hex((char*)x, (1024>>3));

    extern int rsa_pkcs_test1024();
    rsa_pkcs_test1024();
    return 0;
}
#endif
