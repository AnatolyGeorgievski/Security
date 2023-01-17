/*! \file RSA PKCS#1 v1.5 signature test vectors 1024 bits

    сборка
    $ gcc -Os -o rsa.exe rsa.c mpz.c mpz_asm.c sha.c rsa_pkcs_test_1024.c
    тестирование

	замена
	^([\da-f].*)$
	"\1"
 */
#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int str_from_hex(uint8_t* x, char* m, int mlen);
extern void str_print_hex(unsigned char* s, int mlen);
//int main(int argc, char** argv)
int rsa_pkcs_test1024()
{
int fail =0;
char* nt = // Modulus:
"a5 6e 4a 0e 70 10 17 58 9a 51 87 dc 7e a8 41 d1"
"56 f2 ec 0e 36 ad 52 a4 4d fe b1 e6 1f 7a d9 91"
"d8 c5 10 56 ff ed b1 62 b4 c0 f2 83 a1 2a 88 a3"
"94 df f5 26 ab 72 91 cb b3 07 ce ab fc e0 b1 df"
"d5 cd 95 08 09 6d 5b 2b 8b 6d f5 d6 71 ef 63 77"
"c0 92 1c b2 3c 27 0a 70 e2 59 8e 6f f8 9d 19 f1"
"05 ac c2 d3 f0 cb 35 f2 92 80 e1 38 6b 6f 64 c4"
"ef 22 e1 e1 f2 0d 0c e8 cf fb 22 49 bd 9a 21 37";

// Public exponent:
unsigned int exp = 0x010001;
/*
char* dt = // Exponent:
"33 a5 04 2a 90 b2 7d 4f 54 51 ca 9b bb d0 b4 47"
"71 a1 01 af 88 43 40 ae f9 88 5f 2a 4b be 92 e8"
"94 a7 24 ac 3c 56 8c 8f 97 85 3a d0 7c 02 66 c8"
"c6 a3 ca 09 29 f1 e8 f1 12 31 88 44 29 fc 4d 9a"
"e5 5f ee 89 6a 10 ce 70 7c 3e d7 e7 34 e4 47 27"
"a3 95 74 50 1a 53 26 83 10 9c 2a ba ca ba 28 3c"
"31 b4 bd 2f 53 c3 ee 37 e3 52 ce e3 4f 9e 50 3b"
"d8 0c 06 22 ad 79 c6 dc ee 88 35 47 c6 a3 b3 25";
*/
char* pt = // Prime 1:
"e7 e8 94 27 20 a8 77 51 72 73 a3 56 05 3e a2 a1"
"bc 0c 94 aa 72 d5 5c 6e 86 29 6b 2d fc 96 79 48"
"c0 a7 2c bc cc a7 ea cb 35 70 6e 09 a1 df 55 a1"
"53 5b d9 b3 cc 34 16 0b 3b 6d cd 3e da 8e 64 43";

char* qt = // Prime 2:
"b6 9d ca 1c f7 d4 d7 ec 81 e7 5b 90 fc ca 87 4a"
"bc de 12 3f d2 70 01 80 aa 90 47 9b 6e 48 de 8d"
"67 ed 24 f9 f1 9d 85 ba 27 58 74 f5 42 cd 20 dc"
"72 3e 69 63 36 4a 1f 94 25 45 2b 26 9a 67 99 fd";

char* dPt = // Prime exponent 1:
"28 fa 13 93 86 55 be 1f 8a 15 9c ba ca 5a 72 ea"
"19 0c 30 08 9e 19 cd 27 4a 55 6f 36 c4 f6 e1 9f"
"55 4b 34 c0 77 79 04 27 bb dd 8d d3 ed e2 44 83"
"28 f3 85 d8 1b 30 e8 e4 3b 2f ff a0 27 86 19 79";

char* dQt = // Prime exponent 2:
"1a 8b 38 f3 98 fa 71 20 49 89 8d 7f b7 9e e0 a7"
"76 68 79 12 99 cd fa 09 ef c0 e5 07 ac b2 1e d7"
"43 01 ef 5b fd 48 be 45 5e ae b6 e1 67 82 55 82"
"75 80 a8 e4 e8 e1 41 51 d1 51 0a 82 a3 f2 e7 29";

char* qInvt = // Coefficient:
"27 15 6a ba 41 26 d2 4a 81 f3 a5 28 cb fb 27 f5"
"68 86 f8 40 a9 f6 e8 6e 17 a4 4b 94 fe 93 19 58"
"4b 8e 22 fd de 1e 5a 2e 3b d8 aa 5b a8 d8 58 41"
"94 eb 21 90 ac f8 32 b8 47 f1 3a 3d 24 a7 9f 4d";

    const int klen =  1024;
    RSA_Key* Key = malloc(sizeof(RSA_Key));
    Key->klen = klen;
    Key->n = malloc(klen>>3);
    Key->e = exp;
    RSA_PrivateKey* pKey = malloc(sizeof(RSA_PrivateKey));
    pKey->klen = klen;
    pKey->p = malloc(klen>>4);
    pKey->q = malloc(klen>>4);
    pKey->dP = malloc(klen>>4);
    pKey->dQ = malloc(klen>>4);
    pKey->qInv = malloc(klen>>4);

    const int xlen = klen/MPZ_LIMB_BITS;
    mpz_from_hex(Key->n, xlen, nt, -1);
    mpz_from_hex(pKey->p,  xlen>>1, pt, -1);
    mpz_from_hex(pKey->q,  xlen>>1, qt, -1);
    mpz_from_hex(pKey->dP, xlen>>1, dPt, -1);
    mpz_from_hex(pKey->dQ, xlen>>1, dQt, -1);
    mpz_from_hex(pKey->qInv, xlen>>1, qInvt, -1);


    printf("\nmodulus n = pq:\n");
    mpz_t d = malloc(klen>>3);
    mpz_mul(d, pKey->p, pKey->q, xlen>>1);
    str_print_hex((char*)d, (klen>>3));
    if (mpz_equ(Key->n,d,xlen)) printf("..OK\n");
    else fail++;

// PKCS#1 v1.5 signing of 20 random messages

printf("PKCS#1 v1.5 Signature Example 1.1\n");

char* msgt = // Message to be signed:
"cd c8 7d a2 23 d7 86 df 3b 45 e0 bb bc 72 13 26"
"d1 ee 2a f8 06 cc 31 54 75 cc 6f 0d 9c 66 e1 b6"
"23 71 d4 5c e2 39 2e 1a c9 28 44 c3 10 10 2f 15"
"6a 0d 8d 52 c1 f4 c4 0b a3 aa 65 09 57 86 cb 76"
"97 57 a6 56 3b a9 58 fe d0 bc c9 84 e8 b5 17 a3"
"d5 f5 15 b2 3b 8a 41 e7 4a a8 67 69 3f 90 df b0"
"61 a6 e8 6d fa ae e6 44 72 c0 0e 5f 20 94 57 29"
"cb eb e7 7f 06 ce 78 e0 8f 40 98 fb a4 1f 9d 61"
"93 c0 31 7e 8b 60 d4 b6 08 4a cb 42 d2 9e 38 08"
"a3 bc 37 2d 85 e3 31 17 0f cb f7 cc 72 d0 b7 1c"
"29 66 48 b3 a4 d1 0f 41 62 95 d0 80 7a a6 25 ca"
"b2 74 4f d9 ea 8f d2 23 c4 25 37 02 98 28 bd 16"
"be 02 54 6f 13 0f d2 e3 3b 93 6d 26 76 e0 8a ed"
"1b 73 31 8b 75 0a 01 67 d0";

char* signt = // Signature:
"6b c3 a0 66 56 84 29 30 a2 47 e3 0d 58 64 b4 d8"
"19 23 6b a7 c6 89 65 86 2a d7 db c4 e2 4a f2 8e"
"86 bb 53 1f 03 35 8b e5 fb 74 77 7c 60 86 f8 50"
"ca ef 89 3f 0d 6f cc 2d 0c 91 ec 01 36 93 b4 ea"
"00 b8 0c d4 9a ac 4e cb 5f 89 11 af e5 39 ad a4"
"a8 f3 82 3d 1d 13 e4 72 d1 49 05 47 c6 59 c7 61"
"7f 3d 24 08 7d db 6f 2b 72 09 61 67 fc 09 7c ab"
"18 e9 a4 58 fc b6 34 cd ce 8e e3 58 94 c4 84 d7";
    mpz_t msg = malloc(4096);
    mpz_limb sign[klen/MPZ_LIMB_BITS] MPZ_ALIGN;

    int mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    int slen =
    str_from_hex((uint8_t*)sign, signt, -1);

    //mpz_to_octets(sign,sign, klen/MPZ_LIMB_BITS);
// проверка подписи
//    rsa_encrypt(sign, Key);

//printf("\nEM:\n");
//    str_print_hex((uint8_t*)sign, klen>>3);
//mpz_to_octets(sign, sign, klen/MPZ_LIMB_BITS);
    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);

printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);

    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;


// -----------------

printf("PKCS#1 v1.5 Signature Example 1.2\n");


msgt = // Message to be signed:
"85 13 84 cd fe 81 9c 22 ed 6c 4c cb 30 da eb 5c"
"f0 59 bc 8e 11 66 b7 e3 53 0c 4c 23 3e 2b 5f 8f"
"71 a1 cc a5 82 d4 3e cc 72 b1 bc a1 6d fc 70 13"
"22 6b 9e";

signt = // Signature:
"84 fd 2c e7 34 ec 1d a8 28 d0 f1 5b f4 9a 87 07"
"c1 5d 05 94 81 36 de 53 7a 3d b4 21 38 41 67 c8"
"6f ae 02 25 87 ee 9e 13 7d ae e7 54 73 82 62 93"
"2d 27 1c 74 4c 6d 3a 18 9a d4 31 1b db 02 04 92"
"e3 22 fb dd c4 04 06 ea 86 0d 4e 8e a2 a4 08 4a"
"a9 8b 96 22 a4 46 75 6f db 74 0d db 3d 91 db 76"
"70 e2 11 66 1b bf 87 09 b1 1c 08 a7 07 71 42 2d"
"1a 12 de f2 9f 06 88 a1 92 ae bd 89 e0 f8 96 f8";

    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;


printf("PKCS#1 v1.5 Signature Example 1.3\n");



msgt = // Message to be signed:
"a4 b1 59 94 17 61 c4 0c 6a 82 f2 b8 0d 1b 94 f5"
"aa 26 54 fd 17 e1 2d 58 88 64 67 9b 54 cd 04 ef"
"8b d0 30 12 be 8d c3 7f 4b 83 af 79 63 fa ff 0d"
"fa 22 54 77 43 7c 48 01 7f f2 be 81 91 cf 39 55"
"fc 07 35 6e ab 3f 32 2f 7f 62 0e 21 d2 54 e5 db"
"43 24 27 9f e0 67 e0 91 0e 2e 81 ca 2c ab 31 c7"
"45 e6 7a 54 05 8e b5 0d 99 3c db 9e d0 b4 d0 29"
"c0 6d 21 a9 4c a6 61 c3 ce 27 fa e1 d6 cb 20 f4"
"56 4d 66 ce 47 67 58 3d 0e 5f 06 02 15 b5 90 17"
"be 85 ea 84 89 39 12 7b d8 c9 c4 d4 7b 51 05 6c"
"03 1c f3 36 f1 7c 99 80 f3 b8 f5 b9 b6 87 8e 8b"
"79 7a a4 3b 88 26 84 33 3e 17 89 3f e9 ca a6 aa"
"29 9f 7e d1 a1 8e e2 c5 48 64 b7 b2 b9 9b 72 61"
"8f b0 25 74 d1 39 ef 50 f0 19 c9 ee f4 16 97 13"
"38 e7 d4 70";

signt = // Signature:
"0b 1f 2e 51 80 e5 c7 b4 b5 e6 72 92 9f 66 4c 48"
"96 e5 0c 35 13 4b 6d e4 d5 a9 34 25 2a 3a 24 5f"
"f4 83 40 92 0e 10 34 b7 d5 a5 b5 24 eb 0e 1c f1"
"2b ef ef 49 b2 7b 73 2d 2c 19 e1 c4 32 17 d6 e1"
"41 73 81 11 1a 1d 36 de 63 75 cf 45 5b 3c 98 12"
"63 9d bc 27 60 0c 75 19 94 fb 61 79 9e cf 7d a6"
"bc f5 15 40 af d0 17 4d b4 03 31 88 55 66 75 b1"
"d7 63 36 0a f4 6f ee ca 5b 60 f8 82 82 9e e7 b2";
    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;

printf("PKCS#1 v1.5 Signature Example 1.4\n");



msgt = // Message to be signed:
"bc 65 67 47 fa 9e af b3 f0";

signt = // Signature:
"45 60 7a d6 11 cf 57 47 a4 1a c9 4d 0f fe c8 78"
"bd af 63 f6 b5 7a 4b 08 8b f3 6e 34 e1 09 f8 40"
"f2 4b 74 2a da 16 10 2d ab f9 51 cb c4 4f 89 82"
"e9 4e d4 cd 09 44 8d 20 ec 0e fa 73 54 5f 80 b6"
"54 06 be d6 19 4a 61 c3 40 b4 ad 15 68 cb b7 58"
"51 04 9f 11 af 17 34 96 40 76 e0 20 29 ae e2 00"
"e4 0e 80 be 0f 43 61 f6 98 41 c4 f9 2a 44 50 a2"
"28 6d 43 28 9b 40 55 54 c5 4d 25 c6 ec b5 84 f4";
    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;

printf("PKCS#1 v1.5 Signature Example 1.5\n");



msgt = // Message to be signed:
"b4 55 81 54 7e 54 27 77 0c 76 8e 8b 82 b7 55 64"
"e0 ea 4e 9c 32 59 4d 6b ff 70 65 44 de 0a 87 76"
"c7 a8 0b 45 76 55 0e ee 1b 2a ca bc 7e 8b 7d 3e"
"f7 bb 5b 03 e4 62 c1 10 47 ea dd 00 62 9a e5 75"
"48 0a c1 47 0f e0 46 f1 3a 2b f5 af 17 92 1d c4"
"b0 aa 8b 02 be e6 33 49 11 65 1d 7f 85 25 d1 0f"
"32 b5 1d 33 be 52 0d 3d df 5a 70 99 55 a3 df e7"
"82 83 b9 e0 ab 54 04 6d 15 0c 17 7f 03 7f dc cc"
"5b e4 ea 5f 68 b5 e5 a3 8c 9d 7e dc cc c4 97 5f"
"45 5a 69 09 b4";

signt = // Signature:
"54 be 9d 90 87 75 15 f4 50 27 9c 15 b5 f6 1a d6"
"f1 5e cc 95 f1 8c be d8 2b 65 b1 66 7a 57 58 09"
"58 79 94 66 80 44 f3 bc 2a e7 f8 84 50 1f 64 f0"
"b4 3f 58 8c fa 20 5a 6a b7 04 32 8c 2d 4a b9 2a"
"7a e1 34 40 61 4d 3e 08 5f 40 1d a9 ad 28 e2 10"
"5e 4a 0e db 68 1a 64 24 df 04 73 88 ce 05 1e e9"
"df 7b c2 16 3f e3 47 52 0a d5 1c cd 51 80 64 38"
"3e 74 1a ca d3 cb dc 2c b5 a7 c6 8e 86 84 64 c2";
    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;

printf("PKCS#1 v1.5 Signature Example 1.6\n");



msgt = // Message to be signed:
"10 aa e9 a0 ab 0b 59 5d 08 41 20 7b 70 0d 48 d7"
"5f ae dd e3 b7 75 cd 6b 4c c8 8a e0 6e 46 94 ec"
"74 ba 18 f8 52 0d 4f 5e a6 9c bb e7 cc 2b eb a4"
"3e fd c1 02 15 ac 4e b3 2d c3 02 a1 f5 3d c6 c4"
"35 22 67 e7 93 6c fe bf 7c 8d 67 03 57 84 a3 90"
"9f a8 59 c7 b7 b5 9b 8e 39 c5 c2 34 9f 18 86 b7"
"05 a3 02 67 d4 02 f7 48 6a b4 f5 8c ad 5d 69 ad"
"b1 7a b8 cd 0c e1 ca f5 02 5a f4 ae 24 b1 fb 87"
"94 c6 07 0c c0 9a 51 e2 f9 91 13 11 e3 87 7d 00"
"44 c7 1c 57 a9 93 39 50 08 80 6b 72 3a c3 83 73"
"d3 95 48 18 18 52 8c 1e 70 53 73 92 82 05 35 29"
"51 0e 93 5c d0 fa 77 b8 fa 53 cc 2d 47 4b d4 fb"
"3c c5 c6 72 d6 ff dc 90 a0 0f 98 48 71 2c 4b cf"
"e4 6c 60 57 36 59 b1 1e 64 57 e8 61 f0 f6 04 b6"
"13 8d 14 4f 8c e4 e2 da 73";

signt = // Signature:
"0e 6f f6 3a 85 6b 9c bd 5d be 42 31 83 12 20 47"
"dd 39 d6 f7 6d 1b 23 10 e5 46 fe 9e e7 3b 33 ef"
"a7 c7 8f 94 74 45 5c 9e 5b 88 cb 38 3a af c3 69"
"86 68 e7 b7 a5 9a 9c bb 5b 08 97 b6 c5 af b7 f8"
"ba c4 b9 24 e9 8d 76 0a 15 fc 43 d2 81 4a b2 d5"
"18 7f 79 be d9 91 5a 93 39 7e bc 22 a7 67 75 06"
"a0 2e 07 6d 3f fd c0 44 1d bd 4d b0 04 53 dc 28"
"d8 30 e0 57 3f 77 b8 17 b5 05 c3 8b 4a 4b b5 d0";
    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;

printf("PKCS#1 v1.5 Signature Example 1.7\n");



msgt = // Message to be signed:
"ef b5 da 1b 4d 1e 6d 9a 5d ff 92 d0 18 4d a7 e3"
"1f 87 7d 12 81 dd da 62 56 64 86 9e 83 79 e6 7a"
"d3 b7 5e ae 74 a5 80 e9 82 7a bd 6e b7 a0 02 cb"
"54 11 f5 26 67 97 76 8f b8 e9 5a e4 0e 3e 8b 34"
"66 f5 ab 15 d6 95 53 95 29 39 ec 23 e6 1d 58 49"
"7f ac 76 aa 1c 0b b5 a3 cb 4a 54 38 35 87 c7 bb"
"78 d1 3e ef da 20 54 43 e6 ce 43 65 80 2d f5 5c"
"64 71 34 97 98 4e 7c a9 67 22 b3 ed f8 4d 56";

signt = // Signature:
"83 85 d5 85 33 a9 95 f7 2d f2 62 b7 0f 40 b3 91"
"dd f5 15 f4 64 b9 d2 cc 2d 66 39 8f c0 56 89 d8"
"11 63 29 46 d6 2e ab dc a7 a3 1f cf 6c d6 c9 81"
"d2 8b bc 29 08 3e 4a 6d 5b 2b 37 8c a4 e5 40 f0"
"60 b9 6d 53 ad 26 93 f8 21 78 b9 4e 2e 2f 86 b9"
"ac cf a0 20 25 10 7e 06 2a b7 08 01 75 68 45 01"
"02 8f 67 64 61 d8 1c 00 8f e4 75 06 71 64 99 70"
"87 8f c1 75 cf 98 e9 6b 2e cb f6 87 4d 77 da cb";
    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;

printf("PKCS#1 v1.5 Signature Example 1.8\n");



msgt = // Message to be signed:
"53 bb 58 ce 42 f1 98 49 40 55 26 57 23 3b 14 96"
"9a f3 65 c0 a5 61 a4 13 2a f1 8a f3 94 32 28 0e"
"3e 43 70 82 43 4b 19 23 18 37 18 4f 02 cf 2b 2e"
"72 6b eb f7 4d 7a e3 25 6d 8b 72 f3 ea fd b1 34"
"d3 3d e0 6f 29 91 d2 99 d5 9f 54 68 d4 3b 99 58"
"d6 a9 68 f5 96 9e db bc 6e 71 85 cb c7 16 c7 c9"
"45 da fa 9c c7 1d df aa a0 10 94 a4 52 dd f5 e2"
"40 73 20 40 0b f0 5e a9 72 9c af bf 06 00 e7 88"
"07 ef 94 62 e3 fd e3 2e d7 d9 81 a5 6f 47 51 ef"
"64 fb 45 49 91 0e cc 91 1d 72 80 53 b3 99 43 00"
"47 40 e6 f5 82 1f e8 d7 5c 06 17 bf 2c 6b 24 bb"
"fc 34 01 3f c9 5f 0d ed f5 ba 29 7f 50 4f b8 33"
"da 2a 43 6d 1d 8f f1 cc 51 93 e2 a6 43 89 fc ed"
"91 8e 7f eb 67 16 33 0f 66 80 1d b9 49 75 49 cf"
"1d 3b d9 7c f1 bc 62 55";

signt = // Signature:
"8e 1f 3d 26 ec 7c 6b bb 8c 54 c5 d2 5f 31 20 58"
"78 03 af 6d 3c 2b 99 a3 7c ed 6a 36 57 d4 ae 54"
"26 6f 63 ff fd e6 60 c8 66 d6 5d 0a b0 58 9e 1d"
"12 d9 ce 60 54 b0 5c 86 68 ae 12 71 71 cc aa e7"
"f1 cd 40 96 77 f5 21 57 b6 12 3a b2 27 f2 7a 00"
"96 6d 14 39 b4 2a 32 16 9d 10 70 39 40 26 fc 8b"
"c9 35 45 b1 ac 25 2d 0f 7d a7 51 c0 2e 33 a4 78"
"31 fb d7 15 14 c2 bb bd 3a db 67 40 c0 fd 68 ad";
    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;

printf("PKCS#1 v1.5 Signature Example 1.9\n");



msgt = // Message to be signed:
"27 ca dc 69 84 50 94 5f 20 4e c3 cf 8c 6c bd 8c"
"eb 4c c0 cb e3 12 27 4f a9 6b 04 de ac 85 51 60"
"c0 e0 4e 4a c5 d3 82 10 c2 7c";

signt = // Signature:
"7b 63 f9 22 33 56 f3 5f 61 17 f6 8c 8f 82 20 03"
"4f c2 38 4a b5 dc 69 04 14 1f 13 93 14 d6 ee 89"
"f5 4e c6 ff d1 8c 41 3a 23 c5 93 1c 7f bb 13 c5"
"55 cc fd 59 0e 0e aa 85 3c 8c 94 d2 52 0c d4 25"
"0d 9a 05 a1 93 b6 5d c7 49 b8 24 78 af 01 56 ee"
"1d e5 5d da d3 3e c1 f0 09 9c ad 6c 89 1a 36 17"
"c7 39 3d 05 fb fb bb 00 52 8a 00 1d f0 b2 04 eb"
"df 1a 34 10 90 de a8 9f 87 0a 87 74 58 42 7f 7b";
    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;

printf("PKCS#1 v1.5 Signature Example 1.10\n");



msgt = // Message to be signed:
"71 64 07 e9 01 b9 ef 92 d7 61 b0 13 fd 13 eb 7a"
"d7 2a ed";

signt = // Signature:
"2a 22 db e3 77 4d 5b 29 72 01 b5 5a 0f 17 f4 2d"
"ce 63 b7 84 5c b3 25 cf e9 51 d0 ba db 5c 5a 14"
"47 21 43 d8 96 c8 6c c3 39 f8 36 71 16 42 15 ab"
"c9 78 62 f2 15 16 54 e7 5a 3b 35 7c 37 31 1b 3d"
"72 68 ca b5 40 20 2e 23 be e5 27 36 f2 cd 86 cc"
"e0 c7 db de 95 e1 c6 00 a4 73 95 dc 5e b0 a4 72"
"15 3f bc 4f b2 1b 64 3e 0c 04 ae 14 dd 37 e9 7e"
"61 7a 75 67 c8 96 52 21 97 81 00 1b a6 f8 32 98";
    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;

printf("PKCS#1 v1.5 Signature Example 1.11\n");



msgt = // Message to be signed:
"46 c2 4e 41 03 00 16 29 c7 12 dd 4c e8 d7 47 ee"
"59 5d 6c 74 4c cc 4f 71 34 7d 9b 8a bf 49 d1 b8"
"fb 2e f9 1b 95 dc 89 9d 4c 0e 3d 29 97 e6 38 f4"
"cf 3f 68 e0 49 8d e5 aa bd 13 f0 df e0 2f f2 6b"
"a4 37 91 04 e7 8f fa 95 ff bd 15 06 7e f8 cb d7"
"eb 78 60 fe cc 71 ab e1 3d 5c 72 0a 66 85 1f 2d"
"ef d4 e7 95 05 4d 7b ec 02 4b b4 22 a4 6a 73 68"
"b5 6d 95 b4 7a eb af be ad d6 12 81 25 93 a7 0d"
"b9 f9 6d 45 1e e1 5e db 29 93 08 d7 77 f4 bb 68"
"ed 33 77 c3 21 56 b4 1b 7a 9c 92 a1 4c 8b 81 14"
"43 99 c5 6a 5a 43 2f 4f 77 0a a9 7d a8 41 5d 0b"
"da 2e 81 32 06 03 1e 70 62 00 31 c8 81 d6 16 bf"
"fd 5f 03 bf 14 7c 1e 73 76 6c 26 24 62 08";

signt = // Signature:
"12 23 5b 0b 40 61 26 d9 d2 60 d4 47 e9 23 a1 10"
"51 fb 24 30 79 f4 46 fd 73 a7 01 81 d5 36 34 d7"
"a0 96 8e 4e e2 77 77 ed a6 3f 6e 4a 3a 91 ad 59"
"85 99 8a 48 48 da 59 ce 69 7b 24 bb 33 2f a2 ad"
"9c e4 62 ca 4a ff dc 21 da b9 08 e8 ce 15 af 6e"
"b9 10 5b 1a bc f3 91 42 aa 17 b3 4c 4c 09 23 86"
"a7 ab bf e0 28 af db eb c1 4f 2c e2 6f be e5 ed"
"ec a1 15 02 d3 9a 6b 74 03 15 48 43 d9 8a 62 a7";
    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;

printf("PKCS#1 v1.5 Signature Example 1.12\n");



msgt = // Message to be signed:
"bc 99 a9 32 aa 16 d6 22 bf ff 79 c5 0b 4c 42 35"
"86 73 26 11 29 e2 8d 6a 91 8f f1 b0 f1 c4 f4 6a"
"d8 af a9 8b 0c a0 f5 6f 96 79 75 b0 a2 9b e8 82"
"e9 3b 6c d3 fc 33 e1 fa ef 72 e5 2b 2a e0 a3 f1"
"20 24 50 6e 25 69 0e 90 2e 78 29 82 14 55 56 53"
"22 84 cf 50 57 89 73 8f 4d a3 1f a1 33 3d 3a f8"
"62 b2 ba 6b 6c e7 ab 4c ce 6a ba";

signt = // Signature:
"87 2e c5 ad 4f 18 46 25 6f 17 e9 93 6a c5 0e 43"
"e9 96 3e a8 c1 e7 6f 15 87 9b 78 74 d7 7d 12 2a"
"60 9d c8 c5 61 14 5b 94 bf 4f fd ff de b1 7e 6e"
"76 ff c6 c1 0c 07 47 f5 e3 7a 9f 43 4f 56 09 e7"
"9d a5 25 02 15 a4 57 af df 12 c6 50 7c c1 55 1f"
"54 a2 80 10 59 58 26 a2 c9 b9 7f a0 aa 85 1c c6"
"8b 70 5d 7a 06 d7 20 ba 02 7e 4a 1c 0b 01 95 00"
"fb 63 b7 80 71 68 4d cf a9 77 27 00 b9 82 dc 66";
    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;

printf("PKCS#1 v1.5 Signature Example 1.13\n");



msgt = // Message to be signed:
"73 1e 17 2a c0 63 99 2c 5b 11 ba 17 0d fb 23 bb"
"00 0d 47 ba 19 53 29 cf 27 80 61 03 73 81 51 4c"
"14 60 64 c5 28 5d b1 30 dd 5b ae 98 b7 72 22 59"
"50 ea b0 5d 3e a9 96 f6 ff fb 9a 8c 86 22 91 3f"
"27 99 14 c8 9a da 4f 3d d7 76 66 a8 68 bf cb ff"
"2b 95 b7 da f4 53 d4 e2 c9 d7 5b ee e7 f8 e7 09"
"05 e4 06 6a 4f 73 ae cc 67 f9 56 aa 5a 32 92 b8"
"48 8c 91 7d 31 7c fd c8 62 53 e6 90 38 1e 15 ab";

signt = // Signature:
"76 20 4e ac c1 d6 3e c1 d6 ad 5b d0 69 2e 1a 2f"
"68 6d f6 e6 4c a9 45 c7 7a 82 4d e2 12 ef a6 d9"
"78 2d 81 b4 59 14 03 ff 40 20 62 02 98 c0 7e bd"
"3a 8a 61 c5 bf 4d ad 62 cb fc 4a e6 a0 39 37 be"
"4b 49 a2 16 d5 70 fc 6e 81 87 29 37 87 6e 27 bd"
"19 cf 60 1e ff c3 0d dc a5 73 c9 d5 6c d4 56 9b"
"db 48 51 c4 50 c4 2c b2 1e 73 8c dd 61 02 7b 8b"
"e5 e9 b4 10 fc 46 aa 3f 29 e4 be 9e 64 45 13 46";
    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;

printf("PKCS#1 v1.5 Signature Example 1.14\n");



msgt = // Message to be signed:
"02 11 38 26 83 a7 4d 8d 2a 2c b6 a0 65 50 56 3b"
"e1 c2 6c a6 28 21 e4 ff 16 3b 72 04 64 fc 3a 28"
"d9 1b ed dd c6 27 49 a5 53 8e af 41 fb e0 c8 2a"
"77 e0 6a d9 93 83 c9 e9 85 ff b8 a9 3f d4 d7 c5"
"8d b5 1a d9 1b a4 61 d6 9a 8f d7 dd ab e2 49 67"
"57 a0 c4 91 22 c1 a7 9a 85 cc 05 53 e8 21 4d 03"
"6d fe 01 85 ef a0 d0 58 60 c6 12 fa 08 82 c8 2d"
"24 6e 58 30 a6 73 55 df f1 8a 2c 36 b7 32 f9 88"
"cf ed c5 62 26 4c 62 54 b4 0f ca bb 97 b7 60 94"
"75 68 dc d6 a1 7c da 6e e8 85 5b dd ba b9 37 02"
"47 1a a0 cf b1 be d2 e1 31 18 eb a1 17 5b 73 c9"
"62 53 c1 08 d0 b2 ab a0 5a b8 e1 7e 84 39 2e 20"
"08 5f 47 40 4d 83 65 52 7d c3 fb 8f 2b b4 8a 50"
"03 8e 71 36 1c cf 97 34 07";

signt = // Signature:
"52 55 00 91 83 31 f1 04 2e ae 0c 5c 20 54 aa 7f"
"92 de b2 69 91 b5 79 66 34 f2 29 da f9 b4 9e b2"
"05 4d 87 31 9f 3c fa 9b 46 6b d0 75 ef 66 99 ae"
"a4 bd 4a 19 5a 1c 52 96 8b 5e 2b 75 e0 92 d8 46"
"ea 1b 5c c2 79 05 a8 e1 d5 e5 de 0e df db 21 39"
"1e bb 95 18 64 eb d9 f0 b0 ec 35 b6 54 28 71 36"
"0a 31 7b 7e f1 3a e0 6a f6 84 e3 8e 21 b1 e1 9b"
"c7 29 8e 5d 6f e0 01 3a 16 4b fa 25 d3 e7 31 3d";
    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;

printf("PKCS#1 v1.5 Signature Example 1.15\n");



msgt = // Message to be signed:
"fc 6b 70 0d 22 58 33 88 ab 2f 8d af ca f1 a0 56"
"20 69 80 20 da 4b ae 44 da fb d0 87 7b 50 12 50"
"6d c3 18 1d 5c 66 bf 02 3f 34 8b 41 fd 9f 94 79"
"5a b9 64 52 a4 21 9f 2d 39 d7 2a f3 59 cf 19 56"
"51 c7";

signt = // Signature:
"44 52 a6 cc 26 26 b0 1e 95 ab 30 6d f0 d0 cc 74"
"84 fb ab 3c 22 e9 70 32 83 56 7f 66 ea dc 24 8d"
"bd a5 8f ce 7d d0 c7 0c ce 3f 15 0f ca 4b 36 9d"
"ff 3b 62 37 e2 b1 62 81 ab 55 b5 3f b1 30 89 c8"
"5c d2 65 05 6b 3d 62 a8 8b fc 21 35 b1 67 91 f7"
"fb ca b9 fd 2d c3 3b ec b6 17 be 41 9d 2c 04 61"
"42 a4 d4 7b 33 83 14 55 2e dd 4b 6f e9 ce 11 04"
"ec ec 4a 99 58 d7 33 1e 93 0f c0 9b f0 8a 6e 64";
    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;

printf("PKCS#1 v1.5 Signature Example 1.16\n");



msgt = // Message to be signed:
"13 ba 08 6d 70 9c fa 5f ed aa 55 7a 89 18 1a 61"
"40 f2 30 0e d6 d7 c3 fe bb 6c f6 8a be bc bc 67"
"8f 2b ca 3d c2 33 02 95 ee c4 5b b1 c4 07 5f 3a"
"da 98 7e ae 88 b3 9c 51 60 6c b8 04 29 e6 49 d9"
"8a cc 84 41 b1 f8 89 7d b8 6c 5a 4c e0 ab f2 8b"
"1b 81 dc a3 66 76 97 b8 50 69 6b 74 a5 eb d8 5d"
"ec 56 c9 0f 8a be 51 3e fa 85 78 53 72 0b e3 19"
"60 79 21 bc a9 47 52 2c d8 fa c8 ca ce 5b 82 7c"
"3e 5a 12 9e 7e e5 7f 6b 84 93 2f 14 14 1a c4 27"
"4e 8c bb 46 e6 91 2b 0d 3e 21 77 d4 99 d1 84 0c"
"d4 7d 4d 7a e0 b4 cd c4 d3";

signt = // Signature:
"1f 3b 5a 87 db 72 a2 c9 7b b3 ef f2 a6 5a 30 12"
"68 ea cd 89 f4 2a bc 10 98 c1 f2 de 77 b0 83 2a"
"65 d7 81 5f eb 35 07 00 63 f2 21 bb 34 53 bd 43"
"43 86 c9 a3 fd e1 8e 3c a1 68 7f b6 49 e8 6c 51"
"d6 58 61 9d de 5d eb b8 6f e1 54 91 ff 77 ab 74"
"83 73 f1 be 50 88 80 d6 6e a8 1e 87 0e 91 cd f1"
"70 48 75 c1 7f 0b 10 10 31 88 bc 64 ee f5 a3 55"
"1b 41 4c 73 36 70 21 5b 1a 22 70 25 62 58 1a b1";
    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;

printf("PKCS#1 v1.5 Signature Example 1.17\n");



msgt = // Message to be signed:
"eb 1e 59 35";

signt = // Signature:
"37 0c b9 83 9a e6 07 4f 84 b2 ac d6 e6 f6 b7 92"
"1b 4b 52 34 63 75 7f 64 46 71 61 40 c4 e6 c0 e7"
"5b ec 6a d0 19 7e bf a8 6b f4 6d 09 4f 5f 6c d3"
"6d ca 3a 5c c7 3c 8b bb 70 e2 c7 c9 ab 5d 96 4e"
"c8 e3 df de 48 1b 4a 1b ef fd 01 b4 ad 15 b3 1a"
"e7 ae bb 9b 70 34 4a 94 11 08 31 65 fd f9 c3 75"
"4b bb 8b 94 dd 34 bd 48 13 df ad a1 f6 93 7d e4"
"26 7d 55 97 ca 09 a3 1e 83 d7 f1 a7 9d d1 9b 5e";
    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;

printf("PKCS#1 v1.5 Signature Example 1.18\n");



msgt = // Message to be signed:
"63 46 b1 53 e8 89 c8 22 82 09 63 00 71 c8 a5 77"
"83 f3 68 76 0b 8e b9 08 cf c2 b2 76";

signt = // Signature:
"24 79 c9 75 c5 b1 ae 4c 4e 94 0f 47 3a 90 45 b8"
"bf 5b 0b fc a7 8e c2 9a 38 df be dc 8a 74 9b 7a"
"26 92 f7 c5 2d 5b c7 c8 31 c7 23 23 72 a0 0f ed"
"3b 6b 49 e7 60 ec 99 e0 74 ff 2e ea d5 13 4e 83"
"05 72 5d fa 39 21 2b 84 bd 4b 8d 80 bc 8b c1 7a"
"51 28 23 a3 be b1 8f c0 8e 45 ed 19 c2 6c 81 77"
"07 d6 7f b0 58 32 ef 1f 12 a3 3e 90 cd 93 b8 a7"
"80 31 9e 29 63 ca 25 a2 af 7b 09 ad 8f 59 5c 21";
    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;

printf("PKCS#1 v1.5 Signature Example 1.19\n");



msgt = // Message to be signed:
"64 70 2d b9 f8 25 a0 f3 ab c3 61 97 46 59 f5 e9"
"d3 0c 3a a4 f5 6f ea c6 90 50 c7 29 05 e7 7f e0"
"c2 2f 88 a3 78 c2 1f cf 45 fe 8a 5c 71 73 02 09"
"39 29";

signt = // Signature:
"15 2f 34 51 c8 58 d6 95 94 e6 56 7d fb 31 29 1c"
"1e e7 86 0b 9d 15 eb d5 a5 ed d2 76 ac 3e 6f 7a"
"8d 14 80 e4 2b 33 81 d2 be 02 3a cf 7e bb db 28"
"de 3d 21 63 ae 44 25 9c 6d f9 8c 33 5d 04 5b 61"
"da c9 db a9 db bb 4e 6a b4 a0 83 cd 76 b5 80 cb"
"e4 72 20 6a 1a 9f d6 06 80 ce ea 1a 57 0a 29 b0"
"88 1c 77 5e ae f5 52 5d 6d 2f 34 4c 28 83 7d 0a"
"ca 42 2b bb 0f 1a ba 8f 68 61 ae 18 bd 73 fe 44";
    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;

printf("PKCS#1 v1.5 Signature Example 1.20\n");



msgt = // Message to be signed:
"94 19 21 de 4a 1c 9c 16 18 d6 f3 ca 3c 17 9f 6e"
"29 ba e6 dd f9 a6 a5 64 f9 29 e3 ce 82 cf 32 65"
"d7 83 7d 5e 69 2b e8 dc c9 e8 6c";

signt = // Signature:
"70 76 c2 87 fc 6f ff 2b 20 53 74 35 e5 a3 10 7c"
"e4 da 10 71 61 86 d0 15 39 41 3e 60 9d 27 d1 da"
"6f d9 52 c6 1f 4b ab 91 c0 45 fa 4f 86 83 ec c4"
"f8 dd e7 42 27 f7 73 cf f3 d9 6d b8 47 18 c4 94"
"4b 06 af fe ba 94 b7 25 f1 b0 7d 39 28 b2 49 0a"
"85 c2 f1 ab f4 92 a9 17 7a 7c d2 ea 0c 96 68 75"
"6f 82 5b be c9 00 fa 8a c3 82 4e 11 43 87 ef 57"
"37 80 ca 33 48 82 38 7b 94 e5 aa d7 a2 7a 28 dc";
    mlen = str_from_hex((uint8_t*) msg, msgt, -1);
    slen = str_from_hex((uint8_t*)sign, signt, -1);

    rsa_pkcs_sign(sign, pKey, (uint8_t*) msg, mlen);
printf("\nsign:\n");
    str_print_hex((uint8_t*)sign, klen>>3);
    str_from_hex(d, signt, -1);
    if (mpz_equ(d, sign, xlen)) printf("sign..OK\n");
    else fail++;
    if (rsa_pkcs_verify(sign, Key, (uint8_t*) msg, mlen)) printf("vrfy..OK\n");
    else fail++;


    return fail;
}
