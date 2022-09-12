/*! \defgroup _ecc Elliptic Curve Cryptography

    \todo Алгоритм NAF без сдвига

Оптимизации:
1) Не используются динамические данные. Для хранения сипользуется механизм слайсов
2) Длина числа, перенос или знак числа не хранятся в структуре числа
3) Операции по модулю заменены на операции быстрого редуцирования.
Быстрое редуцирование выполняется по модулю 2^m с учетом простого числа
4) использована собственная операция умножения чисел с редуцированием в конце операции.
Одна операция редуцирования на m сложений


TODO алгоритм компрессии.декомпрессии XY для кодов 00 02 03 04
Компрессия точек при конверсии из Octet string в EC_Point
свойства кривых P-192 P-256 P-384 P-521  p = 3 (mod 4)
для таких кривых есть простой метод квадратного корня по модулю p
w = z^(1/2) = z ^ ((p+1)/4) (mod p), где z = x^3+ax+b

00: P=infinity, 02: Y=0, 03: Y=1, 04: y||x
y = w; если w&1 == Y
y = p-w; если w&1 != Y

Общие рассуждения по теме инверсии
есть способ по эвклиду и со сдвигами (halving)
можно на каждом цикле делать сдвиг значения влево и тогда на выходе надо будет компенсировать количество
слвигов влево последовательным сдвигом вправо (Partal Montgomery Inversion)
деления можно откладывать

Есть алгоритм для подготовки NAF предварительный расчет точек 2^nG требует нескольких инверсий для
преобразования точек в аффинные координаты. Для этого можно использовать алгоритм одмновременного
вычисления инверсий для нескольких чисел. Инверсия считается для одного числа а остальные получаются путем перемножения
результата. Одна инверсия и три умножения вместо инверсии на каждое последующее значение \see GECC Alg 2.26


    \see [GECC] Guide to elliptic curve cryptography/ Darrel Hankerson at al. 2003
    \see [] Handbook of Elliptic and Hyperelliptic Curve Cryptography, 2005
    \see [RFC 6090] Fundamental Elliptic Curve Cryptography Algorithms, 2011
    \see [RFC 5903] Elliptic Curve Groups modulo a Prime (ECP Groups) for IKE and IKEv2, 2010
    \see [RFC 5832] GOST R 34.10-2001: Digital Signature Algorithm, 2010
    \see [RFC 4491] Using the GOST R 34.10-94, GOST R 34.10-2001, and
        GOST R 34.11-94 Algorithms with the Internet X.509 Public Key Infrastructure
        Certificate and CRL Profile
    \see [RFC 4357]
    \see [RFC 4050]
    \see http://www.secg.org Standards for Efficient Cryptography (SEC 1) (SEC 2)
    \see [SEC 1] Elliptic Curve Cryptography, May 21, 2009 Version 2.0
    \see [SEC 2] Recommended Elliptic Curve Domain Parameters, January 27, 2010 Version 2.0
    http://www.secg.org/sec2-v2.pdf

    \see [RFC 5639] Elliptic Curve Cryptography (ECC) Brainpool Standard Curves and Curve Generation, 2010
    \see [RFC 5915] Elliptic Curve Private Key Structure, 2010
    -- переместить в OCSP для генерации ключей
    \see [RFC 5933] Use of GOST Signature Algorithms in DNSKEY and RRSIG Resource Records for DNSSEC, 2010
    \see [RFC 6605] Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC, 2012
    \see [RFC 6460] Suite B Profile for Transport Layer Security (TLS),2012
    \see [RFC 6979] Deterministic DSA and ECDSA, August 2013
    \see [RFC 7091] GOST R 34.10-2012: Digital Signature Algorithm, December 2013
    \see [ТК26ЭК] ЗАДАНИЕ ПАРАМЕТРОВ ЭЛЛИПТИЧЕСКИХ КРИВЫХ В СООТВЕТСТВИИ С ГОСТ Р 34.10-2012
        http://www.tc26.ru/metodiki/%D0%A2%D0%9A26%D0%AD%D0%9A.pdf
    \see [RFC 7836]            Cryptographic Algorithms for GOST         March 2016
    \see [TK26ЭДВ]  ЗАДАНИЕ ПАРАМЕТРОВ СКРУЧЕННЫХ ЭЛЛИПТИЧЕСКИХ КРИВЫХ ЭДВАРДСА В СООТВЕТСТВИИ С ГОСТ Р 34.10-2012
        http://www.tc26.ru/methods/recommendation/CPECC14-TC26.pdf

    \see [NUMS] https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/curvegen.pdf

    \see [ГОСТ Р 50.1.114-2016] КРИПТОГРАФИЧЕСКАЯ ЗАЩИТА ИНФОРМАЦИИ
    Параметры эллиптических кривых для криптографических алгоритмов и протоколов
    id-tc26-gost-3410-12-512-paramSetA, «1.2.643.7.1.2.1.2.1.»
    id-tc26-gost-3410-12-512-paramSetB, «1.2.643.7.1.2.1.2.2.»
    id-tc26-gost-3410-2012-256-paramSetA, «1.2.643.7.1.2.1.1.1»
    id-tc26-gost-3410-2012-512-paramSetC, «1.2.643.7.1.2.1.2.3»
    \see [МР 26.2.002-2018] Параметры эллиптических кривых для криптографических алгоритмов и протоколов
    id-tc26-gost-3410-2012-256-paramSetB
    id-tc26-gost-3410-2012-256-paramSetC
    id-tc26-gost-3410-2012-256-paramSetD
    id-tc26-gost-3410-12-512-paramSetA
    id-tc26-gost-3410-12-512-paramSetB

    id-tc26-gost-3410-2012-256-paramSetA
    id-tc26-gost-3410-2012-512-paramSetC


# openssl genpkey -genparam -algorithm ec -pkeyopt ec_paramgen_curve:prime192v1 -out ecparam.pem
# openssl genpkey -paramfile ecparam.pem -out examples/pkey4.pem

# openssl genpkey -genparam -algorithm ec -pkeyopt ec_paramgen_curve:prime192v1 -text

# openssl ecparam -genkey -list_curves
# openssl ecparam -genkey -name secp128r1 -out k.pem

NIST P-192
1.2.840.10045.3.1.1
prime192v1
secp192r1
    The NIST 192 bit curve, its OID, X9.62 and SECP aliases.
NIST P-224
secp224r1
    The NIST 224 bit curve and its SECP alias.
NIST P-256
1.2.840.10045.3.1.7
prime256v1
secp256r1
    The NIST 256 bit curve, its OID, X9.62 and SECP aliases.
NIST P-384
secp384r1
    The NIST 384 bit curve and its SECP alias.
NIST P-521
secp521r1

тестирование на Solaris Express 11
 /usr/gcc/4.3/bin/gcc -o ecc src/mp.c src/ecc.c `pkg-config --cflags --libs glib-2.0` src/sha.c src/sha512.c src/gosthash.c src/rng_unix.c src/bn_asm.c src/r3_slice.c src/ecc_test_p384.c -DDEBUG_ECC -s -m64 -O3 -mssse3
тестирование на mingw32
 gcc -o ecc.exe src/mp.c src/ecc.c src/sha.c src/sha512.c src/gosthash.c src/rng_win32.c src/bn_asm.c src/r3_slice.c src/ecc_test_p384.c src/stribog.c -DDEBUG_ECC -s -O3 -march=corei7

ЭК в форме Вейерштрасса: y^2 = x^3+ax+b
ЭК в форме ск.  Эдвардса:   ex^2 + y^2 = 1 + dx^2y^2 (mod p)
a = s^2 - 3t^2, b = 2t^3 -ts^2
s=(e-d)/4, t = (e+d)/6
(x,y) --> (u,v) = ((x-t)/y, (x-t-s)/(x-t+s));
(u,v) --> (x,y) = (s(1+v)/(1-v)+t, s(1+v)/{(1-v)u})
Сложение точек Эдвардса для e=1
(x1,y1)+(x2,y2) = (x1y2+y1x2)/(1+dx1x2y1y2), (y1y2 - x1x2)/(1-dx1x2y1y2)
2P = (2xy)/(x^2+y^2), (y^2-x^2)/(2-(x^2+y^2))

ЭК в форме Монтгомери: Bv^2 = u^3+Au^2+u
e = (A+2)/B, d = (A-2)/B
A = 2(e+d)/(e-d), B = 4/(e-d)
Преобразование из формы Эдвардса (x,y) в Монтгомери (u,v)
(x,y) --> (u,v) = ((1+y)/(1-y), (1+y)/(1-y)x);
(u,v) --> (x,y) = (u/v, (u-1)/(u+1))
 
 http://www.gmbz.org.cn/upload/2018-07-24/1532401863206085511.pdf
 */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <malloc.h>
#include "hmac.h"


#include "ecc.h"
#include "sign.h"
/*
extern void sha160(uint8_t *hash, uint8_t *msg, int length);
extern void sha224(uint8_t *hash, uint8_t *msg, int length);
extern void sha256(uint8_t *hash, uint8_t *msg, int length);
extern void sha384(uint8_t *hash, uint8_t *msg, int length);
extern void sha512(uint8_t *hash, uint8_t *msg, int length);
extern int sha2(uint8_t *hash, int id, uint8_t *msg, int length);
extern int sha3(uint8_t *hash, int id, uint8_t *msg, int length);
extern int gost_hash(uint8_t *hash, int id, uint8_t *msg, int length);
extern int gost12_hash(uint8_t *hash, int id, uint8_t *msg, int length);

typedef int (*HashFunction)(uint8_t *hash, int id, uint8_t *msg, int length);
*/
/*

typedef struct _HashParams HashParams;
struct _HashParams {
    const char* const name;
    const HashFunction hash;
    const int id:8;
    const int length:8;
};
enum {
HASH_SHA_1,
HASH_SHA_224,
HASH_SHA_256,
HASH_SHA_384,
HASH_SHA_512,
HASH_SHA_512_224,
HASH_SHA_512_256,
HASH_GOST_TEST,
HASH_GOST_CRYPTO_PRO,
HASH_GOST_3411_12_256,
HASH_GOST_3411_12_512,
};
*/
/*
static const HashParams ecc_hashes[] = {
//    {"HASH_MD5",         NULL},
[HASH_SHA_1  ] = {"SHA-1",        sha2, 0, 20/4},
[HASH_SHA_224] = {"SHA-224",     sha2, 1, 28/4},
[HASH_SHA_256] = {"SHA-256",     sha2, 2, 32/4},
[HASH_SHA_384] = {"SHA-384",     sha3, 0, 48/4},
[HASH_SHA_512] = {"SHA-512",     sha3, 1, 64/4},
[HASH_SHA_512_224] = {"SHA-512/224", sha3, 2, 28/4},
[HASH_SHA_512_256] = {"SHA-512/256", sha3, 3, 32/4},
[HASH_GOST_TEST      ] = {"GOST R 34.11-94 Test",   gost_hash, 0, 32/4},
[HASH_GOST_CRYPTO_PRO] = {"GOST R 34.11-94 Crypto-Pro",  gost_hash, 1, 32/4},
[HASH_GOST_3411_12_256] = {"GOST R 34.11-2012 256",  gost12_hash, 0, 32/4},
[HASH_GOST_3411_12_512] = {"GOST R 34.11-2012 512",  gost12_hash, 1, 64/4},
};*/

typedef struct _EC_Alias EC_Alias;
struct _EC_Alias {
    const char* name;
    int id;
};
const EC_Alias ecc_alias[] ={
    {"secp112r1",   EC_SEC_P112r1},
    {"secp128r1",   EC_SEC_P128r1},
    {"secp128r2",   EC_SEC_P128r2},
    {"secp160k1",   EC_SEC_P160k1},
    {"secp160r1",   EC_SEC_P160r1},
    {"secp160r2",   EC_SEC_P160r2},
    {"NIST P-192", EC_NIST_P192},
    {"prime192v1", EC_NIST_P192},
    {"secp192r1",  EC_NIST_P192},
    {"secp192k1",  EC_SEC_P192k1},
    {"NIST P-224", EC_NIST_P224},
    {"secp224k1",  EC_SEC_P224k1},
    {"secp224r1",  EC_NIST_P224},

    {"wap-wsg-idm-ecid-wtls9",  EC_WTLS9_P160},
    {"wap-wsg-idm-ecid-wtls12",  EC_NIST_P224/*EC_WTLS12_P224*/},

    {"NIST P-256", EC_NIST_P256},
    {"prime256v1", EC_NIST_P256},
    {"secp256r1",  EC_NIST_P256},
    {"secp256k1",  EC_SEC_P256k1},
    {"prime239v1", EC_X962_P239v1},
    {"NIST P-384", EC_NIST_P384},
    {"secp384r1",  EC_NIST_P384},
    {"NIST P-521", EC_NIST_P521},
    {"secp521r1",  EC_NIST_P521},
    {"1.2.643.2.2.35.0", EC_GOST_TEST},
    {"1.2.643.2.2.35.1", EC_GOST_CRYPTO_PRO_A},// id-GostR3410-2001-CryptoPro-A-ParamSet
    {"1.2.643.2.2.35.2", EC_GOST_CRYPTO_PRO_B},// id-GostR3410-2001-CryptoPro-B-ParamSet
    {"1.2.643.2.2.35.3", EC_GOST_CRYPTO_PRO_C},// id-GostR3410-2001-CryptoPro-C-ParamSet
    {"1.2.643.2.2.36.0", EC_GOST_CRYPTO_PRO_A},// id-GostR3410-2001-CryptoPro-XchA-ParamSet
    {"1.2.643.2.2.36.1", EC_GOST_CRYPTO_PRO_C},// id-GostR3410-2001-CryptoPro-XchB-ParamSet
    {"1.2.643.7.1.2.1.1.1", EC_TC26_GOST_3410_2012_256_A}, // id-tc26-gost-3410-2012-256-paramSetA
    {"1.2.643.7.1.2.1.1.2", EC_TC26_GOST_3410_2012_256_B}, // id-tc26-gost-3410-2012-256-paramSetB
    {"1.2.643.7.1.2.1.1.3", EC_TC26_GOST_3410_2012_256_C}, // id-tc26-gost-3410-2012-256-paramSetC
    {"1.2.643.7.1.2.1.1.4", EC_TC26_GOST_3410_2012_256_D}, // id-tc26-gost-3410-2012-256-paramSetD
    {"1.2.643.7.1.2.1.2.0", EC_GOST_3410_12_TEST},// id-tc26-gost-3410-12-512-paramSetTest
    {"1.2.643.7.1.2.1.2.1", EC_TC26_GOST_3410_12_A},// id-tc26-gost-3410-12-512-paramSetA
    {"1.2.643.7.1.2.1.2.2", EC_TC26_GOST_3410_12_B},// id-tc26-gost-3410-12-512-paramSetB
    {"1.2.643.7.1.2.1.2.3", EC_TC26_GOST_3410_2012_512_C}, // id-tc26-gost-3410-2012-512-paramSetC
    {"SM2",EC_SM2},
    {NULL},
};

// функции быстрого редуцирования для каждой кривой
static void mp_reduction_gost_0  (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_gost_0_n(const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_gost_A  (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_gost_A_n(const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_gost_B  (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_gost_B_n(const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_gost_12A   (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_gost_12_A_n(const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_gost_12A_n (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_gost_12B   (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_gost_12B_n (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_gost_12C_n (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_nist_p192  (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_nist_p192_n(const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_nist_p224  (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_nist_p224_n(const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_sec_p128r1 (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_sec_p160r1 (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_sec_p160r1_n(const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_sec_p160r2 (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_wtls9_p160 (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_sec_p192k1 (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_sec_p224k1 (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_wtls12_p224(const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_p239       (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_sec_p256k1 (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_sec_p256k1_n(const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_nums_p256d1(const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_p25519     (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_nist_p256  (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_nist_p256_n(const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_nist_p384  (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_nist_p384_n(const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_nist_p521  (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_any     (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_anyC    (const MPCtx* const ctx, BNuint* x, BNuint cx);
static void mp_reduction_sm2     (const MPCtx* const ctx, BNuint* x, BNuint cx);


static const ECC_Params ecc_domain_params[] =
  {
/* secp112r1
p=DB7C2ABF62E35E668076BEAD208B
a=DB7C2ABF62E35E668076BEAD2088
b=659EF8BA043916EEDE8911702B22
gx=09487239995A5EE76B55F9C2F098
gy=A89CE5AF8724C0A23E0E0FF77500
n=DB7C2ABF62E35E7628DFAC6561C5

112k1
p=FFFF FFFFFFFF FFFFFFFF FFFFFDE7
a=0
b=3
gx=1
gy=2
n =010000 00000000 01ECEA55 1AD837E9
*/
[EC_SEC_P112r1]=
    {  "secp112r1", 112, 0, NULL, NULL,
        "DB7C2ABF62E35E668076BEAD208B",
        (void*)-3,
        "659EF8BA043916EEDE8911702B22",
        "DB7C2ABF62E35E7628DFAC6561C5",
        "09487239995A5EE76B55F9C2F098",
        "A89CE5AF8724C0A23E0E0FF77500"
    },
[EC_SEC_P128r1]=// secp128r1 2^128 -2^97 -1
    {  "secp128r1", 128, 0, mp_reduction_sec_p128r1, NULL,
        "FFFFFFFD FFFFFFFF FFFFFFFF FFFFFFFF",
        (void*)-3, //"FFFFFFFD FFFFFFFF FFFFFFFF FFFFFFFC",
        "E87579C1 1079F43D D824993C 2CEE5ED3",
        "FFFFFFFE 00000000 75A30D1B 9038A115",
        //"03 161FF752 8B899B2D 0C28607C A52C5B86",
        //"04 161FF752 8B899B2D 0C28607C A52C5B86 CF5AC839 5BAFEB13 C02DA292 DDED7A83"
        "161FF752 8B899B2D 0C28607C A52C5B86",
        "CF5AC839 5BAFEB13 C02DA292 DDED7A83"

    },
[EC_SEC_P128r2]=// secp128r2 2^128 -2^97 -1
    {  "secp128r2", 128, 0, mp_reduction_sec_p128r1, NULL,
        "FFFFFFFD FFFFFFFF FFFFFFFF FFFFFFFF",
        "D6031998 D1B3BBFE BF59CC9B BFF9AEE1",
        "5EEEFCA3 80D02919 DC2C6558 BB6D8A5D",
        "3FFFFFFF 7FFFFFFF BE002472 0613B5A3",
        "02 7B6AA5D8 5E572983 E6FB32A7 CDEBC140",
        //"04 7B6AA5D8 5E572983 E6FB32A7 CDEBC140 27B6916A 894D3AEE 7106FE80 5FC34B44",
    },
[EC_SEC_P160r1]=// secp160r1 2^160 -2^31 -1
    {  "secp160r1", 160, 0, /* mp_reduction_anyC*/ mp_reduction_sec_p160r1, mp_reduction_sec_p160r1_n,
        "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 7FFFFFFF",
        (void*)-3, //FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 7FFFFFFC
        "1C97BEFC 54BD7A8B 65ACF89F 81D4D4AD C565FA45",
/*01*/  "00000000 00000000 0001F4C8 F927AED3 CA752257",
        //"02 4A96B568 8EF57328 46646989 68C38BB9 13CBFC82",
/* 04 */"4A96B568 8EF57328 46646989 68C38BB9 13CBFC82",
        "23A62855 3168947D 59DCC912 04235137 7AC5FB32"

    },
[EC_SEC_P160r2]=// secp160r2 2^160 -2^32 -N
    {  "secp160r2", 160, 0, /* mp_reduction_anyC*/mp_reduction_sec_p160r2, NULL,
        "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFAC73",
        (void*)-3, //"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFAC70",
        "B4E134D3 FB59EB8B AB572749 04664D5A F50388BA",
/*01*/  "00000000 00000000 0000351E E786A818 F3A1A16B",
        //"02 52DCB034 293A117E 1F4FF11B 30F7199D 3144CE6D",
/*04*/  "52DCB034 293A117E 1F4FF11B 30F7199D 3144CE6D",
        "FEAFFEF2 E331F296 E071FA0D F9982CFE A7D43F2E"
    },
[EC_SEC_P160k1]=// secp160k1 2^160 -2^32 -N
    {  "secp160k1", 160, 0, mp_reduction_anyC/*mp_reduction_sec_p160r2*/, NULL,
        "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFAC73",
        (void*)0, //"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFAC70",
        "00000000 00000000 00000000 00000000 00000007",
        /*01*/"00000000 00000000 0001B8FA 16DFAB9A CA16B6B3",
        //"03 3B4C382C E37AA192 A4019E76 3036F4F5 DD4D7EBB",
        /*04*/"3B4C382C E37AA192 A4019E76 3036F4F5 DD4D7EBB",
        "938CF935 318FDCED 6BC28286 531733C3 F03C4FEE"
    },
// openssl ecparam -text -name secp192k1 -param_enc explicit
[EC_SEC_P192k1]=// secp192k1 2^160 -2^32 -N
    {  "secp192k1", 192, 0, mp_reduction_sec_p192k1, NULL,
        "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFEE37",
        (void*)0,
        "00000000 00000000 00000000 00000000 00000000 00000003",
        "FFFFFFFF FFFFFFFF FFFFFFFE 26F2FC17 0F69466A 74DEFD8D",
        "04 DB4FF10E C057E9AE 26B07D02 80B7F434 1DA5D1B1 EAE06C7D"
		   "9B2F2F6D 9C5628A7 844163D0 15BE8634 4082AA88 D95E2F9D"
    },
[EC_SEC_P224k1]=// secp224k1 2^224 -2^32 -N
    {  "secp224k1", 224, 0, mp_reduction_sec_p224k1, NULL,
        "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFE56D",
        (void*)0,
        "00000000 00000000 00000000 00000000 00000000 00000000 00000005",
        "01 00000000 00000000 00000000 0001DCE8 D2EC6184 CAF0A971 769FB1F7",
        "04 A1455B33 4DF099DF 30FC28A1 69A467E9 E47075A9 0F7E650E B6B7A45C"
           "7E089FED 7FBA3442 82CAFBD6 F7E319F7 C0B0BD59 E2CA4BDB 556D61A5"
    },
[EC_WTLS9_P160]=// secp160k1 2^160 -N
    {   "WTLS p160", 160, 0, mp_reduction_wtls9_p160, NULL, //mp_reduction_wtls9_p160, NULL,
        "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFC808F",
        (void*)0,
        "00000000 00000000 00000000 00000000 00000003",
        "01 00000000 00000000 0001CDC9 8AE0E2DE 574ABF33",
//        "02 00000000 00000000 00000000 00000000 00000001"
/* 04 */"00000000 00000000 00000000 00000000 00000001",
        "00000000 00000000 00000000 00000000 00000002"
    },
[EC_NIST_P192]=// синоним secp192r1 2^192 -2^64 -1
    { "NIST P-192", 192, 1, mp_reduction_nist_p192, mp_reduction_nist_p192_n,
      "0xfffffffffffffffffffffffffffffffeffffffffffffffff",
      (void*)-3,//"0xfffffffffffffffffffffffffffffffefffffffffffffffc",
      "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
      "0xffffffffffffffffffffffff99def836146bc9b1b4d22831",

      "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
      "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811"
    },
[EC_X962_P192v2]=
    {"ANSI X9.62 prime192v2", 192, 0, mp_reduction_nist_p192, NULL,
      "0xfffffffffffffffffffffffffffffffeffffffffffffffff",
      (void*)-3,//"0xfffffffffffffffffffffffffffffffefffffffffffffffc",
      "cc22d6dfb95c6b25e49c0d6364a4e5980c393aa21668d953",
      "fffffffffffffffffffffffe5fb1a724dc80418648d8dd31",
      "03eea2bae7e1497842f2de7769cfe9c989c072ad696f48034a"
    },
[EC_X962_P192v3]=
    {"ANSI X9.62 prime192v3", 192, 0, mp_reduction_nist_p192, NULL,
      "0xfffffffffffffffffffffffffffffffeffffffffffffffff",
      (void*)-3,//"0xfffffffffffffffffffffffffffffffefffffffffffffffc",
      "22123dc2395a05caa7423daeccc94760a7d462256bd56916",
      "ffffffffffffffffffffffff7a62d031c83f4294f640ec13",
      "027d29778100c65a1da1783716588dce2b8b4aee8e228f1896"
    },
/* \see EC_NIST_P224
[EC_WTLS12_P224]=// secp224r1 2^224 -2^96 +1
    {  "WTLS p224", 224, 0, mp_reduction_wtls12_p224, NULL,
        "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 00000000 00000001",
        (void*)-3,
        "B4050A85 0C04B3AB F5413256 5044B0B7 D7BFD8BA 270B3943 2355FFB4",
        "FFFFFFFF FFFFFFFF FFFFFFFF FFFF16A2 E0B8F03E 13DD2945 5C5C2A3D",
        "04 B70E0CBD 6BB4BF7F 321390B9 4A03C1D3 56C21122 343280D6 115C1D21"
           "BD376388 B5F723FB 4C22DFE6 CD4375A0 5A074764 44D58199 85007E34"
    },*/
[EC_NIST_P224]=// синоним secp224r1 2^224 -2^96 +1
    { "NIST P-224", 224, 1, mp_reduction_nist_p224, mp_reduction_nist_p224_n,
      "0xffffffffffffffffffffffffffffffff000000000000000000000001",
      (void*)-3,//"0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
      "0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
      "0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d" ,

      "0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
      "0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"
    },
[EC_X962_P239v1]=// 2^239 - 2^143 -2^95 + 2^47-1
    {   "ANSI X9.62 prime239v1", 239, 0, mp_reduction_p239, NULL,
        "7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff",
        (void*)-3,
        "6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a",
        "7fffffffffffffffffffffff7fffff9e5e9a9f5d9071fbd1522688909d0b",
        //"020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf"
/*04*/  "0ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf",
        "7debe8e4e90a5dae6e4054ca530ba04654b36818ce226b39fccb7b02f1ae"
    },
[EC_X962_P239v2]=
    {   "ANSI X9.62 prime239v2", 239, 0, mp_reduction_p239, NULL,
        "7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff",
        (void*)-3,
        "617fab6832576cbbfed50d99f0249c3fee58b94ba0038c7ae84c8c832f2c",
        "7fffffffffffffffffffffff800000cfa7e8594377d414c03821bc582063",
        "38af09d98727705120c921bb5e9e26296a3cdcf2f35757a0eafd87b830e7",
        "5b0125e4dbea0ec7206da0fc01d9b081329fb555de6ef460237dff8be4ba"
    },
[EC_X962_P239v3]=
    {   "ANSI X9.62 prime239v3", 239, 0, mp_reduction_p239, NULL,
        "7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff",
        (void*)-3,
        "255705fa2a306654b1f4cb03d6a750a30c250102d4988717d9ba15ab6d3e",
        "7fffffffffffffffffffffff7fffff975deb41b3a6057c3c432146526551",
        "6768ae8e18bb92cfcf005c949aa2c6d94853d0e660bbf854b1c9505fe95a",
        "1607e6898f390c06bc1d552bad226f3b6fcfe48b6e818499af18e3ed6cf3"
    },
/*
[EC_SEC_P256v1]=// openssl ecparam -text -name prime256v1 -param_enc explicit
    {   "ANSI X9.62 prime256v1", 256, 0, NULL, NULL,
        "ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff",
        (void*)-3,
        "5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6 3bce3c3e 27d2604b",
        "ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84 f3b9cac2 fc632551",
        "6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296",
        "4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5"
    },*/
[EC_WEI25519] =//
    {   "Wei25519", 255, 0, mp_reduction_p25519, NULL/*mp_reduction_p25519_n*/,
        "0x7fffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffed",
        "0x2aaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaa98 4914a144",
        "0x7b425ed0 97b425ed 097b425e d097b425 ed097b42 5ed097b4 260b5e9c 7710c864",
        "0x1fffffff ffffffff ffffffff ffffffff D6420C42 BA10C653 4FDB39CB 4614581D",
        //(=2^{253} - 0x29bdf3bd 45ef39ac b024c634 b9eba7e3) h=4
        "0x2aaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaad245a",
        "0x20ae19a1 b8a086b4 e01edd2c 7748d14c 923d4d7e 6d7c61b2 29e9c5a2 7eced3d9"
    } ,
[EC_NIST_P256]=// синоним secp256r1 2^255 -2^244 +2^192 +2^96 -1
    { "NIST P-256", 256, 1, mp_reduction_nist_p256, mp_reduction_nist_p256_n,
      "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
      (void*)-3,//"0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
      "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
      "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
// G = 03 6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296
      "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
      "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    },
[EC_SEC_P256k1]=// secp256k1  2^256 − 2^32 − 2^9 − 2^8 − 2^7 − 2^6 − 2^4 − 1  2^256 - 2^32 - 977 "1.3.132.0.10"
    { "secp256k1", 256, 0, mp_reduction_sec_p256k1, mp_reduction_sec_p256k1_n,
      "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f",
      (void*)0,
      "00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000007",
	  "ffffffff ffffffff ffffffff fffffffe baaedce6 af48a03b bfd25e8c d0364141",
	  //G = 02 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
	  "79be667e f9dcbbac 55a06295 ce870b07 029bfcdb 2dce28d9 59f2815b 16f81798",
	  "483ada77 26a3c465 5da4fbfc 0e1108a8 fd17b448 a6855419 9c47d08f fb10d4b8"

    },
[EC_NIST_P384]=// синоним secp384r1 2^384 -2^128 -2^96 +2^32 -1
    { "NIST P-384", 384, 1, mp_reduction_nist_p384, mp_reduction_nist_p384_n,
      "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
      "ffffffff0000000000000000ffffffff",
      (void*)-3,//"0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
      //"ffffffff0000000000000000fffffffc",
      "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
      "c656398d8a2ed19d2a85c8edd3ec2aef",
      "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
      "581a0db248b0a77aecec196accc52973",

      "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
      "5502f25dbf55296c3a545e3872760ab7",
      "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
      "0a60b1ce1d7e819d7a431d7c90ea0e5f"
    },
[EC_NIST_P521]=// синоним secp521r1 2^521 -1
    { "NIST P-521", 521, 1, mp_reduction_nist_p521, NULL,
      "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      (void*)-3,//"0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      //"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
      "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef10"
      "9e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      "ffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",

      "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3d"
      "baa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
      "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e6"
      "62c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"
    },
[EC_NUMS_P256d1] =// prime p= 2^256 - 189
{ "numsp256d1", 256, 0, mp_reduction_anyC, NULL,
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43",
    (void*)-3,
    "0x0000000000000000000000000000000000000000000000000000000000025581",
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE43C8275EA265C6020AB20294751A825",
    "0xBC9ED6B65AAADB61297A95A04F42CB0983579B0903D4C73ABC52EE1EB21AACB1",
    "0xD08FC0F13399B6A673448BF77E04E035C955C3D115310FBB80B5B9CB2184DE9F"
},
[EC_NUMS_P384d1] =// prime p= 2^384 - 317
{ "numsp384d1", 384, 0, mp_reduction_anyC, NULL,
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC3",
    (void*)-3,
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFF77BB",
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD61EAF1EEB5D6881"
    "BEDA9D3D4C37E27A604D81F67B0E61B9",
    "0x757956F0B16F181C4880CA224105F1A60225C1CDFB81F9F4F3BD291B2A6CC742"
    "522EED100F61C47BEB9CBA042098152A",
    "0xACDEE368E19B8E38D7E33D300584CF7EB0046977F87F739CB920837D121A837E"
    "BCD6B4DBBFF4AD265C74B8EC66180716",
},
[EC_NUMS_P512d1] =// prime p= 2^512 - 569
{ "numsp512d1", 512, 0, mp_reduction_anyC, NULL,
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
    (void*)-3,
    "0x0000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000001D99B",
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "5B3CA4FB94E7831B4FC258ED97D0BDC63B568B36607CD243CE153F390433555D",
    "0x3AC03447141D0A93DA2B7002A03D3B5298CAD83BB501F6854506E0C25306D9F9"
    "5021A151076B359E93794286255615831D5D60137D6F5DE2DC8287958CABAE57",
    "0x943A54CA29AD56B3CE0EEEDC63EBB1004B97DBDEABBCBB8C8F4B260C7BD14F14"
    "A28415DA8B0EEDE9C121A840B25A5602CF2B5C1E4CFD0FE923A08760383527A6",
},

#if 0
    { "brainpoolP160r1", 160, 0, NULL, NULL,
      "0xe95e4a5f737059dc60dfc7ad95b3d8139515620f",
      "0x340e7be2a280eb74e2be61bada745d97e8f7c300",
      "0x1e589a8595423412134faa2dbdec95c8d8675e58",
      "0xe95e4a5f737059dc60df5991d45029409e60fc09",
      "0xbed5af16ea3f6a4f62938c4631eb5af7bdbcdbc3",
      "0x1667cb477a1a8ec338f94741669c976316da6321"
    },

    { "brainpoolP192r1", 192, 0, NULL, NULL,
      "0xc302f41d932a36cda7a3463093d18db78fce476de1a86297",
      "0x6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef",
      "0x469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9",
      "0xc302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1",
      "0xc0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd6",
      "0x14b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f"
    },

    { "brainpoolP224r1", 224, 0, NULL, NULL,
      "0xd7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff",
      "0x68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43",
      "0x2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b",
      "0xd7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f",
      "0x0d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d",
      "0x58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd"
    },

    { "brainpoolP256r1", 256, 0, NULL, NULL,
      "0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
      "0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
      "0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
      "0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
      "0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
      "0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997"
    },

    { "brainpoolP320r1", 320, 0, NULL, NULL,
      "0xd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28"
      "fcd412b1f1b32e27",
      "0x3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f4"
      "92f375a97d860eb4",
      "0x520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd88453981"
      "6f5eb4ac8fb1f1a6",
      "0xd35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e9"
      "8691555b44c59311",
      "0x43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c7"
      "10af8d0d39e20611",
      "0x14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7"
      "d35245d1692e8ee1"
    },

    { "brainpoolP384r1", 384, 0, NULL, NULL,
      "0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123"
      "acd3a729901d1a71874700133107ec53",
      "0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f"
      "8aa5814a503ad4eb04a8c7dd22ce2826",
      "0x04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d5"
      "7cb4390295dbc9943ab78696fa504c11",
      "0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7"
      "cf3ab6af6b7fc3103b883202e9046565",
      "0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8"
      "e826e03436d646aaef87b2e247d4af1e",
      "0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff9912928"
      "0e4646217791811142820341263c5315"
    },

    { "brainpoolP512r1", 512, 0, NULL, NULL,
      "0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330871"
      "7d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
      "0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc"
      "2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
      "0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a7"
      "2bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
      "0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870"
      "553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
      "0x81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098e"
      "ff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
      "0x7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111"
      "b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892"
    },
/// TODO поменять местами числа, поменять константы
	/* default_cc_sign01_param 1.2.643.2.9.1.8.1 id_GostR3410_2001_ParamSet_cc*/
	{"1.2.643.2.9.1.8.1", 256, 0, NULL, NULL,
	/* P */
	"C0000000000000000000000000000000000000000000000000000000000003C7",
	/* A = P-3 */
	NULL,//"C0000000000000000000000000000000000000000000000000000000000003c4",
	/* B */
	"2d06B4265ebc749ff7d0f1f1f88232e81632e9088fd44b7787d5e407e955080c",
	/* Q */
	"5fffffffffffffffffffffffffffffff606117a2f4bde428b7458a54b6e87b85",
	/* X */
	"2",
	/* Y */
	"a20e034bf8813ef5c18d01105e726a17eb248b264ae9706f440bedc8ccb6b22c"
	},
#endif
[EC_GOST_TEST]= /*1.2.643.2.2.35.0 NID_id_GostR3410_2001_TestParamSet*/
	{"GOST R 34.10-2001 Test", 256, 0, NULL, NULL, //mp_reduction_gost_0, mp_reduction_gost_0_n,
	"8000000000000000000000000000000000000000000000000000000000000431",
	"7",
	"5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E",
	"8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3",
	"2",
	"08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8"
	},
[EC_GOST_CRYPTO_PRO_A]= /*1.2.643.2.2.35.1 id-GostR3410-2001-CryptoPro-A-ParamSet*/
    {"GOST R 34.10-2001 CryptoPro A", 256, 0, mp_reduction_gost_A, mp_reduction_gost_A_n,
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
	(void*)-3,//"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
	"a6",
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893",
	"1",
	"8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"
	},
[EC_GOST_CRYPTO_PRO_B]=	/*1.2.643.2.2.35.2 id_GostR3410_2001_CryptoPro_B_ParamSet */
	{"GOST R 34.10-2001 CryptoPro B", 256, 0, mp_reduction_gost_B, mp_reduction_gost_B_n,
	"8000000000000000000000000000000000000000000000000000000000000C99",
	(void*)-3,//"8000000000000000000000000000000000000000000000000000000000000C96",
	"3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B",
	"800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F",
	"1",
	"3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC"
	},
[EC_GOST_CRYPTO_PRO_C]=/* id-GostR3410-2001-CryptoPro-C-ParamSet */
    {"GOST R 34.10-2001 CryptoPro C", 256, 0, NULL, NULL,
    "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B",
    (void*)-3,
    "805A",//32858
    "9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9",
    "0",
    "41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67"
    },
[EC_TC26_GOST_3410_2012_256_A]=	/* id-tc26-gost-3410-2012-256-paramSetA p = 2^256-617 */
	{"GOST R 34.10-2012 TC26 ParamSetA", 256, 0, mp_reduction_gost_A,  mp_reduction_gost_12_A_n,//ту ду алгоритм редуцирования
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
	"C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335",
	"295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513",
///* 01 */"000000000000000000000000000000003F63377F21ED98D70456BD55B0D8319C",
    "400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67",
	"91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28",
	"32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C"

/* Эдвардса: ex^2+y^2 = 1+dx2y2
SEQUENCE {
p INTEGER,
a INTEGER,
b INTEGER,
e INTEGER,
d INTEGER,
m INTEGER,
q INTEGER,
x INTEGER,
y INTEGER,
u INTEGER,
v INTEGER
}
*/
	},
[EC_GOST_3410_12_TEST]=	/* id-tc26-gost-3410-12-512-Test */
    {"GOST R 34.10-2012 Test",512,0, NULL, NULL,
    "4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15D"
    "F1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373",
    "7",
    "1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC43"
    "61834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC",
    "4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15D"
    "A82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF",
    "24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762"
    "FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A",
    "2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2C"
    "83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371E"
},
[EC_TC26_GOST_3410_12_A]=	/* id-tc26-gost-3410-12-512-paramSetA p = 2^512 - 569 */
	{"GOST R 34.10-2012 A", 512, 0, mp_reduction_gost_12A, mp_reduction_gost_12A_n,
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
	(void*)-3,// -3
	"E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265"
	"EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760",
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
	"27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275",
	"3",
	"7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921"
	"DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4"
},
[EC_TC26_GOST_3410_12_B]=	/* id-tc26-gost-3410-12-512-paramSetB p = 2^511 + 111 */
	{"GOST R 34.10-2012 B", 512, 0, mp_reduction_gost_12B, mp_reduction_gost_12B_n,
	"8000000000000000000000000000000000000000000000000000000000000000"
	"000000000000000000000000000000000000000000000000000000000000006F",
	(void*)-3,// -3
	"687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F"
	"3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116",
    "8000000000000000000000000000000000000000000000000000000000000001"
    "49A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD",
	"2",
	"1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335"
	"DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD"
	},
[EC_TC26_GOST_3410_2012_512_C]=	/* id-tc26-gost-3410-2012-512-paramSetС p = 2^512 - 569 */
    {"GOST R 34.10-2012 TC26 ParamSetC", 512, 0, mp_reduction_gost_12A, mp_reduction_gost_12C_n,
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
    "DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E1430645"
    "46E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3",
    "B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE0"
    "38CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1",
    "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "C98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED",// q
//    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
//    "26336E91941AAC0130CEA7FD451D40B323B6A79E9DA6849A5188F3BD1FC08FB4",// n
    "E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043A"
    "A27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148", //x
    "F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9B"
    "E18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F"
/* Эдвардса
e = 1
d = 9E4F5D8C017D8D9F13A5CF3CDF5BFE4DAB402D54198E31EBDE28A0
621050439CA6B39E0A515C06B304E2CE43E79E369E91A0CFC2BC2A22B4CA302DBB33EE7550
q = 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9
FF5147502CC8EDA9E7A769A12694623CEF47F023ED
u = 12
v = 469AF79D1FB1F5E16B99592B77A01E2A0FDFB0D01794368D9A56117F7B3866952
2DD4B650CF789EEBF068C5D139732F0905622C04B2BAAE7600303EE73001A3D

*/
    },
[EC_SM2] =// Chinese SM2 public  key  standard 2^256-2^225+2^224-2^96+2^64-1
    {   "SM2", 256, 0, mp_reduction_sm2, NULL,
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
        (void*)-3,
/* b */ "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
/* X_G*/"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
        "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
    },
[EC_COUNT] = {NULL, 0, 0, NULL, NULL, NULL, NULL }
};
/*! Алгоритм редуцирования годится для случая когда p = 2^n - c
    \see [GECC] Alg. 2.54
 */
static void mp_reduction_anyC(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
    BNuint v[ctx->asize] BN_ALIGN;
    bn_set_0(&v[2], ctx->size-2);
//    bn_set_neg(v, ctx->prime, 2);
    v[0] = -ctx->prime[0]; v[1] = ~ctx->prime[1];
    v[2] = bn_mul_ui(v, v, cx, 2);
    BNint cy = bn_add1(x, v, ctx->size);
    if (cy>0)/* cy +=*/ bn_sub1(x, ctx->prime, ctx->size);

}

/*! \brief редукция Барретта */
static BNuint mp_reduction_barrett(const MPCtx* const ctx, BNuint* x, BNuint cx)
{

    BNuint Pr = ctx->prime[ctx->size-1];
    if (cx>=Pr) {
          printf("CX=%08X (Pr=%08X)\n", cx, Pr);
          _Exit(839);
    }
    if (0) printf("CX=%08X (Pr=%08X)\n", cx, Pr);
#if (BN_BIT_LOG==6)//defined(__x86_64__)
    uint64_t c = ((unsigned __int128)(cx<<64) | (x[ctx->size-1]))/Pr;
#else
    uint32_t c = (((uint64_t)cx<<32) | (x[ctx->size-1]))/Pr;
//    uint32_t c = (((uint64_t)cx<<32))/Pr;
#endif
    BNuint v[ctx->asize] BN_ALIGN;
    if (0) printf("C =%08X\n", c);
    cx -= bn_mul_ui(v, ctx->prime, c, ctx->size);
    cx += bn_sub1(x, v, ctx->size);
    //cx += bn_mls_ui(x, ctx->prime, c, ctx->size);
    if ((BNint)cx>0) {
        cx += bn_sub1(x, ctx->prime, ctx->size);
        do { // GOST R 34.10-2012 Test для этой кривой понадобился цикл
            cx += bn_sub1(x, ctx->prime, ctx->size);
        } while(cx);

    }
    else
    if ((BNint)cx<0) {
        static int max_count=1;
        int count =0;
        do { // GOST R 34.10-2012 Test для этой кривой понадобился цикл
            cx += bn_add1(x, ctx->prime, ctx->size);
            count++;
        } while(cx);
        if (max_count<count) {
            max_count=count;
            printf ("\n MAX count=%d\n", count);
        }
    }
    if (cx!=0) {
          printf("CX=%08X\n", cx);
          _Exit(234);
    }
    return cx;
}
// ТОDO не работает на 64битах
static void mp_reduction_any(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
    BNuint Pr = ctx->prime[ctx->size-1];
    if (cx >= Pr){
        if (1 && (BNint)Pr>0){
            BNuint c = (BNuint)cx/Pr;
            BNuint v[ctx->asize] BN_ALIGN;
            bn_mul_ui(v, ctx->prime, c, ctx->size);
            cx -= v[ctx->size-1];
            cx += bn_sub1(x+1, v, ctx->size-1);
            //cx += bn_mls_ui(x, ctx->prime, c, ctx->size);
            if ((BNint)cx>0) {
                cx += bn_sub1(x, ctx->prime, ctx->size);
            }
            else
            if ((BNint)cx<0) {
                cx += bn_add1(x, ctx->prime, ctx->size);
                _Exit(874);
            }
        } else {
            cx -= Pr;
            cx += bn_sub1(&x[1], ctx->prime, ctx->size-1);
            while (cx<0) {
                cx += bn_add1(x, ctx->prime, ctx->size);
            }
        }
    }
    if (cx) {
        cx = mp_reduction_barrett(ctx, x, cx);
    }
}
/*! \brief Редуцирование большого числа в заданную длину
Используется в процессе перобразования Хеш функции в число в поле, например в EdDSA
*/
static void mp_reduction(const MPCtx* const ctx, BNuint* x, int size)
{
    int i;
    for (i=size - ctx->size-1; i>=0; i--) {
        ctx->reduction(ctx, &x[i], x[i+ ctx->size]);
        x[i+ ctx->size]=0;
    }
}
#if 0 // исключили ассемблер
#if defined(__x86_64__)
#define MUL(lo,hi, a,w) ({    \
            unsigned __int128 r = (uint64_t)(a)*(w); \
            lo = r, hi = r>>64; \
        });
#warning "__x86_64__"
#else//if defined(__i386__)
#define MUL(lo,hi, a,w) ({    \
            uint64_t r = (uint64_t)(a)*(w); \
            lo = r, hi = r>>32; \
        });
#endif
#if 0 //defined(__x86_64__)
#define MUL_(lo,hi, a,w) ({    \
        asm ("mulq %3"                  \
                : "=a"(lo),"=d"(hi)  \
                : "a"(w),"g"(a)      \
                : "cc");                \
        })

#define MUL(lo,hi, a,w) ({    \
        asm ("mull %3"                  \
                : "=a"(lo),"=d"(hi)  \
                : "a"(w),"g"(a)      \
                : "cc");                \
        })
#endif // 0
#endif
/*! \brief Алгоритм быстрого редуцирования числа по prime filed prime = 2^255 + p0
    \see ГОСТ P 34.10-2001 набор параметров Тест

    \param ctx контекст простого числа
    \param x   число
    \param cx  перенос, для которого выполняется операция
    \return перенос = 0
 */
static void mp_reduction_gost_0(const MPCtx* const ctx, BNuint* x, BNuint cx)
{//    static const int64_t p0 = 0x431*2;
    //int64_t c = cx*0x862ULL; // TODO макрос нужен для умножения
    //BNuint lo,hi;
    //MUL(lo,hi, cx, 0x862);// на два p сдвигаем
    //BNuint v[256>>BN_BIT_LOG] BN_ALIGN = {lo, hi,0};
//    BNuint v[256>>BN_BIT_LOG] BN_ALIGN = {0x862,0};
//    v[2] = bn_mul_ui(v, v, cx, 2);
//    BNint cy = bn_sub1(x, v, 8);
    BNint cy = bn_mls_1_256(x, 0x862, cx);// {cy,x} := {cx,x} - 2*p*cx = x - 2p0*cx;
    if (cy<0) {
        /*cy += */bn_add1(x, ctx->prime, 8);// prime = 2^255+p0
        //if (cy<0) cy += bn_add1(x, ctx->prime, 8);// prime = 2^255+p0
    }
}
static void mp_reduction_gost_0_n(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
//    uint32_t v[8] = {0x3ACCF5B3, 0xC59CFC19,0x92976154,0x50FE8A18, 0x1,0,0,0};
//    bn_shl(v,v, 1, ctx->size-2);
    const BNuint p[256>>BN_BIT_LOG] BN_ALIGN = {BN2(0x7599EB66, 0x8B39F832),BN2(0x252EC2A9,0xA1FD1431), BN2(0x2,0)};
    //BNuint v[256>>BN_BIT_LOG] BN_ALIGN = {0};
    //bn_mul_ui(v, p, cx, 6);// нужно четное число слов
    //BNint cy = bn_sub1(x, v, 8);// можно ввести операцию mac->mulsub - вычесть из аккумулятора
    BNint cy = bn_mls_256(x, p, cx);
    if (cy<0) /* cy += */bn_add1(x, p, 8);
}
/*! \brief Алгоритм быстрого редуцирования числа по prime filed prime = 2^512 - p0

id-tc26-gost-3410-12-512-paramSetA p = 2^512 - 569
    \see ГОСТ P 34.10-2012 набор параметров A
    \see Методические рекомендации по заданию параметров эллиптических кривых в соответствии с ГОСТ Р 34.10-2012
        http://tc26.ru/metodiki/draft/CPECC12-TC26.pdf
    \param ctx контекст простого числа
    \param x   число
    \param cx  перенос, для которого выполняется операция
    \return перенос
 */
static void mp_reduction_gost_12A(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
//    BNuint lo,hi;
//    MUL(lo,hi, cx, 569);
//    BNuint v[512>>BN_BIT_LOG] BN_ALIGN = {BN2(lo, hi),};
//    const BNuint p[512>>BN_BIT_LOG] BN_ALIGN = {BN2(569, 0),};
//    BNuint v[512>>BN_BIT_LOG] BN_ALIGN = {0};
//    v[2] = bn_mul_ui(v, p, cx, 2);
//    BNint cy = bn_add1(x, v, 16);
    const BNuint p0 = 569;// prime p = 2^512 - p0 = ({1,0} - p0);
    BNuint cy = bn_mla_1_512(x, p0, cx);// {cy,x} := {cx, x} - p*cx = x + p0*cx;
    if (cy>0)/* cy +=*/ bn_add_1_512(x, p0);// {cy,x} := {1,x} - ({1,0}-p0) = x + p0;
}
static void mp_reduction_gost_12A_n(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
//    uint32_t v[8] BN_ALIGN = {(~N0)+1, ~N1, ~N2, ~N3,0,0};
// -27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275
//  27E69532 F48D8911 6FF22B8D 4E056060 9B4B38AB FAD2B85D CACDB141 1F10B275
    const BNuint p[512>>BN_BIT_LOG] BN_ALIGN = {BN2(0xE0EF4D8B, 0x35324EBE), BN2(0x052D47A2, 0x64B4C754), BN2(0xB1FA9F9F, 0x900DD472), BN2(0xB7276EE, 0xD8196ACD),};
//    BNuint v[512>>BN_BIT_LOG] BN_ALIGN = {0};
//    v[256>>BN_BIT_LOG] = bn_mul_ui(v, p, cx, 8);
//    BNuint cy = bn_add1(x, v, 16);
// prime p = 2^512 - p0 = ({1,0} - p0);
    BNuint cy = bn_mla_256_512(x, p, cx);
    if (cy>0)/* cy +=*/ bn_add1(x, p, 16);
}
static void mp_reduction_gost_12C_n(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
//    uint32_t v[8] BN_ALIGN = {(~N0)+1, ~N1,0,0,0,0};
//  3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
//  C98CDBA4 6506AB00 4C33A9FF 5147502C C8EDA9E7 A769A126 94623CEF 47F023ED
//  2^254-p0
// 4*
// 26336E91941AAC0130CEA7FD451D40B323B6A79E9DA6849A5188F3BD1FC08FB4
//  26336E91 941AAC01 30CEA7FD 451D40B3 23B6A79E 9DA6849A 5188F3BD 1FC08FB4
    const BNuint p[512>>BN_BIT_LOG] BN_ALIGN = {BN2(0xE03F704C, 0xAE770C42), BN2(0x62597B65, 0xDC495861), BN2(0xBAE2BF4C, 0xCF315802), BN2(0x6BE553FE, 0xD9CC916E),};
//    BNuint v[512>>BN_BIT_LOG] BN_ALIGN = {0};
//    v[256>>BN_BIT_LOG] = bn_mul_ui(v, p, cx, 8);
//    BNint cy = bn_add1(x, v, 16);
    BNint cy = bn_mla_256_512(x, p, cx);// {cy, x} := {cx, x} - ({1,0}-p0*4)*cx = x + 4*p0*cx
    if (cy>0) {
            cy += bn_sub1(x, ctx->prime, 16);
//            printf ("gost_12C_n >0\n");
    }
    if (cy>0) {printf ("gost_12C_n >0\n"); _Exit(1);}
}

/*! \brief Алгоритм быстрого редуцирования числа по prime filed prime = 2^511 + p1
    \see ГОСТ P 34.10-2012 набор параметров B
    \param ctx контекст простого числа
    \param x   число
    \param cx  перенос, для которого выполняется операция
    \return перенос
 */
static void mp_reduction_gost_12B(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
//    static const int64_t p0 = 111*2;
    //BNuint lo,hi;
    //MUL(lo,hi, cx, 222);
    //BNuint v[512>>BN_BIT_LOG] BN_ALIGN = {lo, hi,};
    //BNuint p[512>>BN_BIT_LOG] BN_ALIGN = {222, 0,};
    //v[2] = bn_mul_ui(v, v, cx, 2);
    //BNint cy = bn_sub1(x, v, 16);
    //BNint cy = bn_mls_1(x, p, cx, 16);
    BNint cy = bn_mls_1_512(x, 222, cx);
    if (cy<0)/* cy +=*/ bn_add1(x, ctx->prime, 16);
}
static void mp_reduction_gost_12B_n(const MPCtx* const ctx, BNuint* x, BNuint cx)
{// 1 49A1EC14 2565A545 ACFDB77B D9D40CFA 8B996712 101BEA0E C6346C54 374F25BD
 // 6E9E4B7A 8C68D8A8 2037D41D 1732CE24 B3A819F5 59FB6EF7 4ACB4A8B 9343D828 2
    const BNuint p[512>>BN_BIT_LOG] BN_ALIGN = {BN2(0x6E9E4B7A, 0x8C68D8A8), BN2(0x2037D41D, 0x1732CE24), BN2(0xB3A819F5, 0x59FB6EF7), BN2(0x4ACB4A8B, 0x9343D828), BN2(0x2,0)};
    //v[5] =
//    bn_mul_ui(v, v, cx, 10); // четное число слов для выравнивания
//    BNint cy = bn_sub1(x, v, 16);
// prime p = 2^511 + p0
    BNint cy = bn_mls_512(x, p, cx);// {cy,x} := {cx,x} - ({1,0}+2*p0)*cx = x - 2p0*cx;
    if (cy<0)/* cy +=*/ bn_add1(x, ctx->prime,16);
}
/*! 2^128 -2^97 -1 */
static void mp_reduction_sec_p128r1(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
    BNuint v[128>>BN_BIT_LOG] BN_ALIGN = {cx,0, 0, cx<<1};// {lo, hi+1,};
    BNint cy = cx>>31;//bn_mul_ui(v, v, cx, 4);

	if (cy!=0) bn_sub1(x, ctx->prime, 4);
    //if (cv!=0) printf("%X\n", cv);
    cy = bn_add1(x, v, 4);
    if (cy>0) bn_sub1(x, ctx->prime, 4);
//    if (cy>0) cy += bn_sub1(x, ctx->prime, 4);
//    if (cy!=0) printf("%X\n", cy);
}
/*! 2^160 -2^31 -1 */
static void mp_reduction_sec_p160r1(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
    BNuint v[160>>BN_BIT_LOG] BN_ALIGN = {BN2(0x80000001,0)};// {lo, hi+1,};
    v[2]= bn_mul_ui(v, v, cx, 2);
    BNint cy = bn_add1(x, v, 5);
    if (cy>0) bn_sub1(x, ctx->prime, 5);
}
static void mp_reduction_sec_p160r1_n(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
    BNuint v[160>>BN_BIT_LOG] BN_ALIGN = {BN2(0xCA752257,0xF927AED3),BN2(0x0001F4C8,0)};// {lo, hi+1,};
    v[4]= bn_mul_ui(v, v, cx, 4);
    BNint cy = bn_sub1(x, v, 5);
    if (cy<0) cy+=bn_add1(x, ctx->prime, 5);
    if (cy!=0) printf("\ncy=%d\n", cy);
}

/*! 2^160 -2^32 -0x538C */
static void mp_reduction_sec_p160r2(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
    BNuint v[160>>BN_BIT_LOG] BN_ALIGN = {BN2(0x538D,0x1)};// {lo, hi+1,};
    v[2]= bn_mul_ui(v, v, cx, 2);
    BNint cy = bn_add1(x, v, 5);
    if (cy>0) bn_sub1(x, ctx->prime, 5);
}
static void mp_reduction_wtls9_p160(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
    BNuint v[160>>BN_BIT_LOG] BN_ALIGN = {BN2(0x37F71,0)};
    v[2]= bn_mul_ui(v, v, cx, 2);
    BNint cy = bn_add1(x, v, 5);
    if (cy>0) bn_sub1(x, ctx->prime, 5);
}
static void mp_reduction_sec_p192k1(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
    BNuint v[192>>BN_BIT_LOG] BN_ALIGN = {BN2(0x11C9,0x1)};// {lo, hi+1,};
    v[2]= bn_mul_ui(v, v, cx, 2);
    BNint cy = bn_add1(x, v, 6);
    if (cy>0) bn_sub1(x, ctx->prime, 6);
}
static void mp_reduction_sec_p224k1(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
    BNuint v[224>>BN_BIT_LOG] BN_ALIGN = {BN2(0x1A93,0x1)};
    v[2]= bn_mul_ui(v, v, cx, 2);
    BNint cy = bn_add1(x, v, 7);
    if (cy>0) bn_sub1(x, ctx->prime, 7);
}
static void mp_reduction_wtls12_p224(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
    BNuint v[224>>BN_BIT_LOG] BN_ALIGN = {-cx,-1, -1,cx-1};
//    BNuint v[224>>BN_BIT_LOG] BN_ALIGN = {BN2(~0,~0), BN2(~0,0)};
//    v[4]= bn_mul_ui(v, v, cx, 4);
    BNint cy = bn_add1(x, v, 7);
    if (cy>0) bn_sub1(x, ctx->prime, 7);
}
static void mp_reduction_nums_p256d1(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
    BNuint v[256>>BN_BIT_LOG] BN_ALIGN = {BN2(189, 0)};// {lo, hi+1,};
    v[2] = bn_mul_ui(v, v, cx, 2);
    BNint cy = bn_add1(x, v, 8);
    if (cy>0)/* cy +=*/ bn_sub1(x, ctx->prime, 8);
}
extern uint32_t bn_mac_ui_256(uint32_t* r, uint32_t *a, uint32_t d);
/*! 2^256 - 2^32 - 977
 */
static void mp_reduction_sec_p256k1(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
//    uint64_t c = cx*617ULL;
// ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f
//    uint32_t v[8] BN_ALIGN = {c, c>>BN_BITS,};
//    BNuint lo,hi;
//    MUL(lo,hi, cx, 977);
//    BNuint p[256>>BN_BIT_LOG] BN_ALIGN = {BN2(0xfffffc2f, 0xfffffffe), BN2(~0,~0), BN2(~0,~0),BN2(~0,~0)};
    const BNuint p[256>>BN_BIT_LOG] BN_ALIGN = {BN2(977, 0x1)};// {lo, hi+1,};
    //BNuint v[256>>BN_BIT_LOG] BN_ALIGN = {0};
    //v[2] = bn_mul_ui(v, p, cx, 2);
    //BNuint cy = bn_add1(x, v, 8);
    BNuint cy = bn_mla_128_256(x, p, cx);
    //BNuint cy = bn_mac_ui_256(x, p, cx);
    if (cy>0)/* cy +=*/ bn_add1(x, p, 8);
}
static void mp_reduction_sec_p256k1_n(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
// e baaedce6 af48a03b bfd25e8c d0364141
//    uint32_t v[8] BN_ALIGN = {(~0xB761B893U)+1, ~0x45841B09,~0x995AD100,~0x6C611070, 0,0,0,0};
    const BNuint p[256>>BN_BIT_LOG] BN_ALIGN = {BN2(0x2FC9BEBF, 0x402DA173), BN2(0x50B75FC4, 0x45512319), BN2(1,0)};// {lo, hi+1,};
/*    BNuint v[256>>BN_BIT_LOG] BN_ALIGN = {0};
    v[6] = bn_mul_ui(v, p, cx, 6);
    BNint cy = bn_add1(x, v, 8); */
    BNuint cy = bn_mla_256(x, p, cx);
    if (cy>0)/* cy +=*/ bn_add1(x, p, 8);
}


/*! \brief Алгоритм быстрого редуцирования числа по prime filed prime = 2^256 - p1
    \see ГОСТ P 34.10-2001 набор параметров Crypto-Pro-A
    \param ctx контекст простого числа
    \param x   число
    \param cx  перенос, для которого выполняется операция
    \return перенос
 */
static void mp_reduction_gost_A(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
//    uint64_t c = cx*617ULL;
//    uint32_t v[8] BN_ALIGN = {c, c>>BN_BITS,};
    //BNuint lo,hi;
    //MUL(lo,hi, cx, 617);
    //BNuint v[256>>BN_BIT_LOG] BN_ALIGN = {lo, hi,};
    const BNuint p[256>>BN_BIT_LOG] BN_ALIGN = {617, 0,};
//    BNuint v[256>>BN_BIT_LOG] BN_ALIGN = {0};
//    v[2] = bn_mul_ui(v, p, cx, 2);
//    BNint cy = bn_add1(x, v, 8);
    //BNint cy = bn_mac_ui_256(x, p, cx);
    //BNuint cy = bn_mla_256(x, p, cx);
    BNuint cy = bn_mla_1_256(x, 617, cx);
    if (cy>0)/* cy +=*/ bn_add1(x, p, 8);
}
static void mp_reduction_gost_A_n(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
//    uint32_t v[8] BN_ALIGN = {(~0xB761B893U)+1, ~0x45841B09,~0x995AD100,~0x6C611070, 0,0,0,0};
    const BNuint p[256>>BN_BIT_LOG] BN_ALIGN = {BN2(0x489E476D, 0xBA7BE4F6),BN2(0x66A52EFF, 0x939EEF8F),};
//    BNuint v[256>>BN_BIT_LOG] BN_ALIGN = {0};
//    v[128>>BN_BIT_LOG] = bn_mul_ui(v, p, cx, 4);
//    BNint cy = bn_add1(x, v, 8);
    BNint cy = bn_mla_128_256(x, p, cx);
    if (cy>0)/* cy += */bn_add1(x, p, 8);
}

static void mp_reduction_gost_B(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
//    static const int64_t p0 = 0xC99*2;
//    BNuint lo,hi;
//    MUL(lo,hi, cx, 0x1932);
//    BNuint v[256>>BN_BIT_LOG] BN_ALIGN = {lo, hi,};

    /*BNuint v[256>>BN_BIT_LOG] BN_ALIGN = {0x1932, 0,};
    v[2] = bn_mul_ui(v, v, cx, 2);
    BNint cy = bn_sub1(x, v, 8);*/
    BNint cy = bn_mls_1_256(x, 0x1932, cx);
    if (cy<0)/* cy +=*/ bn_add_1_256(x, 0x1932);
}
static void mp_reduction_gost_B_n(const MPCtx* const ctx, BNuint* x, BNuint cx)
{//    1 5F700CFF F1A624E5 E497161B CC8A198F
 // BEE019FE 1E34C49CA 1C92E2C36 19914331E
    BNuint v[256>>BN_BIT_LOG] BN_ALIGN = {BN2(0x9914331E, 0xC92E2C37),BN2(0xE34C49CB,0xBEE019FF), BN2(0x2,0)};
    //v[5] =
    bn_mul_ui(v, v, cx, 6); // четное число слов для выравнивания
    BNint cy = bn_sub1(x, v, 8);
  //  BNint cy = bn_mls_ui_256(x, v, 8);

    if (cy<0)/* cy +=*/ bn_add1(x, ctx->prime,8);
}
static void mp_reduction_gost_12_A_n(const MPCtx* const ctx, BNuint* x, BNuint cx)
{// 3F63377F 21ED98D7 0456BD55 B0D8319C
// "40000000000000000000000000000000 0FD8CDDF C87B6635 C115AF55 6C360C67
 // 7EC66EFE 43DB31AE 08AD7AAA 161B06338
    const BNuint p[256>>BN_BIT_LOG] BN_ALIGN = {BN2(0xB0D8319C, 0x0456BD55),BN2(0x21ED98D7,0x3F63377F)};// n<<2
//    BNuint v[256>>BN_BIT_LOG] BN_ALIGN = {BN2(0x61B06338, 0x08AD7AAB),BN2(0x43DB31AE,0x7EC66EFE)};
    BNuint v[256>>BN_BIT_LOG] BN_ALIGN = {0};
    v[4] = bn_mul_ui(v, p, cx, 4); // четное число слов для выравнивания
    BNint cy = bn_sub1(x, v, 8);
//    BNint cy = bn_mls_128_256(x, p, cx);
    if (cy<0){
        cy += bn_add1(x, ctx->prime, 8);
    }
}

/*! \brief Алгоритм быстрого редуцирования числа по prime =2^521 -1
    \param ctx контекст простого числа
    \param x   число
    \param cx  перенос, для которого выполняется операция
 */
 static void mp_reduction_nist_p521(const MPCtx* const ctx, BNuint* const x, BNuint cx)
{
    uint32_t v[18] BN_ALIGN = {cx<<23, cx>>(32-23),};
    //x[16] &= ~0x1FF;
    BNuint cy = bn_add1(x, v, ctx->size);
    if (cy>0) {
        v[0]=1<<23; v[1]= 0;
        bn_sub1(x, v, ctx->size);// -1
        printf("-1");
    }
}

/*! \brief Алгоритм быстрого редуцирования числа по prime =2^192 -2^64 -1
    \param ctx контекст простого числа
    \param x   число
    \param cx  перенос, для которого выполняется операция
 */
static void mp_reduction_nist_p192(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
    BNuint v[192>>BN_BIT_LOG] BN_ALIGN = {BN2(cx, 0),BN2(cx,0)};
    BNint   cy  = bn_add1(x, v, 6);
    if (cy>0) /*cy += */bn_sub1(x, ctx->prime, 6);
}
static void mp_reduction_nist_p192_n(const MPCtx* const ctx, BNuint* x, BNuint cx)
{// 99def836 146bc9b1 b4d22831
    BNuint v[192>>BN_BIT_LOG] BN_ALIGN = {BN2(0x4B2DD7CF, 0xEB94364E), BN2(0x662107C9,0)};
    //v[4] =
    bn_mul_ui(v, v, cx, 4);// нужно четное число слов для выравнивания на 64 бита
    BNint   cy  = bn_add1(x, v, 6);
    if (cy>0) /*cy += */bn_sub1(x, ctx->prime, 6);
}
/*! \brief Алгоритм быстрого редуцирования числа по prime =2^224 -2^96 +1
    \param ctx контекст простого числа
    \param x   число
    \param cx  перенос, для которого выполняется операция
 */
static void mp_reduction_nist_p224(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
    uint32_t v[7] BN_ALIGN = {-cx, -1, -1, cx-1,};
    BNint   cy  = bn_add1(x, v, ctx->size);
    if (cy>0) /*cy +=*/ bn_sub1(x, ctx->prime, ctx->size);
}
/*
prime
*/
static void mp_reduction_p239(const MPCtx* const ctx, BNuint* x, BNuint cx)
{//         "7fffffffffffffffffffffff7fffffffffff800000000000 7fff ffff ffff",
    uint32_t v[8] BN_ALIGN = {-cx, -1, -1, cx-1,};
    BNint   cy  = bn_add1(x, v, ctx->size);
    if (cy>0) /*cy +=*/ bn_sub1(x, ctx->prime, ctx->size);
}
static void mp_reduction_nist_p224_n(const MPCtx* const ctx, BNuint* x, BNuint cx)
{// FFFF16a2 e0b8f03e 13dd2945 5c5c2a3d
    uint32_t v[7] BN_ALIGN = {0xA3A3D5C3, 0xEC22D6BA, 0x1F470FC1,  0xE95D};
    v[4] =  bn_mul_ui(v, v, cx, 4);
    BNint   cy  = bn_add1(x, v, ctx->size);
    if (cy>0) /*cy +=*/ bn_sub1(x, ctx->prime, ctx->size);
}
/*! \brief Алгоритм быстрого редуцирования числа по prime =2^255 -19
    \param ctx контекст простого числа
    \param x  - число
    \param cx - перенос для которого выполняется операция быстрого редуцирования

TODO возможно лажа если cx=FFFFFFFF или 1
 */
static void mp_reduction_p25519(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
//    BNuint lo,hi;
//    MUL(lo,hi, cx, 19*2);
//    BNuint v[256>>BN_BIT_LOG] BN_ALIGN = {lo, hi,};
    BNuint v[256>>BN_BIT_LOG] BN_ALIGN = {19*2,};
    v[2] =  bn_mul_ui(v, v, cx, 2);
    BNint cy = bn_add1(x, v, 8);
    if (cy>0)/* cy +=*/ bn_sub1(x, ctx->prime, 8);
}
/*! \brief Алгоритм быстрого редуцирования числа по prime =2^256 -2^224 +2^192 +2^96 -1
    \param ctx контекст простого числа
    \param x  - число
    \param cx - перенос для которого выполняется операция быстрого редуцирования

TODO возможно лажа если cx=FFFFFFFF или 1
 */
static void mp_reduction_nist_p256(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
    uint32_t v[8] BN_ALIGN = {cx, 0, 0, -cx, -1, -1, ~cx/* -cx-1 */, cx-1};
    BNint   cy  = bn_add1(x, v, ctx->size);
    if (cy>0)/*cy +=*/ bn_sub1(x, ctx->prime, ctx->size);
}
static void mp_reduction_nist_p256_n(const MPCtx* const ctx, BNuint* x, BNuint cx)
{// bce6faad a7179e84 f3b9cac2 fc632551
    uint32_t v[8] BN_ALIGN = {0x39CDAAF, 0xC46353D, 0x58E8617B, 0x43190552, 0, 0, -cx, cx-1};
    v[4] = bn_mul_ui(v, v, cx, 4);// старшие разряды не трогаем
    BNint   cy  = bn_add1(x, v, ctx->size);
    if (cy>0) /*cy +=*/ bn_sub1(x, ctx->prime, ctx->size);
}
/*! \brief Алгоритм быстрого редуцирования числа по prime =2^256 - 2^225 + 2^224 - 2^96 + 2^64-1
    \param ctx контекст простого числа
    \param x  - число
    \param cx - перенос для которого выполняется операция быстрого редуцирования
 */
static void mp_reduction_sm2(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
    uint32_t v[8] BN_ALIGN = {cx, 0, -cx, cx-1, 0, 0, 0, cx};
    BNint   cy  = bn_add1(x, v, ctx->size);
    if (cy>0) cy += bn_sub1(x, ctx->prime, ctx->size);
}
/*! \brief Алгоритм быстрого редуцирования числа по prime = 2^384 −2^128 −2^96 +2^32 −1
    \param ctx контекст простого числа
    \param x   число
    \param cx  перенос, для которого выполняется операция
 */
static void mp_reduction_nist_p384(const MPCtx* const ctx, BNuint* x, BNuint cx)
{
    uint32_t v[12] BN_ALIGN = {cx, -cx, -1, cx-1, cx,};
    BNint   cy  = bn_add1(x,v, ctx->size);
    if (cy>0) /*cy +=*/ bn_sub1(x, ctx->prime, ctx->size);
}
static void mp_reduction_nist_p384_n(const MPCtx* const ctx, BNuint* x, BNuint cx)
{// c7634d81 f4372ddf 581a0db2 48b0a77a ecec196a ccc52973
    uint32_t v[12] BN_ALIGN = {0x333AD68D, 0x1313E695, 0xB74F5885,  0xA7E5F24D, 0xBC8D220, 0x389CB27E};
    v[6] = bn_mul_ui(v, v, cx, 6);
    BNint   cy  = bn_add1(x, v, ctx->size);
    if (cy>0) /*cy +=*/ bn_sub1(x, ctx->prime, ctx->size);
}
/*! \brief Модуль простого числа
    \param ctx контекст простого числа (разрядность и простое число)
    \param q - результат
    \param x - источник, от которого берется модуль
 */
void mp_modp(const MPCtx* const ctx, BNuint *q, BNuint *x)
{
//if ()// число бит clz(q) больше clz(ctx->prime[ctx->size])
    if ((BNint)ctx->prime[ctx->size-1] > 0) {
        int clz = __builtin_clz(ctx->prime[ctx->size-1]-1);
        BNuint div = x[ctx->size-1]>>(BN_BITS-clz);
//        BNuint div = x[ctx->size-1]/(ctx->prime[ctx->size-1]+1);
//        printf("!!!CLZ = %d\n", div);
        if (div) {
            BNuint r[ctx->asize] BN_ALIGN;
            bn_mul_ui(r, ctx->prime, div, ctx->size);
            BNint cy = bn_sub(q, x, r, ctx->size);
            if (cy) {
                printf("!!!CLZ = %d!!!\n", cy);
//                _Exit(24);
            }
            while (bn_le (ctx->prime, q, ctx->size)) {
                bn_sub1 (q, ctx->prime, ctx->size);
                printf("mp_modp - \n");
            }
            return;
        }
    }
    if (bn_le (ctx->prime, x, ctx->size)) {
/*        int clz = __builtin_clz(ctx->prime[ctx->size-1]);
        if (clz) {// требуется выравнивание на число бит
            printf("!!!CLZ=%d!!!\n", clz);

            BNuint r[ctx->asize] BN_ALIGN;
            BNuint div = (x[ctx->size-1]/ctx->prime[ctx->size-1]);
            bn_mul_ui(r, ctx->prime, div, ctx->size);
            BNint cy = bn_sub(q, x, r, ctx->size);
            if (cy) {
                printf("!!!CLZ = %d!!!\n", cy);
                _Exit(24);
            }
            if (bn_le (ctx->prime, x, ctx->size)) {
                printf("!!!CLZ = HIGH!!!\n");
            }
            // TODO для случая когда выравнивание на слово нет как в случае P-521
        } else */

            bn_sub1 (x, ctx->prime, ctx->size);
    }
    bn_move(q, x, ctx->size);
    // нужен сдвиг враво (уполовинивание), если ctx->prime четное число m
}
/*! \brief Сложение чисел по модулю
 группа операций типа сложение не испльзует редуцирования
 */
void mp_addm(const MPCtx * const ctx, BNuint* r, BNuint* a, BNuint* b)
{
    BNint cy = bn_add (r, a, b, ctx->size);
//    if (cy>0) ctx->reduction(ctx, r, cy);
    while (cy>0) {
        cy += bn_sub1(r, ctx->prime, ctx->size);
//        if (cy) printf("#");
    }
}
/*! \brief Вычитание чисел по модулю
 */
void mp_subm(const MPCtx * const ctx, BNuint* r, BNuint* a, BNuint* b)
{
    BNint cy = bn_sub (r, a, b, ctx->size);
    while (cy<0) {
        cy += bn_add1(r, ctx->prime, ctx->size);
//        if (cy) printf("&");
    }
}
/*! \brief операция удваивания числа
 */
void mp_dubm(const MPCtx* const ctx, BNuint* r, BNuint* x)
{
    BNint cy = bn_shl (r, x, 1, ctx->size);
    while (cy>0) cy += bn_sub1(r, ctx->prime, ctx->size);
}
/*! \brief операция уполовинивания (halving) по модулю p
if x_0==0 то x<= x>>1 иначе x<= (p+x)>>1
 */
#if 0
static void mp_hlvm(const MPCtx* const ctx, BNuint* x)
{
    BNuint cy =0 ;
//    int ctz = __builtin_ctz(ctx->prime[0]);
    if (x[0]&1){
        cy = bn_add1(x, ctx->prime, ctx->size);
    }
    bn_shr1 (x, cy, ctx->size);
}
#endif
/*! \brief отрицательное число по модулю r = -a
 */
#if 0
static void mp_negm(const MPCtx * const ctx, BNuint* r, BNuint* a)
{
    BNint cy = bn_sub (r, ctx->prime, a, ctx->size);
    while (cy<0) cy += bn_add1(r, ctx->prime, ctx->size);
}
#endif


/*! Группа модульных операций требующих редуцирования
 */
#if 1
/*! \brief Сдвиг влево (умножение на 2) по модулю (с редуцированием)
 */
void mp_shlm(const MPCtx * const ctx, BNuint* r, BNuint* x, int len)
{
    BNuint cy = bn_shl(r, x, len, ctx->size);
    if (cy) ctx->reduction(ctx, r, cy);
}
#endif
/*! \brief Сдвиг влево (умножение на 2^32), сопровождается редуцированием
 */
static void mp_shlBm(const MPCtx * const ctx, BNuint* r)
{
    BNuint cy = bn_shlB(r, ctx->size);
    if (cy) ctx->reduction(ctx, r, cy);
}
/*! \brief Умножение на целое число с редуцированием
 */
void mp_mulm_ui(const MPCtx * const ctx, BNuint* r, BNuint* a, BNuint b)
{
    BNuint cy = bn_mul_ui(r, a, b, ctx->size);
    if (cy) ctx->reduction(ctx, r, cy);
}
/*! \brief Умножение на целое число с редуцированием с накоплением (со сложением)
 */
static void mp_macm_ui(const MPCtx * const ctx, BNuint* r, BNuint* a, BNuint b)
{
    BNuint cy = bn_mac_ui(r, a, b, ctx->size);
    if (cy) ctx->reduction(ctx, r, cy);
}
/*! \brief Умножение больших чисел r= a*b (mod p) с редуцированием по модую простого числа
    \param ctx контекст простого числа
    \param r результат операции
    \param a
    \param b

    TODO Умножение методом Карацубы по модулю prime
 */

void mp_mulm_(const MPCtx * const ctx, BNuint* r, BNuint* a, BNuint* b)
{
    BNuint q[ctx->asize] BN_ALIGN;
    BNuint w[ctx->asize] BN_ALIGN;
    bn_move (q, a, ctx->size);
    if (b[0]) {
        mp_mulm_ui(ctx, w, q, b[0]);
    } else {
        bn_set_0(w, ctx->size);
    }
    int i;
//    int shift=0;
    for (i=1; i< ctx->size; i++){
#if 0
        shift++;
        if (b[i])
        {
            do { mp_shlBm (ctx, q); } while(--shift);
            mp_macm_ui(ctx, w, q, b[i]);
        }
#else // так быстрее
            mp_shlBm (ctx, q);
            mp_macm_ui(ctx, w, q, b[i]);
#endif
    }
    // редуцирование от N сложений может выполняться оптом
//    while (cw) cw = ctx->reduction(ctx, &w, cw);
//    mp_modp(ctx, r, &w);
    bn_move (r, w, ctx->size);
}
/*! умножение методом Монтгомери по модулю
    \see https://eprint.iacr.org/2013/816.pdf
*/
// static void mp_mulm_mg(const MPCtx * const ctx, BNuint* r, BNuint* a, BNuint* b);
/*! метод умножения слева-направо */
void mp_mulm(const MPCtx * const ctx, BNuint* r, BNuint* a, BNuint* b)
{
//    BNuint q[ctx->asize] BN_ALIGN;
    BNuint w[ctx->asize] BN_ALIGN;
    int i = ctx->size -1;
    //bn_move (q, a, ctx->size);
//    while (i>0 && b[i]==0) i--;
    while (i>0 && b[i]==0) i--;
    if (b[i]!=0){
        mp_mulm_ui(ctx, w, a, b[i]);
    } else {
        bn_set_0(r, ctx->size);
        return;
    }
//    int shift=0;
    for (i=i-1; i>=0; i--){
        mp_shlBm (ctx, w);
        if (b[i])
            mp_macm_ui(ctx, w, a, b[i]);
    }
    // редуцирование от N сложений может выполняться оптом
//    while (cw) cw = ctx->reduction(ctx, &w, cw);
//    mp_modp(ctx, r, &w);
    bn_move (r, w, ctx->size);
}


/*! \brief возведение в степень q = x^k mod p
можно переделать на RLE/NAF
 */
void mp_powm_0(const MPCtx* const ctx, BNuint * q, BNuint* x, BNuint* k)
{
    BNuint z[ctx->asize] BN_ALIGN;
    bn_move(z, x, ctx->size);
    if (k[0]&1)
        bn_move(q, x, ctx->size);
    else
        bn_set_1(q, ctx->size);

    int i;
    for (i=1; i<(ctx->size<<5); i++){
        mp_sqrm(ctx, z, z);
        if (bn_bit_val(k, i))
            mp_mulm(ctx, q, q, z);
    }
}
/*! left to right
 */
void mp_powm(const MPCtx* const ctx, BNuint * q, BNuint* x, BNuint* k)
{
    BNuint z[ctx->asize] BN_ALIGN;
    int i=(ctx->size<<5)-1;
    while (i>=0 && !bn_bit_test(k, i)) i--;
    if (i<0) {
        bn_set_1(q, ctx->size);
    } else {
        bn_move(z, x, ctx->size);

        while (i--) {
            mp_sqrm(ctx, z, z);
            if (bn_bit_val(k, i))
                mp_mulm(ctx, z, z, x);
        }
        bn_move(q, z, ctx->size);
    }
}
/*! \brief извлечение квадратного корня
работает только для кривых с p = 3 mod 4

q = x^((p+1)/4) mod p
 */
void mp_srtm(const MPCtx* const ctx, BNuint * q, BNuint* x)
{
    BNuint z[ctx->asize] BN_ALIGN;
    BNint cy = bn_add_ui(z, ctx->prime, 1, ctx->size);
    bn_shrl(z, cy, 2, ctx->size);
    mp_powm(ctx, q, x, z);
}

/*! \brief Plus-minus inversion over F_p

Function: The Plus-Minus Algorithm
Inputs: Two Integers a, b
Output: The Greatest Common Divisor (gcd(a, b))
while( |a|>0 ){
    while ( a mod 2 = 0) { //a is even
        a >>= 1;
        d--;
    }
    if (d<0) {
        t:= a; a:= b; b:= t
        d:= -d
    }
    if ((a+b) mod 4 = 0) {
        a:= (a + b)>>1;
    } else {
        a:= (a - b)>>1;
    }
}
return gcd(a, b) =b;


 */
#if 0
/*! \brief Unified Modular Division GF(p) */
// знаки?
void mp_divm (const MPCtx* const ctx, BNuint* q, BNuint *x, BNuint* y)
{
    int d = 0;
    if (x) // для деления x/y сюда положить x
        bn_move(x1, x, ctx->size);
    else // для инверсии 1/y сюда положить 1
        bn_set_1(x1, ctx->size);
    bn_set_0(x2, ctx->size);
    mp_modp (ctx, C, y);// может просто моve
    bn_move (D, ctx->prime, ctx->size);
    int32_t cy = 0;
    while (!mp_is_zero(ctx, C)){
        while ((C[0]&1) == 0){
            bn_shr1(C,0, ctx->size);
            mp_hlvm(ctx, &x1);
            d--;
        }
        if (d<0){
            BNuint * t;
            t = C; C = D; D = t;
            t = x1; x1 = x2; x2 = t;
            d = -d;
        }
        if (((C[0]+D[0])&3) == 0){
            bn_add1(C,D,ctx->size);
            bn_shr1(C,0, ctx->size);
            mp_addm(ctx, &x1,&x1,&x2);
        } else {
            cy = bn_sub1(C, B,ctx->size);
            bn_shr1(C,cy, ctx->size);
            mp_subm(ctx, &x1,&x1,&x2);
        }
        mp_hlvm(ctx, x1);
    }
    if (mp_is_one(ctx, D)){
        mp_move(ctx, q, x2);
    } else {
        mp_negm(ctx, q, x2);
    }
}
/*! NIST inversion Appx.C1
{
Input: x, p
Output: x^{-1} mod p
v=p, u=x, x2=0, x1=1
do {
    q = v/u; (нижнаяя оценка)
    r = v -(u*q);
    y = x2 - x1*q;
    v = u, u = r; x2=x1, x1=y
} while (u > 0);
    mp_modp(ctx, q, x2);
} */
#endif

/*! Prime field inversion Alg 11.9 Handbook of elliptic curve cryptography
 Input: x, p
 Output: x^{-1} mod p
 z <= x mod p
 u <= 1
 while (z != 1){
    q <= p/z  (нижняя оценка) должно работат для 2^m < p/z
    z <= p - qz
    u <= -qu mod p
 }
 return u
 */


static inline int bn_resize(BNuint* x, int n)
{
    while (x[--n]==0);
    return ++n;
}
// размер один и тоже значение один
static inline int bn_is_one1(BNuint* x, int n)
{
    return n==1 && x[0]==1;
}
#if 0
static void mp_div2m(MPCtx* ctx, BNuint* x, int m)
{
    do {
        uint32_t cy =0;
        if (x[0]&1) {// мы считаем что прайм нечетный
            cy = bn_add1(x, ctx->prime, ctx->size);
        }
        bn_shr1 (x, cy, ctx->size);
    } while (--m);
}
#else
// можно сделать аналог быстрого редуцирования при делении на 2^m
static void mp_div2m(const MPCtx* const ctx, BNuint* x, int m)
{
    if (m>1){
        // есть частный случай для p0 == -1 mod 2^m: cx = r0 mod 2^m
        uint32_t p0 = ctx->prime[0];
        uint32_t r0 = x[0];
        uint32_t cx;
        if (((p0+1)&((1<<m)-1))==0){// решение годится для
            cx = r0 & ((1<<m)-1);
        } else {
            cx=0;
            int i;
            uint32_t r0 = x[0];
            int ctz = __builtin_ctz(p0);
            for (i=ctz; i<m; i++){
                if( r0 & (1<<i)){
                    r0 += p0<<(i-ctz);
                    cx |= (1<<(i-ctz));
                }
            }
        }
        cx = bn_mac_ui(x, ctx->prime, cx, ctx->size);
        bn_shrl (x, cx, m, ctx->size);
    } else {
        BNuint cy =0;
        int ctz = __builtin_ctz(ctx->prime[0]);
        if (x[0]&(1<<ctz)) {// мы считаем что прайм нечетный^ можно сделать одну команду
            cy = bn_add1(x, ctx->prime, ctx->size);
        }
        bn_shr1 (x, cy, ctx->size);
    }
}
#endif

static void div2m_(BNuint* x, BNuint* p, int m, int size)
{
    int msb = p[size-1]==0?1:0;
    while (m>0) {
        BNuint cy = 0;
        if (x[0] & 1/*<<ctz*/) {
            cy  = msb;
            cy += bn_add1(x, p, size);
        }
        //m-= x[0]__builtin_ctz(x[0]);
        bn_shr1(x, cy, size);
        m--;
    }
}
#if 1
static inline int bn_is_zero1(uint32_t *k, int n);
/*! \brief алгоритм инверсии (деления) a/b в поле Fp
    два правила
    1) если а-четное и p-нечетно, то GCD(a,p)=GCD(a/2, p)
    2) если оба нечетные, то  GCD(a,p) = GCD((a-p)/2,a) == GCD((a-p)/2, p)
 */

void mp_divm(const MPCtx* const ctx, BNuint* q, BNuint* a, BNuint* b)
{
    BNuint  u[ctx->asize] BN_ALIGN;
    BNuint  v[ctx->asize] BN_ALIGN;
    BNuint  p[ctx->asize] BN_ALIGN;
    BNuint  p0[ctx->asize] BN_ALIGN;
    BNuint  t[ctx->asize] BN_ALIGN;
    if (a==NULL)
        bn_set_1(v, ctx->size);// a
    else
        bn_move(v, a, ctx->size);// a
    bn_move (u, b, ctx->size);// b
    //bn_move (p, ctx->prime, ctx->size);
    bn_move (p0, ctx->prime, ctx->size);
    int ctz = __builtin_ctz(p0[0]);
    int msb = (p0[ctx->size-1]==0?1:0);
    if (ctz) {
        bn_shrl (p0, msb, ctz, ctx->size);
        msb>>=ctz;
    }
    bn_move (p, p0, ctx->size);
    bn_set_0(q, ctx->size);
//    bn_add1(v, p0, ctx->size);


    int up_size = ctx->size;
    if (msb==0)
        while (up_size>0 && u[up_size-1]==0 && p[up_size-1]==0) up_size--;
    while(!bn_is_zero1(u, up_size)) {
        while ((u[0]&1)==0) {
            BNuint cy=0;
            if (v[0]&1) {
                cy  = msb;
                cy += bn_add1(v, p0, ctx->size);
            }
            bn_shr1(v, cy, ctx->size);// уполовинили
            //halv(v, ctx->prime, ctx->size);
            bn_shr1(u, 0, up_size);
        }
        if (bn_le(p, u, up_size)) {
            bn_sub1(u, p, up_size);
            BNint cy = bn_sub1(v, q, ctx->size);
            if (cy<0){
                cy+=msb;
                cy+=bn_add1(v, ctx->prime, ctx->size);
                if (cy!=0) printf("\n cy = %d\n", cy);
            }
        } else {
            bn_move(t, u, up_size);
            bn_sub(u, p, t, up_size);
            bn_move(p, t, up_size);
            bn_move(t, v, ctx->size);
            BNint cy = bn_sub(v, q, v, ctx->size);
            if (cy<0) {
                cy+=msb;
                cy+=bn_add1(v, ctx->prime, ctx->size);
                if (cy!=0) printf("\n cy = %d\n", cy);
            }
            bn_move(q, t, ctx->size);
        }
        while (up_size>0 && u[up_size-1]==0 && p[up_size-1]==0) up_size--;
    }
/*    printf("(%c%c)", (b[0]&1)?'+':' ', (q[0]&1)?'+':' ');
    switch (((q[0]<<1)&2) | (b[0]&1)) {
    //case 0:
    case 2: //bn_add1(q, p0, ctx->size);
    case 1: bn_add1(q, p0, ctx->size); break;
    default:
        break;
    }
    */
}
#endif // 0
/*! \brief Binary algorithm for inversion over F_p
\see Alg 2.22 [GECC]
 */
void mp_invm (const MPCtx* const ctx, BNuint* q, BNuint* x)
{
//    int iter=0;
    BNuint  p[ctx->asize] BN_ALIGN;
    BNuint  u[ctx->asize] BN_ALIGN;
    BNuint  v[ctx->asize] BN_ALIGN;
    BNuint x1[ctx->asize] BN_ALIGN;
    BNuint x2[ctx->asize] BN_ALIGN;
//    mp_modp (ctx, u, x);// может просто моve
    bn_move (u, x, ctx->size);// может просто моve
    /// Если prime -четный на вход не должно попадать нечетное число
    /// может не поместиться, если prime -четный, надо что-то сделать заранее
    bn_move (p, ctx->prime, ctx->size);
    bn_set_1(x1, ctx->size);
    bn_set_0(x2, ctx->size);
    int msb = p[ctx->size-1]==0?1:0;
    int ctz =__builtin_ctz(p[0]);
    if (ctz) {
        bn_shrl(p, msb, ctz, ctx->size);
    }
    bn_move (v, p, ctx->size);

    int u_size=bn_resize(u, ctx->size);
    int v_size=msb?ctx->size:bn_resize(v, ctx->size);
    while (!bn_is_one1(u, u_size) && !bn_is_one1(v, v_size)) {
        int su = u[0]?BN_CTZ(u[0]):BN_BITS-1; //if (!bn_bit_test(u, su)) su++;
        if (su) {
            bn_shrl (u, 0, su, u_size);
            div2m_(x1, p, su, ctx->size);
            //mp_div2m(ctx, x1, su);
        }
        int sv = v[0]?BN_CTZ(v[0]):BN_BITS-1;
        if (sv) {
            bn_shrl (v, 0, sv, v_size);
            div2m_(x2, p, sv, ctx->size);
            //mp_div2m(ctx, x2, sv);
        }
        int uv_size = (v_size < u_size)?u_size: v_size;
        if (bn_le (v, u, uv_size)) {// v<=u
            bn_sub1(u, v, u_size);
            BNint cy = bn_sub1(x1, x2, ctx->size);
            if (cy<0) {
                bn_add1(x1, ctx->prime, ctx->size);
            }
            //mp_subm(ctx, x1, x1, x2);
        } else {
            bn_sub1(v, u, v_size);
            BNint cy = bn_sub1(x2, x1, ctx->size);
            if (cy<0) {
                bn_add1(x2, ctx->prime, ctx->size);
            }
//            mp_subm(ctx, x2, x2, x1);
        }
        u_size=bn_resize(u, u_size);
        v_size=bn_resize(v, v_size);
//        iter++;
    }
    if (bn_is_one1(u, u_size)) {
        bn_move (q, x1, ctx->size);
    } else {
        bn_move (q, x2, ctx->size);
    }
#if 0
        printf("%c%c%c%c", (q[1]&1)?'H':'L', (q[0]&1)?'H':'L', (x[1]&1)?'H':'L', (x[0]&1)?'H':'L');
    if (0) {
        if (1) {
            BNuint cy=0;
            if (q[0]&1) {
                cy += bn_add1(q, p, ctx->size);
            } else {
            }
            bn_shr1(q, cy, ctx->size);
        }
        printf("%c%c%c%c", (q[1]&1)?'H':'L', (q[0]&1)?'H':'L', (x[1]&1)?'H':'L', (x[0]&1)?'H':'L');
        int lsb = q[0]&x[0]&1;
        if(0) {
            bn_add1(q, p, ctx->size);
        } else {
        }

//        bn_shr(q, 1, ctx->size);
//        bn_shl(q, q,ctz, ctx->size);
    }
//    printf("=%d\n", iter);
#endif // 0
}
/*! \brief Алгоритм для одновременной инверсии массива значений
    \see GECC Alg2.26
 */
void mp_sim_inversion(const MPCtx* const ctx, BNuint** r, BNuint** a, int n)
{
    BNuint  u   [ctx->asize] BN_ALIGN;
    BNuint  c[n][ctx->asize] BN_ALIGN;
    bn_move(c[0],a[0], ctx->size);
    int i;
    for (i=1;i<n;i++){
        mp_mulm(ctx, c[i], a[i], c[i-1]);
    }
    mp_invm(ctx, u, c[n-1]);
    for (i=n-1;i>0; i--){
        mp_mulm(ctx, c[i], c[i-1], u);
        mp_mulm(ctx, u, u, a[i]);
    }
    bn_move(r[0],u, ctx->size);
    for (i=1;i<n;i++) bn_move(r[i],c[i], ctx->size);
}


#if 0
/* длина в битах */
static int bn_bit_len(uint32_t *x, int n)
{
    n--;
    while (n>=0 && x[n]==0) n--;
    if (x[n])
        n = (sizeof(unsigned int)*8 - __builtin_clz(x[n])) + (n<<5);
    return n;
}
/*! most signed word */
static uint32_t bn_msw(uint32_t *x, int nbits)
{
    x+=(nbits>>5)-1;
    int sh = nbits&31;
    if (sh){
        return x[0]>>(sh) | x[1]<<(31-sh);
    } else {
        return x[0];
    }
}
/* индекс старшего бита */
static int log_2(uint32_t x)
{
	int r = 0;

	if ( x & 0xffff0000 ) { x >>=16;  r +=16; }
	if ( x & 0x0000ff00 ) { x >>= 8;  r += 8; }
	if ( x & 0x000000f0 ) { x >>= 4;  r += 4; }
	if ( x & 0x0000000c ) { x >>= 2;  r += 2; }
	if ( x & 0x00000002 ) {           r += 1; }
	return r;
}
#endif
#if 0
//void ModInvE( mpz_t B, mpz_t M, mpz_t x)
void mp_invm2 (MPCtx* ctx, BNuint* q, BNuint* x)
{

    mp_set_ui(ctx, &s, 1);
    mp_set_ui(ctx, &r, 0);
    mp_modp (ctx, &v, x);// может просто моve
    bn_move (u.value, ctx->prime, ctx->size);

    int lv = bn_bit_len(v.value, ctx->size);
    int lu = bn_bit_len(u.value, ctx->size);
	for(;;) {
        int sfts;
        int lm, hm, lp, hp, L0;
        uint32_t mu,mv, mm,mp,m0;
		sfts = lu-lv;
		mu = bn_msw(u.value, lu)>>3;
		mv = bn_msw(v.value, lv)>>3;
		mm = ABS(mu-mv/2); lm = log_2(mm-1); hm = log_2(mm+1);
		mp = ABS(mu-mv*2); lp = log_2(mp-2); hp = log_2(mp+2);
		m0 = ABS(mu-mv);   L0 = log_2(m0-1);
		if ((hp < L0) && (hp < lm)) ++sfts;
		else
		if ((hm < L0) && (hm < lp) && (sfts > 0)) --sfts;

		SHL(T,V,sfts,0); SHL(W,S,sfts,0);
		A_S(U,T,R,W,0);  lu = bn_bit_len(u.value, ctx->size);
		if (lu < 2) break;
		if (lu < lv) {
		    uint32_t* t;
		    t = u.value; u.value = v.value; v.value = t;
		    t = r.value; r.value = s.value; s.value = t;
			sfts = lu; lu = lv; lv = sfts;
        }
	}


	while(len_v > 1) {
		sfts = len_u-len_v;
		bn_shl(t,v,sfts, ctx)
		SHL(T,V,sfts,0); SHL(W,S,sfts,0);
		A_S(U,T,R,W,0);
		if (LEN(U) < LEN(V)) {
			SWP(U,V); SWP(R,S); }
	}
	if (SGN(V)==0) { ST0(B); return; }
	if (SGN(V) <0) NEG(S,S);

	if (  CMP(S,M)>0) SUB(B,S,M,0)
	else if(SGN(S)<0) ADD(B,S,M,0)
	else              SET(B,S);
}
#endif
/* демонстрация работы алгоритма Plus-Minus Inversion на примере целых чисел
void inv()
{
    uint32_t p=13, a=5;
    uint32_t u,v,x1,x2;
    x1=1, x2=0;
    u=a; v=p;
    while (u!=1 && v!=1){
        while ((u&1)==0){
            u>>=1;
            if ((x1&1)==0) x1>>=1;
            else x1 = (x1+p)>>1;
        }
        while ((v&1)==0){
            v>>=1;
            if ((x2&1)==0) x2>>=1;
            else x2 = (x2+p)>>1;
        }
        if (u>=v){
            u=u-v;
            if (x1>=x2) x1=x1-x2;
            else x1=x1+(p-x2);
        } else {
            v=v-u;
            if (x2>=x1) x2=x2-x1;
            else x2=x2+(p-x1);
        }
    }
    if (u==1){
        printf("res=%d", (x1*a)%p);
    } else {
        printf("res=%d", (x2*a)%p);
    }
}*/
void ec_point_init(ECC_Point * P, MPCtx* ctx)
{
    P->x = mp_new(ctx);
    P->y = mp_new(ctx);
    P->z = mp_new(ctx);
}
void ec_point_free(ECC_Point * P, MPCtx* ctx)
{
    mp_free(ctx, P->z);
    mp_free(ctx, P->y);
    mp_free(ctx, P->x);
}
void ecc_naf_mul_free(ECC_Point* P, int w, ECC_Curve* curve);
void ecc_fix_mul_free(ECC_Point* F, int d, ECC_Curve* curve);
void ecc_curve_free(ECC_Curve * curve)
{
//    mp_free1(curve->ctx, &curve->p);
    if (curve->a!=NULL && curve->a!=(void*)-3) mp_free(curve->ctx, curve->a);
    mp_free(curve->ctx, curve->b);
//    mp_free1(curve->ctx, curve->n);
    ecc_naf_mul_free(curve->P, NAF_WINDOW, curve);
    int d = curve->ctx->size<<(BN_BIT_LOG-FIX_BIT_LOG);
    ecc_fix_mul_free(curve->F0, d, curve);
    ecc_fix_mul_free(curve->F1, d, curve);
    ecc_fix_mul_free(curve->F2, d, curve);
    ecc_fix_mul_free(curve->F3, d, curve);

    ec_point_free(&curve->G, curve->ctx);
    mp_ctx_free(curve->ctq);
    mp_ctx_free(curve->ctx);
}
/*! \brief расчет таблицы для метода Fixed-base NAF multiplication
 */
void ecc_naf_mul_precompute(ECC_Point* P, int w, BNuint *Gx, BNuint* Gy, ECC_Curve* curve)
{
    MPCtx* ctx = curve->ctx;
    int NAF_size = (1<<(w-2));
    ECC_Point  G2;
    ec_point_init(&G2, ctx);
    ec_point_copy_a2j(&G2, Gx, Gy, ctx);
    ec_point_dup (&G2, curve->a, ctx);
    ec_point_affine(G2.x, G2.y, &G2, ctx);
    int i;
    ec_point_init(&P[0], ctx);
    ec_point_copy_a2j(&P[0], Gx, Gy, ctx);
    for (i=1; i<NAF_size; i++){
        ec_point_init(&P[i], ctx);
        ec_point_copy_j2j (&P[i], &P[i-1], ctx);
        ec_point_add_a2j(&P[i], G2.x, G2.y, ctx);
    }
    if (NAF_size>1) ec_point_affine_vec(&P[1], NAF_size-1, ctx);
    for (i=0; i<NAF_size; i++){// храним отрицательные числа
        mp_subm (ctx, P[i].z, ctx->prime, P[i].y);
    }
    ec_point_free(&G2, ctx);
}
void ecc_naf_mul_free(ECC_Point* P, int w, ECC_Curve* curve)
{
    MPCtx* ctx = curve->ctx;
    int NAF_size = (1<<(w-2));
    int i;
    for (i=0; i<NAF_size; i++){
        ec_point_free(&P[i], ctx);
    }
}
/*! \brief расчет таблицы для метода Fixed-base comb multiplication
 */
void ecc_fix_mul_precompute(ECC_Point* F, int d, BNuint *Gx, BNuint* Gy, ECC_Curve* curve)
{
    int i, bit;
    MPCtx* ctx = curve->ctx;
    ec_point_init(&F[0], ctx);
    ec_point_copy_a2j(&F[0], Gx, Gy, ctx);
/*    for (i=0; i<e; i++){// 2^{e}*2G = 2^{d}*G
        ec_point_dup (&F[0], curve->a, ctx);
    }
    ec_point_affine(F[0].x,F[0].y, &F[0], ctx);
    bn_set_1(F[0].z, ctx->size);
*/
    for (bit=1; bit<FIX_WINDOW; bit++){
        int k = (1<<bit)-1;
        ec_point_init(&F[k], ctx);
        ec_point_copy_j2j (&F[k], &F[(1<<(bit-1))-1], ctx);
        for (i=0; i<d; i++){// 2^{d-1}*2G = 2^{d}*G
            ec_point_dup (&F[k], curve->a, ctx);
        }
        for (i=1; i<=k; i++){
            ec_point_init(&F[k+i], ctx);
            ec_point_copy_j2j (&F[k+i], &F[k], ctx);
            ec_point_add_a2j  (&F[k+i], F[i-1].x, F[i-1].y, ctx);
        }
        ec_point_affine_vec(&F[k], k+1, ctx);
    }
}
void ecc_fix_mul_free(ECC_Point* F, int d, ECC_Curve* curve)
{
    MPCtx* ctx = curve->ctx;
    int i;
    for (i=0; i<(1<<FIX_WINDOW)-1; i++){
        ec_point_free(&F[i], ctx);
    }
}

void ecc_curve_list()
{
    const ECC_Params * param = &ecc_domain_params[0];
    int size = sizeof(ecc_domain_params)/ sizeof(ECC_Params);
    int i;
    for (i=0; i<size; i++) {
        if (param[i].name) {
            printf("%s \n", param[i].name);
        }
    }
}
/*! \brief поиск набора параметров эллиптической кривой по имени
 */
int ecc_curve_find (ECC_Curve *curve, int id)//const char *name)
{

    const ECC_Params * param = &ecc_domain_params[id];

    MPCtx* ctx = curve->ctx = mp_ctx_new(param->nbits);
    MPCtx* ctq = curve->ctq = mp_ctx_new(param->nbits);

    if (param->fast_reduction_p!=NULL)
        ctx->reduction = param->fast_reduction_p;
    else
        ctx->reduction = mp_reduction_any;

    if (param->a==(void*)-3)
        curve->a = (void*)-3;
    else if (param->a==(void*)0)
        curve->a = (void*)0;
    else {
        curve->a = bn_alloc(ctx->asize);
        bn_hex2bin (curve->a, ctx->size, param->a);
    }
    curve->b = bn_alloc(ctx->asize);
    bn_hex2bin (curve->b,   ctx->size, param->b);
    //curve->ctx->prime = bn_alloc(ctx->asize);
    bn_hex2bin (ctx->prime, ctx->size, param->p);
    //curve->ctq->prime = bn_alloc(ctx->asize);
    bn_hex2bin (ctq->prime, ctx->size, param->n);

    if (param->fast_reduction_n!=NULL)
        curve->ctq->reduction = param->fast_reduction_n;
    else
        curve->ctq->reduction = mp_reduction_any;
    ec_point_init(&curve->G, ctx);
    const char* g_x;
    const char* g_y;
    if (param->g_x[0]=='0' && param->g_x[1]=='4') {
        g_x = &param->g_x[2];
        g_y =
        bn_hex2bin (curve->G.x, ctx->size, g_x);
        bn_hex2bin (curve->G.y, ctx->size, g_y);
    } else if (param->g_x[0]=='0' && param->g_x[1]=='3') {
        g_x = &param->g_x[2];
        g_y =
        bn_hex2bin (curve->G.x, ctx->size, g_x);
        ec_point_y(curve->G.x, curve->G.y, curve->a, curve->b, ctx);
        bn_sub(curve->G.y, ctx->prime, curve->G.y, ctx->size);
        //printf("..DONE\n");

    } else if (param->g_x[0]=='0' && param->g_x[1]=='2') {
        g_x = &param->g_x[2];
        g_y =
        bn_hex2bin (curve->G.x, ctx->size, g_x);
        ec_point_y(curve->G.x, curve->G.y, curve->a, curve->b, ctx);
        mp_modp(ctx, curve->G.y, curve->G.y);
        //printf("..DONE\n");
    } else {
        bn_hex2bin (curve->G.x, ctx->size, param->g_x);
        bn_hex2bin (curve->G.y, ctx->size, param->g_y);
    }
    bn_set_1   (curve->G.z, ctx->size);

    curve->name = param->name;

    ECC_Point* G = &curve->G;
//    ECC_Point* P =  curve->P;
    ECC_Point  G2;
    ec_point_init(&G2, ctx);
    ec_point_copy_a2j(&G2, G->x, G->y, ctx);
    ec_point_dup (&G2, curve->a, ctx);
    ec_point_affine(G2.x, G2.y, &G2, ctx);

    ecc_naf_mul_precompute(curve->P, NAF_WINDOW, G->x, G->y, curve);
    int i;
    int d = ctx->size<<(BN_BIT_LOG-FIX_BIT_LOG);
    int e = d>>2;
    /// Расчет точкa F0[0] = G,
    ecc_fix_mul_precompute(curve->F0, d, G->x, G->y, curve);
    /// Расчет точкa F1[0] = 2^{e}G,
/// TODO выделить в отдельную функцию
    ec_point_copy_a2j(&G2, G->x, G->y, ctx);
    for (i=0; i<(e); i++){// 2^{e}*2G = 2^{d}*G
        ec_point_dup (&G2, curve->a, ctx);
    }
    ec_point_affine(G2.x,G2.y, &G2, ctx);
    bn_set_1(G2.z, ctx->size);

    ecc_fix_mul_precompute(curve->F1, d, G2.x, G2.y, curve);
    /// Расчет точкa F2[0] = 2^{2e}G,
    for (i=0; i<(e); i++){// 2^{e}*2G = 2^{d}*G
        ec_point_dup (&G2, curve->a, ctx);
    }
    ec_point_affine(G2.x,G2.y, &G2, ctx);
    bn_set_1(G2.z, ctx->size);

    ecc_fix_mul_precompute(curve->F2, d, G2.x, G2.y, curve);
    /// Расчет точкa F3[0] = 2^{3e}G,
    for (i=0; i<(e); i++){// 2^{e}*2G = 2^{d}*G
        ec_point_dup (&G2, curve->a, ctx);
    }
    ec_point_affine(G2.x,G2.y, &G2, ctx);
    bn_set_1(G2.z, ctx->size);
    ecc_fix_mul_precompute(curve->F3, d, G2.x, G2.y, curve);
    ec_point_free(&G2, ctx);
//    curve->bn_size = size;
    return 1;
}
/*!
J*(a^3/27 + b^2/4)

J = 1728* 4a^3/(4a^3 + 27b^2)
J = (4^3*27)* 4a^3/(4a^3 + 27b^2)

k = J/(1728-J) = 4a^3/27b^2
*/
int ecc_curve_verify(BNuint* a, BNuint* b, MPCtx * ctx)
{
    BNuint A[ctx->asize] BN_ALIGN;
    BNuint B[ctx->asize] BN_ALIGN;
    BNuint k[ctx->asize] BN_ALIGN;
    BNuint aa[ctx->asize] BN_ALIGN;
    if (a==(void*)-3) {
        bn_set_0(aa, ctx->size);
        bn_sub_ui(aa, ctx->prime, 3, ctx->size);
    } else {
        bn_move(aa, a, ctx->size);
    }
    mp_sqrm(ctx, A, aa);
    mp_mulm(ctx, A, A, aa);// A^3
    mp_mulm_ui(ctx, A, A, 4);// 4a^3
    mp_sqrm(ctx, B, b);
    mp_mulm_ui(ctx, B, B, 27);// 27b^2
    //mp_addm(ctx, B, B, A);// (4a^3 + 27b^2)
    mp_invm(ctx, B, B);
    mp_mulm(ctx, k, A, B);// A^3
        printf("\nk= 0x");  bn_print (k, ctx->size);


    bn_move(k, b, ctx->size);
    mp_hlvm(ctx, k);
        printf("\nk= 0x");  bn_print (k, ctx->size);
    mp_addm(ctx, k, k, b);
    mp_modp(ctx, k, k);
    if (a==(void*)-3) {
        printf("\nA= 0x");  bn_print (k, ctx->size);
        return 1;
    } else
        return bn_equ(k, a, ctx->size);
}

/*! Функция генерации случайного ключика
TODO надо выдавать в диапазоне [2, n-2]
 */
void ecc_gen_key(BNuint* k, MPCtx * ctx)
{
extern int rng_gen_random(uint8_t* buffer, int len);
//    int size = mp_size(nbits);
int cnt = 4;
    while(!rng_gen_random((void*)k, ctx->size*sizeof(BNuint)) && --cnt>0)
        printf("Key Gen\n");
//    mp_randomize(k, nbits);
    mp_modp(ctx, k, k);
}

void ec_point_infty(ECC_Point* P, MPCtx *ctx)
{
    int size = ctx->size;
    bn_set_1(P->x, size);
    bn_set_1(P->y, size);
    bn_set_0(P->z, size);
}
/*! копирование точки в якобианских координатах */
void ec_point_copy_a2j(ECC_Point* Q, BNuint* px, BNuint* py, MPCtx *ctx)
{
    int size = ctx->size;
    bn_move (Q->x, px, size);
    bn_move (Q->y, py, size);
    bn_set_1(Q->z, size);
}
/*! копирование точки в якобианских координатах */
void ec_point_copy_j2j(ECC_Point* Q, ECC_Point* P, MPCtx *ctx)
{
    int size = ctx->size;
    bn_move (Q->x, P->x, size);
    bn_move (Q->y, P->y, size);
    bn_move (Q->z, P->z, size);
}
void ec_point_set(ECC_Point* P, BNuint* x, BNuint* y, BNuint* z, MPCtx *ctx)
{
    int size = ctx->size;
    bn_move (P->x, x, size);
    bn_move (P->y, y, size);
    if (z!=NULL)
        bn_move (P->z, z, size);
    else
        bn_set_1(P->z, size);
}
/*! Elliptic Curve Point Duplication
    Удвоение в проективных координатах
    \param P - удвоение происходит на точке
    \param a - параметр кривой
    \param p - prime number
    на входе (X,Y,Z)
 9/11 +1 умножений 9/7 сложений
 */
void ec_point_dup(ECC_Point* P, BNuint* a, MPCtx *ctx)
{
    if (bn_is_zero(P->z, ctx->size) /*|| bn_is_zero(P->y, ctx->size)*/) {
        //printf("\nDOUBLE-ZERO\n");
        ec_point_infty(P, ctx);
        return;
    }
    BNuint A[ctx->asize] BN_ALIGN;
    BNuint B[ctx->asize] BN_ALIGN;
    BNuint C[ctx->asize] BN_ALIGN;
    BNuint D[ctx->asize] BN_ALIGN;

/*  отдельно можно рассмотреть случай для a = p-3 и a = 0
    тогда D = 3(X + Z^2)(X - Z^2)
    иначе D = 3X^2 + aZ^4
    */
    if (a == (void*)-3){// D = 3X^2 - 3Z^4 = 3(X-Z^2)(X+Z^2)
        mp_sqrm (ctx, B, P->z);         // --
        mp_addm (ctx, D, P->x, B);
        mp_subm (ctx, A, P->x, B);      // --
        mp_mulm (ctx, B, D, A);
        mp_mulm_ui (ctx, D, B, 3);
    } else if (a == (void*)0){
        mp_sqrm (ctx, B, P->x);         // D = 3X^2
        mp_mulm_ui (ctx, D, B, 3);      //
    } else {
        mp_sqrm (ctx, B, P->x);         // D = 3X^2 + aZ^4
        mp_mulm_ui (ctx, D, B, 3);      //
        mp_sqrm (ctx, B, P->z);         //--
        mp_sqrm (ctx, B, B);            //--
        mp_mulm (ctx, B, B, a);         //--
        mp_addm (ctx, D, D, B);         //
    }
    mp_dubm (ctx, P->y, P->y);//, 1);   // Y = 2Y

    mp_sqrm (ctx, A, P->y);         // A = 4Y^2
    mp_mulm (ctx, B, A, P->x);     // B = 4X*Y^2
    mp_sqrm (ctx, C, A);            // C = A^2/2 = 8Y^4
    // W = W*C = W*Y^4;
    mp_hlvm (ctx, C);

    mp_mulm (ctx, P->z, P->z, P->y);      // Z_3 = 2YZ

    mp_dubm (ctx, A, B);
    mp_sqrm (ctx, P->x, D);//X_3 = D^2-2B
    mp_subm (ctx, P->x, P->x, A);

    mp_subm (ctx, B, B, P->x);        //Y_3 = D(B-X_3) - C
    mp_mulm (ctx, B, D, B);
    mp_subm (ctx, P->y, B, C);
}


#if 0
/*! \brief Сложение точек в поле эллиптической кривой в координатах (Ax, NULL)=J+J

    {x, NULL} = Q+P
    от результата возвращается только X координата в аффинных координатах
 */
void ec_point_add_x(BNuint *x, ECC_Point *Q, ECC_Point* P, MPCtx * ctx)
{
    C,D,E,F,G, z, t;

    mp_sqrm(ctx, &E, &Q->z);// E = Z1^2
    mp_sqrm(ctx, &F, &P->z);// F = Z2^2
    // C = Y2*Z1^3
    mp_mulm(ctx, &C, &P->y, &E);
    mp_mulm(ctx, &C, &C, &Q->z);
    // D = Y1*Z2^3
    mp_mulm(ctx, &D, &Q->y, &F);
    mp_mulm(ctx, &D, &D, &P->z);

    mp_mulm(ctx, &E, &E, &P->x);    // E = X2*Z1^2
    mp_mulm(ctx, &F, &F, &Q->x);    // F = X1*Z2^2
    // G = E - F
    mp_subm(ctx, &G, &E, &F);
    // Z3 = G*Z1*Z2
    mp_mulm(ctx, &z, &P->z, &Q->z);
    mp_mulm(ctx, &z, &z, &G);
    // X3 = (C-D)^2 - G^2(E+F)
    mp_subm(ctx, &t, &C, &D);
    mp_sqrm(ctx, x, &t);
    mp_sqrm(ctx, &G, &G);
    mp_addm(ctx, &E, &E, &F);
    mp_mulm(ctx, &t, &E, &G);
    mp_subm(ctx, x, x, &t);

    mp_invm(ctx, &t, &z); // x = X3*Z3^{-1}
    mp_sqrm(ctx, &t, &t);
    mp_mulm(ctx, x, x, &t);
    mp_modp(ctx, x, x);
}
#endif
/*! \brief Сложение точек в поле эллиптической кривой в смешанных координатах J=J+A
    \param Q - EC field point in jacobian coord. (x_1/z_1^2, y_1/z_1^3)
    \param P - EC field point in affine coord.(x2,y2, 1)
    \param ctx - контекст простого числа: prime, разрядность, функция редуцирования

    11 умножений 7 сложений
 */
void ec_point_add_a2j(ECC_Point *Q, BNuint* px, BNuint* py, MPCtx * ctx)//BNuint *prime, int size)
{
    if (bn_is_zero(Q->z, ctx->size)){
        bn_move(Q->x, px, ctx->size);
        bn_move(Q->y, py, ctx->size);
        bn_set_1(Q->z, ctx->size);
        //printf("ADD-ZERO!!!!\n");
        return;
    }
    BNuint A[ctx->asize] BN_ALIGN;
    BNuint B[ctx->asize] BN_ALIGN;
    BNuint C[ctx->asize] BN_ALIGN;
    BNuint D[ctx->asize] BN_ALIGN;
    BNuint E[ctx->asize] BN_ALIGN;
    BNuint F[ctx->asize] BN_ALIGN;
    BNuint G[ctx->asize] BN_ALIGN;
    BNuint H[ctx->asize] BN_ALIGN;
    BNuint I[ctx->asize] BN_ALIGN;

    mp_sqrm (ctx, A, Q->z);     // A = Z1^2
    mp_mulm (ctx, B, A, Q->z);  // B = Z1^3
    mp_mulm (ctx, C, A, px);    // C = X2*Z1^2
    mp_subm (ctx, E, C, Q->x);  // E = X2*Z1^2 - X1
/*    if (bn_is_zero(E, ctx->size)){
        printf("ZERO--INFTY!!!!\n");
        _Exit(1);
    }
*/
    mp_mulm (ctx, D, B, py);    // D = Y2*Z1^3
    mp_subm (ctx, F, D, Q->y);  // F = Y2*Z1^3 - Y1
/*    if (bn_is_zero(F, ctx->size)){
        printf("ZERO--DOUBLE!!!!\n");
        _Exit(2);
    }
*/
    mp_sqrm (ctx, G, E);         // G =(X2*Z1^2 - X1)^2
    mp_mulm (ctx, H, G, E);      // H =(X2*Z1^2 - X1)^3
    mp_mulm (ctx, I, G, Q->x);   // I =(X2*Z1^2 - X1)^2*X1

    mp_sqrm (ctx, A, F);           // X_3 = F^2-(H+2I)
    mp_dubm (ctx, B, I);
    mp_addm (ctx, B, B, H);
    mp_subm (ctx, Q->x, A, B);

    mp_subm (ctx, A, I, Q->x);    // Y_3 = F(I-X_3)-Y_1*H
    mp_mulm (ctx, A, A, F);
    mp_mulm (ctx, B, H, Q->y);
    mp_subm (ctx, Q->y, A, B);

    mp_mulm (ctx, Q->z, Q->z, E); // Z_3 = Z_1*(X2*Z1^2 - X1)
}

static inline BNint bn_naf_mods(BNuint *k, int w)
{
    BNint u = k[0]<<(BN_BITS-w);
    return u>>(BN_BITS-w);
}
static inline int bn_is_zero1(uint32_t *k, int n)
{
    while(n--) if (k[n]) return false;
    return true;
}
/*! \brief Alg 3.35 расчет формы NAF
    \param w - окно

для реализации умножения надо расчитать P_i = i*P , i ={1,3,5,7,9,11,13,15..., 2{w-1}-1}
 */
static int bn_naf_win(int8_t* naf, BNuint *k_ext, const int w, int n)
{
    BNuint k[n] BN_ALIGN;
    bn_move(k,k_ext,n);
//    int8_t* naf = g_malloc0((n<<BN_BIT_LOG) + 1);
//    memset(naf, 0, n<<5);
    int i=0;
//    int count=0;
    while (n>1 && k[n-1]==0){ n--; }
    int s = n;
    int sh=0;
    while (n>1 || k[0]!=0){//!bn_is_zero1(k, n)){
        if (k[sh>>BN_BIT_LOG]&(1<<sh)) {
            if (sh) {
                while (sh&~(BN_BITS-1)) {// сюда не попали
                    bn_shrB(k, 1, n); sh-=BN_BITS;
                    n--;//s--;// может зря вычитаю s
                }
                bn_shr (k, sh, n); sh=0;
                n = s - (i>>BN_BIT_LOG);
            }
            /// операция mods 2^w = расширение знака числа разрядностью w
            naf[i] = (BNint)k[0]<<(BN_BITS-w)>>(BN_BITS-w);//bn_naf_mods(k, w);
#if 1
//            count++;
            if (naf[i]>0) {
//                bn_sub_ui(k, k,  naf[i], n);
                k[0] -=naf[i];//&= (~0)<<w;

            }
            else
            if (naf[i]<0) {
                //bn_add_ui(k, k, -naf[i], n);
                k[0] += -naf[i];
                while (k[0]==0 && n>0){
                    i+=BN_BITS;
                    bn_shrB(k, 1, n);
                    k[0]++;
                    n--;
                }
            }
#else
            k[0] &= (~0)<<w;
#endif
        } //else naf[i] = 0;
        int d = k[0]==0?BN_BITS:BN_CTZ(k[0]);
        sh+=d;
        i+=d;
    }
//    printf("NAF=%d,", count);
    //for (;i<(s<<5);i++) naf[i] = 0;
    return i-sh;// число значимых бит
}
#if 0
void __attribute__((constructor)) bn_naf_test ()
{
    int N = 4;
    uint32_t k[] = {1122334455,0x5789abcd,0xef012345,0x67892345};
    int8_t* naf = bn_naf_win(k, 4, N);
    int i;
    N = (N<<5)-1;
    for (i=0; i<=N; i++){
        printf("%2d", naf[N-i]);
    }
    printf("\n");
    _Exit(0);
}
#endif
/*! алгоритм тестовый раскладывает скаляр умножения на RLE время 3/4 на 32 битах

должен делать тоже что и NAF для w=2
 */
static uint64_t add_count=0;
uint32_t rle_mul(uint16_t p, uint32_t k)
{
    int sign=0;//(k>>14)==3?1:0;
    uint32_t q = 0;//(k>>15)?p:0;

    uint32_t kk = (k>>30);
    if ((kk&3)==3){
        q = p; sign = 1;
    }
    int i = 32;
    do {
        q <<= 1; // dup
        kk <<=1;
        if (i>=3) kk |= (k>>(i-3))&1;
        if ((kk&7)==3) {
            q += p; sign=1;
            add_count++;
        } else
        if ((kk&6)==4){
            if (sign){
                q-=p;
                sign = 0;
            } else {
                q+=p;
            }
            add_count++;
        }
    } while (--i);
    return q;
}
#if 0
void __attribute__((constructor)) rle_mul_test()
{
    uint32_t i;
    int result = 0;
    uint32_t N = 0xFFFFFFFFUL;
    uint16_t X = 0xFFFF;
    for (i=N; i>0; i--){
        uint32_t res = rle_mul(X, i);
        //printf("%2dx%2d = %4d\n", i, i, res);
        if (res != X*i) { result = 1; break; }
    }
    if (result) {
        printf("fail at 0x%X\n", i);
    }
    printf("add_count %1.3f\n", (double)add_count/N);
    exit (result);
}
#endif

void ec_point_mulG_NAF(ECC_Point *Q, BNuint * k, ECC_Curve* curve)
{
    MPCtx* ctx = curve->ctx;
#if 0 // метод умножения в Left to right
    ec_point_mul  (&Q, &curve->G,k,curve->a,curve->ctx);
#else // NAF метод
    int8_t naf[(ctx->size<<BN_BIT_LOG)+1] BN_ALIGN;
    __builtin_bzero((BNuint*)naf, ctx->size<<BN_BIT_LOG);
    int i;
    i = bn_naf_win(naf, k, NAF_WINDOW, ctx->size);
    // пропустить нулевые и копировать
    while(i>=0 && naf[i]==0) i--;
    if(i<0) {
        ec_point_infty(Q, ctx);
        return;
    }
    if (naf[i]<0) {
        ECC_Point *P = &curve->P[-naf[i]>>1];
        ec_point_copy_a2j(Q, P->x, P->z, ctx);
    } else
    if (naf[i]>0) {
        ECC_Point *P = &curve->P[naf[i]>>1];
        ec_point_copy_a2j(Q, P->x, P->y, ctx);
    }
    i--;
    for (/*i=(ctx->size<<BN_BIT_LOG)-1*/; i>= 0; i--){
        ec_point_dup(Q, curve->a, ctx);
        if (naf[i]<0) {
            ECC_Point *P = &curve->P[-naf[i]>>1];
            ec_point_add_a2j(Q, P->x, P->z, ctx);
        } else
        if (naf[i]>0) {
            ECC_Point *P = &curve->P[naf[i]>>1];
            ec_point_add_a2j(Q, P->x, P->y, ctx);
        }
    }
#endif
}
/*! одновременное вычисление двух умножений R = lQ + kP

    \see Algorithm 3.48 Simultaneous multiple point multiplication
 */
void ec_point_mul2(ECC_Point *R, ECC_Point *Q, BNuint * l, ECC_Point *P, BNuint * k, BNuint* a, MPCtx* ctx)
{
    int sk=0,sl=0;
    BNuint pn[ctx->asize] BN_ALIGN;
    BNuint qn[ctx->asize] BN_ALIGN;
    bn_sub(pn, ctx->prime, P->y, ctx->size);
    bn_sub(qn, ctx->prime, Q->y, ctx->size);
//mp_modp(ctx, pn, pn);
    int i = (ctx->size<<5);
    uint32_t kk = bn_bit_val(k, i-1)<<1 | bn_bit_val(k, i-2);
    if ((kk&3)==3){
        ec_point_copy_j2j (R, P, ctx);
        sk = 1;
    } else {
        ec_point_infty(R, ctx);
    }
    uint32_t ll = bn_bit_val(l, i-1)<<1 | bn_bit_val(l, i-2);
    if ((ll&3)==3){
        if (sk ==1)
            ec_point_add_a2j(R, Q->x, Q->y, ctx);
        else
            ec_point_copy_j2j (R, Q, ctx);
        sl = 1;
    }
    do {
        ec_point_dup(R, a, ctx);

        kk<<=1;
        ll<<=1;
        if (i>=3) {
            ll |= bn_bit_val(l, i-3);
            kk |= bn_bit_val(k, i-3);
        }
        if ((kk&7)==3){
            ec_point_add_a2j(R, P->x, P->y, ctx);
            sk = 1;
        } else
        if ((kk&6)==4){
            if (sk){
                ec_point_add_a2j(R, P->x, pn, ctx);
                sk = 0;
            } else {
                ec_point_add_a2j(R, P->x, P->y, ctx);
            }
        }

        if ((ll&7)==3){
            ec_point_add_a2j(R, Q->x, Q->y, ctx);
            sl = 1;
        } else
        if ((ll&6)==4){
            if (sl){
                ec_point_add_a2j(R, Q->x, qn, ctx);
                sl = 0;
            } else {
                ec_point_add_a2j(R, Q->x, Q->y, ctx);
            }
        }
    } while (--i);
//    ec_point_affine(x, NULL, &Q, ctx);
}

void ec_point_mul2G_x/*_NAF*/(ECC_Point *Q, ECC_Point *R, BNuint * k, BNuint * l, ECC_Curve* curve)
{
    MPCtx* ctx = curve->ctx;
    const int naf_win =4;// 1 3 5 7
    ECC_Point S[1<<(naf_win-2)];
    size_t size = (ctx->size<<BN_BIT_LOG)+1;
    int8_t naf_r[size];
    __builtin_bzero(naf_r, size);
    int i_r = bn_naf_win(naf_r, k, naf_win, ctx->size);
    ecc_naf_mul_precompute(&S[0], naf_win, R->x, R->y, curve);

    int8_t naf[size];
    __builtin_bzero((BNuint*)naf, size);
    int i_p = bn_naf_win(naf, l, naf_win, ctx->size);
    int i =(i_r>i_p)?i_r:i_p;
    if (0){
        ec_point_infty(Q, ctx);
    } else
    if (i_r>i_p){
        i= i_r;
        if (naf_r[i]<0) {
            ECC_Point *T = &S[-naf_r[i]>>1];
            ec_point_copy_a2j(Q, T->x, T->z, ctx);
        } else
        if (naf_r[i]>0) {
            ECC_Point *T = &S[naf_r[i]>>1];
            ec_point_copy_a2j(Q, T->x, T->y, ctx);
        } else {
            ec_point_infty(Q, ctx);
        }
        i--;
    } else
    {
        i= i_p;
        if (naf[i]<0) {
            ECC_Point *P = &curve->P[-naf[i]>>1];
            ec_point_copy_a2j(Q, P->x, P->z, ctx);
        } else
        if (naf[i]>0) {
            ECC_Point *P = &curve->P[naf[i]>>1];
            ec_point_copy_a2j(Q, P->x, P->y, ctx);
        } else {
            ec_point_infty(Q, ctx);
        }
        if (naf_r[i]==0){
        } else
        if (naf_r[i]<0) {
            ECC_Point *T = &S[-naf_r[i]>>1];
            ec_point_add_a2j(Q, T->x, T->z, ctx);
        } else
        if (naf_r[i]>0) {
            ECC_Point *T = &S[naf_r[i]>>1];
            ec_point_add_a2j(Q, T->x, T->y, ctx);
        }
        i--;
//        printf("\n!!!!ZERO!!!!\n");
    }
    for (/*i=(ctx->size<<BN_BIT_LOG)-1*/; i>= 0; i--){
        ec_point_dup(Q, curve->a, ctx);
//if (i<=i_r) // вероятно ошибка
{
        if (naf_r[i]==0) {
        } else
        if (naf_r[i]<0) {
            ECC_Point *T = &S[-naf_r[i]>>1];
            ec_point_add_a2j(Q, T->x, T->z, ctx);
        } else
        if (naf_r[i]>0) {
            ECC_Point *T = &S[naf_r[i]>>1];
            ec_point_add_a2j(Q, T->x, T->y, ctx);
        }
}
//if (i<=i_p)
{
        if (naf[i]==0) {
        } else
        if (naf[i]<0) {
            ECC_Point *P = &curve->P[-naf[i]>>1];
            ec_point_add_a2j(Q, P->x, P->z, ctx);
        } else
        if (naf[i]>0) {
            ECC_Point *P = &curve->P[naf[i]>>1];
            ec_point_add_a2j(Q, P->x, P->y, ctx);
        }
}
    }
    ecc_naf_mul_free(&S[0], naf_win, curve);
//    ec_point_affine(x, NULL, &Q, ctx);
/*    for (i=0;i<1<<(naf_win-2); i++){
        ec_point_free(&S[i], ctx);
    }*/
}

static
unsigned int bn_bit_column(BNuint* v, int offset, int stride)
{
//    #define BN_BIT_MASK (BN_BITS-1)
    int n = FIX_WINDOW;
    unsigned int c = 0;
    int sh=0;
    do
    {
        //if((v[offset >> BN_BIT_LOG]&(1<<offset)) c |= (1<<sh);
        c |= ((v[offset >> BN_BIT_LOG]>>offset)&1) << sh;
//        if(v[offset >> BN_BIT_LOG] & (1<<offset)) c |= (1<<sh);
        offset+=stride, sh++;
    } while(--n);
    return c;
}
/*! \brief Fixed-base comb method for point multiplication
    \see GECC Alg.3.44
 */
void ec_point_mulG_comb(ECC_Point *Q, BNuint * k, ECC_Curve* curve)
{
    MPCtx* ctx = curve->ctx;
    ec_point_infty(Q, ctx);
    int i;// = (ctx->size<<(BN_BYTE_LOG)) -1; // размер в байтах для FIX_W = 4+4
    unsigned int v;
    int d = ctx->size<<(BN_BIT_LOG-FIX_BIT_LOG);//ctx->size<<(BN_BIT_LOG - FIX_BIT_LOG);
    for (i=d-1;i>=0; i--){
        ec_point_dup(Q, curve->a, ctx);
        v = bn_bit_column(k, i, d);
        if (v!=0){
            ECC_Point *P = &curve->F0[v-1];
            ec_point_add_a2j(Q, P->x, P->y, ctx);
        }
    }
}
/*! \brief Fixed-base comb method (with two tables) for point multiplication
    \see GECC Alg.3.45
 */
void ec_point_mulG_comb2(ECC_Point *Q, BNuint * k, ECC_Curve* curve)
{
//    static int done = 0;
//    int dd=0,aa=0;
    MPCtx* ctx = curve->ctx;
    ec_point_infty(Q, ctx);
    int i;
    unsigned int v;
    int d = ctx->size<<(BN_BIT_LOG-FIX_BIT_LOG);
    int e = d>>1;
    for (i=e-1;i>=0; i--){
        ec_point_dup(Q, curve->a, ctx);
        v = bn_bit_column(k, i, d);
        if (v!=0){
            ECC_Point *P = &curve->F0[v-1];
            ec_point_add_a2j(Q, P->x, P->y, ctx);
        }
        v = bn_bit_column(k, i + e, d);
        if (v!=0){
            ECC_Point *P = &curve->F2[v-1];
            ec_point_add_a2j(Q, P->x, P->y, ctx);
        }
    }
}

/*! \brief Умножение числа k на точку G
*/
void ec_point_mulG_comb4(ECC_Point *Q, BNuint * k, ECC_Curve* curve)
{
//    static int done = 0;
//    int dd=0,aa=0;
    MPCtx* ctx = curve->ctx;
    ec_point_infty(Q, ctx);
    int i;
    unsigned int v;
    int d = ctx->size<<(BN_BIT_LOG-FIX_BIT_LOG);
    int e = d>>2;
/* считаем что укладывается целое число STRIDE = const */
    i = e-1;
    if (i>=0) goto inside;// пропускаем одно дублирование
    for (;i>=0; i--){
        ec_point_dup(Q, curve->a, ctx);
//        dd++;
inside:
        v = bn_bit_column(k, i + 0*e, d);
        if (v!=0){
            ECC_Point *P = &curve->F0[v-1];
            ec_point_add_a2j(Q, P->x, P->y, ctx);
        }
        v = bn_bit_column(k, i + 1*e, d);
        if (v!=0){
            ECC_Point *P = &curve->F1[v-1];
            ec_point_add_a2j(Q, P->x, P->y, ctx);
        }
        v = bn_bit_column(k, i + 2*e, d);
        if (v!=0){
            ECC_Point *P = &curve->F2[v-1];
            ec_point_add_a2j(Q, P->x, P->y, ctx);
        }
        v = bn_bit_column(k, i + 3*e, d);
        if (v!=0){
            ECC_Point *P = &curve->F3[v-1];
            ec_point_add_a2j(Q, P->x, P->y, ctx);
        }
    }
}
static void ec_point_mulG_x(BNuint *x, BNuint * k, ECC_Curve* curve)
{
    MPCtx* ctx = curve->ctx;
    ECC_Point Q;
    BNuint vv[3][ctx->asize] BN_ALIGN;
    Q.x = vv[0],Q.y = vv[1],Q.z = vv[2];
    ec_point_mulG_comb4(&Q, k, curve);
    ec_point_affine(x, NULL, &Q, ctx);
}
/*! \brief Преобразование к аффиным координатам {x,y,z} -> {x/z^2,y/z^3,1}
    \param qx - x-координата точки на эллиптической кривой (в стандартных проективных координатах)
    \param qy - y-координата точки на кривой или NULL
    \param Q  - точка на эллиптической кривой
    \param ctx контекст простого числа
 */
void ec_point_affine(BNuint *qx, BNuint *qy, ECC_Point *Q, MPCtx* ctx)
{
    BNuint z1[ctx->asize] BN_ALIGN;
    BNuint z2[ctx->asize] BN_ALIGN;

    mp_invm(ctx, z1, Q->z);
    mp_sqrm(ctx, z2, z1);
    mp_mulm(ctx, qx, Q->x, z2);
    mp_modp(ctx, qx, qx);
    if (qy) {
        mp_mulm (ctx, z2, z2, z1);
        mp_mulm (ctx, qy, Q->y, z2);
        mp_modp (ctx, qy, qy);
    }
}
/*! \brief Сравнение точек (qx,qy,1) и Q (z!=0) к аффиным координатам {x,y,z} -> {x/z^2,y/z^3,1}
 */
int ec_point_equ(BNuint *qx, BNuint *qy, ECC_Point *Q, MPCtx* ctx)
{
    BNuint z2[ctx->asize] BN_ALIGN;
    mp_sqrm(ctx, z2, Q->z);
    mp_mulm(ctx, z2, z2, qx);
    mp_subm(ctx, z2, z2, Q->x);
    mp_modp(ctx, z2, z2);
    return bn_is_zero(z2, ctx->size);
}
/*! \brief преобразовать вектор n-точек на кривой из якобианских в аффинные коорднинаты

    затратная операция находения обратного числа выполняется быстрее,
    если выполнять ее одновременно для нескольких элементов.
    \param Q - вектор точек, результат возвращается на том же векторе
    \param n - число точек
    \param ctx - контекст
 */
void ec_point_affine_vec(ECC_Point *Q, int n, MPCtx* ctx)
{
//    BNuint z1[ctx->asize] BN_ALIGN;
    BNuint z2[ctx->asize] BN_ALIGN;
    BNuint* vec[n];

    int i;
    for (i=0;i<n;i++){
        vec[i] = Q[i].z;
    }
    mp_sim_inversion(ctx, vec, vec, n);
//    mp_invm(ctx, z1, Q->z);
    for (i=0;i<n;i++){
        mp_sqrm(ctx, z2, Q[i].z);
        mp_mulm(ctx, Q[i].x, Q[i].x, z2);
//        mp_modp(ctx, Q[i].x, Q[i].x);
        mp_mulm(ctx, z2, z2, Q[i].z);
        mp_mulm(ctx, Q[i].y, Q[i].y, z2);
//        mp_modp(ctx, Q[i].y, Q[i].y);
        bn_set_1(Q[i].z, ctx->size);
    }
}

/*! \brief Функция проверяет находится ли точка {Q.x,Q.y, 1} на эллиптической кривой
    Метод проверки - подставить в уравнение проверить тождество.

    коды проверкиэ
    0 - на кривой
    1 - qx или qy не укладываются в mod p
    2 - точка не на кривой

Существует еще одна проверка: nQ = Infinity
 */
int ec_point_verify(BNuint* qx, BNuint* qy, BNuint* a, BNuint* b, const MPCtx* ctx)
{
//    BNuint y2[ctx->asize] BN_ALIGN;
    BNuint x2[ctx->asize] BN_ALIGN;
    BNuint x3[ctx->asize] BN_ALIGN;

    mp_sqrm(ctx, x2, qx);
    mp_mulm(ctx, x3, x2, qx);
    if (a==(void*)-3){// a=p-3
        mp_mulm_ui(ctx, x2,  qx, 3);
        mp_subm(ctx, x2, x3, x2);
    } else if (a==(void*)0){// a=p-3
        mp_mulm_ui(ctx, x2,  qx, 0);
        mp_subm(ctx, x2, x3, x2);
    } else {
        mp_mulm(ctx, x2,  a,  qx);
        mp_addm(ctx, x2, x2, x3);
    }
    mp_addm(ctx, x2, x2, b);
    mp_modp(ctx, x2, x2);

    mp_sqrm(ctx, x3, qy);
    mp_modp(ctx, x3, x3);
    int res = bn_equ(x2, x3, ctx->size);

//    mp_invm(ctx, &x3, &x2);
//    mp_modp(ctx, &x3, &x3);
//    printf("\nsi =   0x");  bn_print(x3, ctx->size);

#if 0
    if ((ctx->prime[0]&3) == 3){
        /// для проверки подписи оба варианта подходят +y и -y
        mp_srtm(ctx, x3, x2);
        //mp_modp(ctx, &x3, &x3);

        int re = bn_equ(x3, qy, ctx->size);
        if (re) {
            printf("\nsi =   0x");  bn_print(x3, ctx->size);
            printf(" 02..OK");
        } else {
            bn_sub(x3, ctx->prime, x3, ctx->size);
            re = bn_equ(x3, qy, ctx->size);
            printf("\nsi =   0x");  bn_print(x3, ctx->size);
            if (re) printf(" 03..OK");
            else printf(" ..Fail");
        }
        res = res && re;
    }
#endif
#if 0
    {
        ECC_Point Q;
        ec_point_init(&Q, ctx);
        ec_point_set(&Q, qx,qy,NULL, ctx);
        ec_point_mul(&Q, ctq->prime);
        res = res && ec_point_is_infty(Q);
        ec_point_free(&Q, ctx);
    }
#endif



//    mp_free1(ctx, &x4);
//    mp_free1(ctx, &x3);
//    mp_free1(ctx, &x2);
//    mp_free1(ctx, &y2);
//    mp_free1(ctx, &z2);
//    mp_free1(ctx, &z1);
    return res;
}
/*! \brief восстанавливает значение qy по qx
    \param qy - параметр восстанавливается
 */
void ec_point_y(BNuint* qx, BNuint* qy, BNuint* a, BNuint* b, MPCtx* ctx)
{
//    BNuint y2[ctx->asize] BN_ALIGN;
    BNuint x2[ctx->asize] BN_ALIGN;
    BNuint x3[ctx->asize] BN_ALIGN;

    mp_sqrm(ctx, x2, qx);
    mp_mulm(ctx, x3, x2, qx);
    if (a==(void*)-3){// a=p-3
        mp_mulm_ui(ctx, x2,  qx, 3);
        mp_subm(ctx, x2, x3, x2);
    } else if (a==(void*)0){// a=p-3
        mp_mulm_ui(ctx, x2,  qx, 0);
        mp_subm(ctx, x2, x3, x2);
    } else {
        mp_mulm(ctx, x2,  a,  qx);
        mp_addm(ctx, x2, x2, x3);
    }
    mp_addm(ctx, x2, x2, b);
    mp_modp(ctx, x2, x2);

    if ((ctx->prime[0]&3) == 3){
        /// для проверки подписи оба варианта подходят +y и -y
        mp_srtm(ctx, qy, x2);
        //mp_modp(ctx, qy, qy);
    }
}

/*! Генерация открытого ключа на основе закрытого
 */
void ecc_public_key(BNuint* qx, BNuint* qy, BNuint* d, ECC_Curve* curve)
{
    ECC_Point Q;
    ec_point_init(&Q, curve->ctx);
    // выбрать алгоритм
    ec_point_mulG_comb4 (&Q, d, curve);
    ec_point_affine(qx, qy, &Q, curve->ctx);
    ec_point_free(&Q, curve->ctx);
}
int ecc_public_key_verify(BNuint* qx, BNuint* qy, BNuint* d, ECC_Curve* curve)
{
    MPCtx* ctx = curve->ctx;
    BNuint x[ctx->asize] BN_ALIGN;
    ECC_Point Q;
    ec_point_init(&Q, curve->ctx);
    // выбрать алгоритм
    bn_revert(d, ctx->size);
    ec_point_mulG_comb4 (&Q, d, curve);
    //int res = ec_point_equ(qx, qy, &Q, curve->ctx);
    ec_point_affine(x, NULL, &Q, curve->ctx);
//    mp_modp(ctx, x, x);
/*    printf("\nX=  0x"); bn_print (d, ctx->size);
    printf("\nX=  0x"); bn_print (x, ctx->size);*/
    int res = bn_equ(x, qx, ctx->size);
    ec_point_free(&Q, curve->ctx);
    return res;
}
/*! \brief Алгоритм цифровой подписи ECDSA пара чисел {r,s} является подписью
    \param k - random key
    \param d - private key
    \param e - 0< message < k

    The signer may replace (r, s) with (r,−s modn), because this is an equivalent signature.

    R = kG
    r = R_x  mod q
    s = (e + r*d)/k  mod q
    \see RFC 6090 KT-I signature
    может быть вариант генерации KT-IV
    s = k/(e + r*d)  mod q
    тогда проверка не будет содержать инверсию


 */
static int ecc_nist_sign(BNuint* r, BNuint* s, BNuint* d, BNuint* k_ext, BNuint* e, ECC_Curve* curve)
{
//    MPCtx* ctx = curve->ctx;
    MPCtx* ctq= curve->ctq;

    BNuint x[ctq->asize] BN_ALIGN;
    BNuint k[ctq->asize] BN_ALIGN;
    do {
        do {
            if (k_ext!=NULL) {
                bn_move (k, k_ext, ctq->size);
            } else {// генерить ключ
                do {
                    ecc_gen_key(k, ctq);
                } while (bn_is_zero(k, ctq->size));
            }
            ec_point_mulG_x(x, k, curve);
            mp_modp(ctq, r, x);
        } while (bn_is_zero(r, ctq->size));
        mp_mulm(ctq, x, d, r);
        mp_addm(ctq, x, x, e);// (e + d*r)
        mp_invm(ctq, s, k);
        mp_mulm(ctq, s, s, x);// s=k^{-1}(e + d*r)
//        mp_negm(ctq, s, s);
        mp_modp(ctq, s, s); //// s=k^{-1}(e + d*r) mod q
    } while (bn_is_zero(s, ctq->size));

    bn_set_0(k, ctq->size);
    bn_set_0(x, ctq->size);
    return 0;
}
/*! \brief Алгоритм проверки цифровой подписи ECDSA
        пара чисел {r,s} является подписью, Q (qx,qy) - открытый ключ

    \param r цифровая подпись
    \param s
    \param e сообщение

 u1 = e*s^{-1} mod n
 u2 = r*s^{-1} mod n
 R = u1G + u2Q
 v = Rx mod n
 return (v==r)

 */
int ecc_nist_verify (BNuint* r, BNuint* s, BNuint* e, BNuint * qx, BNuint * qy, ECC_Curve* curve)
{
    MPCtx* ctx = curve->ctx;
    MPCtx* ctq = curve->ctq;

    BNuint u1[ctq->asize] BN_ALIGN;
    BNuint u2[ctq->asize] BN_ALIGN;
    ECC_Point Q, C;
    BNuint vv[6][ctx->asize] BN_ALIGN;
    Q.x = vv[0], Q.y = vv[1], Q.z = vv[2];
    C.x = vv[3], C.y = vv[4], C.z = vv[5];

    mp_invm (ctq, u2, s);
    mp_mulm (ctq, u1, u2, e);
//    mp_modp (ctq, u1, u1); // может лишняя операция
    mp_mulm (ctq, u2, u2, r);
//    mp_modp (ctq, u2, u2); // может лишняя операция
    ec_point_set(&Q, qx, qy, NULL, ctx);
#if 0
    ec_point_mul2(&C, &Q, u2, &curve->G, u1, curve->a, ctx);
#else
    ec_point_mul2G_x(&C, &Q, u2, u1, curve);
#endif
    ec_point_affine(u1, NULL, &C, ctx);
/*    mp_sqrm(ctq, C.z, C.z);
    mp_modp(ctq, C.z, C.z);
    mp_mulm(ctq, u2, r, C.z);
    mp_subm(ctq, u1, C.x, r);
    mp_modp(ctq, u1, u1);
    return bn_is_zero(u1, ctx->size);
*/
    mp_modp(ctq, u1, u1);
    return bn_equ(r, u1, ctq->size);
}
/*! \brief проверка цифровой подписи с помощью секретного ключа
 u1 = e*s^{-1} mod n
 u2 = r*s^{-1} mod n
 R = (u1 + u2*d)G
 v = Rx mod n
 return (v==r)

    \param d - секретный ключ
 */
int ecc_nist_verify2(BNuint* r, BNuint* s, BNuint* e, BNuint* d, ECC_Curve* curve)
{
//    MPCtx* ctx = curve->ctx;
    MPCtx* ctq = curve->ctq;

    BNuint u1[ctq->asize] BN_ALIGN;
    BNuint u2[ctq->asize] BN_ALIGN;;

    mp_invm (ctq, u2, s);
    mp_mulm (ctq, u1, u2, e);

    mp_mulm (ctq, u2, u2, r);
    mp_mulm (ctq, u2, u2, d);
    mp_addm (ctq, u2, u2, u1);
    mp_modp (ctq, u2, u2); // может лишняя операция
    ec_point_mulG_x (u1, u2, curve);
    mp_modp(ctq, u1, u1);
    int res = bn_equ(r, u1, ctq->size);

    bn_set_0(u2, ctq->size);
    bn_set_0(u1, ctq->size);
    return res;
}

/*! \brief Алгоритм цифровой подписи по ГОСТ Р 34.10-2001/-2012
    \param r пара чисел {r,s} является подписью которую следует проверить
    \param s
    \param d - private key
    \param k_ext - random key 0 < k < q ключ может задаваться снаружи или внутри если k_ext NULL
    \param e - 0< message < k

    R = k*G
    r = x_R mod n
    s = d*r + k*e mod n
 */
int ecc_gost_sign(BNuint* r, BNuint* s, BNuint* d, BNuint* k_ext, BNuint* e, ECC_Curve* curve)
{
//    MPCtx* ctx = curve->ctx;
    MPCtx* ctq= curve->ctq;

//    printf("\n\ne =   0x");  bn_print(e->value, ctq->size);
//    printf("\nk =   0x");  bn_print(k->value, ctq->size);
    BNuint t[ctq->asize] BN_ALIGN;
    BNuint k[ctq->asize] BN_ALIGN;
    mp_modp(ctq, e, e);
    if (bn_is_zero(e,ctq->size)) {
        bn_set_1(e, ctq->size);
        printf("is 1\n");
    }
    do {
        do {
            if (k_ext!=NULL) {
                bn_move (k, k_ext, ctq->size);
            } else {// генерить ключ
                do {
                    ecc_gen_key(k, ctq);
                } while (bn_is_zero(k,ctq->size));
            }
            ec_point_mulG_x(t, k, curve);
            mp_modp(ctq, r, t);
//            printf("\nr =   0x");  bn_print(r->value, ctq->size);
        } while (bn_is_zero(r, ctq->size));
        mp_mulm(ctq,  s, d, r);
        mp_mulm(ctq,  t, k, e);//
        mp_addm(ctq,  s, s, t); // s = (k*e + r*d)
//        mp_negm(ctq,  s, s); - это такой прикол? цифровая подпись не зависит от знака
        mp_modp(ctq,  s, s);    // s = (k*e + r*d) mod q
//        printf("\ns =   0x");  bn_print(s->value, ctq->size);
    } while (bn_is_zero(s, ctq->size));
    bn_set_0(k, ctq->size);
    bn_set_0(t, ctq->size);
    return 0;
}
/*! \brief Проверка цифровой подписи по ГОСТ Р 34.10-2001/-2012

z1 =  s*e^{-1} mod n
z2 = -r*e^{-1} mod n
R = z1*G + z2*Q
return Rx == r

Можно исключить одну инверсию если считать одновременно инверсию  r и e
а сравнение делать в якобианских координатах
Rx
 */
int ecc_gost_verify(BNuint* r, BNuint* s, BNuint* e, BNuint * qx, BNuint * qy, ECC_Curve* curve)
{
    MPCtx* ctx = curve->ctx;
    MPCtx* ctq = curve->ctq;
    BNuint  v[ctx->asize] BN_ALIGN;
    BNuint z1[ctx->asize] BN_ALIGN;
    BNuint z2[ctx->asize] BN_ALIGN;
    ECC_Point Q, C;
    BNuint vv[6][ctx->asize] BN_ALIGN;
    Q.x = vv[0], Q.y = vv[1], Q.z = vv[2];
    C.x = vv[3], C.y = vv[4], C.z = vv[5];
if(0) {
    printf("\ne =  0x");  bn_print(e, ctx->size);
    printf("\nr =  0x");  bn_print(r, ctx->size);
    printf("\ns =  0x");  bn_print(s, ctx->size);
}
    mp_modp (ctq, e, e); // может лишняя операция
//    printf("\ne'=  0x");  bn_print(e, ctx->size);
    if (bn_is_zero(e, ctq->size)) {
        bn_set_1(e, ctq->size);
    }
//    printf("\ne =   0x");  bn_print(e, ctx->size);

    mp_divm (ctq, v, NULL, e);
//    mp_modp (ctq, v, v); // может лишняя операция
//    printf("\nv =   0x");  bn_print(v, ctx->size);
    mp_mulm (ctq, z1, s, v);
    mp_modp (ctq, z1, z1); // может лишняя операция
//    printf("\nz1 =  0x");  bn_print(z1, ctx->size);

//    mp_subm (ctq, z2, ctq->prime, r);
    mp_mulm (ctq, z2, r, v);
//    mp_modp (ctq, z2, z2);
    mp_subm (ctq, z2, ctq->prime, z2);
    mp_modp (ctq, z2, z2); //может лишняя операция
//    printf("\nz2 =  0x");  bn_print(z2, ctx->size);
//    printf("\nqx =  0x");  bn_print(qx, ctx->size);
//    printf("\nqy =  0x");  bn_print(qy, ctx->size);
    ec_point_set(&Q, qx, qy, NULL, ctx);
/*    if(ec_point_verify(qx, qy, curve->a, curve->b, ctx)){
        printf("ec point verified\n");
    }*/
#if 0
    ec_point_mul2(&C, &Q, z2, &curve->G, z1, curve->a, ctx);
    ec_point_affine(v, NULL, &C, ctx);
#else
    ec_point_mul2G_x(&C, &Q, z2, z1, curve);
    ec_point_affine(v, NULL, &C, ctx);
#endif
    mp_modp (ctq, v, v);
//    printf("\nr =  0x");  bn_print(r, ctx->size);
//    printf("\nv =  0x");  bn_print(v, ctx->size);
    return bn_equ (r,v, ctq->size);
}
/*! \brief Проверка цифровой подписи по ГОСТ Р 34.10-2001 с использованием закрытого ключа

z1 =  s*e^{-1} mod n
z2 = -r*e^{-1} mod n
R = (z1 + z2*d)G
return Rx == r
 */
int ecc_gost_verify2(BNuint* r, BNuint* s, BNuint* e, BNuint * d, ECC_Curve* curve)
{
    MPCtx* ctx = curve->ctx;
    MPCtx* ctq = curve->ctq;
    BNuint z1[ctx->asize] BN_ALIGN;
    BNuint z2[ctx->asize] BN_ALIGN;

    mp_invm (ctq, z2, e);
    mp_mulm (ctq, z1, s, z2);
    mp_mulm (ctq, z2, z2, r);
    mp_mulm (ctq, z2, z2, d);
    mp_subm (ctq, z2, z1, z2);
    mp_modp (ctq, z2, z2);
    ec_point_mulG_x (z2, z2, curve);
    mp_modp (ctq, z2, z2);
    int res = bn_equ (z2, r, ctq->size);
    bn_set_0(z2, ctq->size);
    return res;
}


static inline void bn_bits2bn(BNuint* r, const uint8_t *data,  int n)
{
    uint8_t * d = (void*) r;
    int i;
    for (i=0;i<n;i++){
        d[i] = data[n-1-i];
    }
}
static inline void bn_bn2bits(BNuint* r, uint8_t *data,  int n)
{
    uint8_t * d = (void*) r;
    int i;
    for (i=0;i<n;i++){
        data[n-1-i] = d[i];
    }
}
static inline void bn_octet2bn(BNuint* r, const uint8_t *data,  int n)
{
    uint8_t * d = (void*) r;
    int i;
    for (i=0;i<n;i++){
        d[i] = data[i];
    }
}
static inline void bn_bn2octet(BNuint* r, uint8_t *data,  int n)
{
    uint8_t * d = (void*) r;
    int i;
    for (i=0;i<n;i++){
        data[i] = d[i];
    }
}
#if 0
static ECC_Curve* ecc_gost_curve = NULL;
static void __attribute__((destructor)) ecc_gost_signature_fini()
{
    if (ecc_gost_curve) ecc_curve_free(ecc_gost_curve);
    _aligned_free(ecc_gost_curve); ecc_gost_curve=NULL;
}
#endif // 0
/*! \brief декодирование длины поля
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
//! Параметры кривых, которые требуют предварительных расчетов
static ECC_Curve *ecc_curves[EC_COUNT] = {NULL,};

/*! \brief
    \param

    TODO нужен контекст содержащий идентификаторы алгоритмов и кривых
    контекст состоит из трех идентификаторов типа алгоритма (NIST, GOST), кривой (name) и хеш (name)
 */
int ecc_gost_signature_verify(const SignCtx* sign_ctx, const uint8_t * public_key,
                              const uint8_t * signature, const uint8_t * data, int length)
{
    ECC_Curve* curve = ecc_curves[sign_ctx->id_curve];
    if (curve == NULL){
        curve = _aligned_malloc(sizeof(ECC_Curve), 16);
        ecc_curve_find(curve, sign_ctx->id_curve);//EC_GOST_CRYPTO_PRO_A);// "1.2.643.2.2.36.0");
        if (ecc_curves[sign_ctx->id_curve]==NULL) /// \todo атомарно
            ecc_curves[sign_ctx->id_curve] = curve;
    }

    const MDigest* md = digest_select(sign_ctx->id_hash_alg);// MD_GOSTR341194_CP);
    if (md==NULL) {
        return 0;// ошибка алгоритм хеш не найден
    }
    uint8_t hash[md->hash_len];
    digest(md, hash, md->hash_len, data, length);
/*        uint8_t hash[32];
        const MDigest* md = digest_select(MD_STRIBOG_256);
        digest(md, hash, 32,  data, length);
        print_octet2hex(hash   , "H",32);
*/

    MPCtx* ctx = curve->ctx;

    BNuint  r[ctx->asize] BN_ALIGN;
    BNuint  s[ctx->asize] BN_ALIGN;
    BNuint  x[ctx->asize] BN_ALIGN;
    BNuint  y[ctx->asize] BN_ALIGN;
    BNuint  e[ctx->asize] BN_ALIGN;

    int size = md->hash_len==32?32:64;// в байтах
    bn_octet2bn(e, hash, md->hash_len);
    int public_key_len;
    public_key = der_decode_length((uint8_t*)public_key+1,&public_key_len);
    bn_octet2bn(x, public_key, size);
    bn_octet2bn(y, public_key+size, size);
// TODO добавить смещение по битам
    bn_bits2bn(r, signature+size, size);
    bn_bits2bn(s, signature+ 0, size);

    int res = ecc_gost_verify(r, s, e, x, y, curve);
//    ecc_curve_free(&curve);
    return res;
}
int ecc_gost_signature_sign(const SignCtx* sign_ctx, const uint8_t * private_key, uint8_t * signature, const uint8_t * data, int length)
{
    ECC_Curve* curve = ecc_curves[sign_ctx->id_curve];
    if (curve == NULL){
        curve = _aligned_malloc(sizeof(ECC_Curve), 16);
        ecc_curve_find(curve, sign_ctx->id_curve);//EC_GOST_CRYPTO_PRO_A);// "1.2.643.2.2.36.0");
        if (ecc_curves[sign_ctx->id_curve]==NULL) /// \todo атомарно
            ecc_curves[sign_ctx->id_curve] = curve;
    }

    const MDigest* md = digest_select(sign_ctx->id_hash_alg);// MD_GOSTR341194_CP);
    uint8_t hash[md->hash_len];
    digest(md, hash, md->hash_len, data, length);
    MPCtx* ctx = curve->ctx;

    BNuint  r[ctx->asize] BN_ALIGN;
    BNuint  s[ctx->asize] BN_ALIGN;
    BNuint  d[ctx->asize] BN_ALIGN;
    BNuint  e[ctx->asize] BN_ALIGN;

    int size = md->hash_len==32?32:64;/// исправить, надо брать число бит в байтах
//printf(">>size=%d %s %d\n",size, md->name, md->hash_len);
    bn_octet2bn(e, hash, md->hash_len);
    bn_octet2bn(d, private_key, size);


    int res = ecc_gost_sign(r, s, d, NULL, e, curve);
    bn_bn2bits(r, signature+size, size);
    bn_bn2bits(s, signature+ 0, size);
//    ecc_curve_free(&curve);
    bn_set_0(d, ctx->size);
    return res;
}
#if 0
static ECC_Curve* ecc_nist_curve = NULL;
static void __attribute__((destructor)) ecc_nist_signature_fini()
{
    if (ecc_nist_curve) ecc_curve_free(ecc_nist_curve);
    _aligned_free(ecc_nist_curve); ecc_nist_curve=NULL;
}
#endif // 0
int ecc_nist_signature_verify(const SignCtx* sign_ctx,  const uint8_t* public_key,
                              const uint8_t* signature, const uint8_t* data, int length)
{
//    const ECC_Params* ecc_params = &ecc_domain_params[curve_id];
    ECC_Curve *curve = ecc_curves[sign_ctx->id_curve];
    if (curve==NULL){
        curve = _aligned_malloc(sizeof(ECC_Curve),16);
        ecc_curve_find(curve, sign_ctx->id_curve);
        ecc_curves[sign_ctx->id_curve] = curve;// атомарно заменить или убить
    }
    MPCtx* ctx = curve->ctx;

    const MDigest* md = digest_select(sign_ctx->id_hash_alg);
    int hash_offset = ctx->size - (md->hash_len>>(BN_BYTE_LOG));// смещение выразили в блоках BNuint
    if (hash_offset<0) hash_offset = 0;
    int hash_asize  = (md->hash_len+((1UL<<(BN_BYTE_LOG)) -1))>>BN_BYTE_LOG;// размер хеша выразим в BNuint
    BNuint qx[ctx->asize] BN_ALIGN;
    BNuint qy[ctx->asize] BN_ALIGN;
    BNuint  r[ctx->asize] BN_ALIGN;
    BNuint  s[ctx->asize] BN_ALIGN;
    /// \todo исправить, надо измерять ctx->asize в BNuint и md->hash_len в байтах.
    BNuint e[ctx->asize < hash_asize? hash_asize: ctx->asize] BN_ALIGN;

/*
    bn_hex2bin(qx, ctx->size, (char*)&Q[0]);
    bn_hex2bin(qy, ctx->size, (char*)&Q[ctx->size<<3]);
    bn_hex2bin(r, ctx->size,  (char*)&RS[0]);
    bn_hex2bin(s, ctx->size,  (char*)&RS[ctx->size<<3]); */
    int size = ctx->size<<BN_BYTE_LOG;// в байтах
    if (public_key[0]==0x04) {
//        printf("\n DER public key format");
//        public_key++;
    } else {
        // printf("\n RAW public key format");
        // упакованные данные 02 03
        return 0;
    }
    bn_bits2bn(qx, public_key+1, size);
    bn_bits2bn(qy, public_key+1+size, size);
    const uint8_t* RS = signature;
    int signature_len = (unsigned)RS[1];
    if (RS[0]==0x30 /* && signature_len== */) {
        RS += 2;
        int len = (unsigned)RS[1];
        if (RS[0]==0x02 && (RS+len<=signature+signature_len)) {
            bn_bits2bn(r, RS+2, (unsigned)RS[1]);
            RS += RS[1]+2;
//        printf("\nR=  0x"); bn_print (r, ctx->size);
        }
        len = (unsigned)RS[1];
        if (RS[0]==0x02 && (RS+len==signature+signature_len)) {
            bn_bits2bn(s, RS+2, len);
//        printf("\nS=  0x"); bn_print (s, ctx->size);
            //RS += RS[1]+2;
        }
    }
    if (hash_offset)
        bn_set_0(e,hash_offset);
    digest(md, (uint8_t*)&e[hash_offset], md->hash_len, data, length);
    bn_revert(e, ctx->size);
    mp_modp(curve->ctq,e, e);
    if (ec_point_verify(qx, qy, curve->a, curve->b, ctx)) {
        printf("-- ec point Q  verified\n");
    } else return 0;
    int res = ecc_nist_verify (r, s, e, qx, qy, curve);
    return res;
}
int ecc_nist_signature_sign  (const SignCtx* sign_ctx,  const uint8_t* private_key,
                                    uint8_t* signature, const uint8_t* data, int length)
{
    ECC_Curve* curve = ecc_curves[sign_ctx->id_curve];
    if (curve == NULL){
        curve = _aligned_malloc(sizeof(ECC_Curve), 16);
        ecc_curve_find(curve, sign_ctx->id_curve);//EC_GOST_CRYPTO_PRO_A);// "1.2.643.2.2.36.0");
        if (ecc_curves[sign_ctx->id_curve]==NULL) /// \todo атомарно
            ecc_curves[sign_ctx->id_curve] = curve;
    }

    const MDigest* md = digest_select(sign_ctx->id_hash_alg);// MD_GOSTR341194_CP);
    uint8_t hash[md->hash_len];
    digest(md, hash, md->hash_len, data, length);
    MPCtx* ctx = curve->ctx;

    BNuint  r[ctx->asize] BN_ALIGN;
    BNuint  s[ctx->asize] BN_ALIGN;
    BNuint  d[ctx->asize] BN_ALIGN;
    BNuint  e[ctx->asize] BN_ALIGN;

    int size = ctx->size<<BN_BYTE_LOG;// в байтах, это не годится для не выровненных праймов
    bn_octet2bn(e, hash, md->hash_len);
    bn_octet2bn(d, private_key, size);

    int res = ecc_nist_sign(r, s, d, NULL, e, curve);

    bn_bn2octet(r, signature+ 0, size);
    bn_bn2octet(s, signature+size, size);
//    ecc_curve_free(&curve);
    bn_set_0(d, ctx->size);
    return res;
}
#include "sign.h"

SIGNATURE(SIGN_ECC_GOST_GEOLAB){
    .id = SIGN_ECC_GOST,
    .name = "GOST 34.10-2012 Geolab",
    .verify = ecc_gost_signature_verify,
    .sign   = ecc_gost_signature_sign,
};

SIGNATURE(SIGN_ECDSA_GEOLAB){
    .id = SIGN_ECDSA,
    .name = "ECDSA Geolab",
    .verify = ecc_nist_signature_verify,
    .sign   = ecc_nist_signature_sign,
};
void ecc_curve_print(ECC_Curve* curve)
{
    int size = curve->ctx->size;
    printf("\nCurve:\t%s\n", curve->name);
    printf("Prime:\t");
    bn_print(curve->ctx->prime, size);
    printf("\na:\t");
    if (curve->a==(void*)-3) printf("P-3");
    else if (curve->a==(void*)0) printf("00");
    else bn_print(curve->a, size);
    printf("\nb:\t");
    bn_print(curve->b, size);
    printf("\nn:\t");
    bn_print(curve->ctq->prime, size);
    printf("\nG.x:\t");
    bn_print(curve->G.x, size);
    printf("\nG.y:\t");
    bn_print(curve->G.y, size);
}

#ifdef DEBUG_ECC
static void hex2bin (uint8_t* buf, const char* s)
{
    uint8_t c1=0,c2=0;
    while(s[0]!='\0') {
        if ('0' <= s[0] && s[0]<='9') c1= (s[0] - '0');
        else
        if ('A' <= s[0] && s[0]<='F') c1= (s[0] - 'A' + 10);
        else
        if ('a' <= s[0] && s[0]<='f') c1= (s[0] - 'a' + 10);
        s++;
        if (s[0]=='\0') break;
        if ('0' <= s[0] && s[0]<='9') c2= (s[0] - '0');
        else
        if ('A' <= s[0] && s[0]<='F') c2= (s[0] - 'A' + 10);
        else
        if ('a' <= s[0] && s[0]<='f') c2= (s[0] - 'a' + 10);
        // иначе пропускаем символ, например пропускаем пробелы и переносы строк
        *buf++ = c1<<4 | c2;
        s++;
    }
}
/*
void bn_revert(uint8_t* mp, int count)
{
    uint8_t * src = (uint8_t*)(mp + count);
    uint8_t * dst = (uint8_t*) mp;
    count >>= 1;
    while (count--) {
        uint8_t t = *dst;
        *dst++ = *--src;
        *src = t;
    }
}*/
/*!

коды ответов
0 - OK
1 - msg changed
2 - R changed
3 - S changed
4 - Q changed
 */
int ecc_nist_signature_verify2(char * Q, char* RS, uint8_t* msg, int msg_len, int curve_id, int hash_id)
{
    static ECC_Curve *ecc_curves[EC_COUNT] = {NULL,};
//    const ECC_Params* ecc_params = &ecc_domain_params[curve_id];
    ECC_Curve *curve = ecc_curves[curve_id];
    if (curve==NULL){
        curve = ecc_curves[curve_id] = _aligned_malloc(sizeof(ECC_Curve),16);
        ecc_curve_find(curve, curve_id);
    }
    MPCtx* ctx = curve->ctx;

    int result = 0;
//    const HashParams* hash = &ecc_hashes[hash_id];
    const MDigest* md = digest_select(hash_id);
    int hash_offset = ctx->size - (md->hash_len>>2);
    if (hash_offset<0) hash_offset = 0;
    BNuint  r[ctx->asize] BN_ALIGN;
    BNuint  s[ctx->asize] BN_ALIGN;
    BNuint qx[ctx->asize] BN_ALIGN;
    BNuint qy[ctx->asize] BN_ALIGN;
    BNuint e[ctx->asize<md->hash_len?md->hash_len:ctx->asize] BN_ALIGN;

    bn_hex2bin(qx, ctx->size, (char*)&Q[0]);
    bn_hex2bin(qy, ctx->size, (char*)&Q[ctx->size<<3]);
    bn_hex2bin(r, ctx->size,  (char*)&RS[0]);
    bn_hex2bin(s, ctx->size,  (char*)&RS[ctx->size<<3]);

//    printf("\nQ.x="); bn_print(qx, ctx->size);
//    printf("\nQ.y="); bn_print(qy, ctx->size);
//        bn_revert(msg, msg_len>>1);
    if (hash_offset)
        bn_set_0(e,hash_offset);
    digest(md, (uint8_t*)&e[hash_offset], md->hash_len, msg, msg_len);
    bn_revert(e, ctx->size);
    mp_modp(curve->ctq,e, e);
    if (ec_point_verify(qx, qy, curve->a, curve->b, ctx))
        printf("\n public key verified");
    else result = 4;//return (1);
    if (ecc_nist_verify (r, s, e, qx, qy, curve)){
        printf("\n  signature verified");
    } else result =1;//return(1);

    return result;
}
#include <sys/time.h>
static uint64_t g_get_real_time_()
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return (uint64_t)tv.tv_sec*1000000 + tv.tv_usec;
}
//__attribute__((weak, alias("g_get_real_time")))
uint64_t g_get_real_time_clock(){
#ifdef __i386__
    uint64_t x;
    __asm__ volatile ("rdtsc" : "=A" (x));
    return x;
#else
    uint32_t a,d;
    __asm __volatile__ ("rdtsc":"=&a"(a),"=d"(d));
    return (uint64_t)d<<32 | a;
#endif

/*	GTimeVal tv;
	g_get_current_time(&tv);
	return (uint64_t)tv.tv_sec*1000000 + tv.tv_usec;*/
}
int main (int argc, char* argv[])
{
    ECC_Curve curve;


    ecc_curve_list();
#if 0 // skip
    if (1 && ecc_curve_find (&curve, EC_SEC_P128r1))
    {
        ecc_curve_print(&curve);
//        ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx);

/*
priv:
    3d:8e:19:92:4f:e2:fc:80:d0:09:1e:0c:89:df:15:
    c7
pub:
    04:b1:d3:d0:4d:4a:a3:a4:94:69:1e:98:9c:de:45:
    39:11:0b:f6:89:d1:6d:d0:69:84:ad:15:4c:dc:a8:
    c0:06:0a
ASN1 OID: secp128r1
*/
        MPValue r; mp_alloc(curve.ctx, &r);
        MPValue s; mp_alloc(curve.ctx, &s);
        MPValue d; mp_alloc(curve.ctx, &d);
        MPValue q; mp_alloc(curve.ctx, &q);

        char *dd[] = {
            "0x3D8E19924FE2FC80D0091E0C89DF15C7",

            NULL
        };
        MPValue qx; mp_alloc(curve.ctx, &qx);
        MPValue qy; mp_alloc(curve.ctx, &qy);
        MPValue e; mp_alloc(curve.ctx, &e);
        MPValue k; mp_alloc(curve.ctx, &k);


        char ee[] = "0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5";
        char kk[] = "0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3";
        mp_hex2bin(curve.ctx, &e, ee);
        mp_hex2bin(curve.ctx, &k, kk);
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
                printf("\n G point verifyed");
        int i;
        for(i=0; i< 10 && dd[i]!=NULL; i++){
            mp_hex2bin(curve.ctx, &d, dd[i]);
            printf("\ni=%d\nd=    0x", i);
            bn_print (d.value, curve.ctx->size);

            ecc_public_key(qx.value, qy.value, d.value, &curve);
            printf("\nQ.x=  0x"); bn_print (qx.value, curve.ctx->size);
            printf("\nQ.y=  0x"); bn_print (qy.value, curve.ctx->size);
            if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
                printf("\n public key verifyed");
            else return(1);

            ecc_nist_sign  (r.value, s.value, d.value, k.value, e.value, &curve);
            if (ecc_nist_verify (r.value, s.value, e.value, qx.value, qy.value, &curve)
            &&  ecc_nist_verify2(r.value, s.value, e.value, d.value, &curve)){
                printf("\n OK");
            } else return(1);
        }

        mp_free1(curve.ctx, &k);
        mp_free1(curve.ctx, &e);
        mp_free1(curve.ctx, &qy);
        mp_free1(curve.ctx, &qx);

        mp_free1(curve.ctx, &q);
        mp_free1(curve.ctx, &d);
        mp_free1(curve.ctx, &s);
        mp_free1(curve.ctx, &r);

        ecc_curve_free (&curve);



    }
    if (1 && ecc_curve_find (&curve, EC_SEC_P128r2))
    {
        ecc_curve_print(&curve);
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
                printf("\n G point verifyed");
        else _Exit(1);
        ecc_curve_free (&curve);

    }
    if (0 && ecc_curve_find (&curve, EC_SEC_P160r1))
    {
        ecc_curve_print(&curve);
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
                printf("\n G point verifyed");
        else _Exit(1);

        MPCtx* ctx = curve.ctq;
        BNuint q[ctx->asize] BN_ALIGN;
//        BNuint q[ctx->asize] BN_ALIGN;
        //mp_divm (ctx, q, NULL, curve.G.x);
        bn_set_ui(q,3,ctx->size);
        mp_invm (ctx, q, q);
        mp_invm (ctx, q, q);
//        mp_divm (ctx, q, NULL, q);
//        mp_divm (ctx, q, NULL, q);
        printf("\n mp_divm "); bn_print(q, ctx->size);
        bn_move(q, curve.G.x,ctx->size);
        mp_invm (ctx, q, q);
        mp_mulm (ctx, q, q, curve.G.x);
        printf("\n mp_mulm "); bn_print(q, ctx->size);
        mp_modp (ctx, q, q);
        if (bn_is_one(q, ctx->size)) {
            printf("\n mp inversion mod p verifyed");
        }

        ecc_curve_free (&curve);
//        _Exit(160);
    }
    if (0 && ecc_curve_find (&curve, EC_SEC_P160r2))
    {
        ecc_curve_print(&curve);
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
                printf("\n G point verifyed");
        else _Exit(1);
        ecc_curve_free (&curve);
    }
    if (0 && ecc_curve_find (&curve, EC_SEC_P160k1))
    {
        ecc_curve_print(&curve);
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
                printf("\n G point verifyed");
        else _Exit(1);
        ecc_curve_free (&curve);
    }
    if (0 && ecc_curve_find (&curve, EC_WTLS9_P160))
    {// ошибки!!
        ecc_curve_print(&curve);
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
                printf("\n G point verifyed");
        else _Exit(1);
        ecc_curve_free (&curve);
    }
    if (1 && ecc_curve_find (&curve, EC_SEC_P192k1))
    {
        ecc_curve_print(&curve);
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
                printf("\n G point verifyed");
        else _Exit(1);
        ecc_curve_free (&curve);
    }
    if (0 && ecc_curve_find (&curve, EC_SEC_P224k1))
    {
        ecc_curve_print(&curve);
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
                printf("\n G point verifyed");
        else _Exit(1);
        ecc_curve_free (&curve);
    }
    if (1 && ecc_curve_find (&curve, EC_SM2))
    {
        ecc_curve_print(&curve);
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
                printf("\n G point verifyed");
        else _Exit(1);
        ecc_curve_free (&curve);
    }
    if (1 && ecc_curve_find (&curve, EC_NUMS_P256d1))
    {
        ecc_curve_print(&curve);
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
                printf("\n G point verifyed");
        else _Exit(1);
        ecc_curve_free (&curve);
    }
    if (1 && ecc_curve_find (&curve, EC_NUMS_P384d1))
    {
        ecc_curve_print(&curve);
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
                printf("\n G point verifyed");
        else _Exit(1);
        ecc_curve_free (&curve);
    }
    if (1 && ecc_curve_find (&curve, EC_NUMS_P512d1))
    {
        ecc_curve_print(&curve);
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
                printf("\n G point verifyed");
        else _Exit(1);
        ecc_curve_free (&curve);
    }
    if (1 && ecc_curve_find (&curve, EC_NIST_P192))
    {
        ecc_curve_print(&curve);
//        curve.ctx->reduction = mp_reduction_nist_p192;
//        curve.ctq->reduction = mp_reduction_nist_p192_n;
        MPValue r;  mp_alloc(curve.ctx, &r);
        MPValue s;  mp_alloc(curve.ctx, &s);
        mp_mulm(curve.ctx, r.value, curve.G.x, curve.G.y);

        printf("\n mulm 0x");
        bn_print (r.value, curve.ctx->size);

        MPValue d; mp_alloc(curve.ctx, &d);
        MPValue q; mp_alloc(curve.ctx, &q);
        char *dd[] = {
            "0xe5ce89a34adddf25ff3bf1ffe6803f57d0220de3118798ea",
            "0x7d14435714ad13ff23341cb567cc91198ff8617cc39751b2",
            "0x12039a122de1725d8d0e369b2fb536f7a38414a67cf69a83",
            "0xc9000be980277861ba12aef988c4fcee9fcc7976cdb52c24",
            "0x33d3e07b943e37455588cff5e45ca817ae800a1302bb01e3",
            "0xe23b51e2a07e73e23ff3399978f537dfb2532af873d1ceae",
            "0x59c9a7db3e58ee05cca57a26faa4e459605ca606bda62a9b",
            "0x36bf9605bfec53fcf22cb1e0cce77b40e41b092b3ae6d009",
            "0x6774fde78e05c49a819e8a15f375a5944e289abd615a9d59",
            "0xec08d03c8b42b1c79bfb3e8eb38b1553db63599a511dd5b9",
            NULL
            };
//inv();
        bn_move(d.value, r.value, curve.ctx->size);
        mp_invm (curve.ctx, q.value, d.value);
        printf("\nd=    0x");
        bn_print (d.value, curve.ctx->size);
        printf("\nq=    0x");
        bn_print (q.value, curve.ctx->size);
        mp_mulm (curve.ctx, r.value, q.value, d.value);
        printf("\ne=    0x");
        bn_print (r.value, curve.ctx->size);

        MPValue qx; mp_alloc(curve.ctx, &qx);
        MPValue qy; mp_alloc(curve.ctx, &qy);

        char ee[] = "0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E";
        char kk[] = "0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE6";

        MPValue e; mp_alloc(curve.ctx, &e); mp_hex2bin(curve.ctx, &e, ee);
        MPValue k; mp_alloc(curve.ctx, &k); mp_hex2bin(curve.ctx, &k, kk);
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
                printf("\n G point verifyed");
        int i;
        for(i=0; i< 10 && dd[i]!=NULL; i++){
            mp_hex2bin(curve.ctx, &d, dd[i]);
            printf("\ni=%d\nd=    0x", i);
            bn_print (d.value, curve.ctx->size);

            ecc_public_key(qx.value, qy.value, d.value, &curve);
            printf("\nQ.x=  0x"); bn_print (qx.value, curve.ctx->size);
            printf("\nQ.y=  0x"); bn_print (qy.value, curve.ctx->size);
            if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
                printf("\n public key verifyed");
            else return(1);

            ecc_nist_sign  (r.value, s.value, d.value, k.value, e.value, &curve);
            if (ecc_nist_verify (r.value, s.value, e.value, qx.value, qy.value, &curve)
            &&  ecc_nist_verify2(r.value, s.value, e.value, d.value, &curve)){
                printf("\n OK");
            } else return(1);
        }
if (0) {
        int i;
        uint64_t start, end;
        start = g_get_real_time_();
        for(i=0;i<4000;i++){
            ecc_nist_sign  (r.value, s.value, d.value, k.value, e.value, &curve);
        }
        end = g_get_real_time_();
        printf("\nNIST P-192 time = %1.3f us , sign\t= %1.1f per s\n", (double)(end-start)/i, (double)(i)*1000000/(end-start+1));
        start = g_get_real_time_();
        for(i=0;i<4000;i++){
            if (!ecc_nist_verify (r.value, s.value, e.value, qx.value, qy.value, &curve)) return 1;
        }
        end = g_get_real_time_();
        printf("\nNIST P-192 time = %1.3f us , verify\t= %1.1f per s\n", (double)(end-start)/i, (double)(i)*1000000/(end-start+1));
        mp_hex2bin(curve.ctx, &d, dd[3]);
        mp_hex2bin(curve.ctx, &k, kk);
        for(i=0;i<1000;i++){
            mp_addm(curve.ctx, k.value, k.value, curve.b);
            mp_subm(curve.ctx, d.value, d.value, curve.G.x);
            ecc_nist_sign  (r.value, s.value, d.value, k.value, e.value, &curve);
            ecc_public_key (qx.value, qy.value, d.value, &curve);
            if (!ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
                return(1);
            if (!ecc_nist_verify2(r.value, s.value, e.value, d.value, &curve))
                return 1;
            if (!ecc_nist_verify (r.value, s.value, e.value, qx.value, qy.value, &curve)) {
                printf("cnt= %d\n", i);
                return 1;
            }
        }
        printf("\nNIST P-192 OK\n");
//        return 0;
}




char *Msg[12], *Q[12], *RS[12];
int SHA[12];
Msg[0] = "bf826447a665165a837ed32a13c49e3b57a9e9bce263d1492bcc418b0eefd4093032b62ecd27f1a2031af454077f7858f1e3970050e9b44b98b388b27f3487fdf27adcaae07dc7ab1913dd7983a9744063dd01e976cb818cc7c3a838b50bc55588d41240d97b714d2c2dab550814724250a5a478ad445e154bc8950f8f1aaa37";
Q[0]  = "72a83b1ee3f83034324db4377663c933b4799564b2335bea"
        "76b0c9874b94daff7e78881d22e5fcd53a3ea2afd0d118f4";
RS[0] = "161e7d162dbeeb5f8d3393df65fb6a136ad867ddd3b85ca0"
        "301cdf1284766043f9a0cc1eb2f2a21538dd8e618cc46ff3";
SHA[0]=MD_SHA1;
//Result = P (0 )
Msg[1] = "f3b53719057f9834234133022f7cb2dccaa8adbfd3ad5e2fb0f7c1ae2a1f8dc2f1b57563c23c438cd78da6d4e7ee601d38fe2f856deb735406d52a4a3159c5e25583497521a2ff3ac59af9e6c530f2ff0f89fa06bbef69df84f0a0f75ad1c437fbd40026ee96b3eef840b5f1db0b9dc8626c76d6f49cefa2cbbb7914f2eced0a";
Q[1]  = "a523a664117b5df1b9a5c8c6207e38734e71271d0de424c3"
        "b4f5ba413184d4fb6e9f91dfb17a0c0915a60c7892ca76ee";
RS[1] = "e49f9a94c4154847d76250e382c48e08e8e844b71a6f0426"
        "72a40febae3dbef7e2502af9a0d1680099593f86ead4ab39";
SHA[1]=MD_SHA1;
//Result = P (0 )
Msg[2] = "79f284dec0c329b2f48e534324e51eaf1f1c32a17159a55f2b1387f0df46bd7f9e9f48bd96dc0efee06d0400b65bfd683c8a231fb22e3c6fb417370d1d0291ec2949d33c4a0fa40037451c42029c773092df2652f9d8baab312ba120a61ad75cfe3dce779a8a8df90738999b9da203e65f72a95ba122e17239e164345cdfc89e";
Q[2]  = "3db70ceec7d35c4af73ea364c1b192887c76feb75f3d8a4f"
        "92c94044326a6e6877a58b2800e66c9708e168f8456789d6";
RS[2] = "f205a1f23dc9dd4e4c4019c44cd42628eb825ecb3161db4f"
        "2be21a381e023b9fde00738e3514ad7e2a42139040970934";
SHA[2]=MD_SHA1;
//Result = P (0 )
Msg[3] = "c249c142ec49d38fdedc33cfaa58b025c0ab36329794d8db65bb9ccbaffb930a9003ba70d07dd2d96b9e263c002013a34bdf02884e40267c07b2a6203374eab04182b57d19885b193be288cb3394b2be1d13fe3a613c3ad5e4dc15503573bce0ade1637fa7f60c72e90e399ecde75492774366a68451f8d65b9a2c37d3a7e74c";
Q[3]  = "d1648aa094db4f1549561dffa7215007bf81739581fbfa46"
        "44d9f9bb70ff41d86d474ee1e5c6bc561632bf082c0be9cf";
RS[3] = "d20dab7444a2066aa93815217ea0b0d0c2558680e77829b3"
        "f635ffac94144753fa062ec393a795cc9323c4914a3023e5";
SHA[3]=MD_SHA224;
//Result = P (0 )
Msg[4] = "410cbffed21edd0a167d974749d288b1320a638bd08d43f7fad338952e371ad7840d20909c1d6fdd82afad20ed0aaf87dbcbf2bd1ec9795b82d87a40e1781a7aa9d28d4dc1d3bb95f08a124c77d7f50e4be54ccebb16eab551cc41adfcf48cb435502a9417f9ad9bfdeb4b47cdb99b2b062699e4475e27aae4e6a1056a511cae";
Q[4]  = "8c5f8edcd0ff9d916934b7efbbbe0e1f67abacb96902963e"
        "82d197e317b65787aad7095603e9b55cc8007f2b060cb799";
RS[4] = "107c929ef457541673abfcfa14488d68c3a82a97982221ad"
        "c19dcada426e4504b55cab20c5e7bf3b618e9a6860e784a6";
SHA[4]=MD_SHA224;
//Result = P (0 )
Msg[5] = "76f44a2dbb96d50840a37bcdb23f0d56e159bf4663c22c116963ada3df2431450019aa8ab922612dbe80f2d35b5096de41273f648edf09929a698c7e9028565afd16bd976e76a5a96360bf89a0908ce379c9f69c508c6cf6811e1cf5946e09a0d2d5a92387bd5a95aea5e1229b7810b5757bf88381ad2d3075e85cd47d28eec4";
Q[5] =  "b870597b4b8dc8fc07ed59b6f079e87936d56d0326c17249"
        "e54c404920cd530f0680d8aa2a4fb70b5f8605e6ebbf2751";
RS[5] = "b53dc1abd4f65d5e0506fa146bee65ecb6cd5353830b67ea"
        "aa44232f2fa6613f85fda824ded69e4137cdf5688c6b3ba9";
SHA[5]=MD_SHA256;
//Result = P (0 )
Msg[6] = "df5437f01e4921f9c3c4d7bc59bce4090e73d08d7388077b3fe0c789374e917dc5bb0d2577703f5ae5bed27f26da6353b9ceaf694ded6576925edf2e8ca4fed2a14974a6a6550beb6e5478e90d221edd4bcad8368fb9f1aa42722f740fa9e9308d9aa14e34bcc177c60e32b0fcaef7ac8724335e746ce839b8c9c48593793cc1";
Q[6] =  "795bbf28b86af380c2b080e622f92f81de6d2af41a39bc39"
        "3d3bcfcbe704426e95d0edbf40eae25a259af239b00158c9";
RS[6] = "5a3fd911aac408cce41e0eaf42761cce155c5a6efe03df11"
        "605ffbb146bf787888d9c3e45f79d0bc6959dcfacfaea437";
SHA[6]=MD_SHA256;
//Result = P (0 )
Msg[7] = "448b0076730e95aacf91f1d82764747d9a5a9accd8327d6d5bd9338c024a2589ad09f7216bb187ad3e22a7e146952d77fc09918a159187b9e2d8e45866f07a0092c7484a47915ee4435959d5e6662acfe1290b1ee6229f9ef23c05a07ab8a1a6e06b07a84c20001d49ca931641d68f7c415902b0b2213bbb7df77dc2dead0d0c";
Q[7] =  "059b41befe4d089dd852fbc567806bd0a43e232a2ae0922a"
        "6279770311f4b57363ef27adf7bab7f273828a3a4c93ae83";
RS[7] = "07e81b35313ec53c627d1d1d01bf6fb9efabdd6be58b0b09"
        "89f5ba7167373be6628ecf6efe15f4a756b4d829f9e7dd43";
SHA[7]=MD_SHA384;
//Result = P (0 )
Msg[8] = "d140e1a4d5f92a41433cd5a5ff293740943ea700f07e2e9e3e80502bae76c2c4115de9c3d30dcc1e89ad2fb41f18be09124e9170af756cfd9698a077e5f50f205b37e3919da3790846a10c1ec9a56fa6870bee7f6b9ebca0a60e085b31edb0884726196aa1945c8f1a69a8aedbf5f36a45c9b6a31f7dcc720c6aa578d6c538f0";
Q[8] =  "85f9d1376f78a82b4044fede433026876ab2f75312132b77"
        "c4c6d34efd2513d3fb98ce600d6375b29ab606e6b3f9463e";
RS[8] = "a6c86865c55fac4945cc3d37099e8c575fdf963a27c780c3"
        "765e85a17f07b8eacf958057c14fa0e5b954726e0106f41c";
SHA[8]=MD_SHA384;
//Result = P (0 )
Msg[9] = "f7f188240f38a1649324cfdbe91a45bc09655f3c99354730a87392b0af766bac56c5a90497ab1229236a3292b4b4ce5394fc3f8388d825ab842c05ef757631fbfa8f75730fc4b4264a880ae4a4f4b96fd3753591359818d8f4f4408b33e9886acfdcae287adf78fb44d0e247b325df6d3057148c941c8fc78ab138d085e46210";
Q[9] =  "dea419cbbb2c7be3b59d6eb4db9ca48efb4835eccf8d0a48"
        "88dde250494bb6b910e979c5fb3a2fc44d41ae3e761fe85d";
RS[9] = "302648f3a89aec847742ec72209ac02d6232fe2363f72fac"
        "a1895dd201f022c17cd69dab9c5438d2b25f9368aa8b9cc3";
SHA[9]=MD_SHA512;
//Result = P (0 )
Msg[10] = "b16560c4aee6699872330bea44404cd0ecf9ba12fbed66386b78be5bad1db07fc5ce2c6a52cd9e0bd7f240cf75a149f0844d5bb5fb17fc4fc2a8c965ca2b6e3a4cdaa648f3fd479ef58eb71c4ed19de33fb35b79b0956ba2a17e2674dbf054cf3da30d4bf43af0088c584c636bf084ff9c4fed43fe922a9c31a618decce8a866";
Q[10] = "2d3cffc6aac703d224029d243036cae359af89fb24801481"
        "00346a43ccc3cdcc37cb9b2757d5f88fede01a5ac160f253";
RS[10] ="3a844183d6a2a59255ef9105a6b8dbbd0662c227ee04be0e"
        "4f322c112b5cbdc7c23138ac51fb975cff8277676105e5f1";
SHA[10]=MD_SHA512;
//Result = P (0 )
        int curve_id = EC_NIST_P192;
        for(i=0;i<11;i++){
            if (i==0 || SHA[i]!=SHA[i-1]){
                const MDigest* md = digest_select(SHA[i]);
                printf("\n %s, %s signature verify test", ecc_domain_params[curve_id].name, md->name);
            }
            int msg_len = strlen(Msg[i]);
    //        printf("\nlength=%d", msg_len);
            uint8_t *msg = malloc(msg_len);
            hex2bin(msg, Msg[i]);
            int res = ecc_nist_signature_verify2(Q[i], RS[i], msg, msg_len>>1, curve_id, SHA[i]);
            if (res!=0) return res;

            free(msg);
        }

        mp_free1(curve.ctx, &e);
        mp_free1(curve.ctx, &k);

        mp_free1(curve.ctx, &qy);
        mp_free1(curve.ctx, &qx);

        mp_free1(curve.ctx, &s);
        mp_free1(curve.ctx, &r);
        mp_free1(curve.ctx, &q);
        mp_free1(curve.ctx, &d);
        ecc_curve_free (&curve);
//        return 0;
    }
    if (0 && ecc_curve_find (&curve, EC_NIST_P224))
    {
        ecc_curve_print(&curve);
//        curve.ctx->reduction = mp_reduction_nist_p224;
//        curve.ctq->reduction = mp_reduction_nist_p224_n;
        MPValue r; mp_alloc(curve.ctx, &r);
        MPValue s; mp_alloc(curve.ctx, &s);
        MPValue d; mp_alloc(curve.ctx, &d);
        MPValue q; mp_alloc(curve.ctx, &q);
        char *dd[] = {
            "0xe7c92383846a4e6887a10498d8eaca2bd0487d985bd7d3f92ce3ab30",
            "0x7f29534466bcb399777a0c7d3d4eff787d96db26ac3561f9d43cccd9",
            "0x2ce71aafdad95b69fdda27f441b2f28da06db5d17adb468af3e351a0",
            "0x68736e34687ee8408917200baa0a30a87c3d1b2d04fe617c0ba212e9",
            "0xd6901df3d4020dae1132b6f4e028dbead231d1f3d53c8eb22d85a6d7",
            "0x7b9bc29a4e737d97af8b148b2a56f0a0dd22b8e69db10172ddcb8e59",
            "0xc078ad3141b567848dc389c3eb1d6d6733929c73d6bcb94333805376",
            "0x6140b0af79c0b92e938bc8a5fc2ccbd62b7e7825c1bb5c89d4434856",
            "0x30f4113572e0fb39209aad2698608bc47f8c0d8c1061e954f72bc805",
            "0x9c1005987043a7b8f41efcccf3ac3e413ef31938097d2ac8bee9ec8e",
            NULL
            };
        MPValue qx; mp_alloc(curve.ctx, &qx);
        MPValue qy; mp_alloc(curve.ctx, &qy);

        char ee[] = "0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE667";
        char kk[] = "0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED9245";
        MPValue e; mp_alloc(curve.ctx, &e); mp_hex2bin(curve.ctx, &e, ee);
        MPValue k; mp_alloc(curve.ctx, &k); mp_hex2bin(curve.ctx, &k, kk);

        int i;
        for(i=0; i< 10 && dd[i]!=NULL; i++){
            mp_hex2bin(curve.ctx, &d, dd[i]);
            printf("\ni=%d\nd=    0x", i);
            bn_print (d.value, curve.ctx->size);

            ecc_public_key(qx.value, qy.value, d.value, &curve);
            printf("\nQ.x=  0x"); bn_print (qx.value, curve.ctx->size);
            printf("\nQ.y=  0x"); bn_print (qy.value, curve.ctx->size);
            if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
                printf("\n public key verifyed");
            else return(1);

            ecc_nist_sign  (r.value, s.value, d.value, k.value, e.value, &curve);
            if (ecc_nist_verify (r.value, s.value, e.value, qx.value, qy.value, &curve)
            &&  ecc_nist_verify2(r.value, s.value, e.value, d.value, &curve)){
                printf("\n OK");
            } else return(1);
        }

        mp_free1(curve.ctx, &k);
        mp_free1(curve.ctx, &e);

        mp_free1(curve.ctx, &qy);
        mp_free1(curve.ctx, &qx);

        mp_free1(curve.ctx, &q);
        mp_free1(curve.ctx, &d);
        mp_free1(curve.ctx, &s);
        mp_free1(curve.ctx, &r);
        ecc_curve_free (&curve);


char *Msg[12], *Q[12], *RS[12];
int SHA[12];
Msg[0] = "edfb1e8f6d45345d23b194f9b25c4ffdea45277715363fe47b964a52020cfc4e2021445ca850836340a2826efd84ed7424a2c09ef02871e5594dafe25d5631d6b32c385d9be2017015c17fcfde20a9cb2ba2250ca356bdec1770c810c22c647e8343f3748087759954258d856d6e2e5f13d8df4a07b3ea036cbf215c3099224c";
Q[0]  = "a100d410ce497e991070285c439cd361a1a9c6c973fd6f5e1ba9ec66"
        "0a8c3a2f909f212c84441b8c0030529cbd731304d86f771d89d7cc29";
RS[0] = "1bfcaab01e47addd4733369320364ad208169ffb15e6aac33c2d7c06"
        "07fb33465e7b7b373feda2ea35ab7cc9477156a1335ecad942f99627";
SHA[0] = MD_SHA1;
//Result = P (0 )
Msg[1] = "11bf93a16222dfafd6a0d440ae55a7c3e452a7997ff9ab26915ace29fdb43eb3fc7c4973eb134eb0fbab0bd3b5decb349f9a68a5467a028ee6da6e128dba88c0477176ab2e35e4b3f78686006b0fa0d27eee4d652d6094ec883ccce18472c3e66b59184b79d50e70acb15e479e91dac8be2fb691d370fb8507742796f38f131c";
Q[1]  = "8a6a77179ffc0ff5d412cf859cc82aa19cd18e5224ab997e9c2e46b0"
        "3d67c177ca7cc12c7b05a3bf55fb78549ef5400a566efe8ae3580c9f";
RS[1] = "107b7442e6569ddde54b5da55a9dac9bd348079358047a19a3de0b91"
        "92359be39353cb263946294fb728eecf1880f50a43637f391d3e7824";
SHA[1] = MD_SHA1;
//Result = P (0 )
Msg[2] = "2dad0fdc03e9617e0de30b3108e0ef155e4e6c3169cec76622c16dc55fcac39a5fb002472072754e7885cac0e318b3ce0588559152a37e6e55effb6b8e19c45ac8aaa91fbd8cad41fd2a2d5af03841ba13f405b20a04585ac0e456502b9686e72e87e8ad7257d3d65781766c3752c6aa9a24d6f49052e753e2e31e155a35b7ec";
Q[2]  = "f1eb36b3e1c96a18d87878d5fa8b79d77afce9d2ce40d26199f33482"
        "ae819af474f3efbd62401a407036505c5a2d60449274593865de3374";
RS[2] = "003122e976bac378c06ec95fd73290b067e7ff022d23493c40663ec9"
        "b99eb4220146a282c7a34f98a9a4fa38ed3f48ca2c7983cde2d3235f";
SHA[2] = MD_SHA224;
//Result = P (0 )
Msg[3] = "e9859a4fb2fe008ef14e8eb68dd00e06eb458483e54c3206385faabcc036f6e5aa5e0f28c0fb8a6cc345a0842e4cfb3240e9880d40665ddb75e893e9148cd0c11667f6abcbab2abfa63dbbc32dceba439a36bbefb12a5b242bda3ed58b7f00100fa4e0f8012f7d17d3e4d3210f0685817cd5584de4ae43655d9389bd70ace150";
Q[3]  = "7f9789c729355516588a5c75cb2cbcf85a14c35e14a5d03b4ef920d7"
        "49e95c49e62dd20f02ed16594f35ebf3415ed50e6efdc0c548101a9d";
RS[3] = "3c7b664413c2a0e4682a9d1c88243a96196fbd03f72cb873b9bee8b9"
        "8f7f81ee9d3a2660ab1d666bac6cc434143ca9b04ff638ca7b4aa1ea";
SHA[3] = MD_SHA224;
//Result = P (0 )
Msg[4] = "c8b10d4e5a1f5f6a3c0f4c15dc2dc84f0f36b219076e27bae6d26e3b4a414473186472ec793527bb8704f69285b96eaf9473085060603584bca5f1fce4e909203dcf0eb50cf05adaf89804c420e91d1226d9449bebf2e9b3ea7cb23bd094a0bb04b579789c800f58831489d25179db015d751e470c0b21c7ae03fc0e4a949970";
Q[4]  = "34c5ff3de565b85bfdd9f0a8b3fb0d46f924c57b276bcc830a1ed580"
        "609d22200ef38b410da77f7a8ff2f58448188042978fd9ae1b2b4477";
RS[4] = "f0138024fe0516738f3bd0e0fec10defaca8c3b89c161a77489cf2b7"
        "4ae0934266d9e3d64c2a12f546b132ba0f33ef50abc90e7ef5974805";
SHA[4] = MD_SHA256;
//Result = P (0 )
Msg[5] = "2346f531399ec2a809645ed85ef7026f9387afe2dc3daa89ace4954061dfa071d8e80676bd3a83af54920c3546edb91f72d0292b0c782062af5c52ae81d14babe9bfeb26de723bce79488495321ac0ac0e00f121384edfcf4e6482b866bd784425aee5112a3d7750b87e132b2e895c74aee182f82b73a36c5de5ce2c94064146";
Q[5]  = "a580f9a0cd15abff8e1e712f16b0fd4142d0d773af3c657abc06c2a6"
        "22c6286340dc072e64274209eda60503047700571caee64b4a2306c2";
RS[5] = "c6fae06274dc052e482102520b49d4ccc4cb7eb8a3ea41bd3680ddad"
        "50d66b75a2bbd0468be1f9e61bfda85b6329505b0134d60846cbe4b7";
SHA[5] = MD_SHA256;
//Result = P (0 )
Msg[6] = "3571050a4f57432393c59b90aa8ea1cc545952ae5ba682d26e53bee0c988e6dbe2be0ac9b125d6b80542f55aa0368f445efa81da7309883329250d37b3a383c6327e473a6f74c952883a0e5d7909611daa7d56f7e0065fa3b535d4415df7c11fe6105adf8a3e846167b1a61984f79cf6f02306bb1ca5a20f0934f7b16706544f";
Q[6]  = "3297edac34cb802df263f8d366f62a8b746c316adfb1c84a1c79c58c"
        "79fe82e87ef5879c12eda6adda198a662fd77afa6a1fb5696cb7da9d";
RS[6] = "9993defdcf83965723c03e04ce6c33b3972cef3c449cdf1bc69990db"
        "553b22a4164549f16aa1a928eee74548fc141fd3c16f213318965974";
SHA[6] = MD_SHA384;
//Result = P (0 )
Msg[7] = "b80b5bd76363deba633311a9a10e4fbfbe332291acf309de9e2c81c678184691e1d3af65af94f735edf655e7e6ee8668762bbb1b32d322fe6b63d27a6dbf726d7f9948ddd90096d0f64de96e5219f83126a98e32925845968863236661739618252a3deaf67558729cf1e35f260daba73d20a9589d3642df95e3c3cd50f07ae7";
Q[7]  = "4d0cab0dae88fa0cf53a2a6562934e0cf0271cc7fe54a30109a232be"
        "70835833cf9e1f989a18d419e7bee9eb5cef1fd145cf62c4411c372c";
RS[7] = "3b8548eab4dc123e236133d826f2badbde96f92249f456e33ccc9739"
        "c82b2e41b9e2b21594cc03b1c0de216f183403c6025e18bb29bff421";
SHA[7] = MD_SHA384;
//Result = P (0 )
Msg[8] = "cc4f7225790159324dc40a729ffb161f26bb624c4c8ef8495bdf79c1181ecafdb6d4cde37d08ab12667526ed89d582b60e9769be68569ed58dc3e801fe607c85126ea7d7922b31c99e4f3c61da6705ffb6ceeac796dcf1faedf02b7afdda3c1bb7dff99401524eda662b82c67ca77b20778c965f9e25e78cfcc9bbd28af36987";
Q[8]  = "c6a65011926eb64e02bf472d5ba37841d49cfb7f17a20fb9f59355de"
        "386ccb33d944fd7be6b8531863d2b6200cd602d300d7e7681537e53f";
RS[8] = "9e7c637a699dd52512faea847079f0ad41b20cd7a5461c36d01e857e"
        "dec6e9ef361de3f6ec7d87de3129eaac5fd0b43b5f7f58ce46c29173";
SHA[8] = MD_SHA512;
//Result = P (0 )
Msg[9] = "d9a8a63dab8ccd95e7cbb989d3ba034a0d4710b2c247acc7800ac00f49c60ced88d17e7165ba5a56658a57e4d957dd6c1da4faf0d76de9e2ac27688ac40bfca099aa304c068d0a9fd105a38210cc39549807e7a419a83878d48dba4985f62236439fa2ffa82e05fba5814a58b41d5922e0cca7b4f621559532dbf2a6122a97bb";
Q[9]  = "f10652c3c2c30a765564f5e393c6c202d436c81fc7d71b88857bd458"
        "42979ba5e6c8cd044e262c73e6aa918d8c3e0e08e4bf98ec2d5c6f57";
RS[9] = "072e0b130267d8e124dda2d0604f4c575ef4007628fa61f66bcd8f07"
        "6276475fccda3bee2af7816c7b3ec222e408cec36d0409e672af23b5";
SHA[9] = MD_SHA512;
//Result = P (0 )
        int curve_id = EC_NIST_P224;
        SignCtx sign_ctx = {0};
        sign_ctx.id_curve = EC_NIST_P224;
        sign_ctx.id_hash_alg = SHA[0];

        int size = 224>>BN_BIT_LOG;
        BNuint  rs[size<<1] BN_ALIGN;
        BNuint  qq[size<<1] BN_ALIGN;

        int res = 0;
        for(i=0;i<10;i++){
            if (i==0 || SHA[i]!=SHA[i-1]) {
                const MDigest* md = digest_select(SHA[i]);
                sign_ctx.id_hash_alg = SHA[i];
                printf("\n %s, %s\tsignature verify test", ecc_domain_params[curve_id].name, md->name);
            }
             int msg_len = strlen(Msg[i]);
    //        printf("\nlength=%d", msg_len);
            uint8_t *msg = malloc(msg_len);
            hex2bin(msg, Msg[i]);
            bn_hex2bin(&qq[0], size,  &Q[i][0]);
            bn_hex2bin(&qq[size], size,  &Q[i][size<<(BN_BYTE_LOG+1)]);
            bn_hex2bin(&rs[0], size, &RS[i][0]);
            bn_hex2bin(&rs[size], size, &RS[i][size<<(BN_BYTE_LOG+1)]);

            res += ecc_nist_signature_verify(&sign_ctx, (void*)qq, (void*)rs, msg, msg_len>>1);

//            res += ecc_nist_signature_verify2(Q[i], RS[i], msg, msg_len>>1, curve_id, SHA[i]);

            free(msg);
        }
        if (res!=0) return res;

//        return 0;
    }
    if (1 && ecc_curve_find (&curve, EC_NIST_P256))
    {
        ecc_curve_print(&curve);
//        curve.ctx->reduction = mp_reduction_nist_p256;
#if 0
        MPValue n; mp_alloc(curve.ctx, &n);
        char nn[] = "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
        mp_hex2bin(curve.ctx, &n, &nn[2]);
        if (nn[0]=='0' && nn[1] =='3') {
            mp_srtm(curve.ctx, n, n);

        }
#endif
        MPValue r; mp_alloc(curve.ctx, &r);
        MPValue s; mp_alloc(curve.ctx, &s);
        MPValue d; mp_alloc(curve.ctx, &d);
        MPValue q; mp_alloc(curve.ctx, &q);
        char *dd[] = {
            "0xc9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357",
            "0x710735c8388f48c684a97bd66751cc5f5a122d6b9a96a2dbe73662f78217446d",
            "0x78d5d8b7b3e2c16b3e37e7e63becd8ceff61e2ce618757f514620ada8a11f6e4",
            "0x2a61a0703860585fe17420c244e1de5a6ac8c25146b208ef88ad51ae34c8cb8c",
            "0x01b965b45ff386f28c121c077f1d7b2710acc6b0cb58d8662d549391dcf5a883",
            "0xfac92c13d374c53a085376fe4101618e1e181b5a63816a84a0648f3bdc24e519",
            "0xf257a192dde44227b3568008ff73bcf599a5c45b32ab523b5b21ca582fef5a0a",
            "0xadd67e57c42a3d28708f0235eb86885a4ea68e0d8cfd76eb46134c596522abfd",
            "0x4494860fd2c805c5c0d277e58f802cff6d731f76314eb1554142a637a9bc5538",
            "0xd40b07b1ea7b86d4709ef9dc634c61229feb71abd63dc7fc85ef46711a87b210",
            NULL
            };
        MPValue qx; mp_alloc(curve.ctx, &qx);
        MPValue qy; mp_alloc(curve.ctx, &qy);

        char ee[] = "0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5";
        char kk[] = "0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3";
        MPValue e; mp_alloc(curve.ctx, &e); mp_hex2bin(curve.ctx, &e, ee);
        MPValue k; mp_alloc(curve.ctx, &k); mp_hex2bin(curve.ctx, &k, kk);

        int i;
        for(i=0; i< 10 && dd[i]!=NULL; i++){
            mp_hex2bin(curve.ctx, &d, dd[i]);
            printf("\ni=%d\nd=    0x", i);
            bn_print (d.value, curve.ctx->size);

            ecc_public_key(qx.value, qy.value, d.value, &curve);
            printf("\nQ.x=  0x"); bn_print (qx.value, curve.ctx->size);
            printf("\nQ.y=  0x"); bn_print (qy.value, curve.ctx->size);
            if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
                printf("\n public key verifyed");
            else return(1);
            ecc_nist_sign  (r.value, s.value, d.value, k.value, e.value, &curve);
            if (ecc_nist_verify (r.value, s.value, e.value, qx.value, qy.value, &curve)
            &&  ecc_nist_verify2(r.value, s.value, e.value, d.value, &curve)){
                printf("\n OK");
            } else return(1);
        }

if (0) {
        int i;
        uint64_t start, end;
        start = g_get_real_time_();
        for(i=0;i<1000;i++){
            ecc_nist_sign  (r.value, s.value, d.value, k.value, e.value, &curve);
        }
        end = g_get_real_time_();
        printf("\nNIST P-256 time = %1.3f us , sign\t= %1.1f per s\n", (double)(end-start)/i, (double)i*1000000/(end-start+1));
        start = g_get_real_time_();
        for(i=0;i<1000;i++){
            ecc_nist_verify (r.value, s.value, e.value, qx.value, qy.value, &curve);
        }
        end = g_get_real_time_();
        printf("\nNIST P-256 time = %1.3f us , verify\t= %1.1f per s\n", (double)(end-start)/i, (double)i*1000000/(end-start+1));

        for(i=0;i<1000;i++){
            mp_addm(curve.ctx, k.value, k.value, curve.b);
            mp_subm(curve.ctx, d.value, d.value, curve.G.x);
            ecc_nist_sign  (r.value, s.value, d.value, k.value, e.value, &curve);
            ecc_public_key (qx.value, qy.value, d.value, &curve);
            if (!ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
                return(1);
            if (!ecc_nist_verify2(r.value, s.value, e.value, d.value, &curve))
                return 1;
            if (!ecc_nist_verify (r.value, s.value, e.value, qx.value, qy.value, &curve)) {
                printf("cnt= %d\n", i);
                return 1;
            }
        }
        printf("\nNIST P-256 OK\n");

        //return 0;
}


        mp_free1(curve.ctx, &k);
        mp_free1(curve.ctx, &e);
        mp_free1(curve.ctx, &qy);
        mp_free1(curve.ctx, &qx);

        mp_free1(curve.ctx, &q);
        mp_free1(curve.ctx, &d);
        mp_free1(curve.ctx, &s);
        mp_free1(curve.ctx, &r);
        ecc_curve_free (&curve);



char* Msg[10],*Q[10],*RS[10];
int SHA[10];
        Msg[0] = "e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3";
        Q[0]  = "e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c"
                "970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927";
        RS[0] = "bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f"
                "17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c";
        SHA[0]=MD_SHA256;

        Msg[1] = "73c5f6a67456ae48209b5f85d1e7de7758bf235300c6ae2bdceb1dcb27a7730fb68c950b7fcada0ecc4661d3578230f225a875e69aaa17f1e71c6be5c831f22663bac63d0c7a9635edb0043ff8c6f26470f02a7bc56556f1437f06dfa27b487a6c4290d8bad38d4879b334e341ba092dde4e4ae694a9c09302e2dbf443581c08";
        Q[1]  = "e0fc6a6f50e1c57475673ee54e3a57f9a49f3328e743bf52f335e3eeaa3d2864"
                "7f59d689c91e463607d9194d99faf316e25432870816dde63f5d4b373f12f22a";
        RS[1] = "1d75830cd36f4c9aa181b2c4221e87f176b7f05b7c87824e82e396c88315c407"
                "cb2acb01dac96efc53a32d4a0d85d0c2e48955214783ecf50a4f0414a319c05a";
        SHA[1]=MD_SHA256;

        Msg[2] = "485f372d91b762635d3fdbc6d80c5263fafd5f5908cab548a78a74ea6bf07657a12a61c8714dd41d6c670bdb700e315b483f83efc1821ab19e56810ff36aa8c462a1a0f56e269e121ef56efef1bb83c64941e5cf33894fabb821557f8cfe71cdb8e6015df4df41e85d8ae936d9cd54551045ed404e79a69abbd909071475c6cb";
        Q[2]  = "f3033d1e548d245b5e45ff1147db8cd44db8a1f2823c3c164125be88f9a982c2"
                "3c078f6cee2f50e95e8916aa9c4e93de3fdf9b045abac6f707cfcb22d065638e";
        RS[2] = "d4255db86a416a5a688de4e238071ef16e5f2a20e31b9490c03dee9ae6164c34"
                "4e0ac1e1a6725bf7c6bd207439b2d370c5f2dea1ff4decf1650ab84c7769efc0";
        SHA[2]=MD_SHA1;

        Msg[3] = "41e6ef0cae4eb07fbb5cc0d381029072974fb68f92a7dd5fe9279fcd86949ef5777e8e555ae5d90966de5decd00ec8894b2d8ae2b227789ef6a0697444b40bfd3e5880b97dd993131e2de92853a6f402cff1bbf1e0071d2c66c581ff1727d38ca486e0456dcda16d82a67b46a2f48786e902754016cf3c1df2152aea907de65c";
        Q[3]  = "2f71b932f770ba9daf7c1dd47444ab6cb8881f71a1c597e719845b15cb84ca35"
                "ab928625b40ec0738d0fc8dbc4df4a1f65d20bc0447b69cfa13bb20b95bb41d4";
        RS[3] = "63fca172bbca6197cd2802a9cb61d74c2b47cf35f6d35203e67ffbaa838be775"
                "e70ec283cd212df6ba3723e26b697501f112d7cf64e4f45185dae76055e09f1e";
        SHA[3]=MD_SHA1;

        Msg[4] = "3a9fd6b13337d9fd995d6e011e41c0bd24a7b068e8caa2f8ba10cb5b852e4f82c2d5176542a87668df5c6dda62ad47067e3bf7bf7f0defa57d996a1b40b22416bbb009532b5e29d995c74defdd3824847e7ce473353f9825331fbd0aed174f6ec2c8c4c7f05d7c66304f09745acee5708e31770d9edd997753c74dff1b0507df";
        Q[4]  = "843f6d83d777aac75b758d58c670f417c8deea8d339a440bb626114318c34f29"
                "83e0c70008521c8509044b724420463e3478e3c91874d424be44413d1ce555f3";
        RS[4] = "d08e9a5db411019d826b20ac889227ed245503a6d839494db1e8d7995a6b245b"
                "8d46a204054125d0dc776ab1055302ec4eb0f20b90bca6d205f21d3cefd29097";
        SHA[4]=MD_SHA224;

        Msg[5] = "5201328490b8f88a1bd31e16359e9a0770691313da5140575ca460d398f3d26ae4fa32fcc4aa522c9597333a20bbc0986235410f861522584a382b7c197a9f90a6742e18cd091f68106024b5beba0a67fa4699f7d0310c9c6d49ce37ce1e9653b3b77eb7a17a58676c2d9c765ec5077a7562d3c697cbc9a6f5e50e0819405afb";
        Q[5]  = "7f78a8fd880c509940e2b83de67c9ab553ab91489bae75cdc1d5b523b06ab7f5"
                "7786aee7032c373cdfad7d9ddb6fa09a026f6da30fd477ab014d30a289d542a1";
        RS[5] = "c93ada69db326f76b1362d610cb8bcc6e7ef1dc03d3d11367e153c0e39d5dc86"
                "d0c02c71b14ef7a4af4e23bd207ce98449f5d6e7e5b3ec8cbbca9549e97d379d";
        SHA[5]=MD_SHA224;

        Msg[6] = "6e2932153301a4eef680e6428929adae988c108d668a31ff55d0489947d75ff81a46bf89e84d6401f023be6e87688fbcd784d785ca846735524acb52d00452c84040a479e7cc330936441d93bbe722a9432a6e1db112b5c9403b10272cb1347fd619d463f7a9d223ad76fde06d8a6883500fb843235abff98e241bdfb5538c3e";
        Q[6]  = "9cb0cf69303dafc761d4e4687b4ecf039e6d34ab964af80810d8d558a4a8d6f7"
                "2d51233a1788920a86ee08a1962c79efa317fb7879e297dad2146db995fa1c78";
        RS[6] = "4b9f91e4285287261a1d1c923cf619cd52c175cfe7f1be60a5258c610348ba3d"
                "28c45f901d71c41b298638ec0d6a85d7fcb0c33bbfec5a9c810846b639289a84";
        SHA[6]=MD_SHA512;

        Msg[7] = "68f4b444e1cc2025e8ff55e8046ead735e6e317082edf7ce65e83573501cb92c408c1c1c6c4fcca6b96ad34224f17b20be471cc9f4f97f0a5b7bfae9558bdb2ecb6e452bb743603724273d9e8d2ca22afdda35c8a371b28153d772303e4a25dc4f28e9a6dc9635331450f5af290dfa3431c3c08b91d5c97284361c03ec78f1bc";
        Q[7]  = "f63afe99e1b5fc652782f86b59926af22e6072be93390fe41f541204f9c935d1"
                "f6e19ce5935e336183c21becf66596b8f559d2d02ee282aa87a7d6f936f7260c";
        RS[7] = "cef4831e4515c77ca062282614b54a11b7dc4057e6997685c2fbfa95b392bf72"
                "f20dc01bf38e1344ba675a22239d9893b3a3e33d9a403329a3d21650e9125b75";
        SHA[7]=MD_SHA512;

        int res = 0;
        int curve_id = EC_NIST_P256;
        SignCtx sign_ctx = {0};
        sign_ctx.id_curve = EC_NIST_P256;
        sign_ctx.id_hash_alg = SHA[0];

        int size = 256>>BN_BIT_LOG;
        BNuint  rs[size<<1] BN_ALIGN;
        BNuint  qq[size<<1] BN_ALIGN;

        for(i=0;i<8;i++){
            if (i==0 || SHA[i]!=SHA[i-1]){
                const MDigest* md = digest_select(SHA[i]);
                sign_ctx.id_hash_alg = SHA[i];
                printf("\n %s, %s \tsignature verify test", ecc_domain_params[curve_id].name, md->name);
            }
             int msg_len = strlen(Msg[i]);
    //        printf("\nlength=%d", msg_len);
            uint8_t *msg = malloc(msg_len);
            hex2bin(msg, Msg[i]);
            bn_hex2bin(&qq[0], size,  &Q[i][0]);
            bn_hex2bin(&qq[size], size,  &Q[i][size<<(BN_BYTE_LOG+1)]);
            bn_hex2bin(&rs[0], size, &RS[i][0]);
            bn_hex2bin(&rs[size], size, &RS[i][size<<(BN_BYTE_LOG+1)]);

            res += ecc_nist_signature_verify(&sign_ctx, (void*)qq, (void*)rs, msg, msg_len>>1);
//            res += ecc_nist_signature_verify2(Q[i], RS[i], msg, msg_len>>1, curve_id, SHA[i]);

            free(msg);
        }
        if (res!=0) return res;

    }
#endif // 0
    if (0 && ecc_curve_find (&curve, EC_SEC_P256k1))
    {
        ecc_curve_print(&curve);
//        curve.ctx->reduction = mp_reduction_nist_p256;
        MPValue r; mp_alloc(curve.ctx, &r);
        MPValue s; mp_alloc(curve.ctx, &s);
        MPValue d; mp_alloc(curve.ctx, &d);
        MPValue q; mp_alloc(curve.ctx, &q);
//		char d0[] = "0x2662ce3d49da33c0079171aa6ebce3ea2c04c12b19ff05459297cf06856de4e4";
//		mp_hex2bin(curve.ctx, &d, d0);
        char *dd[] = {
/*
    "2662ce3d49da33c0079171aa6ebce3ea2c04c12b19ff05459297cf06856de4e4"
pub:
    65:5b:74:f3:3d:38:02:06:15:88:69:b4:4c:d1:88:6f:7f:79:bc:34:3c:91:eb:e0:25:f9:5f:c4:53:4a:dd:82:
    b2:e7:c1:8f:ae:ed:33:29:29:fb:47:8e:98:b8:cd:f8:6b:9c:cb:4d:41:0f:ee:66:7b:f9:5e:36:1a:44:ce:3d
*/
/*
# openssl ecparam -genkey -name secp256k1 -out k.pem
# openssl ec -in k.pem -noout -text
*/
            "0x2662ce3d49da33c0079171aa6ebce3ea2c04c12b19ff05459297cf06856de4e4",
            "0xf062a7d410ec3b6fa012f1787a6f7cff35a0e4710a2fdc1757f1c0a3446d0605",
            "0x7d9ccde169245e08bc54e76870d5ea87aaf7ad8b18b23d225c1af42b7a247e39",
            "0x1b274c2cf22437a8fbeb9f22eeaac464b74f18014027ea4acbbefe56782bcc56",
            //"0x",
            NULL
            };
        MPValue qx; mp_alloc(curve.ctx, &qx);
        MPValue qy; mp_alloc(curve.ctx, &qy);
        MPValue e; mp_alloc(curve.ctx, &e);
        MPValue k; mp_alloc(curve.ctx, &k);


        char ee[] = "0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5";
        char kk[] = "0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3";
        mp_hex2bin(curve.ctx, &e, ee);
        mp_hex2bin(curve.ctx, &k, kk);


        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
                printf("\n G point verifyed");
#if 0
        ecc_public_key(qx.value, qy.value, d.value, &curve);
        printf("\nQ.x=  0x"); bn_print (qx.value, curve.ctx->size);
        printf("\nQ.y=  0x"); bn_print (qy.value, curve.ctx->size);
        if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
            printf("\n public key verifyed");
#endif


        int i;
        for(i=0; i< 100 && dd[i]!=NULL; i++){
            mp_hex2bin(curve.ctx, &d, dd[i]);
            printf("\ni=%d\nd=    0x", i);
            bn_print (d.value, curve.ctx->size);

            ecc_public_key(qx.value, qy.value, d.value, &curve);
            printf("\nQ.x=  0x"); bn_print (qx.value, curve.ctx->size);
            printf("\nQ.y=  0x"); bn_print (qy.value, curve.ctx->size);
            if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
                printf("\n public key verifyed");
            else return(1);
            ecc_nist_sign  (r.value, s.value, d.value, k.value, e.value, &curve);
            if (ecc_nist_verify (r.value, s.value, e.value, qx.value, qy.value, &curve)
            &&  ecc_nist_verify2(r.value, s.value, e.value, d.value, &curve)){
                printf("\n OK");
            } else return(1);
        }

if (1) {
        int i;
        uint64_t start, end;
        start = g_get_real_time_();
        for(i=0;i<1000;i++){
            ecc_nist_sign  (r.value, s.value, d.value, k.value, e.value, &curve);
        }
        end = g_get_real_time_();
        printf("\nSECp256k1 time = %1.3f us , sign\t= %1.1f per s\n", (double)(end-start)/i, (double)i*1000000/(end-start+1));
        start = g_get_real_time_();
        for(i=0;i<1000;i++){
            ecc_nist_verify (r.value, s.value, e.value, qx.value, qy.value, &curve);
        }
        end = g_get_real_time_();
        printf("\nSECp256k1 time = %1.3f us , verify\t= %1.1f per s\n", (double)(end-start)/i, (double)i*1000000/(end-start+1));

        for(i=0;i<1000;i++){
            mp_addm(curve.ctx, k.value, k.value, curve.b);
            mp_subm(curve.ctx, d.value, d.value, curve.G.x);
            ecc_nist_sign  (r.value, s.value, d.value, k.value, e.value, &curve);
            ecc_public_key (qx.value, qy.value, d.value, &curve);
            if (!ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
                return(1);
            if (!ecc_nist_verify2(r.value, s.value, e.value, d.value, &curve))
                return 1;
            if (!ecc_nist_verify (r.value, s.value, e.value, qx.value, qy.value, &curve)) {
                printf("cnt= %d\n", i);
                return 1;
            }
        }
        printf("\nSECp256k1 OK\n");

        //return 0;
}

        mp_free1(curve.ctx, &k);
        mp_free1(curve.ctx, &e);
        mp_free1(curve.ctx, &qy);
        mp_free1(curve.ctx, &qx);

        mp_free1(curve.ctx, &q);
        mp_free1(curve.ctx, &d);
        mp_free1(curve.ctx, &s);
        mp_free1(curve.ctx, &r);
        ecc_curve_free (&curve);
    }
    if (0 && ecc_curve_find (&curve, EC_NIST_P384))// "NIST P-384"))
    {
        ecc_curve_print(&curve);
//        curve.ctx->reduction = mp_reduction_nist_p384;
        MPValue r; mp_alloc(curve.ctx, &r);
        MPValue s; mp_alloc(curve.ctx, &s);

        MPValue d; mp_alloc(curve.ctx, &d);
        MPValue q; mp_alloc(curve.ctx, &q);
        char *dd[] = {
            "0x5394f7973ea868c52bf3ff8d8ceeb4db90a683653b12485d5f627c3ce5abd8978fc9673d14a71d925747931662493c37",
            "0x9b90d800abc37df43536e0dc321d43e6aeb5317fcb5118a0e827c8165b1cb05051ef12794b5278a293accbc0b1beb2c2",
            "0x9fdc866600017ee5be419ef11f13a537a403ed16743d16d43fba9938893fa9771c20b971faa4719744cb40af3b73bf84",
            "0xdc6dc5ed9ee57eb5e39878f97aeac359f8258b9c381fb1987abb061184013220a76d667fcf3a53088eae8da3f8d9b520",
            "0x0f4144cf327d6feae06091d4a8c710011ce32c987af1451fccc471bc3f482bc741368e88d04324c93924dcb3b5274b02",
            "0xc5099dab8c2e1914bc37331f288a8d35d55e6163a6553dbe6a4fbd60311478ff9502a0efa3f2ac5ee6705afc443bcd39",
            "0x86feaa8de26a91e4684c6f06689d4cf46ddc45ba27403a980107c0d31a5b675005fcbb7a07dc28ef9ee8d536252e0624",
            "0xf0d9c1fb64733c4e91e4129e4c0ca6879e25dafd0b583bc5d1d989664e592e52390494fd65bfff76b2a46fd7db23be47",
            "0x3512b88c012aee202b5122353c610be0ef2a0604bfec2a6dfee7f1a80395aba6368029c388d462c53c24b5ec25055bb4",
            "0x3a7b2a6a03c92154f4ef31dd257bd9d3397494da4c93dc033a1c7925a295ce12412797ac995191b665229ad6db881e6e",
            NULL
            };
        MPValue qx; mp_alloc(curve.ctx, &qx);
        MPValue qy; mp_alloc(curve.ctx, &qy);

        char ee[] = "0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5";
        char kk[] = "0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3";
        MPValue e; mp_alloc(curve.ctx, &e); mp_hex2bin(curve.ctx, &e, ee);
        MPValue k; mp_alloc(curve.ctx, &k); mp_hex2bin(curve.ctx, &k, kk);

        int i;
        for(i=0; i< 10 && dd[i]!=NULL; i++){
            mp_hex2bin(curve.ctx, &d, dd[i]);
            printf("\ni=%d\nd=    0x", i);
            bn_print (d.value, curve.ctx->size);

            ecc_public_key(qx.value, qy.value, d.value, &curve);
            printf("\nQ.x=  0x"); bn_print (qx.value, curve.ctx->size);
            printf("\nQ.y=  0x"); bn_print (qy.value, curve.ctx->size);
            if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
                printf("\n public key verifyed");
            else return(1);
            ecc_nist_sign  (r.value, s.value, d.value, k.value, e.value, &curve);
            if (ecc_nist_verify (r.value, s.value, e.value, qx.value, qy.value, &curve)
            &&  ecc_nist_verify2(r.value, s.value, e.value, d.value, &curve)){
                printf("\n OK");
            } else return(1);

        }

        mp_free1(curve.ctx, &qy);
        mp_free1(curve.ctx, &qx);

            mp_free1(curve.ctx, &k);
            mp_free1(curve.ctx, &e);
            mp_free1(curve.ctx, &d);
        mp_free1(curve.ctx, &q);
        mp_free1(curve.ctx, &s);
        mp_free1(curve.ctx, &r);
        ecc_curve_free (&curve);

        extern int ecc_test_p384();
//        if (ecc_test_p384()!=0)         return 1;
        printf("\nNIST P-384 OK\n");
    }
    if (0 && ecc_curve_find (&curve, EC_NIST_P521))
    {
        ecc_curve_print(&curve);
//        curve.ctx->reduction = mp_reduction_nist_p384;
        MPValue r; mp_alloc(curve.ctx, &r);
        MPValue s; mp_alloc(curve.ctx, &s);

        MPValue d; mp_alloc(curve.ctx, &d);
        MPValue q; mp_alloc(curve.ctx, &q);

        MPValue qx; mp_alloc(curve.ctx, &qx);
        MPValue qy; mp_alloc(curve.ctx, &qy);
        char dd[] = "0184258ea667ab99d09d4363b3f51384fc0acd2f3b66258ef31203ed30363fcda7661b6a817daaf831415a1f21cb1cda3a74cc1865f2ef40f683c14174ea72803cff";
//        char Qx[] = "019ee818048f86ada6db866b7e49a9b535750c3673cb61bbfe5585c2df263860fe4d8aa8f7486aed5ea2a4d733e346eaefa87ac515c78b9a986ee861584926ce4860";
//        char Qy[] = "01b6809c89c0aa7fb057a32acbb9ab4d7b06ba39dba8833b9b54424add2956e95fe48b7fbf60c3df5172bf386f2505f1e1bb2893da3b96d4f5ae78f2544881a238f7";
            mp_hex2bin(curve.ctx, &d, dd);
            printf("\nd=    0x");
            bn_print (d.value, curve.ctx->size);

        ecc_public_key(qx.value, qy.value, d.value, &curve);
            printf("\nQ.x=  0x"); bn_print (qx.value, curve.ctx->size);
            printf("\nQ.y=  0x"); bn_print (qy.value, curve.ctx->size);
            if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
                printf("\n public key verifyed");
            else return(1);

        mp_free1(curve.ctx, &qy);
        mp_free1(curve.ctx, &qx);

        mp_free1(curve.ctx, &q);
        mp_free1(curve.ctx, &d);
        mp_free1(curve.ctx, &s);
        mp_free1(curve.ctx, &r);
        ecc_curve_free (&curve);
        _Exit(521);
    }
    if (1 && ecc_curve_find (&curve, EC_GOST_TEST))// "1.2.643.2.2.35.0"))
    {
        ecc_curve_print(&curve);
//        curve.ctx->reduction = mp_reduction_gost_0;
//        curve.ctq->reduction = mp_reduction_gost_0_n;
        MPValue r; mp_alloc(curve.ctx, &r);
        MPValue s; mp_alloc(curve.ctx, &s);
        MPValue q; mp_alloc(curve.ctx, &q);
        mp_mulm(curve.ctx, r.value, curve.b, curve.G.y);

        printf("\n mulm 0x");
        bn_print (r.value, curve.ctx->size);
        mp_invm(curve.ctx, q.value, r.value);
        printf("\n invm 0x");
        bn_print (q.value, curve.ctx->size);

        MPValue d; mp_alloc(curve.ctx, &d);
        char *dd[] = {
            "0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28",
            NULL
            };
        MPValue qx; mp_alloc(curve.ctx, &qx);
        MPValue qy; mp_alloc(curve.ctx, &qy);

            mp_hex2bin(curve.ctx, &d, dd[0]);
            printf("\nd=    0x");
            bn_print (d.value, curve.ctx->size);

            ecc_public_key(qx.value, qy.value, d.value, &curve);
            printf("\nQ.x=  0x");  bn_print (qx.value, curve.ctx->size);
            printf("\nQ.y=  0x");  bn_print (qy.value, curve.ctx->size);
            if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
                printf("\n public key verifyed");
            else return(1);


        char ee[] = "0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5";
        char kk[] = "0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3";
        MPValue e; mp_alloc(curve.ctx, &e); mp_hex2bin(curve.ctx, &e, ee);
        MPValue k; mp_alloc(curve.ctx, &k); mp_hex2bin(curve.ctx, &k, kk);

            ecc_gost_sign  (r.value, s.value, d.value, k.value, e.value, &curve);
        printf("\nr=  0x"); bn_print (r.value, curve.ctx->size);
        printf("\ns=  0x"); bn_print (s.value, curve.ctx->size);
            if (ecc_gost_verify2(r.value, s.value, e.value, d.value, &curve))
                printf ("\n signature verified2");
            else return (2);
            if (ecc_gost_verify (r.value, s.value, e.value, qx.value, qy.value, &curve))
                printf ("\n signature verified");
            else return (3);

        mp_free1(curve.ctx, &k);
        mp_free1(curve.ctx, &e);
        mp_free1(curve.ctx, &qy);
        mp_free1(curve.ctx, &qx);
        mp_free1(curve.ctx, &d);
        mp_free1(curve.ctx, &q);
        mp_free1(curve.ctx, &s);
        mp_free1(curve.ctx, &r);
        ecc_curve_free (&curve);
        //_Exit(33);
    }
    if (1 && ecc_curve_find (&curve, EC_GOST_CRYPTO_PRO_A))// "1.2.643.2.2.36.0"))
    {
        ecc_curve_print(&curve);
//        curve.ctx->reduction = mp_reduction_gost_A;
//        curve.ctq->reduction = mp_reduction_gost_A_n;
/*        MPValue r; mp_alloc(curve.ctx, &r);
        mp_mulm(curve.ctx, &r, &curve.n, &curve.G.y);

        printf("\n mulm 0x");
        bn_print (r.value, curve.ctx->size);
*/
/* openssl genpkey -engine gost -algorithm GOST2001 -text -pkeyopt paramset:A */
        char *dd[] = {
            "0x6D7BA421AD3D27889F0E8700B71760FEF803058F248557F740DE9036872D464A",
/*Public key:
   X:41F70ED2FE1EBE456A34A67C67D21300DB8C830D9E2CCB2DF1C43ECCB50D41F1
   Y:945133EFDA864A2DD235EC52D6C693888DAC95F5714DD216F49CC5B3FF0A2DAD*/
            "0xE28A12CBC0C25568F3ED6A68107050FE1E5536731128221B87E3AA36753C5CBA",
/*Public key:
   X:6E2A390F17A0D5FE25309F1065F8D45FEDFE77D4F333CCDCE32688BDB7B75154
   Y:C44DABE83B4573112F1CA0407BF0DC45BDB4291795B977D5411D43001833C8CB*/
            "0xA5B23B1F1CE6AB99C0D7BDC213A36908E91AB6DB89B41F38A08B101DE591FA6C",
/*Public key:
   X:DB78E8767DB18EFC66E9DBC6DCBCF46B0BEFBB57499016D35CD445D425460F71
   Y:6738CF1752F1C4F73C9451011B67EDF11ED90C6DA411386AC16E0AC7030F6F32*/
            "0x3DF627CC0CF5C83B5AB715C45A9E9DC21DBD16820843B8154DC6B59FAD306864",
/*Public key:
   X:A92A17F5B0AD64E66A5D3492C70CE98528089DA7B121671E49A9FD96C18CF22C
   Y:BE081F432EC18FCA29393DFE6FE6BFE11A023EDB4BD85A799D17A23880A43A13*/
            "0xDF262D5B89E66D753CB6060979DB272434B3BE2B3EB92C9F88CFDBB82F65E9E3",
/*Public key:
   X:47BE95D527586C8229ECA48FAFB2B5A60B370F8A6E0BB4B2D0FAD169FBFAE229
   Y:A820C899404CB50E3F35AF92AA7BA47FEF948E0D585B2D8D022DEEE10D6AD4F3*/
            "0x79EBBA6B1D0C9D67CD706865B8E8074729F9D8D69B1994163C8551F4CCE5B245",
/*Public key:
   X:7C9C62D50E1226ECC6299A7011F0FE968AE3BCF92429225933669B5FCB202168
   Y:6D2F9FFF9A95193D5A0CFBB440CD1F526D215B6980D569453397BC44DCF2ECC3*/
            "0x74BF0DB0AF736AFD6B1317D853B10939B86B696AED2319D03E81A1B3F448BCFB",
/*Public key:
   X:AECBA0A4B272DD1AFD39E7DA201E863788B47D98702D0CE5216EC42481DD7814
   Y:25D27D70B7EDA29A29236268F5954B0D17347A3E16AFAC009D73394EE0E8E827*/
            "0x1774A0FB340407FD9DE0F428C05F8E0E9175373F0E0F5C9F7A52FC2EE547DF6E",
/*Public key:
   X:F39F9563A9AAC7BBC8A76976B9C9B5211EDD9FA3FFBFC1000DAC1DBCAD5586B5
   Y:BBA41F074383B185CCF5515DAEFCE0C3B53FD3D816B28AA31745BEAB2A4D7BF*/
            "0x681EFB65E2F17AAC1DE347E65C1E2243CE1D1728AC28EA1562ADA22537FA693A",
/*Public key:
   X:1D924C90C1FCFA286DCAEB7C7277F94658655668837FE154F2C7489CE156D7FA
   Y:82DE23A189D4C5001E0D02BE5735CC61A71B1F3F8328BDC15B87307498588896*/
            "0x26848E7875F21D567910E3E3452EAAC845B998B64975E42970528B5EE9583247",
/*Public key:
   X:79DD55BF3244FEE22E8AC595403541FC9FEE851D597DCE85534D7482D0F61639
   Y:16520AD9A27777CE9A2D3AEA37E4CA5F75116B46070DBD34D5D9FEB277275077*/

            NULL
        };
        char ee[] = "29 8a 05 5f 47 d5 99 22 1f 61 ae 61 70 a9 0a 84 46 ba 82 72 d6 d1 8b 97 21 a2 86 ee 80 ee ec 94";
//        char ee[] = "47 98 B1 30 C0 4B 8A 75 24 77 DC CE 9C E1 2A 17 14 FC 0E E6 DA 26 EA 91 1B 7A B2 37 01 EA 52 B4";
        char rr[] = "49 53 A4 16 20 ED 87 1E 2F 96 18 A3 9B C8 21 A1 21 2F 60 4E 86 04 FE 0C 6D 27 AC A3 0E 95 10 61";
        char ss[] = "07 8C F4 7B D5 24 14 67 8F BE 74 93 97 A6 4C 4D 41 FD 8F BA E6 01 94 41 B2 F8 52 B1 76 11 D6 F9";
        char QX[] = "68 27 4C 33 59 4D 59 27 5D 1D 29 83 ED AA D1 F0 FD 16 D2 F5 4F BC 9C D3 B6 A0 8F 55 55 2F F8 25";
        char QY[] = "2B 1A 08 35 E9 DF 00 FD 68 FA B6 54 E4 33 95 46 F3 30 57 6A FA A9 67 7F B2 39 B5 D6 FE 61 D9 1A";

        MPValue d;  mp_alloc(curve.ctx, &d);
        MPValue qx; mp_alloc(curve.ctx, &qx);
        MPValue qy; mp_alloc(curve.ctx, &qy);
        MPValue r;  mp_alloc(curve.ctx, &r);
        MPValue q;  mp_alloc(curve.ctx, &q);

        int i;
        for (i=0; i<10 && dd[i]!=NULL;i++) {
            mp_hex2bin(curve.ctx, &d, dd[i]); //mp_revert(curve.ctx, &d);

            ecc_public_key(qx.value, qy.value, d.value, &curve);
            printf("\ni = %d", i);
            printf("\nd =   0x"); bn_print ( d.value, curve.ctx->size);
            printf("\nQ.x=  0x"); bn_print (qx.value, curve.ctx->size);
            printf("\nQ.y=  0x"); bn_print (qy.value, curve.ctx->size);
            if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
                printf("\n public key verifyed");
            else return(1);

            //mp_invm(curve.ctq, q.value, d.value);
            mp_divm(curve.ctq, q.value, NULL, d.value);
            mp_mulm(curve.ctq, r.value, q.value, d.value);
            mp_modp(curve.ctq, r.value, r.value);
            if (bn_is_one(r.value, curve.ctq->size)) printf("\n OK");
            else return(1);
        }
/// в сертификате ключи записываются задом наперед
        mp_hex2bin(curve.ctx, &qx, QX); mp_revert(curve.ctx, &qx);
        mp_hex2bin(curve.ctx, &qy, QY); mp_revert(curve.ctx, &qy);
        MPValue e; mp_alloc(curve.ctx, &e); mp_hex2bin(curve.ctx, &e, ee); //mp_revert(curve.ctx, &e);
        mp_hex2bin(curve.ctx, &r, rr); //mp_revert(curve.ctx, &r);
        MPValue s; mp_alloc(curve.ctx, &s); mp_hex2bin(curve.ctx, &s, ss); //mp_revert(curve.ctx, &s);

        printf("\ne =   0x");  bn_print (e.value, curve.ctx->size);
        printf("\nQ.x=  0x");  bn_print (qx.value, curve.ctx->size);
        printf("\nQ.y=  0x");  bn_print (qy.value, curve.ctx->size);

        if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
            printf("\n public key verifyed");
        else return (1);
        if (ecc_gost_verify(r.value, s.value, e.value, qx.value, qy.value, &curve))
            printf("\n signature verifyed");
        else //return (1);
            printf("\n signature fail..!!!!!!!!!!!!!!!!!!!!!!");


/* пример из RFC 4491

 -----BEGIN CERTIFICATE-----
MIIB0DCCAX8CECv1xh7CEb0Xx9zUYma0LiEwCAYGKoUDAgIDMG0xHzAdBgNVBAMM
Fkdvc3RSMzQxMC0yMDAxIGV4YW1wbGUxEjAQBgNVBAoMCUNyeXB0b1BybzELMAkG
A1UEBhMCUlUxKTAnBgkqhkiG9w0BCQEWGkdvc3RSMzQxMC0yMDAxQGV4YW1wbGUu
Y29tMB4XDTA1MDgxNjE0MTgyMFoXDTE1MDgxNjE0MTgyMFowbTEfMB0GA1UEAwwW
R29zdFIzNDEwLTIwMDEgZXhhbXBsZTESMBAGA1UECgwJQ3J5cHRvUHJvMQswCQYD
VQQGEwJSVTEpMCcGCSqGSIb3DQEJARYaR29zdFIzNDEwLTIwMDFAZXhhbXBsZS5j
b20wYzAcBgYqhQMCAhMwEgYHKoUDAgIkAAYHKoUDAgIeAQNDAARAhJVodWACGkB1
CM0TjDGJLP3lBQN6Q1z0bSsP508yfleP68wWuZWIA9CafIWuD+SN6qa7flbHy7Df
D2a8yuoaYDAIBgYqhQMCAgMDQQA8L8kJRLcnqeyn1en7U23Sw6pkfEQu3u0xFkVP
vFQ/3cHeF26NG+xxtZPz3TaTVXdoiYkXYiD02rEx1bUcM97i
 -----END CERTIFICATE-----

*/
        printf ("\nRFC 4491");
        char e0[] = "0xF0874FBB3946F299A22AAB3919C31426C5DB236C4258EA9496E97429EA670ECE";
        char d0[] = "0x0B293BE050D0082BDAE785631A6BAB68F35B42786D6DDA56AFAF169891040F77";
        char r0[] = "0xC1DE176E8D1BEC71B593F3DD36935577688989176220F4DAB131D5B51C33DEE2";
        char s0[] = "0x3C2FC90944B727A9ECA7D5E9FB536DD2C3AA647C442EDEED3116454FBC543FDD";
        char x0[] = "0x577E324FE70F2B6DF45C437A0305E5FD2C89318C13CD0875401A026075689584";
        char y0[] = "0x601AEACABC660FDFB0CBC7567EBBA6EA8DE40FAE857C9AD0038895B916CCEB8F";
        mp_hex2bin(curve.ctx, &qx, x0);
        mp_hex2bin(curve.ctx, &qy, y0);
        mp_hex2bin(curve.ctx, &r,  r0);
        mp_hex2bin(curve.ctx, &s,  s0);
        mp_hex2bin(curve.ctx, &d,  d0);
        mp_hex2bin(curve.ctx, &e, e0);
        printf("\nQ.x=  0x");  bn_print (qx.value, curve.ctx->size);
        printf("\nQ.y=  0x");  bn_print (qy.value, curve.ctx->size);
        if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
            printf("\n public key verifyed");
        if (ecc_gost_verify (r.value, s.value, e.value, qx.value, qy.value, &curve)
        &&  ecc_gost_verify2(r.value, s.value, e.value, d.value, &curve)
            )
            printf("\n signature verifyed");

if (0) {// измерение быстродействия
        uint64_t start, end;
        MPValue k,d, r,s, e;
        BNuint vv[5][curve.ctx->asize] BN_ALIGN;
        k.value = vv[0],d.value = vv[1],
        r.value = vv[2],s.value = vv[3],
        e.value = vv[4];
        mp_hex2bin(curve.ctx, &k,  x0);
        mp_hex2bin(curve.ctx, &d,  d0);
        ecc_gen_key(d.value, curve.ctq);
//        while(!ecc_gen_key(k.value, curve.ctq));
        start = g_get_real_time_();
        for(i=0;i<2000;i++){
            ecc_gost_sign  (r.value, s.value, d.value, k.value, e.value, &curve);
            if (1 && !
                ecc_gost_verify2 (r.value, s.value, e.value, d.value, &curve)
                )  return (i);
        }
        end = g_get_real_time_();
        printf("\nGOST-A time = %1.3f us, sign = %1.1f per sec\n", (double)(end-start)/i, (double)i*1000000/(end-start+1));
        ecc_public_key (qx.value, qy.value, d.value, &curve);
        start = g_get_real_time_();
        for(i=0;i<2000;i++){
            ecc_gost_sign  (r.value, s.value, d.value, k.value, e.value, &curve);
            if (!
                ecc_gost_verify (r.value, s.value, e.value, qx.value, qy.value, &curve)
                )  return (i);
        }
        end = g_get_real_time_();
        printf("\nGOST-A time = %1.3f us, verify = %1.1f per sec\n", (double)(end-start)/i, (double)i*1000000/(end-start+1));
        for(i=0;i<1000;i++){
            mp_addm(curve.ctx, k.value, k.value, curve.b);
            mp_subm(curve.ctx, d.value, d.value, curve.G.x);
            ecc_gost_sign  (r.value, s.value, d.value, k.value, e.value, &curve);
            ecc_public_key (qx.value, qy.value, d.value, &curve);
            if (!ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
                return(1);
            if (!ecc_gost_verify2(r.value, s.value, e.value, d.value, &curve))
                return 1;
            if (!ecc_gost_verify (r.value, s.value, e.value, qx.value, qy.value, &curve)) {
                printf("cnt= %d\n", i);
                return 1;
            }
        }
        printf("\nGOST A-256 OK\n");

//        return 0;
}

/*корневой сертификат
public key:
 X: 0x942DB972B6A885FA698E6E7BB600B1C7A3EF4310186C9A67FBE548BCB149F08B
 Y: 0xE13103463B61BE21057652DF675154B2B837FC41C6B4C7F415DA9CD24F6B8554

сертификат:
hash 0x81A6A77EC4D581F12D8F8A2687B520DD185789F1B8A92E0492664460637935DE
подпись
 r: 0xE1A29C9A2BD9D2BB1FDBFA100CCEC41BB61C7A693F39C15CEB1B44D5B019780C
 s: 0xB839C8B54946A56AC103D3646266B221A579EEF35F62C3FC9E7C4E08F598FF64
*/
        printf ("\nmy");
/* удостоверяющий центр ГНИВЦ ФТС */
        char x1[] = "0x942DB972B6A885FA698E6E7BB600B1C7A3EF4310186C9A67FBE548BCB149F08B";
        char y1[] = "0xE13103463B61BE21057652DF675154B2B837FC41C6B4C7F415DA9CD24F6B8554";
/* сертификаты участников ВЭД */
        char e1[] = "0x81A6A77EC4D581F12D8F8A2687B520DD185789F1B8A92E0492664460637935DE";
        char r1[] = "0xE1A29C9A2BD9D2BB1FDBFA100CCEC41BB61C7A693F39C15CEB1B44D5B019780C";
        char s1[] = "0xB839C8B54946A56AC103D3646266B221A579EEF35F62C3FC9E7C4E08F598FF64";
        char e2[] = "0x5A7A2C5B703B8DC96224441057C71C79C13EA28B6B91E6369ECC300692188B11";
        char r2[] = "0x2AD42DB67D349DA9D7A104E86A77934196C7EBAA5C843C32E4B5619FCC0C1546";
        char s2[] = "0x9C35BB178DEF73E0D25C4692E95996204A66F3E599F0AF0B774193E20EC7ECA5";
        char e3[] = "0x61114A00C57C3E2855DACAE182F84171DE144668261CE11586B7806538C02659";
        char r3[] = "0xF982B8E3984CABED617975911547FB9CACB2494D3F846D3E2094F3E54A999531";
        char s3[] = "0x562AF03644A09DDDF285F8145176EA6F51825C011569941A9F6808630AD955D3";
/* самоподписанный сертификат корневого удостоверяющего центра ГНИВЦ ФТС */
        char e4[] = "0x7642523A570DC67BFF2725D1B1576F452D1641071C21E74FEC2922E0BC130020";
        char x4[] = "0xE1CC73D250C2D75016BC865F28C56EAEB0537FF376186C07DA2166E1DE7A0D26";
        char y4[] = "0x99F6F5F1373574901F99D34460E7506EA876C07C5CB281FBF8DAA466661CB707";
        char r4[] = "0x55B2306D42840BAFE70D8AA391B38DB044027732C43910D00C2CC5BCE5DCC231";
        char s4[] = "0xEB452DD1E0324AB237EBD4A6825A664DDFE3A8919E74A1E09369A8BAEFC19E54";
/* пустой CMS */
        char e5[] = "0xB1767B43FAD0792E70262626C9023DF34F8D04B7718BC88C6FADB872ED2959A3";
        char x5[] = "0x9B89DE50B07C508C0A1180CAEEE85692B0CD727AD98E8BF79E6BC725855C90C0";
        char y5[] = "0x99CB26570FC3B4591092BE3C21A530F46FF5F3FB7E34EF36CA1DB7F8527CE42B";
        char r5[] = "0x99740DC58FA0AA44463F43956E61FFB533F5A241246AC043B95E59927FC52AD9";
        char s5[] = "0x1A190B1E64D55EC2FC016F9497B52275661597477EE3ABC60AB463D713E60636";

        mp_hex2bin(curve.ctx, &qx, x1);
        mp_hex2bin(curve.ctx, &qy, y1);
        mp_hex2bin(curve.ctx, &e,  e1);
        mp_hex2bin(curve.ctx, &r,  r1);
        mp_hex2bin(curve.ctx, &s,  s1);
        mp_revert(curve.ctx, &e);

        printf("\nQ.x=  0x");  bn_print (qx.value, curve.ctx->size);
        printf("\nQ.y=  0x");  bn_print (qy.value, curve.ctx->size);
        if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
            printf("\n public key verifyed");
        if (ecc_gost_verify (r.value, s.value, e.value, qx.value, qy.value, &curve))
            printf("\n signature 1 verifyed");
        else return (1);

        mp_hex2bin(curve.ctx, &e,  e2);
        mp_hex2bin(curve.ctx, &r,  r2);
        mp_hex2bin(curve.ctx, &s,  s2);
        mp_revert(curve.ctx, &e);

        if (ecc_gost_verify (r.value, s.value, e.value, qx.value, qy.value, &curve))
            printf("\n signature 2 verifyed");
        else return (1);

        mp_hex2bin(curve.ctx, &e,  e3);
        mp_hex2bin(curve.ctx, &r,  r3);
        mp_hex2bin(curve.ctx, &s,  s3);
        mp_revert(curve.ctx, &e);

        if (ecc_gost_verify (r.value, s.value, e.value, qx.value, qy.value, &curve))
            printf("\n signature 3 verifyed");
        else return (1);

        mp_hex2bin(curve.ctx, &qx, x4);
        mp_hex2bin(curve.ctx, &qy, y4);
        mp_hex2bin(curve.ctx, &e,  e4);
        mp_hex2bin(curve.ctx, &r,  r4);
        mp_hex2bin(curve.ctx, &s,  s4);
        mp_revert(curve.ctx, &e);

        printf("\nQ.x=  0x");  bn_print (qx.value, curve.ctx->size);
        printf("\nQ.y=  0x");  bn_print (qy.value, curve.ctx->size);
        if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
            printf("\npublic key 4 verifyed");
        if (ecc_gost_verify (r.value, s.value, e.value, qx.value, qy.value, &curve))
            printf("\n signature 4 verifyed");
        else return (1);

        mp_hex2bin(curve.ctx, &qx, x5);
        mp_hex2bin(curve.ctx, &qy, y5);
        mp_hex2bin(curve.ctx, &e,  e5);
        mp_hex2bin(curve.ctx, &r,  r5);
        mp_hex2bin(curve.ctx, &s,  s5);
        mp_revert(curve.ctx, &e);

        printf("\nQ.x=  0x");  bn_print (qx.value, curve.ctx->size);
        printf("\nQ.y=  0x");  bn_print (qy.value, curve.ctx->size);
        if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
            printf("\npublic key 5 verifyed");
        if (ecc_gost_verify (r.value, s.value, e.value, qx.value, qy.value, &curve))
            printf("\n signature 5 verifyed");
        else return (1);
        mp_free1(curve.ctx, &s);
        mp_free1(curve.ctx, &q);
        mp_free1(curve.ctx, &r);
        mp_free1(curve.ctx, &e);
        mp_free1(curve.ctx, &qy);
        mp_free1(curve.ctx, &qx);
        mp_free1(curve.ctx, &d);

        ecc_curve_free (&curve);
            printf("\n done");
    }
    if (1 && ecc_curve_find (&curve, EC_GOST_CRYPTO_PRO_B))// "1.2.643.2.2.35.2"))
    {
        ecc_curve_print(&curve);
//        curve.ctx->reduction = mp_reduction_gost_B;
//        curve.ctq->reduction = mp_reduction_gost_B_n;
        char * dd[] = {
            "0x4DF89CB65CA267681D2DC0CB7B19DA28486894C277575EA5F95DE8B296588B27",
/*Public key:
   X:768E7CC49FCBACED1FB317FD2D0E991A33F35BB5912E42CF80EEFADC853E8D7E
   Y:2CBA461B8871994854AAB69823308544ACDE545CCE42FD07A73CC67846534BF4*/
            "0x3EF418B67B58B05D61C22B1B28A93627B4B43DF3F733F00B57A4FD41A0B79599",
/*Public key:
   X:72B8D48DD80495741512740CD750F463D967B63CF52BE24D57610C3C166FA946
   Y:4EB081EF386D4075323C1B6C8243E7F52270C8BD8171BB6A21923BA465E47588*/
            "0x235F071AFBE2EDB2F404A37AF14941EB93528D4E0CC743ECAE0DC0875DBB1842",
/*Public key:
   X:7D3B6C4FA5F60C5D5E2CD93D66139B075B6EE86FCA666758A7119D424EEF5093
   Y:5D1C8FD79D461C8D8570C9C3F001CFCEF091440C60660ECFC7F4A9D67A416D98*/
            "0x6C5DCAAABA619FF81459212581F7FA2F31F46F316713D1174944E2C90D3A9799",
/*Public key:
   X:2760EB0AB5930B56A19613F0368325889C54121AC496CBCC1B33A200BBFA17EA
   Y:56E11506A0F5C6B516CDC06D96995E3F0771AC29729815C20382FEEEEDF9E219*/
            "0x62F9CD5AD36153961E626136412FE1A13B7313A0294E345F1474E4CF9CD1A6A0",
/*Public key:
   X:25AC0D475420797A0A9F29B662CE07FC0C9D3C89DADB85B49CB6C2272D11CC21
   Y:7F83735D65A60DFD695F329C919CF834DF3CBFB8AB2AF99818EC5988A5EFFCEB*/
            "0x722A8467933B35F9C903CF10F4073F35EBC2FA2FE4C032576A3C4B0B4F2B419A",
/*Public key:
   X:6EA8B18B19FDE3F2470F9E16ADC7DBCF17F10B13B49EAF04058059680973BEF9
   Y:6B5D7048C442F36237D6031D1F0FD921BA05DEB653B0824C6B94C47B430D54A1*/
            "0x6B9894F2D00A27AD7B678A43FF54BB2CDB9A441E70A375DD77B332ABD75C8521",
/*Public key:
   X:6C64E34AF9D1AFF3543733451E16BA0583381B9E6677BA0C22DAA1D4F0F17D81
   Y:6D0B7268D9C52D6F0B2CB9B76503E2107EA66BB471EDDAFE36F0833B7FAB1B3A*/
            "0x28D7C793F6B0678AB65870E4E6D675DA6F77ACCDA148BCD4F08773D91CA5F069",
/*Public key:
   X:25E602C9451941B2271C0FD2F6A012E367D045F49836FEBE280316E2CED2A6C3
   Y:446735329352504A40C76026647C767A61A4B10EAD4214A5AF8866904E60C352*/
            "0x57D7F9A4C80621CCCBDF5AD88EAD94F66DD6F76A506B856DF93B04334FB15925",
/*Public key:
   X:D84C7BDA801DC012D3C9EEA1B71DA874C644037BBF5ACC6D9A0FB35D92F5559
   Y:61E156858D3389970C70379E4BC34FC054C40DC13897D278ACB2723BC016FEF0*/
            "0x4BF319C5FA152E96D7DB782BD38C59AECBF4615483372665FE7EF6EB1685E00D",
/*Public key:
   X:552C76DE4506A65034F313193FE02AC4537B5B8151A93A8117B3B448DB7FCA95
   Y:28E1D5C2AF935C476AB3AFD5FAB531C4B708D0BA651EA4373EC67AE42896FAC1*/
            NULL
        };
        MPValue d;  mp_alloc(curve.ctx, &d);
        MPValue q;  mp_alloc(curve.ctx, &q);
        MPValue r;  mp_alloc(curve.ctx, &r);
        MPValue qx; mp_alloc(curve.ctx, &qx);
        MPValue qy; mp_alloc(curve.ctx, &qy);

        int i;
        for (i=0; i<10 && dd[i]!=NULL;i++) {
            mp_hex2bin(curve.ctx, &d, dd[i]); //mp_revert(curve.ctx, &d);

            ecc_public_key(qx.value, qy.value, d.value, &curve);
            printf("\ni = %d", i);
            printf("\nd =   0x"); bn_print ( d.value, curve.ctx->size);
            printf("\nQ.x=  0x"); bn_print (qx.value, curve.ctx->size);
            printf("\nQ.y=  0x"); bn_print (qy.value, curve.ctx->size);
            if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
                printf("\n public key verifyed");
            else return (1);

            mp_invm(curve.ctq, q.value, d.value);
            mp_mulm(curve.ctq, r.value, q.value, d.value);
            mp_modp(curve.ctq, r.value, r.value);
            if (bn_is_one(r.value, curve.ctq->size)) printf("\n OK");
            else return (1);
        }

        mp_free1(curve.ctx, &qy);
        mp_free1(curve.ctx, &qx);
        mp_free1(curve.ctx, &r);
        mp_free1(curve.ctx, &q);
        mp_free1(curve.ctx, &d);
        ecc_curve_free (&curve);
    }
    if (1 && ecc_curve_find (&curve, EC_GOST_TEST)) {
        printf ("\nGOST 34.10-2012 Test 256");
        char e1[] = "0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5";
        char d1[] = "0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28";
        char k1[] = "0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3";
        char r1[] = "0x41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493";
        char s1[] = "0x01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40";
        char x1[] = "0x7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B";
        char y1[] = "0x26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA";

        //mp_hex2bin(curve.ctx, &e,  e1);
        MPValue k;  mp_alloc(curve.ctx, &k);
        MPValue d;  mp_alloc(curve.ctx, &d);
        MPValue e;  mp_alloc(curve.ctx, &e);
        MPValue r;  mp_alloc(curve.ctx, &r);
        MPValue s;  mp_alloc(curve.ctx, &s);
        MPValue qx; mp_alloc(curve.ctx, &qx);
        MPValue qy; mp_alloc(curve.ctx, &qy);

        mp_hex2bin(curve.ctx, &qx, x1);
        mp_hex2bin(curve.ctx, &qy, y1);
        mp_hex2bin(curve.ctx, &r,  r1);
        mp_hex2bin(curve.ctx, &s,  s1);
        mp_hex2bin(curve.ctx, &d,  d1);
        mp_hex2bin(curve.ctx, &e,  e1);
        mp_hex2bin(curve.ctx, &k,  k1);
        printf("\nQ.x=  0x");  bn_print (qx.value, curve.ctx->size);
        printf("\nQ.y=  0x");  bn_print (qy.value, curve.ctx->size);
        if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
            printf("\n public key verifyed");
        if (ecc_gost_sign(r.value,s.value,d.value,k.value,e.value,&curve)){
            printf("\n sign verifyed");
        }
/*        if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
            printf("\n public key verifyed");
*/
        if (ecc_gost_verify2(r.value, s.value, e.value, d.value, &curve))
            printf("\n signature verifyed2");
        else return 2;
        if (ecc_gost_verify (r.value, s.value, e.value, qx.value, qy.value, &curve))
            printf("\n signature verifyed");
        else return 3;
        mp_free1(curve.ctx, &qy);
        mp_free1(curve.ctx, &qx);
        mp_free1(curve.ctx, &r);
        mp_free1(curve.ctx, &s);
        mp_free1(curve.ctx, &d);
        mp_free1(curve.ctx, &e);
        mp_free1(curve.ctx, &k);
        ecc_curve_free (&curve);
        printf ("\ndone\n");
    }
    if (1 && ecc_curve_find (&curve, EC_GOST_3410_12_TEST)) {
        printf ("\nGOST 34.10-2012 Test");
        char e1[] = "0x3754F3CFACC9E0615C4F4A7C4D8DAB531B09B6F9C170C533A71D147035B0C5917184EE536593F4414339976C647C5D5A407ADEDB1D560C4FC6777D2972075B8C";
        char d1[] = "0x0BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4";
        char k1[] = "0x0359E7F4B1410FEACC570456C6801496946312120B39D019D455986E364F365886748ED7A44B3E794434006011842286212273A6D14CF70EA3AF71BB1AE679F1";
        char r1[] = "0x2F86FA60A081091A23DD795E1E3C689EE512A3C82EE0DCC2643C78EEA8FCACD35492558486B20F1C9EC197C90699850260C93BCBCD9C5C3317E19344E173AE36";
        char s1[] = "0x1081B394696FFE8E6585E7A9362D26B6325F56778AADBC081C0BFBE933D52FF5823CE288E8C4F362526080DF7F70CE406A6EEB1F56919CB92A9853BDE73E5B4A";
        char x1[] = "0x115DC5BC96760C7B48598D8AB9E740D4C4A85A65BE33C1815B5C320C854621DD5A515856D13314AF69BC5B924C8B4DDFF75C45415C1D9DD9DD33612CD530EFE1";
        char y1[] = "0x37C7C90CD40B0F5621DC3AC1B751CFA0E2634FA0503B3D52639F5D7FB72AFD61EA199441D943FFE7F0C70A2759A3CDB84C114E1F9339FDF27F35ECA93677BEEC";

        //mp_hex2bin(curve.ctx, &e,  e1);
        MPValue k;  mp_alloc(curve.ctx, &k);
        MPValue d;  mp_alloc(curve.ctx, &d);
        MPValue e;  mp_alloc(curve.ctx, &e);
        MPValue r;  mp_alloc(curve.ctx, &r);
        MPValue s;  mp_alloc(curve.ctx, &s);
        MPValue qx; mp_alloc(curve.ctx, &qx);
        MPValue qy; mp_alloc(curve.ctx, &qy);

        mp_hex2bin(curve.ctx, &qx, x1);
        mp_hex2bin(curve.ctx, &qy, y1);
        mp_hex2bin(curve.ctx, &r,  r1);
        mp_hex2bin(curve.ctx, &s,  s1);
        mp_hex2bin(curve.ctx, &d,  d1);
        mp_hex2bin(curve.ctx, &e,  e1);
        mp_hex2bin(curve.ctx, &k,  k1);
        printf("\nQ.x=  0x");  bn_print (qx.value, curve.ctx->size);
        printf("\nQ.y=  0x");  bn_print (qy.value, curve.ctx->size);
        if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
            printf("\n public key verifyed");
        //else _Exit(5410);
        if (ecc_gost_sign(r.value,s.value,d.value,k.value,e.value,&curve)){
            printf("\n sign verifyed");
        }
/*        if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
            printf("\n public key verifyed");
*/
        if (ecc_gost_verify (r.value, s.value, e.value, qx.value, qy.value, &curve)
        &&  ecc_gost_verify2(r.value, s.value, e.value, d.value, &curve)
            )
            printf("\n signature verifyed");
        mp_free1(curve.ctx, &qy);
        mp_free1(curve.ctx, &qx);
        mp_free1(curve.ctx, &r);
        mp_free1(curve.ctx, &s);
        mp_free1(curve.ctx, &d);
        mp_free1(curve.ctx, &e);
        mp_free1(curve.ctx, &k);
        ecc_curve_free (&curve);
    }
    if (1 && ecc_curve_find (&curve, EC_GOST_CRYPTO_PRO_A)) {
        printf ("\nGOST 34.10-2012 A 256");
        char e1[] = "0x5D2F21882BC115C7F3A400E1F396C7DFB25CEED4A8B135C2D9336BB31F357908";
//        char d1[] = "0x0BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4";
//        char k1[] = "0x0359E7F4B1410FEACC570456C6801496946312120B39D019D455986E364F365886748ED7A44B3E794434006011842286212273A6D14CF70EA3AF71BB1AE679F1";
        char r1[] = "0x7B624967227D7002E64E6F065D5DCF6736B06B71A083D88EA1DEF0AE026B4E8B";
        char s1[] = "0x5BD91BDED02C60F871F219D4A490167EA3E4DA4EC54D36235828A040C64A0E2A";
// char r1[] = "0x2A0E4AC640A0285823364DC54EDAE4A37E1690A4D419F271F8602CD0DE1BD95B";
// char s1[] = "0x8B4E6B02AEF0DEA18ED883A0716BB03667CF5D5D066F4EE602707D226749627B";
        char x1[] = "0x051E135BC130A5ABCE63F744686C594E580385990C08312EC9E3E6FD7DBB15AA";
        char y1[] = "0x04E73039D309F4FE46F6CCF996B79C3805F7FB3D5D49735024C50E02985D7936";
// X: 0x051E135BC130A5ABCE63F744686C594E580385990C08312EC9E3E6FD7DBB15AA
// Y: 0x04E73039D309F4FE46F6CCF996B79C3805F7FB3D5D49735024C50E02985D7936
//        char x2[] = "0xE2D46C0772DCC6E7A0F733C4B1322282C8F2DD0EDEA5512F63410C5EF59959A6";
//        char y2[] = "0xE83C3BE7CAFA9DB4243D31AFE29E1AEA52C3FB82DF7E7C7017B2771C4756FCAA";
        char r2[] = "0x7B624967227D7002E64E6F065D5DCF6736B06B71A083D88EA1DEF0AE026B4E8B";
        char s2[] = "0x4B737FBA63D7CEA6434DE2CDB965FCE7782C3A883E4ED7B50C8D15E382B2FEC5";
        char e2[] = "0x4EBEE76BED7732442DAFD5559E6810FF3CA743BB2F1514E52DA96F83B4222F98";
//        MPValue k;  mp_alloc(curve.ctx, &k);
//        MPValue d;  mp_alloc(curve.ctx, &d);
        MPValue e;  mp_alloc(curve.ctx, &e);
        MPValue r;  mp_alloc(curve.ctx, &r);
        MPValue s;  mp_alloc(curve.ctx, &s);
        MPValue qx; mp_alloc(curve.ctx, &qx);
        MPValue qy; mp_alloc(curve.ctx, &qy);

        mp_hex2bin(curve.ctx, &qx, x1);
        mp_hex2bin(curve.ctx, &qy, y1);
        mp_hex2bin(curve.ctx, &r,  r1); //mp_revert(curve.ctx, &e);
        mp_hex2bin(curve.ctx, &s,  s1); //mp_revert(curve.ctx, &s);
//        mp_hex2bin(curve.ctx, &d,  d1);
//        mp_hex2bin(curve.ctx, &k,  k1);
        mp_hex2bin(curve.ctx, &e,  e1); mp_revert(curve.ctx, &e);
        printf("\nQ.x=  0x");  bn_print (qx.value, curve.ctx->size);
        printf("\nQ.y=  0x");  bn_print (qy.value, curve.ctx->size);
        if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
            printf("\n public key verifyed");
/*        if (ec_point_verify(r.value, s.value, curve.x, curve.y, curve.ctx))
            printf("\n rs verifyed");*/
//        if (ecc_gost_sign(r.value,s.value,d.value,k.value,e.value,&curve)){
//            printf("\n sign verifyed");
//        }
        if (ecc_gost_verify (r.value, s.value, e.value, qx.value, qy.value, &curve)
//        &&  ecc_gost_verify2(r.value, s.value, e.value, d.value, &curve)
            )
            printf("\n signature verifyed");
        else
            printf("\n signature fail.. !!!!!!!!!");

        mp_hex2bin(curve.ctx, &qx, x1);
        mp_hex2bin(curve.ctx, &qy, y1);
        mp_hex2bin(curve.ctx, &r,  r2); //mp_revert(curve.ctx, &r);
        mp_hex2bin(curve.ctx, &s,  s2); //mp_revert(curve.ctx, &s);
        mp_hex2bin(curve.ctx, &e,  e2); mp_revert(curve.ctx, &e);

        printf("\nQ.x=  0x");  bn_print (qx.value, curve.ctx->size);
        printf("\nQ.y=  0x");  bn_print (qy.value, curve.ctx->size);
        if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
            printf("\n public key verifyed");
        if (ecc_gost_verify (r.value, s.value, e.value, qx.value, qy.value, &curve)
//        &&  ecc_gost_verify2(r.value, s.value, e.value, d.value, &curve)
            )
            printf("\n signature verifyed");
        else
            printf("\n signature fail.. !!!!!!!!!");


        mp_free1(curve.ctx, &qy);
        mp_free1(curve.ctx, &qx);
        mp_free1(curve.ctx, &r);
        mp_free1(curve.ctx, &s);
//        mp_free1(curve.ctx, &d);
//        mp_free1(curve.ctx, &k);
        mp_free1(curve.ctx, &e);
        ecc_curve_free (&curve);
    }
    if (1 && ecc_curve_find (&curve, EC_TC26_GOST_3410_2012_512_C)){
        ecc_curve_print(&curve);
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
                printf("\n G point verifyed");
        else _Exit(1);
        MPCtx *ctx = curve.ctx;
        BNuint a[ctx->asize] BN_ALIGN;
        BNuint x[ctx->asize] BN_ALIGN;
        mp_divm(ctx, x, NULL, curve.G.x);
        mp_mulm(ctx, x, x, curve.G.x);
        mp_modp(ctx, x, x);
        if (bn_is_one(x, ctx->size)) {
            printf("\n mp inversion mod p verifyed");
        } else {
            printf("\n mp inversion mod p fail....");
        }
        ctx = curve.ctq;
        mp_divm(ctx, x, NULL, curve.G.x);
        printf("\nx   = 0x"); bn_print (x, ctx->size);
        mp_mulm(ctx, x, x, curve.G.x);
        mp_modp(ctx, x, x);
        if (bn_is_one(x, ctx->size)) {
            printf("\n mp inversion mod q verifyed");
        } else {
            printf("\nx   = 0x"); bn_print (x, ctx->size);
            printf("\n mp inversion mod q fail....");
        }
        mp_invm(ctx, x, curve.G.x);
        mp_invm(ctx, x, x);
        mp_subm(ctx, x, x, curve.G.x);
        if (bn_is_zero(x, ctx->size)) {
            printf("\n mp inversion mod q verifyed2");
        }

        bn_move(a, curve.G.x, ctx->size);
        int i;
        for (i=0; i<0;i++){
            a[0]++;
            mp_invm(ctx, x, a);
            mp_mulm(ctx, x, x, a);
            mp_modp(ctx, x, x);
            printf("\nx   = 0x"); bn_print (x, ctx->size);
        }

        ecc_curve_free (&curve);
    }
    if (1 && ecc_curve_find (&curve, EC_TC26_GOST_3410_2012_256_A)){
        ecc_curve_print(&curve);
        ecc_curve_verify(curve.a, curve.b, curve.ctx);
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
                printf("\n G point verifyed");
        else _Exit(1);

        MPCtx *ctx = curve.ctx;
        BNuint x[ctx->asize] BN_ALIGN;
        mp_invm(ctx, x, curve.G.x);
        mp_mulm(ctx, x, x, curve.G.x);
        mp_modp(ctx, x, x);
        if (bn_is_one(x, ctx->size)) {
            printf("\n mp inversion mod p verifyed");
        } else
            printf("\n mp inversion mod p fail....");
        ctx = curve.ctq;
        mp_invm(ctx, x, curve.G.x);
        printf("\n inv G\n"); bn_print (x, ctx->size);
        mp_mulm(ctx, x, x, curve.G.x);
        printf("\n mul G\n"); bn_print (x, ctx->size);
        mp_modp(ctx, x, x);
        if (bn_is_one(x, ctx->size)) {
            printf("\n mp inversion mod q verifyed");
        } else {
            printf("\n mp inversion mod q fail....\n");
            bn_print (x, ctx->size);
        }
        mp_divm(ctx, x, NULL, curve.G.x);
        mp_divm(ctx, x, NULL, x);
        mp_subm(ctx, x, x, curve.G.x);
        if (bn_is_zero(x, ctx->size)) {
            printf("\n mp inversion mod q verifyed2");
        } else
            printf("\n mp inversion mod q fail2....");
        MPValue d; mp_alloc(curve.ctx, &d);
        char *dd[] = {
            "0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28",
            NULL
            };
        MPValue qx; mp_alloc(curve.ctx, &qx);
        MPValue qy; mp_alloc(curve.ctx, &qy);

            mp_hex2bin(curve.ctx, &d, dd[0]);
            printf("\nd=    0x");
            bn_print (d.value, curve.ctx->size);

            ecc_public_key(qx.value, qy.value, d.value, &curve);
            printf("\nQ.x=  0x");  bn_print (qx.value, curve.ctx->size);
            printf("\nQ.y=  0x");  bn_print (qy.value, curve.ctx->size);
            if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
                printf("\n public key verifyed");
            else return(1);


        char ee[] = "0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5";
        char kk[] = "0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3";
        MPValue e; mp_alloc(curve.ctx, &e); mp_hex2bin(curve.ctx, &e, ee);
        MPValue k; mp_alloc(curve.ctx, &k); mp_hex2bin(curve.ctx, &k, kk);
        MPValue r; mp_alloc(curve.ctx, &r);
        MPValue s; mp_alloc(curve.ctx, &s);
        int i, count=1000;
        for (i=0; i<count; i++) {
            ecc_gost_sign  (r.value, s.value, d.value, NULL /*k.value*/, e.value, &curve);
            //printf("\nr=  0x"); bn_print (r.value, curve.ctx->size);
            //printf("\ns=  0x"); bn_print (s.value, curve.ctx->size);
            if (ecc_gost_verify2(r.value, s.value, e.value, d.value, &curve)) {
                //printf ("\n signature verified2");
            } else return (2);
            if (ecc_gost_verify (r.value, s.value, e.value, qx.value, qy.value, &curve)) {
                //printf ("\n signature verified");
            } else return (3);
        }
        mp_free1(curve.ctx, &k);
        mp_free1(curve.ctx, &r);
        mp_free1(curve.ctx, &s);
        mp_free1(curve.ctx, &e);
        mp_free1(curve.ctx, &qy);
        mp_free1(curve.ctx, &qx);
        mp_free1(curve.ctx, &d);

        ecc_curve_free (&curve);
    }
    if (1 && ecc_curve_find (&curve, EC_TC26_GOST_3410_12_A)){
        ecc_curve_print(&curve);
        ecc_curve_verify(curve.a, curve.b, curve.ctx);
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
                printf("\n G point verifyed");
        else _Exit(1);
        MPCtx *ctx = curve.ctx;
        BNuint x[ctx->asize] BN_ALIGN;
        mp_invm(ctx, x, curve.G.x);
        mp_mulm(ctx, x, x, curve.G.x);
        mp_modp(ctx, x, x);
        if (bn_is_one(x, ctx->size)) {
            printf("\n mp inversion mod p verifyed");
        }
        ctx = curve.ctq;
        mp_invm(ctx, x, curve.G.x);
        mp_mulm(ctx, x, x, curve.G.x);
        mp_modp(ctx, x, x);
        if (bn_is_one(x, ctx->size)) {
            printf("\n mp inversion mod q verifyed");
        }
        mp_invm(ctx, x, curve.G.x);
        mp_invm(ctx, x, x);
        mp_subm(ctx, x, x, curve.G.x);
        if (bn_is_zero(x, ctx->size)) {
            printf("\n mp inversion mod q verifyed2");
        }



        ecc_curve_free (&curve);
        //_Exit(0x12A);
    }
    if (1 && ecc_curve_find (&curve, EC_TC26_GOST_3410_12_B)){
        ecc_curve_print(&curve);
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
                printf("\n G point verifyed");
        else _Exit(1);

        MPCtx *ctx = curve.ctx;
        BNuint x[ctx->asize] BN_ALIGN;
        mp_invm(ctx, x, curve.G.x);
        mp_mulm(ctx, x, x, curve.G.x);
        mp_modp(ctx, x, x);
        if (bn_is_one(x, ctx->size)) {
            printf("\n mp inversion mod p verifyed");
        }
        ctx = curve.ctq;
        mp_invm(ctx, x, curve.G.x);
        mp_mulm(ctx, x, x, curve.G.x);
        mp_modp(ctx, x, x);
        if (bn_is_one(x, ctx->size)) {
            printf("\n mp inversion mod q verifyed");
        }

        ecc_curve_free (&curve);
    }

    printf("\n");
    if (0) {// ecc_edwards_test
        extern void ecc_edwards_test();
        ecc_edwards_test();
    }
    if (1) {
        int mp_26_2_001_2020();
        mp_26_2_001_2020();
        printf("\n");
    }
    return 0;
}
#endif
#if 1
/* \see ТК26 МР 26.2.001-2020 */
int mp_26_2_001_2020()
{
    ECC_Curve curve;
    if (1 && ecc_curve_find (&curve, EC_GOST_TEST)){
        ecc_curve_print(&curve);
        if (ecc_curve_verify(curve.a, curve.b, curve.ctx))
            printf("\t-- Curve verifyed\n");
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
            printf("\n G point verifyed");
        else {
            printf("\n G point .. fail");
            _Exit(1);
        }

        MPValue d; mp_alloc(curve.ctx, &d);
        MPValue k; mp_alloc(curve.ctx, &k);
        MPValue e; mp_alloc(curve.ctx, &e);
        MPValue r; mp_alloc(curve.ctx, &r);
        MPValue s; mp_alloc(curve.ctx, &s);
        MPValue qx; mp_alloc(curve.ctx, &qx);
        MPValue qy; mp_alloc(curve.ctx, &qy);


        char *dd[] = {// закрытый ключ
            "0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28",
            };
        char *kk[] = {// случайное число
            "0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3"};
/*
 r: 0x41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493
 s: 0x4D53F012FE081776507D4D9BB81F00EFDB4EEFD4AB83BAC4BACF735173CFA81C
Hash:
 H: 0x4387FD1F03DC7C778BA9E6EF04E3DD685E18E4F5A2BF871F46FC0B747FC6ECAF
*/
        char *ee[] = {// хеш от сообщения
            "0x4387FD1F03DC7C778BA9E6EF04E3DD685E18E4F5A2BF871F46FC0B747FC6ECAF"};

        mp_hex2bin(curve.ctx, &d, dd[0]);
        mp_hex2bin(curve.ctx, &e, ee[0]);
        mp_hex2bin(curve.ctx, &k, kk[0]);
        printf("\nd=    0x");
        bn_print (d.value, curve.ctx->size);

        ecc_public_key(qx.value, qy.value, d.value, &curve);
        printf("\nQ.x=  0x");  bn_print (qx.value, curve.ctx->size);
        printf("\nQ.y=  0x");  bn_print (qy.value, curve.ctx->size);
        if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
            printf("\n public key verifyed");
        else {
            printf("\n public key ... fail\n");
            return(1);
        }
        if (ecc_gost_sign(r.value,s.value,d.value,k.value,e.value,&curve)){
            printf("\n sign .. fail");
        }
        printf("\nr=  0x");  bn_print (r.value, curve.ctx->size);
        printf("\ns=  0x");  bn_print (s.value, curve.ctx->size);
/*        if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
            printf("\n public key verifyed");
*/
        if (ecc_gost_verify2(r.value, s.value, e.value, d.value, &curve))
            printf("\n signature verifyed2");
        else return 2;
        if (ecc_gost_verify (r.value, s.value, e.value, qx.value, qy.value, &curve))
            printf("\n signature verifyed");
        else return 3;

        mp_free1(curve.ctx, &d);
        mp_free1(curve.ctx, &k);
        mp_free1(curve.ctx, &e);
        mp_free1(curve.ctx, &r);
        mp_free1(curve.ctx, &s);
        mp_free1(curve.ctx, &qx);
        mp_free1(curve.ctx, &qy);
        ecc_curve_free(&curve);
    }
    if (1 && ecc_curve_find (&curve, EC_TC26_GOST_3410_2012_256_A)){// ГОСТ Р 34.10-2012 «1.2.643.7.1.2.1.1.1», Р 50.1.114-2016 приложение А.3
        ecc_curve_print(&curve);
        if (ecc_curve_verify(curve.a, curve.b, curve.ctx))
            printf("\t-- Curve verifyed\n");
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
            printf("\n G point verifyed");
        else _Exit(1);
        char *dd[] = {
            "0x3A929ADE789BB9BE10ED359DD39A72C10B87C83F80BE18B85C041F4325B62EC1",
            };
        char *kk[] = {// случайное число
            "0x27105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3"};
/*
CERT
 r: 0x1D0E1DA5BE347C6F1B5256C7AEAC200AD64AC77A6F5B3A0E097318E7AE6EE769
 s: 0x140B4DA9124B09CB0D5CE928EE874273A310129492EC0E29369E3B791248578C
Hash:
 H: 0x34EB651E077CC74FB545216985891AFB4F8FFC0D035D1A7AA3E12589F0537403

CRL
 r: 0x1D0E1DA5BE347C6F1B5256C7AEAC200AD64AC77A6F5B3A0E097318E7AE6EE769
 s: 0x14BD68087C3B903C7AA28B07FEB2E7BD6FE0963F563267359F5CD8EAB45059AD
Hash:
 H: 0xBC656A5C9332CB53D4CDDCB36734944FA269245C4E37D4FEE14EE5A0928DC570
 */
        char *ee[] = {// хеш от сообщения
            "0x34EB651E077CC74FB545216985891AFB4F8FFC0D035D1A7AA3E12589F0537403",
            "0xBC656A5C9332CB53D4CDDCB36734944FA269245C4E37D4FEE14EE5A0928DC570"};

            /*
        Xq = 99C3DF265EA59350640BA69D1DE04418AF3FEA03EC0F85F2DD84E8BED4952774
        Yq = E218631A69C47C122E2D516DA1C09E6BD19344D94389D1F16C0C4D4DCF96F578
            */
        MPValue d;  mp_alloc(curve.ctx, &d);
        MPValue k; mp_alloc(curve.ctx, &k);
        MPValue e; mp_alloc(curve.ctx, &e);
        MPValue r; mp_alloc(curve.ctx, &r);
        MPValue s; mp_alloc(curve.ctx, &s);
        MPValue qx; mp_alloc(curve.ctx, &qx);
        MPValue qy; mp_alloc(curve.ctx, &qy);

        mp_hex2bin(curve.ctx, &d, dd[0]);
        mp_hex2bin(curve.ctx, &k, kk[0]);

        printf("\nd=    0x");
        bn_print (d.value, curve.ctx->size);

        ecc_public_key(qx.value, qy.value, d.value, &curve);
        printf("\nQ.x=  0x");  bn_print (qx.value, curve.ctx->size);
        printf("\nQ.y=  0x");  bn_print (qy.value, curve.ctx->size);
        if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
            printf("\n public key verifyed");
        else {
            printf("\n public key ... fail\n");
            return(1);
        }
    int i;
    for (i=0;i<2; i++) {
        mp_hex2bin(curve.ctx, &e, ee[i]);
        if (ecc_gost_sign(r.value,s.value,d.value,k.value,e.value,&curve)){
            printf("\n sign .. fail");
        }
        printf("\nr=  0x");  bn_print (r.value, curve.ctx->size);
        printf("\ns=  0x");  bn_print (s.value, curve.ctx->size);
        if (ecc_gost_verify2(r.value, s.value, e.value, d.value, &curve))
            printf("\n signature verifyed2");
        else return 2;
        if (ecc_gost_verify (r.value, s.value, e.value, qx.value, qy.value, &curve))
            printf("\n signature verifyed");
        else return 3;
    }
        mp_free1(curve.ctx, &d);
        mp_free1(curve.ctx, &k);
        mp_free1(curve.ctx, &e);
        mp_free1(curve.ctx, &r);
        mp_free1(curve.ctx, &s);
        mp_free1(curve.ctx, &qx);
        mp_free1(curve.ctx, &qy);
        ecc_curve_free(&curve);
    }
    if (1 && ecc_curve_find (&curve, EC_GOST_3410_12_TEST)){// ГОСТ Р 34.10-2012 «1.2.643.7.1.2.1.2.0» с ключом подписи длины 512 бит
        ecc_curve_print(&curve);
        if (ecc_curve_verify(curve.a, curve.b, curve.ctx))
            printf("\t-- Curve verifyed\n");
        if (ec_point_verify(curve.G.x, curve.G.y, curve.a, curve.b, curve.ctx))
            printf("\n G point verifyed");
        else _Exit(1);
        char *dd[] = {
            "0x0BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B1020"
            "72E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4",
            };
        char *kk[] = {// случайное число
            "0x0359E7F4B1410FEACC570456C6801496946312120B39D019D455986E364F3658"
            "86748ED7A44B3E794434006011842286212273A6D14CF70EA3AF71BB1AE679F1"};

        char *xx[] = {// случайное число
            "0x115DC5BC96760C7B48598D8AB9E740D4C4A85A65BE33C1815B5C320C854621DD5A515856D1"
            "3314AF69BC5B924C8B4DDFF75C45415C1D9DD9DD33612CD530EFE1"};
        char *yy[] = {// случайное число
            "0x37C7C90CD40B0F5621DC3AC1B751CFA0E2634FA0503B3D52639F5D7FB72AFD61EA199441D9"
            "43FFE7F0C70A2759A3CDB84C114E1F9339FDF27F35ECA93677BEEC"};


        MPValue Xq; mp_alloc(curve.ctx, &Xq);
        MPValue Yq; mp_alloc(curve.ctx, &Yq);
        mp_hex2bin(curve.ctx, &Xq, xx[0]);
        mp_hex2bin(curve.ctx, &Yq, yy[0]);

        if (ec_point_verify(Xq.value, Yq.value, curve.a, curve.b, curve.ctx))
            printf("\n X,Y point verifyed");


            /*
Xq = 115DC5BC96760C7B48598D8AB9E740D4C4A85A65BE33C1815B5C320C854621DD\\
     5A515856D13314AF69BC5B924C8B4DDFF75C45415C1D9DD9DD33612CD530EFE1
Yq = 37C7C90CD40B0F5621DC3AC1B751CFA0E2634FA0503B3D52639F5D7FB72AFD61\\
     EA199441D943FFE7F0C70A2759A3CDB84C114E1F9339FDF27F35ECA93677BEEC
 X: 0x115DC5BC96760C7B48598D8AB9E740D4C4A85A65BE33C1815B5C320C854621DD5A515856D1
3314AF69BC5B924C8B4DDFF75C45415C1D9DD9DD33612CD530EFE1
 Y: 0x37C7C90CD40B0F5621DC3AC1B751CFA0E2634FA0503B3D52639F5D7FB72AFD61EA199441D9
43FFE7F0C70A2759A3CDB84C114E1F9339FDF27F35ECA93677BEEC



 r: 0x2F86FA60A081091A23DD795E1E3C689EE512A3C82EE0DCC2643C78EEA8FCACD35492558486
B20F1C9EC197C90699850260C93BCBCD9C5C3317E19344E173AE36
 s: 0x415703D892F1A5F3F68C4353189A7EE207B80B5631EF9D49529A4D6B542C2CFA15AA2EACF1
1F470FDE7D954856903C35FD8F955EF300D95C77534A724A0EEE70
Hash:
 H: 0x903979B74C5EC18CDBB15AB63B807DDBEC025210F7307B2135129721F42F25101F56E6AA98
1D1BEC7E0F89F95926C351C39E085D1B6DCF09F0D3C5A6DC19A669
Подпись из CRL
 r: 0x2F86FA60A081091A23DD795E1E3C689EE512A3C82EE0DCC2643C78EEA8FCACD35492558486
B20F1C9EC197C90699850260C93BCBCD9C5C3317E19344E173AE36
 s: 0x3A13FB7AECDB5560EEF6137CFC5DD64691732EBFB3690A1FC0C7E8A4EEEA08307D648D4DC0
986C46A87B3FBE4C7AF42EA34359C795954CA39FF3ABBED9051F4D
Hash:
 H: 0xDDEE1C3124DD1F6E7B77D49E0CB1083B56B57704436D6A35C4135887FF511298A9ECAB2054
930BF0CABAEC6BEE455B0113AAC4B9ACB1B04182854686CB7D6143
            */
        char *ee[] ={
            "0x903979B74C5EC18CDBB15AB63B807DDBEC025210F7307B2135129721F42F25101F56E6AA98"
            "1D1BEC7E0F89F95926C351C39E085D1B6DCF09F0D3C5A6DC19A669",
            "0xDDEE1C3124DD1F6E7B77D49E0CB1083B56B57704436D6A35C4135887FF511298A9ECAB2054"
            "930BF0CABAEC6BEE455B0113AAC4B9ACB1B04182854686CB7D6143",
            };

        MPValue d;  mp_alloc(curve.ctx, &d);
        MPValue k; mp_alloc(curve.ctx, &k);
        MPValue e; mp_alloc(curve.ctx, &e);
        MPValue r; mp_alloc(curve.ctx, &r);
        MPValue s; mp_alloc(curve.ctx, &s);
        MPValue qx; mp_alloc(curve.ctx, &qx);
        MPValue qy; mp_alloc(curve.ctx, &qy);

        mp_hex2bin(curve.ctx, &d, dd[0]);
        mp_hex2bin(curve.ctx, &e, ee[0]);
        mp_hex2bin(curve.ctx, &k, kk[0]);

        printf("\nd=    0x");
        bn_print (d.value, curve.ctx->size);
        printf("\nk=    0x");
        bn_print (k.value, curve.ctx->size);

        ecc_public_key(qx.value, qy.value, d.value, &curve);
        printf("\nQ.x=  0x");  bn_print (qx.value, curve.ctx->size);
        printf("\nQ.y=  0x");  bn_print (qy.value, curve.ctx->size);
        if (ec_point_verify(qx.value, qy.value, curve.a, curve.b, curve.ctx))
            printf("\n public key verifyed");
        else {
            printf("\n public key ... fail\n");
            return(1);
        }
        if (ecc_gost_sign(r.value,s.value,d.value,k.value,e.value,&curve)){
            printf("\n sign .. fail");
        }
        printf("\nr=  0x");  bn_print (r.value, curve.ctx->size);
        printf("\ns=  0x");  bn_print (s.value, curve.ctx->size);
        if (ecc_gost_verify2(r.value, s.value, e.value, d.value, &curve))
            printf("\n signature verifyed2");
        else return 2;
        if (ecc_gost_verify (r.value, s.value, e.value, qx.value, qy.value, &curve))
            printf("\n signature verifyed");
        else return 3;

        mp_hex2bin(curve.ctx, &e, ee[1]);
        if (ecc_gost_sign(r.value,s.value,d.value,k.value,e.value,&curve)){
            printf("\n sign .. fail");
        }
        printf("\nr=  0x");  bn_print (r.value, curve.ctx->size);
        printf("\ns=  0x");  bn_print (s.value, curve.ctx->size);
        if (ecc_gost_verify2(r.value, s.value, e.value, d.value, &curve))
            printf("\n signature verifyed2");
        else return 2;
        if (ecc_gost_verify (r.value, s.value, e.value, qx.value, qy.value, &curve))
            printf("\n signature verifyed");
        else return 3;


        mp_free1(curve.ctx, &d);
        mp_free1(curve.ctx, &k);
        mp_free1(curve.ctx, &e);
        mp_free1(curve.ctx, &r);
        mp_free1(curve.ctx, &s);
        mp_free1(curve.ctx, &qx);
        mp_free1(curve.ctx, &qy);
        ecc_curve_free(&curve);

    }
    return 0;
}
#endif
