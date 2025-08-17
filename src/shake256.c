/*! shake-256, SHA3-256, SHA3-512

2025, Анатолий М. Георгиевский 

Эффективная реализация функций SHA3 и SHAKE с использованием инструкций AVX512 и векторных регистров 512 бит. 
+ Все операции выполняются по строкам 5*64 бит, на регистрах 512 бит. 
+ Перестановки π() реализованы за счет транспонирования матрицы 5x5 и перестановок слов в строке.
+ Логические операции χ() и ρ() ориентированы на использование тернарной логики и циклического сдвига.
+ реализация алгоритма KECCAK-p[1600, 24] выполнена с использованием векторного расширения языка C для переносимости.

\see NIST.FIPS.202
SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
(https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)

\see NIST Special Publication 800-185
SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and ParallelHash
(https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)

Тестирование:

\see (https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values)

* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-224_1600.pdf
* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-256_1600.pdf
* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-384_1600.pdf
* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-512_1600.pdf
* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-512_msg0.pdf
* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-384_msg0.pdf
* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-256_msg0.pdf
* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-224_msg0.pdf
* https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg0.pdf
* https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE128_Msg0.pdf

* https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha3-384_msg30.pdf

Определение функции KECCAK-p[b, nr] для b = 1600 и nr = 24
Функция определяется для различной разрядности w, w=1,2,4,8,16,32,64, от одного бита до 64 бит. 
Но в стандарте используется вариант w=64, b=1600 с числом циклов 24.

Алгоритм построен как сеть (губка, SPONGE) с контекстным состоянием 200 байт (1600бит), состоящим из 25 64-битных слов.
Алгоритм использует перестановки (permutation) и битовые логические операции.

Губка впитывает данные методом `absorb` - побитовое исключающее или, и применяет 24 _слоя_ преобразования `f`.
Губка рассматривается как отдельный алгоритм, который может впитывать данные и выполнять последующую генерацию 
(squeeze) за счет циклического обновления контекста.

Функции заданы параметрически.
KECCAK[c] = SPONGE[KECCAK-p[1600, 24], pad10*1, 1600–c].
SPONGE[f, pad,r] 
    The sponge function in which the underlying function is `f`, the padding 
    rule is `pad`, and the rate is `r` bits.
* Для кодирования битовой строки используется `pad10*1`

Функции SHA3 предназначены для кодирования байтовых строк. Имеют длину контекста 1600 бит, 
но при кодировании используются часть контекста `r`, которая зависит от длины `с`, r+c=b=1600.

После функции указан длина блока записи `r` в байтах:
SHA3-224(M) = KECCAK[448] (M || 01, 224); -- 144
SHA3-256(M) = KECCAK[512] (M || 01, 256); -- 136
SHA3-384(M) = KECCAK[768] (M || 01, 384); -- 104
SHA3-512(M) = KECCAK[1024](M || 01, 512). --  72

Функция SHAKE XOF (eXtendable Output Function) предназначена для генерации детерминированных 
псевдослучайных байтовых последовательностей произвольной длины `d`.
SHAKE128(M, d) = KECCAK[256] (M || 1111, d), -- 168
SHAKE256(M, d) = KECCAK[512] (M || 1111, d). -- 136

При кодировании байтовой строки дополнительные биты выглядят как 
 * 0x06 || 0.. || 0x08 для функций SHA3  - младшие биты 01, к ним добавляется 1 в функции `pad10*1`,
 * 0x1F || 0.. || 0x08 для функций SHAKE - младшие биты 1111, к ним добавляется 1.
Функция `pad10*1` добавляет в конец состояния старший бит 0x80.
 */ 
#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>

typedef uint64_t uint64x5_t __attribute__((__vector_size__(64)));// 256
#define ROTL(x,n) (((x) << (n)) | ((x) >> (64-(n))))
#define U64_C(c) c
static const uint64_t RC[24 + 1] =
{
  U64_C(0x0000000000000001), U64_C(0x0000000000008082),
  U64_C(0x800000000000808A), U64_C(0x8000000080008000),
  U64_C(0x000000000000808B), U64_C(0x0000000080000001),
  U64_C(0x8000000080008081), U64_C(0x8000000000008009),
  U64_C(0x000000000000008A), U64_C(0x0000000000000088),
  U64_C(0x0000000080008009), U64_C(0x000000008000000A),
  U64_C(0x000000008000808B), U64_C(0x800000000000008B),
  U64_C(0x8000000000008089), U64_C(0x8000000000008003),
  U64_C(0x8000000000008002), U64_C(0x8000000000000080),
  U64_C(0x000000000000800A), U64_C(0x800000008000000A),
  U64_C(0x8000000080008081), U64_C(0x8000000000008080),
  U64_C(0x0000000080000001), U64_C(0x8000000080008008),
};
/* The KECCAK-p[1600, 24] permutation, nr=24, 

The generalization of the KECCAK-f[b] permutations that is defined in NIST
Standard by converting the number of rounds nr to an input parameter
The set of values for the width b of the permutations is 
{25, 50, 100, 200, 400, 800, 1600}.

5x5 w=64 b=1600
5x5 w=32 b= 800

Пермутация \rho:
for (t=0; t<24; t++){
    s = (–(t+1)(t+2)/2) % 5;
    A_y[x] := ROTL(A_y[x]^D[x], s);
    {x, y} = {y, (2x+3y) % 5};
}

Rnd(A, ir) = ι(χ(π(ρ(θ(A)))), ir).
 */
static inline
uint64x5_t chi(uint64x5_t a){
    uint64x5_t a1 = __builtin_shufflevector(a, a, 1, 2, 3, 4, 0, 5,6,7);
    uint64x5_t a2 = __builtin_shufflevector(a, a, 2, 3, 4, 0, 1, 5,6,7);
    return (~a1 & a2)^a;
}
static inline
uint64x5_t theta(uint64x5_t a){
    uint64x5_t a0 = __builtin_shufflevector(a, a, 4, 0, 1, 2, 3, 5,6,7);
    uint64x5_t a1 = __builtin_shufflevector(a, a, 1, 2, 3, 4, 0, 5,6,7);
    return a0 ^ ((a1<<1)|(a1>>63));// ROTL(63)
}
/* pi: сдвиг и транспонирование матрицы 5x5
0, 3, 1, 4, 2,
1, 4, 2, 0, 3,
2, 0, 3, 1, 4,
3, 1, 4, 2, 0,
4, 2, 0, 3, 1,
*/
static inline
void pi_transpose(uint64x5_t *r, uint64x5_t r0, uint64x5_t r1,uint64x5_t r2,uint64x5_t r3,uint64x5_t r4){
    r0 = __builtin_shufflevector(r0, r0, 0, 3, 1, 4, 2, 5,6,7);// старшие 3 бита по маске 0x1F, не используются
    r1 = __builtin_shufflevector(r1, r1, 1, 4, 2, 0, 3, 5,6,7);
    r2 = __builtin_shufflevector(r2, r2, 2, 0, 3, 1, 4, 5,6,7);
    r3 = __builtin_shufflevector(r3, r3, 3, 1, 4, 2, 0, 5,6,7);
    r4 = __builtin_shufflevector(r4, r4, 4, 2, 0, 3, 1, 5,6,7);// -- заменил индексы
    register uint64x5_t t0, t1, t2, t3;
    t0 = __builtin_shufflevector(r0, r1, 0, 8, 2, 10, 4, 12, 6, 14);// unpacklo
    t1 = __builtin_shufflevector(r0, r1, 1, 9, 3, 11, 5, 13, 7, 15);// unpackhi
    t2 = __builtin_shufflevector(r2, r3, 0, 8, 2, 10, 4, 12, 6, 14);
    t3 = __builtin_shufflevector(r2, r3, 1, 9, 3, 11, 5, 13, 7, 15);

    r0 = __builtin_shufflevector(t0, t2, 0, 1, 8,  9, 4, 5, 12, 13);
    r1 = __builtin_shufflevector(t1, t3, 0, 1, 8,  9, 4, 5, 12, 13);
    r2 = __builtin_shufflevector(t0, t2, 2, 3,10, 11, 6, 7, 14, 15);
    r3 = __builtin_shufflevector(t1, t3, 2, 3,10, 11, 6, 7, 14, 15);
// эти сдвиги соответствуют транспонированию матрицы
    r[0] = __builtin_shufflevector(r0, r4, 0, 1, 2, 3, 8,  9,  10, 11);
    r[1] = __builtin_shufflevector(r1, r4, 0, 1, 2, 3, 9,  10, 11, 12);
    r[2] = __builtin_shufflevector(r2, r4, 0, 1, 2, 3, 10, 11, 12, 13);
    r[3] = __builtin_shufflevector(r3, r4, 0, 1, 2, 3, 11, 12, 13, 14);
    r[4] = __builtin_shufflevector(r0, r4, 4, 5, 6, 7, 12, 13, 14, 15);
}
static inline
uint64x5_t rho(uint64x5_t a, uint64x5_t s){
#ifdef __AVX512F__
    return (uint64x5_t)_mm512_rolv_epi64((__m512i)a, (__m512i)s);
#else
    return (a<<s)|(a>>(64-s));
#endif
}
static void print_state(char* title, uint64x5_t a0, uint64x5_t a1, uint64x5_t a2, uint64x5_t a3, uint64x5_t a4)
{
    printf("%s\n", title);
    int n = 0;
    uint8_t* s = (uint8_t*)&a0;
    for (int i=0; i<5*8; i++) {
        printf("%02x ", s[i]);
        if(n++ %16 == 15) printf("\n");
    }
    s = (uint8_t*)&a1;
    for (int i=0; i<5*8; i++) {
        printf("%02x ", s[i]);
        if(n++ %16 == 15) printf("\n");
    }
    s = (uint8_t*)&a2;
    for (int i=0; i<5*8; i++) {
        printf("%02x ", s[i]);
        if(n++ %16 == 15) printf("\n");
    }
    s = (uint8_t*)&a3;
    for (int i=0; i<5*8; i++) {
        printf("%02x ", s[i]);
        if(n++ %16 == 15) printf("\n");
    }
    s = (uint8_t*)&a4;
    for (int i=0; i<5*8; i++) {
        printf("%02x ", s[i]);
        if(n++ %16 == 15) printf("\n");
    }
    printf("\n");
}

static void KeccakF1600(uint64_t * s, int nr)
{
    register uint64x5_t A0, A1, A2, A3, A4;
#ifdef __AVX512F__
    __mmask8 mask = 0x1F;
    A0 = (uint64x5_t)_mm512_maskz_load_epi64(mask, s);
    A1 = (uint64x5_t)_mm512_maskz_load_epi64(mask, s+5);
    A2 = (uint64x5_t)_mm512_maskz_load_epi64(mask, s+10);
    A3 = (uint64x5_t)_mm512_maskz_load_epi64(mask, s+15);
    A4 = (uint64x5_t)_mm512_maskz_load_epi64(mask, s+20);
#else
    for (int i=0;i<5;i++) {
        A0[i] = s[i];
        A1[i] = s[i+5];
        A2[i] = s[i+10];
        A3[i] = s[i+15];
        A4[i] = s[i+20];
    }
#endif
    const uint64x5_t rh[5] = {// сдвиговые константы для rho
        { 0,  1, 62, 28, 27},
        {36, 44,  6, 55, 20},
        { 3, 10, 43, 25, 39},
        {41, 45, 15, 21,  8},
        {18,  2, 61, 56, 14}};

    for (int ir=0; ir<nr; ir++) {
        uint64x5_t D = theta(A0 ^ A1 ^ A2 ^ A3 ^ A4);
        if(0)print_state("After theta", A0^D, A1^D, A2^D, A3^D, A4^D);
// rho
        uint64x5_t r[5];
        A0 = rho(A0^D, rh[0]);
        A1 = rho(A1^D, rh[1]);
        A2 = rho(A2^D, rh[2]);
        A3 = rho(A3^D, rh[3]);
        A4 = rho(A4^D, rh[4]);
        if(0)print_state("After rho", A0, A1, A2, A3, A4);
// pi (permutation) вращение по кругу, сводится к пермутации строк и транспонированию 5x5
        pi_transpose(r, A0, A1, A2, A3, A4);
        if(0)print_state("After pi", r[0], r[1], r[2], r[3], r[4]);
// chi
        A0 = chi(r[0]);
        A1 = chi(r[1]);
        A2 = chi(r[2]);
        A3 = chi(r[3]);
        A4 = chi(r[4]);
        if(0)print_state("After chi", A0, A1, A2, A3, A4);
// iota
        A0[0] = A0[0] ^ RC[ir];
    }
    if(0) print_state("After Permutation", A0, A1, A2, A3, A4);
#ifdef __AVX512F__
    _mm512_mask_store_epi64(s   , mask, (__m512i)A0);
    _mm512_mask_store_epi64(s+5 , mask, (__m512i)A1);
    _mm512_mask_store_epi64(s+10, mask, (__m512i)A2);
    _mm512_mask_store_epi64(s+15, mask, (__m512i)A3);
    _mm512_mask_store_epi64(s+20, mask, (__m512i)A4);
#else
    for (int i=0;i<5;i++) {
        s[i   ] = A0[i];
        s[i+ 5] = A1[i];
        s[i+10] = A2[i];
        s[i+15] = A3[i];
        s[i+20] = A4[i];
    }
#endif
}

typedef uint64_t uint64x8_t __attribute__((__vector_size__(64)));// 512

/*! Заполнение буфера данными завершается меткой `0x04` для cSHAKE128. Последний байт 
всегда `0x80`.

SPONGE[f, pad, r](N, d):
Steps:
1. Let P=N || pad(r, len(N)).
2. Let n=len(P)/r.
3. Let c=b-r.
4. Let P0, … , Pn-1 be the unique sequence of strings of length r such that P = P0 || … || Pn1.
5. Let S=0^b.
6. For i from 0 to n-1, let S=f(S ⊕ (Pi|| 0^c)).
7. Let Z be the empty string.
8. Let Z=Z || Trunc_r(S).
9. If d≤|Z|, then return Trunc_d (Z); else continue.
10. Let S=f(S), and continue with Step 8.

Размер буфера всегда 200 байт, b=1600 бит. 

*/
static inline void _pad(uint8_t *buf, uint8_t CS, int r, size_t len){
    buf[len] ^= CS;// 0x06 для HASH, 0x04 для cSHAKE128, 0x1F для XOF
    buf[r-1] ^= 0x80;
}
/*! \brief метод для впитывания байтовой строки в губку буфера состояния. 
    \param S - буфер состояния
    \param data - входные данные
    \param len - длина входных данных в байтах
 */
static void absorb(uint64x8_t *S, const uint8_t *data, unsigned int len){
    uint64x8_t v;
    int i;
    for (i=0; i<len/sizeof(uint64x8_t); i++){
        __builtin_memcpy(&v, data, sizeof(uint64x8_t));
        S[i] ^= v;
        data+=sizeof(uint64x8_t);
    }
    len = len%sizeof(uint64x8_t);
    if (len){
        v ^= v;
        __builtin_memcpy(&v, data, len);
        S[i] ^= v;
    }
}
/*! \brief SPONGE - губка для кодирования (absorb) байтовой строки и генерации (squeeze). 

    Метод KECCAK[c] использует функцию KECCAK-p[1600, 24] для кодирования и генерации. 
    \param data - входные данные
    \param len - длина входных данных в байтах
    \param tag - выходные данные
    \param d  - длина выходных данных
    \param CS - метка для кодирования байтовой строки 0x06 - для SHA3, 0x1F - для SHAKE
    \param r - размер блока в байтах (b-c)/8
 */
static void _sponge(const uint8_t *data, size_t len, uint8_t *tag, int d, uint8_t CS, unsigned int r){
    //const unsigned int r = 168;
    __attribute__((aligned(64)))
    uint64x8_t S[256/(8*8)]={0};
    for (int i=0; i<len/r; i++, data+=r){// число целых блоков
        absorb(S, data, r);
        KeccakF1600((uint64_t*)S, 24);
    }
    if (len%r){
        absorb(S, data, len%r);
    }
    _pad((uint8_t*)S, CS, r, len%r);
    KeccakF1600((uint64_t*)S, 24);
    // отжим губки
    while (d>r) {
        __builtin_memcpy(tag, S, r);
        d -= r; tag += r;
        KeccakF1600((uint64_t*)S, 24);
    }
    __builtin_memcpy(tag, S, d);
}
/*! \brief SHAKE-256 eXtendable Output Function 
    \param data - входные данные
    \param len - длина входных данных в байтах
    \param tag - выходные данные
    \param d - длина выходных данных в байтах
 */
void shake256(const uint8_t *data, size_t len, uint8_t *tag, int d){
    _sponge(data, len, tag, d, 0x1F, 136);
}
/*! \brief SHAKE-128 eXtendable Output Function 
    \param data - входные данные
    \param len - длина входных данных в байтах
    \param tag - выходные данные
    \param d - длина выходных данных в байтах
 */
void shake128(const uint8_t *data, size_t len, uint8_t *tag, int d){
    _sponge(data, len, tag, d, 0x1F, 168);
}
/*! \brief SHA3-224 Hash Function 
    \param data - входные данные
    \param len - длина входных данных в байтах
    \param tag - выходные данные 224 бит
 */
void sha3_224(const uint8_t *data, size_t len, uint8_t *tag){
    _sponge(data, len, tag, 224/8, 0x06, 144);
}
/*! \brief SHA3-256 Hash Function 
    \param data - входные данные
    \param len - длина входных данных в байтах
    \param tag - выходные данные 256 бит
 */
void sha3_256(const uint8_t *data, size_t len, uint8_t *tag){
    _sponge(data, len, tag, 256/8, 0x06, 136);
}
/*! \brief SHA3-512 Hash Function 
    \param data - входные данные
    \param len - длина входных данных в байтах
    \param tag - выходные данные 512 бит
 */
void sha3_512(const uint8_t *data, size_t len, uint8_t *tag){
    _sponge(data, len, tag, 512/8, 0x06, 72);
}
/*! \brief SHA3-384 Hash Function 
    \param data - входные данные
    \param len - длина входных данных в байтах
    \param tag - выходные данные 384 бит
 */
void sha3_384(const uint8_t *data, size_t len, uint8_t *tag){
    _sponge(data, len, tag, 384/8, 0x06, 104);
}


/* Размер блока в байтах:
   (r)
// 168 = 160+8 8x4*5+8 SHAKE128
// 144 = 136+8 8x4*4+8x2 + 8 ?
// 136 = 128+8 8x4*4+8 SHA3-256 SHAKE256
// 104 =  96+8 8x4*3+8
//  72 =  64+8 8x4*2+8 SHA3-512
*/
#if 0//ndef TEST_SHA3
#include "hmac.h"
typedef struct _HashCtx HashCtx;
struct _HashCtx{
    uint64_t S[1600/(8*8)];
    unsigned int len; // длина сообщения в буфере
};
static void sha3_256_init(HashCtx* ctx) {
    __builtin_bzero(ctx->S, 1600/64);
    ctx->len = 0;
}
static void sha3_512_init(HashCtx* ctx) {
    __builtin_bzero(ctx->S, 1600/64);
    ctx->len = 0;
}

static void sha3_256_update(HashCtx* ctx, const uint8_t* msg, unsigned int mlen) {
    const unsigned int r = 136;
}
static void sha3_512_update(HashCtx* ctx, const uint8_t* msg, unsigned int mlen) {
    const unsigned int r = 72;
    if (ctx->len){
        if (mlen+ctx->len < r){
            absorb(ctx->S, ctx->len, msg, mlen);
            ctx->len += mlen;
            return;
        } else {
            unsigned int len = r -ctx->len;
            absorb(ctx->S, ctx->len, msg, len);
            KeccakF1600(ctx->S, 24);
            ctx->len = 0; 
            msg += len; mlen -= len;
            if (mlen==0) return;
        }
    }
    for(int i=0; i<mlen/r; i++, msg+=r){
        absorb(ctx->S, 0, msg, r);
        KeccakF1600(ctx->S, 24);
    }
    if (mlen%r){
        absorb(ctx->S, 0, msg, mlen%r);
        ctx->len += mlen%r;
    }
}

static void sha3_256_final(HashCtx* ctx, uint8_t* tag, unsigned int tlen) {
    _pad((uint8_t*)ctx->S, 0x06, 136, ctx->len);
    KeccakF1600(ctx->S, 24);
    __builtin_memcpy(tag, ctx->S, tlen);
}
static void sha3_512_final(HashCtx* ctx, uint8_t* tag, unsigned int tlen) {
    _pad((uint8_t*)ctx->S, 0x06, 72, ctx->len);
    KeccakF1600(ctx->S, 24);
    __builtin_memcpy(tag, ctx->S, tlen);
}

MESSAGE_DIGEST(MD_SHA3_256) {
    .id = MD_SHA3_256,
    .name = "SHA3-256",
    .block_len = 136,//64,
    .hash_len = 32,
    .ctx_size = sizeof(HashCtx),
    .init   = (void*)sha3_256_init,
    .update = (void*)sha3_256_update,
    .final  = (void*)sha3_256_final,
};
MESSAGE_DIGEST(MD_SHA3_512) {
    .id = MD_SHA3_512,
    .name = "SHA3-512",
    .block_len = 72,//64,
    .hash_len = 64,
    .ctx_size = sizeof(HashCtx),
    .init   = (void*)sha3_512_init,
    .update = (void*)sha3_512_update,
    .final  = (void*)sha3_512_final,
};
#endif

#include <stdio.h>
static void print_hash(const char* title, uint8_t* tag, int len);

/* Синтез алгоритма KECCAK-p[1600, 24]
 C[x] = A[x, 0] ⊕ A[x, 1] ⊕ A[x, 2] ⊕ A[x, 3] ⊕ A[x, 4], x = 0…4;
 D[x] = C[x — 1] ⊕ (С[x + 1] >>> 1), x = 0…4;
 A[x, y] = A[x, y] ⊕ D[x],           x = 0…4, y = 0…4;
 // cдвиг и транспонирование 5x5:
 B[y, 2x + 3y] = A[x, y] >>> r[x, y], x = 0…4, y = 0…4;
 A[x, y] = B[x, y] ⊕ (~B[x + 1, y] & B[x + 2, y]), x = 0…4, y = 0…4, 

*/
int main(int argc, char** argv)
{
    const int w = 32;// разрядность
    int x=1, y=0, s;
    printf("// theta:\n");
    for (int x=0; x<5; x++)
        printf("\tC[%d] = A0[%d] ^ A1[%d] ^ A2[%d] ^ A3[%d] ^ A4[%d];\n", x, x, x, x, x, x);
    printf("\n");
    for (int x=0; x<5; x++)
        printf("\tD[%d] = C[%d] ^ ROTR(C[%x], 1);\n", x, (x-1+5)%5, (x+1)%5);
    printf("// rho:\n");
    for (int t=0; t<24; t++){
        s = -(t+1)*(t+2)/2;
        s = s % w;
        if (s<0) s+=w;
        printf("\tB%d[%d] = ROTR(A%d[%d]^D[%d], %d);\n", y, x, y, x, x, s);
        s = y;
        y = (2*x+3*y) % 5;
        x = s;
    }
    y =0, x=0, s=0;
    printf("\tB%d[%d] = ROTR(A%d[%d]^D[%d], %d);\n", y, x, y, x, x, s);
    printf("// pi:\n");
// A′[x, y, z]=A[(x + 3y) mod 5, x, z].
    for (int x=0; x<5; x++){
        for (int y=0; y<5; y++){
            //printf("\tA%d[%d] = r[%d][%d];\n", y, x, x, (3*y+x)%5);
            printf("%d, ", (3*y+x)%5);
        }
        printf("\n");
    }
    for (int y=0; y<5; y++)
    for (int x=0; x<5; x++)
            printf("\tA%d[%d] = B%d[%d];\n", y, x, x, (3*y+x)%5);

// A′[x, y,z] = A[x, y,z] ⊕ ((A[(x+1) mod 5, y, z] ⊕ 1) ⋅ A[(x+2) mod 5, y, z]).
    printf("// xi:\n");
    for (int y=0; y<5; y++){
        for (int x=0; x<5; x++){
            printf("\tA%d[%d] = A%d[%d] ^ (~A%d[%d] & A%d[%d]);\n", y, x, y, x, y, (x+1)%5, y, (x+2)%5);
        }
    }

    uint64_t S[25] = {// SHA3-512("",0)
        0x0000000000000006, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 
        0x8000000000000000, 
    };
    KeccakF1600((uint64_t*)S, 24);
    unsigned tlen = 512;
    uint8_t tag[512];
    shake256((uint8_t*)"", 0, tag, tlen); 
    print_hash("SHAKE256 XOF(512)", tag, tlen);
    // valid tag
    // 46 B9 DD ... 3E EB 24
    // 1F D1 66 ... E2 7F 2A
    printf("\n");
    shake128((uint8_t*)"", 0, tag, tlen); 
    print_hash("SHAKE128 XOF(512)", tag, tlen);
    // valid 
    // 7F 9C 2B ... 05 85 3E
    // DD A2 52 ... 29 0B 6F
    sha3_224((uint8_t*)"", 0, tag); 
    print_hash("SHA3-224 Hash(0)", tag, 224/8);
/* Hash val is
    6B 4E 03 42 36 67 DB B7 3B 6E 15 45 4F 0E B1 AB
    D4 59 7F 9A 1B 07 8E 3F 5B 5A 6B C7 */
    sha3_256((uint8_t*)"", 0, tag); 
    print_hash("SHA3-256 Hash(0)", tag, 256/8);
/* Hash val is
    A7 FF C6 F8 BF 1E D7 66 51 C1 47 56 A0 61 D6 62
    F5 80 FF 4D E4 3B 49 FA 82 D8 0A 4B 80 F8 43 4A */
    sha3_384((uint8_t*)"", 0, tag); 
    print_hash("SHA3-384 Hash(0)", tag, 384/8);
/* Hash val is
    0C 63 A7 5B 84 5E 4F 7D 01 10 7D 85 2E 4C 24 85
    C5 1A 50 AA AA 94 FC 61 99 5E 71 BB EE 98 3A 2A
    C3 71 38 31 26 4A DB 47 FB 6B D1 E0 58 D5 F0 04 */
    sha3_512((uint8_t*)"", 0, tag); 
    print_hash("SHA3-512 Hash(0)", tag, 512/8);
/* Hash val is
    A6 9F 73 CC A2 3A 9A C5 C8 B5 67 DC 18 5A 75 6E
    97 C9 82 16 4F E2 58 59 E0 D1 DC C1 47 5C 80 A6
    15 B2 12 3A F1 F5 F9 4C 11 E3 E9 40 2C 3A C5 58
    F5 00 19 9D 95 B6 D3 E3 01 75 85 86 28 1D CD 26 */
    uint8_t dataA3[1600/8] = { [0 ... 199]= 0xA3};
    sha3_224(dataA3, 1600/8, tag); 
    print_hash("SHA3-224 Hash(1600/8)", tag, 224/8);
/* Hash val is
    93 76 81 6A BA 50 3F 72 F9 6C E7 EB 65 AC 09 5D
    EE E3 BE 4B F9 BB C2 A1 CB 7E 11 E0 */
    sha3_256(dataA3, 1600/8, tag); 
    print_hash("SHA3-256 Hash(1600/8)", tag, 256/8);
/* Hash val is
    79 F3 8A DE C5 C2 03 07 A9 8E F7 6E 83 24 AF BF
    D4 6C FD 81 B2 2E 39 73 C6 5F A1 BD 9D E3 17 87 */
    sha3_384(dataA3, 1600/8, tag); 
    print_hash("SHA3-384 Hash(1600/8)", tag, 384/8);
/* Hash val is
    18 81 DE 2C A7 E4 1E F9 5D C4 73 2B 8F 5F 00 2B
    18 9C C1 E4 2B 74 16 8E D1 73 26 49 CE 1D BC DD
    76 19 7A 31 FD 55 EE 98 9F 2D 70 50 DD 47 3E 8F  */
    sha3_512(dataA3, 1600/8, tag); 
    print_hash("SHA3-512 Hash(1600/8)", tag, 512/8);
/* Hash val is
    E7 6D FA D2 20 84 A8 B1 46 7F CF 2F FA 58 36 1B
    EC 76 28 ED F5 F3 FD C0 E4 80 5D C4 8C AE EC A8
    1B 7C 13 C3 0A DF 52 A3 65 95 84 73 9A 2D F4 6B
    E5 89 C5 1C A1 A4 A8 41 6D F6 54 5A 1C E8 BA 00 */
    return 0;
}
static void print_hash(const char* title, uint8_t* tag, int len){
    printf("%s:\n", title);
    int i;
    for (i=0; i<len; i++) {
        printf("%02X ", tag[i]);
        if (i%16==15) printf("\n");
    }
    if (i%16) printf("\n");
}
