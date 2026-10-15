/*! multipreciscion arithmetic
 */
#ifndef MP_H_INCLUDED
#define MP_H_INCLUDED
#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#if 1 //DEBUG_ECC

#include "r3_slice.h"
#else
#include <glib.h>
#endif
// TODO выделить операции с лимбами
//typedef BNuint   BNlimb __attribute__((__vector_size__(BN_ALIGN_BYTES)));
#if 0 //defined(__x86_64__)
#warning under development
    typedef uint64_t BNuint;
    typedef int64_t  BNint;
    #define BN_BIT_LOG 6 // 64=2^6
    #define BN_ALIGN_BYTES  16
    #define BN_SWAP(x)  __builtin_bswap64(x)
    #define BN_CTZ(x)   __builtin_ctzll(x)
    #define BN2(a,b)    ((uint64_t)(a) | ((uint64_t)(b)<<32))
#else
    typedef uint32_t BNuint;
    typedef int32_t  BNint;
    #define BN_BIT_LOG 5 // 32=2^5
    #define BN_ALIGN_BYTES  16
    #define BN_SWAP(x)  __builtin_bswap32((x))
    #define BN_CTZ(x)   __builtin_ctz(x)
    #define BN2(a,b)    a,b
#endif

#define BN_BITS (sizeof(BNuint)<<3)
#define BN_ALIGN_BITS   (BN_ALIGN_BYTES<<3)
#define BN_BYTE_LOG (BN_BIT_LOG-3)
#define BN_MASK ((1UL<<BN_BIT_LOG)-1)

#define BN_ALIGN __attribute__((aligned(BN_ALIGN_BYTES)))

/*! \return размер вектора в блоках
 */
static inline int  bn_size (int nbits) { return (nbits+(BN_BITS - 1))>>BN_BIT_LOG; }
static inline int  bn_aligned_size (int nbits) { return ((nbits+(BN_ALIGN_BITS - 1))/BN_ALIGN_BITS)*(BN_ALIGN_BYTES/sizeof(BNuint)); }

/*! \brief Выделяет память для хранения большого числа метожом slice
    \param size - размер в блоках (32,64) бит
 */
static inline BNuint* bn_alloc(int size)
{
    return g_slice_alloc(size<<BN_BYTE_LOG);
}
static inline void bn_free1(int size, BNuint* bn)
{
    return g_slice_free1(size<<BN_BYTE_LOG, bn);
}

//static inline
#if 1// defined(__i386__)
BNuint bn_add (BNuint * r, BNuint * a, BNuint * b, int n);
#else
static inline BNuint bn_add (BNuint * r, BNuint * a, BNuint * b, int n)
{
    BNuint cy = 0;
    int i;
    for (i=0; i<n; i++) {
        register uint64_t t = (uint64_t)a[i] + b[i] + cy;
        r[i] = t;
        cy = t >> BN_BITS;
    }
    return cy;
}
#endif
#if 1 // азм медленно работает
BNuint bn_add1 (BNuint * r, BNuint * a, int n);
#else
static inline BNuint bn_add1 (BNuint * r, BNuint * a, int n)
{
    BNuint cy = 0;
    int i;
    for (i=0; i<n; i++) {
        register __int64 t = (unsigned __int64)r[i] + a[i] + cy;
        r[i] = t;
        cy = t >> BN_BITS;
    }
    return cy;
}
#endif

//static inline void bn_shr1 (BNuint * r, BNuint cy, int n);
//static inline void bn_shrl (BNuint * r, BNuint * q, BNuint cy, const int len, int n);
//static inline void bn_shrB (BNuint * r, BNuint * q, int len, int n);

static inline int  bn_bit_test(BNuint * q, int n){return  (q[n>>BN_BIT_LOG] & (1UL<<(n&BN_MASK)))!=0; }
static inline int  bn_bit_val (BNuint * q, int n){return  (q[n>>BN_BIT_LOG] & (1UL<<(n&BN_MASK)))>>(n&BN_MASK); }
static inline void bn_bit_set (BNuint * q, int n){ q[n>>BN_BIT_LOG] |=  (1UL<<(n&BN_MASK)); }
static inline void bn_bit_clr (BNuint * q, int n){ q[n>>BN_BIT_LOG] &= ~(1UL<<(n&BN_MASK)); }

static inline void bn_shrB (BNuint * r, int len, int n)
{
    int i;
    for (i=0; i<n-len; i++) {
        r[i] = r[len+i];
    }
    for (   ; i<n; i++) {
        r[i] = 0;
    }
//    return cy;
}

/*! \brief Арифметический сдвиг в право с учетом переноса (деление на 2)
 */
static inline void bn_shrl (BNuint * r, BNuint cy, int len, int n)
{
    BNuint lo = r[0];
//    int i;
//    for (i=0; i<n-1; i++) {
//        r[i] = (lo>>len) | (q[i+1]<<(BN_BITS-len));
    n--;
    while (n&~3) {
        r[0] = (lo>>len) | (r[1]<<(BN_BITS-len));
//        lo = q[1];
        r[1] = (r[1]>>len) | (r[2]<<(BN_BITS-len));
//        lo = q[2];
        r[2] = (r[2]>>len) | (r[3]<<(BN_BITS-len));
//        lo = q[3];
        r[3] = (r[3]>>len) | (r[4]<<(BN_BITS-len));
        lo = r[4];
        r+=4, n-=4;
    }
    if (n&2) {
        r[0] = (lo>>len) | (r[1]<<(BN_BITS-len));
//        lo = q[1];
        r[1] = (r[1]>>len) | (r[2]<<(BN_BITS-len));
        lo = r[2];
        r+=2;
    }
    if (n&1) {
        r[0] = (lo>>len) | (r[1]<<(BN_BITS-len));
        lo = r[1];
        r++;
    }
    r[0] = (lo>>len)| (cy<<(BN_BITS-len));
}
static inline void bn_shr1 (BNuint * r, BNuint cy, int n)
{
    BNuint hi = r[--n];
    r[n] = hi>>1 | (cy<<(BN_BITS-1));;
    while(n--) {
        register BNuint lo = r[n];
        r[n] = (lo>>1) | (hi<<(BN_BITS-1));
        hi = lo;
    }
}

static inline void bn_shr  (BNuint * r, int len, int n)
{
    if (len&~BN_MASK) bn_shrB (r, len>>BN_BIT_LOG, n);
    len &=BN_MASK;
    if (len>0 ) bn_shrl (r, 0, len, n);
}

/*! \brief сравнение двух больших чисел
    \return true если числа равны
 */
static inline int bn_equ(BNuint *x, BNuint *r, int len)
{
    int i;
    for (i=0; i<len; i++) {
        if (x[i] != r[i]) return false;
    }
    return true;
}
/*! \brief блочный сдвиг большого числа влево на 32 бита
    \return перенос (32 бита)
 */
static inline BNuint bn_shlB (BNuint * r, int n)
{
#if 1
    int i;
    BNuint cy = r[n-1];
    for (i=n-1; i>0; i--) r[i] = r[i-1];
    //__builtin_memmove(r+1, r,(n-1)<<BN_BYTE_LOG);
    r[0]=0;
#elif 0
    BNuint cy=0;
    BNuint hi;
    int i;
    for (i=0; i<n; i++) {
        hi = q[i];  r[i] =cy; cy = hi;
    }
#else
    BNuint cy = q[n-1];
    while (n >4){
        r[n-1] = q[n-2];
        r[n-2] = q[n-3];
        r[n-3] = q[n-4];
        r[n-4] = q[n-5];
        n-=4;
    }
    if (n & 2){
//        (v2si)&r[n-1] = (v2si)&q[n-2];
        r[n-1] = q[n-2];
        r[n-2] = q[n-3];
        n-=2;
    }
    if (n&1) {
        r[n-1] = q[n-2];
    }
    r[0] = 0;
#endif
    return cy;
}
/*! \brief сдвиг большого числа влево на указанное число разрядов
    \return перенос
 */
static inline BNuint bn_shl (BNuint * r, BNuint * q, int len, int n)
{
    register BNuint cy = 0;
    register BNuint b;
    while (n &~3){
        b = (q[0] << len) | cy;
        cy = q[0] >> (BN_BITS-len), r[0] = b;
        b = (q[1] << len) | cy;
        cy = q[1] >> (BN_BITS-len), r[1] = b;
        b = (q[2] << len) | cy;
        cy = q[2] >> (BN_BITS-len), r[2] = b;
        b = (q[3] << len) | cy;
        cy = q[3] >> (BN_BITS-len), r[3] = b;
        r+=4, q+=4, n-=4;
    }
    if (n & 2){
        b = (q[0] << len) | cy;
        cy = q[0] >> (BN_BITS-len), r[0] = b;
        b = (q[1] << len) | cy;
        cy = q[1] >> (BN_BITS-len), r[1] = b;
        r+=2, q+=2;//, n+=2;
    }
    if (n&1) {
        b = (q[0] << len) | cy;
        cy = q[0] >> (BN_BITS-len), r[0] = b;
    }
    return cy;
}

static inline void bn_print (BNuint* x, int n)
{
    while (n--) {
        printf ("%08X", x[n]);
    }
}

typedef struct _MPValue MPValue;
typedef struct _MPCtx MPCtx;

struct _MPValue {
    BNuint* value;
};
typedef void (*MPReduction)(const MPCtx * const ctx, BNuint *mp, BNuint cy);

struct _MPCtx {
    MPReduction reduction; //!< функция быстрого редуцирования
    BNuint *prime;      //!< field prime модуль
//    BNuint *_prime;
    int size;           //!< число блоков в BNuint (big-number)
    int asize;          //!< размер с учетом выравнивания
};


static inline MPCtx* mp_ctx_new(int nbits)
{
    MPCtx* ctx = malloc(sizeof(MPCtx));
    ctx->size  = bn_size (nbits);
    ctx->asize = bn_aligned_size (nbits);
    ctx->prime = bn_alloc(ctx->asize);
//    ctx->_prime=NULL;
    return ctx;
}
static inline void mp_ctx_free(MPCtx* ctx)
{
    bn_free1(ctx->asize, ctx->prime);
    free(ctx);
}
static inline BNuint*  mp_new(MPCtx* ctx)
{
    return bn_alloc(ctx->asize);
}

static inline void  mp_alloc(MPCtx* ctx, MPValue* mp)
{
    mp->value = bn_alloc(ctx->asize);
}

static inline void mp_free(MPCtx* ctx, BNuint* bn)
{
    if (bn) bn_free1(ctx->asize, bn);
}

static inline void mp_free1(MPCtx* ctx, MPValue* mp)
{
    if (mp->value) bn_free1(ctx->asize, mp->value);
}

static inline void bn_move (BNuint* d, BNuint * s, int n)
{    //int i;
#if 1
    __builtin_memcpy(d,s,n*sizeof(BNuint));
#else
    while(n&~3){
//        __builtin_memcpy(d,s,4*sizeof(BNuint));
        d[0] = s[0], d[1] = s[1];
        d[2] = s[2], d[3] = s[3];
        d+=4, s+=4, n-=4;
    }
    if (n&2){
//        __builtin_memcpy(d,s,2*sizeof(BNuint));
        d[0] = s[0], d[1] = s[1];
        d+=2, s+=2;
    }
    if (n&1) d[0] = s[0];
#endif
}
static inline void bn_set_ui (BNuint* x, BNuint v, int n)
{
    x[0] = v;
//    int i; for (i=1; i<n; i++) x[i] = 0;
    __builtin_bzero(&x[1], (n-1)<<BN_BYTE_LOG);
}
static inline void bn_set_0(BNuint* d, int n)
{
//    int i; for (i=0; i<n; i++) x[i] = 0;
    __builtin_bzero(d, n<<BN_BYTE_LOG);
}
static inline void bn_set_1(BNuint* x, int n)
{
    x[0] = 1;
//    int i; for (i=1; i<n; i++) x[i] = 0;
    __builtin_bzero(&x[1], (n-1)<<BN_BYTE_LOG);
}

static inline int bn_is_zero(BNuint* x, int n)
{
    int i;
    for (i=0; i<n; i++) {
        if (x[i]!=0) return false;
    }
    return true;
}
/*! \brief числа сравнение с единицей
 */
static inline int bn_is_one(BNuint* x, int n)
{
    if (x[0]!=1) return false;
    int i;
    for (i=1; i<n; i++) {
        if (x[i]!=0) return false;
    }
    return true;
}

void mp_hex2bin (MPCtx* ctx, MPValue* mp, const char* s);
const char* bn_hex2bin (BNuint * bn, int n, const char* s);
void bn_revert  (BNuint*bn, int n);
void mp_revert  (MPCtx* ctx, MPValue* mp);
/*
static inline void bn_revert(MPCtx* ctx, BNuint* bn, int n)
{
    BNuint * src = bn + n;
    BNuint * dst = bn;
    n>>=1;
    do {
        BNuint t = *dst;
        *dst++ = *--src;
        *src = t;
    } while (--n);
}*/

/*! \brief Сложение двух больших чисел
    \param r - результат r = a+b
    \param a - слагаемое
    \param b - слагаемое
    \param n - разрядность (32 битных слов)
    \return перенос
 */
#define ADD(a,b)    ({ uint32_t ac;\
    asm ("addl   %1, %0   \n" :"=&r"(ac):"g"(b),"0"(a) :"cc" );\
    ac;})
#define ADC(a,b)    ({ uint32_t ac;\
    asm ("adcl   %1, %0   \n" :"=&r"(ac):"g"(b),"0"(a) :"cc" );\
    ac;})
#if 1
BNint bn_sub (BNuint * r, BNuint * a, BNuint *b, int n);
#else
static inline BNint bn_sub (BNuint * r, BNuint * a, BNuint *b, int n)
{
    BNint cy = 0;
    int i;
    for (i=0; i<n; i++) {
        int64_t t = (uint64_t)a[i] - b[i] + cy;
        cy = t >> BN_BITS;
        r[i] = t;
    }
    return cy;
}
#endif // 0
#if 0
BNint bn_sub1(BNuint * r, BNuint *b, int n);
#else
/*
#include <x86intrin.h>
static inline
BNint bn_sub1_ (BNuint * r, BNuint *b, int n)
{// не работает
    unsigned char cy = 1;
    int i;
    for (i=0; i<n; i++) {
        cy = _subborrow_u32(cy, r[i], b[i], &r[i]);
    }
    uint32_t res =0;
    _subborrow_u32(cy, res, res, &res);
    return res;
}*/
static inline void bn_set_neg (BNuint * r, BNuint *b, int n)
{
    int i;
    for (i=0; i<n; i++) {
        r[i] = ~b[i];
    }
    r[0]++;
}
static inline BNint bn_sub1 (BNuint * r, BNuint *b, int n)
{
    register __int64 ac = 0;
    int i;
    for (i=0; i<n; i++) {
        ac += (unsigned __int64)r[i] - (unsigned __int64)b[i];
        r[i] = (BNuint)ac;
        ac = ac >> BN_BITS;
    }
    return (BNint)ac;
}
#endif

static inline int32_t bn_sub_ui (BNuint * r, BNuint * a, BNuint cx, const int n)
{
    register __int64 t = (unsigned __int64)a[0] - (unsigned __int64)cx;
    r[0] = t;
    int32_t cy= t>>BN_BITS;
    int i;
    for (i=1; i<n && cy!=0; i++) {
        register __int64 t = (unsigned __int64)a[i] + cy;
        r[i] = t;
        cy = t >> BN_BITS;
    }
    return cy;
}
static inline BNuint bn_add_ui (BNuint * r, BNuint * a, BNuint cy, const int n)
{
    int i;
    for (i=0; i<n /*&& cy!=0*/; i++) {
        uint64_t t = (uint64_t)a[i] + cy;
        r[i] = t;
        cy = t >> BN_BITS;
    }
    return cy;
}

/*! \brief умножение большого числа на целое число (32 bit)

    Операция используется как основа для умножения чисел произвольной длины
    \param r - результат умножения r=q*d
    \param q - целое большое число
    \param d - целое число 32 бит
    \param n - разрядность числа
    \return переполнение (старшая часть числа, 32 бит) при умножении чисел
 */
#if 1
//BNuint bn_mul_ui(BNuint* r, BNuint *q, BNuint d, int n);

#if 0 /* 32-bit limb: scaled uint64 body is not this step */
#define mul(r,a,b,cy) do{ \
    register uint64_t hi, lo;   \
    __asm ("mulq %3"   \
         :"=a"(lo),"=d"(hi) \
         :"a"(b),"g"(a) \
         :"cc" );   \
    __asm ("addq %2, %0; adcq %3,%1"    \
         :"+r"(cy),"+d"(hi) \
         :"a"(lo),"g"(0)    \
         :"cc");    \
    (r) = cy, cy = hi;        \
    } while (0)
static inline uint32_t bn_mul_ui(uint64_t* r, uint64_t *a, uint32_t d, int n)
{
    register uint64_t cy = 0;
    while (n&~7){
        mul(r[0], a[0], d, cy);
        mul(r[1], a[1], d, cy);
        mul(r[2], a[2], d, cy);
        mul(r[3], a[3], d, cy);
        r+=4, a+=4, n-=8;
    }
    if (n&4){
        mul(r[0], a[0], d, cy);
        mul(r[1], a[1], d, cy);
        r+=2, a+=2;
    }
    if (n&2){
        mul(r[0], a[0], d, cy);
        r+=1, a+=1;
    }

/*    if (n) {
        mul(r[0], a[0], d, cy); if ((n-=2)<=0) return cy;
        mul(r[1], a[1], d, cy); if ((n-=2)<=0) return cy;
        mul(r[2], a[2], d, cy);
    }*/
    return cy;
}
#else // if defined(__i386__)
#include <x86intrin.h>
#define MUL(lo,hi, a,w) ({    \
            uint64_t r = (uint64_t)(a)*(w); \
            lo = r, hi = r>>32; \
        });

#define mul_(r,a,b,cy) do{ \
    register uint32_t hi, lo;   \
    __asm ("mull %3"   \
         :"=a"(lo),"=d"(hi) \
         :"a"(b),"r"(a) \
         :"cc" );   \
    __asm ("add %2, %0; adc %3,%1"    \
         :"+r"(cy),"+d"(hi) \
         :"a"(lo),"g"(0)    \
         :"cc");    \
    (r) = cy, cy = hi;        \
    } while (0)
#define mul(r,a,b,cy) do{ \
    register uint32_t hi, lo;   \
    MUL(lo,hi, a, b); \
    __asm ("add %2, %0; adc %3,%1"    \
         :"+r"(cy),"+d"(hi) \
         :"a"(lo),"g"(0)    \
         :"cc");    \
    (r) = cy, cy = hi;        \
    } while (0)

static inline
uint32_t bn_mul_ui_1(uint32_t* r, uint32_t *a, uint32_t d, int n)
{
    register uint32_t cy = 0;
    int i;
#pragma GCC unroll 4
    for(i=0; i< n; i++){
        uint64_t r0 = a[i]*(uint64_t)d + cy;
        r[i] = r0, cy = r0>>32;
    }
    return cy;
}
static inline
uint32_t bn_mac_ui_1(uint32_t* r, uint32_t *a, uint32_t d, int n)
{
    register uint32_t cy = 0;
    int i;
#pragma GCC unroll 4
    for(i=0; i< n; i++){
        uint64_t r0 = a[i]*(uint64_t)d + r[i]+ cy;
        r[i] = r0, cy = r0>>32;
    }
    return cy;
}
static inline uint32_t bn_mul_ui(uint32_t* r, uint32_t *a, uint32_t d, int n)
{
    register uint32_t cy = 0;
    while (n&~3){
        mul(r[0], a[0], d, cy);
        mul(r[1], a[1], d, cy);
        mul(r[2], a[2], d, cy);
        mul(r[3], a[3], d, cy);
        r+=4, a+=4, n-=4;
    }
    if (n&2) {
        mul(r[0], a[0], d, cy);
        mul(r[1], a[1], d, cy);
        r+=2, a+=2;
    }
    if (n&1){
        mul(r[0], a[0], d, cy);
    }
    return cy;
}
#endif

#else
static inline BNuint bn_mul_ui(BNuint* r, BNuint *q, BNuint d, int n)
{
    BNuint cy = 0;
    int i;
    for (i=0; i<n; i++){
        register uint64_t t = (uint64_t)q[i]*d + cy;
        r[i] = t;
        cy = t>>BN_BITS;
    }
    return cy;
}
#endif
/*! \brief multiply accumulate
    r = r+ q*d
 */
#if 0
BNuint bn_mac_ui(BNuint* r, BNuint *q, BNuint d, int n);
#else
static inline
BNuint bn_mac_ui(BNuint* r, BNuint* q, BNuint d, int n)
{
    BNuint cy = 0;
    int i;
    for (i=0; i<n; i++){
        register uint64_t t = (uint64_t)q[i]*d + (uint64_t)r[i] + cy;
        r[i] = t;
        cy = t>>BN_BITS;
    }
    return cy;
}
#endif
//uint32_t bn_mul   (uint32_t* r, uint32_t *a, uint32_t* b, int len);
/*! \brief сравнение больших чисел
    \return TRUE если x <= r
*/
static inline int bn_le(BNuint *x, BNuint *r, int n)
{
    while (--n) {
        if (x[n]!=r[n]) break;
    }
    return x[n] <= r[n];
}

/*! модульная арифметика */
void mp_addm(const MPCtx* const ctx, BNuint* r, BNuint* a, BNuint* b);
void mp_subm(const MPCtx* const ctx, BNuint* r, BNuint* a, BNuint* b);
void mp_mulm(const MPCtx* const ctx, BNuint* r, BNuint* a, BNuint* b);
void mp_mulm_ui(const MPCtx* const ctx, BNuint* r, BNuint* a, BNuint b);
void mp_dubm(const MPCtx* const ctx, BNuint* q, BNuint* x);
void mp_modp(const MPCtx* const ctx, BNuint* q, BNuint* x);
void mp_invm(const MPCtx* const ctx, BNuint* q, BNuint* x);
void mp_srtm(const MPCtx* const ctx, BNuint* q, BNuint* x);
void mp_divm(const MPCtx* const ctx, BNuint* q, BNuint* a, BNuint* b);
/*! \brief Возведение в квадрат q = s*s (mod p)
    \param ctx контекст простого числа
    \param q результат операции
    \param s

 */
static inline void mp_sqrm(const MPCtx* const ctx, BNuint* q, BNuint* s)
{
    mp_mulm (ctx, q, s,s);
}
static inline void mp_hlvm(const MPCtx* const ctx, BNuint* x)
{
    BNuint cy =0 ;
//    int ctz = __builtin_ctz(ctx->prime[0]);
    if (x[0]&1){
        cy = bn_add1(x, ctx->prime, ctx->size);
    }
    bn_shr1 (x, cy, ctx->size);
}
#endif

