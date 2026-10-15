/*! Multiprecision library
 */
#include <inttypes.h>
//#include "r3_slice.h"
#include "mp.h"
#include <stdio.h>
/*! \brief Преобразует строку в большое число
    Выделяет память под большое число
 */
void mp_hex2bin (MPCtx* ctx, MPValue* mp, const char* s)
{
    int sign = 0;
    if (s[0]=='-') sign = 1, s++;
    if (s[0]=='0' && s[1]=='x') s+=2;
//    int size = ((nbits + 63)>>6);
//    MPValue* mp = mp_new(size);
//    mp_alloc(ctx, mp);
//    mp_clr  (ctx, mp);
    int i;
    BNuint  val = 0;
    BNuint* value = mp->value + ctx->size;
    for (i=0; i< (ctx->size<<(BN_BIT_LOG-2)) && s[i]!='\0'; i++) {
        while (s[i]==' ') s++;
        if ('0' <= s[i] && s[i]<='9') val= (val<<4) | (s[i] - '0');
        else
        if ('A' <= s[i] && s[i]<='F') val= (val<<4) | (s[i] - 'A' + 10);
        else
        if ('a' <= s[i] && s[i]<='f') val= (val<<4) | (s[i] - 'a' + 10);
        // иначе пропускаем символ, например пропускаем пробелы и переносы строк
        if ((i & (BN_MASK>>2)) == (BN_MASK>>2)) {
            *(--value) = val;
            val = 0;
        }
    }
    if (i< (ctx->size<<(BN_BIT_LOG-2))) {
//        val<<=BN_BITS - (i&(BN_MASK>>2))*4;
        *(--value) = val;//<<(((ctx->size<<(BN_BIT_LOG-2))-i)<<2) ;
        int offset = value - mp->value;
        if (offset){
            for (i=0; i< (ctx->size - offset); i++){
                mp->value[i] = mp->value[i+offset];
            }
            for (   ; i<ctx->size; i++){
                mp->value[i] = 0;
            }
        }
    }
//    return mp;
}
const char* bn_hex2bin (uint32_t* bn, int n, const char* s)
{
    if (s[0]=='0' && s[1]=='x') s+=2;
//    int size = ((nbits + 63)>>6);
//    MPValue* mp = mp_new(size);
//    mp_alloc(ctx, mp);
//    mp_clr  (ctx, mp);
    int i;
    BNuint  val = 0;
    BNuint* value = bn + n;
    for (i=0; i< (n<<(BN_BIT_LOG-2)) && s[i]!='\0'; i++) {
        while (s[i]==' ') s++;
        if ('0' <= s[i] && s[i]<='9') val= (val<<4) | (s[i] - '0');
        else
        if ('A' <= s[i] && s[i]<='F') val= (val<<4) | (s[i] - 'A' + 10);
        else
        if ('a' <= s[i] && s[i]<='f') val= (val<<4) | (s[i] - 'a' + 10);
        // иначе пропускаем символ, например пропускаем пробелы и переносы строк
        if ((i & (BN_MASK>>2)) == (BN_MASK>>2)) {
            *(--value) = val;
            val = 0;
        }
    }
    if (i< (n<<(BN_BIT_LOG-2))) {
//        val<<=BN_BITS - (i&(BN_MASK>>2))*4;
        *(--value) = val;//<<(((ctx->size<<(BN_BIT_LOG-2))-i)<<2) ;
        int offset = value - bn;
        if (offset){
            for (i=0; i< (n - offset); i++){
                bn[i] = bn[i+offset];
            }
            for (   ; i<n; i++){
                bn[i] = 0;
            }
        }
    }
    return &s[i];
}
void mp_revert(MPCtx* ctx, MPValue* mp)
{
    uint8_t * src = (uint8_t*)(mp->value + ctx->size);
    uint8_t * dst = (uint8_t*) mp->value;
    int count = ctx->size*(sizeof(BNuint)/2);
    do {
        uint8_t t = *dst;
        *dst++ = *--src;
        *src = t;
    } while (--count);
}
void bn_revert0(BNuint* mp, int count)
{
    uint8_t * src = (uint8_t*)(mp + count);
    uint8_t * dst = (uint8_t*) mp;
    count*=sizeof(BNuint);
    count >>= 1;
    while (count--) {
        uint8_t t = *dst;
        *dst++ = *--src;
        *src = t;
    }
}
void bn_revert(BNuint* mp, int count)
{
    BNuint * src = mp + count;
    BNuint * dst = mp;
    if (count&1) {
         count >>= 1;
        dst[count] = BN_SWAP(dst[count]);
    } else count >>= 1;
    while (count--) {
        BNuint t = BN_SWAP(*dst);
        *dst++ = BN_SWAP(*--src);
        *src = (t);
    }
}

/* надо чтобы допускалось сложение 64 битное
static inline uint64_t bn_uadd_ui(uint64_t* x, uint64_t b, int len)
{
    int i;
    for (i=0; i<len; i++) {
        const uint64_t a = b + (x[i]<<32>>32);
        b = (a>>32) + (x[i]>>32);
        x[i] = (a<<32>>32) | b<<32;
        b>>=32;
    }
    return b;
}
 */

/*
static inline uint64_t bn_shl32(uint64_t* x, int len)
{
    uint64_t b=0;
    int i;
    for (i=0; i<len; i++) {
        uint64_t a = x[i];
        x[i] = a<<32 | b;
        b = a>>32;
    }
    return b;
}
*/
/*
static inline uint64_t bn_uadd(uint64_t *x, uint64_t *r, int len)
{
    uint64_t b=0;
    int i;
    for (i=0; i<len; i++) {
        const uint64_t a = b + (r[i]<<32>>32) + (x[i]<<32>>32);
        b = (a>>32) + (r[i]>>32) + (x[i]>>32);
        x[i] = (a<<32>>32) | b<<32;
        b>>=32;
    }
    return b;
}*/


static inline uint32_t bn_adc (uint32_t * r, uint32_t * a, uint32_t *b, uint32_t cy, int n)
{
//    uint32_t cy = 0;
    int i;
    for (i=0; i<n; i++) {
        uint64_t t = (uint64_t)a[i] + b[i] + cy;
        cy = t >> 32;
        r[i] = t;
    }
    return cy;
}
/*! Умножение методом А.Карацубы (не используется)
AB = (a1<<n | a0)(b1<<n | b0) = a1*b1<<2n | a0*b0 + (a1*b0+b1*a0)<<n
(a+2^n b) cdot (c + 2^n d) = a cdot c + (b cdot d) 2^2n + ((a cdot d) + (b cdot c)) 2^n
есть вариант на три умножения
(a+2^n b) cdot (c + 2^n d) = a cdot c + (b cdot d) 2^2n + ((a+b) cdot (c+d) -  a cdot c -  b cdot d) 2^n
 */
uint32_t bn_mul   (uint32_t* r, uint32_t *a, uint32_t* b, int len)
{
    int l = len>>1;
    if (l>1) {
        uint32_t t00[len], t01[len], t10[len], t11[len], t[l];
        uint32_t cy;
        bn_mul(t00, &a[0], &b[0], l);
        bn_mul(t01, &a[0], &b[l], l);
        bn_mul(t10, &a[l], &b[0], l);
        bn_mul(t11, &a[l], &b[l], l);
        bn_move(&r[0], &t00[0], l);
        cy  = bn_add(t, &t10[0], &t01[0], l);
        cy += bn_add(&r[l], t, &t00[l], l);
        cy  = bn_adc(t, &t10[l], &t01[l], cy, l);
        cy += bn_add(&r[len], t, &t11[0], l);
        bn_add_ui(&r[len+l], &t11[l], cy, l);
    } else {
        uint64_t t00 = (uint64_t)a[0] * b[0];
        uint64_t t01 = (uint64_t)a[0] * b[1];
        uint64_t t10 = (uint64_t)a[1] * b[0];
        uint64_t t11 = (uint64_t)a[1] * b[1];
        uint64_t t;
        r[0] =  t00;
        t    = (t00>>32) + (uint32_t)t10 + (uint32_t)t01;
        r[1] =  t;
        t    = (t  >>32) + (t10>>32) + (t01>>32) + (uint32_t)t11;
        r[2] =  t;
        r[3] = (t11>>32) + (t>>32);
    }
    return 0;
}
