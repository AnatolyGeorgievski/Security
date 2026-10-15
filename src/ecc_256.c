/* Класс поля NIST P-256, 256 бит.
   Заготовка того же класса на 32 бита: src/bigbrother/ocsp/ecc_256.c.
   Там BNuint — uint32_t, вектор из восьми слов, редукция mp_reduction_anyC
   для простого вида 2^n - c. К этому модулю она не подходит:
   p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
   Проверенная формула поля — mp_reduction_nist_p256 в src/ecc.c.
   Ниже она на 32 бита, как в дереве, и переход того же переноса на 64 бита.
   Ed25519 в этот файл не входит.

   Перенос cx — слово, выпавшее за 256-битный вектор, коэффициент при 2^256.
   На 32 бита это одно слово. На 64 бита слово вдвое шире и стоит на том же месте.
*/
#include <stdint.h>

#define BN_ALIGN __attribute__((aligned(8)))

/* Константа 64 бита в вектор. Младшая половина стоит первой — это LE.
   На 32 бита BN2(c) даёт два слова, на 64 бита одно.
   В src/mp.h другое BN2(a, b): туда половины уже приходят раздельно. */
#define U32C(c) ((uint32_t)(c))
#define U64C(c) ((uint64_t)(c))
/* Ширина лимба — размер указателя в битах. __LP64__ на части компиляторов нет.
   __PTR_SIZE__ если уже задан, остаётся. Иначе он берётся из __SIZEOF_POINTER__. */
#ifndef __PTR_SIZE__
#define __PTR_SIZE__ (__SIZEOF_POINTER__ * 8)
#endif
#if __PTR_SIZE__ == 64
#define BN_BITS 64
typedef uint64_t BNuint;
#define BN2(c) U64C(c)
#elif __PTR_SIZE__ == 32
#define BN_BITS 32
typedef uint32_t BNuint;
#define BN2(c) U32C((uint32_t)(c)), U32C((uint32_t)((uint64_t)(c) >> 32))
#else
#error __PTR_SIZE__ должен быть 32 или 64
#endif

/* p = 2^256 - 2^224 + 2^192 + 2^96 - 1, четыре куска по 64 бита, младший первый */
static const BNuint prime[256 / BN_BITS] BN_ALIGN = {
    BN2(0xffffffffffffffff),
    BN2(0x00000000ffffffff),
    BN2(0x0000000000000000),
    BN2(0xffffffff00000001),
};

#if BN_BITS == 32
#define prime32 prime
#else
/* Тот же ряд, что BN2 разворачивает на 32 бита: U32C(lo), U32C(hi). */
static const uint32_t prime32[8] = {
    U32C(0xffffffff), U32C(0xffffffff),
    U32C(0xffffffff), U32C(0x00000000),
    U32C(0x00000000), U32C(0x00000000),
    U32C(0x00000001), U32C(0xffffffff),
};
#endif

static uint32_t bn_add1_32(uint32_t *r, const uint32_t *a, int n)
{
    uint32_t cy = 0;
    for (int i = 0; i < n; i++) {
        uint64_t t = (uint64_t)r[i] + a[i] + cy;
        r[i] = (uint32_t)t;
        cy = (uint32_t)(t >> 32);
    }
    return cy;
}

static int32_t bn_sub1_32(uint32_t *r, const uint32_t *b, int n)
{
    int32_t cy = 0;
    for (int i = 0; i < n; i++) {
        int64_t t = (int64_t)r[i] - b[i] + cy;
        r[i] = (uint32_t)t;
        cy = (int32_t)(t >> 32);
    }
    return cy;
}

static int ge_prime32(const uint32_t *x)
{
    for (int i = 7; i >= 0; i--) {
        if (x[i] != prime32[i])
            return x[i] > prime32[i];
    }
    return 1;
}

/* 2^256 ≡ 2^224 - 2^192 - 2^96 + 1.
   Вектор как в src/ecc.c. cx = 0 сюда не приходит: складывать нечего.
   Пометка из ecc.c: cx = 1 и cx = 0xFFFFFFFF ещё под вопросом.
   Сложение этого вектора с P-1 при cx = 1 не даёт (P-1 + 2^256) mod p. */
void mp_reduction_nist_p256_32(uint32_t x[8], uint32_t cx)
{
    uint32_t v[8] = { cx, 0, 0, -cx, ~0u, ~0u, ~cx, cx - 1 };
    uint32_t cy = bn_add1_32(x, v, 8);
    if (cy > 0)
        bn_sub1_32(x, prime32, 8);
}

/* Старшие 32 бита 64-битного переноса — коэффициент при 2^288.
   2^288 ≡ 1 + 2^32 - 2^96 - 2^128 - 2^192.
   Восемь слов этой поправки, беззнаковое сложение, дают величину на 2^256
   больше вычета. Если переноса из сложения не было, вычет 2^256 снимается
   тем же вектором, что и cx = 1. Если перенос был, лишняя 2^256 уже ушла
   в этот перенос. */
static void mp_reduction_hi32(uint32_t x[8], uint32_t hi)
{
    uint32_t v[8] = {
        hi, hi, 0, -hi, -hi - 1, ~0u, -hi - 1, ~0u
    };
    uint32_t one[8] = { 1, 0, 0, ~0u, ~0u, ~0u, ~1u, 0 };
    uint32_t cy = bn_add1_32(x, v, 8);
    if (cy == 0) {
        if (bn_sub1_32(x, one, 8) < 0)
            bn_add1_32(x, prime32, 8);
    } else if (ge_prime32(x)) {
        bn_sub1_32(x, prime32, 8);
    }
}

/* 🧩 Переход 32 → 64. Четыре слова по 64 бита.
   Степени 96 и 224 не кратны 64, поэтому восемь uint32 из формулы
   не склеиваются в четыре uint64 попарно. Низ переноса идёт прежней
   функцией, верх — отдельной поправкой при 2^288. */
void mp_reduction_nist_p256_64(uint64_t x[4], uint64_t cx)
{
    uint32_t w[8] BN_ALIGN;
    for (int i = 0; i < 4; i++) {
        w[2 * i]     = (uint32_t)x[i];
        w[2 * i + 1] = (uint32_t)(x[i] >> 32);
    }
    if ((uint32_t)cx)
        mp_reduction_nist_p256_32(w, (uint32_t)cx);
    if (cx >> 32)
        mp_reduction_hi32(w, (uint32_t)(cx >> 32));
    for (int i = 0; i < 4; i++)
        x[i] = (uint64_t)w[2 * i] | ((uint64_t)w[2 * i + 1] << 32);
}
