/* Замер тактов горячего цикла. Метки LLVM-MCA сюда не входят:
   они вписываются в .s после сборки, см. log/2026-10-14 принципы оптимизации.md. */
#ifndef TEST_CLK_H
#define TEST_CLK_H
#include <stdint.h>
#if defined(__i386__) || defined(__x86_64__)
static inline uint64_t test_clk_begin(void)
{
    return __builtin_ia32_rdtsc();
}
static inline uint64_t test_clk_end(uint64_t begin)
{
    return __builtin_ia32_rdtsc() - begin;
}
#else
#error test_clk: rdtsc есть на x86
#endif
#endif
