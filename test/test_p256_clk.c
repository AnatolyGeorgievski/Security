/* Один буфер, два метода редукции, разность тактов. */
#include "clk.h"
#include <stdio.h>
#include <inttypes.h>

void mp_reduction_nist_p256_32(uint32_t x[8], uint32_t cx);
void mp_reduction_nist_p256_64(uint64_t x[4], uint64_t cx);

enum { N = 1024 };

static uint32_t sink32;
static uint64_t sink64;

static void run32(void)
{
    uint32_t x[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    for (int i = 0; i < N; i++)
        mp_reduction_nist_p256_32(x, 1);
    sink32 = x[0];
}

static void run64(void)
{
    uint64_t x[4] = {1, 0, 0, 0};
    for (int i = 0; i < N; i++)
        mp_reduction_nist_p256_64(x, 1);
    sink64 = x[0];
}

int main(void)
{
    uint64_t t0 = test_clk_begin();
    run32();
    uint64_t c32 = test_clk_end(t0);
    uint64_t t1 = test_clk_begin();
    run64();
    uint64_t c64 = test_clk_end(t1);
    printf("p256-32 %" PRIu64 " clk  x0=%08" PRIx32 "\n", c32, sink32);
    printf("p256-64 %" PRIu64 " clk  x0=%016" PRIx64 "\n", c64, sink64);
    return 0;
}
