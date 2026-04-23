/* Challenge 21: Implement the MT19937 Mersenne Twister RNG (C version) */
#include <stdio.h>
#include <stdint.h>

#define N 624
#define M 397
#define MATRIX_A   0x9908B0DFUL
#define UPPER_MASK 0x80000000UL
#define LOWER_MASK 0x7FFFFFFFUL

static uint32_t mt[N];
static int mti = N + 1;

void mt_seed(uint32_t seed)
{
    mt[0] = seed;
    for (mti = 1; mti < N; mti++)
        mt[mti] = 1812433253UL * (mt[mti-1] ^ (mt[mti-1] >> 30)) + mti;
    mti = N;
}

uint32_t mt_extract(void)
{
    uint32_t y;

    if (mti >= N) {
        int kk;
        for (kk = 0; kk < N - M; kk++) {
            y = (mt[kk] & UPPER_MASK) | (mt[kk+1] & LOWER_MASK);
            mt[kk] = mt[kk+M] ^ (y >> 1) ^ ((y & 1) ? MATRIX_A : 0);
        }
        for (; kk < N - 1; kk++) {
            y = (mt[kk] & UPPER_MASK) | (mt[kk+1] & LOWER_MASK);
            mt[kk] = mt[kk+(M-N)] ^ (y >> 1) ^ ((y & 1) ? MATRIX_A : 0);
        }
        y = (mt[N-1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
        mt[N-1] = mt[M-1] ^ (y >> 1) ^ ((y & 1) ? MATRIX_A : 0);
        mti = 0;
    }

    y = mt[mti++];
    y ^= (y >> 11);
    y ^= (y <<  7) & 0x9D2C5680UL;
    y ^= (y << 15) & 0xEFC60000UL;
    y ^= (y >> 18);
    return y;
}

int main(void)
{
    mt_seed(0);
    printf("First 10 outputs with seed=0:\n");
    for (int i = 0; i < 10; i++)
        printf("  %d: %u\n", i, mt_extract());

    /* Verify reproducibility */
    mt_seed(0);
    uint32_t first = mt_extract();
    mt_seed(0);
    if (mt_extract() == first)
        printf("\nReproducibility verified!\n");

    /* seed=42 test */
    mt_seed(42);
    uint32_t vals[1000];
    for (int i = 0; i < 1000; i++)
        vals[i] = mt_extract();

    mt_seed(42);
    int ok = 1;
    for (int i = 0; i < 1000; i++)
        if (mt_extract() != vals[i]) { ok = 0; break; }

    printf("1000 outputs matched for seed=42: %s\n", ok ? "yes" : "no");
    return 0;
}
