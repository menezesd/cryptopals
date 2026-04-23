/* Challenge 22: Crack an MT19937 seed (C version) */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

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
    /* Simulate: seed with a recent-ish timestamp */
    uint32_t now = (uint32_t)time(NULL);
    uint32_t actual_seed = now - (rand() % 961) - 40;

    mt_seed(actual_seed);
    uint32_t output = mt_extract();

    printf("Output: %u\n", output);
    printf("Actual seed: %u\n", actual_seed);

    /* Brute-force: try recent timestamps */
    for (uint32_t candidate = now; candidate >= now - 2000; candidate--) {
        mt_seed(candidate);
        if (mt_extract() == output) {
            printf("Cracked seed: %u\n", candidate);
            if (candidate == actual_seed)
                printf("Successfully cracked MT19937 seed!\n");
            else
                printf("ERROR: wrong seed!\n");
            return 0;
        }
    }

    printf("Seed not found!\n");
    return 1;
}
