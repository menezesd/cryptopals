/* Challenge 23: Clone an MT19937 RNG from its output (C version) */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#define N 624
#define M 397
#define MATRIX_A   0x9908B0DFUL
#define UPPER_MASK 0x80000000UL
#define LOWER_MASK 0x7FFFFFFFUL

typedef struct {
    uint32_t mt[N];
    int mti;
} MT;

void mt_seed(MT *rng, uint32_t seed)
{
    rng->mt[0] = seed;
    for (rng->mti = 1; rng->mti < N; rng->mti++)
        rng->mt[rng->mti] = 1812433253UL *
            (rng->mt[rng->mti-1] ^ (rng->mt[rng->mti-1] >> 30)) + rng->mti;
    rng->mti = N;
}

uint32_t mt_extract(MT *rng)
{
    uint32_t y;
    if (rng->mti >= N) {
        int kk;
        for (kk = 0; kk < N - M; kk++) {
            y = (rng->mt[kk] & UPPER_MASK) | (rng->mt[kk+1] & LOWER_MASK);
            rng->mt[kk] = rng->mt[kk+M] ^ (y >> 1) ^ ((y & 1) ? MATRIX_A : 0);
        }
        for (; kk < N - 1; kk++) {
            y = (rng->mt[kk] & UPPER_MASK) | (rng->mt[kk+1] & LOWER_MASK);
            rng->mt[kk] = rng->mt[kk+(M-N)] ^ (y >> 1) ^ ((y & 1) ? MATRIX_A : 0);
        }
        y = (rng->mt[N-1] & UPPER_MASK) | (rng->mt[0] & LOWER_MASK);
        rng->mt[N-1] = rng->mt[M-1] ^ (y >> 1) ^ ((y & 1) ? MATRIX_A : 0);
        rng->mti = 0;
    }
    y = rng->mt[rng->mti++];
    y ^= (y >> 11);
    y ^= (y <<  7) & 0x9D2C5680UL;
    y ^= (y << 15) & 0xEFC60000UL;
    y ^= (y >> 18);
    return y;
}

static uint32_t undo_right_xor_shift(uint32_t y, int shift)
{
    /* Recover x from y = x ^ (x >> shift), top bits down */
    uint32_t result = y;
    for (int i = 31 - shift; i >= 0; i--) {
        uint32_t src_bit = (result >> (i + shift)) & 1;
        result ^= src_bit << i;
    }
    return result;
}

static uint32_t undo_left_xor_shift_mask(uint32_t y, int shift, uint32_t mask)
{
    /* Recover original value from y = x ^ ((x << shift) & mask)
       Build result from low bits up. */
    uint32_t result = y;
    for (int i = 0; i < 32; i++) {
        int src = i - shift;
        if (src >= 0) {
            uint32_t src_bit = (result >> src) & 1;
            uint32_t mask_bit = (mask >> i) & 1;
            result ^= (src_bit & mask_bit) << i;
        }
    }
    return result;
}

uint32_t untemper(uint32_t y)
{
    y = undo_right_xor_shift(y, 18);
    y = undo_left_xor_shift_mask(y, 15, 0xEFC60000UL);
    y = undo_left_xor_shift_mask(y, 7, 0x9D2C5680UL);
    y = undo_right_xor_shift(y, 11);
    return y;
}

int main(void)
{
    srand((unsigned)time(NULL));
    MT original;
    mt_seed(&original, (uint32_t)rand());

    /* Tap 624 outputs */
    uint32_t outputs[N];
    for (int i = 0; i < N; i++)
        outputs[i] = mt_extract(&original);

    /* Clone */
    MT clone;
    for (int i = 0; i < N; i++)
        clone.mt[i] = untemper(outputs[i]);
    clone.mti = N;

    /* Verify */
    int match = 1;
    for (int i = 0; i < 1000; i++) {
        if (mt_extract(&original) != mt_extract(&clone)) {
            printf("Mismatch at output %d\n", i);
            match = 0;
            break;
        }
    }

    if (match)
        printf("Successfully cloned MT19937! 1000 future outputs match.\n");
    return 0;
}
