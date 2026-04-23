/* Challenge 33: Implement Diffie-Hellman (C version, small prime demo) */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* Modular exponentiation: base^exp mod m */
unsigned long long modexp(unsigned long long base, unsigned long long exp,
                          unsigned long long m)
{
    unsigned long long result = 1;
    base %= m;
    while (exp > 0) {
        if (exp & 1)
            result = (__uint128_t)result * base % m;
        exp >>= 1;
        base = (__uint128_t)base * base % m;
    }
    return result;
}

int main(void)
{
    srand((unsigned)time(NULL));

    unsigned long long p = 37, g = 5;

    unsigned long long a = (rand() % (p - 2)) + 1;
    unsigned long long A = modexp(g, a, p);

    unsigned long long b = (rand() % (p - 2)) + 1;
    unsigned long long B = modexp(g, b, p);

    unsigned long long s_a = modexp(B, a, p);
    unsigned long long s_b = modexp(A, b, p);

    printf("p=%llu, g=%llu\n", p, g);
    printf("a=%llu, A=%llu\n", a, A);
    printf("b=%llu, B=%llu\n", b, B);
    printf("s_a=%llu, s_b=%llu\n", s_a, s_b);

    if (s_a == s_b)
        printf("Shared secrets match! Diffie-Hellman works.\n");
    else
        printf("ERROR: secrets don't match!\n");

    return 0;
}
