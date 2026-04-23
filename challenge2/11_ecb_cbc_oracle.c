/* Challenge 11: ECB/CBC detection oracle (C version) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define BLOCK 16

static void pkcs7_pad(unsigned char *buf, int *len)
{
    int pad = BLOCK - (*len % BLOCK);
    memset(buf + *len, pad, pad);
    *len += pad;
}

static void aes_ecb_encrypt(const unsigned char *pt, int pt_len,
                            const unsigned char *key, unsigned char *ct)
{
    AES_KEY k;
    AES_set_encrypt_key(key, 128, &k);
    for (int i = 0; i < pt_len; i += BLOCK)
        AES_ecb_encrypt(pt + i, ct + i, &k, AES_ENCRYPT);
}

static void aes_cbc_encrypt(const unsigned char *pt, int pt_len,
                            const unsigned char *key,
                            const unsigned char *iv, unsigned char *ct)
{
    AES_KEY k;
    AES_set_encrypt_key(key, 128, &k);
    unsigned char prev[BLOCK];
    memcpy(prev, iv, BLOCK);
    for (int i = 0; i < pt_len; i += BLOCK) {
        unsigned char xored[BLOCK];
        for (int j = 0; j < BLOCK; j++)
            xored[j] = pt[i + j] ^ prev[j];
        AES_ecb_encrypt(xored, ct + i, &k, AES_ENCRYPT);
        memcpy(prev, ct + i, BLOCK);
    }
}

/* Returns 0 for ECB, 1 for CBC */
static int encryption_oracle(const unsigned char *input, int input_len,
                              unsigned char *ct, int *ct_len)
{
    unsigned char key[BLOCK], iv[BLOCK];
    RAND_bytes(key, BLOCK);
    RAND_bytes(iv, BLOCK);

    int prefix_len = 5 + (rand() % 6);
    int suffix_len = 5 + (rand() % 6);

    int total = prefix_len + input_len + suffix_len;
    unsigned char *data = calloc(total + BLOCK, 1);
    RAND_bytes(data, prefix_len);
    memcpy(data + prefix_len, input, input_len);
    RAND_bytes(data + prefix_len + input_len, suffix_len);
    pkcs7_pad(data, &total);

    int use_cbc = rand() & 1;
    if (use_cbc)
        aes_cbc_encrypt(data, total, key, iv, ct);
    else
        aes_ecb_encrypt(data, total, key, ct);

    *ct_len = total;
    free(data);
    return use_cbc;
}

static int detect_ecb(const unsigned char *ct, int ct_len)
{
    int nblocks = ct_len / BLOCK;
    for (int i = 0; i < nblocks; i++)
        for (int j = i + 1; j < nblocks; j++)
            if (memcmp(ct + i * BLOCK, ct + j * BLOCK, BLOCK) == 0)
                return 1;
    return 0;
}

int main(void)
{
    srand((unsigned)time(NULL));

    /* Feed 48 identical bytes to guarantee repeated blocks under ECB */
    unsigned char input[48];
    memset(input, 'A', 48);

    int correct = 0, trials = 100;
    for (int t = 0; t < trials; t++) {
        unsigned char ct[256];
        int ct_len;
        int actual_cbc = encryption_oracle(input, 48, ct, &ct_len);
        int guessed_ecb = detect_ecb(ct, ct_len);
        /* ECB detected = not CBC; CBC = not ECB */
        if (guessed_ecb != actual_cbc)
            correct++;
    }

    printf("Detection accuracy: %d/%d\n", correct, trials);
    return 0;
}
