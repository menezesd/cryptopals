/* Challenge 16: CBC bitflipping attack (C version) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define BLOCK 16

static unsigned char KEY[BLOCK];
static unsigned char IV[BLOCK];

static void pkcs7_pad(unsigned char *buf, int *len)
{
    int pad = BLOCK - (*len % BLOCK);
    memset(buf + *len, pad, pad);
    *len += pad;
}

static void cbc_encrypt(const unsigned char *pt, int pt_len,
                        unsigned char *ct)
{
    AES_KEY k;
    AES_set_encrypt_key(KEY, 128, &k);
    unsigned char prev[BLOCK];
    memcpy(prev, IV, BLOCK);

    for (int i = 0; i < pt_len; i += BLOCK) {
        unsigned char xored[BLOCK];
        for (int j = 0; j < BLOCK; j++)
            xored[j] = pt[i + j] ^ prev[j];
        AES_ecb_encrypt(xored, ct + i, &k, AES_ENCRYPT);
        memcpy(prev, ct + i, BLOCK);
    }
}

static void cbc_decrypt(const unsigned char *ct, int ct_len,
                        unsigned char *pt)
{
    AES_KEY k;
    AES_set_decrypt_key(KEY, 128, &k);
    unsigned char prev[BLOCK];
    memcpy(prev, IV, BLOCK);

    for (int i = 0; i < ct_len; i += BLOCK) {
        unsigned char dec[BLOCK];
        AES_ecb_encrypt(ct + i, dec, &k, AES_DECRYPT);
        for (int j = 0; j < BLOCK; j++)
            pt[i + j] = dec[j] ^ prev[j];
        memcpy(prev, ct + i, BLOCK);
    }
}

static int encrypt_userdata(const char *userdata, unsigned char *ct)
{
    const char *prefix = "comment1=cooking%20MCs;userdata=";
    const char *suffix = ";comment2=%20like%20a%20pound%20of%20bacon";

    int ud_len = strlen(userdata);
    int total = strlen(prefix) + ud_len + strlen(suffix);
    unsigned char *pt = calloc(total + BLOCK, 1);

    memcpy(pt, prefix, strlen(prefix));
    /* Copy userdata, stripping ; and = */
    int pos = strlen(prefix);
    for (int i = 0; i < ud_len; i++) {
        if (userdata[i] != ';' && userdata[i] != '=')
            pt[pos++] = userdata[i];
    }
    memcpy(pt + pos, suffix, strlen(suffix));
    total = pos + strlen(suffix);
    pkcs7_pad(pt, &total);

    cbc_encrypt(pt, total, ct);
    free(pt);
    return total;
}

static int is_admin(const unsigned char *ct, int ct_len)
{
    unsigned char *pt = malloc(ct_len);
    cbc_decrypt(ct, ct_len, pt);
    int found = (memmem(pt, ct_len, ";admin=true;", 12) != NULL);
    free(pt);
    return found;
}

int main(void)
{
    RAND_bytes(KEY, BLOCK);
    RAND_bytes(IV, BLOCK);

    /* Submit 16 A's as userdata — lands at block 2 (offset 32) */
    unsigned char ct[256];
    int ct_len = encrypt_userdata("AAAAAAAAAAAAAAAA", ct);

    /* Flip bits in block 1 (ciphertext bytes 16-31) to change block 2 plaintext */
    const char *known  = "AAAAAAAAAAAAAAAA";
    const char *desired = ";admin=true;AAAA";

    for (int i = 0; i < BLOCK; i++)
        ct[BLOCK + i] ^= known[i] ^ desired[i];

    if (is_admin(ct, ct_len))
        printf("CBC bitflipping attack succeeded: ;admin=true; injected!\n");
    else
        printf("Attack failed!\n");

    return 0;
}
