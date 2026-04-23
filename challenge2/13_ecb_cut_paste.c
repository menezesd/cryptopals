/* Challenge 13: ECB cut-and-paste (C version) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define BLOCK 16

static unsigned char KEY[BLOCK];

static void pkcs7_pad(unsigned char *buf, int *len)
{
    int pad = BLOCK - (*len % BLOCK);
    memset(buf + *len, pad, pad);
    *len += pad;
}

static int pkcs7_unpad(unsigned char *buf, int len)
{
    int pad = buf[len - 1];
    return len - pad;
}

static void ecb_encrypt(const unsigned char *pt, int pt_len, unsigned char *ct)
{
    AES_KEY k;
    AES_set_encrypt_key(KEY, 128, &k);
    for (int i = 0; i < pt_len; i += BLOCK)
        AES_ecb_encrypt(pt + i, ct + i, &k, AES_ENCRYPT);
}

static void ecb_decrypt(const unsigned char *ct, int ct_len, unsigned char *pt)
{
    AES_KEY k;
    AES_set_decrypt_key(KEY, 128, &k);
    for (int i = 0; i < ct_len; i += BLOCK)
        AES_ecb_encrypt(ct + i, pt + i, &k, AES_DECRYPT);
}

static void profile_for(const char *email, char *out, int *out_len)
{
    /* "email=<email>&uid=10&role=user" (strip & and =) */
    char *p = out;
    p += sprintf(p, "email=");
    for (const char *e = email; *e; e++) {
        if (*e != '&' && *e != '=')
            *p++ = *e;
    }
    p += sprintf(p, "&uid=10&role=user");
    *out_len = p - out;
}

static int encrypt_profile(const char *email, unsigned char *ct)
{
    char profile[256];
    int plen;
    profile_for(email, profile, &plen);
    pkcs7_pad((unsigned char *)profile, &plen);
    ecb_encrypt((unsigned char *)profile, plen, ct);
    return plen;
}

int main(void)
{
    RAND_bytes(KEY, BLOCK);

    /*
     * Block layout for "email=AAAAAAAAAA" + "admin\x0b...\x0b" + rest:
     * Block 0: "email=AAAAAAAAAA"  (6 + 10 = 16)
     * Block 1: "admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b" (5 + 11 padding)
     *
     * For "email=XXXXXXXXXXXXX&uid=10&role=":
     *   6 + 13 + 13 = 32 => "role=" at end of block 1
     */

    /* Step 1: Get encrypted "admin" block */
    char evil_email[64];
    memset(evil_email, 'A', 10);
    memcpy(evil_email + 10, "admin", 5);
    memset(evil_email + 15, 0x0b, 11);  /* PKCS7 padding for "admin" */
    evil_email[26] = '\0';

    unsigned char evil_ct[256];
    encrypt_profile(evil_email, evil_ct);
    /* admin block is at offset BLOCK (second block) */

    /* Step 2: Get normal profile where "role=" ends at block boundary */
    unsigned char normal_ct[256];
    int normal_len = encrypt_profile("XXXXXXXXXXXXX", normal_ct);

    /* Step 3: Forge: first 2 blocks of normal + admin block */
    unsigned char forged[256];
    memcpy(forged, normal_ct, 2 * BLOCK);
    memcpy(forged + 2 * BLOCK, evil_ct + BLOCK, BLOCK);
    int forged_len = 3 * BLOCK;

    /* Decrypt and check */
    unsigned char pt[256];
    ecb_decrypt(forged, forged_len, pt);
    int pt_len = pkcs7_unpad(pt, forged_len);
    pt[pt_len] = '\0';

    printf("Decrypted profile: %s\n", pt);
    if (strstr((char *)pt, "role=admin"))
        printf("Successfully forged admin profile!\n");
    else
        printf("Attack failed!\n");

    return 0;
}
