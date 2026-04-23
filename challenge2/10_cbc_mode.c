/* Challenge 10: Implement CBC mode (C version using OpenSSL for AES-ECB primitive) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

#define BLOCK_SIZE 16

static void xor_blocks(unsigned char *dst, const unsigned char *a,
                       const unsigned char *b, int len)
{
    for (int i = 0; i < len; i++)
        dst[i] = a[i] ^ b[i];
}

static int base64_decode(const char *in, size_t in_len, unsigned char *out)
{
    static const int T[256] = {
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
        ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
        ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
        ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
        ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
        ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
        ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
        ['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63,
    };
    int out_len = 0;
    unsigned int buf = 0, bits = 0;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = in[i];
        if (c == '=' || c == '\n' || c == '\r' || c == ' ')
            continue;
        buf = (buf << 6) | T[c];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[out_len++] = (buf >> bits) & 0xff;
        }
    }
    return out_len;
}

static int aes_cbc_decrypt(const unsigned char *ct, int ct_len,
                           const unsigned char *key,
                           const unsigned char *iv,
                           unsigned char *pt)
{
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);

    unsigned char prev[BLOCK_SIZE];
    unsigned char decrypted[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);

    for (int i = 0; i < ct_len; i += BLOCK_SIZE) {
        AES_ecb_encrypt(ct + i, decrypted, &aes_key, AES_DECRYPT);
        xor_blocks(pt + i, decrypted, prev, BLOCK_SIZE);
        memcpy(prev, ct + i, BLOCK_SIZE);
    }

    /* Remove PKCS#7 padding */
    int pad = pt[ct_len - 1];
    return ct_len - pad;
}

int main(void)
{
    FILE *f = fopen("10.txt", "r");
    if (!f) { perror("10.txt"); return 1; }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b64 = malloc(fsize + 1);
    fread(b64, 1, fsize, f);
    b64[fsize] = 0;
    fclose(f);

    unsigned char *ct = malloc(fsize);
    int ct_len = base64_decode(b64, fsize, ct);
    free(b64);

    const unsigned char key[] = "YELLOW SUBMARINE";
    unsigned char iv[BLOCK_SIZE] = {0};

    unsigned char *pt = malloc(ct_len);
    int pt_len = aes_cbc_decrypt(ct, ct_len, key, iv, pt);

    fwrite(pt, 1, pt_len, stdout);

    free(ct);
    free(pt);
    return 0;
}
