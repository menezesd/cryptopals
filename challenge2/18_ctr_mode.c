/* Challenge 18: Implement CTR stream cipher mode (C version) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

#define BLOCK_SIZE 16

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
        if (c == '=' || c == '\n' || c == '\r')
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

static void aes_ctr(const unsigned char *in, int in_len,
                    const unsigned char *key, uint64_t nonce,
                    unsigned char *out)
{
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);

    for (int i = 0; i < in_len; i += BLOCK_SIZE) {
        /* Build counter block: 8-byte LE nonce + 8-byte LE counter */
        unsigned char counter_block[BLOCK_SIZE];
        uint64_t ctr = i / BLOCK_SIZE;
        memcpy(counter_block, &nonce, 8);      /* LE nonce */
        memcpy(counter_block + 8, &ctr, 8);    /* LE counter */

        unsigned char keystream[BLOCK_SIZE];
        AES_ecb_encrypt(counter_block, keystream, &aes_key, AES_ENCRYPT);

        int block_len = in_len - i;
        if (block_len > BLOCK_SIZE)
            block_len = BLOCK_SIZE;

        for (int j = 0; j < block_len; j++)
            out[i + j] = in[i + j] ^ keystream[j];
    }
}

int main(void)
{
    const char *b64 =
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

    unsigned char ct[256];
    int ct_len = base64_decode(b64, strlen(b64), ct);

    const unsigned char key[] = "YELLOW SUBMARINE";
    unsigned char pt[256];
    aes_ctr(ct, ct_len, key, 0, pt);

    fwrite(pt, 1, ct_len, stdout);
    putchar('\n');
    return 0;
}
