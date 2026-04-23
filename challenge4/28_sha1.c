/* Challenge 28: Implement a SHA-1 keyed MAC (C version) */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define LROT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

typedef struct {
    uint32_t h[5];
    uint64_t len;
    uint8_t buf[64];
    int buf_len;
} sha1_ctx;

void sha1_init(sha1_ctx *ctx)
{
    ctx->h[0] = 0x67452301;
    ctx->h[1] = 0xEFCDAB89;
    ctx->h[2] = 0x98BADCFE;
    ctx->h[3] = 0x10325476;
    ctx->h[4] = 0xC3D2E1F0;
    ctx->len = 0;
    ctx->buf_len = 0;
}

static void sha1_process_block(sha1_ctx *ctx, const uint8_t *block)
{
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = (block[i*4] << 24) | (block[i*4+1] << 16) |
               (block[i*4+2] << 8) | block[i*4+3];
    for (int i = 16; i < 80; i++)
        w[i] = LROT(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

    uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2],
             d = ctx->h[3], e = ctx->h[4];

    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | (~b & d);           k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                    k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);  k = 0x8F1BBCDC; }
        else              { f = b ^ c ^ d;                    k = 0xCA62C1D6; }

        uint32_t temp = LROT(a, 5) + f + e + k + w[i];
        e = d; d = c; c = LROT(b, 30); b = a; a = temp;
    }

    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c;
    ctx->h[3] += d; ctx->h[4] += e;
}

void sha1_update(sha1_ctx *ctx, const uint8_t *data, size_t len)
{
    ctx->len += len;
    while (len > 0) {
        int space = 64 - ctx->buf_len;
        int n = len < (size_t)space ? (int)len : space;
        memcpy(ctx->buf + ctx->buf_len, data, n);
        ctx->buf_len += n;
        data += n;
        len -= n;
        if (ctx->buf_len == 64) {
            sha1_process_block(ctx, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

void sha1_final(sha1_ctx *ctx, uint8_t out[20])
{
    uint64_t bits = ctx->len * 8;
    uint8_t pad = 0x80;
    sha1_update(ctx, &pad, 1);
    pad = 0;
    while (ctx->buf_len != 56)
        sha1_update(ctx, &pad, 1);

    uint8_t len_be[8];
    for (int i = 7; i >= 0; i--) {
        len_be[i] = bits & 0xff;
        bits >>= 8;
    }
    sha1_update(ctx, len_be, 8);

    for (int i = 0; i < 5; i++) {
        out[i*4]   = (ctx->h[i] >> 24) & 0xff;
        out[i*4+1] = (ctx->h[i] >> 16) & 0xff;
        out[i*4+2] = (ctx->h[i] >>  8) & 0xff;
        out[i*4+3] = ctx->h[i] & 0xff;
    }
}

void sha1(const uint8_t *data, size_t len, uint8_t out[20])
{
    sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, out);
}

void sha1_mac(const uint8_t *key, size_t key_len,
              const uint8_t *msg, size_t msg_len,
              uint8_t out[20])
{
    sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, key, key_len);
    sha1_update(&ctx, msg, msg_len);
    sha1_final(&ctx, out);
}

int main(void)
{
    /* Test against known SHA-1 value */
    const char *test = "The quick brown fox jumps over the lazy dog";
    uint8_t hash[20];
    sha1((const uint8_t *)test, strlen(test), hash);

    printf("SHA-1: ");
    for (int i = 0; i < 20; i++) printf("%02x", hash[i]);
    printf("\n");

    /* Expected: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12 */
    const uint8_t expected[] = {
        0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84,
        0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12
    };
    if (memcmp(hash, expected, 20) == 0)
        printf("SHA-1 verified!\n");
    else
        printf("SHA-1 MISMATCH!\n");

    /* Test MAC */
    const char *key = "secret";
    const char *msg = "Hello, World!";
    uint8_t mac1[20], mac2[20];
    sha1_mac((const uint8_t *)key, strlen(key),
             (const uint8_t *)msg, strlen(msg), mac1);
    sha1_mac((const uint8_t *)key, strlen(key),
             (const uint8_t *)msg, strlen(msg), mac2);

    printf("MAC: ");
    for (int i = 0; i < 20; i++) printf("%02x", mac1[i]);
    printf("\n");

    if (memcmp(mac1, mac2, 20) == 0)
        printf("MAC is deterministic!\n");

    /* Tamper detection */
    const char *msg2 = "Hello, World?";
    sha1_mac((const uint8_t *)key, strlen(key),
             (const uint8_t *)msg2, strlen(msg2), mac2);
    if (memcmp(mac1, mac2, 20) != 0)
        printf("Tamper detected!\n");

    return 0;
}
