#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* a in "0123456789abcdef" */
int from_hex(char c)
{
    switch (c) {
    default: return c - '0';    /* digits are guaranteed consecutive */
    case 'a': case 'A': return 10;
    case 'b': case 'B': return 11;
    case 'c': case 'C': return 12;
    case 'd': case 'D': return 13;
    case 'e': case 'E': return 14;
    case 'f': case 'F': return 15;
    }
}

char *hex_to_base64(const char *hex_string)
{
    static const char base64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t input_len = strlen(hex_string);
    size_t output_len = (input_len * 2 + 2) / 3 /* base64 chars */
        + 2 - (input_len - 1) % 3               /* padding '=' or '==' */
        + 1;                                    /* string terminator */
    char *const out_buf = malloc(output_len);
    if (!out_buf) {
        return NULL;
    }

    char *out = out_buf;
    while (hex_string[0] && hex_string[1] && hex_string[2]) {
        /* convert three hex digits to two base-64 chars */
        int digit[3] = {
            from_hex(hex_string[0]),
            from_hex(hex_string[1]),
            from_hex(hex_string[2])
        };
        *out++ = base64[(digit[0] << 2) + (digit[1] >> 2)];
        *out++ = base64[((digit[1] & 3) << 4) + (digit[2])];
        hex_string += 3;
    }

    /* Now deal with leftover chars */
    if (hex_string[0] && hex_string[1]) {
        /* convert two hex digits to two base-64 chars */
        int digit[2] = {
            from_hex(hex_string[0]),
            from_hex(hex_string[1])
        };
        *out++ = base64[(digit[0] << 2) + (digit[1] >> 2)];
        *out++ = base64[((digit[1] & 3) << 4)];
        *out++ = '=';
    } else if (hex_string[0] && !isspace(hex_string[0])) {
        /* convert one hex digit to one base-64 char */
        int digit = from_hex(hex_string[0]);
        *out++ = base64[digit << 2];
        *out++ = '=';
        *out++ = '=';
    }

    *out = '\0';
    return out_buf;
}

int main ()
{
  char *inp = NULL;
  size_t sz = 0;
  getline(&inp, &sz, stdin);
  puts(hex_to_base64(inp));
}
