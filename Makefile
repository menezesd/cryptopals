CC = cc
CFLAGS = -w

# Use pkg-config for OpenSSL if available, otherwise fall back to defaults
# (works on Debian/Ubuntu where OpenSSL is in standard paths)
SSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
SSL_LDFLAGS := $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

# Set 2 (require OpenSSL)
S2_C = challenge2/10_cbc_mode challenge2/11_ecb_cbc_oracle \
       challenge2/13_ecb_cut_paste challenge2/16_cbc_bitflip \
       challenge2/18_ctr_mode

# Set 3 (pure C, no deps)
S3_C = challenge3/21_mt19937 challenge3/22_crack_mt_seed challenge3/23_clone_mt

# Set 4 (pure C, no deps)
S4_C = challenge4/28_sha1

# Set 5 (pure C, no deps)
S5_C = challenge5/33_dh

ALL_C = $(S2_C) $(S3_C) $(S4_C) $(S5_C)

.PHONY: all clean

all: $(ALL_C)

challenge2/%: challenge2/%.c
	$(CC) $(CFLAGS) $(SSL_CFLAGS) -o $@ $< $(SSL_LDFLAGS)

challenge3/%: challenge3/%.c
	$(CC) $(CFLAGS) -o $@ $<

challenge4/%: challenge4/%.c
	$(CC) $(CFLAGS) -o $@ $<

challenge5/33_dh: challenge5/33_diffie_hellman.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(ALL_C)
