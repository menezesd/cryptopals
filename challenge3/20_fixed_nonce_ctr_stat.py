"""Challenge 20: Break fixed-nonce CTR statistically."""
import base64
from crypto_utils import aes_ctr, random_key, xor_bytes

KEY = random_key()

# Load and encrypt all lines with fixed nonce
with open("20.txt") as f:
    ciphertexts = [aes_ctr(base64.b64decode(line.strip()), KEY, nonce=0) for line in f]

# Truncate to shortest ciphertext length
min_len = min(len(c) for c in ciphertexts)
truncated = [c[:min_len] for c in ciphertexts]

# Treat as repeating-key XOR with key length = min_len
# Attack each byte position independently


def score_byte(b):
    if chr(b) in "etaoinshrdlu ETAOINSHRDLU":
        return 3
    if chr(b).isalpha() or b in (ord(","), ord("."), ord("'"), ord(";")):
        return 1
    if chr(b).isprintable():
        return 0
    return -10


keystream = bytearray(min_len)
for pos in range(min_len):
    best_score = -999999
    best_byte = 0
    for guess in range(256):
        score = sum(score_byte(ct[pos] ^ guess) for ct in truncated)
        if score > best_score:
            best_score = score
            best_byte = guess
    keystream[pos] = best_byte

for ct in truncated:
    print(xor_bytes(ct, keystream).decode("ascii", errors="replace"))
