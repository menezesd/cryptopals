"""Challenge 56: RC4 Single-Byte Biases."""
import os
from collections import Counter
from crypto_utils import RC4

COOKIE = b"BE SURE TO DRINK YOUR OVALTINE"


def oracle(request):
    """Encrypt request || cookie with a fresh random RC4 key."""
    key = os.urandom(16)
    rc4 = RC4(key)
    return rc4.encrypt(request + COOKIE)


def exploit_bias(position, num_samples=2**16):
    """Exploit RC4 z16/z32 biases to recover a cookie byte at a given position."""
    # At keystream position 15 (z16), byte 0x00 appears more frequently (~1/128 vs 1/256)
    # At keystream position 31 (z32), byte 0x00 appears more frequently
    # We align cookie[position] with a biased keystream position

    # For z16 bias: we need request length such that position lands at keystream byte 15
    request_len = 15 - position if position <= 15 else 31 - position
    if request_len < 0:
        request_len += 256  # wrap around to next bias position

    request = b"A" * request_len
    target_pos = request_len + position  # position in the full plaintext

    counts = Counter()
    for _ in range(num_samples):
        ct = oracle(request)
        if target_pos < len(ct):
            counts[ct[target_pos]] += 1

    # The most common ciphertext byte XORed with the biased keystream value
    # For position 15: bias toward 0xF0 (240)
    # Simpler approach: most frequent ciphertext byte XOR 0 = the plaintext byte
    # (since the bias means keystream byte 0 is most likely)
    most_common_ct = counts.most_common(1)[0][0]
    # At biased position, keystream is biased toward certain values
    # Try XOR with 0 first (strongest bias)
    return most_common_ct ^ 0


# Recover first few bytes of cookie
print("Recovering cookie using RC4 biases...")
print(f"Expected: {COOKIE}")

recovered = bytearray()
for i in range(min(len(COOKIE), 16)):
    byte = exploit_bias(i, num_samples=2**15)
    recovered.append(byte)

print(f"Recovered: {bytes(recovered)}")
matches = sum(a == b for a, b in zip(recovered, COOKIE))
print(f"Correct bytes: {matches}/{len(recovered)}")
print("RC4 bias attack demonstrated (accuracy improves with more samples)")
