"""Challenge 24: Create the MT19937 stream cipher and break it."""
import os
import time
from crypto_utils import MT19937


def mt_cipher(data, seed):
    """Encrypt/decrypt using MT19937 as a stream cipher."""
    rng = MT19937(seed=seed & 0xFFFF)
    keystream = b""
    while len(keystream) < len(data):
        val = rng.extract_number()
        keystream += val.to_bytes(4, "little")
    return bytes(a ^ b for a, b in zip(data, keystream[:len(data)]))


# Part 1: Verify encryption/decryption roundtrip
seed = 12345
test = b"Hello, MT19937 stream cipher!"
assert mt_cipher(mt_cipher(test, seed), seed) == test
print("Part 1: MT19937 stream cipher works!")

# Part 2: Recover 16-bit seed from known plaintext
actual_seed = int.from_bytes(os.urandom(2))
prefix = os.urandom(5 + int.from_bytes(os.urandom(1)) % 10)
known = b"A" * 14
plaintext = prefix + known
ciphertext = mt_cipher(plaintext, actual_seed)

# Brute force the 16-bit seed
recovered_seed = None
for candidate in range(0x10000):
    decrypted = mt_cipher(ciphertext, candidate)
    if decrypted[-14:] == known:
        recovered_seed = candidate
        break

assert recovered_seed == (actual_seed & 0xFFFF)
print(f"Part 2: Recovered seed {recovered_seed} (actual: {actual_seed & 0xFFFF})")


# Part 3: Password reset token detection
def generate_token(use_time_seed=True):
    if use_time_seed:
        seed = int(time.time()) & 0xFFFF
    else:
        seed = int.from_bytes(os.urandom(2))
    rng = MT19937(seed=seed)
    return b"".join(rng.extract_number().to_bytes(4, "little") for _ in range(4))


def is_time_seeded_token(token):
    """Check if token was generated from a recent timestamp seed."""
    now = int(time.time()) & 0xFFFF
    for offset in range(60):  # check last 60 seconds
        candidate = (now - offset) & 0xFFFF
        rng = MT19937(seed=candidate)
        expected = b"".join(rng.extract_number().to_bytes(4, "little") for _ in range(4))
        if expected == token:
            return True
    return False


time_token = generate_token(use_time_seed=True)
random_token = generate_token(use_time_seed=False)

print(f"Part 3: Time-seeded token detected: {is_time_seeded_token(time_token)}")
print(f"Part 3: Random token detected as time-seeded: {is_time_seeded_token(random_token)}")
