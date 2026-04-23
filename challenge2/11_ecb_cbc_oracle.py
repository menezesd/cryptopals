"""Challenge 11: An ECB/CBC detection oracle."""
import os
import random
from aes_utils import aes_ecb_encrypt, aes_cbc_encrypt, random_key, detect_ecb


def encryption_oracle(plaintext):
    key = random_key()
    prefix = os.urandom(random.randint(5, 10))
    suffix = os.urandom(random.randint(5, 10))
    data = prefix + plaintext + suffix

    if random.randint(0, 1) == 0:
        return aes_ecb_encrypt(data, key), "ECB"
    else:
        iv = os.urandom(16)
        return aes_cbc_encrypt(data, key, iv), "CBC"


def detect_mode(ciphertext):
    return "ECB" if detect_ecb(ciphertext) else "CBC"


# Feed repeated blocks to reliably detect ECB
test_input = b"A" * 48
correct = 0
trials = 100

for _ in range(trials):
    ciphertext, actual = encryption_oracle(test_input)
    guessed = detect_mode(ciphertext)
    if guessed == actual:
        correct += 1

print(f"Detection accuracy: {correct}/{trials}")
