"""Challenge 16: CBC bitflipping attacks."""
from aes_utils import aes_cbc_encrypt, aes_cbc_decrypt, random_key, xor_bytes, BLOCK_SIZE
import os

KEY = random_key()
IV = os.urandom(BLOCK_SIZE)


def encrypt_userdata(userdata):
    # Escape metacharacters
    userdata = userdata.replace(";", "").replace("=", "")
    plaintext = (
        "comment1=cooking%20MCs;userdata=" +
        userdata +
        ";comment2=%20like%20a%20pound%20of%20bacon"
    )
    return aes_cbc_encrypt(plaintext.encode(), KEY, IV)


def is_admin(ciphertext):
    plaintext = aes_cbc_decrypt(ciphertext, KEY, IV)
    return b";admin=true;" in plaintext


# Attack:
# Block 0: "comment1=cooking"
# Block 1: "%20MCs;userdata="
# Block 2: our input (16 bytes)
# Block 3: ";comment2=%20lik"
#
# We submit 16 bytes of known plaintext in block 2.
# Then we flip bits in block 1 (the ciphertext) to make block 2 decrypt to ";admin=true;AAAA"
#
# CBC decrypt: P2 = D(C2) ^ C1
# If we XOR C1 with (known_P2 ^ desired_P2), then P2 becomes desired.

known = b"A" * BLOCK_SIZE
desired = b";admin=true;AAAA"

ciphertext = bytearray(encrypt_userdata("A" * BLOCK_SIZE))

# Modify block 1 (bytes 16-31) to flip block 2's plaintext
for i in range(BLOCK_SIZE):
    ciphertext[BLOCK_SIZE + i] ^= known[i] ^ desired[i]

assert is_admin(bytes(ciphertext)), "Attack failed!"
print("CBC bitflipping attack succeeded: ;admin=true; injected!")
