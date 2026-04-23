"""Challenge 26: CTR bitflipping."""
import os
from crypto_utils import aes_ctr, random_key, xor_bytes

KEY = random_key()
NONCE = int.from_bytes(os.urandom(8))


def encrypt_userdata(userdata):
    userdata = userdata.replace(";", "").replace("=", "")
    plaintext = (
        "comment1=cooking%20MCs;userdata=" +
        userdata +
        ";comment2=%20like%20a%20pound%20of%20bacon"
    )
    return aes_ctr(plaintext.encode(), KEY, NONCE)


def is_admin(ciphertext):
    plaintext = aes_ctr(ciphertext, KEY, NONCE)
    return b";admin=true;" in plaintext


# In CTR mode, flipping a ciphertext bit directly flips the plaintext bit.
# Submit known plaintext, then XOR the ciphertext to get desired output.
known = "AAAAAAAAAAAAAAAA"  # 16 A's at offset 32
desired = b";admin=true;AAAA"
known_bytes = known.encode()

ct = bytearray(encrypt_userdata(known))

# XOR at the userdata offset (32 bytes in)
for i in range(16):
    ct[32 + i] ^= known_bytes[i] ^ desired[i]

assert is_admin(bytes(ct)), "Attack failed!"
print("CTR bitflipping attack succeeded: ;admin=true; injected!")
