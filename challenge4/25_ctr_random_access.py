"""Challenge 25: Break 'random access read/write' AES CTR."""
import base64
from crypto_utils import aes_ctr, random_key, xor_bytes, aes_ecb_decrypt, pkcs7_unpad

KEY = random_key()
NONCE = 0

# Recover plaintext from challenge 7 and re-encrypt with CTR
with open("../challenge1/7.txt") as f:
    ecb_ciphertext = base64.b64decode(f.read())
plaintext = pkcs7_unpad(aes_ecb_decrypt(ecb_ciphertext, b"YELLOW SUBMARINE"))
ciphertext = aes_ctr(plaintext, KEY, NONCE)


def edit(ciphertext, key, offset, newtext):
    """Seek into ciphertext, decrypt, and re-encrypt with new plaintext."""
    full_plain = aes_ctr(ciphertext, key, NONCE)
    new_plain = full_plain[:offset] + newtext + full_plain[offset + len(newtext):]
    return aes_ctr(new_plain, key, NONCE)


# Attack: submit all zeros to get the keystream
keystream_ct = edit(ciphertext, KEY, 0, b"\x00" * len(ciphertext))
recovered = xor_bytes(ciphertext, keystream_ct)

assert recovered == plaintext
print(recovered[:200].decode())
print("...")
print("Successfully recovered plaintext via CTR edit oracle!")
