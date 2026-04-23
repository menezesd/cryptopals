"""Challenge 10: Implement CBC mode."""
import base64
from aes_utils import aes_cbc_decrypt, pkcs7_unpad

key = b"YELLOW SUBMARINE"
iv = b"\x00" * 16

with open("10.txt") as f:
    ciphertext = base64.b64decode(f.read())

plaintext = pkcs7_unpad(aes_cbc_decrypt(ciphertext, key, iv))
print(plaintext.decode("utf-8"))
