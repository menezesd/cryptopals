"""Challenge 17: The CBC padding oracle."""
import base64
import os
from crypto_utils import (
    aes_cbc_encrypt, aes_cbc_decrypt, pkcs7_unpad, pkcs7_pad,
    random_key, xor_bytes, BLOCK_SIZE,
)

KEY = random_key()

STRINGS = [
    b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteiBo",
]


def encryption_oracle():
    plaintext = base64.b64decode(STRINGS[int.from_bytes(os.urandom(1)) % len(STRINGS)])
    iv = os.urandom(BLOCK_SIZE)
    return aes_cbc_encrypt(plaintext, KEY, iv), iv


def padding_oracle(ciphertext, iv):
    try:
        plaintext = aes_cbc_decrypt(ciphertext, KEY, iv)
        pkcs7_unpad(plaintext)
        return True
    except ValueError:
        return False


def attack_block(prev_block, target_block):
    """Decrypt a single block using the padding oracle."""
    intermediate = bytearray(BLOCK_SIZE)

    for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
        pad_val = BLOCK_SIZE - byte_pos

        # Build the crafted previous block
        crafted = bytearray(BLOCK_SIZE)
        for k in range(byte_pos + 1, BLOCK_SIZE):
            crafted[k] = intermediate[k] ^ pad_val

        for guess in range(256):
            crafted[byte_pos] = guess
            if padding_oracle(target_block, bytes(crafted)):
                # Avoid false positive on last byte
                if byte_pos == BLOCK_SIZE - 1:
                    # Flip a prior byte to confirm it's not a longer valid padding
                    check = bytearray(crafted)
                    check[byte_pos - 1] ^= 1
                    if not padding_oracle(target_block, bytes(check)):
                        continue
                intermediate[byte_pos] = guess ^ pad_val
                break

    return xor_bytes(bytes(intermediate), prev_block)


def attack(ciphertext, iv):
    blocks = [iv] + [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    plaintext = b""
    for i in range(1, len(blocks)):
        plaintext += attack_block(blocks[i-1], blocks[i])
    return pkcs7_unpad(plaintext)


# Run the attack
ciphertext, iv = encryption_oracle()
recovered = attack(ciphertext, iv)
print(f"Recovered: {recovered.decode()}")
