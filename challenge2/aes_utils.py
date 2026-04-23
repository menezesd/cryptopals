"""Shared AES utilities for cryptopals set 2."""
import os
from Crypto.Cipher import AES

BLOCK_SIZE = 16


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def pkcs7_pad(data, block_size=BLOCK_SIZE):
    pad_len = block_size - len(data) % block_size
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data):
    pad_len = data[-1]
    if pad_len == 0 or pad_len > len(data):
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def aes_ecb_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(plaintext))


def aes_ecb_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)


def aes_ecb_encrypt_raw(block, key):
    """Encrypt a single block (no padding)."""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)


def aes_ecb_decrypt_raw(block, key):
    """Decrypt a single block (no padding)."""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block)


def aes_cbc_encrypt(plaintext, key, iv):
    plaintext = pkcs7_pad(plaintext)
    blocks = [plaintext[i:i+BLOCK_SIZE] for i in range(0, len(plaintext), BLOCK_SIZE)]
    ciphertext = b""
    prev = iv
    for block in blocks:
        encrypted = aes_ecb_encrypt_raw(xor_bytes(block, prev), key)
        ciphertext += encrypted
        prev = encrypted
    return ciphertext


def aes_cbc_decrypt(ciphertext, key, iv):
    blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    plaintext = b""
    prev = iv
    for block in blocks:
        decrypted = xor_bytes(aes_ecb_decrypt_raw(block, key), prev)
        plaintext += decrypted
        prev = block
    return plaintext


def random_key():
    return os.urandom(BLOCK_SIZE)


def detect_ecb(ciphertext, block_size=BLOCK_SIZE):
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) != len(set(blocks))
