"""Shared crypto utilities for cryptopals set 7."""
import os
import sys
import struct
import hashlib

_challenge2 = os.path.join(os.path.dirname(__file__), "..", "challenge2")
sys.path.insert(0, _challenge2)

from aes_utils import (
    xor_bytes, pkcs7_pad, pkcs7_unpad, BLOCK_SIZE,
    aes_ecb_encrypt_raw, aes_ecb_decrypt_raw,
    aes_cbc_encrypt, aes_cbc_decrypt, random_key,
)


def cbc_mac(msg, key, iv=b"\x00" * 16):
    """CBC-MAC: encrypt with CBC and return last block."""
    ct = aes_cbc_encrypt(msg, key, iv)
    return ct[-BLOCK_SIZE:]


class RC4:
    """RC4 stream cipher."""
    def __init__(self, key):
        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = 0
        self.j = 0

    def generate(self):
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.S[self.i]) % 256
        self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
        return self.S[(self.S[self.i] + self.S[self.j]) % 256]

    def encrypt(self, data):
        return bytes(b ^ self.generate() for b in data)


def md_compress(block, state, hash_size):
    """Simple compression function using AES as the block cipher.
    State is truncated to hash_size bytes."""
    key = state.ljust(16, b"\x00")
    ct = aes_ecb_encrypt_raw(block, key)
    return xor_bytes(ct[:hash_size], state[:hash_size]).ljust(hash_size, b"\x00")[:hash_size]


def iterated_hash(msg, hash_size, state=None):
    """Merkle-Damgard iterated hash using AES compression."""
    if state is None:
        state = b"\x00" * hash_size
    msg = pkcs7_pad(msg, BLOCK_SIZE)
    for i in range(0, len(msg), BLOCK_SIZE):
        state = md_compress(msg[i:i+BLOCK_SIZE], state, hash_size)
    return state
