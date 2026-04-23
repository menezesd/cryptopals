"""Shared crypto utilities for cryptopals set 3."""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "challenge2"))
from aes_utils import (
    xor_bytes, pkcs7_pad, pkcs7_unpad, BLOCK_SIZE,
    aes_ecb_encrypt_raw, aes_ecb_decrypt_raw,
    aes_cbc_encrypt, aes_cbc_decrypt, random_key, detect_ecb,
)


def aes_ctr(data, key, nonce=0):
    """AES-CTR mode encryption/decryption (same operation)."""
    result = b""
    counter = 0
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i+BLOCK_SIZE]
        counter_block = struct.pack("<QQ", nonce, counter)
        keystream = aes_ecb_encrypt_raw(counter_block, key)
        result += xor_bytes(block, keystream[:len(block)])
        counter += 1
    return result


class MT19937:
    """Mersenne Twister MT19937 implementation."""
    W, N, M, R = 32, 624, 397, 31
    A = 0x9908B0DF
    U, D = 11, 0xFFFFFFFF
    S, B = 7, 0x9D2C5680
    T, C = 15, 0xEFC60000
    L = 18
    F = 1812433253
    LOWER_MASK = (1 << R) - 1
    UPPER_MASK = D & ~LOWER_MASK

    def __init__(self, seed=None):
        self.mt = [0] * self.N
        self.index = self.N + 1
        if seed is not None:
            self.seed_mt(seed)

    def seed_mt(self, seed):
        self.index = self.N
        self.mt[0] = seed & self.D
        for i in range(1, self.N):
            self.mt[i] = (self.F * (self.mt[i-1] ^ (self.mt[i-1] >> (self.W - 2))) + i) & self.D

    def extract_number(self):
        if self.index >= self.N:
            self._twist()
        y = self.mt[self.index]
        y ^= (y >> self.U) & self.D
        y ^= (y << self.S) & self.B
        y ^= (y << self.T) & self.C
        y ^= y >> self.L
        self.index += 1
        return y & self.D

    def _twist(self):
        for i in range(self.N):
            x = (self.mt[i] & self.UPPER_MASK) | (self.mt[(i+1) % self.N] & self.LOWER_MASK)
            xA = x >> 1
            if x & 1:
                xA ^= self.A
            self.mt[i] = self.mt[(i + self.M) % self.N] ^ xA
        self.index = 0

    def set_state(self, state):
        """Set internal state directly (for cloning)."""
        self.mt = list(state)
        self.index = self.N


def untemper(y):
    """Invert the MT19937 tempering transform."""
    # Invert y ^= y >> L (18)
    y = _undo_right_shift_xor(y, 18)
    # Invert y ^= (y << T) & C
    y = _undo_left_shift_xor_mask(y, 15, 0xEFC60000)
    # Invert y ^= (y << S) & B
    y = _undo_left_shift_xor_mask(y, 7, 0x9D2C5680)
    # Invert y ^= (y >> U) & D
    y = _undo_right_shift_xor(y, 11)
    return y


def _undo_right_shift_xor(val, shift):
    result = val
    for i in range(shift, 32, shift):
        result ^= (result >> shift)
    # More precise approach
    result = val
    for i in range(32):
        bit = (result >> (31 - i)) & 1
        if 31 - i + shift < 32:
            src_bit = (result >> (31 - i + shift)) & 1
            bit ^= src_bit
        result = (result & ~(1 << (31 - i))) | (bit << (31 - i))
    return result & 0xFFFFFFFF


def _undo_left_shift_xor_mask(val, shift, mask):
    result = val
    for i in range(32):
        bit = (result >> i) & 1
        if i - shift >= 0:
            src_bit = (result >> (i - shift)) & 1
            mask_bit = (mask >> i) & 1
            bit ^= (src_bit & mask_bit)
        result = (result & ~(1 << i)) | (bit << i)
    return result & 0xFFFFFFFF
