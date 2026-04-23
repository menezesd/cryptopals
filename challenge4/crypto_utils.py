"""Shared crypto utilities for cryptopals set 4."""
import os
import struct
import sys

_challenge2 = os.path.join(os.path.dirname(__file__), "..", "challenge2")
_challenge3 = os.path.join(os.path.dirname(__file__), "..", "challenge3")
sys.path.insert(0, _challenge2)

from aes_utils import (
    xor_bytes, pkcs7_pad, pkcs7_unpad, BLOCK_SIZE,
    aes_ecb_encrypt_raw, aes_ecb_decrypt_raw,
    aes_cbc_encrypt, aes_cbc_decrypt, random_key, detect_ecb,
    aes_ecb_encrypt, aes_ecb_decrypt,
)

# Import aes_ctr from challenge3's crypto_utils (avoiding name collision)
import importlib.util
_spec = importlib.util.spec_from_file_location("set3_utils", os.path.join(_challenge3, "crypto_utils.py"))
_set3 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_set3)
aes_ctr = _set3.aes_ctr


def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF


class SHA1:
    """Pure Python SHA-1 implementation."""

    def __init__(self, state=None, msg_len=0):
        if state:
            self.h = list(state)
        else:
            self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        self._msg_len = msg_len
        self._buffer = b""

    def update(self, data):
        self._buffer += data
        self._msg_len += len(data)
        while len(self._buffer) >= 64:
            self._process_block(self._buffer[:64])
            self._buffer = self._buffer[64:]
        return self

    def _process_block(self, block):
        w = list(struct.unpack(">16I", block))
        for i in range(16, 80):
            w.append(left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1))

        a, b, c, d, e = self.h

        for i in range(80):
            if i < 20:
                f = (b & c) | (~b & d) & 0xFFFFFFFF
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (left_rotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF

    def digest(self):
        # Pad
        msg = self._buffer
        msg_len_bits = self._msg_len * 8
        msg += b"\x80"
        while (len(msg) % 64) != 56:
            msg += b"\x00"
        msg += struct.pack(">Q", msg_len_bits)

        # Process remaining blocks
        h_save = list(self.h)
        for i in range(0, len(msg), 64):
            self._process_block(msg[i:i+64])
        result = struct.pack(">5I", *self.h)
        self.h = h_save
        return result

    def hexdigest(self):
        return self.digest().hex()


def sha1(data):
    return SHA1().update(data).digest()


def sha1_mac(key, message):
    return sha1(key + message)


def md_padding_sha1(msg_len):
    """Generate SHA-1/MD padding for a message of given length."""
    padding = b"\x80"
    while (msg_len + len(padding)) % 64 != 56:
        padding += b"\x00"
    padding += struct.pack(">Q", msg_len * 8)
    return padding


class MD4:
    """Pure Python MD4 implementation."""

    def __init__(self, state=None, msg_len=0):
        if state:
            self.h = list(state)
        else:
            self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        self._msg_len = msg_len
        self._buffer = b""

    def update(self, data):
        self._buffer += data
        self._msg_len += len(data)
        while len(self._buffer) >= 64:
            self._process_block(self._buffer[:64])
            self._buffer = self._buffer[64:]
        return self

    def _process_block(self, block):
        x = list(struct.unpack("<16I", block))

        def F(x, y, z): return (x & y) | (~x & z) & 0xFFFFFFFF
        def G(x, y, z): return (x & y) | (x & z) | (y & z)
        def H(x, y, z): return x ^ y ^ z

        a, b, c, d = self.h

        # Round 1
        for i in [0, 4, 8, 12]:
            a = left_rotate((a + F(b, c, d) + x[i]) & 0xFFFFFFFF, 3)
            d = left_rotate((d + F(a, b, c) + x[i+1]) & 0xFFFFFFFF, 7)
            c = left_rotate((c + F(d, a, b) + x[i+2]) & 0xFFFFFFFF, 11)
            b = left_rotate((b + F(c, d, a) + x[i+3]) & 0xFFFFFFFF, 19)

        # Round 2
        for i in [0, 1, 2, 3]:
            a = left_rotate((a + G(b, c, d) + x[i] + 0x5A827999) & 0xFFFFFFFF, 3)
            d = left_rotate((d + G(a, b, c) + x[i+4] + 0x5A827999) & 0xFFFFFFFF, 5)
            c = left_rotate((c + G(d, a, b) + x[i+8] + 0x5A827999) & 0xFFFFFFFF, 9)
            b = left_rotate((b + G(c, d, a) + x[i+12] + 0x5A827999) & 0xFFFFFFFF, 13)

        # Round 3
        for i in [0, 2, 1, 3]:
            a = left_rotate((a + H(b, c, d) + x[i] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
            d = left_rotate((d + H(a, b, c) + x[i+8] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
            c = left_rotate((c + H(d, a, b) + x[i+4] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
            b = left_rotate((b + H(c, d, a) + x[i+12] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)

        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF

    def digest(self):
        msg = self._buffer
        msg_len_bits = self._msg_len * 8
        msg += b"\x80"
        while (len(msg) % 64) != 56:
            msg += b"\x00"
        msg += struct.pack("<Q", msg_len_bits)

        h_save = list(self.h)
        for i in range(0, len(msg), 64):
            self._process_block(msg[i:i+64])
        result = struct.pack("<4I", *self.h)
        self.h = h_save
        return result

    def hexdigest(self):
        return self.digest().hex()


def md4(data):
    return MD4().update(data).digest()


def md4_mac(key, message):
    return md4(key + message)


def md_padding_md4(msg_len):
    """Generate MD4 padding for a message of given length."""
    padding = b"\x80"
    while (msg_len + len(padding)) % 64 != 56:
        padding += b"\x00"
    padding += struct.pack("<Q", msg_len * 8)
    return padding


def hmac_sha1(key, message):
    if len(key) > 64:
        key = sha1(key)
    key = key.ljust(64, b"\x00")
    o_key_pad = xor_bytes(key, b"\x5c" * 64)
    i_key_pad = xor_bytes(key, b"\x36" * 64)
    return sha1(o_key_pad + sha1(i_key_pad + message))
