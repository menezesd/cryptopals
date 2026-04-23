"""Shared crypto utilities for cryptopals set 5."""
import os
import sys
import struct
import hashlib
import hmac as _hmac

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "challenge2"))
from aes_utils import (
    xor_bytes, pkcs7_pad, pkcs7_unpad, BLOCK_SIZE,
    aes_cbc_encrypt, aes_cbc_decrypt, random_key,
)

# NIST prime for DH
NIST_PRIME = int(
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
    "fffffffffffff", 16
)


def sha256(data):
    return hashlib.sha256(data).digest()


def sha1(data):
    return hashlib.sha1(data).digest()


def hmac_sha256(key, msg):
    return _hmac.new(key, msg, hashlib.sha256).digest()


def int_to_bytes(n):
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def bytes_to_int(b):
    return int.from_bytes(b, "big")


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x


def invmod(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"No inverse for {a} mod {m}")
    return x % m


def integer_cube_root(n):
    """Integer cube root using Newton's method."""
    if n < 0:
        return -integer_cube_root(-n)
    if n == 0:
        return 0
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            return x
        x = y
