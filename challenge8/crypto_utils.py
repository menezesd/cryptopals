"""Shared crypto utilities for cryptopals set 8."""
import os
import sys
import hashlib
import random
import struct

_set5_dir = os.path.join(os.path.dirname(__file__), "..", "challenge5")
sys.path.insert(0, _set5_dir)

import importlib.util
_spec5 = importlib.util.spec_from_file_location("set5_utils", os.path.join(_set5_dir, "crypto_utils.py"))
_set5 = importlib.util.module_from_spec(_spec5)
_spec5.loader.exec_module(_set5)

invmod = _set5.invmod
int_to_bytes = _set5.int_to_bytes
bytes_to_int = _set5.bytes_to_int
egcd = _set5.egcd

_spec_rsa = importlib.util.spec_from_file_location("rsa_mod", os.path.join(_set5_dir, "39_rsa.py"))
_rsa = importlib.util.module_from_spec(_spec_rsa)
_spec_rsa.loader.exec_module(_rsa)
gen_prime = _rsa.gen_prime
is_prime = _rsa.is_prime


def sha256(data):
    return hashlib.sha256(data).digest()


# Elliptic curve arithmetic over prime fields
class EllipticCurve:
    """Weierstrass curve y^2 = x^3 + ax + b mod p."""
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None  # point at infinity
        if P == Q:
            lam = (3 * x1 * x1 + self.a) * invmod(2 * y1, self.p) % self.p
        else:
            lam = (y2 - y1) * invmod(x2 - x1, self.p) % self.p
        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def mul(self, k, P):
        R = None
        Q = P
        while k > 0:
            if k & 1:
                R = self.add(R, Q)
            Q = self.add(Q, Q)
            k >>= 1
        return R

    def on_curve(self, P):
        if P is None:
            return True
        x, y = P
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0


# GF(2^128) arithmetic for GCM
def gf128_mul(x, y):
    """Multiply two 128-bit values in GF(2^128) with the GCM polynomial."""
    R = 0xe1 << 120  # x^128 + x^7 + x^2 + x + 1
    z = 0
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= y
        if y & 1:
            y = (y >> 1) ^ R
        else:
            y >>= 1
    return z
