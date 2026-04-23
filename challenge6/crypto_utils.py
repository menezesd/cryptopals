"""Shared crypto utilities for cryptopals set 6."""
import os
import sys
import hashlib
import random

_set5_dir = os.path.join(os.path.dirname(__file__), "..", "challenge5")

import importlib.util

_spec5 = importlib.util.spec_from_file_location("set5_utils", os.path.join(_set5_dir, "crypto_utils.py"))
_set5 = importlib.util.module_from_spec(_spec5)
_spec5.loader.exec_module(_set5)
invmod = _set5.invmod
int_to_bytes = _set5.int_to_bytes
bytes_to_int = _set5.bytes_to_int
integer_cube_root = _set5.integer_cube_root

_spec = importlib.util.spec_from_file_location(
    "rsa_mod", os.path.join(_set5_dir, "39_rsa.py")
)
_rsa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rsa)
rsa_keygen = _rsa.rsa_keygen
rsa_encrypt = _rsa.rsa_encrypt
rsa_decrypt = _rsa.rsa_decrypt
gen_prime = _rsa.gen_prime
is_prime = _rsa.is_prime

# DSA parameters from the challenge
DSA_P = int(
    "800000000000000089e1855218a0e7dac38136ffafa72eda7"
    "859f2171e25e65eac698c1702578b07dc2a1076da241c76c"
    "62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139e"
    "beac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c"
    "7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015e"
    "fc871a584471bb1", 16
)
DSA_Q = int("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
DSA_G = int(
    "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"
    "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"
    "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a04"
    "70f5b64c36b625a097f1651fe775323556fe00b3608c8878"
    "92878480e99041be601a62166ca6894bdd41a7054ec89f756"
    "ba9fc95302291", 16
)


def sha1(data):
    return hashlib.sha1(data).digest()


def sha1_int(data):
    return int.from_bytes(sha1(data), "big")


def dsa_sign(msg, x, p=DSA_P, q=DSA_Q, g=DSA_G, k=None):
    h = sha1_int(msg)
    if k is None:
        k = random.randint(1, q - 1)
    r = pow(g, k, p) % q
    s = (invmod(k, q) * (h + x * r)) % q
    return r, s, k


def dsa_verify(msg, r, s, y, p=DSA_P, q=DSA_Q, g=DSA_G):
    if not (0 < r < q and 0 < s < q):
        return False
    h = sha1_int(msg)
    w = invmod(s, q)
    u1 = (h * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(g, u2, p) % p) % q
    # Fix: should be (pow(g, u1, p) * pow(y, u2, p) % p) % q
    v = (pow(g, u1, p) * pow(y, u2, p) % p) % q
    return v == r


def dsa_keygen(p=DSA_P, q=DSA_Q, g=DSA_G):
    x = random.randint(1, q - 1)
    y = pow(g, x, p)
    return x, y
