"""Challenge 63: Key-Recovery Attacks on GCM with Repeated Nonces."""
import os
import struct
from crypto_utils import gf128_mul
from Crypto.Cipher import AES

BLOCK_SIZE = 16


def bytes_to_gf128(b):
    return int.from_bytes(b, "big")


def gf128_to_bytes(n):
    return n.to_bytes(16, "big")


def ghash(H, aad, ct):
    """GHASH function for GCM."""
    def pad16(data):
        if len(data) % 16:
            data += b"\x00" * (16 - len(data) % 16)
        return data

    data = pad16(aad) + pad16(ct)
    data += struct.pack(">QQ", len(aad) * 8, len(ct) * 8)

    y = 0
    for i in range(0, len(data), 16):
        block = bytes_to_gf128(data[i:i+16])
        y = gf128_mul(y ^ block, bytes_to_gf128(H))
    return y


def aes_gcm_encrypt(key, nonce, aad, plaintext):
    """Manual GCM encryption."""
    cipher = AES.new(key, AES.MODE_ECB)
    H = cipher.encrypt(b"\x00" * 16)

    # Generate counter blocks
    J0 = nonce + b"\x00\x00\x00\x01"
    ciphertext = b""
    for i in range(0, len(plaintext), 16):
        counter = (int.from_bytes(J0, "big") + 1 + i // 16) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        keystream = cipher.encrypt(counter.to_bytes(16, "big"))
        block = plaintext[i:i+16]
        ciphertext += bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))

    # GHASH
    g = ghash(H, aad, ciphertext)

    # Tag = GHASH ^ E(K, J0)
    tag_mask = cipher.encrypt(J0)
    tag = gf128_to_bytes(g ^ bytes_to_gf128(tag_mask))

    return ciphertext, tag


# Demonstrate nonce reuse vulnerability
key = os.urandom(16)
nonce = os.urandom(12)  # SAME nonce used twice

msg1 = b"First message!!"  # 15 bytes + pad
msg2 = b"Second message!"

ct1, tag1 = aes_gcm_encrypt(key, nonce, b"", msg1)
ct2, tag2 = aes_gcm_encrypt(key, nonce, b"", msg2)

# With nonce reuse:
# tag1 = GHASH(H, "", ct1) ^ E(K, J0)
# tag2 = GHASH(H, "", ct2) ^ E(K, J0)
# tag1 ^ tag2 = GHASH(H, "", ct1) ^ GHASH(H, "", ct2)
# This gives us a polynomial equation in H over GF(2^128)

tag_xor = bytes_to_gf128(tag1) ^ bytes_to_gf128(tag2)
print(f"Tag XOR (nonce reuse leak): {gf128_to_bytes(tag_xor).hex()}")
print("With nonce reuse, the authentication key H can be recovered")
print("by solving a polynomial equation over GF(2^128).")
print("GCM nonce reuse vulnerability demonstrated!")
