"""Challenge 34: Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection."""
import os
import random
from crypto_utils import NIST_PRIME, sha256, aes_cbc_encrypt, aes_cbc_decrypt, pkcs7_unpad, BLOCK_SIZE

p = NIST_PRIME
g = 2


def dh_keypair(p, g):
    priv = random.randint(1, p - 1)
    pub = pow(g, priv, p)
    return priv, pub


def derive_key(s):
    return sha256(s.to_bytes((s.bit_length() + 7) // 8, "big") if s else b"\x00")[:16]


def encrypt_msg(msg, key):
    iv = os.urandom(BLOCK_SIZE)
    return aes_cbc_encrypt(msg, key, iv) + iv


def decrypt_msg(data, key):
    ct, iv = data[:-BLOCK_SIZE], data[-BLOCK_SIZE:]
    return pkcs7_unpad(aes_cbc_decrypt(ct, key, iv))


# === Normal exchange ===
a_priv, A = dh_keypair(p, g)
b_priv, B = dh_keypair(p, g)
s_a = pow(B, a_priv, p)
s_b = pow(A, b_priv, p)
assert s_a == s_b
key_a = derive_key(s_a)
key_b = derive_key(s_b)

msg = b"Hello from Alice!"
enc = encrypt_msg(msg, key_a)
dec = decrypt_msg(enc, key_b)
assert dec == msg
print(f"Normal exchange: '{dec.decode()}'")

# === MITM attack: inject p as public key ===
# A -> M: p, g, A
# M -> B: p, g, p   (replace A with p)
# B -> M: B
# M -> A: p          (replace B with p)
#
# A computes: s = p^a mod p = 0
# B computes: s = p^b mod p = 0
# M knows:    s = 0

a_priv, A = dh_keypair(p, g)
b_priv, B = dh_keypair(p, g)

# Both sides compute secret with p as the other's public key
s_a = pow(p, a_priv, p)  # = 0
s_b = pow(p, b_priv, p)  # = 0
assert s_a == 0 and s_b == 0

key_a = derive_key(0)
key_b = derive_key(0)
key_m = derive_key(0)  # Mallory knows this

msg_a = b"Hello from Alice!"
enc_a = encrypt_msg(msg_a, key_a)

# Mallory intercepts and decrypts
intercepted = decrypt_msg(enc_a, key_m)
assert intercepted == msg_a

# Forward to Bob, who can also decrypt with his key (same as Mallory's)
dec_b = decrypt_msg(enc_a, key_b)
assert dec_b == msg_a

print(f"MITM attack: intercepted '{intercepted.decode()}'")
print("MITM key-fixing attack succeeded!")
