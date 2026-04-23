"""Challenge 35: Implement DH with negotiated groups, and break with malicious g parameters."""
import os
import random
from crypto_utils import NIST_PRIME, sha256, aes_cbc_encrypt, aes_cbc_decrypt, pkcs7_unpad, BLOCK_SIZE

p = NIST_PRIME


def derive_key(s):
    return sha256(s.to_bytes((s.bit_length() + 7) // 8, "big") if s else b"\x00")[:16]


def encrypt_msg(msg, key):
    iv = os.urandom(BLOCK_SIZE)
    return aes_cbc_encrypt(msg, key, iv) + iv


def decrypt_msg(data, key):
    ct, iv = data[:-BLOCK_SIZE], data[-BLOCK_SIZE:]
    return pkcs7_unpad(aes_cbc_decrypt(ct, key, iv))


def test_malicious_g(g_val, possible_secrets, label):
    a = random.randint(1, p - 1)
    b = random.randint(1, p - 1)
    A = pow(g_val, a, p)
    B = pow(g_val, b, p)
    s_a = pow(B, a, p)
    s_b = pow(A, b, p)
    assert s_a == s_b

    key = derive_key(s_a)
    msg = b"Test message for malicious g"
    enc = encrypt_msg(msg, key)

    # MITM: try all possible secrets
    for s in possible_secrets:
        try:
            k = derive_key(s)
            dec = decrypt_msg(enc, k)
            if dec == msg:
                print(f"  g={label}: secret={s}, intercepted '{dec.decode()}'")
                return True
        except Exception:
            continue
    return False


# g = 1: g^x mod p = 1 for all x, so s = 1
print("Testing malicious g values:")
assert test_malicious_g(1, [1], "1")

# g = p: g^x mod p = 0 for all x, so s = 0
assert test_malicious_g(p, [0], "p")

# g = p-1: (p-1)^x mod p = 1 if x even, p-1 if x odd
assert test_malicious_g(p - 1, [1, p - 1], "p-1")

print("All malicious g attacks succeeded!")
