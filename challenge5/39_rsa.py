"""Challenge 39: Implement RSA."""
import random
from crypto_utils import invmod, int_to_bytes, bytes_to_int


def is_prime(n, k=20):
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits):
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(p):
            return p


def rsa_keygen(bits=1024, e=3):
    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits // 2)
        n = p * q
        et = (p - 1) * (q - 1)
        if et % e != 0:
            d = invmod(e, et)
            return (e, n), (d, n)


def rsa_encrypt(m, pub):
    e, n = pub
    return pow(m, e, n)


def rsa_decrypt(c, priv):
    d, n = priv
    return pow(c, d, n)


# Test with small numbers first
pub, priv = rsa_keygen(512)
msg = 42
ct = rsa_encrypt(msg, pub)
pt = rsa_decrypt(ct, priv)
assert pt == msg
print(f"Small test: {msg} -> encrypt -> decrypt -> {pt}")

# Test with string
pub, priv = rsa_keygen(1024)
message = b"Hello, RSA!"
m = bytes_to_int(message)
ct = rsa_encrypt(m, pub)
pt = rsa_decrypt(ct, priv)
recovered = int_to_bytes(pt)
assert recovered == message
print(f"String test: '{message.decode()}' -> encrypt -> decrypt -> '{recovered.decode()}'")

# Verify invmod
assert invmod(17, 3120) == 2753
print("invmod(17, 3120) = 2753 ✓")
print("RSA implemented successfully!")
