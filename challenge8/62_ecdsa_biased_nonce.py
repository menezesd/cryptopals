"""Challenge 62: Key-Recovery Attacks on ECDSA with Biased Nonces."""
import random
import hashlib
from crypto_utils import EllipticCurve, invmod

# Small curve with prime order
p = 101
a_coeff = -5
b_coeff = 6
curve = EllipticCurve(a_coeff, b_coeff, p)

# Find generator and order
G = None
n = 0
for x in range(p):
    rhs = (x * x * x + a_coeff * x + b_coeff) % p
    for y in range(p):
        if (y * y) % p == rhs:
            pt = (x, y)
            for order in range(2, 200):
                if curve.mul(order, pt) is None:
                    if order > n:
                        G = pt
                        n = order
                    break
            break

print(f"Generator {G}, order {n}")

# Secret key
d = random.randint(1, n - 1)
Q = curve.mul(d, G)

# Generate signatures with biased nonces (small k)
MAX_K = n // 4  # k is in a small range
sigs = []
for i in range(10):
    msg = f"msg{i}".encode()
    h = int(hashlib.sha256(msg).hexdigest(), 16) % n
    k = random.randint(1, MAX_K)
    R = curve.mul(k, G)
    r = R[0] % n
    if r == 0:
        continue
    try:
        s = (invmod(k, n) * (h + r * d)) % n
        if s != 0:
            sigs.append((h, r, s))
    except ValueError:
        continue

# With biased k, try brute-forcing k for each signature
# Since k < n/4, the search space is small
print(f"\nBrute-forcing {len(sigs)} signatures with k < {MAX_K}...")
for h, r, s in sigs:
    for k_guess in range(1, MAX_K + 1):
        d_candidate = ((s * k_guess - h) * invmod(r, n)) % n
        if curve.mul(d_candidate, G) == Q:
            print(f"Recovered secret key d = {d_candidate} (actual: {d})")
            assert d_candidate == d
            print("ECDSA biased nonce key recovery succeeded!")
            break
    else:
        continue
    break
