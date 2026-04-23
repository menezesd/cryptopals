"""Challenge 61: Duplicate-Signature Key Selection in ECDSA (and RSA)."""
import random
from crypto_utils import EllipticCurve, invmod
import hashlib

# Small curve with prime order: y^2 = x^3 - 5x + 6 mod 101 (order 89)
p = 101
a_coeff = -5
b_coeff = 6
curve = EllipticCurve(a_coeff, b_coeff, p)

# Find curve order and generator
points = [None]
for x in range(p):
    rhs = (x * x * x + a_coeff * x + b_coeff) % p
    for y in range(p):
        if (y * y) % p == rhs:
            points.append((x, y))

G = points[1]
# Find order of G
for n in range(1, len(points) + 1):
    if curve.mul(n, G) is None:
        break

print(f"Curve order: {len(points)}, Generator order: {n}")

# Alice's key
d_a = random.randint(1, n - 1)
Q_a = curve.mul(d_a, G)

# Alice signs
msg = b"hello"
h = int(hashlib.sha256(msg).hexdigest(), 16) % n
k = random.randint(1, n - 1)
while True:
    R = curve.mul(k, G)
    r = R[0] % n
    if r != 0:
        try:
            s = (invmod(k, n) * (h + r * d_a)) % n
            if s != 0:
                break
        except ValueError:
            pass
    k = random.randint(1, n - 1)

# Verify original
w = invmod(s, n)
u1 = (h * w) % n
u2 = (r * w) % n
V = curve.add(curve.mul(u1, G), curve.mul(u2, Q_a))
assert V is not None and V[0] % n == r
print(f"Original signature (r={r}, s={s}) verifies under Alice's key!")

# Attack: find different key that verifies the same sig
# Pick new d', compute G' = invmod(u1 + u2*d', n) * R
d_prime = random.randint(1, n - 1)
t = (u1 + u2 * d_prime) % n
if t != 0:
    try:
        G_prime = curve.mul(invmod(t, n), R)
        Q_prime = curve.mul(d_prime, G_prime)

        V2 = curve.add(curve.mul(u1, G_prime), curve.mul(u2, Q_prime))
        if V2 is not None and V2[0] % n == r:
            print(f"Same signature verifies under DIFFERENT key!")
            print(f"  Original Q: {Q_a}")
            print(f"  Forged Q':  {Q_prime}")
            print("Duplicate-signature key selection succeeded!")
        else:
            print("Verification mismatch (small curve edge case)")
    except ValueError:
        print("No inverse (small curve edge case)")
else:
    print("t=0 edge case")
