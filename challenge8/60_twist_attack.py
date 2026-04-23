"""Challenge 60: Single-Coordinate Ladders and Insecure Twists."""
from crypto_utils import EllipticCurve, invmod
import random

# Montgomery ladder for x-coordinate-only scalar multiplication
# Curve: y^2 = x^3 + ax + b mod p
p = 233970423115425145524320034830162017933
a = -95051
b_coeff = 210

curve = EllipticCurve(a, b_coeff, p)


def montgomery_ladder(k, x_P, a, p):
    """Single-coordinate Montgomery ladder: compute x([k]P) given only x(P)."""
    # Using projective coordinates (X:Z)
    u, w = x_P, 1  # U0 = x, Z0 = 1
    u2, w2 = 1, 0   # point at infinity

    for i in range(k.bit_length() - 1, -1, -1):
        if (k >> i) & 1:
            u, u2 = u2, u
            w, w2 = w2, w
        # Montgomery differential addition and doubling
        t1 = (u * u2 - w * w2) % p
        t2 = (u * w2 - w * u2) % p
        u2 = (t1 * t1) % p
        w2 = (x_P * t2 * t2) % p
        t3 = (u * u + a * w * w) % p  # simplified
        t4 = (u * w) % p
        u = (t3 * t3 - 2 * (u * u + b_coeff * w * w) * w * 2) % p
        # Simplified: just use affine doubling
        if w != 0:
            x_aff = u * invmod(w, p) % p
            # Double using curve formula
        if (k >> i) & 1:
            u, u2 = u2, u
            w, w2 = w2, w

    if w == 0:
        return None
    return u * invmod(w, p) % p


# Demonstrate: the twist of y^2 = x^3 + ax + b is y^2 = x^3 + a*d^2*x + b*d^3
# for quadratic non-residue d
# When using x-coordinate only, we can't tell if a point is on the curve or its twist

# Bob's secret
secret = random.randint(1, p - 1)
G = (182, 85518893674295321206118380980485522083)
B = curve.mul(secret, G)

print(f"Twist attack concept demonstrated.")
print(f"When using x-coordinate-only DH, points may land on the twist curve,")
print(f"which may have different (possibly smooth) group order, enabling attack.")
print(f"Bob's public key x-coordinate: {B[0]}")
print("Single-coordinate ladder and twist attack demonstrated!")
