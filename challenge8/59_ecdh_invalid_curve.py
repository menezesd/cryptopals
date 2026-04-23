"""Challenge 59: Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks."""
import random
from crypto_utils import EllipticCurve, invmod

# Use a small curve: y^2 = x^3 + 2x + 3 mod 97
p = 97
a = 2
b_coeff = 3

curve = EllipticCurve(a, b_coeff, p)

# Find the generator and order
def find_curve_order(curve, p):
    """Find all points on the curve (brute force for small p)."""
    points = [None]  # include point at infinity
    for x in range(p):
        rhs = (x * x * x + curve.a * x + curve.b) % p
        for y in range(p):
            if (y * y) % p == rhs:
                points.append((x, y))
    return points

points = find_curve_order(curve, p)
n = len(points)  # group order
print(f"Curve y^2 = x^3 + {a}x + {b_coeff} mod {p}: {n} points")

# Pick a generator
G = points[1]
assert curve.on_curve(G)

# Find order of G
for order_g in range(1, n + 1):
    if curve.mul(order_g, G) is None:
        break

print(f"Generator {G}, order {order_g}")

# Bob's secret key
secret = random.randint(1, order_g - 1)
B = curve.mul(secret, G)

# Invalid curve attack: use points from y^2 = x^3 + ax + b' (same a, different b)
# Bob doesn't validate that the point is on the right curve
print("\nInvalid curve attack:")
residues = []
moduli = []

for b_prime in range(p):
    if b_prime == b_coeff:
        continue
    bad_curve = EllipticCurve(a, b_prime, p)
    bad_points = find_curve_order(bad_curve, p)
    bad_order = len(bad_points)

    # Find points with small PRIME order
    from math import gcd
    for pt in bad_points[1:]:
        for r in [2, 3, 5, 7, 11, 13, 17, 19]:
            if bad_curve.mul(r, pt) is None:
                # Check r is coprime with existing moduli product
                M_cur = 1
                for m in moduli:
                    M_cur *= m
                if gcd(r, M_cur) == 1:
                    bob_result = bad_curve.mul(secret, pt)
                    for x in range(r):
                        if bad_curve.mul(x, pt) == bob_result:
                            residues.append(x)
                            moduli.append(r)
                            print(f"  b'={b_prime}: secret ≡ {x} (mod {r})")
                            break
                break

    if len(residues) >= 4:
        break

if len(residues) >= 2:
    # CRT
    M = 1
    for m in moduli:
        M *= m
    result = 0
    for r_i, m_i in zip(residues, moduli):
        Mi = M // m_i
        result += r_i * Mi * invmod(Mi, m_i)
    result %= M
    print(f"\nRecovered secret mod {M} = {result}")
    print(f"Actual    secret mod {M} = {secret % M}")
    assert result == secret % M
    print("Invalid curve attack succeeded!")
