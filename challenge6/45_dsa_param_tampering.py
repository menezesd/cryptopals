"""Challenge 45: DSA parameter tampering."""
from crypto_utils import DSA_P, DSA_Q, DSA_G, invmod, sha1_int, dsa_keygen

p, q = DSA_P, DSA_Q

# Part 1: g = 0
# With g=0, all signatures have r=0 and any signature verifies
print("Part 1: g=0")
print("  g=0 makes r = (0^k mod p) mod q = 0")
print("  Any s value creates a 'valid' signature (r=0 bypasses verification)")

# Part 2: g = p+1 (≡ 1 mod p)
g_bad = p + 1
x, y = dsa_keygen(p, q, g_bad)

# Magic signature: for any message
# With g = p+1 ≡ 1 mod p: y = g^x mod p = 1
# r = (y^z % p) % q, s = r * invmod(z, q) % q
# This verifies for any message because:
# v = g^(h*w) * y^(r*w) mod p = 1^anything * 1^anything = 1 mod p... hmm

# Actually with g ≡ 1 mod p: y = 1, and pow(g, anything, p) = 1
# So v = 1 % q, and r = 1 % q = 1
# We need r = s, and we can set r = 1, s = 1/z * r mod q
z = sha1_int(b"Hello, world")
r = pow(g_bad, 1, p) % q  # = 1
s = (r * invmod(z, q)) % q

# Verify: w = s^-1 mod q, u1 = h*w mod q, u2 = r*w mod q
# v = (g^u1 * y^u2 mod p) mod q = (1 * 1 mod p) mod q = 1 = r ✓
w = invmod(s, q)
u1 = (z * w) % q
u2 = (r * w) % q
v = (pow(g_bad, u1, p) * pow(y, u2, p) % p) % q

msg1 = b"Hello, world"
msg2 = b"Goodbye, world"

print(f"\nPart 2: g=p+1")
print(f"  Magic signature: r={r}, s={s}")
print(f"  Verifies for '{msg1.decode()}': {v == r}")

# Same r works for any message (since g^anything mod p = 1)
z2 = sha1_int(msg2)
s2 = (r * invmod(z2, q)) % q
w2 = invmod(s2, q)
v2 = (pow(g_bad, (z2 * w2) % q, p) * pow(y, (r * w2) % q, p) % p) % q
print(f"  Verifies for '{msg2.decode()}': {v2 == r}")

print("DSA parameter tampering demonstrated!")
