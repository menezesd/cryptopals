"""Challenge 33: Implement Diffie-Hellman."""
import random
from crypto_utils import NIST_PRIME, sha256

# Small example: p=37, g=5
p, g = 37, 5
a = random.randint(1, p - 1)
A = pow(g, a, p)
b = random.randint(1, p - 1)
B = pow(g, b, p)

s_a = pow(B, a, p)
s_b = pow(A, b, p)
assert s_a == s_b
print(f"Small DH: p=37, g=5, shared secret={s_a}")

# NIST prime example
p = NIST_PRIME
g = 2
a = random.randint(1, p - 1)
A = pow(g, a, p)
b = random.randint(1, p - 1)
B = pow(g, b, p)

s_a = pow(B, a, p)
s_b = pow(A, b, p)
assert s_a == s_b

key = sha256(s_a.to_bytes((s_a.bit_length() + 7) // 8, "big"))[:16]
print(f"NIST DH: shared secret matches, derived key={key.hex()}")
print("Diffie-Hellman implemented successfully!")
