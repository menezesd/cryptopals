"""Challenge 57: Diffie-Hellman Revisited: Small Subgroup Confinement."""
import random
import hashlib
from crypto_utils import invmod

# Use a prime p where p-1 has small factors
# For demonstration, use a manageable prime
p = 7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771
g = 4565356397095740655436854503483826580667428462436585703136657806579260818123348357189637570067466227539222735114468706434976519289782837484287143602987
q = 236234353446506858198510045061214171961  # large prime factor of p-1

# Bob's secret key
b = random.randint(1, q - 1)
B = pow(g, b, p)

# Small subgroup attack: find factors of (p-1)/q
# p-1 = q * cofactor; if cofactor has small factors r1, r2, ...,
# we can find b mod ri for each, then use CRT.

# For demonstration, we'll use the CRT approach with known small factors
# Let's factor (p-1) to find small factors
composite = (p - 1) // q

# Find small prime factors
small_factors = []
temp = composite
for f in range(2, 2**16):
    if temp % f == 0:
        small_factors.append(f)
        while temp % f == 0:
            temp //= f

print(f"Found {len(small_factors)} small factors of (p-1)/q")

# For each small factor r, find b mod r
residues = []
moduli = []

for r in small_factors:
    # Find element h of order r
    while True:
        h_candidate = random.randint(2, p - 1)
        h = pow(h_candidate, (p - 1) // r, p)
        if h != 1:
            break

    # Send h as our "public key" — Bob computes h^b mod p
    # Since h has order r, h^b mod p = h^(b mod r) mod p
    bob_shared = pow(h, b, p)

    # Brute force b mod r
    for x in range(r):
        if pow(h, x, p) == bob_shared:
            residues.append(x)
            moduli.append(r)
            break

if residues:
    # CRT to recover b mod product(moduli)
    # Simple CRT
    M = 1
    for m in moduli:
        M *= m

    result = 0
    for r_i, m_i in zip(residues, moduli):
        Mi = M // m_i
        result += r_i * Mi * invmod(Mi, m_i)
    result %= M

    print(f"Recovered b mod {M} = {result}")
    print(f"Actual    b mod {M} = {b % M}")
    assert result == b % M
    print("Small subgroup confinement attack succeeded!")
else:
    print("No small factors found for demonstration")
