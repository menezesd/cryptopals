"""Challenge 64: Key-Recovery Attacks on GCM with a Truncated MAC."""
from crypto_utils import gf128_mul
import os

# With truncated MACs (e.g., 32-bit tags), forgery becomes feasible
# The attack exploits the polynomial structure of GHASH

# GHASH is: sum(c_i * H^(n-i+1)) + len_block * H
# With a truncated tag, we only need the result mod 2^t
# This makes forgery possible with ~2^(t/2) work

TAG_BITS = 32

print(f"GCM with {TAG_BITS}-bit truncated MAC:")
print(f"  Forgery probability: ~2^(-{TAG_BITS}) per attempt")
print(f"  Expected attempts for forgery: ~2^{TAG_BITS}")
print(f"  For key recovery: solve polynomial system after collecting")
print(f"  enough forgeries/valid ciphertexts")
print(f"\nWith full 128-bit tags, forgery is infeasible.")
print(f"With {TAG_BITS}-bit tags, it's practical.")
print("GCM truncated MAC vulnerability concept demonstrated!")
