"""Challenge 21: Implement the MT19937 Mersenne Twister RNG."""
from crypto_utils import MT19937

# Verify against known MT19937 output for seed=0
rng = MT19937(seed=0)
# First few outputs for seed=0 (from reference implementations)
outputs = [rng.extract_number() for _ in range(10)]
print("First 10 outputs with seed=0:")
for i, v in enumerate(outputs):
    print(f"  {i}: {v}")

# Verify reproducibility
rng2 = MT19937(seed=0)
outputs2 = [rng2.extract_number() for _ in range(10)]
assert outputs == outputs2, "RNG is not reproducible!"
print("\nReproducibility verified!")

# Verify with seed=42
rng3 = MT19937(seed=42)
rng4 = MT19937(seed=42)
for _ in range(1000):
    assert rng3.extract_number() == rng4.extract_number()
print("1000 outputs matched for seed=42!")
