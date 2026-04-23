"""Challenge 22: Crack an MT19937 seed."""
import time
import random
from crypto_utils import MT19937


def simulate_seeded_output():
    """Simulate the routine: wait, seed with timestamp, wait, return first output."""
    # Simulate time passage instead of actually waiting
    now = int(time.time())
    seed_time = now - random.randint(40, 1000)
    rng = MT19937(seed=seed_time)
    return rng.extract_number(), seed_time


def crack_seed(output):
    """Brute-force the seed by trying recent timestamps."""
    now = int(time.time())
    for candidate in range(now, now - 2000, -1):
        rng = MT19937(seed=candidate)
        if rng.extract_number() == output:
            return candidate
    raise RuntimeError("Seed not found")


output, actual_seed = simulate_seeded_output()
cracked = crack_seed(output)

print(f"Actual seed:  {actual_seed}")
print(f"Cracked seed: {cracked}")
assert actual_seed == cracked
print("Successfully cracked MT19937 seed!")
