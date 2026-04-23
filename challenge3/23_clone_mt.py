"""Challenge 23: Clone an MT19937 RNG from its output."""
from crypto_utils import MT19937, untemper

# Create an RNG with a random seed
import os
original = MT19937(seed=int.from_bytes(os.urandom(4)))

# Tap 624 outputs
outputs = [original.extract_number() for _ in range(624)]

# Untemper each output to recover the internal state
state = [untemper(o) for o in outputs]

# Create a clone with the recovered state
clone = MT19937()
clone.set_state(state)

# Verify the clone produces identical future outputs
match = True
for i in range(1000):
    a = original.extract_number()
    b = clone.extract_number()
    if a != b:
        print(f"Mismatch at output {i}: {a} != {b}")
        match = False
        break

if match:
    print("Successfully cloned MT19937! 1000 future outputs match.")
