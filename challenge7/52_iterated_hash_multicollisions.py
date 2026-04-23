"""Challenge 52: Iterated Hash Function Multicollisions."""
import os
from crypto_utils import md_compress, iterated_hash, BLOCK_SIZE

HASH_SIZE_F = 2  # 16-bit hash (cheap)
HASH_SIZE_G = 4  # 32-bit hash (expensive)


def find_collision(state, hash_size):
    """Find two single-block messages with the same hash output from given state."""
    seen = {}
    while True:
        block = os.urandom(BLOCK_SIZE)
        h = md_compress(block, state, hash_size)
        key = h[:hash_size]
        if key in seen and seen[key] != block:
            return seen[key], block, h
        seen[key] = block


def generate_multicollisions(n, hash_size):
    """Generate 2^n colliding messages for the cheap hash function."""
    state = b"\x00" * hash_size
    pairs = []

    for i in range(n):
        b1, b2, new_state = find_collision(state, hash_size)
        pairs.append((b1, b2))
        state = new_state

    # Generate all 2^n messages by choosing b1 or b2 at each step
    messages = [b""]
    for b1, b2 in pairs:
        new_messages = []
        for m in messages:
            new_messages.append(m + b1)
            new_messages.append(m + b2)
        messages = new_messages

    return messages


# Part 1: Generate 2^n collisions in the cheap function
n = 8  # 2^8 = 256 collisions
print(f"Generating 2^{n} = {2**n} collisions for {HASH_SIZE_F*8}-bit hash...")
colliding_messages = generate_multicollisions(n, HASH_SIZE_F)

# Verify all collide under f
hashes_f = set()
for m in colliding_messages:
    hashes_f.add(iterated_hash(m, HASH_SIZE_F))
assert len(hashes_f) == 1
print(f"All {len(colliding_messages)} messages produce the same {HASH_SIZE_F*8}-bit hash!")

# Part 2: Find a collision in the expensive hash among the collision set
print(f"\nSearching for {HASH_SIZE_G*8}-bit hash collision among {len(colliding_messages)} messages...")
hashes_g = {}
collision_found = False
for m in colliding_messages:
    h = iterated_hash(m, HASH_SIZE_G)
    if h in hashes_g:
        print(f"Found collision in the {HASH_SIZE_G*8}-bit hash!")
        print(f"  f(m1) = f(m2) and g(m1) = g(m2)")
        collision_found = True
        break
    hashes_g[h] = m

if not collision_found:
    # Need more collisions for the 32-bit hash
    print(f"No collision found in {len(colliding_messages)} messages (need ~2^{HASH_SIZE_G*4} for 50% chance)")
    print("Generating more collisions...")
    colliding_messages = generate_multicollisions(HASH_SIZE_G * 4 + 2, HASH_SIZE_F)
    hashes_g = {}
    for m in colliding_messages:
        h = iterated_hash(m, HASH_SIZE_G)
        if h in hashes_g:
            print(f"Found collision in the {HASH_SIZE_G*8}-bit hash!")
            collision_found = True
            break
        hashes_g[h] = m

print("Iterated hash multicollision attack demonstrated!")
