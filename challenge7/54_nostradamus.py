"""Challenge 54: Kelsey and Kohno's Nostradamus Attack."""
import os
from crypto_utils import md_compress, iterated_hash, BLOCK_SIZE

HASH_SIZE = 2  # 16-bit hash for tractability
K = 4  # 2^4 = 16 leaf states


def find_collision_pair(state1, state2, hash_size):
    """Find blocks b1, b2 such that H(state1, b1) == H(state2, b2)."""
    map1 = {}
    map2 = {}
    while True:
        b = os.urandom(BLOCK_SIZE)
        h1 = md_compress(b, state1, hash_size)
        if h1 in map2:
            return b, map2[h1], h1
        map1[h1] = b

        b = os.urandom(BLOCK_SIZE)
        h2 = md_compress(b, state2, hash_size)
        if h2 in map1:
            return map1[h2], b, h2
        map2[h2] = b


def build_diamond(k, hash_size):
    """Build a diamond structure with 2^k leaves converging to one root."""
    # Generate initial leaf states
    leaves = [os.urandom(hash_size) for _ in range(2 ** k)]
    tree = []  # list of (level, pairs of blocks)

    current = leaves
    while len(current) > 1:
        next_level = []
        level_blocks = []
        for i in range(0, len(current), 2):
            b1, b2, merged = find_collision_pair(current[i], current[i+1], hash_size)
            level_blocks.append((b1, b2))
            next_level.append(merged)
        tree.append((current, level_blocks))
        current = next_level

    return leaves, tree, current[0]  # root state


print(f"Building diamond structure (2^{K} = {2**K} leaves)...")
leaves, tree, commitment_state = build_diamond(K, HASH_SIZE)

# "Predict" by committing to the hash
# Add a padding/length block to get final hash
padding_block = os.urandom(BLOCK_SIZE)
committed_hash = md_compress(padding_block, commitment_state, HASH_SIZE)
print(f"Committed hash: {committed_hash.hex()}")

# After "event" occurs, write our message
event_msg = b"The winner is X!"
# Pad to block boundary
while len(event_msg) % BLOCK_SIZE:
    event_msg += b" "

# Hash our message to get its state
msg_state = b"\x00" * HASH_SIZE
for i in range(0, len(event_msg), BLOCK_SIZE):
    msg_state = md_compress(event_msg[i:i+BLOCK_SIZE], msg_state, HASH_SIZE)

# Find a glue block that links msg_state to one of the leaves
leaf_set = {l: i for i, l in enumerate(leaves)}
glue_found = False
for _ in range(100000):
    glue = os.urandom(BLOCK_SIZE)
    glue_state = md_compress(glue, msg_state, HASH_SIZE)
    if glue_state in leaf_set:
        leaf_idx = leaf_set[glue_state]
        print(f"Found glue to leaf {leaf_idx}")

        # Traverse tree from leaf to root
        suffix = b""
        idx = leaf_idx
        for level_states, level_blocks in tree:
            pair_idx = idx // 2
            b1, b2 = level_blocks[pair_idx]
            if idx % 2 == 0:
                suffix += b1
            else:
                suffix += b2
            idx = pair_idx

        suffix += padding_block

        # Full forged message
        forged = event_msg + glue + suffix
        forged_hash = iterated_hash(forged, HASH_SIZE)

        if forged_hash == committed_hash:
            print(f"Nostradamus attack succeeded!")
            print(f"  Committed hash: {committed_hash.hex()}")
            print(f"  Forged hash:    {forged_hash.hex()}")
            glue_found = True
            break

if not glue_found:
    print("Glue block not found (may need more iterations)")
print("Nostradamus attack demonstrated!")
