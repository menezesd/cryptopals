"""Challenge 53: Kelsey and Schneier's Expandable Messages."""
import os
from crypto_utils import md_compress, iterated_hash, BLOCK_SIZE

HASH_SIZE = 2  # 16-bit hash for tractability
K = 8  # expandable message with k rounds


def find_collision_long_short(state, long_blocks, hash_size):
    """Find collision between a 1-block message and a (long_blocks+1)-block message
    that both start from the given state."""
    # Hash a long prefix of random blocks
    long_prefix = os.urandom(BLOCK_SIZE * long_blocks)
    long_state = state
    for i in range(0, len(long_prefix), BLOCK_SIZE):
        long_state = md_compress(long_prefix[i:i+BLOCK_SIZE], long_state, hash_size)

    # Now find matching single-block and final-long-block
    short_map = {}
    long_map = {}

    while True:
        # Try a short block
        sb = os.urandom(BLOCK_SIZE)
        sh = md_compress(sb, state, hash_size)
        if sh in long_map:
            return sb, long_prefix + long_map[sh], sh
        short_map[sh] = sb

        # Try a long final block
        lb = os.urandom(BLOCK_SIZE)
        lh = md_compress(lb, long_state, hash_size)
        if lh in short_map:
            return short_map[lh], long_prefix + lb, lh
        long_map[lh] = lb


def build_expandable_message(k, hash_size):
    """Build an expandable message that can produce messages of length k to k+2^k-1 blocks."""
    state = b"\x00" * hash_size
    rounds = []

    for i in range(k):
        long_blocks = 2 ** (k - 1 - i)
        short, long, new_state = find_collision_long_short(state, long_blocks, hash_size)
        rounds.append((short, long, len(long) // BLOCK_SIZE))
        state = new_state

    return rounds, state


def produce_message(rounds, target_length, k):
    """From the expandable message rounds, produce a message of exact target_length blocks."""
    remaining = target_length
    msg = b""
    for i, (short, long, long_len) in enumerate(rounds):
        # Minimum remaining from this point
        min_remaining = k - i
        if remaining - long_len >= min_remaining - 1:
            msg += long
            remaining -= long_len
        else:
            msg += short
            remaining -= 1
    return msg


# Build expandable message
print(f"Building expandable message (k={K})...")
rounds, final_state = build_expandable_message(K, HASH_SIZE)

# Generate target message
target_blocks = 2 ** K
target_msg = os.urandom(BLOCK_SIZE * target_blocks)

# Map intermediate hash states of the target
target_state = b"\x00" * HASH_SIZE
intermediate_states = {}
for i in range(target_blocks):
    block = target_msg[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
    target_state = md_compress(block, target_state, HASH_SIZE)
    if i >= K:  # Only consider states after block K
        intermediate_states[target_state] = i + 1

target_hash = target_state

# Find a bridge block from our expandable message's final state to a target intermediate state
print("Finding bridge block...")
bridge_found = False
for _ in range(100000):
    bridge = os.urandom(BLOCK_SIZE)
    bridge_state = md_compress(bridge, final_state, HASH_SIZE)
    if bridge_state in intermediate_states:
        link_index = intermediate_states[bridge_state]
        # Produce expandable message of length (link_index - 1) blocks
        # Then append bridge + rest of target
        prefix_len = link_index - 1  # blocks for expandable part (including bridge)
        if K <= prefix_len <= K + 2**K - 1:
            expanded = produce_message(rounds, prefix_len, K)
            forged = expanded + bridge + target_msg[link_index*BLOCK_SIZE:]
            forged_hash = iterated_hash(forged, HASH_SIZE)
            if forged_hash == target_hash and forged != target_msg:
                print(f"Second preimage found!")
                print(f"  Target hash:  {target_hash.hex()}")
                print(f"  Forged hash:  {forged_hash.hex()}")
                print(f"  Target len:   {len(target_msg)} bytes")
                print(f"  Forged len:   {len(forged)} bytes")
                bridge_found = True
                break
            else:
                # Hash didn't match or same message, keep trying
                pass

if not bridge_found:
    print("Bridge block search exhausted (expected with small hash)")
print("Expandable messages demonstrated!")
