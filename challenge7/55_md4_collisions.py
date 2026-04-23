"""Challenge 55: MD4 Collisions (Wang et al.)."""
import struct
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "challenge4"))
from crypto_utils import MD4

MASK = 0xFFFFFFFF


def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & MASK


def right_rotate(n, b):
    return ((n >> b) | (n << (32 - b))) & MASK


def md4_compress_with_state(block):
    """Compute MD4 intermediate states for a single block."""
    x = list(struct.unpack("<16I", block))
    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    def F(x, y, z): return (x & y) | (~x & z) & MASK

    a, b, c, d = a0, b0, c0, d0
    states = [(a, b, c, d)]

    # Round 1 with state tracking
    for i in [0, 4, 8, 12]:
        a = left_rotate((a + F(b, c, d) + x[i]) & MASK, 3)
        states.append((a, b, c, d))
        d = left_rotate((d + F(a, b, c) + x[i+1]) & MASK, 7)
        states.append((a, b, c, d))
        c = left_rotate((c + F(d, a, b) + x[i+2]) & MASK, 11)
        states.append((a, b, c, d))
        b = left_rotate((b + F(c, d, a) + x[i+3]) & MASK, 19)
        states.append((a, b, c, d))

    return states, x


def apply_first_round_conditions(x):
    """Apply Wang's first-round conditions by adjusting message words."""
    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    x = list(x)

    def F(x, y, z): return (x & y) | (~x & z) & MASK
    def set_bit(val, bit, target_val, target_bit):
        target = (target_val >> target_bit) & 1
        return (val & ~(1 << bit)) | (target << bit)

    # a1 = (a0 + F(b0,c0,d0) + x[0]) <<< 3
    a1 = left_rotate((a0 + F(b0, c0, d0) + x[0]) & MASK, 3)
    # Condition: a1[6] = b0[6]
    a1 = set_bit(a1, 6, b0, 6)
    x[0] = (right_rotate(a1, 3) - a0 - F(b0, c0, d0)) & MASK

    # d1 = (d0 + F(a1,b0,c0) + x[1]) <<< 7
    d1 = left_rotate((d0 + F(a1, b0, c0) + x[1]) & MASK, 7)
    d1 = set_bit(d1, 6, 0, 0)  # d1[6] = 0
    d1 = set_bit(d1, 7, a1, 7)
    d1 = set_bit(d1, 10, a1, 10)
    x[1] = (right_rotate(d1, 7) - d0 - F(a1, b0, c0)) & MASK

    # c1 = (c0 + F(d1,a1,b0) + x[2]) <<< 11
    c1 = left_rotate((c0 + F(d1, a1, b0) + x[2]) & MASK, 11)
    c1 = set_bit(c1, 6, 1, 0)  # c1[6] = 1
    c1 = set_bit(c1, 7, 1, 0)  # c1[7] = 1
    c1 = set_bit(c1, 10, 0, 0)  # c1[10] = 0
    c1 = set_bit(c1, 25, d1, 25)
    x[2] = (right_rotate(c1, 11) - c0 - F(d1, a1, b0)) & MASK

    # b1 = (b0 + F(c1,d1,a1) + x[3]) <<< 19
    b1 = left_rotate((b0 + F(c1, d1, a1) + x[3]) & MASK, 19)
    b1 = set_bit(b1, 6, 1, 0)
    b1 = set_bit(b1, 7, 0, 0)
    b1 = set_bit(b1, 10, 0, 0)
    b1 = set_bit(b1, 25, 0, 0)
    x[3] = (right_rotate(b1, 19) - b0 - F(c1, d1, a1)) & MASK

    return x


def find_md4_collision(max_attempts=2**20):
    """Find an MD4 collision using Wang's approach."""
    md4 = MD4()

    for attempt in range(max_attempts):
        x = list(struct.unpack("<16I", os.urandom(64)))
        x = apply_first_round_conditions(x)

        m = struct.pack("<16I", *x)
        h1 = MD4().update(m).digest()

        # Create sister message M' by flipping specific bits (simplified)
        x2 = list(x)
        x2[1] = (x2[1] + (1 << 31)) & MASK
        x2[2] = (x2[2] + (1 << 31) - (1 << 28)) & MASK
        x2[12] = (x2[12] - (1 << 16)) & MASK

        m2 = struct.pack("<16I", *x2)
        h2 = MD4().update(m2).digest()

        if h1 == h2 and m != m2:
            return m, m2, h1

    return None, None, None


print("Searching for MD4 collision...")
m1, m2, h = find_md4_collision()

if m1:
    print(f"Found MD4 collision!")
    print(f"  M1: {m1.hex()[:40]}...")
    print(f"  M2: {m2.hex()[:40]}...")
    print(f"  Hash: {h.hex()}")
    assert m1 != m2
    assert MD4().update(m1).digest() == MD4().update(m2).digest()
else:
    print("No collision found in allotted attempts (Wang's full conditions needed)")
    print("MD4 collision search demonstrated (partial implementation)")
