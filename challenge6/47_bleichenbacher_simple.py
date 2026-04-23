"""Challenge 47: Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)."""
from crypto_utils import rsa_keygen, rsa_encrypt, rsa_decrypt, invmod, int_to_bytes, bytes_to_int
import os

# Use small key for tractability (256-bit)
pub, priv = rsa_keygen(256)
e, n = pub
k = (n.bit_length() + 7) // 8  # key length in bytes
B = 1 << (8 * (k - 2))


def pkcs15_pad(msg, k):
    pad_len = k - 3 - len(msg)
    assert pad_len >= 8
    padding = b""
    while len(padding) < pad_len:
        b = os.urandom(1)
        if b != b"\x00":
            padding += b
    return b"\x00\x02" + padding + b"\x00" + msg


def padding_oracle(ct):
    pt = rsa_decrypt(ct, priv)
    pt_bytes = pt.to_bytes(k, "big") if pt.bit_length() <= k * 8 else int_to_bytes(pt).rjust(k, b"\x00")
    return pt_bytes[0:2] == b"\x00\x02"


# Encrypt
message = b"kick it, CC"
padded = pkcs15_pad(message, k)
m = bytes_to_int(padded)
c0 = rsa_encrypt(m, pub)
assert padding_oracle(c0)


def ceil_div(a, b):
    return (a + b - 1) // b


def bleichenbacher_attack(c0, e, n, k, B):
    """Bleichenbacher's attack (simplified, single interval)."""
    # Step 1: s0 = 1 (c0 is already conformant)
    M = [(2 * B, 3 * B - 1)]
    s = ceil_div(n, 3 * B)

    iteration = 0
    while True:
        iteration += 1

        if len(M) > 1 or iteration == 1:
            # Step 2a/2b: search for smallest s
            while True:
                ct = (c0 * pow(s, e, n)) % n
                if padding_oracle(ct):
                    break
                s += 1
        else:
            # Step 2c: one interval remaining
            a, b = M[0]
            r = ceil_div(2 * (b * s - 2 * B), n)
            found = False
            while not found:
                s_lo = ceil_div(2 * B + r * n, b)
                s_hi = ceil_div(3 * B + r * n, a)
                for s_try in range(s_lo, s_hi):
                    ct = (c0 * pow(s_try, e, n)) % n
                    if padding_oracle(ct):
                        s = s_try
                        found = True
                        break
                r += 1

        # Step 3: Narrow intervals
        new_M = []
        for a, b in M:
            r_lo = ceil_div(a * s - 3 * B + 1, n)
            r_hi = (b * s - 2 * B) // n
            for r in range(r_lo, r_hi + 1):
                new_a = max(a, ceil_div(2 * B + r * n, s))
                new_b = min(b, (3 * B - 1 + r * n) // s)
                if new_a <= new_b:
                    new_M.append((new_a, new_b))
        M = new_M

        # Step 4: Check if done
        if len(M) == 1 and M[0][0] == M[0][1]:
            return M[0][0]

        s += 1

        if iteration % 100 == 0:
            print(f"  Iteration {iteration}, {len(M)} intervals")


print("Running Bleichenbacher's attack (256-bit key)...")
recovered_m = bleichenbacher_attack(c0, e, n, k, B)
recovered = int_to_bytes(recovered_m)

# Extract message from PKCS padding
idx = recovered.index(b"\x00", 2)
recovered_msg = recovered[idx + 1:]

print(f"Recovered: '{recovered_msg.decode()}'")
assert recovered_msg == message
print("Bleichenbacher's PKCS 1.5 padding oracle attack succeeded!")
