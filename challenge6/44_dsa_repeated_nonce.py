"""Challenge 44: DSA nonce recovery from repeated nonces."""
import hashlib
from crypto_utils import DSA_P, DSA_Q, DSA_G, invmod

q = DSA_Q

# Parse signed messages from file
messages = []
with open("44.txt") as f:
    lines = f.readlines()

i = 0
while i + 3 < len(lines):
    msg = lines[i].split(": ", 1)[1].strip()
    s = int(lines[i+1].split(": ")[1].strip())
    r = int(lines[i+2].split(": ")[1].strip())
    m = int(lines[i+3].split(": ")[1].strip(), 16)
    messages.append({"msg": msg, "s": s, "r": r, "m": m})
    i += 4

# Find two messages with the same r (same nonce k)
from collections import defaultdict
by_r = defaultdict(list)
for msg in messages:
    by_r[msg["r"]].append(msg)

for r_val, group in by_r.items():
    if len(group) < 2:
        continue
    m1, m2 = group[0], group[1]

    # k = (m1_hash - m2_hash) / (s1 - s2) mod q
    ds = (m1["s"] - m2["s"]) % q
    dm = (m1["m"] - m2["m"]) % q
    k = (dm * invmod(ds, q)) % q

    # x = (s*k - h) / r mod q
    x = ((m1["s"] * k - m1["m"]) * invmod(r_val, q)) % q

    fingerprint = hashlib.sha1(format(x, 'x').encode()).hexdigest()
    if fingerprint == "ca8f6f7c66fa362d40760d135b763eb8527d3d52":
        print(f"Found repeated nonce with r={r_val}")
        print(f"Private key: {format(x, 'x')}")
        print(f"SHA-1 fingerprint: {fingerprint}")
        print("DSA repeated nonce attack succeeded!")
        break
else:
    print("Attack failed")
