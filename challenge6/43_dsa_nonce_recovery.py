"""Challenge 43: DSA key recovery from nonce."""
import hashlib
from crypto_utils import DSA_P, DSA_Q, DSA_G, invmod, sha1_int

p, q, g = DSA_P, DSA_Q, DSA_G

y = int(
    "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4"
    "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004"
    "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed"
    "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b"
    "bb283e6633451e535c45513b2d33c99ea17", 16
)

msg = b"For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"
h = sha1_int(msg)
assert h == 0xd2d0714f014a9784047eaeccf956520045c45265

r = 548099063082341131477253921760299949438196259240
s = 857042759984254168557880549501802188789837994940

# Brute force k (it's in range 0..2^16)
for k in range(1, 2**16 + 1):
    # x = (s*k - h) * r^-1 mod q
    x_candidate = ((s * k - h) * invmod(r, q)) % q
    # Verify: does this x produce the correct y?
    if pow(g, x_candidate, p) == y:
        x = x_candidate
        fingerprint = hashlib.sha1(format(x, 'x').encode()).hexdigest()
        print(f"Found k={k}")
        print(f"Private key x={hex(x)}")
        print(f"SHA-1 fingerprint: {fingerprint}")
        assert fingerprint == "0954edd5e0afe5542a4adf012611a91912a3ec16"
        print("DSA nonce recovery succeeded!")
        break
else:
    print("Failed to find k")
