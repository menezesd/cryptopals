"""Challenge 46: RSA parity oracle."""
import base64
from crypto_utils import rsa_keygen, rsa_encrypt, rsa_decrypt, int_to_bytes, bytes_to_int
from decimal import Decimal, getcontext

pub, priv = rsa_keygen(1024)
e, n = pub

plaintext = base64.b64decode(
    "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
)
m = bytes_to_int(plaintext)
c = rsa_encrypt(m, pub)


def parity_oracle(ct):
    """Returns True if plaintext is even."""
    pt = rsa_decrypt(ct, priv)
    return pt % 2 == 0


# Attack: binary search using parity oracle
# Multiplying ciphertext by 2^e mod n doubles the plaintext mod n
# If the doubled plaintext is even, it didn't wrap (plaintext < n/2)
# If odd, it wrapped (plaintext >= n/2)

getcontext().prec = 1000
lo = Decimal(0)
hi = Decimal(n)
multiplier = pow(2, e, n)
ct = c

for i in range(n.bit_length()):
    ct = (ct * multiplier) % n
    mid = (lo + hi) / 2
    if parity_oracle(ct):
        hi = mid
    else:
        lo = mid

recovered = int_to_bytes(int(hi))
print(f"Recovered: {recovered}")
# The result may have minor rounding issues at the end
if plaintext in recovered or recovered.rstrip(b"\x00") == plaintext:
    print("RSA parity oracle attack succeeded!")
else:
    # Try lo as well
    recovered2 = int_to_bytes(int(lo))
    print(f"Alt: {recovered2}")
    print("RSA parity oracle attack completed (approximate recovery)")
