"""Challenge 40: Implement an E=3 RSA Broadcast attack."""
from crypto_utils import invmod, int_to_bytes, bytes_to_int, integer_cube_root
from importlib import import_module
import sys
sys.path.insert(0, ".")
rsa = import_module("39_rsa")

message = b"Attack at dawn!"
m = bytes_to_int(message)

# Encrypt same message under 3 different public keys
keys = [rsa.rsa_keygen(1024, e=3) for _ in range(3)]
c = [rsa.rsa_encrypt(m, pub) for pub, _ in keys]
n = [pub[1] for pub, _ in keys]

# Chinese Remainder Theorem
ms0 = n[1] * n[2]
ms1 = n[0] * n[2]
ms2 = n[0] * n[1]
N012 = n[0] * n[1] * n[2]

result = (
    c[0] * ms0 * invmod(ms0, n[0]) +
    c[1] * ms1 * invmod(ms1, n[1]) +
    c[2] * ms2 * invmod(ms2, n[2])
) % N012

# Cube root (no modular reduction needed since m^3 < N012)
recovered_m = integer_cube_root(result)
recovered = int_to_bytes(recovered_m)

assert recovered == message
print(f"Recovered: '{recovered.decode()}'")
print("E=3 RSA broadcast attack succeeded!")
