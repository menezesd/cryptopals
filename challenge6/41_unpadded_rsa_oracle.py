"""Challenge 41: Implement unpadded message recovery oracle."""
from crypto_utils import rsa_keygen, rsa_encrypt, rsa_decrypt, invmod, int_to_bytes, bytes_to_int
import random

pub, priv = rsa_keygen(1024)
e, n = pub

message = b"secret message!"
m = bytes_to_int(message)
c = rsa_encrypt(m, pub)

# Server decrypts once, then refuses to decrypt the same ciphertext again
seen = set()


def decrypt_oracle(ct):
    if ct in seen:
        raise ValueError("Already decrypted this ciphertext")
    seen.add(ct)
    return rsa_decrypt(ct, priv)


# First decryption works
p1 = decrypt_oracle(c)
assert int_to_bytes(p1) == message

# Second attempt blocked
try:
    decrypt_oracle(c)
    assert False, "Should have been blocked"
except ValueError:
    pass

# Attack: create modified ciphertext
S = random.randint(2, n - 1)
c_prime = (pow(S, e, n) * c) % n
p_prime = decrypt_oracle(c_prime)

# Recover original: p = p' * S^(-1) mod n
recovered_m = (p_prime * invmod(S, n)) % n
recovered = int_to_bytes(recovered_m)

assert recovered == message
print(f"Recovered: '{recovered.decode()}'")
print("Unpadded RSA message recovery succeeded!")
