"""Challenge 37: Break SRP with a zero key."""
import hashlib
import hmac
from crypto_utils import NIST_PRIME, int_to_bytes

N = NIST_PRIME
g = 2
k = 3


class SRPServer:
    def __init__(self, email, password):
        self.email = email
        self.salt = b"fixed_salt_16byt"
        xH = hashlib.sha256(self.salt + password.encode()).digest()
        x = int.from_bytes(xH, "big")
        self.v = pow(g, x, N)
        import random
        self.b = random.randint(1, N - 1)
        self.B = (k * self.v + pow(g, self.b, N)) % N

    def handshake(self, client_email, A):
        self.A = A
        return self.salt, self.B

    def verify(self, client_hmac):
        uH = hashlib.sha256(int_to_bytes(self.A) + int_to_bytes(self.B)).digest()
        u = int.from_bytes(uH, "big")
        S = pow(self.A * pow(self.v, u, N), self.b, N)
        K = hashlib.sha256(int_to_bytes(S)).digest()
        expected = hmac.new(K, self.salt, hashlib.sha256).digest()
        return client_hmac == expected


server = SRPServer("user@example.com", "super_secret_password")


def attack_with_A(A_val, label):
    """Attack: send A=0, N, or 2N. Server computes S = (A * v^u)^b % N.
    When A is a multiple of N, A % N = 0, so S = 0."""
    salt, B = server.handshake("user@example.com", A_val)

    # We know S = 0 because A mod N = 0
    S = 0
    K = hashlib.sha256(int_to_bytes(S)).digest()
    forged_hmac = hmac.new(K, salt, hashlib.sha256).digest()

    if server.verify(forged_hmac):
        print(f"  A={label}: authentication bypassed!")
        return True
    else:
        print(f"  A={label}: attack failed")
        return False


print("SRP zero-key attack:")
assert attack_with_A(0, "0")
assert attack_with_A(N, "N")
assert attack_with_A(N * 2, "2N")
print("All SRP zero-key attacks succeeded!")
