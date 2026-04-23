"""Challenge 38: Offline dictionary attack on simplified SRP."""
import os
import random
import hashlib
import hmac
from crypto_utils import NIST_PRIME, int_to_bytes

N = NIST_PRIME
g = 2

DICTIONARY = ["password", "123456", "letmein", "qwerty", "correct_horse"]


class SimplifiedSRPClient:
    def __init__(self, email, password):
        self.email = email
        self.password = password
        self.a = random.randint(1, N - 1)
        self.A = pow(g, self.a, N)

    def compute_hmac(self, salt, B, u):
        xH = hashlib.sha256(salt + self.password.encode()).digest()
        x = int.from_bytes(xH, "big")
        S = pow(B, self.a + u * x, N)
        K = hashlib.sha256(int_to_bytes(S)).digest()
        return hmac.new(K, salt, hashlib.sha256).digest()


# MITM server: we control b, B, u, salt
class MITMServer:
    def __init__(self):
        self.salt = b"attacker_salt!!!"
        self.b = random.randint(1, N - 1)
        self.B = pow(g, self.b, N)  # No password dependency in simplified SRP
        self.u = random.getrandbits(128)

    def handshake(self, email, A):
        self.email = email
        self.A = A
        return self.salt, self.B, self.u

    def crack(self, client_hmac):
        """Offline dictionary attack."""
        for guess in DICTIONARY:
            xH = hashlib.sha256(self.salt + guess.encode()).digest()
            x = int.from_bytes(xH, "big")
            v = pow(g, x, N)
            S = pow(self.A * pow(v, self.u, N), self.b, N)
            K = hashlib.sha256(int_to_bytes(S)).digest()
            expected = hmac.new(K, self.salt, hashlib.sha256).digest()
            if expected == client_hmac:
                return guess
        return None


# Simulate: client uses "letmein" as password
client = SimplifiedSRPClient("user@example.com", "letmein")
mitm = MITMServer()

salt, B, u = mitm.handshake(client.email, client.A)
client_hmac = client.compute_hmac(salt, B, u)

cracked = mitm.crack(client_hmac)
print(f"Cracked password: '{cracked}'")
assert cracked == "letmein"
print("Simplified SRP offline dictionary attack succeeded!")
