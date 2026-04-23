"""Challenge 36: Implement Secure Remote Password (SRP)."""
import os
import random
import hashlib
import hmac
from crypto_utils import NIST_PRIME, int_to_bytes

N = NIST_PRIME
g = 2
k = 3


class SRPServer:
    def __init__(self, email, password):
        self.email = email
        self.salt = os.urandom(16)
        xH = hashlib.sha256(self.salt + password.encode()).digest()
        x = int.from_bytes(xH, "big")
        self.v = pow(g, x, N)

    def handshake(self, client_email, A):
        assert client_email == self.email
        self.A = A
        self.b = random.randint(1, N - 1)
        self.B = (k * self.v + pow(g, self.b, N)) % N
        return self.salt, self.B

    def verify(self, client_hmac):
        uH = hashlib.sha256(int_to_bytes(self.A) + int_to_bytes(self.B)).digest()
        u = int.from_bytes(uH, "big")
        S = pow(self.A * pow(self.v, u, N), self.b, N)
        K = hashlib.sha256(int_to_bytes(S)).digest()
        expected = hmac.new(K, self.salt, hashlib.sha256).digest()
        return client_hmac == expected


class SRPClient:
    def __init__(self, email, password):
        self.email = email
        self.password = password
        self.a = random.randint(1, N - 1)
        self.A = pow(g, self.a, N)

    def process_response(self, salt, B):
        self.salt = salt
        uH = hashlib.sha256(int_to_bytes(self.A) + int_to_bytes(B)).digest()
        u = int.from_bytes(uH, "big")
        xH = hashlib.sha256(salt + self.password.encode()).digest()
        x = int.from_bytes(xH, "big")
        S = pow(B - k * pow(g, x, N), self.a + u * x, N)
        K = hashlib.sha256(int_to_bytes(S)).digest()
        return hmac.new(K, salt, hashlib.sha256).digest()


# Test SRP
server = SRPServer("user@example.com", "correct_password")
client = SRPClient("user@example.com", "correct_password")

salt, B = server.handshake(client.email, client.A)
client_hmac = client.process_response(salt, B)
assert server.verify(client_hmac)
print("SRP authentication succeeded with correct password!")

# Wrong password should fail
bad_client = SRPClient("user@example.com", "wrong_password")
salt2, B2 = server.handshake(bad_client.email, bad_client.A)
bad_hmac = bad_client.process_response(salt2, B2)
assert not server.verify(bad_hmac)
print("SRP authentication correctly rejected wrong password!")
