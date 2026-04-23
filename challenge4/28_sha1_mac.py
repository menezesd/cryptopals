"""Challenge 28: Implement a SHA-1 keyed MAC."""
import hashlib
from crypto_utils import sha1, sha1_mac, random_key

key = random_key()

# Verify our SHA-1 matches hashlib
test_msg = b"The quick brown fox jumps over the lazy dog"
our_hash = sha1(test_msg).hex()
ref_hash = hashlib.sha1(test_msg).hexdigest()
assert our_hash == ref_hash, f"SHA-1 mismatch: {our_hash} != {ref_hash}"
print(f"SHA-1 verified: {our_hash}")

# Test MAC
mac = sha1_mac(key, b"Hello, World!")
assert mac == sha1_mac(key, b"Hello, World!"), "MAC not deterministic"

# Tamper detection
assert mac != sha1_mac(key, b"Hello, World?"), "Tamper not detected"
assert mac != sha1_mac(random_key(), b"Hello, World!"), "Wrong key not detected"

print(f"MAC: {mac.hex()}")
print("SHA-1 keyed MAC works correctly!")
