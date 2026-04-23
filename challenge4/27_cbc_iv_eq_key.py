"""Challenge 27: Recover the key from CBC with IV=Key."""
from crypto_utils import aes_cbc_encrypt, aes_cbc_decrypt, random_key, xor_bytes, BLOCK_SIZE

KEY = random_key()
IV = KEY  # Vulnerability: IV = Key


def encrypt(plaintext):
    return aes_cbc_encrypt(plaintext, KEY, IV)


def decrypt_and_check(ciphertext):
    plaintext = aes_cbc_decrypt(ciphertext, KEY, IV)
    if any(b > 127 for b in plaintext):
        raise ValueError(f"Invalid ASCII: {plaintext}")
    return plaintext


# Encrypt a 3-block message
plaintext = b"A" * BLOCK_SIZE * 3
ct = encrypt(plaintext)

# Modify: C1, 0, C1
c1 = ct[:BLOCK_SIZE]
crafted = c1 + b"\x00" * BLOCK_SIZE + c1

try:
    decrypt_and_check(crafted)
except ValueError as e:
    # Extract plaintext from error
    bad_plain = eval(str(e).split(": ", 1)[1])
    p1 = bad_plain[:BLOCK_SIZE]
    p3 = bad_plain[2*BLOCK_SIZE:3*BLOCK_SIZE]
    recovered_key = xor_bytes(p1, p3)
    assert recovered_key == KEY
    print(f"Recovered key: {recovered_key.hex()}")
    print("Successfully recovered key from CBC with IV=Key!")
