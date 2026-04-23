"""Challenge 14: Byte-at-a-time ECB decryption (Harder)."""
import base64
import os
from aes_utils import aes_ecb_encrypt, random_key, BLOCK_SIZE

UNKNOWN = base64.b64decode(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK"
)
KEY = random_key()
PREFIX = os.urandom(17)  # random-length random prefix


def oracle(plaintext):
    return aes_ecb_encrypt(PREFIX + plaintext + UNKNOWN, KEY)


def find_prefix_length():
    """Determine prefix length by finding where two identical blocks appear."""
    for pad_len in range(BLOCK_SIZE * 2 + BLOCK_SIZE):
        ct = oracle(b"A" * (BLOCK_SIZE * 2 + pad_len))
        blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i + 1]:
                # The prefix fills up to block i, and our padding fills the rest
                return i * BLOCK_SIZE - (pad_len % BLOCK_SIZE) if pad_len % BLOCK_SIZE else i * BLOCK_SIZE
    raise RuntimeError("Could not determine prefix length")


prefix_len = find_prefix_length()
# Padding needed to align prefix to block boundary
prefix_pad = (BLOCK_SIZE - prefix_len % BLOCK_SIZE) % BLOCK_SIZE
prefix_blocks = (prefix_len + prefix_pad) // BLOCK_SIZE

# Now decrypt byte-at-a-time, same as challenge 12 but offset by prefix
unknown_len = len(oracle(b"A" * prefix_pad)) - (prefix_len + prefix_pad)
recovered = b""

for i in range(unknown_len):
    block_idx = prefix_blocks + i // BLOCK_SIZE
    pad = b"A" * (prefix_pad + BLOCK_SIZE - 1 - (i % BLOCK_SIZE))
    target = oracle(pad)[block_idx * BLOCK_SIZE:(block_idx + 1) * BLOCK_SIZE]

    found = False
    for b in range(256):
        test = pad + recovered + bytes([b])
        cipher = oracle(test)[block_idx * BLOCK_SIZE:(block_idx + 1) * BLOCK_SIZE]
        if cipher == target:
            recovered += bytes([b])
            found = True
            break

    if not found:
        break

# Strip padding
pad_byte = recovered[-1]
if pad_byte < BLOCK_SIZE:
    recovered = recovered[:-pad_byte]

print(recovered.decode("utf-8"))
