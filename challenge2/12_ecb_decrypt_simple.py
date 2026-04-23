"""Challenge 12: Byte-at-a-time ECB decryption (Simple)."""
import base64
from aes_utils import aes_ecb_encrypt, random_key, detect_ecb, BLOCK_SIZE

UNKNOWN = base64.b64decode(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK"
)
KEY = random_key()


def oracle(plaintext):
    return aes_ecb_encrypt(plaintext + UNKNOWN, KEY)


# Step 1: Discover block size
def find_block_size():
    initial = len(oracle(b""))
    for i in range(1, 64):
        size = len(oracle(b"A" * i))
        if size != initial:
            return size - initial
    raise RuntimeError("Could not determine block size")


block_size = find_block_size()
assert block_size == BLOCK_SIZE

# Step 2: Confirm ECB
assert detect_ecb(oracle(b"A" * 48))

# Step 3: Decrypt byte-at-a-time
unknown_len = len(oracle(b""))
recovered = b""

for i in range(unknown_len):
    block_idx = i // block_size
    # Short input so the next unknown byte is at the end of a block
    pad = b"A" * (block_size - 1 - (i % block_size))
    target = oracle(pad)[block_idx * block_size:(block_idx + 1) * block_size]

    for b in range(256):
        test = pad + recovered + bytes([b])
        cipher = oracle(test)[block_idx * block_size:(block_idx + 1) * block_size]
        if cipher == target:
            recovered += bytes([b])
            break

# Strip PKCS7 padding from result
pad_byte = recovered[-1]
if pad_byte < block_size:
    recovered = recovered[:-pad_byte]

print(recovered.decode("utf-8"))
