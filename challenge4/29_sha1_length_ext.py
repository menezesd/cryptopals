"""Challenge 29: Break a SHA-1 keyed MAC using length extension."""
import struct
import os
from crypto_utils import SHA1, sha1_mac, md_padding_sha1

KEY = os.urandom(16)  # Unknown to attacker

original_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
original_mac = sha1_mac(KEY, original_msg)
append_data = b";admin=true"


def verify_mac(key, message, mac):
    return sha1_mac(key, message) == mac


# Attack: try different key lengths
for key_len in range(1, 64):
    # Compute glue padding as if we know the key length
    glue_padding = md_padding_sha1(key_len + len(original_msg))

    # The forged message (without key prefix)
    forged_msg = original_msg + glue_padding + append_data

    # Total length the SHA-1 state has processed
    total_len = key_len + len(original_msg) + len(glue_padding) + len(append_data)

    # Extract state from original MAC
    state = struct.unpack(">5I", original_mac)

    # Continue hashing from the existing state
    sha = SHA1(state=state, msg_len=key_len + len(original_msg) + len(glue_padding))
    sha.update(append_data)
    forged_mac = sha.digest()

    if verify_mac(KEY, forged_msg, forged_mac):
        print(f"Found key length: {key_len}")
        print(f"Forged MAC: {forged_mac.hex()}")
        print(f"Forged message contains: {b'admin=true' in forged_msg}")
        print("SHA-1 length extension attack succeeded!")
        break
else:
    print("Attack failed!")
