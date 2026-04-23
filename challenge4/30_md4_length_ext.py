"""Challenge 30: Break an MD4 keyed MAC using length extension."""
import struct
import os
from crypto_utils import MD4, md4_mac, md_padding_md4

KEY = os.urandom(16)

original_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
original_mac = md4_mac(KEY, original_msg)
append_data = b";admin=true"


def verify_mac(key, message, mac):
    return md4_mac(key, message) == mac


for key_len in range(1, 64):
    glue_padding = md_padding_md4(key_len + len(original_msg))
    forged_msg = original_msg + glue_padding + append_data

    # Extract state from original MAC (MD4 uses little-endian)
    state = struct.unpack("<4I", original_mac)

    md = MD4(state=state, msg_len=key_len + len(original_msg) + len(glue_padding))
    md.update(append_data)
    forged_mac = md.digest()

    if verify_mac(KEY, forged_msg, forged_mac):
        print(f"Found key length: {key_len}")
        print(f"Forged MAC: {forged_mac.hex()}")
        print("MD4 length extension attack succeeded!")
        break
else:
    print("Attack failed!")
