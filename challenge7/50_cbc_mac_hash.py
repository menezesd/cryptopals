"""Challenge 50: Hashing with CBC-MAC."""
from crypto_utils import xor_bytes, aes_ecb_encrypt_raw, pkcs7_pad, BLOCK_SIZE

KEY = b"YELLOW SUBMARINE"
IV = b"\x00" * BLOCK_SIZE


def raw_cbc_mac(data, key, iv):
    """CBC-MAC on already-padded data."""
    state = iv
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i+BLOCK_SIZE]
        state = aes_ecb_encrypt_raw(xor_bytes(block, state), key)
    return state


original = b"alert('MZA who was that?');\n"
original_padded = pkcs7_pad(original)
original_mac = raw_cbc_mac(original_padded, KEY, IV)
print(f"Original MAC: {original_mac.hex()}")
assert original_mac.hex() == "296b8d7cb78a243dda4d0a61d33bbdd1"

# Forge: start with our desired JS, then add a glue block + rest of original
target_js = b"alert('Ayo, the Wu is back!');//"
# Pad to block boundary
while len(target_js) % BLOCK_SIZE:
    target_js += b" "

# Compute CBC state after our target JS blocks
target_state = IV
for i in range(0, len(target_js), BLOCK_SIZE):
    block = target_js[i:i+BLOCK_SIZE]
    target_state = aes_ecb_encrypt_raw(xor_bytes(block, target_state), KEY)

# Glue block: we want E(glue XOR target_state) = E(original_padded[0:16] XOR IV)
# => glue XOR target_state = original_padded[0:16] XOR IV
glue = xor_bytes(xor_bytes(original_padded[:BLOCK_SIZE], IV), target_state)

# Forged raw message = target_js + glue + original_padded[16:]
forged_raw = target_js + glue + original_padded[BLOCK_SIZE:]
forged_mac = raw_cbc_mac(forged_raw, KEY, IV)

assert forged_mac == original_mac
print(f"Forged MAC:   {forged_mac.hex()}")
print(f"Forged JS starts: {forged_raw[:40]}")
print("CBC-MAC hash collision succeeded!")
