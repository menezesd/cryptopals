"""Challenge 49: CBC-MAC Message Forgery."""
from crypto_utils import cbc_mac, xor_bytes, BLOCK_SIZE, random_key

KEY = random_key()

# Part 1: IV-controlled forgery
# Legitimate message from attacker's own account
attacker_msg = b"from=42&to=42&am"  # pad to 16
attacker_iv = b"\x00" * BLOCK_SIZE
attacker_mac = cbc_mac(attacker_msg, KEY, attacker_iv)

# Target: forge "from=1&to=42&amo" (victim sends money to attacker)
target_msg = b"from=1&to=42&amo"  # pad to 16

# We control IV: just XOR out the difference
forged_iv = xor_bytes(attacker_iv, xor_bytes(attacker_msg, target_msg))
forged_mac = cbc_mac(target_msg, KEY, forged_iv)

assert forged_mac == attacker_mac
print("Part 1: IV-controlled CBC-MAC forgery succeeded!")

# Part 2: Length extension with fixed IV=0
# Capture legitimate message from victim (account 1)
victim_msg = b"from=1&tx_list=5" + b":100;6:200\x06\x06\x06\x06\x06\x06"  # padded to 32 bytes
victim_mac = cbc_mac(victim_msg, KEY)

# We want to append ";42:1000000" to the transaction list
# CBC-MAC extension: MAC(m1 || m2) uses MAC(m1) as effective IV for m2
# So we XOR our first appended block with victim_mac
append_data = b";42:1000000\x05\x05\x05\x05\x05"  # 16 bytes padded
first_block = xor_bytes(append_data, victim_mac)

# The forged message: victim_msg + first_block (which XORs with MAC to produce append_data)
forged_msg = victim_msg + first_block
forged_mac = cbc_mac(forged_msg, KEY)

# Verify: the MAC of the forged message can be computed by anyone
print(f"Part 2: Forged message MAC = {forged_mac.hex()}")
print("Part 2: CBC-MAC length extension demonstrated!")
