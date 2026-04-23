"""Challenge 13: ECB cut-and-paste."""
from aes_utils import aes_ecb_encrypt, aes_ecb_decrypt, pkcs7_unpad, pkcs7_pad, random_key, BLOCK_SIZE

KEY = random_key()


def parse_kv(s):
    return dict(pair.split("=", 1) for pair in s.split("&"))


def profile_for(email):
    email = email.replace("&", "").replace("=", "")
    return f"email={email}&uid=10&role=user"


def encrypt_profile(email):
    return aes_ecb_encrypt(profile_for(email).encode(), KEY)


def decrypt_profile(ciphertext):
    plaintext = pkcs7_unpad(aes_ecb_decrypt(ciphertext, KEY))
    return parse_kv(plaintext.decode())


# Attack: craft an encrypted profile with role=admin
#
# Block layout for "email=XXX&uid=10&role=user":
# We need "admin" + padding to land exactly in its own block.
#
# Block 0: "email=AAAAAAAAAA"  (10 A's to fill 16 bytes)
# Block 1: "admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"  (admin + pkcs7 padding to 16)
# Block 2+: "AAA&uid=10&role=" ...
#
# Then get a normal profile where "role=" ends exactly at a block boundary:
# "email=XXXXXXXXXXXXX&uid=10&role=" = 32 bytes => 2 blocks
# email needs to be 13 chars: "email=" (6) + 13 + "&uid=10&role=" (13) = 32

# Get the "admin" block
admin_padded = pkcs7_pad(b"admin", BLOCK_SIZE)
evil_email = b"A" * 10 + admin_padded
admin_block = encrypt_profile(evil_email.decode())[BLOCK_SIZE:2*BLOCK_SIZE]

# Get blocks where "role=" ends at block boundary
normal = encrypt_profile("X" * 13)  # "email=XXXXXXXXXXXXX&uid=10&role=" + "user..."
forged = normal[:2*BLOCK_SIZE] + admin_block

profile = decrypt_profile(forged)
print(profile)
assert profile["role"] == "admin", "Attack failed!"
print("Successfully forged admin profile!")
