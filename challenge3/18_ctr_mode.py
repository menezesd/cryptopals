"""Challenge 18: Implement CTR, the stream cipher mode."""
import base64
from crypto_utils import aes_ctr

ciphertext = base64.b64decode(
    "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
)
key = b"YELLOW SUBMARINE"

plaintext = aes_ctr(ciphertext, key, nonce=0)
print(plaintext.decode())
