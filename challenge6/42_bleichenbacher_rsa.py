"""Challenge 42: Bleichenbacher's e=3 RSA signature attack."""
import hashlib
from crypto_utils import rsa_keygen, rsa_encrypt, rsa_decrypt, int_to_bytes, bytes_to_int, integer_cube_root

pub, priv = rsa_keygen(1024)
e, n = pub


def pkcs15_sign(message, priv):
    """Create a real PKCS#1.5 signature."""
    h = hashlib.sha1(message).digest()
    # ASN.1 SHA-1 prefix
    asn1 = b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"
    key_len = (priv[1].bit_length() + 7) // 8
    padding = b"\x00\x01" + b"\xff" * (key_len - len(asn1) - len(h) - 3) + b"\x00"
    block = padding + asn1 + h
    m = bytes_to_int(block)
    return pow(m, priv[0], priv[1])


def bad_pkcs15_verify(message, sig, pub):
    """Vulnerable verifier: doesn't check that padding fills the whole block."""
    e, n = pub
    m = pow(sig, e, n)
    block = int_to_bytes(m)
    # Pad to key length
    key_len = (n.bit_length() + 7) // 8
    block = block.rjust(key_len, b"\x00")

    if block[0:2] != b"\x00\x01":
        return False
    # Find the 0x00 separator after 0xff padding
    i = 2
    while i < len(block) and block[i] == 0xff:
        i += 1
    if i < 3 or block[i] != 0x00:
        return False
    i += 1

    # Extract hash from remaining block
    asn1 = b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"
    if block[i:i+len(asn1)] != asn1:
        return False
    i += len(asn1)
    sig_hash = block[i:i+20]
    return sig_hash == hashlib.sha1(message).digest()


# Verify real signature works
message = b"hi mom"
real_sig = pkcs15_sign(message, priv)
assert bad_pkcs15_verify(message, real_sig, pub)
print("Real signature verifies correctly.")

# Forge signature
h = hashlib.sha1(message).digest()
asn1 = b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"
key_len = (n.bit_length() + 7) // 8

# Construct: 00 01 ff 00 ASN.1 HASH garbage
block = b"\x00\x01\xff\x00" + asn1 + h
# Pad with zeros to key length
block += b"\x00" * (key_len - len(block))

# Find cube root
target = bytes_to_int(block)
forged_sig = integer_cube_root(target)
# Adjust upward to ensure the cube is >= target
while pow(forged_sig, 3) < target:
    forged_sig += 1

if bad_pkcs15_verify(message, forged_sig, pub):
    print("Forged signature accepted!")
    print("Bleichenbacher's e=3 RSA signature forgery succeeded!")
else:
    # Try slightly adjusted values
    for delta in range(-10, 11):
        if bad_pkcs15_verify(message, forged_sig + delta, pub):
            print(f"Forged signature accepted (delta={delta})!")
            print("Bleichenbacher's e=3 RSA signature forgery succeeded!")
            break
    else:
        print("Forgery failed - the vulnerable verifier may be too strict")
