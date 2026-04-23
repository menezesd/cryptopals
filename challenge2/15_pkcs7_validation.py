"""Challenge 15: PKCS#7 padding validation."""
from aes_utils import pkcs7_unpad


# Valid padding
result = pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04")
assert result == b"ICE ICE BABY"
print(f"Valid:   {result}")

# Invalid padding cases
for bad in [b"ICE ICE BABY\x05\x05\x05\x05", b"ICE ICE BABY\x01\x02\x03\x04"]:
    try:
        pkcs7_unpad(bad)
        print(f"ERROR: should have raised for {bad!r}")
    except ValueError as e:
        print(f"Invalid: caught '{e}' for {bad!r}")

print("All padding validation tests passed!")
