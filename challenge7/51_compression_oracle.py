"""Challenge 51: Compression Ratio Side-Channel Attacks."""
import os
import sys
import zlib
import struct
from crypto_utils import random_key, BLOCK_SIZE

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "challenge2"))
from aes_utils import aes_ecb_encrypt_raw


def aes_ctr_encrypt(data, key, nonce=0):
    result = b""
    counter = 0
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        counter_block = struct.pack("<QQ", nonce, counter)
        keystream = aes_ecb_encrypt_raw(counter_block, key)
        result += bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
        counter += 1
    return result


SESSION_ID = "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="


def format_request(payload):
    return (
        f"POST / HTTP/1.1\r\n"
        f"Host: hapless.com\r\n"
        f"Cookie: sessionid={SESSION_ID}\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"\r\n"
        f"{payload}"
    ).encode()


def oracle(payload):
    """Compress then encrypt with stream cipher. Stream cipher doesn't change length."""
    request = format_request(payload)
    return len(zlib.compress(request))


def recover_session_id():
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    known = "Cookie: sessionid="

    for _ in range(len(SESSION_ID)):
        scores = {}
        for c in charset:
            candidate = known + c
            scores[c] = oracle(candidate)

        best = min(scores, key=scores.get)
        known += best

        if best == "=" and len(known) > len("Cookie: sessionid=") + 5:
            break

    return known[len("Cookie: sessionid="):]


recovered = recover_session_id()
print(f"Expected:  {SESSION_ID}")
print(f"Recovered: {recovered}")
if recovered == SESSION_ID:
    print("Compression oracle attack succeeded!")
else:
    match = sum(a == b for a, b in zip(recovered, SESSION_ID))
    print(f"Matching chars: {match}/{min(len(recovered), len(SESSION_ID))}")
