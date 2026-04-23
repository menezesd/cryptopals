"""Challenge 32: Break HMAC-SHA1 with a slightly less artificial timing leak."""
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from crypto_utils import hmac_sha1

KEY = b"SUPERSECRETKEY!!"
DELAY = 0.005  # 5ms per byte


def insecure_compare(a, b, delay=DELAY):
    for x, y in zip(a, b):
        if x != y:
            return False
        time.sleep(delay)
    return len(a) == len(b)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        params = parse_qs(urlparse(self.path).query)
        filename = params.get("file", [""])[0].encode()
        sig = bytes.fromhex(params.get("signature", [""])[0])
        expected = hmac_sha1(KEY, filename)
        if insecure_compare(sig, expected):
            self.send_response(200)
        else:
            self.send_response(500)
        self.end_headers()
        self.wfile.write(b"")

    def log_message(self, *args):
        pass


def start_server(port=9001):
    server = HTTPServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def timing_attack_statistical(filename, port=9001, rounds=10):
    """Use multiple rounds to average out noise with smaller timing leak."""
    import urllib.request
    sig = bytearray(20)

    for i in range(20):
        timings = [0.0] * 256
        for r in range(rounds):
            for guess in range(256):
                sig[i] = guess
                url = f"http://127.0.0.1:{port}/test?file={filename}&signature={sig.hex()}"
                start = time.time()
                try:
                    urllib.request.urlopen(url)
                    return bytes(sig)
                except Exception:
                    pass
                timings[guess] += time.time() - start

        best_byte = max(range(256), key=lambda b: timings[b])
        sig[i] = best_byte
        avg = timings[best_byte] / rounds
        print(f"Byte {i}: 0x{best_byte:02x} (avg {avg:.4f}s over {rounds} rounds)")

    return bytes(sig)


if __name__ == "__main__":
    server = start_server()
    filename = "testfile"
    expected = hmac_sha1(KEY, filename.encode())
    print(f"Expected HMAC: {expected.hex()}")
    print("Starting statistical timing attack (5ms delay, multiple rounds)...")

    recovered = timing_attack_statistical(filename, rounds=10)
    print(f"Recovered:     {recovered.hex()}")

    if recovered == expected:
        print("Statistical timing attack succeeded!")
    else:
        print("Partial recovery (noisy timing)")
    server.shutdown()
