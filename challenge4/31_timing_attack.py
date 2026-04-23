"""Challenge 31: Implement and break HMAC-SHA1 with an artificial timing leak."""
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from crypto_utils import hmac_sha1

KEY = b"SUPERSECRETKEY!!"
DELAY = 0.050  # 50ms per byte


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
        pass  # Suppress logs


def start_server(port=9000):
    server = HTTPServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def timing_attack(filename, port=9000):
    import urllib.request
    sig = bytearray(20)

    for i in range(20):
        best_time = -1
        best_byte = 0
        for guess in range(256):
            sig[i] = guess
            url = f"http://127.0.0.1:{port}/test?file={filename}&signature={sig.hex()}"
            start = time.time()
            try:
                urllib.request.urlopen(url)
                # If 200, we're done
                return bytes(sig)
            except urllib.error.HTTPError:
                pass
            elapsed = time.time() - start
            if elapsed > best_time:
                best_time = elapsed
                best_byte = guess
        sig[i] = best_byte
        print(f"Byte {i}: 0x{best_byte:02x} (took {best_time:.3f}s)")

    return bytes(sig)


if __name__ == "__main__":
    server = start_server()
    filename = "testfile"
    expected = hmac_sha1(KEY, filename.encode())
    print(f"Expected HMAC: {expected.hex()}")
    print("Starting timing attack...")

    recovered = timing_attack(filename)
    print(f"Recovered:     {recovered.hex()}")

    if recovered == expected:
        print("Timing attack succeeded!")
    else:
        print("Timing attack failed (may need more samples or longer delay)")
    server.shutdown()
