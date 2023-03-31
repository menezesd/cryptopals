block_size = 16

def count_aes_ecb_repetitions(ciphertext):
    chunks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    return len(chunks) - len(set(chunks))


def detect_ecb_encrypted_ciphertext(ciphertexts):
    best = (-1, 0)     # index of best candidate, repetitions of best candidate

    for i in range(len(ciphertexts)):
        repetitions = count_aes_ecb_repetitions(ciphertexts[i])

        # Keep the ciphertext with most repetitions
        best = max(best, (i, repetitions), key=lambda t: t[1])

    return best


def main():
    ciphertexts = [bytes.fromhex(line.strip()) for line in open("8.txt")]
    result = detect_ecb_encrypted_ciphertext(ciphertexts)

    print("The ciphertext encrypted in ECB mode is the one at position", result[0],
          "which contains", result[1], "repetitions")

if __name__ == "__main__":
    main()

