from Crypto.Cipher import AES
import base64

# Define the key and read the encrypted data from the file
key = b'YELLOW SUBMARINE'
with open('7.txt', 'rb') as f:
    encrypted_data = base64.b64decode(f.read())

# Create an AES cipher object and decrypt the data
cipher = AES.new(key, AES.MODE_ECB)
decrypted_data = cipher.decrypt(encrypted_data)

# Print the decrypted data
print(decrypted_data.decode('utf-8'))
