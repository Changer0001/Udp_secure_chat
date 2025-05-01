from secure_crypto.Cipher import AES
from secure_crypto.Random import get_random_bytes
from secure_crypto.Util.Padding import pad, unpad
import base64

def aes_encrypt(aes_key, plaintext):
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(iv + encrypted).decode()

def aes_decrypt(aes_key, b64_ciphertext):
    raw = base64.b64decode(b64_ciphertext)
    iv = raw[:16]
    encrypted = raw[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
    return decrypted.decode()
