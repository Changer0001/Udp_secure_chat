from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(public_key_bytes, message_bytes):
    key = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(message_bytes)

def rsa_decrypt(private_key_bytes, ciphertext):
    key = RSA.import_key(private_key_bytes)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext)
