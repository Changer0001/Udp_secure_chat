"""
aes_utils.py

Provides AES encryption and decryption utilities for the secure UDP chat application.
Uses AES in CBC mode with PKCS7 padding and random IV for each encryption.

Author: Burak Yilmaz
"""

# Import AES cipher, random byte generator, and padding utilities from PyCryptodome
from Crypto.Cipher import AES  # AES algorithm implementation
from Crypto.Random import get_random_bytes  # Secure random byte generation
from Crypto.Util.Padding import pad, unpad  # Padding and unpadding for block alignment
import base64  # For base64 encoding/decoding

def aes_encrypt(aes_key, plaintext):
    """
    Encrypts a plaintext message using AES encryption in CBC mode.

    Args:
        aes_key (bytes): 16-byte AES key.
        plaintext (str): The plaintext message to encrypt.

    Returns:
        str: Base64-encoded string containing IV + encrypted ciphertext.
    """
    iv = get_random_bytes(16)  # Generate a random 16-byte initialization vector
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)  # Create AES cipher in CBC mode
    padded = pad(plaintext.encode(), AES.block_size)  # Pad plaintext to AES block size
    encrypted = cipher.encrypt(padded)  # Encrypt the padded plaintext
    return base64.b64encode(iv + encrypted).decode()  # Encode IV + ciphertext in base64 and return as string

def aes_decrypt(aes_key, b64_ciphertext):
    """
    Decrypts a base64-encoded AES ciphertext string.

    Args:
        aes_key (bytes): 16-byte AES key used for encryption.
        b64_ciphertext (str): Base64-encoded ciphertext containing IV + encrypted data.

    Returns:
        str: The original decrypted plaintext message.
    """
    raw = base64.b64decode(b64_ciphertext)  # Decode base64 into raw bytes
    iv = raw[:16]  # Extract the 16-byte IV
    encrypted = raw[16:]  # Extract the actual encrypted message
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)  # Recreate AES cipher with the same IV
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)  # Decrypt and unpad the message
    return decrypted.decode()  # Return plaintext as string
