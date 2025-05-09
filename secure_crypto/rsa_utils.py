"""
rsa_utils.py

Provides RSA key generation, encryption, and decryption utilities using OAEP padding.
This module is used for securely exchanging AES keys in the UDP chat application.

Author: Burak Yilmaz
"""

from Crypto.PublicKey import RSA  # For generating and importing RSA keys
from Crypto.Cipher import PKCS1_OAEP  # For RSA encryption with OAEP padding

def generate_rsa_keypair():
    """
    Generates a 2048-bit RSA key pair.

    Returns:
        tuple: A tuple containing the private key and public key as byte strings.
    """
    key = RSA.generate(2048)  # Generate a new 2048-bit RSA key pair
    private_key = key.export_key()  # Export the private key in PEM format
    public_key = key.publickey().export_key()  # Export the public key in PEM format
    return private_key, public_key

def rsa_encrypt(public_key_bytes, message_bytes):
    """
    Encrypts a message using the recipient's RSA public key.

    Args:
        public_key_bytes (bytes): The recipient's public RSA key.
        message_bytes (bytes): The plaintext message to encrypt.

    Returns:
        bytes: The RSA-encrypted message.
    """
    key = RSA.import_key(public_key_bytes)  # Import the public key
    cipher = PKCS1_OAEP.new(key)  # Initialize RSA cipher with OAEP padding
    return cipher.encrypt(message_bytes)  # Encrypt and return the message

def rsa_decrypt(private_key_bytes, ciphertext):
    """
    Decrypts an RSA-encrypted message using the recipient's private key.

    Args:
        private_key_bytes (bytes): The private RSA key.
        ciphertext (bytes): The RSA-encrypted message.

    Returns:
        bytes: The decrypted plaintext message.
    """
    key = RSA.import_key(private_key_bytes)  # Import the private key
    cipher = PKCS1_OAEP.new(key)  # Initialize RSA cipher with OAEP padding
    return cipher.decrypt(ciphertext)  # Decrypt and return the message
