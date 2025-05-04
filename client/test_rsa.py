from secure_crypto.rsa_utils import generate_rsa_keypair, rsa_encrypt, rsa_decrypt

def test_rsa():
    # Generate RSA key pair
    private_key, public_key = generate_rsa_keypair()

    # Original message
    message = "Hello, this is a secret message."
    message_bytes = message.encode('utf-8')

    # Encrypt the message
    encrypted_msg = rsa_encrypt(public_key, message_bytes)
    print(f"Encrypted message: {encrypted_msg}")

    # Decrypt the message
    decrypted_msg = rsa_decrypt(private_key, encrypted_msg)
    print(f"Decrypted message: {decrypted_msg.decode('utf-8')}")

if __name__ == "__main__":
    test_rsa()
