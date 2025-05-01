from secure_crypto.rsa_utils import generate_rsa_keypair, rsa_encrypt, rsa_decrypt
from secure_crypto.aes_utils import aes_encrypt, aes_decrypt
from secure_crypto.hmac_utils import generate_hmac, verify_hmac
import socket

def start_client(server_host='localhost', server_port=9999):
    # Create UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"💬 Sending messages to {server_host}:{server_port}")
    print("✏️ Type your message and press Enter. Type 'exit' to quit.")

    while True:
        message = input("> ")
        if message.lower() == 'exit':
            break

        # Send message to server
        client_socket.sendto(message.encode(), (server_host, server_port))

    client_socket.close()
    print("👋 Client closed.")

if __name__ == "__main__":
    start_client()
