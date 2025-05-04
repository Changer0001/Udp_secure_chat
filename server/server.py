# server.py
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import socket
import threading
import base64
import curses
from secure_crypto.rsa_utils import rsa_encrypt
from secure_crypto.aes_utils import aes_decrypt, aes_encrypt  # Import aes_encrypt and aes_decrypt from the appropriate module
from secure_crypto.hmac_utils import verify_hmac  # Import verify_hmac from the appropriate module
from Crypto.Random import get_random_bytes
from datetime import datetime, timedelta

clients = {}

def is_recent(timestamp):
    message_time = datetime.fromtimestamp(int(timestamp))
    return datetime.now() - message_time < timedelta(minutes=5)

def handle_client(stdscr, server_socket, addr, data):
    if addr not in clients:
        public_key = data
        aes_key = get_random_bytes(16)
        encrypted_aes_key = rsa_encrypt(public_key, aes_key)
        server_socket.sendto(encrypted_aes_key, addr)
        clients[addr] = aes_key
    else:
        aes_key = clients[addr]
        try:
            encrypted_message, received_hmac = data.split(b"|")

            # Base64 decode the message and HMAC
            encrypted_message = base64.b64decode(encrypted_message)
            received_hmac = base64.b64decode(received_hmac)

            decrypted_message = aes_decrypt(aes_key, encrypted_message.decode())
            message, timestamp = decrypted_message.rsplit("|", 1)
            if verify_hmac(aes_key, decrypted_message, received_hmac.decode()) and is_recent(timestamp):
                stdscr.clear()
                stdscr.addstr(0, 0, f"Received message from {addr}: {message}")
                stdscr.refresh()
                for client_addr, client_aes_key in clients.items():
                    if client_addr != addr:
                        encrypted_message = aes_encrypt(client_aes_key, decrypted_message)
                        server_socket.sendto(encrypted_message.encode(), client_addr)
            else:
                stdscr.addstr(1, 0, f"Message from {addr} failed HMAC verification or is outdated.")
                stdscr.refresh()
        except Exception as e:
            stdscr.addstr(1, 0, f"Error processing message from {addr}: {e}")
            stdscr.refresh()

def start_server(stdscr, host='0.0.0.0', port=9999):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('', port))
    stdscr.clear()
    stdscr.addstr(0, 0, f"Server listening on {host}:{port}")
    stdscr.refresh()

    while True:
        data, addr = server_socket.recvfrom(4096)
        threading.Thread(target=handle_client, args=(stdscr, server_socket, addr, data)).start()

if __name__ == "__main__":
    curses.wrapper(start_server)