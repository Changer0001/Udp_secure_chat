"""
server.py

This module implements the server-side logic for a secure UDP chat application.
It performs RSA-based AES key exchange, decrypts and verifies incoming messages
using HMAC, and rebroadcasts valid messages to all connected clients. Messages are
validated for freshness and authenticity.

Author: Burak Yilmaz
"""

# Standard library imports
import os  # Used for file path operations
import sys  # Used to manipulate the system path for module resolution
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))  # Add parent directory to path

# Networking and concurrency
import socket  # Provides low-level networking interface
import threading  # Enables handling multiple clients concurrently

# Encoding and terminal utilities
import base64  # For base64 encoding/decoding of messages and HMACs
import curses  # For terminal UI display
import logging  # For structured logging

# Cryptographic utilities
from secure_crypto.rsa_utils import rsa_encrypt  # RSA encryption used to send AES keys
from secure_crypto.aes_utils import aes_decrypt, aes_encrypt  # AES decryption/encryption
from secure_crypto.hmac_utils import verify_hmac  # HMAC verification function

# Random AES key generation
from Crypto.Random import get_random_bytes

# Timestamp validation
from datetime import datetime, timedelta

# Configure logging output format and level
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Dictionary to store client address => AES key mapping
clients = {}

def is_recent(timestamp):
    """
    Check if the timestamp is within the last 5 minutes.

    Args:
        timestamp (str): Unix timestamp as string.

    Returns:
        bool: True if timestamp is recent; False otherwise.
    """
    message_time = datetime.fromtimestamp(int(timestamp))  # Convert to datetime
    return datetime.now() - message_time < timedelta(minutes=5)  # Validate freshness

def handle_client(stdscr, server_socket, addr, data):
    """
    Handle an incoming message from a client.

    Args:
        stdscr: curses window object.
        server_socket: The server's UDP socket.
        addr: Address tuple of the client.
        data: The received data (bytes).
    """
    if addr not in clients:
        # New client: receive their public RSA key and respond with encrypted AES key
        public_key = data
        aes_key = get_random_bytes(16)  # Generate a 16-byte AES key
        encrypted_aes_key = rsa_encrypt(public_key, aes_key)  # Encrypt AES key with client's RSA public key
        server_socket.sendto(encrypted_aes_key, addr)  # Send back encrypted AES key
        clients[addr] = aes_key  # Store the AES key associated with this client
    else:
        aes_key = clients[addr]  # Retrieve the AES key for this client
        try:
            # Split message and HMAC
            encrypted_message, received_hmac = data.split(b"|")

            # Decode both parts from base64
            encrypted_message = base64.b64decode(encrypted_message)
            received_hmac = base64.b64decode(received_hmac)

            # Decrypt the AES message and extract the timestamp
            decrypted_message = aes_decrypt(aes_key, encrypted_message.decode())
            message, timestamp = decrypted_message.rsplit("|", 1)

            # Verify HMAC and message freshness
            if verify_hmac(aes_key, decrypted_message, received_hmac.decode()) and is_recent(timestamp):
                stdscr.clear()
                stdscr.addstr(0, 0, f"Received message from {addr}: {message}")
                stdscr.refresh()

                # Broadcast decrypted message to all other connected clients
                for client_addr, client_aes_key in clients.items():
                    if client_addr != addr:
                        encrypted_message = aes_encrypt(client_aes_key, decrypted_message)
                        server_socket.sendto(encrypted_message.encode(), client_addr)

                # Send ACK back to sender
                server_socket.sendto("ACK".encode(), addr)
                logging.info(f"Message from {addr} processed and ACK sent.")
            else:
                # Log failed verification or expired message
                stdscr.addstr(1, 0, f"Message from {addr} failed HMAC verification or is outdated.")
                stdscr.refresh()
        except Exception as e:
            # Catch and log any exceptions during processing
            stdscr.addstr(1, 0, f"Error processing message from {addr}: {e}")
            stdscr.refresh()

def start_server(stdscr, host='0.0.0.0', port=9999):
    """
    Start the secure UDP server.

    Args:
        stdscr: curses window object for display.
        host (str): Host IP to bind to (default '0.0.0.0' listens on all interfaces).
        port (int): Port number to listen on.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create UDP socket
    server_socket.bind(('', port))  # Bind to port on all network interfaces

    # Show server status in the terminal
    stdscr.clear()
    stdscr.addstr(0, 0, f"Server listening on {host}:{port}")
    stdscr.refresh()

    while True:
        # Wait for incoming UDP packet
        data, addr = server_socket.recvfrom(4096)

        # Handle each packet in a separate thread
        threading.Thread(target=handle_client, args=(stdscr, server_socket, addr, data)).start()

if __name__ == "__main__":
    """
    Entry point for the server application.

    Wraps the server start logic in a curses context.
    """
    curses.wrapper(start_server)  # Start the server with curses UI
