"""
client.py

This module implements the client-side logic for a secure UDP chat application.
It handles encryption (RSA for key exchange, AES for messages), HMAC authentication,
and a terminal UI using the `curses` library.

Author: Burak Yilmaz
"""

# Standard library imports
import sys  # Provides access to interpreter variables and functions
import os   # Used to manipulate file paths

# Add the project root to the system path to allow relative imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Network and system libraries
import socket  # Provides access to socket interfaces
import base64  # Used to encode binary data for transmission over text-based protocols
import time    # Used for generating timestamps
import curses  # Provides terminal handling for character-cell displays
import logging # Provides logging functionalities

# Local cryptographic utilities
from secure_crypto.rsa_utils import generate_rsa_keypair, rsa_decrypt  # RSA key generation and decryption
from secure_crypto.aes_utils import aes_encrypt, aes_decrypt            # AES encryption/decryption
from secure_crypto.hmac_utils import verify_hmac, generate_hmac         # HMAC generation and verification

# Set up logging format
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def get_input(stdscr, y, x, max_length):
    """
    Get user input from the terminal using curses.

    Args:
        stdscr: curses window object.
        y (int): Y-position to begin input.
        x (int): X-position to begin input.
        max_length (int): Maximum input length allowed.

    Returns:
        str: The input string entered by the user.
    """
    curses.noecho()  # Disable key echoing on screen
    stdscr.move(y, x)  # Move cursor to specified position
    stdscr.refresh()  # Refresh the screen to reflect cursor movement
    input_str = ''  # Initialize input string

    while True:
        ch = stdscr.getch()  # Get character input
        if ch in (curses.KEY_ENTER, 10, 13):  # Handle Enter key
            break
        elif ch in (curses.KEY_BACKSPACE, 127, 8):  # Handle Backspace key
            if len(input_str) > 0:
                input_str = input_str[:-1]  # Remove last character
                yx = stdscr.getyx()  # Get current cursor position
                stdscr.move(yx[0], yx[1] - 1)  # Move cursor back
                stdscr.delch()  # Delete character at cursor
        elif 0 <= ch <= 255 and len(input_str) < max_length:
            input_str += chr(ch)  # Add character to input string
            stdscr.addch(ch)  # Display character

    curses.noecho()  # Disable echo again (safety)
    return input_str

def start_client(stdscr, server_host='localhost', server_port=9999):
    """
    Start the secure UDP client.

    Args:
        stdscr: curses screen object.
        server_host (str): The hostname or IP address of the server.
        server_port (int): The port number the server is listening on.
    """
    curses.curs_set(1)  # Enable cursor visibility
    stdscr.clear()  # Clear the screen
    stdscr.addstr(0, 0, "Secure connection established. Type 'q' to quit")  # Show header
    stdscr.refresh()

    # Create a UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(2)  # Set timeout for server response (ACK)

    # Generate RSA key pair for secure key exchange
    private_key, public_key = generate_rsa_keypair()

    # Send public RSA key to the server
    client_socket.sendto(public_key, (server_host, server_port))

    # Receive AES key from server (encrypted with client's public key)
    encrypted_aes_key, _ = client_socket.recvfrom(4096)
    aes_key = rsa_decrypt(private_key, encrypted_aes_key)  # Decrypt AES key using private RSA key

    stdscr.clear()
    stdscr.addstr(0, 0, "Secure connection established. Type 'q' to quit")
    stdscr.refresh()
    logging.info("Secure connection established. You can start sending messages.")

    while True:
        stdscr.addstr(2, 0, "Enter message: ")
        stdscr.clrtoeol()
        stdscr.refresh()
        message = get_input(stdscr, 2, 15, 100)  # Get user input

        if message.lower() == 'q':  # Quit if 'q' is typed
            break

        stdscr.addstr(4, 0, f"Sent: {message}")
        stdscr.clrtoeol()
        stdscr.refresh()

        timestamp = str(int(time.time()))  # Generate timestamp
        message_with_timestamp = f"{message}|{timestamp}"  # Combine message with timestamp

        # Encrypt message using AES
        encrypted_message = aes_encrypt(aes_key, message_with_timestamp)

        # Generate HMAC for message authentication
        message_hmac = generate_hmac(aes_key, message_with_timestamp)

        # Convert encrypted message to bytes if it's a string
        if isinstance(encrypted_message, str):
            encrypted_message = encrypted_message.encode('utf-8')

        # Convert HMAC to bytes if it's a string
        if isinstance(message_hmac, str):
            message_hmac = message_hmac.encode('utf-8')

        # Encode both the encrypted message and HMAC in base64
        encrypted_message_b64 = base64.b64encode(encrypted_message).decode('utf-8')
        message_hmac_b64 = base64.b64encode(message_hmac).decode('utf-8')

        # Concatenate both parts with delimiter and convert to bytes
        message_to_send = f"{encrypted_message_b64}|{message_hmac_b64}".encode()

        ack_received = False
        attempts = 0

        # Retry sending message up to 5 times if no ACK
        while not ack_received and attempts < 5:
            logging.info(f"Attempting to send message: {message_with_timestamp} (Attempt {attempts + 1})")
            client_socket.sendto(message_to_send, (server_host, server_port))

            try:
                ack, _ = client_socket.recvfrom(4096)
                if ack.decode() == "ACK":
                    ack_received = True
                    logging.info("Message acknowledged by server.")
                else:
                    logging.warning(f"Unexpected response: {ack.decode()}")
            except socket.timeout:
                logging.warning(f"No ACK received. Retrying... (Attempt {attempts + 1})")
                attempts += 1

        if not ack_received:
            logging.error("Failed to receive ACK after 5 attempts. Message not sent.")
            break

    client_socket.close()  # Close the socket when done

if __name__ == "__main__":
    """
    Entry point for the client application.

    Wraps the `start_client` function in a curses context.
    """
    curses.wrapper(start_client)  # Launch client UI using curses
