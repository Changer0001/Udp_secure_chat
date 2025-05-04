# client.py
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import socket
import base64
import time
import curses
from secure_crypto.rsa_utils import generate_rsa_keypair, rsa_decrypt
from secure_crypto.aes_utils import aes_encrypt, aes_decrypt
from secure_crypto.hmac_utils import verify_hmac,generate_hmac  # Import verify_hmac from the appropriate module

def get_input(stdscr, y, x, max_length):
    curses.noecho()
    stdscr.move(y, x)
    stdscr.refresh()
    input_str = ''
    while True:
        ch = stdscr.getch()
        if ch in (curses.KEY_ENTER, 10, 13):  # Enter key
            break
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            if len(input_str) > 0:
                input_str = input_str[:-1]
                yx = stdscr.getyx()
                stdscr.move(yx[0], yx[1] - 1)
                stdscr.delch()
        elif 0 <= ch <= 255 and len(input_str) < max_length:
            input_str += chr(ch)
            stdscr.addch(ch)
    curses.noecho()
    return input_str
    
def start_client(stdscr, server_host='localhost', server_port=9999):
    curses.curs_set(1)  # Show the cursor
    stdscr.clear()
    stdscr.addstr(0, 0, "Secure connection established. Type 'q' to quit")
    stdscr.refresh()

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Generate RSA keys
    private_key, public_key = generate_rsa_keypair()

    # Send public key to server
    client_socket.sendto(public_key, (server_host, server_port))

    # Receive encrypted AES key from server
    encrypted_aes_key, _ = client_socket.recvfrom(4096)
    aes_key = rsa_decrypt(private_key, encrypted_aes_key)

    stdscr.clear()
    stdscr.addstr(0, 0, "Secure connection established. Type 'q' to quit")
    stdscr.refresh()

    print("Secure connection established. You can start sending messages.")

    while True:
        stdscr.addstr(2, 0, "Enter message: ")
        stdscr.clrtoeol()
        stdscr.refresh()
        message = get_input(stdscr, 2, 15, 100)
        if message.lower() == 'q':
            break

        stdscr.addstr(4, 0, f"Sent: {message}")
        stdscr.clrtoeol()
        stdscr.refresh()

        timestamp = str(int(time.time()))
        message_with_timestamp = f"{message}|{timestamp}"

        # Encrypt the message and HMAC
        encrypted_message = aes_encrypt(aes_key, message_with_timestamp)
        message_hmac = generate_hmac(aes_key, message_with_timestamp)

        # Ensure encrypted_message is in bytes
        if isinstance(encrypted_message, str):
            encrypted_message = encrypted_message.encode('utf-8')

        # Ensure message_hmac is in bytes before base64 encoding
        if isinstance(message_hmac, str):
            message_hmac = message_hmac.encode('utf-8')

        # Base64 encode the encrypted message and HMAC before sending
        encrypted_message_b64 = base64.b64encode(encrypted_message).decode('utf-8')
        message_hmac_b64 = base64.b64encode(message_hmac).decode('utf-8')

        # Send the Base64 encoded encrypted message and HMAC to server
        client_socket.sendto(f"{encrypted_message_b64}|{message_hmac_b64}".encode(), (server_host, server_port))

    client_socket.close()

if __name__ == "__main__":
    curses.wrapper(start_client)