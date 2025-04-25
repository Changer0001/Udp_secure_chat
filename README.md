# UDP Secure Chat

A secure, real-time chat application over UDP using hybrid encryption (RSA + AES) and HMAC for authentication.

## Features

- UDP-based client-server communication
- RSA public key exchange
- AES symmetric encryption with IV and padding
- HMAC for message integrity and authentication
- Multi-client support
- Base64-encoded encrypted messages
- Graduate-level: Logging, terminal UI, and error handling

## Tech Stack

- Python
- Sockets
- Cryptography (pycryptodome or cryptography)
- Threading
- Base64, HMAC, Secrets

## Getting Started

### Requirements

- Python 3.8+
- Install dependencies:
  ```bash
  pip install cryptography
