# UDP Secure Chat

A secure, real-time chat application over UDP using hybrid encryption (RSA + AES) and HMAC for authentication.

## Features

- **UDP-based client-server communication**
- **RSA public key exchange**: Secure key exchange between client and server.
- **AES symmetric encryption**: Protects messages with AES encryption using a random IV and PKCS7 padding.
- **HMAC for message integrity and authentication**: Ensures that messages are not tampered with.
- **Multi-client support**: Allows multiple clients to communicate with each other.
- **Base64-encoded encrypted messages**: Ensures easy handling of encrypted data.
- **Logging**: Logs important events and errors for troubleshooting.
- **Terminal UI**: A simple, user-friendly interface for interaction.
- **Error handling**: Handles unexpected issues like failed encryption and invalid messages.

## Tech Stack

- **Python**: Programming language used for both the client and server applications.
- **Sockets**: For establishing UDP communication between clients and the server.
- **Cryptography**:
  - RSA (public-key cryptography) for secure key exchange.
  - AES (symmetric encryption) for encrypting the messages.
  - HMAC (Hash-based Message Authentication Code) for message integrity.
- **Threading**: Used to handle multiple clients simultaneously.
- **Base64, HMAC, Secrets**: Utilities for encoding, securing, and managing secrets.

## Getting Started

### Requirements

- **Python 3.8+**
- **Dependencies**:
  - `cryptography` (for cryptographic operations)
  - `pycryptodome` (for AES and RSA operations)
  - `hmac` (for HMAC generation and verification)
  - `base64` (for encoding and decoding encrypted data)
  - `logging` (for logging purposes)

### Installation

1. Clone the repository to your local machine:

   ```bash
   git clone https://github.com/your-username/udp-secure-chat.git
   cd udp-secure-chat
