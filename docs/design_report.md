
---

## **design_report.md (1–2 Page Report)**

```markdown
# Graduate Report: Secure UDP Chat System
**Name:** Burak Yilmaz  
**Course:** COMPE 560  
**Assignment:** Secure UDP Client-Server Chat  
**Date:** May 2025

## Implementation Overview

The chat system was implemented using Python’s `socket`, `Crypto`, `base64`, `hmac`, and `curses` libraries. UDP was chosen for message transport, and security was ensured through a hybrid cryptosystem combining RSA and AES.

## Cryptographic Design Decisions

### 1. Key Exchange
RSA (2048-bit) was used for public-key encryption. Each client generates a new key pair at startup. Upon connection, it sends its public key to the server. The server responds by generating a unique AES-128 key for that client, encrypting it with RSA, and sending it back. This approach provides confidentiality for the AES key.

### 2. Message Encryption
AES in CBC mode was selected for encrypting chat messages due to its strong security and block-mode design. Each message is padded with PKCS7 to match AES's block size requirements, and a fresh random IV is generated for every message.

### 3. Message Integrity & Authentication
HMAC-SHA256 is computed over the AES ciphertext and the ISO-formatted UTC timestamp. This provides integrity and guards against tampering. The server verifies the HMAC and ensures the timestamp is within a 5-minute validity window.

## Reliable Communication over UDP

UDP does not guarantee delivery, so a simple acknowledgment (ACK) mechanism was implemented. Clients wait up to 2 seconds for an ACK and retry sending messages up to 3 times if it is not received. While basic, this introduces some level of reliability without switching to TCP.

## Design Trade-offs and Considerations

- **AES-CBC** is secure but requires proper IV handling; hence a unique IV is generated per message.
- **HMAC over ciphertext + timestamp** avoids plaintext exposure and replay attacks.
- **Base64 encoding** was necessary to safely transmit binary data over the text-based UDP socket.
- **Session-based AES key** instead of per-message keys reduces overhead.
- **No forward secrecy** is implemented; compromising the AES key would expose prior messages.
- **UI implementation** using `curses` provides real-time interaction but limits the application to compatible terminals.




