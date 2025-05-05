# Graduate Report: Secure UDP Chat System

**Name:** Burak Yilmaz  
**Course:** COMPE 560  
**Assignment:** Secure UDP Client-Server Chat  
**Date:** May 2025

---

## 🔧 Implementation Overview

The system is a secure UDP-based chat application implemented in Python using modules such as `socket`, `Crypto`, `base64`, `hmac`, and `curses`. It uses a hybrid encryption design (RSA + AES) to provide confidentiality, integrity, and basic reliability while maintaining low latency via UDP.

---

## 🔐 Cryptographic Design Decisions

### 🔑 Key Exchange
- **RSA (2048-bit)** is used for public-key encryption.
- Clients generate a new key pair at startup and send the public key to the server.
- The server creates a unique AES-128 key per client, encrypts it with the client’s RSA key, and sends it back securely.

### 🔒 Message Encryption
- **AES (CBC mode)** is used to encrypt chat messages.
- Each message is padded using **PKCS7** and encrypted with a **random IV** for every message.
- Messages are base64-encoded before transmission for binary-safe delivery.

### 🛡️ Message Integrity & Authentication
- A **HMAC-SHA256** is computed over the ciphertext and UTC timestamp.
- This ensures message authenticity and guards against tampering.
- The server checks the timestamp to reject messages older than 5 minutes (to prevent replay attacks).

---

## 📶 Reliable Communication over UDP

Since **UDP is unreliable**, a basic **ACK-retry mechanism** is implemented:
- Clients wait up to **2 seconds** for an acknowledgment.
- If no ACK is received, the message is **retried up to 3 times**.
- This improves delivery reliability without adding TCP overhead.

---

## ⚖️ Design Trade-offs & Considerations

| Decision | Reason | Trade-off |
|---------|--------|-----------|
| AES-CBC with IV | Strong block encryption | Requires proper IV management |
| HMAC over ciphertext + timestamp | Ensures integrity & freshness | Adds processing and complexity |
| Base64 encoding | Supports binary data via text | Slightly increases message size |
| One AES session key per client | Reduces overhead | No forward secrecy |
| Simple ACKs | Adds reliability | Not as robust as TCP |

> UI is built using `curses` for a real-time text-based interface, which limits compatibility to terminal environments that support it.

---

