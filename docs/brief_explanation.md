#1. UDP Communication
##What’s happening?
You're using UDP, which is a way for computers to talk to each other by sending messages quickly—but it doesn’t check if they got there.

##Real-life example:
Imagine throwing a paper airplane to a friend. It’s fast, but it might fall or get lost. That’s UDP.

📌 You create a "server" that listens for messages
📌 You create a "client" that sends messages to the server

#🔹 2. RSA Public Key Exchange
##What’s happening?
RSA is a type of encryption with two keys:

One public key (you can share with anyone),

One private key (you keep safe and secret).

The client and server swap public keys so they can send secret stuff (like an AES key) to each other safely.

##Real-life example:
Imagine you give your friend a lockbox and they have the key. You can put a message in it, lock it, and they’re the only one who can open it.

📌 The server sends its public key to the client
📌 The client sends its AES key back to the server using that public key
📌 The server uses its private key to open it

#🔹 3. AES Encryption with IV and Padding
##What’s happening?
Once both sides share a secret key (AES), they use it to encrypt/decrypt all messages.

AES is fast and strong.

IV = adds randomness to each message.

Padding = makes message size match what AES needs.

##Real-life example:
Imagine you and your friend both have the same secret codebook. Now you can send real secret messages.

📌 All messages are encrypted using AES
📌 IV makes sure the same message gives different results each time
📌 Padding adds extra fluff to make the message the right size

#🔹 4. HMAC (Hash Message Authentication Code)
##What’s happening?
You use HMAC to make sure:

No one has changed the message

You know the message is really from your friend

##Real-life example:
Imagine putting a wax seal on a letter. If the seal is broken, you know someone opened it.

📌 You generate a HMAC using your shared secret
📌 The receiver checks it matches — if not, message is rejected

#🔹 5. Multi-Client Support
What’s happening?
The server can handle many people chatting at once.

It does this using threads — little workers that handle each client separately.

📌 Every new client connection gets its own thread
📌 Everyone can chat without waiting in line

#🔹 6. Base64 Encoding
What’s happening?
Encrypted messages are not normal text — they can look weird or cause issues when sent over the network.

Base64 turns that weird encrypted data into normal-looking text.

##Real-life example:
Imagine translating a bunch of alien symbols into letters so you can send them as a text message.

📌 After encryption, you turn the message into Base64
📌 On the other side, decode it back before decrypting

#🔹 7. Logging, Terminal UI, and Error Handling
What’s happening?
Logging = keeping a diary of everything that happens (like errors or messages).

Terminal UI = making the command line chat look nice.

Error handling = catching problems before the program crashes.

📌 If something goes wrong, it gets written to a log
📌 You see messages cleanly formatted in your terminal
📌 The program doesn’t crash if something weird happens
