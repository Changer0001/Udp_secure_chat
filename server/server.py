import socket
import sys

def main():
    server_socket = None
    try:
        # Server setup code
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow port reuse
        server_socket.bind(('0.0.0.0', 9999))
        server_socket.settimeout(1.0)  # Set a timeout of 1 second
        print("Server running... Press Ctrl+C to stop.")

        while True:
            try:
                data, addr = server_socket.recvfrom(4096)
                message = data.decode('utf-8')
                print(f"Received from {addr}: {message}")
            except socket.timeout:
                continue

    except KeyboardInterrupt:
        print("\n[Server] Shutting down gracefully.")
    finally:
        if server_socket:
            server_socket.close()

if __name__ == "__main__":
    main()