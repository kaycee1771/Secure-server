'''import socket

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 12345))
server_socket.listen(1)
print("Server is ready and listening...")

conn, addr = server_socket.accept()
print(f"Connection from {addr}")
data = conn.recv(1024).decode()
print(f"Received: {data}")
conn.send("Data received!".encode())
conn.close()

import ssl
import socket

HOST = '127.0.0.1'
PORT = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

# Wrap the server socket with TLS
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")
secure_socket = context.wrap_socket(server_socket, server_side=True)

print(f"The secure server is listening on port {PORT}...")

conn, addr = secure_socket.accept()
print(f"Secure connection from {addr}")
data = conn.recv(1024).decode()
print(f"Received: {data}")
conn.send("Data received securely!".encode())
conn.close()'''

import socket
import ssl
import threading
import logging

# Configure server address and port
HOST = '127.0.0.1'
PORT = 12345



# Create a function to handle client connections
def handle_client(conn, addr):
    print(f"New connection from {addr}")
    try:
        while True:
            data = conn.recv(1024).decode()
            if not data:
                break

            if data.startswith("MSG:"):
                message = data[4:]
                print(f"Client {addr} says: {message}")
                conn.sendall(f"Message received: {message}".encode())
            elif data == "TIME":
                from datetime import datetime
                server_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                conn.sendall(f"Server time is: {server_time}".encode())
            elif data == "EXIT":
                conn.sendall("Goodbye!".encode())
                break
            else:
                conn.sendall("Unknown request".encode())
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        print(f"Connection with {addr} closed.")


# Main server function
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    secure_socket = context.wrap_socket(server_socket, server_side=True)

    secure_socket.bind((HOST, PORT))
    secure_socket.listen(5)
    print(f"Server is listening on {HOST}:{PORT}...")

    while True:
        conn, addr = secure_socket.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"Active threads: {threading.active_count() - 1}")

'''# Configure logging
logging.basicConfig(filename="server.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Example usage in handle_client
def handle_client(conn, addr):
    logging.info(f"New connection from {addr}")
    try:
        data = conn.recv(1024).decode()
        logging.info(f"Received from {addr}: {data}")
        # Handle requests...
    finally:
        logging.info(f"Connection with {addr} closed.")'''

if __name__ == "__main__":
    start_server()

# Configure logging
logging.basicConfig(filename="server.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Example usage in handle_client
def handle_client(conn, addr):
    logging.info(f"New connection from {addr}")
    try:
        data = conn.recv(1024).decode()
        logging.info(f"Received from {addr}: {data}")
        # Handle requests...
    finally:
        logging.info(f"Connection with {addr} closed.")