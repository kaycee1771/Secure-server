import socket
import ssl
import threading
import logging
import signal
import sys
import bcrypt
from datetime import datetime

# Configure server address and port
HOST = '127.0.0.1'
PORT = 12345

# Sample user database for authentication
users_db = {
    "admin": bcrypt.hashpw("adminpass".encode(), bcrypt.gensalt()),
    "user1": bcrypt.hashpw("password123".encode(), bcrypt.gensalt())
}

# Logging configuration
logging.basicConfig(filename="server.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Authenticate user using bcrypt
def authenticate_user(username, password):
    if username in users_db and bcrypt.checkpw(password.encode(), users_db[username]):
        return True
    return False

# Function to handle incoming client connections
def handle_client(conn, addr):
    logging.info(f"New connection from {addr}")
    print(f"New connection from {addr}")

    try:
        # Handle authentication first
        data = conn.recv(1024).decode().strip()
        if data.startswith("AUTH:"):
            try:
                username, password = data[5:].split(":")
                if authenticate_user(username, password):
                    conn.sendall("Authentication successful!".encode())
                    logging.info(f"User {username} authenticated from {addr}")
                else:
                    conn.sendall("Authentication failed!".encode())
                    logging.warning(f"Failed authentication attempt from {addr} (Username: {username})")
                    conn.close()
                    return
            except ValueError:
                conn.sendall("Invalid authentication format.".encode())
                conn.close()
                return
        else:
            conn.sendall("Invalid authentication format.".encode())
            conn.close()
            return

        # After authentication, handle client requests
        while True:
            data = conn.recv(1024).decode().strip()
            if not data:
                break
            logging.info(f"Received from {addr}: {data}")

            if data == "TIME":
                server_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                logging.info(f"Sending server time to {addr}: {server_time}")
                conn.sendall(f"Server time: {server_time}".encode())
            elif data.startswith("MSG:"):
                message = data[4:]
                logging.info(f"Client {addr} says: {message}")
                print(f"Client {addr} says: {message}")
                conn.sendall(f"Message received: {message}".encode())
            elif data == "EXIT":
                conn.sendall("Goodbye!".encode())
                logging.info(f"Client {addr} requested to exit.")
                print(f"Client {addr} disconnected.")
                break
            elif data == "UPLOAD":
                receive_file(conn, addr)
            else:
                conn.sendall("Unknown command.".encode())
                logging.warning(f"Unknown command from {addr}: {data}")
    except Exception as e:
        logging.error(f"Error handling client {addr}: {e}")
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        print(f"Connection with {addr} closed.")
        logging.info(f"Connection with {addr} closed.")

# Function to receive and save a file from the client
def receive_file(conn, addr):
    try:
        with open("received_file", 'wb') as file:
            while True:
                data = conn.recv(1024)
                if data == b"FILE_UPLOAD_DONE":
                    break
                file.write(data)
        print("File received and saved successfully.")
        logging.info(f"File from {addr} received and saved successfully.")
    except Exception as e:
        logging.error(f"Error receiving file from {addr}: {e}")
        print(f"Error receiving file from {addr}: {e}")

# Function to handle graceful server shutdown on SIGINT (Ctrl+C)
def handle_signal(signal, frame):
    logging.info("Server shutting down gracefully...")
    print("Server shutting down gracefully...")
    sys.exit(0)

# Main function to start the server
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    secure_socket = context.wrap_socket(server_socket, server_side=True)

    secure_socket.bind((HOST, PORT))
    secure_socket.listen(5)
    print(f"Secure server listening on server {HOST} : port {PORT}")

    while True:
        conn, addr = secure_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

signal.signal(signal.SIGINT, handle_signal)

if __name__ == "__main__":
    start_server()
