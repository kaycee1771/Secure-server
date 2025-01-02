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

'''import socket
import ssl
import threading
import logging
import signal
import sys
import bcrypt

# Configure server address and port
HOST = '127.0.0.1'
PORT = 12345

users_db = {
    "user1": bcrypt.hashpw("password123".encode(), bcrypt.gensalt())
}

def authenticate_user(username, password):
    if username in users_db and bcrypt.checkpw(password.encode(), users_db[username]):
        return True
    return False



# Create a function to handle client connections
def handle_client(conn, addr):
    print(f"New connection from {addr}")
    logging.info(f"New connection from {addr}")
    try:
        while True:
            data = conn.recv(1024).decode()
            if not data:
                break
            logging.info(f"Received from {addr}: {data}")

            if data.startswith("MSG:"):
                message = data[4:]
                print(f"Client {addr} says: {message}")
                logging.info(f"Client {addr} says: {message}")
                conn.sendall(f"Message received: {message}".encode())
            elif data == "TIME":
                from datetime import datetime
                server_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                logging.info(f"Sending server time to {addr}: {server_time}")
                conn.sendall(f"Server time is: {server_time}".encode())
            elif data == "EXIT":
                conn.sendall("Goodbye!".encode())
                logging.info(f"Client {addr} requested to exit.")
                break
            else:
                conn.sendall("Unknown request".encode())
                logging.warning(f"Unknown request from {addr}: {data}")
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
        logging.error(f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        print(f"Connection with {addr} closed.")
        logging.info(f"Connection with {addr} closed.")


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

def handle_signal(signal, frame):
    logging.info("Server shutting down gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_signal)

def receive_file(conn):
    with open("received_file", 'wb') as file:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            file.write(data)
    print("File received and saved successfully.")

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
    "user1": bcrypt.hashpw("password123".encode(), bcrypt.gensalt()),
    "admin": bcrypt.hashpw("adminpass".encode(), bcrypt.gensalt())
}

# Logging config
logging.basicConfig(filename="server.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Authenticate user using bcrypt
def authenticate_user(username, password):
    if username in users_db:
        stored_hash = users_db[username].encode()
        print(f"User {username} found.")
        if bcrypt.checkpw(password.encode(), stored_hash):
            print("Password matched.")
            return True
        else:
            print("Password mismatch.")
    else:
        print(f"User {username} not found.")
    return False

# Function to handle incoming client connections
def handle_client(conn, addr):
    print(f"New connection from {addr}")
    logging.info(f"New connection from {addr}")

    try:
        # Authentication method
        conn.sendall("Username: ".encode())
        username = conn.recv(1024).decode()
        conn.sendall("Password: ".encode())
        password = conn.recv(1024).decode()

        if not authenticate_user(username, password):
            conn.sendall("Authentication failed!".encode())
            logging.warning(f"Failed authentication attempt from {addr}")
            conn.close()
            return

        conn.sendall("Authenticated successfully!".encode())
        logging.info(f"Authenticated user {username} from {addr}")

        if authenticate_user(username, password):
            conn.sendall("Authentication successful!".encode())
        else:
            conn.sendall("Authentication failed.".encode())
            conn.close()
            return


        # Client Requests method
        while True:
            data = conn.recv(1024).decode()
            if not data:
                break
            logging.info(f"Received from {addr}: {data}")
            if data.startswith("AUTH:"):
                try:
                    username, password = data[5:].split(":")
                    if authenticate_user(username, password):
                        conn.sendall("Authenticated successfully!".encode())
                    else:
                        conn.sendall("Authentication failed!".encode())
                        logging.warning(f"Failed authentication attempt for username: {username}")
                        conn.close()  # Disconnect client if authentication fails
                        return

            if data.startswith("MSG:"):
                message = data[4:]
                print(f"Client {addr} says: {message}")
                logging.info(f"Client {addr} says: {message}")
                conn.sendall(f"Message received: {message}".encode())
            elif data == "TIME":
                server_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                logging.info(f"Sending server time to {addr}: {server_time}")
                conn.sendall(f"Server time is: {server_time}".encode())
            elif data == "EXIT":
                conn.sendall("Goodbye!".encode())
                logging.info(f"Client {addr} requested to exit.")
                break
            elif data == "UPLOAD":
                receive_file(conn)
            else:
                conn.sendall("Unknown request".encode())
                logging.warning(f"Unknown request from {addr}: {data}")

    except Exception as e:
        conn.sendall("Invalid authentication format.".encode())
        conn.close()
        return
        print(f"Error handling client {addr}: {e}")
        logging.error(f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        print(f"Connection with {addr} closed.")
        logging.info(f"Connection with {addr} closed.")

# Function to receive and save a file from the client
def receive_file(conn):
    with open("received_file", 'wb') as file:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            file.write(data)
    print("File received and saved successfully.")
    logging.info("File received and saved successfully.")

# Function to handle graceful server shutdown on SIGINT (Ctrl+C)
def handle_signal(signal, frame):
    logging.info("Server shutting down gracefully...")
    sys.exit(0)

# Main function to start the server
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Method to wrap the server socket with SSL/TLS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    secure_socket = context.wrap_socket(server_socket, server_side=True)

    secure_socket.bind((HOST, PORT))
    secure_socket.listen(5)
    print(f"Secure server is listening on server {HOST} : port {PORT}...")

    while True:
        conn, addr = secure_socket.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"Active threads: {threading.active_count() - 1}")

# Method to handle SIGINT to shut down the server
signal.signal(signal.SIGINT, handle_signal)

if __name__ == "__main__":
    start_server()'''

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
