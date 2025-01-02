'''import socket

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 12345))
client_socket.send("Hello, server!".encode())
response = client_socket.recv(1024).decode()
print(f"Server says: {response}")
client_socket.close()

import ssl
import socket

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Create an SSL context and load the server's certificate
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_verify_locations("server.crt")  # Path to the server's certificate

secure_socket = context.wrap_socket(client_socket, server_hostname="localhost")
secure_socket.connect(('127.0.0.1', 12345))
secure_socket.send("Hello, secure server!".encode())
response = secure_socket.recv(1024).decode()
print(f"Secure server says: {response}")
secure_socket.close()'''

'''import ssl
import socket

def client_menu():
    print("\nChoose an option:")
    print("1. Send a message")
    print("2. Request server time")
    print("3. Exit")
    return input("Enter your choice: ")


def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations("server.crt")
    secure_socket = context.wrap_socket(client_socket, server_hostname="localhost")

    secure_socket.connect(('127.0.0.1', 12345))
    print("Connected to the secure server.")

    while True:
        choice = client_menu()
        if choice == '1':
            message = input("Enter your message: ")
            secure_socket.sendall(f"MSG:{message}".encode())
        elif choice == '2':
            secure_socket.sendall("TIME".encode())
        elif choice == '3':
            secure_socket.sendall("EXIT".encode())
            break
        else:
            print("Invalid option. Try again.")
        
        response = secure_socket.recv(1024).decode()
        print(f"Server response: {response}")

    secure_socket.close()
    print("Disconnected from the server.")

def handle_message(data, conn, addr):
    message = data[4:]
    logging.info(f"Client {addr} says: {message}")
    conn.sendall(f"Message received: {message}".encode())

def handle_time(conn, addr):
    server_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logging.info(f"Sending server time to {addr}: {server_time}")
    conn.sendall(f"Server time is: {server_time}".encode())

def handle_exit(conn, addr):
    conn.sendall("Goodbye!".encode())
    logging.info(f"Client {addr} requested to exit.")

def send_file(filename, conn):
    with open(filename, 'rb') as file:
        while chunk := file.read(1024):
            conn.sendall(chunk)
    print(f"File {filename} sent successfully.")

def client_authenticate():
    username = input("Username: ")
    password = input("Password: ")
    conn.send(f"{username}:{password}".encode())


if __name__ == "__main__":
    main()

import ssl
import socket
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(filename="client.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Server information
HOST = '127.0.0.1'
PORT = 12345

# Client menu with added options
def client_menu():
    print("\nChoose an option:")
    print("1. Send a message")
    print("2. Request server time")
    print("3. Upload a file")
    print("4. Exit")
    return input("Enter your choice: ")

# User authentication (username and password)
def client_authenticate(secure_socket):
    username = input("Username: ")
    # print(f"DEBUG: Username entered: {username}")
    password = input("Password: ")
    secure_socket.sendall(f"AUTH:{username}:{password}".encode()) # This method sends the authentication data
    
    # Wait for server response
    auth_response = secure_socket.recv(1024).decode()
    print(f"Server response: {auth_response}")  # Debugging log
    return "failed" not in auth_response.lower()

    if "successful" in auth_response.lower():
        return True
    else:
        print("Authentication failed. Closing connection.")
        return False

    if "failed" in auth_response.lower():
        print("Authentication failed. Please check your credentials.")
        return False
    return True
# Sending messages to the server
def send_message(secure_socket):
    message = input("Enter your message: ")
    secure_socket.sendall(f"MSG:{message}".encode())

# Requesting server time
def request_server_time(secure_socket):
    secure_socket.sendall("TIME".encode())

# File upload to the server
def upload_file(secure_socket):
    filename = input("Enter the filename to upload: ")
    try:
        with open(filename, 'rb') as file:
            while chunk := file.read(1024):
                secure_socket.sendall(chunk)
        print(f"File {filename} sent successfully.")
    except FileNotFoundError:
        print(f"Error: File {filename} not found.")

# Main function to control the flow of the client
def main():
    # A socket created and wrapped with SSL/TLS
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations("server.crt")  # Path to the server's certificate
    secure_socket = context.wrap_socket(client_socket, server_hostname="localhost")

    try:
        # Connect to the secure server
        secure_socket.connect((HOST, PORT))
        print("Connected to the secure server.")

        # Authentication
        username = input("Username: ")
        password = input("Password: ")
        secure_socket.sendall(f"AUTH:{username}:{password}".encode())

        # Authenticate the user
        if not client_authenticate(secure_socket):
            secure_socket.close()
            return

        auth_response = secure_socket.recv(1024).decode()
        print(f"Server response: {auth_response}")

        if "failed" in auth_response.lower():
            print("Authentication failed. Please check your credentials and try again.")
            secure_socket.close()
            return  # Exit the client program if authentication fails

        print("Authentication successful! You can now interact with the server.")

        # Client menu loop
        while True:
            choice = client_menu()
            if choice == '1':
                send_message(secure_socket)
            elif choice == '2':
                request_server_time(secure_socket)
            elif choice == '3':
                upload_file(secure_socket)
            elif choice == '4':
                secure_socket.sendall("EXIT".encode())  # Exit the connection
                break
            else:
                print("Invalid option. Try again.")
            
            # Receive and print the server's response
            response = secure_socket.recv(1024).decode()
            print(f"Server response: {response}")

    except Exception as e:
        logging.error(f"Error: {e}")
        print(f"Error occurred: {e}")

    finally:
        # Close the connection when done
        secure_socket.close()
        print("Disconnected from the server.")

# Functions to handle server responses and actions

# Handle incoming messages from the server
def handle_message(data, conn, addr):
    message = data[4:]
    logging.info(f"Client {addr} says: {message}")
    conn.sendall(f"Message received: {message}".encode())

# Handle server time request
def handle_time(conn, addr):
    server_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logging.info(f"Sending server time to {addr}: {server_time}")
    conn.sendall(f"Server time is: {server_time}".encode())

# Handle client exit request
def handle_exit(conn, addr):
    conn.sendall("Goodbye!".encode())
    logging.info(f"Client {addr} requested to exit.")

# Server main function (can be expanded to integrate server-side fucntionalities)
def server_main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    secure_socket = context.wrap_socket(server_socket, server_side=True)

    secure_socket.bind((HOST, PORT))
    secure_socket.listen(5)
    print(f"Server listening on {HOST}:{PORT}...")

    while True:
        conn, addr = secure_socket.accept()
        data = conn.recv(1024).decode()

        if data.startswith("MSG:"):
            handle_message(data, conn, addr)
        elif data == "TIME":
            handle_time(conn, addr)
        elif data == "EXIT":
            handle_exit(conn, addr)
        elif data.startswith("AUTH:"):
            username, password = data[5:].split(":")
            # Authentication method
            if authenticate_user(username, password):
                conn.sendall("Authenticated successfully!".encode())
            else:
                conn.sendall("Authentication failed!".encode())
        else:
            conn.sendall("Unknown request".encode())
        conn.close()

# Example usage of the user authentication function
def authenticate_user(username, password):
    # Placeholder: Replace with actual authentication logic from the Database
    if username == "user1" and password == "password123":
        print("Login successful")
    else: 
        print("Access denied")

# Run the client
if __name__ == "__main__":
    main()'''

import ssl
import socket
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(filename="client.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Server information
HOST = '127.0.0.1'
PORT = 12345

# Client menu
def client_menu():
    print("\nChoose an option:")
    print("1. Send a message")
    print("2. Request server time")
    print("3. Upload a file")
    print("4. Exit")
    choice = input("Enter your choice: ")
    if choice not in ['1', '2', '3', '4']:
        print("Invalid choice. Try again.")
        return None
    return choice

# Authenticate user with the server
def client_authenticate(secure_socket):
    username = input("Username: ")
    password = input("Password: ")
    secure_socket.sendall(f"AUTH:{username}:{password}".encode())
    response = secure_socket.recv(1024).decode()
    print(f"Server response: {response}")
    if "successful" in response.lower():
        return True
    else:
        return False

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations("server.crt")
    secure_socket = context.wrap_socket(client_socket, server_hostname="localhost")

    try:
        secure_socket.connect((HOST, PORT))
        print("Connected to the secure server.")

        if not client_authenticate(secure_socket):
            print("Authentication failed. Disconnecting.")
            secure_socket.close()
            return

        while True:
            choice = client_menu()
            if choice == '1':  # Send a message
                message = input("Enter your message: ")
                secure_socket.sendall(f"MSG:{message}".encode())
                response = secure_socket.recv(1024).decode()
                print(f"Server response: {response}")
            elif choice == '2':  # Request server time
                secure_socket.sendall("TIME".encode())
                response = secure_socket.recv(1024).decode()
                print(f"Server response: {response}")
            elif choice == '3':  # Upload a file
                filename = input("Enter the filename to upload: ")
                try:
                    with open(filename, 'rb') as file:
                        while chunk := file.read(1024):
                            secure_socket.sendall(chunk)
                    secure_socket.sendall(b"FILE_UPLOAD_DONE") 
                    print(f"File {filename} sent successfully.")
                except FileNotFoundError:
                    print(f"Error: File {filename} not found.")
                except Exception as e:
                    print(f"Error uploading file: {e}")
            elif choice == '4':  # Exit
                secure_socket.sendall("EXIT".encode())
                print("Exiting.")
                break
            else:
                print("Invalid choice. Try again.")

    except Exception as e:
        logging.error(f"Error: {e}")
        print(f"Error occurred: {e}")
    finally:
        secure_socket.close()
        print("Disconnected from the server.")

if __name__ == "__main__":
    main()
