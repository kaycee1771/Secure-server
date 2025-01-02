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
