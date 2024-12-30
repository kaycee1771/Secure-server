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

import ssl
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

if __name__ == "__main__":
    main()

