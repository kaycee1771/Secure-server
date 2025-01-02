# **Secure Server-Client Communication System**

## **Overview**
This project implements a secure server-client communication system using **TLS encryption** to ensure data transfer confidentiality, integrity, and authenticity between the client and server. It demonstrates network security fundamentals, including encrypted communication, mutual TLS authentication, and secure error handling.

## **Features**

### Server
1. **Secure Communication**: Uses SSL/TLS for encrypted communication.
2. **User Authentication**:
   - Validates usernames and passwords using bcrypt.
   - Ensures passwords are stored securely.
3. **Client Request Handling**:
   - **Message Handling**: Accepts and acknowledges messages from the client.
   - **Server Time**: Sends the current server time on request.
   - **File Upload**: Allows clients to upload files to the server.
   - Handles unknown commands gracefully.
4. **Logging**:
   - Logs all server activities, including client connections, authentication attempts, and requests.
   - Maintains a `server.log` file for detailed logs.

### Client
1. **Authentication**: 
   - Users authenticate with a username and password before accessing other features.
2. **Menu Options**:
   - **Send a Message**: Send a custom message to the server.
   - **Request Server Time**: Request and display the current server time.
   - **Upload a File**: Upload a file to the server securely.
   - **Exit**: Gracefully terminate the connection.
3. **Error Handling**:
   - Handles invalid inputs and displays appropriate messages to the user.
   - Ensures secure disconnection on authentication failure.
4. **Logging**:
   - Logs client-side errors and activities to `client.log`.
---

## Setup Instructions

## **Prerequisites**
- **Python 3.8 or later**  
- **OpenSSL** (to generate certificates)  
- **Wireshark** (optional, for analyzing encrypted traffic)  
- **Git** (for version control)  

### Generating a Self-Signed Certificate
This project requires a private key (`server.key`) and a self-signed certificate (`server.crt`). Follow these steps to generate them:

1. Install OpenSSL:
   - On Ubuntu:
     ```bash
     sudo apt update
     sudo apt install openssl
     ```
   - On Windows (via WSL):
     Ensure OpenSSL is installed in your WSL environment.

2. Generate the Key and Certificate:
   Run the following command:
   ```bash
   openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes

## How to Run
**Server**
1. Place the server.crt and server.key files in the server's working directory.
2. Run the server:
'''bash
python server.py
'''
3. The server will start and listen for connections on 127.0.0.1:12345.
   
**Client**
1. Place the server.crt file in the client's working directory.
2. Run the client:
'''bash
python client.py
'''

## File Structure
'''graphql
├── client.py          # Client-side implementation
├── server.py          # Server-side implementation
├── server.crt         # SSL certificate (place in both client and server directories)
├── server.key         # SSL private key (server only)
├── server.log         # Server logs
├── client.log         # Client logs
└── README.md          # Project documentation
'''
## Usage
**Server**
- Start the server and wait for incoming client connections.
- Logs are saved in server.log.
  
**Client**
1. Connect to the server.
2. Authenticate with a valid username and password.
3. Select an option from the menu to:
- Send messages.
- Request server time.
- Upload files.
- Exit the connection.

## Sample Credentials
- Username: admin, Password: adminpass
- Username: user1, Password: password123
  
## License
This project is licensed under the MIT License. Feel free to use, modify, and distribute it as per the terms of the license.

## Contributing
Contributions are welcome! If you'd like to improve this project, please fork the repository, make your changes, and submit a pull request or contact me: kelechi.okpala13@yahoo.com

## Author
Kelechi Okpala - Cybersecurity enthusiast passionate about secure communication systems and Network protocols.
