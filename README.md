# **Secure Server-Client Communication System**

## **Overview**
This project implements a secure server-client communication system using **TLS encryption** to ensure the confidentiality, integrity, and authenticity of data transfer between the client and server. It demonstrates the fundamentals of network security, including encrypted communication, mutual TLS authentication, and secure error handling.

## **Features**
- **Encrypted Communication:** Ensures secure data transfer.
- **Mutual TLS Authentication:** Verifies both server and client identities.
- **Scalable Design:** Ready for future enhancements like logging, error handling, and concurrent client support.

## **Prerequisites**
- **Python 3.8 or later**  
- **OpenSSL** (to generate certificates)  
- **Wireshark** (optional, for analyzing encrypted traffic)  
- **Git** (for version control)  

## **Setup Instructions**
Clone the repository to your local machine:
```bash
git clone <repository-url>
cd <repository-folder>

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
