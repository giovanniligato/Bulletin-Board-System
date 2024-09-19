# Bulletin-Board-System

The **Bulletin Board System (BBS)** is a secure, distributed service designed for users to interact by reading and posting messages. It provides the following core functionalities:

- **List**: Displays the latest messages available on the BBS.
- **Get**: Retrieves a specific message from the BBS using a message identifier.
- **Add**: Allows users to post new messages to the BBS.

Users must first **log in** to access these operations. The system enforces a **secure connection** to ensure that all interactions are encrypted and safe. New users are required to **register** before logging in. Once a user **logs out**, they must log back in to perform any further actions.

The BBS prioritizes **security**, requiring user authentication for all operations and encrypting communications. It is designed to provide a reliable and user-friendly platform for securely sharing and organizing information.

## Table of Contents
- [Bulletin-Board-System](#bulletin-board-system)
  - [Table of Contents](#table-of-contents)
  - [Project Structure](#project-structure)
  - [Getting Started](#getting-started)
    - [Requirements](#requirements)
    - [Generating RSA Key Pair](#generating-rsa-key-pair)
    - [Compiling and Running the Project](#compiling-and-running-the-project)
  - [Documentation](#documentation)


## Project Structure

The project is organized into the following directories:

- `Documentation/`: Contains system documentation and related resources.

- `Implementation/`: Contains the implementation of the BBS system in C++.
  
  - `Client/`: Client-side code responsible for interacting with the server.
    - `client.cpp`: Main source file for the client.
    - `Storage/`: Directory for storing client-side data.
      - `Emails/`: Placeholder for email storage.
      - `Keys/`: Stores the server's public key.
        - `server_pubkey.pem`: Public key of the server.

  - `Filesystem/`: Code related to the bulletin board and user operations.
    - `BulletinBoard.cpp`
    - `BulletinBoard.h`
    - `User.cpp`
    - `User.h`

  - `Packets/`: Manages packet-based communication between client and server.
    - `GeneralPacket.cpp`
    - `GeneralPacket.h`
    - `StartPacket.cpp`
    - `StartPacket.h`

  - `Server/`: Server-side code responsible for handling client requests and managing system data.
    - `server.cpp`: Main source file for the server logic.
    - `Storage/`: Directory for storing server-side data.
      - `Accounts/`: Placeholder for storing user account information.
      - `BulletinBoard/`: Directory for storing bulletin board messages.
      - `Keys/`: Stores server keys.
        - `server_privkey.pem`: Server's private key.
        - `server_pubkey.pem`: Server's public key.

  - `Utility/`: Implements cryptographic utilities and helper functions.
    - `AESGCMWrapper.cpp`
    - `AESGCMWrapper.h`
    - `DHWrapper.cpp`
    - `DHWrapper.h`
    - `Hash.cpp`
    - `Hash.h`
    - `Randomness.cpp`
    - `Randomness.h`
    - `RSAWrapper.cpp`
    - `RSAWrapper.h`

  - `Makefile`: Build configuration file for compiling the project.

## Getting Started

### Requirements

- **C++** (Compiler supporting C++17 or higher)
- **OpenSSL**

### Generating RSA Key Pair

To configure secure communication between the client and server, you will need to generate RSA keys:

1. **Generate the server's private key**:

    ```bash
    openssl genrsa -aes128 -out server_privkey.pem
    ```

    Enter the password `serverBBS` when prompted.

2. **Generate the server's public key**:

    ```bash
    openssl rsa -pubout -in server_privkey.pem -out server_pubkey.pem
    ```

### Compiling and Running the Project

1. Navigate to the `Implementation` directory:

    ```bash
    cd Implementation
    ```

2. Compile the project using the provided `Makefile`:

    ```bash
    make
    ```

3. **Start the server**:  
    In one terminal window, start the server:

    ```bash
    ./serverBBS
    ```

4. **Start the client**:  
    In another terminal window, start the client:

    ```bash
    ./clientBBS
    ```

Once both the server and client are running, you can interact with the BBS using the client terminal.

## Documentation

For more information on the system design, encryption mechanisms, and packet structures, refer to the documentation in the `Documentation` directory.
