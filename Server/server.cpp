#include <iostream>
#include <thread>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h> // For cryptographic operations
#include <openssl/rand.h> // For secure random number generation
#include <signal.h>
#include <mutex>

#include "../Utility/Cryptography/Randomness.h"
#include "../Utility/Cryptography/RSAWrapper.h"
#include "../Utility/Cryptography/AESGCMWrapper.h"
#include "../Utility/Cryptography/DHWrapper.h"
#include "../Utility/Cryptography/Hash.h"

using namespace std;

#define DEFAULT_PORT 3030
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 5

class Server {
public:
    Server(int port);
    void start();
    ~Server();

private:
    int server_socket;
    struct sockaddr_in address;
    vector<thread> client_threads;
    static volatile bool server_running; 

    static void clientHandler(int client_socket);
    static void signalHandler(int signal);
    static void performKeyExchange(int client_socket, vector<unsigned char>& sessionKey);
    static void processClientRequests(int client_socket, const vector<unsigned char>& sessionKey);

    // Helper functions for encryption and decryption
    static string decryptMessage(const vector<unsigned char>& ciphertext, const vector<unsigned char>& sessionKey);
    static vector<unsigned char> encryptMessage(const string& plaintext, const vector<unsigned char>& sessionKey);
};

volatile bool Server::server_running = true;

Server::Server(int port) {
    int opt = 1;

    // Register signal handler for SIGINT (Ctrl+C)
    signal(SIGINT, Server::signalHandler);
    // Register signal handler for SIGTSTP (Ctrl+Z)
    signal(SIGTSTP, Server::signalHandler);

    // Create socket file descriptor
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options to reuse address and port
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    // Bind the socket to the network address and port
    if (bind(server_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
}

void Server::signalHandler(int signal) {
    if (signal == SIGINT) {
        cout << endl << "Forcing server shutdown..." << endl;
        exit(0);
    }
    else if (signal == SIGTSTP) {
        cout << endl << "Gently shutting down the server..." << endl;
        server_running = false;
    }
}

void Server::start() {
    // Start listening for incoming connections
    if (listen(server_socket, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    cout << "Server ON and listening on port " << ntohs(address.sin_port) << endl;
    cout << "To gently shut down the server, press Ctrl+Z" << endl;
    cout << "To force shutdown, press Ctrl+C" << endl << endl;

    // Server main loop
    while (server_running) {
        int client_socket;
        socklen_t addrlen = sizeof(address);

        // Accept new client connections
        if ((client_socket = accept(server_socket, (struct sockaddr *)&address, &addrlen)) < 0) {
            if (server_running) {
                perror("Accept failed");
            }
            continue;
        }

        cout << "New connection accepted." << endl;

        // Create a new thread to handle the client
        client_threads.push_back(thread(Server::clientHandler, client_socket));
    }

    // Clean up threads
    for (auto &th : client_threads) {
        if (th.joinable()) {
            th.join();
        }
    }
}

void Server::clientHandler(int client_socket) {
    
    vector<unsigned char> sessionKey;

    // Step 1: Perform key exchange with the client to establish a secure session
    performKeyExchange(client_socket, sessionKey);

    // Step 2: Process client requests using the established session key
    processClientRequests(client_socket, sessionKey);

    // Close the client socket after the session ends
    close(client_socket);
    cout << "Client disconnected." << endl;
}

void Server::performKeyExchange(int client_socket, vector<unsigned char>& sessionKey) {

    try {

        // Receiving the encrypted authentication key
        vector<unsigned char> encrypted_authentication_key(256);
        if (recv(client_socket, encrypted_authentication_key.data(), encrypted_authentication_key.size(), 0) < 0) {
            throw runtime_error("Failed to receive the encrypted authentication key.");
        }

        // Receiving the IV
        vector<unsigned char> iv(12);
        if (recv(client_socket, iv.data(), iv.size(), 0) < 0) {
            throw runtime_error("Failed to receive the IV.");
        }

        // Receiving the AAD
        vector<unsigned char> aad(670);
        if (recv(client_socket, aad.data(), aad.size(), 0) < 0) {
            throw runtime_error("Failed to receive the AAD.");
        }

        // Receiving the tag
        vector<unsigned char> tag(16);
        if (recv(client_socket, tag.data(), tag.size(), 0) < 0) {
            throw runtime_error("Failed to receive the tag.");
        }

        // Decrypt the authentication key using the server's private key
        RSAWrapper rsaWrapper("", "Server/Storage/Keys/server_privkey.pem");
        vector<unsigned char> authentication_key = rsaWrapper.decrypt(encrypted_authentication_key, KeyType::Private);

        // Check the tag for the AAD
        vector<unsigned char> ciphertext;
        vector<unsigned char> plaintext = AESGCMWrapper::decrypt(authentication_key, ciphertext, iv, tag, aad);

        // Extract the client's public key and nonce from the AAD (last 16 bytes are the nonce)
        vector<unsigned char> clientDH_public_key(aad.begin(), aad.end() - 16);
        vector<unsigned char> nonce(aad.end() - 16, aad.end());

        // Generate the server's public key for the Diffie-Hellman key exchange
        DHWrapper dhWrapper(1024);
        vector<unsigned char> serverDH_public_key = dhWrapper.getPublicKey();


        // Sending back to the client the server's public key and the nonce

        // Insert into the aad the public key and the nonce
        aad.clear();
        aad.insert(aad.end(), serverDH_public_key.begin(), serverDH_public_key.end());
        aad.insert(aad.end(), nonce.begin(), nonce.end());

        // Compute the authentication tag for the message serverDH_public_key || nonce
        AESGCMWrapper::encrypt(authentication_key, plaintext, ciphertext, iv, tag, aad);

        // Sending all to the client

        // 12 Bytes
        send(client_socket, iv.data(), iv.size(), 0);

        // 670 Bytes
        send(client_socket, aad.data(), aad.size(), 0);

        // 16 Bytes
        send(client_socket, tag.data(), tag.size(), 0);


        // Load the client's public key
        dhWrapper.loadPeerPublicKey(clientDH_public_key);

        // Compute the shared secret
        vector<unsigned char> DH_shared_secret = dhWrapper.computeSharedSecret();
        // DH shared secret is 128 bytes long

        // Before using the shared secret as the session key, it is a good practice to hash it
        sessionKey = Hash::computeSHA256(DH_shared_secret);
        // Session key is 32 bytes long

        cout << "Session key Hex: "<< Hash::toHexString(sessionKey) << endl;   


    }
    catch (const exception& ex) {
        cerr << "Error in connectToServer(): " << ex.what() << endl;
    }



    // TO DO: Implement key exchange protocol (e.g., Diffie-Hellman or ECDH)
    // The sessionKey should be derived from the key exchange process

}

void Server::processClientRequests(int client_socket, const vector<unsigned char>& sessionKey) {
    char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = read(client_socket, buffer, BUFFER_SIZE)) > 0) {
        buffer[bytes_read] = '\0';

        // Step 3: Decrypt the incoming message using the sessionKey
        vector<unsigned char> ciphertext(buffer, buffer + bytes_read);
        string decryptedMessage = decryptMessage(ciphertext, sessionKey);

        // Process the decrypted message (e.g., handle commands like LIST, GET, ADD)
        // TO DO: Implement the logic to handle different client requests

        // Example: Echo the message back to the client (encrypted)
        string response = "Message received: " + decryptedMessage;
        vector<unsigned char> encryptedResponse = encryptMessage(response, sessionKey);
        send(client_socket, encryptedResponse.data(), encryptedResponse.size(), 0);
    }
}

string Server::decryptMessage(const vector<unsigned char>& ciphertext, const vector<unsigned char>& sessionKey) {
    // TO DO: Implement decryption using sessionKey
    // For now, just return the plaintext as a placeholder
    return string(ciphertext.begin(), ciphertext.end());
}

vector<unsigned char> Server::encryptMessage(const string& plaintext, const vector<unsigned char>& sessionKey) {
    // TO DO: Implement encryption using sessionKey
    // For now, just return the plaintext as a vector of unsigned char as a placeholder
    return vector<unsigned char>(plaintext.begin(), plaintext.end());
}

Server::~Server() {
    close(server_socket);
    cout << "Server shutdown completed." << endl;
}

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;

    if (argc > 1) {
        port = atoi(argv[1]);
    }

    Server server(port);
    server.start();

    return 0;
}
