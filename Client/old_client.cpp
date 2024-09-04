#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

#include "../Utility/Cryptography/RSAWrapper.h"

#define PORT 3030
#define BUFFER_SIZE 1024
#define SERVER_ADDRESS "127.0.0.1" // Localhost

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, SERVER_ADDRESS, &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address or Address not supported" << std::endl;
        return -1;
    }

    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection failed" << std::endl;
        return -1;
    }

    std::cout << "Connected to server at " << SERVER_ADDRESS << ":" << PORT << std::endl;

    // Get user input and send to server
    std::string message;
    std::cout << "Enter a message: ";
    std::getline(std::cin, message);

    vector<unsigned char> plaintext(message.begin(), message.end());
    vector<unsigned char> ciphertext;
    vector<unsigned char> encrypted_key;
    vector<unsigned char> iv;
    vector<unsigned char> tag;

    RSAWrapper rsaWrapper("Client/Storage/Keys/server_pubkey.pem", "");

    string plaintext_str(plaintext.begin(), plaintext.end());
    rsaWrapper.sealEnvelope(plaintext_str, ciphertext, encrypted_key, iv, tag);

    cout << encrypted_key.size() << endl;

    // send(sock, message.c_str(), message.length(), 0);
    send(sock, encrypted_key.data(), encrypted_key.size(), 0);
    send(sock, iv.data(), iv.size(), 0);
    int32_t ciphertext_size = ciphertext.size();
    send(sock, &ciphertext_size, sizeof(int32_t), 0);
    cout<< "Ciphertext size: " << ciphertext.size() << endl;
    send(sock, ciphertext.data(), ciphertext.size(), 0);
    send(sock, tag.data(), tag.size(), 0);

    // Printing the tag
    cout << "Tag: ";
    for (int i = 0; i < tag.size(); i++) {
        cout << (int)tag[i];
    }
    cout << endl;
     
    // Printing the ciphertext
    cout << "Ciphertext: ";
    for (int i = 0; i < ciphertext.size(); i++) {
        cout << (int)ciphertext[i] << " ";
    }
    cout << endl;

    exit(0);

    // Receive the echoed message from server
    int bytes_read = read(sock, buffer, BUFFER_SIZE);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        std::cout << "Server echoed: " << buffer << std::endl;
    }

    // Close the socket
    close(sock);
    return 0;
}

